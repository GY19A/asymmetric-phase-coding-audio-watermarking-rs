// SPDX-License-Identifier: BSD-2-Clause
//! The optional resync search against the Python reference
//! (`tests/fixtures/resync.json`):
//! the score grid, the order of offsets, and the full verify report including
//! the work counters, on delayed / cut / MP3 / unsigned / wrong-key inputs.

mod common;

use apcaw::resync::{delta_order, score_grid};
use apcaw::wav::read_wav;
use apcaw::{verify, Options, Profile, PublicKey};
use common::*;

fn transform(x: &[f64], kind: &str, n: usize) -> Vec<f64> {
    let mut out = vec![0.0; x.len()];
    match kind {
        "delay" => out[n..].copy_from_slice(&x[..x.len() - n]),
        "cut" => out[..x.len() - n].copy_from_slice(&x[n..]),
        "none" => out.copy_from_slice(x),
        k => panic!("unknown transform {k}"),
    }
    out
}

#[test]
fn resync_matches_reference() {
    let j = fixture("resync.json");
    let cases = j["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for c in cases {
        let file = c["file"].as_str().unwrap();
        let kind = c["transform"].as_str().unwrap();
        let n = c["n"].as_u64().unwrap() as usize;
        let what = format!("{file} {kind} {n}");
        let x = transform(&read_wav(&vector_bytes(file)).unwrap().samples, kind, n);
        let pk = PublicKey::from_bytes(hex32(c["public_key_hex"].as_str().unwrap()));

        let s = score_grid(&x, Profile::WB.p_lo, Profile::WB.p_hi);
        let order = delta_order(&s);
        let want: Vec<usize> = u64s(&c["order"]).iter().map(|&v| v as usize).collect();
        assert_eq!(order, want, "{what}: offset order");
        let mut worst = 0.0f64;
        for (d, row) in order.iter().zip(c["score_rows"].as_array().unwrap()) {
            worst = worst.max(max_abs_diff(&s[*d], &f64s(row)));
        }
        assert!(worst <= 1e-9, "{what}: score max |Δ| {worst:e}");

        let t = std::time::Instant::now();
        let r = verify(&x, 44_100, &pk, None, &Options::v1(), true);
        eprintln!(
            "{what}: {} ({} tried) in {:.2?} (python {}s); score max |Δ| {worst:e}",
            r.reason,
            r.candidates_tried,
            t.elapsed(),
            c["python_seconds"]
        );
        let s = |k: &str| c[k].as_str().map(str::to_owned);
        let u = |k: &str| c[k].as_u64().map(|v| v as usize);
        assert_eq!(r.verified, c["verified"].as_bool().unwrap(), "{what}: {}", r.reason);
        assert_eq!(r.message_hex(), s("message_hex"), "{what}");
        assert_eq!(r.channel.map(|v| v.as_str().to_owned()), s("channel"), "{what}");
        assert_eq!(r.profile.map(str::to_owned), s("profile"), "{what}");
        assert_eq!(r.path.map(|p| p.as_str().to_owned()), s("path"), "{what}");
        assert_eq!(r.rs_corrected, u("rs_corrected"), "{what}");
        assert_eq!(r.payload_bits, u("payload_bits"), "{what}");
        assert_eq!(r.candidates_tried, u("candidates_tried").unwrap(), "{what}: candidates_tried");
        assert_eq!(r.rs_passes, u("rs_passes").unwrap(), "{what}: rs_passes");
        assert_eq!(r.sig_checks, u("sig_checks").unwrap(), "{what}: sig_checks");
        assert_eq!(r.reason, s("reason").unwrap(), "{what}");
    }
}
