// SPDX-License-Identifier: BSD-2-Clause
//! `inspect` against the Python CLI (reference fixture
//! `tests/fixtures/inspect.json`),
//! the top-level `layout`, and segmented mode (Rust only, format §10).

mod common;

use apcaw::params::{GROUP, N_FFT};
use apcaw::segment::DEFAULT_SEGMENT_GROUPS;
use apcaw::wav::read_wav;
use apcaw::{
    inspect, keygen_from_seed, layout, scan, sign, sign_segmented, verify, Error, Layout, Options, Profile, PublicKey,
};
use common::*;
use serde_json::Value;

const MSG: &[u8] = b"segment test";

fn clip(name: &str) -> Vec<f64> {
    read_wav(&vector_bytes(name)).unwrap().samples
}

/// Structural JSON equality, floats within `tol`.
fn same(a: &Value, b: &Value, tol: f64, at: &str) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let kx: Vec<&String> = x.keys().collect();
            let ky: Vec<&String> = y.keys().collect();
            assert_eq!(kx, ky, "{at}: keys");
            for (k, v) in x {
                same(v, &y[k], tol, &format!("{at}.{k}"));
            }
        }
        (Value::Number(x), Value::Number(y)) if x.is_f64() || y.is_f64() => {
            let (x, y) = (x.as_f64().unwrap(), y.as_f64().unwrap());
            assert!((x - y).abs() <= tol, "{at}: {x} vs {y}");
        }
        _ => assert_eq!(a, b, "{at}"),
    }
}

#[test]
fn inspect_matches_python_cli() {
    let j = fixture("inspect.json");
    let pk = PublicKey::from_bytes(hex32(j["public_key_hex"].as_str().unwrap()));
    let cases = j["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    let base = clip("clip_A.wav");
    for c in cases {
        let want = &c["report"];
        let name = want["file"].as_str().unwrap();
        let x = match name {
            "short_3g.wav" => base[..50_000].to_vec(),
            "short_0g.wav" => base[..10_000].to_vec(),
            _ => clip(name),
        };
        let opt = if c["legacy"].as_bool().unwrap() { Options::legacy() } else { Options::v1() };
        let rep = inspect(&x, 44_100, &pk, &opt).unwrap();
        let mut got = serde_json::json!({ "file": name });
        for (k, v) in serde_json::to_value(&rep).unwrap().as_object().unwrap() {
            got[k] = v.clone();
        }
        same(&got, want, 1e-12, name);
    }
}

#[test]
fn inspect_rejects_wrong_rate() {
    let pk = keygen_from_seed([1; 32]).public;
    assert!(matches!(inspect(&[0.0; 10], 48_000, &pk, &Options::v1()), Err(Error::SampleRate(48_000))));
}

#[test]
fn layout_fn_matches_layout_vectors() {
    let j = vector_json("payload.json");
    let pk = PublicKey::from_bytes(hex32(j["public_key_hex"].as_str().unwrap()));
    let seed = j["key_seed"].as_u64().unwrap() as u32;
    for p in Profile::ALL {
        assert_eq!(layout(&pk, &p, None), Layout::from_seed(seed, &p));
        assert_eq!(layout(&pk, &p, Some(42)), Layout::from_seed(42, &p));
    }
}

/// Three copies of clip_A: 80 groups, blocks of 26 + a 2-group remainder.
fn long_clip() -> Vec<f64> {
    let a = clip("clip_A.wav");
    [a.clone(), a.clone(), a].concat()
}

#[test]
fn segmented_sign_and_scan() {
    let kp = keygen_from_seed([9; 32]);
    let x = long_clip();
    let k = DEFAULT_SEGMENT_GROUPS;
    let (y, info) = sign_segmented(&x, 44_100, &kp.secret, MSG, &Profile::WB, &Options::v1(), k).unwrap();
    assert_eq!(y.len(), x.len());
    assert_eq!(info.blocks.len(), 4);
    assert_eq!(info.embedded(), 3, "the 2-group remainder cannot carry the stream");
    let bs = k * GROUP * N_FFT;
    for (b, blk) in info.blocks.iter().enumerate() {
        assert_eq!((blk.start_group, blk.start_sample), (b * k, b * bs));
    }
    assert_eq!(info.blocks[3].groups, 2);
    assert_eq!(info.blocks[3].end_sample, x.len());
    assert_eq!(&y[info.blocks[3].start_sample..], &x[info.blocks[3].start_sample..], "remainder untouched");

    // every full block is exactly `sign` of that block
    for blk in &info.blocks[..3] {
        let s = &x[blk.start_sample..blk.end_sample];
        let want = sign(s, 44_100, &kp.secret, MSG, &Profile::WB, &Options::v1()).unwrap();
        assert!(want == y[blk.start_sample..blk.end_sample], "block at group {}", blk.start_group);
    }

    let r = scan(&y, 44_100, &kp.public, None, &Options::v1(), k).unwrap();
    assert_eq!(r.groups, 80);
    assert_eq!(r.windows_tried, 4);
    let starts: Vec<usize> = r.blocks.iter().map(|h| h.start_group).collect();
    assert_eq!(starts, [0, 26, 52]);
    for h in &r.blocks {
        assert!(h.report.verified);
        assert_eq!(h.report.message.as_deref(), Some(MSG));
    }

    // an unsigned input and a wrong key find nothing (window by window)
    let other = keygen_from_seed([10; 32]).public;
    let head = &y[..(k + 2) * GROUP * N_FFT];
    let r = scan(head, 44_100, &other, Some(&Profile::WB), &Options::v1(), k).unwrap();
    assert!(!r.verified());
    assert_eq!(r.windows_tried, 3 + 1, "windows at groups 0, 1, 2 and the remainder at 3");
}

#[test]
fn segmented_plain_verify_reads_the_first_block() {
    let kp = keygen_from_seed([9; 32]);
    let x = long_clip();
    let (y, _) = sign_segmented(&x, 44_100, &kp.secret, MSG, &Profile::WB, &Options::v1(), 26).unwrap();
    let r = verify(&y, 44_100, &kp.public, None, &Options::v1(), false);
    eprintln!("plain verify of a segmented file: {} ({:?} {:?})", r.reason, r.channel, r.path);
    assert!(r.verified, "{}", r.reason);
    assert_eq!(r.message.as_deref(), Some(MSG));
}

#[test]
fn segmented_errors() {
    let kp = keygen_from_seed([9; 32]);
    let x = clip("clip_A.wav");
    let o = Options::v1();
    assert!(matches!(sign_segmented(&x, 44_100, &kp.secret, MSG, &Profile::WB, &o, 0), Err(Error::InvalidOption(_))));
    assert!(matches!(sign_segmented(&x, 44_100, &kp.secret, MSG, &Profile::WB, &o, 2), Err(Error::TooShort { .. })));
    assert!(matches!(scan(&x, 22_050, &kp.public, None, &o, 26), Err(Error::SampleRate(22_050))));
    // input shorter than one block: a single (partial) block, same as `sign`
    let (y, info) = sign_segmented(&x, 44_100, &kp.secret, MSG, &Profile::WB, &o, 100).unwrap();
    assert_eq!(info.blocks.len(), 1);
    assert_eq!(y, sign(&x, 44_100, &kp.secret, MSG, &Profile::WB, &o).unwrap());
}
