// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw selftest`: the reference's eleven checks against the vector set it
//! bundles (`selftest.json`, byte-identical to the Python
//! reference's `apcaw/data/selftest.json`), followed by checks against the audio vectors
//! of `crates/apcaw/vectors`: the signed clip_A files byte for byte (by their
//! MANIFEST sha256), the MP3-transcoded vector, and the negative cases.
//! Everything is compiled into the binary.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use apcaw::keys::{from_hex, to_hex};
use apcaw::mt19937::Mt19937;
use apcaw::wav::{read_wav, write_wav, Codec};
use apcaw::{keygen_from_seed, layout_seed, Layout, Options, Profile, PublicKey, VerifyReport, SAMPLE_RATE};

use crate::cmd::Ctx;
use crate::errors::{CliError, CliResult, EXIT_FAIL, EXIT_OK};
use crate::report::Paint;

macro_rules! vector {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../apcaw/vectors/", $name))
    };
}

const SELFTEST_JSON: &[u8] = vector!("selftest.json");
const MANIFEST_JSON: &[u8] = vector!("MANIFEST.json");
const NEGATIVES_JSON: &[u8] = vector!("negatives.json");
const CLIP_A: &[u8] = vector!("clip_A.wav");
const CLIP_A_MP3: &[u8] = vector!("clip_A_signed_v1_mp3.wav");

/// The message of the clip_A vectors.
pub const VECTOR_MESSAGE: &str = "NIPS2026: Authenticity Token for Deepfake Defense";
const TOL: f64 = 1e-9;

/// One check: name, passed, detail.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Python's `%.{p}g`.
pub fn py_g(v: f64, p: usize) -> String {
    if v == 0.0 || !v.is_finite() {
        return match v {
            _ if v.is_nan() => "nan".into(),
            _ if v.is_infinite() => if v > 0.0 { "inf" } else { "-inf" }.into(),
            _ => if v.is_sign_negative() { "-0" } else { "0" }.into(),
        };
    }
    let p = p.max(1);
    let sci = format!("{:.*e}", p - 1, v);
    let (mant, exp) = sci.split_once('e').expect("exponent");
    let x: i32 = exp.parse().expect("integer exponent");
    let trim = |s: &str| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s.to_string()
        }
    };
    if x < -4 || x >= p as i32 {
        format!("{}e{}{:02}", trim(mant), if x < 0 { '-' } else { '+' }, x.abs())
    } else {
        trim(&format!("{:.*}", (p as i32 - 1 - x).max(0) as usize, v))
    }
}

/// `x[i] = (u_i / 2^32 - 0.5) / 2`, `u_i` the MT19937 outputs of `seed`.
pub fn signal(seed: u32, n: usize) -> Vec<f64> {
    let mut mt = Mt19937::new(seed);
    (0..n).map(|_| (mt.next_u32() as f64 / 4_294_967_296.0 - 0.5) * 0.5).collect()
}

fn hex(v: &Value) -> Vec<u8> {
    v.as_str().and_then(from_hex).unwrap_or_default()
}

fn seed32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap_or([0; 32])
}

fn uint(v: &Value) -> u64 {
    v.as_u64().unwrap_or(u64::MAX)
}

fn usizes(v: &Value) -> Vec<usize> {
    v.as_array().map(|a| a.iter().map(|x| uint(x) as usize).collect()).unwrap_or_default()
}

fn pairs(v: &Value) -> Vec<[usize; 2]> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|p| {
                    let p = usizes(p);
                    [p.first().copied().unwrap_or(0), p.get(1).copied().unwrap_or(0)]
                })
                .collect()
        })
        .unwrap_or_default()
}

fn list<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v[key].as_array().map_or(&[], Vec::as_slice)
}

/// The reference's verify tuple `(verified, channel, path, profile, rs_corrected, message_hex)`.
fn tuple(r: &VerifyReport) -> Value {
    json!([r.verified, r.channel, r.path, r.profile, r.rs_corrected, r.message_hex()])
}

fn counters(r: &VerifyReport) -> Value {
    let mut v = serde_json::to_value(r).expect("report serializes");
    if let Value::Object(m) = &mut v {
        m.remove("message");
    }
    v
}

/// The reference's checks, in its order.
fn reference_checks(out: &mut Vec<Check>) -> CliResult<()> {
    let bad = |e: serde_json::Error| CliError::io(format!("selftest data corrupt: {e}"));
    let r: Value = serde_json::from_slice(SELFTEST_JSON).map_err(bad)?;
    let mut check = |name: &str, passed: bool, detail: String| out.push(Check { name: name.into(), passed, detail });
    let vec = &r["vectors"];
    let pv = &vec["payload"];
    let kp = keygen_from_seed(seed32(&pv["secret_seed_hex"]));
    check("keygen", kp.public.to_hex() == pv["public_key_hex"], String::new());
    check("seed_from_pk", u64::from(layout_seed(kp.public.as_bytes())) == uint(&pv["key_seed"]), String::new());

    let mt = list(&vec["mt19937"], "seeds");
    let ok = mt.iter().all(|e| {
        let want = usizes(&e["outputs"]);
        let mut g = Mt19937::new(uint(&e["seed"]) as u32);
        want.iter().all(|&w| g.next_u32() as usize == w)
    });
    check("mt19937", ok, format!("{} seeds", mt.len()));
    let sseed = uint(&r["signal"]["seed"]) as u32;
    let mut g = Mt19937::new(sseed);
    let direct: Vec<f64> = (0..8).map(|_| (g.next_u32() as f64 / 2f64.powi(32) - 0.5) * 0.5).collect();
    check("signal", signal(sseed, 8) == direct, String::new());

    let (mut ok, mut n) = (true, 0);
    for e in list(&vec["layout"], "seeds") {
        let seed = uint(&e["seed"]) as u32;
        for p in Profile::ALL {
            let l = Layout::from_seed(seed, &p);
            let want = &e[p.id];
            ok &= l.phase_bins == usizes(&want["phase_bins"]);
            ok &= l.mag_pairs == pairs(&want["mag_pairs"]);
            let mut bins: Vec<usize> = (p.p_lo..p.p_hi).collect();
            Mt19937::new(seed).shuffle(&mut bins);
            ok &= bins == usizes(&want["phase_bins"]);
            n += 1;
        }
    }
    check("layout", ok, format!("{n} seed/profile pairs"));

    let (mut ok_p, mut ok_s) = (true, true);
    let msgs = list(pv, "messages");
    for e in msgs {
        let m = hex(&e["message_hex"]);
        let Ok(p) = apcaw::payload::build(&kp.secret, &m) else {
            (ok_p, ok_s) = (false, false);
            continue;
        };
        ok_p &= to_hex(&p) == e["payload_hex"]
            && p.len() >= 32 + m.len()
            && to_hex(&p[2 + m.len()..p.len() - 30]) == e["signature_hex"];
        let body = apcaw::payload::unpack_bits(&p);
        for (ch, st) in e["streams_clip_A_wb"].as_object().into_iter().flatten() {
            let (rmax, name) = if ch == "phase" { (Profile::WB.rp, "phase") } else { (Profile::WB.rm, "magnitude") };
            ok_s &= match apcaw::payload::stream(&body, uint(&st["capacity"]) as usize, rmax, name) {
                Ok(mut s) => {
                    let n = s.len() as u64;
                    // np.packbits zero-pads to whole bytes
                    s.resize(s.len().div_ceil(8) * 8, 0);
                    n == uint(&st["stream_len"]) && to_hex(&apcaw::payload::pack_bits(&s)) == st["stream_hex"]
                }
                Err(_) => false,
            };
        }
    }
    check("payload", ok_p, format!("{} messages", msgs.len()));
    check("stream", ok_s, String::new());

    let (mut ok, mut n) = (true, 0);
    for e in list(&vec["rs"], "cases") {
        for c in list(e, "corrupted") {
            let got = match apcaw::rs::decode(&hex(&c["received_hex"])) {
                Ok((d, k)) => json!([true, to_hex(&d), k]),
                Err(_) => json!([false, null, null]),
            };
            ok &= got == json!([c["decodes"], c["decoded_hex"], c["n_corrected"]]);
            n += 1;
        }
    }
    check("reed-solomon", ok, format!("{n} corrupted codewords"));

    let s = &r["signal"];
    let ks = keygen_from_seed(seed32(&s["secret_seed_hex"]));
    let profile = s["profile"].as_str().and_then(Profile::by_id).unwrap_or(Profile::WB);
    let x = signal(sseed, uint(&s["n"]) as usize);
    let msg = s["message"].as_str().unwrap_or_default().as_bytes();
    let y = apcaw::sign(&x, SAMPLE_RATE, &ks.secret, msg, &profile, &Options::v1());
    let err = match &y {
        Ok(y) => usizes(&s["sample_index"])
            .iter()
            .zip(list(s, "sample_value"))
            .map(|(&i, v)| y.get(i).map_or(f64::INFINITY, |y| (y - v.as_f64().unwrap_or(f64::NAN)).abs()))
            .fold(0.0, f64::max),
        Err(_) => f64::INFINITY,
    };
    check("sign", err <= TOL, format!("max abs diff {} (tol {})", py_g(err, 3), py_g(TOL, 6)));
    let y = y.unwrap_or_default();
    let v = &r["verify"];
    let rep = apcaw::verify(&y, SAMPLE_RATE, &ks.public, None, &Options::v1(), false);
    let want = json!([v["verified"], v["channel"], v["path"], v["profile"], v["rs_corrected"], v["message_hex"]]);
    check("verify", tuple(&rep) == want, String::new());
    let mut s2 = [0u8; 32];
    s2.iter_mut().zip(1u8..).for_each(|(b, i)| *b = i);
    let wrong = keygen_from_seed(s2);
    check(
        "verify-wrong-key",
        !apcaw::verify(&y, SAMPLE_RATE, &wrong.public, None, &Options::v1(), false).verified,
        String::new(),
    );
    Ok(())
}

/// Checks against the audio vectors (Rust only; the reference bundles no audio).
fn audio_checks(out: &mut Vec<Check>) -> CliResult<()> {
    let bad = |e: String| CliError::io(format!("selftest data corrupt: {e}"));
    let manifest: Value = serde_json::from_slice(MANIFEST_JSON).map_err(|e| bad(e.to_string()))?;
    let negatives: Value = serde_json::from_slice(NEGATIVES_JSON).map_err(|e| bad(e.to_string()))?;
    let clip = read_wav(CLIP_A).and_then(|a| a.mono(None)).map_err(|e| bad(e.to_string()))?;
    let mut seed = [0u8; 32];
    seed.iter_mut().zip(0u8..).for_each(|(b, i)| *b = i);
    let kp = keygen_from_seed(seed);
    let msg = VECTOR_MESSAGE.as_bytes();

    let mut signed_v1 = None;
    for (name, opt) in [("v1", Options::v1()), ("legacy", Options::legacy())] {
        let file = format!("clip_A_signed_{name}.wav");
        let want = manifest["files"][&file]["sha256"].as_str().unwrap_or_default();
        let wav = apcaw::sign(&clip, SAMPLE_RATE, &kp.secret, msg, &Profile::WB, &opt)
            .map(|y| write_wav(&y, SAMPLE_RATE, Codec::Pcm16));
        let (passed, detail) = match &wav {
            Ok(w) => {
                let got = to_hex(&Sha256::digest(w));
                (got == want, format!("sha256 {}", &got[..16]))
            }
            Err(e) => (false, e.to_string()),
        };
        out.push(Check { name: format!("clip_A sign {name}"), passed, detail: format!("{detail}, {file}") });
        if name == "v1" {
            signed_v1 = wav.ok();
        }
    }

    let mp3 = read_wav(CLIP_A_MP3).and_then(|a| a.mono(None)).map_err(|e| bad(e.to_string()))?;
    let r = apcaw::verify(&mp3, SAMPLE_RATE, &kp.public, None, &Options::v1(), false);
    out.push(Check {
        name: "clip_A verify after mp3".into(),
        passed: r.verified && r.message.as_deref() == Some(msg),
        detail: format!(
            "channel {}, rs_corrected {}",
            r.channel.map_or("None", |c| c.as_str()),
            r.rs_corrected.map_or("None".into(), |n| n.to_string())
        ),
    });

    let (mut ok, mut n) = (true, 0);
    for c in list(&negatives, "cases") {
        let samples = match c["file"].as_str() {
            Some("clip_A.wav") => Some(clip.clone()),
            Some("clip_A_signed_v1.wav") => {
                signed_v1.as_deref().and_then(|w| read_wav(w).and_then(|a| a.mono(None)).ok())
            }
            _ => None,
        };
        let pk = <[u8; 32]>::try_from(hex(&c["public_key_hex"])).ok().map(PublicKey::from_bytes);
        ok &= match (samples, pk) {
            (Some(x), Some(pk)) => {
                let got = counters(&apcaw::verify(&x, SAMPLE_RATE, &pk, None, &Options::v1(), false));
                [
                    "verified",
                    "message_hex",
                    "channel",
                    "profile",
                    "path",
                    "rs_corrected",
                    "payload_bits",
                    "candidates_tried",
                    "rs_passes",
                    "sig_checks",
                    "reason",
                ]
                .iter()
                .all(|k| got[k] == c[k])
            }
            _ => false,
        };
        n += 1;
    }
    out.push(Check { name: "negatives".into(), passed: ok && n > 0, detail: format!("{n} cases, verifier counters") });
    Ok(())
}

/// All checks.
pub fn run_checks() -> CliResult<Vec<Check>> {
    let mut out = Vec::new();
    reference_checks(&mut out)?;
    audio_checks(&mut out)?;
    Ok(out)
}

/// `{passed, checks: [{name, passed, detail}]}`.
pub fn report_json(checks: &[Check]) -> Value {
    json!({"passed": checks.iter().all(|c| c.passed), "checks": checks})
}

pub fn run(ctx: &Ctx) -> CliResult<i32> {
    let checks = run_checks()?;
    let ok = checks.iter().all(|c| c.passed);
    if ctx.ui.json {
        ctx.ui.json(&report_json(&checks));
    } else {
        for c in &checks {
            let (word, p) = if c.passed { ("PASS", Paint::Green) } else { ("FAIL", Paint::Red) };
            let detail = if c.detail.is_empty() { String::new() } else { format!("  ({})", c.detail) };
            ctx.ui.line(&format!("{}  {}{detail}", ctx.ui.paint(word, p), c.name));
        }
        ctx.ui.line(if ok { "selftest passed" } else { "selftest FAILED" });
    }
    Ok(if ok { EXIT_OK } else { EXIT_FAIL })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_g_matches_python() {
        // python3 -c "print('%.3g %.3g %.3g %.3g %g %g %g' % (0.0, 1.2345e-12, 0.000123456, 123456.0, 1e-9, 0.5, 100000.0))"
        let got = [
            py_g(0.0, 3),
            py_g(1.2345e-12, 3),
            py_g(0.000123456, 3),
            py_g(123456.0, 3),
            py_g(1e-9, 6),
            py_g(0.5, 6),
            py_g(100000.0, 6),
        ];
        assert_eq!(got.join(" "), "0 1.23e-12 0.000123 1.23e+05 1e-09 0.5 100000");
    }

    #[test]
    fn all_checks_pass() {
        let checks = run_checks().unwrap();
        let failed: Vec<_> = checks.iter().filter(|c| !c.passed).collect();
        assert!(failed.is_empty(), "{failed:?}");
        assert_eq!(checks.len(), 15);
    }
}
