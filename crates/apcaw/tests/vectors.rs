// SPDX-License-Identifier: BSD-2-Clause
//! Conformance against the frozen vectors of the Python reference
//! (`crates/apcaw/vectors/`, a checked copy of `spec/vectors/`; format §11).
//! A missing vector fails the test, it never skips.

mod common;

use apcaw::layout::{layout_seed, Layout};
use apcaw::mt19937::Mt19937;
use apcaw::params::{n_frames, Channel, GROUP};
use apcaw::wav::{quantize_pcm16, read_wav, write_wav, Codec};
use apcaw::{keygen_from_seed, payload, read_soft, rs, sign, verify, Options, Profile, PublicKey, VerifyReport};
use common::*;
use sha2::{Digest, Sha256};

const NIPS_MSG: &[u8] = b"NIPS2026: Authenticity Token for Deepfake Defense";

fn seed_of(j: &serde_json::Value, key: &str) -> [u8; 32] {
    hex32(j[key].as_str().unwrap())
}

fn secret_seed() -> [u8; 32] {
    seed_of(&vector_json("payload.json"), "secret_seed_hex")
}

fn wav_mono(name: &str) -> Vec<f64> {
    let a = read_wav(&vector_bytes(name)).unwrap();
    assert_eq!((a.rate, a.channels), (44_100, 1), "{name}");
    a.samples
}

#[test]
fn manifest_hashes_match() {
    let m = vector_json("MANIFEST.json");
    assert!(m["format"].as_str().unwrap().starts_with("apcaw-v1"), "{}", m["format"]);
    let files = m["files"].as_object().unwrap();
    assert!(files.len() >= 13);
    for (name, meta) in files {
        let b = vector_bytes(name);
        assert_eq!(b.len() as u64, meta["bytes"].as_u64().unwrap(), "{name} size");
        assert_eq!(to_hex(&Sha256::digest(&b)), meta["sha256"].as_str().unwrap(), "{name} sha256");
    }
}

#[test]
fn mt19937_first16() {
    let j = vector_json("mt19937.json");
    let seeds = j["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 5);
    for s in seeds {
        let seed = s["seed"].as_u64().unwrap() as u32;
        let mut m = Mt19937::new(seed);
        let got: Vec<u64> = (0..16).map(|_| m.next_u32() as u64).collect();
        assert_eq!(got, u64s(&s["outputs"]), "seed {seed}");
    }
}

#[test]
fn layouts() {
    let j = vector_json("layout.json");
    for s in j["seeds"].as_array().unwrap() {
        let seed = s["seed"].as_u64().unwrap() as u32;
        for (id, prof) in [("wb", Profile::WB), ("nb", Profile::NB)] {
            let got = Layout::from_seed(seed, &prof);
            let want_p: Vec<usize> = u64s(&s[id]["phase_bins"]).iter().map(|&v| v as usize).collect();
            let want_m: Vec<[usize; 2]> = s[id]["mag_pairs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let p = u64s(p);
                    [p[0] as usize, p[1] as usize]
                })
                .collect();
            assert_eq!(got.phase_bins, want_p, "phase bins, seed {seed} {id}");
            assert_eq!(got.mag_pairs, want_m, "mag pairs, seed {seed} {id}");
        }
    }
}

#[test]
fn payloads_headers_and_streams() {
    let j = vector_json("payload.json");
    let kp = keygen_from_seed(seed_of(&j, "secret_seed_hex"));
    assert_eq!(kp.public.to_hex(), j["public_key_hex"].as_str().unwrap());
    assert_eq!(layout_seed(kp.public.as_bytes()) as u64, j["key_seed"].as_u64().unwrap());

    let clip = wav_mono("clip_A.wav");
    let cap = &j["clip_A_capacity_wb"];
    let frames = n_frames(clip.len());
    let groups = frames / GROUP;
    assert_eq!(frames as u64, cap["frames"].as_u64().unwrap());
    assert_eq!(groups as u64, cap["groups"].as_u64().unwrap());
    assert_eq!((groups * Profile::WB.bp()) as u64, cap["phase"].as_u64().unwrap());
    assert_eq!((groups * Profile::WB.bm()) as u64, cap["magnitude"].as_u64().unwrap());

    let msgs = j["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 4);
    for m in msgs {
        let msg = hex(m["message_hex"].as_str().unwrap());
        assert_eq!(msg.len() as u64, m["message_len"].as_u64().unwrap());
        let what = format!("message of {} bytes", msg.len());
        assert_eq!(to_hex(&kp.secret.sign(&msg)), m["signature_hex"].as_str().unwrap(), "{what}");
        let p = payload::build(&kp.secret, &msg).unwrap();
        assert_eq!(to_hex(&p), m["payload_hex"].as_str().unwrap(), "{what}");
        let body = payload::unpack_bits(&p);
        assert_eq!(body.len() as u64, m["payload_bits"].as_u64().unwrap());
        let h: String = payload::header_bits(body.len() as u32).iter().map(|b| char::from(b'0' + b)).collect();
        assert_eq!(h, m["header_bits"].as_str().unwrap(), "{what}");
        for ch in Channel::ALL {
            let w = &m["streams_clip_A_wb"][ch.as_str()];
            let c = w["capacity"].as_u64().unwrap() as usize;
            let s = payload::stream(&body, c, Profile::WB.max_replicas(ch), ch.as_str()).unwrap();
            assert_eq!(s.len() as u64, w["stream_len"].as_u64().unwrap(), "{what} {ch:?}");
            assert_eq!(((s.len() - 96) / body.len()) as u64, w["replicas"].as_u64().unwrap());
            let mut padded = s.clone();
            padded.resize(s.len().div_ceil(8) * 8, 0);
            assert_eq!(to_hex(&payload::pack_bits(&padded)), w["stream_hex"].as_str().unwrap());
        }
    }
}

#[test]
fn reed_solomon() {
    let j = vector_json("rs.json");
    let cases = j["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let mut rejected = 0;
    for c in cases {
        let msg = hex(c["message_hex"].as_str().unwrap());
        assert_eq!(to_hex(&rs::encode(&msg)), c["codeword_hex"].as_str().unwrap());
        for k in c["corrupted"].as_array().unwrap() {
            let recv = hex(k["received_hex"].as_str().unwrap());
            let n = k["n_errors"].as_u64().unwrap();
            match rs::decode_chunked(&recv) {
                Ok((m, ncorr)) => {
                    assert!(k["decodes"].as_bool().unwrap(), "{n} errors: reedsolo rejects");
                    assert_eq!(to_hex(&m), k["decoded_hex"].as_str().unwrap());
                    assert_eq!(ncorr as u64, k["n_corrected"].as_u64().unwrap());
                }
                Err(_) => {
                    assert!(!k["decodes"].as_bool().unwrap(), "{n} errors: reedsolo decodes");
                    rejected += 1;
                }
            }
        }
    }
    assert!(rejected > 0, "the 16-error words must exercise the rejection path");
}

fn signed_v1() -> Vec<f64> {
    let kp = keygen_from_seed(secret_seed());
    sign(&wav_mono("clip_A.wav"), 44_100, &kp.secret, NIPS_MSG, &Profile::WB, &Options::v1()).unwrap()
}

#[test]
fn embedding_matches_float_and_pcm16() {
    let y = signed_v1();
    let want = read_f64(&vector_bytes("clip_A_signed_v1.f64"));
    let d = max_abs_diff(&y, &want);
    assert!(d <= 1e-9, "max |Δ| = {d:e}");
    eprintln!("embedding: max |y_rust - y_python| = {d:e}");

    // .npy: same samples behind a v1.0 header ('<f8', 1-D)
    let npy = vector_bytes("clip_A_signed_v1.npy");
    assert_eq!(&npy[..6], b"\x93NUMPY");
    let hlen = u16::from_le_bytes([npy[8], npy[9]]) as usize;
    let header = std::str::from_utf8(&npy[10..10 + hlen]).unwrap();
    assert!(header.contains("'descr': '<f8'") && header.contains("'fortran_order': False"), "{header}");
    assert_eq!(read_f64(&npy[10 + hlen..]), want);

    // PCM16: identical file bytes (quantization + the canonical 44-byte header)
    let wav = vector_bytes("clip_A_signed_v1.wav");
    let q = quantize_pcm16(&y);
    let qw = quantize_pcm16(&want);
    let diff = q.iter().zip(&qw).filter(|(a, b)| a != b).count();
    assert_eq!(diff, 0, "{diff} PCM16 samples differ");
    assert_eq!(write_wav(&y, 44_100, Codec::Pcm16), wav, "WAV bytes differ");
}

fn check_report(got: &VerifyReport, want: &serde_json::Value, what: &str) {
    let s = |k: &str| want[k].as_str().map(str::to_owned);
    let u = |k: &str| want[k].as_u64().map(|v| v as usize);
    assert_eq!(got.verified, want["verified"].as_bool().unwrap(), "{what}: verified ({})", got.reason);
    assert_eq!(got.message_hex(), s("message_hex"), "{what}: message");
    assert_eq!(got.channel.map(|c| c.as_str().to_owned()), s("channel"), "{what}: channel");
    assert_eq!(got.profile.map(str::to_owned), s("profile"), "{what}: profile");
    assert_eq!(got.path.map(|p| p.as_str().to_owned()), s("path"), "{what}: path");
    assert_eq!(got.rs_corrected, u("rs_corrected"), "{what}: rs_corrected");
    assert_eq!(got.payload_bits, u("payload_bits"), "{what}: payload_bits");
    assert_eq!(got.candidates_tried, u("candidates_tried").unwrap(), "{what}: candidates_tried");
    assert_eq!(got.rs_passes, u("rs_passes").unwrap(), "{what}: rs_passes");
    assert_eq!(got.sig_checks, u("sig_checks").unwrap(), "{what}: sig_checks");
    assert_eq!(got.reason, s("reason").unwrap(), "{what}: reason");
}

#[test]
fn soft_values_and_verify_results() {
    let j = vector_json("soft_A.json");
    let pk = PublicKey::from_bytes(seed_of(&j, "public_key_hex"));
    let files = j["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    for f in files {
        let name = f["file"].as_str().unwrap();
        let legacy = f["options"] == "legacy";
        let o = if legacy { Options::legacy() } else { Options::v1() };
        assert_eq!(f["profile"], "wb");
        let x = wav_mono(name);
        let layout = Layout::for_key(pk.as_bytes(), &Profile::WB, o.seed);
        let soft = read_soft(&x, &layout, &Profile::WB, o.erasure_tau);
        let (wp, wm) = (f64s(&f["phase_soft"]), f64s(&f["mag_soft"]));
        let (dp, dm) = (max_abs_diff(&soft.phase, &wp), max_abs_diff(&soft.magnitude, &wm));
        eprintln!("{name}: soft max |Δ| phase {dp:e}, magnitude {dm:e}");
        assert!(dp <= 1e-9 && dm <= 1e-9, "{name}: phase {dp:e}, magnitude {dm:e}");

        let prof = legacy.then_some(&Profile::WB);
        let r = verify(&x, 44_100, &pk, prof, &o, false);
        check_report(&r, &f["verify"], name);
    }
}

#[test]
fn negatives() {
    let j = vector_json("negatives.json");
    let cases = j["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for c in cases {
        let name = c["file"].as_str().unwrap();
        let pk = PublicKey::from_bytes(seed_of(c, "public_key_hex"));
        let r = verify(&wav_mono(name), 44_100, &pk, None, &Options::v1(), false);
        check_report(&r, c, &format!("{name} ({})", c["case"].as_str().unwrap()));
    }
}

#[test]
fn wrong_key_is_the_other_secret() {
    let other: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let j = vector_json("negatives.json");
    let wrong = j["cases"].as_array().unwrap().iter().find(|c| c["case"] == "wrong key").unwrap();
    assert_eq!(keygen_from_seed(other).public.to_hex(), wrong["public_key_hex"].as_str().unwrap());
}

#[test]
fn rust_signed_file_verifies_like_python() {
    // the Rust PCM16 output is byte-identical, so it must verify exactly as the reference file
    let kp = keygen_from_seed(secret_seed());
    let bytes = write_wav(&signed_v1(), 44_100, Codec::Pcm16);
    let x = read_wav(&bytes).unwrap().samples;
    let r = verify(&x, 44_100, &kp.public, None, &Options::v1(), false);
    let j = vector_json("soft_A.json");
    let want = j["files"].as_array().unwrap().iter().find(|f| f["file"] == "clip_A_signed_v1.wav").unwrap();
    check_report(&r, &want["verify"], "rust-signed clip_A");
}
