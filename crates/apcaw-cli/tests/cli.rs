// SPDX-License-Identifier: BSD-2-Clause
//! End-to-end tests of the `apcaw` binary: the exit-code table, stdin /
//! stdout, output codecs, ffmpeg decoding, and every subcommand. The
//! `vectors_*` tests compare the CLI's output with the frozen conformance
//! vectors of `crates/apcaw/vectors/`; the others are self-consistency tests.
//! ffmpeg (with libmp3lame) must be on PATH.

mod common;

use std::fs;
use std::io::Write;
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

use predicates::prelude::*;
use predicates::str::{contains, starts_with};
use serde_json::{json, Value};

use apcaw::wav::{read_wav, write_wav, Codec};
use common::*;

const MSG: &str = "hello NIPS";

/// The keys of a verify report, in the Python CLI's order.
const VERIFY_KEYS: [&str; 13] = [
    "file",
    "verified",
    "message",
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
];

fn keys_of(v: &Value) -> Vec<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

// ---------------------------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------------------------

#[test]
fn help_version_and_bad_syntax() {
    apcaw()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Exit codes:").and(contains("130  interrupted")).and(contains("Global options:")));
    apcaw().arg("--version").assert().success().stdout(format!("apcaw {}\n", env!("CARGO_PKG_VERSION")));
    // no subcommand, an unknown one, a missing required flag, a bad value: usage (2)
    apcaw().assert().code(2);
    apcaw().arg("frobnicate").assert().code(2);
    apcaw().args(["verify", "-i", "a.wav"]).assert().code(2);
    apcaw().args(["--threads", "0", "selftest"]).assert().code(2);
    apcaw().args(["sign", "-i", "a", "-o", "b", "-k", "c", "-m", "x", "--profile", "xb"]).assert().code(2);
    apcaw().args(["verify", "-i", "a", "-p", "k", "--scan", "--resync"]).assert().code(2);
}

#[test]
fn sign_verify_and_wrong_key() {
    let d = scratch("sign_verify_and_wrong_key");
    let (sk, pk) = keygen(&d, "k");
    let (_, wrong) = keygen(&d, "w");
    let out = d.join("s.wav");
    apcaw()
        .args(["sign", "-i", s(&media(1)), "-o", s(&out), "-k", s(&sk), "-m", MSG])
        .assert()
        .success()
        .stdout(starts_with("signed ").and(contains("closed-loop verify ok")));
    apcaw()
        .args(["verify", "-i", s(&out), "-p", s(&pk)])
        .assert()
        .code(0)
        .stdout(starts_with("VERIFIED  message='hello NIPS'  channel=phase profile=wb path=header rs_corrected="));
    apcaw()
        .args(["verify", "-i", s(&out), "-p", s(&wrong)])
        .assert()
        .code(1)
        .stdout(starts_with("NOT VERIFIED  no candidate passed RS decoding (460 tried)\n"));
    // the unsigned input under the right key
    apcaw().args(["verify", "-i", s(&media(1)), "-p", s(&pk)]).assert().code(1).stdout(starts_with("NOT VERIFIED"));
}

#[test]
fn io_errors_exit_3() {
    let d = scratch("io_errors_exit_3");
    let (sk, pk) = keygen(&d, "k");
    let signed = d.join("s.wav");
    sign(&media(0), &signed, &sk, MSG, &[]);
    let missing = d.join("missing.wav");
    apcaw()
        .args(["verify", "-i", s(&missing), "-p", s(&pk)])
        .assert()
        .code(3)
        .stderr(contains("cannot read").and(contains("no such file")));
    apcaw()
        .args(["verify", "-i", s(&signed), "-p", s(&d.join("none.pub"))])
        .assert()
        .code(3)
        .stderr(contains("cannot read public key"));
    let junk = d.join("junk.wav");
    fs::write(&junk, b"not audio at all").unwrap();
    apcaw().args(["verify", "-i", s(&junk), "-p", s(&pk)]).assert().code(3);
    // a write failure
    apcaw()
        .args(["sign", "-i", s(&media(0)), "-o", s(&d.join("no/dir/x.wav")), "-k", s(&sk), "-m", "x"])
        .assert()
        .code(3)
        .stderr(contains("cannot write"));
    // non-WAV input without ffmpeg, by flag and by environment
    let mp3 = d.join("s.mp3");
    to_mp3(&signed, &mp3);
    apcaw()
        .args(["--ffmpeg", "/nonexistent/ffmpeg", "verify", "-i", s(&mp3), "-p", s(&pk)])
        .assert()
        .code(3)
        .stderr(contains("ffmpeg not found"));
    apcaw().env("APCAW_FFMPEG", "/nonexistent/ffmpeg").args(["verify", "-i", s(&mp3), "-p", s(&pk)]).assert().code(3);
    // WAV needs no ffmpeg
    apcaw().args(["--ffmpeg", "/nonexistent/ffmpeg", "verify", "-i", s(&signed), "-p", s(&pk)]).assert().code(0);
}

#[test]
fn usage_errors_exit_2() {
    let d = scratch("usage_errors_exit_2");
    let (sk, pk) = keygen(&d, "k");
    let bad = d.join("bad.key");
    fs::write(&bad, "junk\n").unwrap();
    let out = d.join("s.wav");
    apcaw()
        .args(["sign", "-i", s(&media(0)), "-o", s(&out), "-k", s(&bad), "-m", "x"])
        .assert()
        .code(2)
        .stderr(contains("malformed secret key"));
    apcaw()
        .args(["verify", "-i", s(&media(0)), "-p", s(&bad)])
        .assert()
        .code(2)
        .stderr(contains("malformed public key (5 bytes; expected raw 32 B, 64 hex, or PEM)"));
    let long = "x".repeat(160);
    apcaw()
        .args(["sign", "-i", s(&media(0)), "-o", s(&out), "-k", s(&sk), "-m", &long])
        .assert()
        .code(2)
        .stderr(contains("message too long: 160 bytes > 159"));
    assert!(!out.exists());
    // 159 bytes fit
    sign(&media(0), &out, &sk, &"x".repeat(159), &[]);
    apcaw().args(["-q", "verify", "-i", s(&out), "-p", s(&pk)]).assert().code(0);
    apcaw()
        .args(["verify", "-i", s(&out), "-p", s(&pk), "--channel", "1"])
        .assert()
        .code(2)
        .stderr(contains("channel 1 requested but the input has 1 channel(s)"));
    apcaw().args(["layout", "--seed", "4294967296"]).assert().code(2).stderr("apcaw: seed must be in [0, 2**32)\n");
    apcaw().args(["layout", "--seed", "-1"]).assert().code(2);
}

#[test]
fn existing_outputs_need_y() {
    let d = scratch("existing_outputs_need_y");
    let (sk, pk) = keygen(&d, "k");
    let out = d.join("s.wav");
    fs::write(&out, b"keep me").unwrap();
    apcaw()
        .args(["sign", "-i", s(&media(0)), "-o", s(&out), "-k", s(&sk), "-m", MSG])
        .assert()
        .code(2)
        .stderr(contains("exists (use -y to overwrite)"));
    assert_eq!(fs::read(&out).unwrap(), b"keep me");
    for flag in ["-y", "--overwrite", "--force"] {
        apcaw().args([flag, "sign", "-i", s(&media(0)), "-o", s(&out), "-k", s(&sk), "-m", MSG]).assert().success();
    }
    apcaw().args(["-q", "verify", "-i", s(&out), "-p", s(&pk)]).assert().code(0);
    // keygen refuses too, and leaves both files alone
    let before = (fs::read(&sk).unwrap(), fs::read(&pk).unwrap());
    apcaw()
        .args(["keygen", "--secret-out", s(&sk), "--public-out", s(&pk)])
        .assert()
        .code(2)
        .stderr(contains("use --force to overwrite"));
    assert_eq!(before, (fs::read(&sk).unwrap(), fs::read(&pk).unwrap()));
    apcaw().args(["keygen", "--secret-out", s(&sk), "--public-out", s(&pk), "--force"]).assert().success();
    assert_ne!(before.0, fs::read(&sk).unwrap());
}

#[cfg(unix)]
#[test]
fn interrupt_exits_130_and_leaves_no_output() {
    let d = scratch("interrupt_exits_130");
    let (sk, _) = keygen(&d, "k");
    let out = d.join("s.wav");
    // `-i -` blocks on the open stdin until the signal arrives
    let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin!("apcaw"))
        .args(["sign", "-i", "-", "-o", s(&out), "-k", s(&sk), "-m", "x"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&fs::read(media(0)).unwrap()[..1000]).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let kill = StdCommand::new("kill").args(["-INT", &child.id().to_string()]).status().unwrap();
    assert!(kill.success());
    let status = child.wait().unwrap();
    drop(stdin);
    assert_eq!(status.code(), Some(130));
    assert_eq!(fs::read_dir(&d).unwrap().count(), 2, "only the key files remain");
}

// ---------------------------------------------------------------------------------------------
// Conformance vectors through the CLI
// ---------------------------------------------------------------------------------------------

#[test]
fn vectors_signed_wavs_are_byte_identical() {
    let d = scratch("vectors_signed_wavs");
    let (sk, pk) = vector_keys(&d);
    for (name, extra) in [("clip_A_signed_v1.wav", &[][..]), ("clip_A_signed_legacy.wav", &["--legacy"][..])] {
        let out = d.join(name);
        sign(&vector("clip_A.wav"), &out, &sk, VECTOR_MESSAGE, extra);
        assert!(fs::read(&out).unwrap() == fs::read(vector(name)).unwrap(), "{name} differs");
    }
    // and through stdin / stdout
    let a = apcaw()
        .args(["sign", "-i", "-", "-o", "-", "-k", s(&sk), "-m", VECTOR_MESSAGE])
        .write_stdin(fs::read(vector("clip_A.wav")).unwrap())
        .assert()
        .success()
        .stderr(starts_with("signed -: "));
    assert!(a.get_output().stdout == fs::read(vector("clip_A_signed_v1.wav")).unwrap());
    // the verify results of soft_A.json ('v1': default options, profile
    // auto; 'legacy': the legacy verifier, profile wb)
    for e in vector_json("soft_A.json")["files"].as_array().unwrap() {
        let file = vector(e["file"].as_str().unwrap());
        let mut c = apcaw();
        c.args(["--json", "verify", "-i", s(&file), "-p", s(&pk)]);
        if e["options"] == "legacy" {
            c.args(["--legacy", "--profile", "wb"]);
        }
        let got = json_out(&c.assert().code(0).get_output().stdout);
        assert_eq!(got["message"], VECTOR_MESSAGE);
        for (k, v) in e["verify"].as_object().unwrap() {
            assert_eq!(&got[k], v, "{}: {k}", e["file"]);
        }
    }
}

#[test]
fn vectors_negatives_and_counters() {
    let d = scratch("vectors_negatives");
    let neg = vector_json("negatives.json");
    for (i, c) in neg["cases"].as_array().unwrap().iter().enumerate() {
        let pk = hex_key(&d, &format!("n{i}.pub"), c["public_key_hex"].as_str().unwrap());
        let file = vector(c["file"].as_str().unwrap());
        let a = apcaw().args(["--json", "verify", "-i", s(&file), "-p", s(&pk)]).assert().code(1);
        let got = json_out(&a.get_output().stdout);
        assert_eq!(keys_of(&got), VERIFY_KEYS);
        for k in &VERIFY_KEYS[1..] {
            if *k != "message" {
                assert_eq!(got[k], c[k], "{}: {k}", c["case"]);
            }
        }
    }
}

#[test]
fn vectors_layout() {
    let d = scratch("vectors_layout");
    let (_, pk) = vector_keys(&d);
    for e in vector_json("layout.json")["seeds"].as_array().unwrap() {
        let seed = e["seed"].as_u64().or_else(|| e["seed"].as_str().and_then(|s| s.parse().ok())).unwrap();
        let a = apcaw().args(["--json", "layout", "--seed", &seed.to_string()]).assert().success();
        let got = json_out(&a.get_output().stdout);
        assert_eq!(got["seed"], seed);
        for p in ["wb", "nb"] {
            assert_eq!(got[p]["phase_bins"], e[p]["phase_bins"], "seed {seed} {p}");
            assert_eq!(got[p]["mag_pairs"], e[p]["mag_pairs"], "seed {seed} {p}");
        }
        let a = apcaw().args(["--json", "layout", "--seed", &seed.to_string(), "--profile", "nb"]).assert().success();
        assert_eq!(keys_of(&json_out(&a.get_output().stdout)), ["seed", "nb"]);
    }
    let key_seed = vector_json("payload.json")["key_seed"].clone();
    let a = apcaw().args(["--json", "layout", "-p", s(&pk)]).assert().success();
    assert_eq!(json_out(&a.get_output().stdout)["seed"], key_seed);
    apcaw().args(["layout", "-p", s(&pk)]).assert().success().stdout(contains(key_seed.to_string()));
}

#[test]
fn selftest_passes() {
    let a = apcaw().arg("selftest").assert().success().stdout(contains("selftest passed"));
    let out = text(&a.get_output().stdout);
    assert_eq!(out.lines().filter(|l| l.starts_with("PASS  ")).count(), 15, "{out}");
    let a = apcaw().args(["--json", "selftest"]).assert().success();
    let v = json_out(&a.get_output().stdout);
    assert_eq!(v["passed"], true);
    assert_eq!(v["checks"].as_array().unwrap().len(), 15);
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

#[test]
fn key_formats() {
    let d = scratch("key_formats");
    let (sk, pk) = keygen(&d, "raw");
    assert_eq!((fs::read(&sk).unwrap().len(), fs::read(&pk).unwrap().len()), (32, 32));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&sk).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let (psk, ppk) = (d.join("pem.sec"), d.join("pem.pub"));
    apcaw()
        .args(["keygen", "--secret-out", s(&psk), "--public-out", s(&ppk), "--pem"])
        .assert()
        .success()
        .stdout(contains("public key").and(contains("layout seed")));
    assert!(fs::read_to_string(&psk).unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(fs::read_to_string(&ppk).unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));
    let out = d.join("s.wav");
    sign(&media(2), &out, &psk, MSG, &[]);
    apcaw().args(["-q", "verify", "-i", s(&out), "-p", s(&ppk)]).assert().code(0);
    // the raw public key as 64 hex digits
    let hex: String = fs::read(&pk).unwrap().iter().map(|b| format!("{b:02x}")).collect();
    let hpk = hex_key(&d, "hex.pub", &hex);
    apcaw().args(["-q", "verify", "-i", s(&out), "-p", s(&hpk)]).assert().code(1);
    sign(&media(2), &out, &sk, MSG, &["-y"]);
    apcaw().args(["-q", "verify", "-i", s(&out), "-p", s(&hpk)]).assert().code(0);
    // -q keygen: only the "wrote" line
    let a = apcaw()
        .args(["-q", "keygen", "--secret-out", s(&d.join("q.sec")), "--public-out", s(&d.join("q.pub"))])
        .assert()
        .success();
    assert_eq!(text(&a.get_output().stdout).lines().count(), 1);
}

// ---------------------------------------------------------------------------------------------
// Input and output
// ---------------------------------------------------------------------------------------------

#[test]
fn stdin_and_stdout() {
    let d = scratch("stdin_and_stdout");
    let (sk, pk) = keygen(&d, "k");
    let file = d.join("s.wav");
    sign(&media(0), &file, &sk, MSG, &[]);
    let a = apcaw()
        .args(["sign", "-i", "-", "-o", "-", "-k", s(&sk), "-m", MSG])
        .write_stdin(fs::read(media(0)).unwrap())
        .assert()
        .success();
    let piped = a.get_output().stdout.clone();
    assert!(piped == fs::read(&file).unwrap(), "-o - differs from the file output");
    // all text goes to stderr when stdout carries audio
    assert!(text(&a.get_output().stderr).contains("closed-loop verify ok"));
    apcaw()
        .args(["verify", "-i", "-", "-p", s(&pk)])
        .write_stdin(piped.clone())
        .assert()
        .code(0)
        .stdout(contains("input     -: 10.00 s"));
    // non-WAV on stdin goes through ffmpeg
    let mp3 = d.join("s.mp3");
    to_mp3(&file, &mp3);
    apcaw().args(["-q", "verify", "-i", "-", "-p", s(&pk)]).write_stdin(fs::read(&mp3).unwrap()).assert().code(0);
    apcaw()
        .args(["sign", "-i", "-", "-o", "-", "-k", s(&sk), "-m", MSG, "--sidecar"])
        .write_stdin(fs::read(media(0)).unwrap())
        .assert()
        .code(2);
}

#[test]
fn output_codecs() {
    let d = scratch("output_codecs");
    let (sk, pk) = keygen(&d, "k");
    let u16le = |b: &[u8], at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
    for (codec, bits, float) in [("pcm_s24le", 24, false), ("f32", 32, true)] {
        let out = d.join(format!("{codec}.wav"));
        sign(&media(2), &out, &sk, codec, &["--codec", codec]);
        let b = fs::read(&out).unwrap();
        assert_eq!(u16le(&b, 34), bits, "{codec}: bits per sample");
        // WAVE_FORMAT_EXTENSIBLE: the sub-format GUID starts with the format tag
        let tag = if u16le(&b, 20) == 0xfffe { u16le(&b, 44) } else { u16le(&b, 20) };
        assert_eq!(tag, if float { 3 } else { 1 }, "{codec}: format tag");
        apcaw()
            .args(["-q", "verify", "-i", s(&out), "-p", s(&pk)])
            .assert()
            .code(0)
            .stdout(format!("VERIFIED  message='{codec}'  channel=phase profile=wb path=header rs_corrected=0\n"));
    }
    // FLAC, by flag and by extension; STREAMINFO carries the sample count
    for (name, extra) in [("a.flac", &[][..]), ("b.out", &["--codec", "flac"][..])] {
        let out = d.join(name);
        sign(&media(2), &out, &sk, "flac", extra);
        let b = fs::read(&out).unwrap();
        assert_eq!(&b[..4], b"fLaC");
        let total = (u64::from(b[21] & 0x0f) << 32) | u64::from(u32::from_be_bytes([b[22], b[23], b[24], b[25]]));
        assert_eq!(total, 441_000);
        apcaw().args(["verify", "-i", s(&out), "-p", s(&pk)]).assert().code(0).stdout(contains("mono, flac (ffmpeg)"));
    }
    // FLAC and -o -
    let a = apcaw()
        .args(["sign", "-i", s(&media(2)), "-o", "-", "--codec", "flac", "-k", s(&sk), "-m", "x"])
        .assert()
        .success();
    assert_eq!(&a.get_output().stdout[..4], b"fLaC");
}

#[test]
fn ffmpeg_inputs_mp3_resample_downmix() {
    let d = scratch("ffmpeg_inputs");
    let (sk, pk) = keygen(&d, "k");
    let signed = d.join("s.wav");
    sign(&media(0), &signed, &sk, MSG, &[]);
    let mp3 = d.join("s.mp3");
    to_mp3(&signed, &mp3);
    apcaw()
        .args(["verify", "-i", s(&mp3), "-p", s(&pk)])
        .assert()
        .code(0)
        .stdout(starts_with("VERIFIED  message='hello NIPS'").and(contains("mp3 (ffmpeg)")));
    // stereo 48 kHz FLAC: resampled and downmixed, each with a note
    let st = d.join("s48.flac");
    ffmpeg(&["-i", s(&signed), "-ac", "2", "-ar", "48000", s(&st)]);
    apcaw()
        .args(["verify", "-i", s(&st), "-p", s(&pk)])
        .assert()
        .code(0)
        .stdout(starts_with("VERIFIED  message='hello NIPS'"))
        .stderr(
            contains("note: downmixed 2 channels to mono (channel mean)")
                .and(contains("note: resampled 48000 Hz -> 44100 Hz (ffmpeg aresample)")),
        );
    apcaw().args(["-q", "verify", "-i", s(&st), "-p", s(&pk)]).assert().code(0).stderr(predicate::str::is_empty());
    apcaw().args(["-q", "verify", "-i", s(&st), "-p", s(&pk), "--channel", "1"]).assert().code(0);
    apcaw().args(["-q", "verify", "-i", s(&st), "-p", s(&pk), "--channel", "2"]).assert().code(2);
    // a stereo WAV whose right channel is the signed one; the left is silence
    let a = read_wav(&fs::read(&signed).unwrap()).unwrap().mono(None).unwrap();
    let st16 = d.join("lr.wav");
    ffmpeg(&[
        "-i",
        s(&signed),
        "-filter_complex",
        "[0:a]asplit[a][b];[a]volume=0[l];[l][b]amerge=inputs=2",
        "-c:a",
        "pcm_s16le",
        s(&st16),
    ]);
    apcaw().args(["-q", "verify", "-i", s(&st16), "-p", s(&pk), "--channel", "1"]).assert().code(0);
    // re-signing a 48 kHz input writes 44.1 kHz
    let out = d.join("r.wav");
    sign(&st, &out, &sk, "again", &["-y"]);
    let r = read_wav(&fs::read(&out).unwrap()).unwrap();
    assert_eq!((r.rate, r.channels), (44_100, 1));
    assert!(r.mono(None).unwrap().len().abs_diff(a.len()) < 64);
}

// ---------------------------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------------------------

#[test]
fn json_and_quiet_output() {
    let d = scratch("json_and_quiet_output");
    let (sk, pk) = keygen(&d, "k");
    let out = d.join("s.wav");
    let a = apcaw()
        .args(["--json", "sign", "-i", s(&media(1)), "-o", s(&out), "-k", s(&sk), "-m", MSG, "--sidecar"])
        .assert()
        .success();
    let v = json_out(&a.get_output().stdout);
    assert_eq!(v["signed"], true);
    assert_eq!(v["closed_loop"]["verified"], true);
    assert_eq!(v["message_hex"], "68656c6c6f204e495053");
    let side: Value = serde_json::from_slice(&fs::read(d.join("s.wav.apcaw.json")).unwrap()).unwrap();
    assert_eq!(side["signed"], true);
    let a = apcaw().args(["--json", "verify", "-i", s(&out), "-p", s(&pk)]).assert().code(0);
    let v = json_out(&a.get_output().stdout);
    assert_eq!(keys_of(&v), VERIFY_KEYS);
    assert_eq!((v["verified"].clone(), v["message"].clone()), (json!(true), json!(MSG)));
    let a = apcaw().args(["-q", "verify", "-i", s(&out), "-p", s(&pk)]).assert().code(0).stderr("");
    assert_eq!(text(&a.get_output().stdout).lines().count(), 1);
    let a = apcaw().args(["verify", "-i", s(&out), "-p", s(&pk)]).assert().code(0);
    assert!(text(&a.get_output().stdout).lines().skip(1).all(|l| l.starts_with("  ")));
    // no closed loop: the report says so
    let a = apcaw()
        .args(["--json", "sign", "-i", s(&media(1)), "-o", s(&out), "-k", s(&sk), "-m", MSG, "-y", "--no-closed-loop"])
        .assert()
        .success();
    assert_eq!(json_out(&a.get_output().stdout)["closed_loop"], Value::Null);
}

#[test]
fn profile_auto_and_nb() {
    let d = scratch("profile_auto_and_nb");
    let (sk, pk) = keygen(&d, "k");
    let out = d.join("s.wav");
    // LibriSpeech is 16 kHz speech: little energy above 4 kHz
    apcaw()
        .args(["sign", "-i", s(&media(0)), "-o", s(&out), "-k", s(&sk), "-m", MSG, "--profile", "auto"])
        .assert()
        .success()
        .stdout(contains("profile nb").and(contains("profile   auto -> nb (energy above 4 kHz")));
    let a = apcaw()
        .args(["--json", "sign", "-i", s(&media(0)), "-o", s(&out), "-k", s(&sk), "-m", MSG, "--profile", "auto", "-y"])
        .assert()
        .success();
    let v = json_out(&a.get_output().stdout);
    assert_eq!(v["profile"], "nb");
    let f = v["profile_auto"]["energy_above_4khz"].as_f64().unwrap();
    assert!(f < 0.05 && v["profile_auto"]["threshold"] == 0.05, "{v}");
    apcaw()
        .args(["-q", "verify", "-i", s(&out), "-p", s(&pk), "--profile", "nb"])
        .assert()
        .code(0)
        .stdout(contains("profile=nb"));
    // white noise has most of its energy above 4 kHz
    let noise = d.join("noise.wav");
    let mut mt = apcaw::mt19937::Mt19937::new(7);
    let x: Vec<f64> = (0..441_000).map(|_| (f64::from(mt.next_u32()) / 4_294_967_296.0 - 0.5) * 0.5).collect();
    fs::write(&noise, write_wav(&x, 44_100, Codec::Pcm16)).unwrap();
    apcaw()
        .args(["sign", "-i", s(&noise), "-o", s(&d.join("n.wav")), "-k", s(&sk), "-m", MSG, "--profile", "auto"])
        .assert()
        .success()
        .stdout(contains("profile wb").and(contains("auto -> wb")));
}

#[test]
fn legacy_round_trip() {
    let d = scratch("legacy_round_trip");
    let (sk, pk) = keygen(&d, "k");
    let out = d.join("s.wav");
    sign(&media(1), &out, &sk, MSG, &["--legacy"]);
    for flag in ["--legacy", "--legacy-verifier"] {
        apcaw()
            .args(["-q", "verify", "-i", s(&out), "-p", s(&pk), flag])
            .assert()
            .code(0)
            .stdout(starts_with("VERIFIED  message='hello NIPS'"));
    }
}

#[test]
fn inspect_report() {
    let d = scratch("inspect_report");
    let (sk, pk) = keygen(&d, "k");
    let out = d.join("s.wav");
    sign(&media(1), &out, &sk, MSG, &[]);
    let a = apcaw().args(["--json", "inspect", "-i", s(&out), "-p", s(&pk)]).assert().success();
    let v = json_out(&a.get_output().stdout);
    assert_eq!(keys_of(&v), ["file", "samples", "frames", "seed", "profiles"]);
    assert_eq!((v["samples"].clone(), v["frames"].clone()), (json!(441_000), json!(215)));
    assert_eq!(v["profiles"]["wb"]["groups"], 26);
    assert_eq!(v["profiles"]["wb"]["phase"]["capacity"], 6240);
    let a = apcaw().args(["--json", "layout", "-p", s(&pk)]).assert().success();
    assert_eq!(json_out(&a.get_output().stdout)["seed"], v["seed"]);
    apcaw().args(["inspect", "-i", s(&out), "-p", s(&pk)]).assert().success();
}

#[test]
fn batch_verify_ndjson() {
    let d = scratch("batch_verify_ndjson");
    let (sk, pk) = keygen(&d, "k");
    let files: Vec<_> = (0..3)
        .map(|i| {
            let out = d.join(format!("s{i}.wav"));
            sign(&media(i), &out, &sk, &format!("clip {i}"), &[]);
            out
        })
        .collect();
    let (missing, unsigned) = (d.join("missing.wav"), media(1));
    let list = [s(&files[2]), s(&files[0]), s(&missing), s(&unsigned), s(&files[1])];
    for jobs in ["1", "4"] {
        let a = apcaw()
            .args(["batch-verify", "-p", s(&pk), "--jobs", jobs])
            .args(list)
            .assert()
            .code(3)
            .stderr(contains("batch-verify: 3/5 verified"));
        let lines: Vec<Value> = text(&a.get_output().stdout).lines().map(|l| json_out(l.as_bytes())).collect();
        assert_eq!(lines.len(), 5);
        for (l, f) in lines.iter().zip(list) {
            assert_eq!(l["file"], f);
        }
        assert_eq!(lines[0]["message"], "clip 2");
        assert_eq!(lines[1]["message"], "clip 0");
        assert_eq!(lines[2]["error"]["code"], 3);
        assert_eq!(lines[3]["verified"], false);
        assert_eq!(lines[4]["message"], "clip 1");
        assert_eq!(keys_of(&lines[0]), VERIFY_KEYS);
    }
    // exit code: the worst file
    apcaw().args(["batch-verify", "-p", s(&pk), s(&files[0]), s(&files[1])]).assert().code(0);
    apcaw().args(["batch-verify", "-p", s(&pk), s(&files[0]), s(&media(0))]).assert().code(1);
    apcaw().args(["batch-verify", "-p", s(&pk), "-", "-"]).assert().code(2);
}

#[test]
fn serve_protocol() {
    let d = scratch("serve_protocol");
    let (sk, pk) = keygen(&d, "k");
    let out = d.join("s.wav");
    let req = |v: Value| v.to_string();
    let lines = [
        req(json!({"id": 1, "op": "version"})),
        String::new(),
        req(
            json!({"id": 2, "op": "sign", "input": s(&media(0)), "output": s(&out), "secret_key_file": s(&sk), "message": MSG}),
        ),
        req(json!({"id": 3, "op": "verify", "input": s(&out), "public_key_file": s(&pk)})),
        req(json!({"id": "w", "op": "verify", "input": s(&media(0)), "public_key_file": s(&pk)})),
        req(
            json!({"id": 4, "op": "sign", "input": s(&media(0)), "output": s(&out), "secret_key_file": s(&sk), "message": MSG}),
        ),
        req(json!({"id": 5, "op": "verify", "input": s(&d.join("none.wav")), "public_key_file": s(&pk)})),
        req(json!({"id": 6, "op": "frob"})),
        "not json".into(),
        req(json!({"id": 7, "op": "layout", "seed": 0, "profile": "wb"})),
        req(json!({"id": 8, "op": "inspect", "input": s(&out), "public_key_file": s(&pk)})),
        req(json!({"id": 9, "op": "verify", "input": "-", "public_key_file": s(&pk)})),
        req(json!({"id": 10, "op": "shutdown"})),
        req(json!({"id": 11, "op": "version"})),
    ];
    let a = apcaw().args(["serve", "--stdio"]).write_stdin(lines.join("\n") + "\n").assert().success();
    let replies: Vec<Value> = text(&a.get_output().stdout).lines().map(|l| json_out(l.as_bytes())).collect();
    let ids: Vec<Value> = replies.iter().map(|r| r["id"].clone()).collect();
    assert_eq!(
        ids,
        [
            json!(1),
            json!(2),
            json!(3),
            json!("w"),
            json!(4),
            json!(5),
            json!(6),
            Value::Null,
            json!(7),
            json!(8),
            json!(9),
            json!(10)
        ]
    );
    let ok: Vec<bool> = replies.iter().map(|r| r["ok"] == true).collect();
    assert_eq!(ok, [true, true, true, true, false, false, false, false, true, true, false, true]);
    assert_eq!(replies[0]["result"]["protocol"], 1);
    assert_eq!(replies[0]["result"]["format"], "apcaw-v1");
    assert_eq!(replies[1]["result"]["closed_loop"]["verified"], true);
    assert_eq!(replies[2]["result"]["message"], MSG);
    assert_eq!(replies[3]["result"]["verified"], false);
    let codes: Vec<Value> = [4, 5, 6, 7, 10].iter().map(|&i| replies[i]["error"]["code"].clone()).collect();
    assert_eq!(codes, [json!(2), json!(3), json!(2), json!(2), json!(2)]);
    assert_eq!(replies[8]["result"]["wb"]["phase_bins"], vector_json("layout.json")["seeds"][0]["wb"]["phase_bins"]);
    assert_eq!(replies[9]["result"]["samples"], 441_000);
    // the short field names: path, pk and sk (hex text)
    let hex = |p: &std::path::Path| fs::read(p).unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>();
    let t = d.join("t.wav");
    let short = [
        req(json!({"id": 1, "op": "sign", "path": s(&media(1)), "output": s(&t), "sk": hex(&sk), "message": "short"})),
        req(json!({"id": 2, "op": "verify", "path": s(&t), "pk": hex(&pk)})),
    ];
    let a = apcaw().args(["serve", "--stdio"]).write_stdin(short.join("\n")).assert().success();
    let replies: Vec<Value> = text(&a.get_output().stdout).lines().map(|l| json_out(l.as_bytes())).collect();
    assert_eq!(replies[0]["ok"], true, "{}", replies[0]);
    assert_eq!(replies[1]["result"]["message"], "short");
    // EOF ends the server too
    apcaw().args(["serve", "--stdio"]).write_stdin("").assert().success().stdout("");
    apcaw().arg("serve").assert().code(2);
}

/// Three clips back to back (30 s), group-aligned cuts of it.
#[test]
fn segment_and_scan() {
    let d = scratch("segment_and_scan");
    let (sk, pk) = keygen(&d, "k");
    let x: Vec<f64> =
        (0..3).flat_map(|i| read_wav(&fs::read(media(i)).unwrap()).unwrap().mono(None).unwrap()).collect();
    let long = d.join("long.wav");
    fs::write(&long, write_wav(&x, 44_100, Codec::Pcm16)).unwrap();
    let signed = d.join("seg.wav");
    apcaw()
        .args(["sign", "-i", s(&long), "-o", s(&signed), "-k", s(&sk), "-m", "seg", "--segment"])
        .assert()
        .success()
        .stdout(contains("3 segment(s) of 26 groups").and(contains("closed-loop verify ok")));
    apcaw().args(["-q", "verify", "-i", s(&signed), "-p", s(&pk), "--scan"]).assert().code(0);
    // groups 20..60 of the signed file: blocks 26..52 and 52..60 lie inside
    const G: usize = 8 * 2048;
    let y = read_wav(&fs::read(&signed).unwrap()).unwrap().mono(None).unwrap();
    let cut = d.join("cut.wav");
    fs::write(&cut, write_wav(&y[20 * G..60 * G], 44_100, Codec::Pcm16)).unwrap();
    let a = apcaw().args(["--json", "verify", "-i", s(&cut), "-p", s(&pk), "--scan"]).assert().code(0);
    let v = json_out(&a.get_output().stdout);
    let starts: Vec<Value> = v["blocks"].as_array().unwrap().iter().map(|b| b["start_group"].clone()).collect();
    assert_eq!(starts, [json!(6), json!(32)]);
    assert!(v["blocks"].as_array().unwrap().iter().all(|b| b["report"]["message"] == "seg"));
    apcaw()
        .args(["verify", "-i", s(&cut), "-p", s(&pk), "--scan"])
        .assert()
        .code(0)
        .stdout(starts_with("VERIFIED  2 block(s) of 26 groups"));
    // without --scan the cut does not verify; an unsigned file scans to 1
    apcaw().args(["-q", "verify", "-i", s(&cut), "-p", s(&pk)]).assert().code(1);
    apcaw().args(["-q", "verify", "-i", s(&long), "-p", s(&pk), "--scan"]).assert().code(1);
}

#[test]
fn bench_reports_both_pools() {
    let a = apcaw().args(["--json", "--threads", "2", "bench", "-i", s(&media(0)), "--repeat", "2"]).assert().success();
    let v = json_out(&a.get_output().stdout);
    let runs = v["runs"].as_array().unwrap();
    assert_eq!(runs.iter().map(|r| r["threads"].clone()).collect::<Vec<_>>(), [json!(1), json!(2)]);
    assert!(runs.iter().all(|r| r["total_ms"].as_f64().unwrap() > 0.0));
    assert_eq!(v["samples"], 441_000);
    apcaw()
        .args(["--threads", "1", "bench", "-i", s(&media(0)), "--repeat", "1"])
        .assert()
        .success()
        .stdout(contains("threads 1 "));
}
