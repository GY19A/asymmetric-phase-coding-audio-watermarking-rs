// SPDX-License-Identifier: BSD-2-Clause
//! Shared helpers of the CLI integration tests. Scratch files go to
//! `target/tmp/<test>/`; ffmpeg must be on PATH.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;
use serde_json::Value;

/// The real clips of `tests/media/`.
pub const CLIPS: [&str; 3] = [
    "0000_librispeech_5639-40744-0030.wav",
    "0001_librispeech_8555-284447-0010.wav",
    "0002_librispeech_3570-5695-0012.wav",
];

/// The message of the clip_A vectors.
pub const VECTOR_MESSAGE: &str = "NIPS2026: Authenticity Token for Deepfake Defense";

/// The `apcaw` binary under test, with the settings it reads from the
/// environment cleared.
pub fn apcaw() -> Command {
    let mut c = assert_cmd::cargo::cargo_bin_cmd!("apcaw");
    c.env_remove("APCAW_FFMPEG").env_remove("APCAW_FFPROBE").env("NO_COLOR", "1");
    c
}

/// Workspace root.
pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Clip `i` of `tests/media/`.
pub fn media(i: usize) -> PathBuf {
    root().join("tests/media").join(CLIPS[i])
}

/// A conformance vector of `crates/apcaw/vectors/`.
pub fn vector(name: &str) -> PathBuf {
    root().join("crates/apcaw/vectors").join(name)
}

pub fn vector_json(name: &str) -> Value {
    serde_json::from_slice(&fs::read(vector(name)).unwrap()).unwrap()
}

/// A fresh, empty scratch directory `target/tmp/<name>`.
pub fn scratch(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A path as `&str` (the test paths are ASCII).
pub fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// `apcaw keygen` into `dir/{name}.sec` and `dir/{name}.pub`.
pub fn keygen(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let (sk, pk) = (dir.join(format!("{name}.sec")), dir.join(format!("{name}.pub")));
    apcaw().args(["keygen", "--secret-out", s(&sk), "--public-out", s(&pk)]).assert().success();
    (sk, pk)
}

/// `apcaw sign` of `input` into `output`, which must succeed.
pub fn sign(input: &Path, output: &Path, sk: &Path, msg: &str, extra: &[&str]) {
    apcaw().args(["sign", "-i", s(input), "-o", s(output), "-k", s(sk), "-m", msg]).args(extra).assert().success();
}

/// A key file holding `hex` as text.
pub fn hex_key(dir: &Path, name: &str, hex: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, format!("{hex}\n")).unwrap();
    p
}

/// The vectors' key pair (secret seed `00 01 .. 1f`) as hex key files.
pub fn vector_keys(dir: &Path) -> (PathBuf, PathBuf) {
    let seed: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
    let pk = vector_json("payload.json")["public_key_hex"].as_str().unwrap().to_string();
    (hex_key(dir, "vec.sec", &seed), hex_key(dir, "vec.pub", &pk))
}

/// Run ffmpeg quietly, overwriting outputs; panics if it is missing or fails.
pub fn ffmpeg(args: &[&str]) {
    let out = StdCommand::new("ffmpeg")
        .args(["-hide_banner", "-nostdin", "-v", "error", "-y"])
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("ffmpeg is required by these tests (not found: {e})"));
    assert!(out.status.success(), "ffmpeg {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// `src` through MP3 at 128 kb/s (libmp3lame), written as `dst` (.mp3).
pub fn to_mp3(src: &Path, dst: &Path) {
    ffmpeg(&["-i", s(src), "-c:a", "libmp3lame", "-b:a", "128k", s(dst)]);
}

/// Standard output parsed as one JSON value.
pub fn json_out(out: &[u8]) -> Value {
    serde_json::from_slice(out).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(out)))
}

pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}
