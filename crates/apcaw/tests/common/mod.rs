// SPDX-License-Identifier: BSD-2-Clause
//! Shared helpers of the integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

/// `crates/apcaw`.
pub fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Workspace root.
pub fn root_dir() -> PathBuf {
    crate_dir().join("../..").canonicalize().unwrap()
}

/// A reference fixture (`tests/fixtures/`), produced by the Python reference and numpy.
pub fn fixture(name: &str) -> serde_json::Value {
    let p = crate_dir().join("tests/fixtures").join(name);
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&s).unwrap()
}

/// Path of a tracked conformance vector (`crates/apcaw/vectors/`, a copy of the vectors in the
/// Python reference repository). Panics loudly when it is
/// missing: vector tests must fail, never skip.
pub fn vector_path(name: &str) -> PathBuf {
    let p = crate_dir().join("vectors").join(name);
    assert!(
        p.is_file(),
        "conformance vector {} is missing; copy it from the Python reference repository. \
         This test fails on purpose until it exists.",
        p.display()
    );
    p
}

/// A tracked conformance vector parsed as JSON.
pub fn vector_json(name: &str) -> serde_json::Value {
    let p = vector_path(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

/// A tracked conformance vector as bytes.
pub fn vector_bytes(name: &str) -> Vec<u8> {
    std::fs::read(vector_path(name)).unwrap()
}

/// Little-endian float64 file.
pub fn read_f64(bytes: &[u8]) -> Vec<f64> {
    assert_eq!(bytes.len() % 8, 0);
    bytes.chunks_exact(8).map(|c| f64::from_le_bytes(c.try_into().unwrap())).collect()
}

pub fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd hex length");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

pub fn u64s(v: &serde_json::Value) -> Vec<u64> {
    v.as_array().unwrap().iter().map(|x| x.as_u64().unwrap()).collect()
}

pub fn f64s(v: &serde_json::Value) -> Vec<f64> {
    v.as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect()
}

/// Largest absolute difference.
pub fn max_abs_diff(a: &[f64], b: &[f64]) -> f64 {
    assert_eq!(a.len(), b.len(), "length mismatch");
    a.iter().zip(b).map(|(x, y)| (x - y).abs()).fold(0.0, f64::max)
}

/// The three test clips of `tests/media/` (44.1 kHz mono PCM16, 10 s).
pub fn media_clips() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(root_dir().join("tests/media"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "wav"))
        .collect();
    v.sort();
    v
}

/// Read a PCM16 mono WAV as `int / 32768`.
pub fn read_pcm16(path: &std::path::Path) -> (Vec<f64>, u32) {
    let mut r = hound::WavReader::open(path).unwrap();
    let spec = r.spec();
    assert_eq!((spec.channels, spec.bits_per_sample), (1, 16));
    let x = r.samples::<i16>().map(|s| s.unwrap() as f64 / 32768.0).collect();
    (x, spec.sample_rate)
}
