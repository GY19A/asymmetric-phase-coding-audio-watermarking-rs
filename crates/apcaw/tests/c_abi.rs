// SPDX-License-Identifier: BSD-2-Clause
//! The C ABI: `include/apcaw.h` declares exactly the exported functions, and
//! `examples/c/verify.c` builds against the static library and runs (round
//! trip on noise, the signed vector clip with the right and a wrong key).

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::*;

fn exported() -> Vec<String> {
    let src = std::fs::read_to_string(root_dir().join("crates/apcaw/src/ffi.rs")).unwrap();
    src.lines()
        .filter_map(|l| l.split_once("extern \"C\" fn "))
        .map(|(_, r)| r.split('(').next().unwrap().to_string())
        .collect()
}

fn header() -> String {
    std::fs::read_to_string(root_dir().join("include/apcaw.h")).unwrap()
}

#[test]
fn header_declares_every_export() {
    let h = header();
    let names = exported();
    assert!(names.len() >= 7, "{names:?}");
    for n in &names {
        assert!(h.contains(&format!("{n}(")), "{n} missing from include/apcaw.h");
    }
    let code = h.lines().filter(|l| {
        let t = l.trim_start();
        !t.starts_with('*') && !t.starts_with("/*") && t.contains("apcaw_") && t.contains('(')
    });
    for line in code {
        let name = line.split('(').next().unwrap().rsplit([' ', '*']).next().unwrap();
        assert!(names.iter().any(|n| n == name), "header declares {name}, not exported");
    }
}

/// `target/<profile>/deps/`, next to this test binary: cargo builds the
/// library's `staticlib` there along with the tests (it is only copied up to
/// `target/<profile>/` by `cargo build`).
fn deps_dir() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().to_path_buf()
}

#[test]
fn c_example_builds_and_runs() {
    let lib = deps_dir().join("libapcaw.a");
    assert!(lib.exists(), "{} not built (cargo builds it with the library)", lib.display());
    let out_dir = root_dir().join("target/scratch");
    std::fs::create_dir_all(&out_dir).unwrap();
    let exe = out_dir.join(format!("c_verify_{}", std::process::id()));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let st = Command::new(&cc)
        .args(["-O2", "-Wall", "-Wextra", "-Werror", "-std=c99"])
        .arg("-I")
        .arg(root_dir().join("include"))
        .arg(root_dir().join("examples/c/verify.c"))
        .arg(&lib)
        .args(["-lpthread", "-ldl", "-lm", "-o"])
        .arg(&exe)
        .status()
        .unwrap_or_else(|e| panic!("cannot run {cc}: {e}"));
    assert!(st.success(), "C example does not compile");

    let o = Command::new(&exe).output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    eprintln!("{stdout}");
    assert!(o.status.success(), "round trip: {stdout} {}", String::from_utf8_lossy(&o.stderr));
    assert!(stdout.contains(&format!("apcaw {}", env!("CARGO_PKG_VERSION"))));
    assert!(stdout.contains("sample rate must be 44100 Hz (got 48000); resample first"));

    let j = vector_json("payload.json");
    let pk = j["public_key_hex"].as_str().unwrap();
    let clip = vector_path("clip_A_signed_v1.wav");
    let o = Command::new(&exe).arg(&clip).arg(pk).output().unwrap();
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(r["verified"], true);
    assert_eq!(r["message"], "NIPS2026: Authenticity Token for Deepfake Defense");
    assert_eq!(r["path"], "header");

    let neg = vector_json("negatives.json");
    let want = neg["cases"].as_array().unwrap().iter().find(|c| c["case"] == "wrong key").unwrap();
    let wrong = want["public_key_hex"].as_str().unwrap();
    let o = Command::new(&exe).arg(&clip).arg(wrong).output().unwrap();
    let r: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(1));
    for k in ["verified", "candidates_tried", "rs_passes", "sig_checks", "reason"] {
        assert_eq!(r[k], want[k], "{k}");
    }

    let o = Command::new(&exe).arg(&clip).arg("zz").output().unwrap();
    assert_eq!(o.status.code(), Some(2));
    let o = Command::new(&exe).arg(out_dir.join("missing.wav")).arg(pk).output().unwrap();
    assert_eq!(o.status.code(), Some(3));
    let _ = std::fs::remove_file(&exe);
}

#[test]
fn ffi_from_rust() {
    use apcaw::ffi::*;
    use std::ffi::CStr;
    unsafe {
        let v = CStr::from_ptr(apcaw_version()).to_str().unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
        let (mut sk, mut pk, mut pk2) = ([0u8; 32], [0u8; 32], [0u8; 32]);
        assert_eq!(apcaw_keygen(sk.as_mut_ptr(), pk.as_mut_ptr()), 0);
        assert_eq!(apcaw_public_key(sk.as_ptr(), pk2.as_mut_ptr()), 0);
        assert_eq!(pk, pk2);
        assert_eq!(apcaw_keygen(std::ptr::null_mut(), pk.as_mut_ptr()), -1);

        // too short: sign fails with 1 and a message
        let x = vec![0.1f64; 1000];
        let mut y = vec![0.0f64; 1000];
        let rc = apcaw_sign_f64(
            x.as_ptr(),
            x.len(),
            44_100,
            sk.as_ptr(),
            b"m".as_ptr(),
            1,
            std::ptr::null(),
            0,
            y.as_mut_ptr(),
        );
        assert_eq!(rc, 1);
        let e = CStr::from_ptr(apcaw_last_error()).to_str().unwrap();
        assert!(e.starts_with("too short"), "{e}");
        let bad = c"xx";
        let rc =
            apcaw_sign_f64(x.as_ptr(), x.len(), 44_100, sk.as_ptr(), b"m".as_ptr(), 1, bad.as_ptr(), 0, y.as_mut_ptr());
        assert_eq!(rc, -1);
        assert!(apcaw_verify_f64(x.as_ptr(), x.len(), 44_100, pk.as_ptr(), bad.as_ptr(), 0, 0).is_null());
        let r = apcaw_verify_f64(x.as_ptr(), x.len(), 44_100, pk.as_ptr(), std::ptr::null(), 0, 0);
        let j: serde_json::Value = serde_json::from_str(CStr::from_ptr(r).to_str().unwrap()).unwrap();
        apcaw_string_free(r);
        assert_eq!(j["verified"], false);
        assert!(j["reason"].as_str().unwrap().starts_with("too short"));
        apcaw_string_free(std::ptr::null_mut());
    }
}
