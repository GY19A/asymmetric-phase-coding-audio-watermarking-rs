// SPDX-License-Identifier: BSD-2-Clause
//! Payload, bits, header and stream against Python (reference fixture).

mod common;

use apcaw::keys::{keygen_from_seed, PublicKey, SecretKey};
use apcaw::payload;
use common::*;

#[test]
fn keys_from_fixed_seed() {
    let j = fixture("payload.json");
    let kp = keygen_from_seed(hex32(j["sk_seed_hex"].as_str().unwrap()));
    assert_eq!(kp.public.to_hex(), j["pk_hex"].as_str().unwrap());
    assert_eq!(kp.secret.to_hex(), j["sk_seed_hex"].as_str().unwrap());
}

#[test]
fn payloads_match_python() {
    let j = fixture("payload.json");
    let sk = SecretKey::from_seed(hex32(j["sk_seed_hex"].as_str().unwrap()));
    let pk = sk.public_key();
    for p in j["payloads"].as_array().unwrap() {
        let m = hex(p["message_hex"].as_str().unwrap());
        assert_eq!(to_hex(&sk.sign(&m)), p["sig_hex"].as_str().unwrap());
        let c = payload::container(&sk, &m).unwrap();
        assert_eq!(to_hex(&c), p["c_hex"].as_str().unwrap());
        let pl = payload::build(&sk, &m).unwrap();
        assert_eq!(to_hex(&pl), p["payload_hex"].as_str().unwrap());
        assert_eq!(pl.len(), m.len() + 96);
        let bits = payload::unpack_bits(&pl);
        assert_eq!(bits.len() as u64, p["body_bits"].as_u64().unwrap());
        assert_eq!(payload::pack_bits(&bits), pl);
        let h: Vec<u64> = payload::header_bits(bits.len() as u32).iter().map(|&b| b as u64).collect();
        assert_eq!(h, u64s(&p["header_bits"]));
        let (msg, sig) = payload::open(&c).unwrap();
        assert_eq!(msg, &m[..]);
        assert!(pk.verify(msg, &sig));
    }
}

#[test]
fn message_limit() {
    let sk = SecretKey::from_seed([1; 32]);
    assert!(payload::build(&sk, &[b'x'; 159]).is_ok());
    assert!(matches!(payload::build(&sk, &[b'x'; 160]), Err(apcaw::Error::MessageTooLong { len: 160, max: 159 })));
}

#[test]
fn stream_rule() {
    let body = vec![1u8; 1160];
    // phase, 10 s clip: 26 groups x 240
    let s = payload::stream(&body, 26 * 240, 1, "phase").unwrap();
    assert_eq!(s.len(), 96 + 1160);
    // magnitude WB: 26 x 120 = 3120 -> r = 2
    let s = payload::stream(&body, 26 * 120, 5, "magnitude").unwrap();
    assert_eq!(s.len(), 96 + 2 * 1160);
    assert_eq!(&s[..32], &payload::header_bits(1160));
    assert_eq!(&s[32..64], &s[..32]);
    assert_eq!(&s[64..96], &s[..32]);
    // exactly fits once
    assert_eq!(payload::stream(&body, 96 + 1160, 5, "magnitude").unwrap().len(), 1256);
    assert!(matches!(
        payload::stream(&body, 96 + 1159, 5, "magnitude"),
        Err(apcaw::Error::Capacity { capacity: 1255, needed: 1256, body: 1160, .. })
    ));
    // cap below the header
    assert!(payload::stream(&body, 50, 5, "phase").is_err());
}

#[test]
fn open_checks_length_consistency() {
    let sk = SecretKey::from_seed([2; 32]);
    let mut c = payload::container(&sk, b"abc").unwrap();
    assert!(payload::open(&c).is_some());
    c[1] = 4;
    assert!(payload::open(&c).is_none());
    assert!(payload::open(&c[..10]).is_none());
    assert!(payload::open(&[]).is_none());
}

#[test]
fn key_encodings_roundtrip() {
    let kp = keygen_from_seed([9; 32]);
    for text in [kp.secret.to_hex(), kp.secret.to_pem(), format!("  {}\n", kp.secret.to_hex())] {
        assert_eq!(SecretKey::parse(text.as_bytes()).unwrap().seed(), [9; 32]);
    }
    assert_eq!(SecretKey::parse(&[9; 32]).unwrap().seed(), [9; 32]);
    for text in [kp.public.to_hex(), kp.public.to_pem()] {
        assert_eq!(PublicKey::parse(text.as_bytes()).unwrap(), kp.public);
    }
    assert_eq!(PublicKey::parse(kp.public.as_bytes()).unwrap(), kp.public);
    assert!(kp.secret.to_pem().starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(kp.public.to_pem().starts_with("-----BEGIN PUBLIC KEY-----\n"));
    // A public PEM is not a secret key and vice versa.
    assert!(SecretKey::parse(kp.public.to_pem().as_bytes()).is_err());
    assert!(PublicKey::parse(kp.secret.to_pem().as_bytes()).is_err());
    assert!(PublicKey::parse(b"zz").is_err());
}

#[test]
fn keygen_is_random() {
    let a = apcaw::keygen();
    let b = apcaw::keygen();
    assert_ne!(a.public, b.public);
    assert_eq!(a.secret.public_key(), a.public);
}

#[test]
fn invalid_point_fails_signature_checks() {
    // y = 2 is not on the curve; the bytes are still a usable layout key.
    let mut raw = [0u8; 32];
    raw[0] = 2;
    let pk = PublicKey::from_bytes(raw);
    assert!(!pk.verify(b"m", &[0u8; 64]));
}
