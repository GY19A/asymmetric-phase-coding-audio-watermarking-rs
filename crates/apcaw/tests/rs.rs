// SPDX-License-Identifier: BSD-2-Clause
//! Reed–Solomon against reedsolo.RSCodec(30) (reference fixture) plus properties.

mod common;

use apcaw::rs::{decode, encode, RsError};
use common::*;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

#[test]
fn encode_matches_reedsolo() {
    let j = fixture("rs.json");
    for c in j["cases"].as_array().unwrap() {
        let msg = hex(c["msg"].as_str().unwrap());
        assert_eq!(to_hex(&encode(&msg)), c["codeword"].as_str().unwrap(), "len {}", msg.len());
    }
}

#[test]
fn decode_matches_reedsolo() {
    let j = fixture("rs.json");
    let (mut ok, mut fail) = (0, 0);
    for c in j["cases"].as_array().unwrap() {
        for k in c["corrupt"].as_array().unwrap() {
            let data = hex(k["data"].as_str().unwrap());
            let nerr = k["nerr"].as_u64().unwrap();
            match decode(&data) {
                Ok((m, n)) => {
                    assert!(k["ok"].as_bool().unwrap(), "reedsolo failed, we decoded (nerr {nerr})");
                    assert_eq!(to_hex(&m), k["decoded"].as_str().unwrap());
                    assert_eq!(n as u64, k["corrected"].as_u64().unwrap(), "nerr {nerr}");
                    ok += 1;
                }
                Err(e) => {
                    assert!(!k["ok"].as_bool().unwrap(), "we failed ({e:?}), reedsolo decoded (nerr {nerr})");
                    fail += 1;
                }
            }
        }
    }
    assert!(ok > 20 && fail > 5, "ok {ok} fail {fail}");
}

#[test]
fn rejects_bad_lengths() {
    assert_eq!(decode(&[0u8; 256]), Err(RsError::Length));
    assert_eq!(decode(&[]), Err(RsError::Length));
    // reedsolo semantics for words no longer than the parity: empty message,
    // accepted iff at most 15 symbols are non-zero.
    assert_eq!(decode(&[0u8; 30]), Ok((vec![], 0)));
    assert_eq!(decode(&[0u8; 31]), Ok((vec![0u8], 0)));
}

fn corrupt(cw: &[u8], positions: &[usize], values: &[u8]) -> Vec<u8> {
    let mut bad = cw.to_vec();
    for (&p, &v) in positions.iter().zip(values) {
        bad[p % cw.len()] ^= v;
    }
    bad
}

proptest! {
    // Failure seeds go next to this file (`rs.proptest-regressions`); the
    // default `SourceParallel` looks for a lib.rs that tests/ does not have.
    #![proptest_config(ProptestConfig {
        cases: 400,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("proptest-regressions"))),
        ..ProptestConfig::default()
    })]

    /// Any pattern of up to 15 symbol errors decodes to the original message
    /// with the exact number of corrected symbols.
    #[test]
    fn up_to_15_errors_always_decode(
        msg in proptest::collection::vec(any::<u8>(), 1..=225),
        pos in proptest::sample::subsequence((0usize..255).collect::<Vec<_>>(), 0..=15),
        vals in proptest::collection::vec(1u8..=255, 15),
    ) {
        let cw = encode(&msg);
        let pos: Vec<usize> = pos.into_iter().filter(|&p| p < cw.len()).collect();
        let bad = corrupt(&cw, &pos, &vals);
        let (m, n) = decode(&bad).unwrap();
        prop_assert_eq!(m, msg);
        prop_assert_eq!(n, pos.len());
    }

    /// With 16 or more errors the decoder may fail or land on a different
    /// codeword (miscorrection); it never returns a word that is not a codeword.
    /// Miscorrections are caught by the Ed25519 check in the verifier.
    #[test]
    fn beyond_15_errors_output_is_a_codeword_or_failure(
        msg in proptest::collection::vec(any::<u8>(), 1..=225),
        pos in proptest::sample::subsequence((0usize..255).collect::<Vec<_>>(), 16..=40),
        vals in proptest::collection::vec(1u8..=255, 40),
    ) {
        let cw = encode(&msg);
        let pos: Vec<usize> = pos.into_iter().filter(|&p| p < cw.len()).collect();
        let bad = corrupt(&cw, &pos, &vals);
        if let Ok((m, n)) = decode(&bad) {
            let re = encode(&m);
            let dist = re.iter().zip(&bad).filter(|(a, b)| a != b).count();
            prop_assert!(n <= 15);
            prop_assert_eq!(dist, n);
        }
    }
}

/// Inputs of any length follow reedsolo's 255-byte chunking (reference
/// fixture produced by reedsolo itself).
#[test]
fn chunked_decode_matches_reedsolo() {
    let v = fixture("rs_chunked.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() > 40);
    for c in cases {
        let rx = hex(c["received_hex"].as_str().unwrap());
        let got = apcaw::rs::decode_chunked(&rx);
        match c["decodes"].as_bool().unwrap() {
            true => {
                let (m, n) = got.unwrap_or_else(|e| panic!("{} len {}: {e:?}", c["kind"], rx.len()));
                assert_eq!(to_hex(&m), c["decoded_hex"].as_str().unwrap(), "{}", c["kind"]);
                assert_eq!(n as u64, c["n_corrected"].as_u64().unwrap(), "{}", c["kind"]);
            }
            false => assert!(got.is_err(), "{} len {} decoded", c["kind"], rx.len()),
        }
    }
    assert_eq!(apcaw::rs::decode_chunked(&[]), Ok((vec![], 0)));
}
