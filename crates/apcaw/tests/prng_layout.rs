// SPDX-License-Identifier: BSD-2-Clause
//! MT19937 / numpy legacy shuffle / layout against numpy (reference fixture).

mod common;

use apcaw::layout::{layout_seed, Layout};
use apcaw::mt19937::Mt19937;
use apcaw::Profile;
use common::*;

#[test]
fn mt19937_known_first_outputs() {
    // numpy.random.RandomState(s).randint(0, 2**32, dtype=np.uint32) / std::mt19937
    assert_eq!(Mt19937::new(42).next_u32(), 1_608_637_542);
    assert_eq!(Mt19937::new(0).next_u32(), 2_357_136_044);
    // 10000th output of std::mt19937 with the default seed 5489 (C++11 [rand.predef]).
    let mut m = Mt19937::new(5489);
    let v = (0..10_000).map(|_| m.next_u32()).last().unwrap();
    assert_eq!(v, 4_123_659_995);
}

#[test]
fn mt19937_first16_matches_numpy() {
    let j = fixture("prng_layout.json");
    let mut n = 0;
    for (seed, vals) in j["mt19937_first16"].as_object().unwrap() {
        let mut m = Mt19937::new(seed.parse().unwrap());
        let got: Vec<u64> = (0..16).map(|_| m.next_u32() as u64).collect();
        assert_eq!(got, u64s(vals), "seed {seed}");
        n += 1;
    }
    assert!(n >= 5);
}

#[test]
fn interval_edge_cases() {
    let mut m = Mt19937::new(1);
    assert_eq!(m.interval(0), 0);
    for max in [1u32, 2, 3, 7, 8, 255, 256, 1000, u32::MAX] {
        for _ in 0..200 {
            assert!(m.interval(max) <= max);
        }
    }
}

#[test]
fn shuffle_matches_numpy() {
    let j = fixture("prng_layout.json");
    for (seed, by_n) in j["shuffle_arange"].as_object().unwrap() {
        for (n, want) in by_n.as_object().unwrap() {
            let n: usize = n.parse().unwrap();
            let mut a: Vec<u64> = (0..n as u64).collect();
            Mt19937::new(seed.parse().unwrap()).shuffle(&mut a);
            assert_eq!(a, u64s(want), "seed {seed} n {n}");
        }
    }
}

#[test]
fn key_derived_seed_matches() {
    let j = fixture("prng_layout.json");
    let pk = hex32(j["pk_hex"].as_str().unwrap());
    assert_eq!(layout_seed(&pk) as u64, j["key_derived_seed"].as_u64().unwrap());
}

#[test]
fn layouts_match_numpy() {
    let j = fixture("prng_layout.json");
    for l in j["layouts"].as_array().unwrap() {
        let seed = l["seed"].as_u64().unwrap() as u32;
        for (id, prof) in [("wb", Profile::WB), ("nb", Profile::NB)] {
            let got = Layout::from_seed(seed, &prof);
            assert_eq!(got.seed, seed);
            assert_eq!(got.profile, id);
            let want_p: Vec<usize> = u64s(&l[id]["phase_bins"]).iter().map(|&v| v as usize).collect();
            assert_eq!(got.phase_bins, want_p, "phase seed {seed} {id}");
            let want_m: Vec<[usize; 2]> = l[id]["mag_pairs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| {
                    let p = u64s(p);
                    [p[0] as usize, p[1] as usize]
                })
                .collect();
            assert_eq!(got.mag_pairs, want_m, "mag seed {seed} {id}");
            assert_eq!(got.phase_bins.len(), prof.bp());
            assert_eq!(got.mag_pairs.len(), prof.bm());
        }
    }
}

#[test]
fn wb_and_nb_share_the_phase_channel() {
    let a = Layout::from_seed(1234, &Profile::WB);
    let b = Layout::from_seed(1234, &Profile::NB);
    assert_eq!(a.phase_bins, b.phase_bins);
    assert_eq!((Profile::WB.bm(), Profile::NB.bm()), (120, 76));
}
