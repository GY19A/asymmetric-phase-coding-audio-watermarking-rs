// SPDX-License-Identifier: BSD-2-Clause
//! Key-derived layout: phase bin order and magnitude pair order (format §2).

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::mt19937::Mt19937;
use crate::params::{Profile, MAG_SEED_XOR};

/// Where each slot of a group lives in the spectrum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    /// Layout seed (key-derived or overridden).
    pub seed: u32,
    /// Profile id.
    pub profile: &'static str,
    /// `Kp[s]`: phase bin of slot `s`, length `Bp`.
    pub phase_bins: Vec<usize>,
    /// `pairs[perm][s]`: magnitude bin pair of slot `s`, length `Bm`.
    pub mag_pairs: Vec<[usize; 2]>,
}

/// Layout of `profile` for a public key, or for `seed_override` when given
/// (the legacy benchmark used 42).
pub fn layout(pk: &crate::PublicKey, profile: &Profile, seed_override: Option<u32>) -> Layout {
    Layout::for_key(pk.as_bytes(), profile, seed_override)
}

/// `int.from_bytes(SHA256(pk)[0:8], "big") mod 2^32`, i.e. digest bytes 4..8 big-endian.
pub fn layout_seed(pk: &[u8; 32]) -> u32 {
    let d = Sha256::digest(pk);
    u32::from_be_bytes([d[4], d[5], d[6], d[7]])
}

impl Layout {
    /// Layout of a profile for an explicit seed.
    pub fn from_seed(seed: u32, profile: &Profile) -> Layout {
        let mut phase_bins: Vec<usize> = (profile.p_lo..profile.p_hi).collect();
        Mt19937::new(seed).shuffle(&mut phase_bins);
        let mut perm: Vec<usize> = (0..profile.bm()).collect();
        Mt19937::new(seed ^ MAG_SEED_XOR).shuffle(&mut perm);
        let mag_pairs = perm.into_iter().map(|p| [profile.m_lo + 2 * p, profile.m_lo + 2 * p + 1]).collect();
        Layout { seed, profile: profile.id, phase_bins, mag_pairs }
    }

    /// Layout for a public key, or for `seed_override` when given
    /// (`Options::seed`; the legacy benchmark used 42).
    pub fn for_key(pk: &[u8; 32], profile: &Profile, seed_override: Option<u32>) -> Layout {
        Layout::from_seed(seed_override.unwrap_or_else(|| layout_seed(pk)), profile)
    }
}
