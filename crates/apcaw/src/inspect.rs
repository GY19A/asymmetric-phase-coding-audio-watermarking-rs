// SPDX-License-Identifier: BSD-2-Clause
//! Capacity, header lengths and soft-value statistics of a signal under a key
//! (the Python CLI's `inspect`). Diagnostic only: nothing here decides
//! whether a file verifies.

use serde::ser::{Serialize, SerializeMap, Serializer};

use crate::error::{Error, Result};
use crate::keys::PublicKey;
use crate::layout::{layout_seed, Layout};
use crate::params::{n_frames, replicas, Channel, Options, Profile, GROUP, HEADER_BITS, SAMPLE_RATE};
use crate::stft::pairwise_sum;
use crate::verify::{header_length, read_soft, MIN_PAYLOAD_BITS};

/// Statistics of one channel's soft stream.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ChannelStats {
    /// Channel capacity in bits.
    pub capacity: usize,
    /// Majority-voted header length, `None` below 96 bits of capacity.
    pub header_length: Option<u32>,
    /// Bits of the stream the header announces (`96 + r·ℓ`) when `ℓ` is a
    /// plausible payload length, else the capacity.
    pub stream_bits: usize,
    /// Mean `|soft|` over `stream_bits`.
    pub mean_abs_soft: Option<f64>,
    /// Mean `|soft|` over the capacity.
    pub mean_abs_soft_capacity: Option<f64>,
    /// Soft values that are exactly zero (erased silent bins).
    pub erased: usize,
}

/// One profile's view of the signal.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ProfileStats {
    /// Complete groups.
    pub groups: usize,
    /// STFT frames.
    pub frames: usize,
    /// Phase channel.
    pub phase: ChannelStats,
    /// Magnitude channel.
    pub magnitude: ChannelStats,
}

/// Result of [`inspect`]. Serializes as the Python CLI's JSON minus `file`:
/// `{samples, frames, seed, profiles: {wb: .., nb: ..}}`.
#[derive(Debug, Clone, PartialEq)]
pub struct InspectReport {
    /// Input length in samples.
    pub samples: usize,
    /// STFT frames.
    pub frames: usize,
    /// Layout seed used.
    pub seed: u32,
    /// `(profile id, statistics)` in the order WB, NB.
    pub profiles: Vec<(&'static str, ProfileStats)>,
}

impl Serialize for InspectReport {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        struct Profiles<'a>(&'a [(&'static str, ProfileStats)]);
        impl Serialize for Profiles<'_> {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                let mut m = s.serialize_map(Some(self.0.len()))?;
                for (id, p) in self.0 {
                    m.serialize_entry(id, p)?;
                }
                m.end()
            }
        }
        let mut m = s.serialize_map(Some(4))?;
        m.serialize_entry("samples", &self.samples)?;
        m.serialize_entry("frames", &self.frames)?;
        m.serialize_entry("seed", &self.seed)?;
        m.serialize_entry("profiles", &Profiles(&self.profiles))?;
        m.end()
    }
}

/// numpy `np.mean(np.abs(v))`, `None` for an empty slice.
fn mean_abs(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let a: Vec<f64> = v.iter().map(|x| x.abs()).collect();
    Some(pairwise_sum(&a) / a.len() as f64)
}

fn channel_stats(soft: &[f64], max_replicas: usize) -> ChannelStats {
    let cap = soft.len();
    let ell = header_length(soft);
    let mut n = cap;
    if let Some(l) = ell.map(|l| l as usize) {
        if l % 8 == 0 && l >= MIN_PAYLOAD_BITS && l + HEADER_BITS <= cap {
            n = HEADER_BITS + replicas(cap, l, max_replicas).expect("fits") * l;
        }
    }
    ChannelStats {
        capacity: cap,
        header_length: ell,
        stream_bits: n,
        mean_abs_soft: mean_abs(&soft[..n]),
        mean_abs_soft_capacity: mean_abs(soft),
        erased: soft.iter().filter(|&&v| v == 0.0).count(),
    }
}

/// Soft-value statistics of `samples` (mono, 44100 Hz) under `pk` for both
/// profiles. `opt.seed` overrides the key-derived seed, `opt.erasure_tau`
/// applies as in verification. Fails only on a wrong sample rate.
pub fn inspect(samples: &[f64], sr: u32, pk: &PublicKey, opt: &Options) -> Result<InspectReport> {
    if sr != SAMPLE_RATE {
        return Err(Error::SampleRate(sr));
    }
    let seed = opt.seed.unwrap_or_else(|| layout_seed(pk.as_bytes()));
    let frames = n_frames(samples.len());
    let profiles = Profile::ALL
        .iter()
        .map(|p| {
            let soft = read_soft(samples, &Layout::from_seed(seed, p), p, opt.erasure_tau);
            let stats = ProfileStats {
                groups: frames / GROUP,
                frames,
                phase: channel_stats(&soft.phase, p.max_replicas(Channel::Phase)),
                magnitude: channel_stats(&soft.magnitude, p.max_replicas(Channel::Magnitude)),
            };
            (p.id, stats)
        })
        .collect();
    Ok(InspectReport { samples: samples.len(), frames, seed, profiles })
}
