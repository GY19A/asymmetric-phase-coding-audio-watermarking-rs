// SPDX-License-Identifier: BSD-2-Clause
//! Format constants, profiles (format §3) and options with the legacy switches.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Format identifier of this implementation.
pub const FORMAT: &str = "apcaw-v1";
/// The only sample rate the core accepts (format §1).
pub const SAMPLE_RATE: u32 = 44_100;
/// STFT size and hop (format §1).
pub const N_FFT: usize = 2048;
/// Number of rfft bins.
pub const N_BINS: usize = N_FFT / 2 + 1;
/// Frames per group (format §1).
pub const GROUP: usize = 8;
/// Length of the triple header in bits (format §5).
pub const HEADER_BITS: usize = 96;
/// Reed–Solomon parity symbols (format §4).
pub const RS_PARITY: usize = 30;
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;
/// Largest message the single-codeword payload can carry (format §4).
pub const MAX_MSG_LEN: usize = 159;
/// Payload overhead: be16 length + signature + parity.
pub const PAYLOAD_OVERHEAD: usize = 2 + SIG_LEN + RS_PARITY;
/// Log-magnitude floor (format §6).
pub const LOG_EPS: f64 = 1e-8;
/// Layout seed of the legacy benchmark (format §2).
pub const LEGACY_SEED: u32 = 42;
/// v1 silent-bin erasure threshold (format §7).
pub const ERASURE_TAU: f64 = 1e-6;
/// XOR constant of the magnitude pair permutation seed (format §2).
pub const MAG_SEED_XOR: u32 = 0xDEAD_BEEF;

/// A carrier profile (format §3).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Profile {
    /// Profile id, `"wb"` or `"nb"`.
    pub id: &'static str,
    /// First phase bin.
    pub p_lo: usize,
    /// One past the last phase bin.
    pub p_hi: usize,
    /// First magnitude bin.
    pub m_lo: usize,
    /// One past the last magnitude bin (before rounding the width down to even).
    pub m_hi: usize,
    /// QIM step in nats.
    pub delta: f64,
    /// Maximum phase replicas.
    pub rp: usize,
    /// Maximum magnitude replicas.
    pub rm: usize,
}

impl Profile {
    /// Wideband, the default.
    pub const WB: Profile = Profile { id: "wb", p_lo: 60, p_hi: 300, m_lo: 100, m_hi: 340, delta: 1.0, rp: 1, rm: 5 };
    /// Narrowband, for capture that is band-limited to about 8 kHz.
    pub const NB: Profile = Profile { id: "nb", p_lo: 60, p_hi: 300, m_lo: 16, m_hi: 168, delta: 1.0, rp: 1, rm: 5 };
    /// Profiles in the order a verifier tries them when none is given (format §3).
    pub const ALL: [Profile; 2] = [Profile::WB, Profile::NB];

    /// Look a profile up by id.
    pub fn by_id(id: &str) -> Option<Profile> {
        match id {
            "wb" => Some(Profile::WB),
            "nb" => Some(Profile::NB),
            _ => None,
        }
    }

    /// Phase bits per group, `Bp = p_hi - p_lo`.
    pub fn bp(&self) -> usize {
        self.p_hi - self.p_lo
    }

    /// Magnitude width rounded down to even, `W`.
    pub fn mag_width(&self) -> usize {
        let w = self.m_hi - self.m_lo;
        w - w % 2
    }

    /// Magnitude bits per group, `Bm = W / 2`.
    pub fn bm(&self) -> usize {
        self.mag_width() / 2
    }

    /// Bits per group of a channel.
    pub fn bits_per_group(&self, channel: Channel) -> usize {
        match channel {
            Channel::Phase => self.bp(),
            Channel::Magnitude => self.bm(),
        }
    }

    /// Maximum replicas of a channel.
    pub fn max_replicas(&self, channel: Channel) -> usize {
        match channel {
            Channel::Phase => self.rp,
            Channel::Magnitude => self.rm,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let ok = self.p_lo < self.p_hi
            && self.p_hi <= N_BINS
            && self.m_lo + 2 <= self.m_hi
            && self.m_hi <= N_BINS
            && self.delta.is_finite()
            && self.delta > 0.0
            && self.rp >= 1
            && self.rm >= 1;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidOption(format!("invalid profile {self:?}")))
        }
    }
}

/// The two carrier channels, in verification order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// ±π/2 phase write on the first frame of each group.
    Phase,
    /// QIM on the group-mean log-magnitude difference of a bin pair.
    Magnitude,
}

impl Channel {
    /// Verification order (format §8).
    pub const ALL: [Channel; 2] = [Channel::Phase, Channel::Magnitude];

    /// JSON / report name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Channel::Phase => "phase",
            Channel::Magnitude => "magnitude",
        }
    }
}

/// Which verification steps run (format §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verifier {
    /// Legacy: header fast path only.
    Header,
    /// v1: header fast path, then the protocol length search.
    Search,
}

/// What happens to the samples after the last whole frame (format §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tail {
    /// Legacy: zero-filled.
    Zero,
    /// v1: copied from the input.
    Passthrough,
}

/// Algorithm switches. [`Options::v1`] is the default,
/// [`Options::legacy`] reproduces the original release.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    /// Frames written by the phase channel per group, `1..=8` (legacy 8).
    pub phase_frames: usize,
    /// Verification steps (legacy `Header`).
    pub verifier: Verifier,
    /// Tail handling (legacy `Zero`).
    pub tail: Tail,
    /// Silent-bin erasure threshold, `0` disables it (legacy 0).
    pub erasure_tau: f64,
    /// Layout seed override; `None` derives it from the public key (legacy 42).
    pub seed: Option<u32>,
    /// Longest message length the protocol search tries, `0..=159`.
    pub max_msg_len: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options::v1()
    }
}

impl Options {
    /// v1 defaults.
    pub const fn v1() -> Self {
        Options {
            phase_frames: 1,
            verifier: Verifier::Search,
            tail: Tail::Passthrough,
            erasure_tau: ERASURE_TAU,
            seed: None,
            max_msg_len: MAX_MSG_LEN,
        }
    }

    /// The full legacy configuration of the original release, including the
    /// fixed benchmark seed 42.
    pub const fn legacy() -> Self {
        Options {
            phase_frames: GROUP,
            verifier: Verifier::Header,
            tail: Tail::Zero,
            erasure_tau: 0.0,
            seed: Some(LEGACY_SEED),
            max_msg_len: MAX_MSG_LEN,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.phase_frames == 0 || self.phase_frames > GROUP {
            return Err(Error::InvalidOption(format!("phase_frames must be 1..={GROUP}, got {}", self.phase_frames)));
        }
        if !(self.erasure_tau >= 0.0 && self.erasure_tau.is_finite()) {
            return Err(Error::InvalidOption(format!("erasure_tau must be finite and >= 0, got {}", self.erasure_tau)));
        }
        if self.max_msg_len > MAX_MSG_LEN {
            return Err(Error::InvalidOption(format!(
                "max_msg_len must be <= {MAX_MSG_LEN}, got {}",
                self.max_msg_len
            )));
        }
        Ok(())
    }
}

/// Number of STFT frames of a signal, `T = floor((len - N)/N) + 1` (0 if shorter than one frame).
pub fn n_frames(len: usize) -> usize {
    if len < N_FFT {
        0
    } else {
        (len - N_FFT) / N_FFT + 1
    }
}

/// Number of complete groups of a signal.
pub fn n_groups(len: usize) -> usize {
    n_frames(len) / GROUP
}

/// Payload length in bytes for a message length, `L = len(M) + 96`.
pub fn payload_len(msg_len: usize) -> usize {
    msg_len + PAYLOAD_OVERHEAD
}

/// Replicas of a body of `body_bits` in a channel of `cap` bits (format §5),
/// or `None` if not even one copy fits.
pub fn replicas(cap: usize, body_bits: usize, max_reps: usize) -> Option<usize> {
    if body_bits == 0 || cap < HEADER_BITS || cap - HEADER_BITS < body_bits {
        return None;
    }
    Some(((cap - HEADER_BITS) / body_bits).min(max_reps).max(1))
}
