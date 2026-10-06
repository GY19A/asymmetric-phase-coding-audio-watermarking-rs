// SPDX-License-Identifier: BSD-2-Clause
//! Error type of the protocol core.

/// Everything that can go wrong in the core. Verification never returns an
/// error for a well-formed call: a missing or broken watermark is a
/// [`crate::VerifyReport`] with `verified == false`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    /// The core works at 44100 Hz only; tools resample first.
    #[error("sample rate must be 44100 Hz (got {0}); resample first")]
    SampleRate(u32),
    /// The message exceeds the format limit of 159 bytes.
    #[error("message too long: {len} bytes > {max}")]
    MessageTooLong {
        /// Message length in bytes.
        len: usize,
        /// The format limit.
        max: usize,
    },
    /// The message exceeds `Options::max_msg_len`.
    #[error("message too long: {len} bytes > max_msg_len {max_msg_len}")]
    MessageOverLimit {
        /// Message length in bytes.
        len: usize,
        /// `Options::max_msg_len`.
        max_msg_len: usize,
    },
    /// The clip has too few STFT groups to carry one copy of the stream in both channels.
    #[error("too short: {samples} samples give {groups} groups; profile {profile} needs {needed} bits per channel (phase cap {phase_capacity}, magnitude cap {mag_capacity})")]
    TooShort {
        /// Input length in samples.
        samples: usize,
        /// Complete groups.
        groups: usize,
        /// Profile id.
        profile: &'static str,
        /// `96 + |b|`.
        needed: usize,
        /// Phase capacity `groups * Bp` in bits.
        phase_capacity: usize,
        /// Magnitude capacity `groups * Bm` in bits.
        mag_capacity: usize,
    },
    /// A channel of `capacity` bits cannot hold the header plus one body copy.
    #[error("{channel} channel capacity is {capacity} bits, the stream needs {needed} (header 96 + body {body})")]
    Capacity {
        /// `"phase"` or `"magnitude"`.
        channel: &'static str,
        /// Channel capacity in bits.
        capacity: usize,
        /// `96 + |b|`.
        needed: usize,
        /// Body length `|b|` in bits.
        body: usize,
    },
    /// Samples that are NaN or infinite.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// An option value outside its valid range.
    #[error("invalid option: {0}")]
    InvalidOption(String),
    /// A key that is not 32 bytes, not valid hex or not valid PEM.
    #[error("{0}")]
    InvalidKey(String),
    /// Malformed WAV data.
    #[error("invalid WAV: {0}")]
    Wav(String),
    /// A file could not be read or written (WAV helpers only).
    #[error("{0}")]
    Io(String),
}

/// Result alias of the core.
pub type Result<T> = std::result::Result<T, Error>;
