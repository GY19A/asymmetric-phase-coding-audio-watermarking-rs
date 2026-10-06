// SPDX-License-Identifier: BSD-2-Clause
//! Segmented mode (format §10; tools only, off by default, no Python
//! counterpart).
//!
//! Signing embeds the §5 stream independently in every block of `K` groups:
//! block `b` covers samples `[b·K·G·N, (b+1)·K·G·N)` and its layout indices
//! restart at the block's first frame. Frames do not overlap, so this is the
//! same as calling [`sign`](crate::sign) on each block. A trailing partial
//! block is embedded when it can carry the stream and skipped otherwise.
//!
//! [`scan`] runs §8 on group-aligned windows of `K` groups. After a window
//! verifies it jumps a whole block ahead; otherwise it moves by one group.
//! The last window, shorter than `K` groups, runs to the end of the input.

use serde::Serialize;

use crate::embed::{apply_tail, check_fits, check_input, embed_bits, prepare, SignInfo};
use crate::error::{Error, Result};
use crate::keys::{PublicKey, SecretKey};
use crate::layout::Layout;
use crate::params::{n_frames, Options, Profile, GROUP, N_FFT};
use crate::verify::{try_verify, VerifyReport};

/// Default block length in groups (26 groups ≈ 9.66 s at 44.1 kHz).
pub const DEFAULT_SEGMENT_GROUPS: usize = 26;

/// One block of a segmented signing.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Block {
    /// First group of the block.
    pub start_group: usize,
    /// Complete groups in the block.
    pub groups: usize,
    /// First sample.
    pub start_sample: usize,
    /// One past the last sample.
    pub end_sample: usize,
    /// What was embedded, `None` for a trailing block too short for the stream.
    pub info: Option<SignInfo>,
}

/// Result of [`sign_segmented`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SegmentInfo {
    /// Block length `K` in groups.
    pub segment_groups: usize,
    /// Blocks in signal order.
    pub blocks: Vec<Block>,
}

impl SegmentInfo {
    /// Blocks that carry a mark.
    pub fn embedded(&self) -> usize {
        self.blocks.iter().filter(|b| b.info.is_some()).count()
    }
}

fn check_k(k: usize) -> Result<()> {
    if k == 0 {
        return Err(Error::InvalidOption("segment length must be at least 1 group".into()));
    }
    Ok(())
}

/// Samples per block of `k` groups.
fn block_samples(k: usize) -> usize {
    k * GROUP * N_FFT
}

/// Sign every block of `k` groups of `samples` (mono, 44100 Hz) with `msg`.
///
/// Fails like [`sign`](crate::sign) when the first block cannot carry the
/// stream (message too long for `k`, or input shorter than that).
pub fn sign_segmented(
    samples: &[f64],
    sr: u32,
    sk: &SecretKey,
    msg: &[u8],
    profile: &Profile,
    opt: &Options,
    k: usize,
) -> Result<(Vec<f64>, SegmentInfo)> {
    check_k(k)?;
    let body = prepare(samples, sr, sk, msg, profile, opt)?;
    let layout = Layout::for_key(sk.public_key().as_bytes(), profile, opt.seed);
    let step = block_samples(k);
    let mut y = samples.to_vec();
    let mut blocks = Vec::new();
    let mut start = 0;
    loop {
        let full = start + step <= y.len();
        let end = if full { start + step } else { y.len() };
        let len = end - start;
        let groups = n_frames(len) / GROUP;
        if blocks.is_empty() {
            check_fits(len, body.len(), profile)?;
        }
        if groups == 0 {
            break;
        }
        let info = match check_fits(len, body.len(), profile) {
            Ok(()) => {
                let mut i = embed_bits(&mut y[start..end], &body, &layout, profile, opt)?;
                i.message_len = msg.len();
                Some(i)
            }
            Err(_) => None,
        };
        blocks.push(Block { start_group: start / (GROUP * N_FFT), groups, start_sample: start, end_sample: end, info });
        if !full {
            break;
        }
        start = end;
    }
    apply_tail(&mut y, opt.tail);
    Ok((y, SegmentInfo { segment_groups: k, blocks }))
}

/// A window that verified.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanHit {
    /// First group of the window.
    pub start_group: usize,
    /// Complete groups in the window.
    pub groups: usize,
    /// First sample.
    pub start_sample: usize,
    /// One past the last sample.
    pub end_sample: usize,
    /// The verification of the window.
    pub report: VerifyReport,
}

/// Result of [`scan`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ScanReport {
    /// Window length `K` in groups.
    pub segment_groups: usize,
    /// Windows verified, in signal order.
    pub blocks: Vec<ScanHit>,
    /// Windows examined.
    pub windows_tried: usize,
    /// Complete groups of the input.
    pub groups: usize,
}

impl ScanReport {
    /// At least one window verified.
    pub fn verified(&self) -> bool {
        !self.blocks.is_empty()
    }
}

/// Verify every group-aligned window of `k` groups of `samples` (mono,
/// 44100 Hz) against `pk`; `profile` and `opt` as in [`verify`](crate::verify).
pub fn scan(
    samples: &[f64],
    sr: u32,
    pk: &PublicKey,
    profile: Option<&Profile>,
    opt: &Options,
    k: usize,
) -> Result<ScanReport> {
    check_k(k)?;
    check_input(samples, sr).or_else(|e| match e {
        Error::SampleRate(_) => Err(e),
        _ => Ok(()),
    })?;
    let gs = GROUP * N_FFT;
    let groups = n_frames(samples.len()) / GROUP;
    let mut out = ScanReport { segment_groups: k, blocks: Vec::new(), windows_tried: 0, groups };
    let mut w = 0;
    while w < groups {
        let whole = w + k <= groups;
        let (start, end) = (w * gs, if whole { (w + k) * gs } else { samples.len() });
        let r = try_verify(&samples[start..end], sr, pk, profile, opt, false)?;
        out.windows_tried += 1;
        let n = n_frames(end - start) / GROUP;
        if r.verified {
            out.blocks.push(ScanHit { start_group: w, groups: n, start_sample: start, end_sample: end, report: r });
            w += k;
        } else if whole {
            w += 1;
        } else {
            break;
        }
    }
    Ok(out)
}
