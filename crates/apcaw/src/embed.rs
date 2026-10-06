// SPDX-License-Identifier: BSD-2-Clause
//! Embedding: phase write and magnitude QIM on one STFT (format §5, §6).
//!
//! Only frames that carry stream bits are transformed back; every other frame
//! is copied from the input, which equals numpy's `irfft(rfft(x))` of an
//! unmodified frame to about 1e-16. Inside a modified frame, bins outside the
//! written cells keep the original spectrum instead of `A·exp(j·wrap(P))`
//! (the same value to a few ulps).

use std::f64::consts::FRAC_PI_2;

use realfft::num_complex::Complex64;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::keys::SecretKey;
use crate::layout::Layout;
use crate::params::{n_frames, Options, Profile, Tail, GROUP, LOG_EPS, N_BINS, N_FFT, SAMPLE_RATE};
use crate::payload;
use crate::stft::{abs, angle, group_mean, inverse_frame, wrap, Stft};

/// What an embedding wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignInfo {
    /// Profile id.
    pub profile: &'static str,
    /// Layout seed used.
    pub seed: u32,
    /// Message length in bytes.
    pub message_len: usize,
    /// Body length `|b|` in bits.
    pub body_bits: usize,
    /// STFT frames of the signal.
    pub frames: usize,
    /// Complete groups of the signal.
    pub groups: usize,
    /// Phase channel capacity in bits.
    pub phase_capacity: usize,
    /// Phase stream length in bits.
    pub phase_stream: usize,
    /// Phase body replicas.
    pub phase_replicas: usize,
    /// Magnitude channel capacity in bits.
    pub mag_capacity: usize,
    /// Magnitude stream length in bits.
    pub mag_stream: usize,
    /// Magnitude body replicas.
    pub mag_replicas: usize,
}

pub(crate) fn check_input(samples: &[f64], sr: u32) -> Result<()> {
    if sr != SAMPLE_RATE {
        return Err(Error::SampleRate(sr));
    }
    if let Some(i) = samples.iter().position(|v| !v.is_finite()) {
        return Err(Error::InvalidInput(format!("sample {i} is not finite")));
    }
    Ok(())
}

/// Sign `samples` (mono, 44100 Hz) with `msg` under `sk` (format §4–6).
///
/// Returns the watermarked signal, same length as the input. Fails if the
/// rate is not 44100 Hz, the message is longer than `opt.max_msg_len`, or the
/// clip cannot carry one copy of the stream in both channels.
pub fn sign(
    samples: &[f64],
    sr: u32,
    sk: &SecretKey,
    msg: &[u8],
    profile: &Profile,
    opt: &Options,
) -> Result<Vec<f64>> {
    sign_detailed(samples, sr, sk, msg, profile, opt).map(|(y, _)| y)
}

/// [`sign`] plus a description of what was written.
pub fn sign_detailed(
    samples: &[f64],
    sr: u32,
    sk: &SecretKey,
    msg: &[u8],
    profile: &Profile,
    opt: &Options,
) -> Result<(Vec<f64>, SignInfo)> {
    let body = prepare(samples, sr, sk, msg, profile, opt)?;
    check_fits(samples.len(), body.len(), profile)?;
    let layout = Layout::for_key(sk.public_key().as_bytes(), profile, opt.seed);
    let mut y = samples.to_vec();
    let mut info = embed_bits(&mut y, &body, &layout, profile, opt)?;
    info.message_len = msg.len();
    apply_tail(&mut y, opt.tail);
    Ok((y, info))
}

/// Validate a sign call and build the body bits `b` (format §4).
pub(crate) fn prepare(
    samples: &[f64],
    sr: u32,
    sk: &SecretKey,
    msg: &[u8],
    profile: &Profile,
    opt: &Options,
) -> Result<Vec<u8>> {
    check_input(samples, sr)?;
    opt.validate()?;
    profile.validate()?;
    if msg.len() > crate::params::MAX_MSG_LEN {
        return Err(Error::MessageTooLong { len: msg.len(), max: crate::params::MAX_MSG_LEN });
    }
    if msg.len() > opt.max_msg_len {
        return Err(Error::MessageOverLimit { len: msg.len(), max_msg_len: opt.max_msg_len });
    }
    Ok(payload::unpack_bits(&payload::build(sk, msg)?))
}

/// Both channels of `len` samples hold one header plus one body copy.
pub(crate) fn check_fits(len: usize, body_bits: usize, profile: &Profile) -> Result<()> {
    let groups = n_frames(len) / GROUP;
    let needed = crate::params::HEADER_BITS + body_bits;
    let (phase_capacity, mag_capacity) = (groups * profile.bp(), groups * profile.bm());
    if phase_capacity.min(mag_capacity) < needed {
        return Err(Error::TooShort {
            samples: len,
            groups,
            profile: profile.id,
            needed,
            phase_capacity,
            mag_capacity,
        });
    }
    Ok(())
}

/// Zero the samples after the last whole frame for `Tail::Zero`.
pub(crate) fn apply_tail(y: &mut [f64], tail: Tail) {
    if tail == Tail::Zero {
        let end = n_frames(y.len()) * N_FFT;
        y[end..].fill(0.0);
    }
}

/// Embed body bits into the frames of `x` in place (format §5, §6). The layout
/// indices start at the first frame of `x`; samples after the last whole
/// frame are not touched (the caller applies the tail rule).
pub fn embed_bits(x: &mut [f64], body: &[u8], layout: &Layout, profile: &Profile, opt: &Options) -> Result<SignInfo> {
    let frames = n_frames(x.len());
    let groups = frames / GROUP;
    let (bp, bm) = (profile.bp(), profile.bm());
    let ps = payload::stream(body, groups * bp, profile.rp, "phase")?;
    let ms = payload::stream(body, groups * bm, profile.rm, "magnitude")?;
    let gp = ps.len().div_ceil(bp);
    let gm = ms.len().div_ceil(bm);
    let used = ((gp - 1) * GROUP + opt.phase_frames).max(gm * GROUP);
    let spec = Stft::analyze(x, used);

    // Written cells inside the band [lo, hi): new phase (NaN = unchanged) and magnitude gain.
    let lo = profile.p_lo.min(profile.m_lo);
    let hi = profile.p_hi.max(profile.m_lo + profile.mag_width());
    let width = hi - lo;
    let mut new_phase = vec![f64::NAN; used * width];
    let mut gain = vec![1.0f64; used * width];
    let mut touched = vec![false; used];
    let cell = |k: usize, t: usize| t * width + (k - lo);

    for (i, &bit) in ps.iter().enumerate() {
        let (g, s) = (i / bp, i % bp);
        let k = layout.phase_bins[s];
        let f = g * GROUP;
        let target = if bit == 1 { FRAC_PI_2 } else { -FRAC_PI_2 };
        let delta = target - angle(spec.at(k, f));
        for t in f..f + opt.phase_frames {
            new_phase[cell(k, t)] = angle(spec.at(k, t)) + delta;
            touched[t] = true;
        }
    }

    let step = profile.delta;
    for (i, &bit) in ms.iter().enumerate() {
        let (g, s) = (i / bm, i % bm);
        let [k1, k2] = layout.mag_pairs[s];
        let f = g * GROUP;
        let d = mean_log(&spec, k1, f) - mean_log(&spec, k2, f);
        let mut c = (d / step).round_ties_even();
        if (c as i64 & 1) as u8 != bit {
            c += if d >= c * step { 1.0 } else { -1.0 };
        }
        let shift = c * step - d;
        let (g1, g2) = ((shift / 2.0).exp(), (-shift / 2.0).exp());
        for t in f..f + GROUP {
            gain[cell(k1, t)] = g1;
            gain[cell(k2, t)] = g2;
            touched[t] = true;
        }
    }

    let synth = |t: usize, out: &mut [f64], (buf, scratch): &mut (Vec<Complex64>, Vec<Complex64>)| {
        buf.copy_from_slice(spec.frame(t));
        for (k, b) in (lo..hi).zip(&mut buf[lo..hi]) {
            let c = cell(k, t);
            let p = new_phase[c];
            if !p.is_nan() {
                let a = abs(*b) * gain[c];
                let w = wrap(p);
                *b = Complex64::new(a * w.cos(), a * w.sin());
            } else if gain[c] != 1.0 {
                *b *= gain[c];
            }
        }
        inverse_frame(buf, out, scratch);
    };
    let init = || (vec![Complex64::new(0.0, 0.0); N_BINS], Vec::new());
    let region = &mut x[..used * N_FFT];
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        region
            .par_chunks_mut(N_FFT)
            .enumerate()
            .filter(|(t, _)| touched[*t])
            .for_each_init(init, |st, (t, out)| synth(t, out, st));
    }
    #[cfg(not(feature = "parallel"))]
    {
        let mut st = init();
        for (t, out) in region.chunks_mut(N_FFT).enumerate() {
            if touched[t] {
                synth(t, out, &mut st);
            }
        }
    }

    Ok(SignInfo {
        profile: profile.id,
        seed: layout.seed,
        message_len: (body.len() / 8).saturating_sub(crate::params::PAYLOAD_OVERHEAD),
        body_bits: body.len(),
        frames,
        groups,
        phase_capacity: groups * bp,
        phase_stream: ps.len(),
        phase_replicas: (ps.len() - 96) / body.len(),
        mag_capacity: groups * bm,
        mag_stream: ms.len(),
        mag_replicas: (ms.len() - 96) / body.len(),
    })
}

/// `np.mean(np.log(A[k, f:f+8] + 1e-8))`.
#[inline]
pub(crate) fn mean_log(spec: &Stft, k: usize, f: usize) -> f64 {
    let mut l = [0.0f64; GROUP];
    for (j, v) in l.iter_mut().enumerate() {
        *v = (abs(spec.at(k, f + j)) + LOG_EPS).ln();
    }
    group_mean(&l)
}

/// `np.mean(A[k, f:f+8])`.
#[inline]
pub(crate) fn mean_abs(spec: &Stft, k: usize, f: usize) -> f64 {
    let mut a = [0.0f64; GROUP];
    for (j, v) in a.iter_mut().enumerate() {
        *v = abs(spec.at(k, f + j));
    }
    group_mean(&a)
}
