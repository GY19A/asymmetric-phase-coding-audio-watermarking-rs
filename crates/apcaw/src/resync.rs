// SPDX-License-Identifier: BSD-2-Clause
//! Optional decoder-side resync (format §8), the Python reference's
//! `apcaw.resync`: score every integer offset `δ ∈ [0, N)` and whole-frame
//! skip `f0 ∈ [0, FMAX]` by the magnitude-weighted phase alignment
//! `Σ|Im Z| / Σ|Z|` over the phase band, then run §8 steps 1–3 on `δ = 0`
//! (every `f0`) and on the 8 best-scoring `δ`. Ed25519 still gates every
//! acceptance; the score only orders the attempts.

use std::cmp::Ordering;

use realfft::num_complex::Complex64;

use crate::params::{n_frames, GROUP, N_BINS, N_FFT};
use crate::stft::{abs, pairwise_sum, Stft};
use crate::verify::{Path, Search, VerifyReport};

/// Largest whole-frame skip tried.
pub const FMAX: usize = 10;
/// Groups whose first frames enter the score.
pub const SCORE_GROUPS: usize = 6;
/// Offsets tried besides `δ = 0`.
pub const TOPK_DELTA: usize = 8;
/// Frames analysed per offset: `FMAX + (SCORE_GROUPS - 1) * G + 1`.
pub const SCORE_FRAMES: usize = FMAX + (SCORE_GROUPS - 1) * GROUP + 1;

/// `S[δ][f0]`; `-1` where the frames `f0 + g·G` (`g < SCORE_GROUPS`) do not
/// all exist or carry no energy. The sums follow numpy's pairwise order, so
/// scores (and hence the attempt order) match the reference to the ulps of
/// the FFT.
pub fn score_grid(x: &[f64], p_lo: usize, p_hi: usize) -> Vec<[f64; FMAX + 1]> {
    let mut s = vec![[-1.0f64; FMAX + 1]; N_FFT];
    let row = |d: usize, out: &mut [f64; FMAX + 1], (buf, spec, scratch, re, im): &mut Bufs| {
        let nf = SCORE_FRAMES.min(x.len().saturating_sub(d) / N_FFT);
        if nf == 0 {
            return;
        }
        let fft = crate::stft::forward_plan();
        let mut num = [0.0f64; SCORE_FRAMES];
        let mut den = [0.0f64; SCORE_FRAMES];
        for f in 0..nf {
            let start = d + f * N_FFT;
            buf.copy_from_slice(&x[start..start + N_FFT]);
            fft.process_with_scratch(buf, spec, scratch).expect("rfft buffer sizes");
            re.clear();
            im.clear();
            for &c in &spec[p_lo..p_hi] {
                im.push(c.im.abs());
                re.push(abs(c));
            }
            num[f] = pairwise_sum(im);
            den[f] = pairwise_sum(re);
        }
        for (f0, v) in out.iter_mut().enumerate() {
            if f0 + (SCORE_GROUPS - 1) * GROUP >= nf {
                continue;
            }
            let (mut n, mut dd) = (0.0f64, 0.0f64);
            for g in 0..SCORE_GROUPS {
                n += num[f0 + g * GROUP];
                dd += den[f0 + g * GROUP];
            }
            *v = if dd > 0.0 { n / dd } else { -1.0 };
        }
    };
    let init = || -> Bufs {
        (
            vec![0.0; N_FFT],
            vec![Complex64::new(0.0, 0.0); N_BINS],
            crate::stft::forward_plan().make_scratch_vec(),
            Vec::with_capacity(N_BINS),
            Vec::with_capacity(N_BINS),
        )
    };
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        s.par_iter_mut().enumerate().for_each_init(init, |b, (d, out)| row(d, out, b));
    }
    #[cfg(not(feature = "parallel"))]
    {
        let mut b = init();
        for (d, out) in s.iter_mut().enumerate() {
            row(d, out, &mut b);
        }
    }
    s
}

type Bufs = (Vec<f64>, Vec<Complex64>, Vec<Complex64>, Vec<f64>, Vec<f64>);

/// numpy `np.argsort(-v, kind="stable")`: descending, ties by index, NaN last.
fn argsort_desc(v: &[f64]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..v.len()).collect();
    idx.sort_by(|&i, &j| {
        let (a, b) = (-v[i], -v[j]);
        match (a.is_nan(), b.is_nan()) {
            (false, false) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
        }
    });
    idx
}

/// numpy `max` of a row: NaN propagates.
fn np_max(row: &[f64]) -> f64 {
    let mut m = row[0];
    for &v in &row[1..] {
        if v.is_nan() || m.is_nan() {
            return f64::NAN;
        }
        if v > m {
            m = v;
        }
    }
    m
}

/// Offsets in the order they are tried: `0`, then the [`TOPK_DELTA`] best
/// rows of `s` by their maximum (stable, ties by `δ`), `0` not repeated.
pub fn delta_order(s: &[[f64; FMAX + 1]]) -> Vec<usize> {
    let best: Vec<f64> = s.iter().map(|r| np_max(r)).collect();
    let mut order = vec![0usize];
    order.extend(argsort_desc(&best).into_iter().take(TOPK_DELTA).filter(|&i| i != 0));
    order
}

/// Try alignments in reference order on the verify state `st` (shared
/// de-duplication and counters). `(δ, f0) = (0, 0)` is the plain path and is skipped.
pub(crate) fn resync_search(x: &[f64], st: &mut Search<'_>) -> Option<VerifyReport> {
    let first = st.profiles[0].0;
    let s = score_grid(x, first.p_lo, first.p_hi);
    for d in delta_order(&s) {
        let xd = &x[d.min(x.len())..];
        let frames = n_frames(xd.len());
        if frames == 0 {
            continue;
        }
        let spec = Stft::analyze(xd, frames);
        for f0 in argsort_desc(&s[d]) {
            let v = s[d][f0];
            if v < 0.0 || (d, f0) == (0, 0) {
                continue;
            }
            if let Some(r) = st.run(&spec, f0, Some(Path::Resync)) {
                return Some(VerifyReport { reason: format!("ok (resync delta={d} f0={f0})"), ..r });
            }
        }
    }
    None
}
