// SPDX-License-Identifier: BSD-2-Clause
//! Non-overlapping rectangular STFT, `N = hop = 2048`, no centering (format §1).
//!
//! `realfft` (rustfft) matches numpy's pocketfft to a few ulps; the inverse is
//! unnormalized in realfft, so frames are scaled by `1/N` (exact, a power of two).

use std::sync::{Arc, OnceLock};

use realfft::num_complex::Complex64;
use realfft::{ComplexToReal, RealFftPlanner, RealToComplex};

use crate::params::{N_BINS, N_FFT};

struct Plans {
    fwd: Arc<dyn RealToComplex<f64>>,
    inv: Arc<dyn ComplexToReal<f64>>,
}

fn plans() -> &'static Plans {
    static P: OnceLock<Plans> = OnceLock::new();
    P.get_or_init(|| {
        let mut planner = RealFftPlanner::<f64>::new();
        Plans { fwd: planner.plan_fft_forward(N_FFT), inv: planner.plan_fft_inverse(N_FFT) }
    })
}

/// The shared forward plan (`N = 2048`).
pub(crate) fn forward_plan() -> &'static Arc<dyn RealToComplex<f64>> {
    &plans().fwd
}

/// Spectrum of consecutive frames, frame-major: bin `k` of frame `t` is `data[t * 1025 + k]`.
#[derive(Clone, Debug)]
pub struct Stft {
    /// Number of frames.
    pub frames: usize,
    /// `frames * 1025` complex bins.
    pub data: Vec<Complex64>,
}

impl Stft {
    /// rfft of frames `0..frames` of `x` (frame `t` is `x[t*N .. (t+1)*N]`).
    pub fn analyze(x: &[f64], frames: usize) -> Stft {
        assert!(x.len() >= frames * N_FFT, "signal shorter than the requested frames");
        let mut data = vec![Complex64::new(0.0, 0.0); frames * N_BINS];
        let run = |(t, out): (usize, &mut [Complex64]), (buf, scratch): &mut (Vec<f64>, Vec<Complex64>)| {
            buf.copy_from_slice(&x[t * N_FFT..(t + 1) * N_FFT]);
            plans().fwd.process_with_scratch(buf, out, scratch).expect("rfft buffer sizes");
        };
        let init = || (vec![0.0; N_FFT], plans().fwd.make_scratch_vec());
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            data.par_chunks_mut(N_BINS).enumerate().for_each_init(init, |st, job| run(job, st));
        }
        #[cfg(not(feature = "parallel"))]
        {
            let mut st = init();
            data.chunks_mut(N_BINS).enumerate().for_each(|job| run(job, &mut st));
        }
        Stft { frames, data }
    }

    /// Bins of frame `t`.
    #[inline]
    pub fn frame(&self, t: usize) -> &[Complex64] {
        &self.data[t * N_BINS..(t + 1) * N_BINS]
    }

    /// `X[k, t]`.
    #[inline]
    pub fn at(&self, k: usize, t: usize) -> Complex64 {
        self.data[t * N_BINS + k]
    }
}

/// `irfft(spec, n=2048)` into `out`, the numpy `norm="backward"` scaling.
/// The imaginary parts of DC and Nyquist are ignored, as numpy does.
/// `spec` is used as scratch space and left unspecified.
pub fn inverse_frame(spec: &mut [Complex64], out: &mut [f64], scratch: &mut Vec<Complex64>) {
    spec[0].im = 0.0;
    spec[N_BINS - 1].im = 0.0;
    if scratch.len() < plans().inv.get_scratch_len() {
        *scratch = plans().inv.make_scratch_vec();
    }
    plans().inv.process_with_scratch(spec, out, scratch).expect("irfft buffer sizes");
    const SCALE: f64 = 1.0 / N_FFT as f64;
    for v in out.iter_mut() {
        *v *= SCALE;
    }
}

/// `np.angle`: `atan2(im, re)`.
#[inline]
pub fn angle(z: Complex64) -> f64 {
    z.im.atan2(z.re)
}

/// `np.abs` of a complex value: `hypot(re, im)`.
#[inline]
pub fn abs(z: Complex64) -> f64 {
    z.re.hypot(z.im)
}

/// Mean of the 8 values of a group, summed left to right then divided by 8.
///
/// This is the Python reference's `_group_mean` (`acc = v0; acc = acc + v1; ...; acc / G`),
/// not numpy's pairwise `np.mean`; the two differ in the last bits.
#[inline]
pub fn group_mean(a: &[f64; 8]) -> f64 {
    let mut acc = a[0];
    for &v in &a[1..] {
        acc += v;
    }
    acc / 8.0
}

/// numpy `(p + π) % (2π) - π` with Python/numpy floor-mod semantics.
#[inline]
pub fn wrap(p: f64) -> f64 {
    const TAU: f64 = 2.0 * std::f64::consts::PI;
    np_remainder(p + std::f64::consts::PI, TAU) - std::f64::consts::PI
}

/// numpy `np.remainder` for float64 (`npy_divmod`): C `fmod`, then shifted to
/// the divisor's sign; a zero result takes the divisor's sign.
#[inline]
pub fn np_remainder(a: f64, b: f64) -> f64 {
    let m = a % b;
    if m != 0.0 {
        if (b < 0.0) != (m < 0.0) {
            m + b
        } else {
            m
        }
    } else {
        0.0f64.copysign(b)
    }
}

/// numpy's `np.sum` of a contiguous float64 array (`pairwise_sum` in
/// `loops_utils.h`): blocks of up to 128 values use eight interleaved
/// accumulators, longer arrays split recursively at a multiple of 8.
pub fn pairwise_sum(a: &[f64]) -> f64 {
    let n = a.len();
    if n < 8 {
        let mut res = 0.0;
        for &v in a {
            res += v;
        }
        res
    } else if n <= 128 {
        let mut r = [0.0f64; 8];
        r.copy_from_slice(&a[..8]);
        let body = n - n % 8;
        let mut i = 8;
        while i < body {
            for j in 0..8 {
                r[j] += a[i + j];
            }
            i += 8;
        }
        let mut res = ((r[0] + r[1]) + (r[2] + r[3])) + ((r[4] + r[5]) + (r[6] + r[7]));
        for &v in &a[body..] {
            res += v;
        }
        res
    } else {
        let mut n2 = n / 2;
        n2 -= n2 % 8;
        pairwise_sum(&a[..n2]) + pairwise_sum(&a[n2..])
    }
}
