// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw bench`: wall-clock time of sign and verify on one input, after a
//! warm-up run, in a 1-thread pool and in an N-thread pool (`--threads`).

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use apcaw::{keygen_from_seed, Profile, SecretKey, SAMPLE_RATE};

use crate::cli::BenchArgs;
use crate::cmd::sign::choose_profile;
use crate::cmd::{input_text, load, options, show_notes, Ctx};
use crate::errors::{CliError, CliResult, EXIT_OK};
use crate::keyfile::{self, KeyArg};

/// Mean, median and minimum of a series, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Stats {
    pub mean: f64,
    pub median: f64,
    pub min: f64,
}

impl Stats {
    pub fn of(d: &[Duration]) -> Stats {
        let mut ms: Vec<f64> = d.iter().map(|d| d.as_secs_f64() * 1e3).collect();
        ms.sort_by(f64::total_cmp);
        let n = ms.len().max(1);
        let median = match ms.len() {
            0 => 0.0,
            l if l % 2 == 1 => ms[l / 2],
            l => (ms[l / 2 - 1] + ms[l / 2]) / 2.0,
        };
        Stats { mean: ms.iter().sum::<f64>() / n as f64, median, min: ms.first().copied().unwrap_or(0.0) }
    }
}

/// Times for one pool size.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Run {
    pub threads: usize,
    pub sign_ms: Stats,
    pub verify_ms: Stats,
    /// Mean of sign + verify.
    pub total_ms: f64,
}

fn time_pool(
    threads: usize,
    repeat: usize,
    x: &[f64],
    sk: &SecretKey,
    msg: &[u8],
    profile: &Profile,
    legacy: bool,
) -> CliResult<Run> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| CliError::io(format!("cannot start {threads} threads: {e}")))?;
    let pk = sk.public_key();
    let opt = options(legacy);
    pool.install(|| {
        let (mut ts, mut tv) = (Vec::with_capacity(repeat), Vec::with_capacity(repeat));
        // run 0 is the warm-up
        for i in 0..=repeat {
            let t = Instant::now();
            let y = apcaw::sign(x, SAMPLE_RATE, sk, msg, profile, &opt)
                .map_err(|e| CliError::fail(format!("signing failed: {e}")))?;
            let t_sign = t.elapsed();
            let t = Instant::now();
            let r = apcaw::verify(&y, SAMPLE_RATE, &pk, None, &opt, false);
            let t_verify = t.elapsed();
            if !r.verified {
                return Err(CliError::fail(format!("the signed signal does not verify ({})", r.reason)));
            }
            if i > 0 {
                ts.push(t_sign);
                tv.push(t_verify);
            }
        }
        let (sign_ms, verify_ms) = (Stats::of(&ts), Stats::of(&tv));
        Ok(Run { threads, sign_ms, verify_ms, total_ms: sign_ms.mean + verify_ms.mean })
    })
}

pub fn run(ctx: &Ctx, a: &BenchArgs) -> CliResult<i32> {
    let x = load(ctx, &a.input, a.channel.channel)?;
    let sk = match &a.key {
        Some(k) => keyfile::secret(&KeyArg::File(k.clone()))?,
        None => {
            let mut seed = [0u8; 32];
            seed.iter_mut().zip(0u8..).for_each(|(b, i)| *b = i);
            keygen_from_seed(seed).secret
        }
    };
    show_notes(&ctx.ui, &x);
    let (profile, _) = choose_profile(a.profile, &x.samples);
    let msg = a.message.as_bytes();
    let mut pools = vec![1];
    if ctx.threads > 1 {
        pools.push(ctx.threads);
    }
    let runs = pools
        .into_iter()
        .map(|t| time_pool(t, a.repeat, &x.samples, &sk, msg, &profile, a.legacy))
        .collect::<CliResult<Vec<_>>>()?;
    let secs = x.samples.len() as f64 / SAMPLE_RATE as f64;
    if ctx.ui.json {
        let v: Value = json!({
            "file": a.input,
            "seconds": secs,
            "samples": x.samples.len(),
            "profile": profile.id,
            "legacy": a.legacy,
            "message_len": msg.len(),
            "repeat": a.repeat,
            "runs": runs,
        });
        ctx.ui.json(&v);
        return Ok(EXIT_OK);
    }
    ctx.ui.line(&format!(
        "bench {}: {secs:.2} s of audio, profile {}, mean of {} run(s) after a warm-up",
        a.input, profile.id, a.repeat
    ));
    ctx.ui.detail(&input_text(&a.input, &x));
    for r in &runs {
        ctx.ui.line(&format!(
            "  threads {:<3} sign {:7.2} ms  verify {:7.2} ms  total {:7.2} ms  ({:.0}x real time)",
            r.threads,
            r.sign_ms.mean,
            r.verify_ms.mean,
            r.total_ms,
            secs * 1e3 / r.total_ms.max(1e-9)
        ));
        ctx.ui.detail(&format!(
            "            sign median {:.2} min {:.2}, verify median {:.2} min {:.2}",
            r.sign_ms.median, r.sign_ms.min, r.verify_ms.median, r.verify_ms.min
        ));
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats() {
        let d = |ms: &[u64]| ms.iter().map(|&m| Duration::from_millis(m)).collect::<Vec<_>>();
        let s = Stats::of(&d(&[3, 1, 2, 10]));
        assert_eq!((s.mean, s.median, s.min), (4.0, 2.5, 1.0));
        assert_eq!(Stats::of(&d(&[5, 1, 3])).median, 3.0);
    }
}
