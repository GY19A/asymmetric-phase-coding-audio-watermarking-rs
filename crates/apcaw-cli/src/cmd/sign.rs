// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw sign`: embed, encode, and (by default) re-read the written file
//! and verify it through the same decoder and verifier as `apcaw verify`
//! before it replaces the output (format §9). Nothing is left at the output
//! path when that closed-loop check fails.

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use serde_json::{json, Value};

use apcaw::params::{n_frames, MAX_MSG_LEN, N_BINS};
use apcaw::segment::SegmentInfo;
use apcaw::stft::Stft;
use apcaw::{Options, Profile, PublicKey, ScanReport, VerifyReport, SAMPLE_RATE};

use crate::audio::{self, OutCodec, TempFile};
use crate::cli::{SignArgs, SignProfile};
use crate::cmd::{input_text, load, options, Ctx};
use crate::errors::{py_os_error, strerror, CliError, CliResult, EXIT_OK};
use crate::keyfile::{self, KeyArg};
use crate::report::to_py_json;

/// First STFT bin above 4 kHz (`186 * 44100 / 2048 = 4005 Hz`).
pub const AUTO_BIN: usize = 186;
/// `--profile auto` picks nb below this fraction of the energy above 4 kHz.
pub const AUTO_THRESHOLD: f64 = 0.05;

/// One signing, as the CLI and `serve` describe it.
#[derive(Debug, Clone)]
pub struct SignJob {
    pub input: String,
    /// Output path, `-` for standard output.
    pub output: String,
    pub key: KeyArg,
    pub message: Vec<u8>,
    pub profile: SignProfile,
    pub legacy: bool,
    /// Segmented signing with blocks of this many groups.
    pub segment: Option<usize>,
    pub closed_loop: bool,
    pub sidecar: bool,
    /// Output encoding (default from the output name).
    pub codec: Option<OutCodec>,
    pub channel: Option<usize>,
    /// Replace existing output files.
    pub overwrite: bool,
}

/// A completed signing.
#[derive(Debug)]
pub struct Signed {
    /// The JSON report (`--json`, `--sidecar`, `serve`).
    pub report: Value,
    /// The result line.
    pub line: String,
    /// Detail lines.
    pub details: Vec<String>,
    /// The encoded file when the output is `-`.
    pub stdout: Option<Vec<u8>>,
}

/// Fraction of the STFT energy in the bins above 4 kHz; `None` for a silent
/// or sub-frame input.
pub fn high_band_fraction(x: &[f64]) -> Option<f64> {
    let t = n_frames(x.len());
    let s = Stft::analyze(x, t);
    let (mut hi, mut total) = (0.0, 0.0);
    for f in 0..t {
        for (k, c) in s.frame(f).iter().enumerate().take(N_BINS) {
            let e = c.norm_sqr();
            total += e;
            if k >= AUTO_BIN {
                hi += e;
            }
        }
    }
    (total > 0.0).then(|| hi / total)
}

/// The profile to sign with, and the `auto` measurement.
pub fn choose_profile(p: SignProfile, x: &[f64]) -> (Profile, Option<Option<f64>>) {
    match p {
        SignProfile::Wb => (Profile::WB, None),
        SignProfile::Nb => (Profile::NB, None),
        SignProfile::Auto => {
            let f = high_band_fraction(x);
            let nb = f.is_some_and(|f| f < AUTO_THRESHOLD);
            (if nb { Profile::NB } else { Profile::WB }, Some(f))
        }
    }
}

/// What the closed loop found.
enum Check {
    Plain(VerifyReport),
    Segments(ScanReport),
}

/// Verify the re-read output: `Err(reason)` unless it carries `msg`
/// (in every signed block, for segmented signing).
fn check(
    back: &[f64],
    pk: &PublicKey,
    profile: &Profile,
    opt: &Options,
    msg: &[u8],
    seg: Option<&SegmentInfo>,
) -> Result<Check, String> {
    let Some(seg) = seg else {
        let r = apcaw::verify(back, SAMPLE_RATE, pk, Some(profile), opt, false);
        return match (r.verified, r.message.as_deref() == Some(msg)) {
            (true, true) => Ok(Check::Plain(r)),
            (true, false) => Err("it carries a different message".into()),
            _ => Err(r.reason),
        };
    };
    let s = apcaw::scan(back, SAMPLE_RATE, pk, Some(profile), opt, seg.segment_groups).map_err(|e| e.to_string())?;
    for b in seg.blocks.iter().filter(|b| b.info.is_some()) {
        let ok = s
            .blocks
            .iter()
            .any(|h| h.start_group == b.start_group && h.report.verified && h.report.message.as_deref() == Some(msg));
        if !ok {
            return Err(format!(
                "the block at group {} ({:.2} s) does not verify",
                b.start_group,
                b.start_sample as f64 / SAMPLE_RATE as f64
            ));
        }
    }
    Ok(Check::Segments(s))
}

/// Run a signing; `note` receives the notes (conversions, clipping) as they happen.
pub fn sign_job(ctx: &Ctx, job: &SignJob, note: &dyn Fn(&str)) -> CliResult<Signed> {
    let msg = &job.message;
    if msg.len() > MAX_MSG_LEN {
        return Err(CliError::usage(format!("message too long: {} bytes > {MAX_MSG_LEN}", msg.len())));
    }
    let to_stdout = job.output == "-";
    let sidecar = format!("{}.apcaw.json", job.output);
    if job.sidecar && to_stdout {
        return Err(CliError::usage("--sidecar needs an output file, not -o -"));
    }
    if !to_stdout && !job.overwrite {
        let outs = [Some(job.output.as_str()), job.sidecar.then_some(sidecar.as_str())];
        if let Some(p) = outs.into_iter().flatten().find(|p| Path::new(p).exists()) {
            return Err(CliError::usage(format!("{p} exists (use -y to overwrite)")));
        }
    }
    let x = load(ctx, &job.input, job.channel)?;
    let sk = keyfile::secret(&job.key)?;
    for n in &x.notes {
        note(n);
    }
    let (profile, auto) = choose_profile(job.profile, &x.samples);
    let opt = options(job.legacy);

    let t0 = Instant::now();
    let failed = |e: apcaw::Error| CliError::fail(format!("signing failed: {e}"));
    let (y, info, seg) = match job.segment {
        None => {
            let (y, info) = apcaw::sign_detailed(&x.samples, SAMPLE_RATE, &sk, msg, &profile, &opt).map_err(failed)?;
            (y, Some(info), None)
        }
        Some(k) => {
            let (y, seg) =
                apcaw::sign_segmented(&x.samples, SAMPLE_RATE, &sk, msg, &profile, &opt, k).map_err(failed)?;
            (y, None, Some(seg))
        }
    };
    let t_sign = t0.elapsed();
    let codec = job.codec.unwrap_or_else(|| OutCodec::for_path(&job.output));
    let clipped = codec.clipped(&y);
    if clipped > 0 {
        note(&format!("{clipped} samples clipped to [-1, 1)"));
    }
    let bytes = audio::encode(&y, codec, &ctx.tools)?;
    let pk = sk.public_key();

    let t1 = Instant::now();
    let cannot_write =
        |e: std::io::Error, p: &str| CliError::io(format!("cannot write {}: {}", job.output, py_os_error(&e, p)));
    let does_not_verify = |why: String| {
        CliError::fail(format!(
            "signing failed: the written file does not verify ({why}); nothing written to {}",
            job.output
        ))
    };
    let mut stdout = None;
    let checked = if to_stdout {
        let c = if job.closed_loop {
            let back = audio::decode(&bytes, "-", None, None, &ctx.tools)?;
            Some(check(&back.samples, &pk, &profile, &opt, msg, seg.as_ref()).map_err(does_not_verify)?)
        } else {
            None
        };
        stdout = Some(bytes);
        c
    } else {
        let out = Path::new(&job.output);
        let tmp = TempFile::beside(out).map_err(|e| cannot_write(e, &job.output))?;
        fs::write(tmp.path(), &bytes).map_err(|e| cannot_write(e, &tmp.path().to_string_lossy()))?;
        let c = if job.closed_loop {
            let back = match tmp.path().to_str() {
                Some(p) => audio::load(p, None, &ctx.tools)?,
                None => audio::decode(&bytes, &job.output, None, None, &ctx.tools)?,
            };
            Some(check(&back.samples, &pk, &profile, &opt, msg, seg.as_ref()).map_err(does_not_verify)?)
        } else {
            None
        };
        tmp.persist(out).map_err(|e| cannot_write(e, &job.output))?;
        c
    };
    let t_check = t1.elapsed();
    ctx.ui.debug(|| {
        format!("sign {:.1} ms, encode + closed loop {:.1} ms", t_sign.as_secs_f64() * 1e3, t_check.as_secs_f64() * 1e3)
    });

    // report
    let closed_loop = match &checked {
        None => Value::Null,
        Some(Check::Plain(r)) => json!({
            "verified": true,
            "channel": r.channel,
            "path": r.path,
            "profile": r.profile,
            "rs_corrected": r.rs_corrected,
        }),
        Some(Check::Segments(s)) => json!({
            "verified": true,
            "blocks_verified": s.blocks.iter().filter(|h| h.report.message.as_deref() == Some(msg.as_slice())).count(),
            "windows_tried": s.windows_tried,
        }),
    };
    let auto_json = auto.map(|f| json!({"energy_above_4khz": f, "threshold": AUTO_THRESHOLD}));
    let report = json!({
        "signed": true,
        "file": job.output,
        "input": job.input,
        "message_len": msg.len(),
        "message_hex": apcaw::keys::to_hex(msg),
        "profile": profile.id,
        "profile_auto": auto_json,
        "legacy": job.legacy,
        "codec": codec.name(),
        "clipped": clipped,
        "closed_loop": closed_loop,
        "segment": seg,
        "sign": info,
    });

    let lead = format!("signed {}: {}-byte message, profile {}", job.output, msg.len(), profile.id);
    let line = match (&checked, &seg) {
        (None, None) => format!("{lead}, closed-loop verify skipped"),
        (None, Some(s)) => {
            format!("{lead}, {} segment(s) of {} groups, closed-loop verify skipped", s.embedded(), s.segment_groups)
        }
        (Some(Check::Plain(r)), _) => format!(
            "{lead}, closed-loop verify ok (channel {}, path {})",
            r.channel.map_or("None", |c| c.as_str()),
            r.path.map_or("None", |p| p.as_str())
        ),
        (Some(Check::Segments(_)), Some(s)) => {
            format!("{lead}, {} segment(s) of {} groups, closed-loop verify ok", s.embedded(), s.segment_groups)
        }
        (Some(Check::Segments(_)), None) => unreachable!("segment check without segments"),
    };

    let mut details = vec![input_text(&job.input, &x)];
    if let Some(f) = auto {
        details.push(match f {
            Some(f) => format!(
                "profile   auto -> {} (energy above 4 kHz {:.2}% {} {:.0}%)",
                profile.id,
                f * 100.0,
                if f < AUTO_THRESHOLD { "<" } else { ">=" },
                AUTO_THRESHOLD * 100.0
            ),
            None => format!("profile   auto -> {} (no signal energy)", profile.id),
        });
    }
    let first = info.as_ref().or_else(|| seg.as_ref().and_then(|s| s.blocks.iter().find_map(|b| b.info.as_ref())));
    if let Some(i) = first {
        details.push(format!(
            "payload   {} body bits, layout seed {}{}",
            i.body_bits,
            i.seed,
            if job.legacy { " (legacy)" } else { "" }
        ));
        let per = if seg.is_some() { " per segment" } else { "" };
        details.push(format!(
            "phase     capacity {} bits, stream {} bits, {} replica(s){per}",
            i.phase_capacity, i.phase_stream, i.phase_replicas
        ));
        details.push(format!(
            "magnitude capacity {} bits, stream {} bits, {} replica(s){per}",
            i.mag_capacity, i.mag_stream, i.mag_replicas
        ));
    }
    if let Some(s) = &seg {
        let left = s.blocks.len() - s.embedded();
        details.push(format!(
            "segments  {} of {} block(s) signed{}",
            s.embedded(),
            s.blocks.len(),
            if left > 0 { " (a trailing partial block is left unsigned)" } else { "" }
        ));
    }
    details.push(format!(
        "output    {}, {} samples, {clipped} clipped{}",
        codec.name(),
        y.len(),
        if to_stdout { ", standard output" } else { "" }
    ));

    if job.sidecar {
        let text = to_py_json(&report, Some(2)) + "\n";
        fs::write(&sidecar, text)
            .map_err(|e| CliError::io(format!("cannot write {sidecar}: {}", py_os_error(&e, &sidecar))))?;
        details.push(format!("sidecar   {sidecar}"));
    }
    Ok(Signed { report, line, details, stdout })
}

#[cfg(unix)]
fn os_bytes(s: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_bytes(s: &OsStr) -> Vec<u8> {
    s.to_string_lossy().into_owned().into_bytes()
}

pub fn run(ctx: &Ctx, a: &SignArgs) -> CliResult<i32> {
    let message = match (&a.message, &a.message_file) {
        (Some(m), _) => os_bytes(m),
        (None, Some(f)) => {
            fs::read(f).map_err(|e| CliError::io(format!("cannot read message file {f}: {}", strerror(&e))))?
        }
        (None, None) => return Err(CliError::usage("a message is required (-m TEXT or --message-file PATH)")),
    };
    if a.output == "-" {
        ctx.ui.text_to_stderr();
    }
    let job = SignJob {
        input: a.input.clone(),
        output: a.output.clone(),
        key: KeyArg::File(a.key.clone()),
        message,
        profile: a.profile,
        legacy: a.legacy,
        segment: a.segment,
        closed_loop: !a.no_closed_loop,
        sidecar: a.sidecar,
        codec: a.codec,
        channel: a.channel.channel,
        overwrite: ctx.overwrite,
    };
    let s = sign_job(ctx, &job, &|n| ctx.ui.note(n))?;
    if let Some(b) = &s.stdout {
        let mut o = std::io::stdout().lock();
        o.write_all(b)
            .and_then(|_| o.flush())
            .map_err(|e| CliError::io(format!("cannot write standard output: {}", strerror(&e))))?;
    }
    if ctx.ui.json {
        ctx.ui.json(&s.report);
    } else {
        ctx.ui.line(&s.line);
        for d in &s.details {
            ctx.ui.detail(d);
        }
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_profile_measures_the_band_above_4k() {
        let n = 20 * 2048;
        let tone = |f: f64| -> Vec<f64> {
            (0..n).map(|i| (2.0 * std::f64::consts::PI * f * i as f64 / 44100.0).sin() * 0.3).collect()
        };
        let low = high_band_fraction(&tone(1000.0)).unwrap();
        let high = high_band_fraction(&tone(8000.0)).unwrap();
        assert!(low < 0.01 && high > 0.99, "{low} {high}");
        assert_eq!(choose_profile(SignProfile::Auto, &tone(1000.0)).0.id, "nb");
        assert_eq!(choose_profile(SignProfile::Auto, &tone(8000.0)).0.id, "wb");
        assert_eq!(high_band_fraction(&vec![0.0; n]), None);
        assert_eq!(choose_profile(SignProfile::Auto, &[0.0; 10]).0.id, "wb");
    }
}
