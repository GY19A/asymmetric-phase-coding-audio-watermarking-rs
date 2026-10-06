// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw verify`: the reference's result line (`VERIFIED  message=...` /
//! `NOT VERIFIED  reason`) and JSON, plus `--scan` for segmented signing.

use serde_json::{json, Value};

use apcaw::{Options, Profile, PublicKey, ScanReport, VerifyReport, SAMPLE_RATE};

use crate::audio::Loaded;
use crate::cli::{VerifyArgs, VerifyProfile};
use crate::cmd::{input_text, load, options, show_notes, with_file, Ctx};
use crate::errors::{CliError, CliResult, EXIT_FAIL, EXIT_OK};
use crate::keyfile::{self, KeyArg};
use crate::report::{py_repr, Paint};

/// One verification request (CLI, `batch-verify`, `serve`).
#[derive(Debug, Clone)]
pub struct VerifyJob {
    pub input: String,
    pub profile: Option<Profile>,
    pub legacy: bool,
    pub resync: bool,
    /// Scan windows of this many groups.
    pub scan: Option<usize>,
    pub channel: Option<usize>,
}

/// The outcome of a [`VerifyJob`].
#[derive(Debug)]
pub enum Outcome {
    Plain(VerifyReport),
    Scan(ScanReport),
}

impl Outcome {
    pub fn verified(&self) -> bool {
        match self {
            Outcome::Plain(r) => r.verified,
            Outcome::Scan(s) => s.verified(),
        }
    }

    /// The JSON report: the reference's `_result_json`, or the scan report.
    pub fn json(&self, file: &str) -> Value {
        match self {
            Outcome::Plain(r) => with_file(file, r),
            Outcome::Scan(s) => json!({
                "file": file,
                "verified": s.verified(),
                "segment_groups": s.segment_groups,
                "groups": s.groups,
                "windows_tried": s.windows_tried,
                "blocks": s.blocks.iter().map(|h| json!({
                    "start_group": h.start_group,
                    "groups": h.groups,
                    "start_sample": h.start_sample,
                    "end_sample": h.end_sample,
                    "start_seconds": h.start_sample as f64 / SAMPLE_RATE as f64,
                    "report": h.report,
                })).collect::<Vec<_>>(),
            }),
        }
    }
}

/// The reference's result line for a report.
pub fn result_line(r: &VerifyReport) -> String {
    if r.verified {
        format!(
            "VERIFIED  message={}  channel={} profile={} path={} rs_corrected={}",
            py_repr(&r.message_text().unwrap_or_default()),
            r.channel.map_or("None", |c| c.as_str()),
            r.profile.unwrap_or("None"),
            r.path.map_or("None", |p| p.as_str()),
            r.rs_corrected.map_or("None".into(), |n| n.to_string())
        )
    } else {
        format!("NOT VERIFIED  {}", r.reason)
    }
}

/// Verify decoded samples.
pub fn verify_samples(x: &[f64], pk: &PublicKey, job: &VerifyJob, opt: &Options) -> CliResult<Outcome> {
    match job.scan {
        None => Ok(Outcome::Plain(apcaw::verify(x, SAMPLE_RATE, pk, job.profile.as_ref(), opt, job.resync))),
        Some(k) => apcaw::scan(x, SAMPLE_RATE, pk, job.profile.as_ref(), opt, k)
            .map(Outcome::Scan)
            .map_err(|e| CliError::usage(e.to_string())),
    }
}

/// Load and verify one input.
pub fn verify_job(ctx: &Ctx, job: &VerifyJob, pk: &PublicKey) -> CliResult<(Loaded, Outcome)> {
    let x = load(ctx, &job.input, job.channel)?;
    let r = verify_samples(&x.samples, pk, job, &options(job.legacy))?;
    Ok((x, r))
}

/// Detail lines of a verification.
pub fn details(input: &str, x: &Loaded, o: &Outcome) -> Vec<String> {
    let mut d = vec![input_text(input, x)];
    match o {
        Outcome::Plain(r) => {
            if let (Some(m), Some(bits)) = (&r.message, r.payload_bits) {
                d.push(format!("message   {} bytes, hex {}", m.len(), apcaw::keys::to_hex(m)));
                d.push(format!("payload   {bits} body bits"));
            }
            d.push(format!(
                "decoder   {} candidate(s), {} RS-decoded, {} signature check(s)",
                r.candidates_tried, r.rs_passes, r.sig_checks
            ));
        }
        Outcome::Scan(s) => {
            for h in &s.blocks {
                d.push(format!(
                    "block     groups {}..{} ({:.2}-{:.2} s): {}",
                    h.start_group,
                    h.start_group + h.groups,
                    h.start_sample as f64 / SAMPLE_RATE as f64,
                    h.end_sample as f64 / SAMPLE_RATE as f64,
                    result_line(&h.report)
                ));
            }
            d.push(format!(
                "scan      {} window(s) of {} groups over {} groups",
                s.windows_tried, s.segment_groups, s.groups
            ));
        }
    }
    d
}

pub fn run(ctx: &Ctx, a: &VerifyArgs) -> CliResult<i32> {
    let job = VerifyJob {
        input: a.input.clone(),
        profile: VerifyProfile::profile(a.profile),
        legacy: a.legacy,
        resync: a.resync,
        scan: a.scan,
        channel: a.channel.channel,
    };
    // the reference's order: decode, read the key, then the notes
    let x = load(ctx, &job.input, job.channel)?;
    let pk = keyfile::public(&KeyArg::File(a.public_key.clone()))?;
    show_notes(&ctx.ui, &x);
    let o = verify_samples(&x.samples, &pk, &job, &options(job.legacy))?;
    if ctx.ui.json {
        ctx.ui.json(&o.json(&a.input));
    } else {
        let line = match &o {
            Outcome::Plain(r) => result_line(r),
            Outcome::Scan(s) if s.verified() => {
                format!("VERIFIED  {} block(s) of {} groups", s.blocks.len(), s.segment_groups)
            }
            Outcome::Scan(s) => {
                format!("NOT VERIFIED  no window of {} groups verified ({} tried)", s.segment_groups, s.windows_tried)
            }
        };
        let paint = if o.verified() { Paint::Green } else { Paint::Red };
        let (head, rest) = line.split_once("  ").unwrap_or((&line, ""));
        ctx.ui.line(&format!("{}  {rest}", ctx.ui.paint(head, paint)));
        for d in details(&a.input, &x, &o) {
            ctx.ui.detail(&d);
        }
    }
    Ok(if o.verified() { EXIT_OK } else { EXIT_FAIL })
}
