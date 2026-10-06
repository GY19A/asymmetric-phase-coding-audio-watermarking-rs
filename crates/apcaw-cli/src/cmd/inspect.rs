// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw inspect`: capacity, voted header length and soft-value statistics
//! of both channels under both profiles (the reference's lines and JSON).

use serde_json::Value;

use apcaw::inspect::ChannelStats;
use apcaw::{InspectReport, PublicKey, SAMPLE_RATE};

use crate::cli::InspectArgs;
use crate::cmd::{load, options, show_notes, with_file, Ctx};
use crate::errors::{CliError, CliResult, EXIT_OK};
use crate::keyfile::{self, KeyArg};

/// Inspect decoded samples.
pub fn inspect_samples(x: &[f64], pk: &PublicKey, legacy: bool) -> CliResult<InspectReport> {
    apcaw::inspect(x, SAMPLE_RATE, pk, &options(legacy)).map_err(|e| CliError::fail(e.to_string()))
}

/// The JSON report: `{file, samples, frames, seed, profiles}`.
pub fn report_json(file: &str, r: &InspectReport) -> Value {
    with_file(file, r)
}

fn channel_line(name: &str, ch: &str, e: &ChannelStats) -> String {
    let opt = |v: Option<String>| v.unwrap_or_else(|| "None".into());
    format!(
        "{name} {ch:9} capacity {:5}  header_length {}  mean|soft| over {} bits {}  erased {}",
        e.capacity,
        opt(e.header_length.map(|l| l.to_string())),
        e.stream_bits,
        opt(e.mean_abs_soft.map(|m| format!("{m:.4}"))),
        e.erased
    )
}

/// The reference's text lines.
pub fn report_lines(file: &str, r: &InspectReport) -> (String, Vec<String>) {
    let head = format!("{file}: {} samples, {} frames, seed {}", r.samples, r.frames, r.seed);
    let mut lines = Vec::new();
    for (name, p) in &r.profiles {
        lines.push(channel_line(name, "phase", &p.phase));
        lines.push(channel_line(name, "magnitude", &p.magnitude));
    }
    (head, lines)
}

pub fn run(ctx: &Ctx, a: &InspectArgs) -> CliResult<i32> {
    let x = load(ctx, &a.input, a.channel.channel)?;
    let pk = keyfile::public(&KeyArg::File(a.public_key.clone()))?;
    show_notes(&ctx.ui, &x);
    let r = inspect_samples(&x.samples, &pk, a.legacy)?;
    if ctx.ui.json {
        ctx.ui.json(&report_json(&a.input, &r));
    } else {
        let (head, lines) = report_lines(&a.input, &r);
        ctx.ui.line(&head);
        // the per-channel lines are the reference's output, printed with -q too
        for l in lines {
            ctx.ui.line(&format!("  {l}"));
        }
    }
    Ok(EXIT_OK)
}
