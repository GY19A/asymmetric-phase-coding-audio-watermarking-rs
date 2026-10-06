// SPDX-License-Identifier: BSD-2-Clause
//! The subcommands. Each returns its exit code or a [`CliError`](crate::errors::CliError);
//! the pieces `serve` reuses (sign jobs, report JSON) live next to the command.

pub mod batch;
pub mod bench;
pub mod inspect;
pub mod keygen;
pub mod layout;
pub mod selftest;
pub mod serve;
pub mod sign;
pub mod verify;

use serde::Serialize;
use serde_json::{Map, Value};

use apcaw::Options;

use crate::audio::{self, Loaded, Tools};
use crate::errors::CliResult;
use crate::report::Ui;

/// Settings shared by the subcommands.
#[derive(Debug)]
pub struct Ctx {
    pub ui: Ui,
    pub tools: Tools,
    /// `--threads` (default: all cores).
    pub threads: usize,
    /// `-y` / `--force`.
    pub overwrite: bool,
}

/// The reference's `_options`: `Options.legacy()` with `--legacy`.
pub fn options(legacy: bool) -> Options {
    if legacy {
        Options::legacy()
    } else {
        Options::v1()
    }
}

/// Decode an input to mono 44100 Hz (notes are left to [`show_notes`], which
/// the commands call after loading the key, in the reference's order).
pub fn load(ctx: &Ctx, path: &str, channel: Option<usize>) -> CliResult<Loaded> {
    if ctx.ui.verbose > 0 {
        if let Some(p) = audio::probe(path, &ctx.tools) {
            ctx.ui.debug(|| format!("ffprobe {path}: {p}"));
        }
    }
    let a = audio::load(path, channel, &ctx.tools)?;
    ctx.ui.debug(|| {
        format!(
            "{path}: {} Hz, {} channel(s), {} via {}; {} samples at 44100 Hz",
            a.source_rate,
            a.channels,
            a.encoding,
            a.decoder,
            a.samples.len()
        )
    });
    Ok(a)
}

/// `apcaw: note: ...` for the conversions of an input.
pub fn show_notes(ui: &Ui, a: &Loaded) {
    for n in &a.notes {
        ui.note(n);
    }
}

/// `{"file": file, ...v}`: a report object with the file name first.
pub fn with_file<T: Serialize + ?Sized>(file: &str, v: &T) -> Value {
    let mut m = Map::new();
    m.insert("file".into(), Value::String(file.into()));
    match serde_json::to_value(v).expect("report serializes") {
        Value::Object(o) => m.extend(o),
        other => {
            m.insert("report".into(), other);
        }
    }
    Value::Object(m)
}

/// `1 channel` / `2 channels`.
pub fn channels_text(n: usize) -> String {
    match n {
        1 => "mono".into(),
        n => format!("{n} channels"),
    }
}

/// A one-line description of a decoded input.
pub fn input_text(path: &str, a: &Loaded) -> String {
    format!(
        "input     {path}: {:.2} s, {} Hz, {}, {} ({})",
        a.seconds(),
        a.source_rate,
        channels_text(a.channels),
        a.encoding,
        a.decoder
    )
}
