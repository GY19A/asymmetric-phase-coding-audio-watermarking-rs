// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw`: the ffmpeg-style command-line tool of the apcaw-v1 watermark.
//!
//! Exit codes: 0 success / VERIFIED, 1 NOT VERIFIED or signing failed,
//! 2 usage error, 3 I/O error, 130 interrupted (see `apcaw --help`).

mod audio;
mod cli;
mod cmd;
mod errors;
mod keyfile;
mod report;

use clap::Parser;

use crate::audio::Tools;
use crate::cli::{Cli, Cmd};
use crate::cmd::Ctx;
use crate::errors::{CliError, CliResult, EXIT_INTERRUPTED};
use crate::report::Ui;

fn main() {
    // clap prints usage errors (exit 2) and --help / --version (exit 0) itself
    let cli = Cli::try_parse().unwrap_or_else(|e| e.exit());
    // Ctrl-C: remove the temporary output files, exit 130 like the reference
    let _ = ctrlc::set_handler(|| {
        audio::remove_temps();
        std::process::exit(EXIT_INTERRUPTED);
    });
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("apcaw: {e}");
            e.code()
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> CliResult<i32> {
    let g = cli.global;
    let threads = g.threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    if g.threads.is_some() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| CliError::Usage(format!("--threads {threads}: {e}")))?;
    }
    let ctx = Ctx {
        ui: Ui::new(g.verbose, g.quiet, g.json, g.no_color),
        tools: Tools { ffmpeg: g.ffmpeg, ffprobe: g.ffprobe },
        threads,
        overwrite: g.overwrite,
    };
    match cli.command {
        Cmd::Keygen(a) => cmd::keygen::run(&ctx, &a),
        Cmd::Sign(a) => cmd::sign::run(&ctx, &a),
        Cmd::Verify(a) => cmd::verify::run(&ctx, &a),
        Cmd::BatchVerify(a) => cmd::batch::run(&ctx, &a),
        Cmd::Inspect(a) => cmd::inspect::run(&ctx, &a),
        Cmd::Layout(a) => cmd::layout::run(&ctx, &a),
        Cmd::Selftest => cmd::selftest::run(&ctx),
        Cmd::Bench(a) => cmd::bench::run(&ctx, &a),
        Cmd::Serve(_) => cmd::serve::run(&ctx),
    }
}
