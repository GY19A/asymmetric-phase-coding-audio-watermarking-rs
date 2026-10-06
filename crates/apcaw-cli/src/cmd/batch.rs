// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw batch-verify`: verify many files concurrently and print one JSON
//! object per file on stdout (NDJSON), in the order the files were given.
//! A file that cannot be read is reported in its line and does not stop the
//! batch; the exit code is the worst of the files (3 > 2 > 1 > 0).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

use serde_json::{json, Value};

use apcaw::PublicKey;

use crate::audio::{self, Tools};
use crate::cli::{BatchArgs, VerifyProfile};
use crate::cmd::options;
use crate::cmd::verify::{verify_samples, VerifyJob};
use crate::cmd::Ctx;
use crate::errors::{CliError, CliResult, EXIT_FAIL, EXIT_OK};
use crate::keyfile::{self, KeyArg};
use crate::report::to_py_json;

/// One file's line and exit code, plus its notes.
struct Done {
    line: Value,
    code: i32,
    verified: bool,
    notes: Vec<String>,
}

/// The line of a file that could not be verified.
pub fn error_line(file: &str, e: &CliError) -> Value {
    json!({
        "file": file,
        "verified": false,
        "error": {"code": e.code(), "message": e.message()},
    })
}

fn one(job: &VerifyJob, pk: &PublicKey, tools: &Tools) -> Done {
    let r = audio::load(&job.input, job.channel, tools)
        .and_then(|x| verify_samples(&x.samples, pk, job, &options(job.legacy)).map(|o| (x, o)));
    match r {
        Ok((x, o)) => Done {
            line: o.json(&job.input),
            code: if o.verified() { EXIT_OK } else { EXIT_FAIL },
            verified: o.verified(),
            notes: x.notes,
        },
        Err(e) => Done { line: error_line(&job.input, &e), code: e.code(), verified: false, notes: Vec::new() },
    }
}

pub fn run(ctx: &Ctx, a: &BatchArgs) -> CliResult<i32> {
    let pk = keyfile::public(&KeyArg::File(a.public_key.clone()))?;
    let jobs: Vec<VerifyJob> = a
        .files
        .iter()
        .map(|f| VerifyJob {
            input: f.clone(),
            profile: VerifyProfile::profile(a.profile),
            legacy: a.legacy,
            resync: a.resync,
            scan: None,
            channel: a.channel.channel,
        })
        .collect();
    if jobs.iter().filter(|j| j.input == "-").count() > 1 {
        return Err(CliError::usage("standard input (-) can be given only once"));
    }
    let workers = a.jobs.unwrap_or(ctx.threads).min(jobs.len()).max(1);
    // one pool: file-level workers and the library's own parallelism share its threads
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build()
        .map_err(|e| CliError::io(format!("cannot start {workers} worker threads: {e}")))?;
    ctx.ui.debug(|| format!("batch-verify: {} file(s), {workers} worker(s)", jobs.len()));

    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<(usize, Done)>();
    let (tools, pk, jobs) = (&ctx.tools, &pk, &jobs);
    let (mut worst, mut verified) = (EXIT_OK, 0usize);
    std::thread::scope(|s| {
        s.spawn(|| {
            pool.scope(|ps| {
                for _ in 0..workers {
                    let tx = tx.clone();
                    let next = &next;
                    ps.spawn(move |_| loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(job) = jobs.get(i) else { break };
                        if tx.send((i, one(job, pk, tools))).is_err() {
                            break;
                        }
                    });
                }
            });
            drop(tx);
        });
        // print in input order as the results arrive
        let mut pending = BTreeMap::new();
        let mut want = 0;
        for (i, d) in rx {
            pending.insert(i, d);
            while let Some(d) = pending.remove(&want) {
                for n in &d.notes {
                    ctx.ui.note(&format!("{}: {n}", jobs[want].input));
                }
                println!("{}", to_py_json(&d.line, None));
                worst = worst.max(d.code);
                verified += usize::from(d.verified);
                want += 1;
            }
        }
    });
    if !ctx.ui.quiet {
        eprintln!("batch-verify: {verified}/{} verified", jobs.len());
    }
    Ok(worst)
}
