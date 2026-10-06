// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw serve --stdio`: one JSON request per line on stdin, one JSON reply
//! per line on stdout, in order. The protocol is documented in docs/CLI.md.
//!
//! Request: `{"id": any, "op": "...", ...fields}`. Reply:
//! `{"id": .., "ok": true, "result": {..}}` or
//! `{"id": .., "ok": false, "error": {"code": 1|2|3, "message": ".."}}`,
//! the codes being the CLI's exit codes. A NOT VERIFIED file is a result
//! (`"verified": false`), not an error. Blank lines are skipped; EOF or
//! `{"op": "shutdown"}` ends the server with exit code 0.

use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};

use clap::ValueEnum;
use serde_json::{json, Map, Value};

use apcaw::layout_seed;

use crate::audio::OutCodec;
use crate::cli::{SignProfile, VerifyProfile};
use crate::cmd::sign::{sign_job, SignJob};
use crate::cmd::verify::{verify_job, VerifyJob};
use crate::cmd::{inspect, keygen, layout, selftest, Ctx};
use crate::errors::{CliError, CliResult, EXIT_OK};
use crate::keyfile::{self, KeyArg};
use crate::report::to_py_json;

/// Protocol revision (the `version` op).
pub const PROTOCOL: u32 = 1;

/// The fields of a request object.
struct Req<'a>(&'a Map<String, Value>);

/// Short field names accepted for the long ones (`{"op": "verify", "path": .., "pk": ".."}`).
const ALIASES: [(&str, &str); 3] = [("input", "path"), ("public_key", "pk"), ("secret_key", "sk")];

impl Req<'_> {
    fn get(&self, k: &str) -> Option<&Value> {
        let alias = ALIASES.iter().find(|(long, _)| *long == k).map(|(_, short)| *short);
        let found = |k: &str| self.0.get(k).filter(|v| !v.is_null());
        found(k).or_else(|| alias.and_then(found))
    }

    fn str(&self, k: &str) -> CliResult<Option<String>> {
        match self.get(k) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(CliError::usage(format!("field {k:?}: expected a string"))),
        }
    }

    fn req_str(&self, k: &str) -> CliResult<String> {
        self.str(k)?.ok_or_else(|| CliError::usage(format!("field {k:?} is required")))
    }

    fn bool(&self, k: &str) -> CliResult<bool> {
        match self.get(k) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(CliError::usage(format!("field {k:?}: expected true or false"))),
        }
    }

    fn uint(&self, k: &str) -> CliResult<Option<u64>> {
        match self.get(k) {
            None => Ok(None),
            Some(v) => v
                .as_u64()
                .map(Some)
                .ok_or_else(|| CliError::usage(format!("field {k:?}: expected a non-negative integer"))),
        }
    }

    fn count(&self, k: &str) -> CliResult<Option<usize>> {
        match self.uint(k)? {
            Some(0) => Err(CliError::usage(format!("field {k:?}: must be at least 1"))),
            n => Ok(n.map(|n| n as usize)),
        }
    }

    fn choice<T: ValueEnum>(&self, k: &str) -> CliResult<Option<T>> {
        self.str(k)?
            .map(|s| T::from_str(&s, true).map_err(|_| CliError::usage(format!("field {k:?}: invalid value {s:?}"))))
            .transpose()
    }

    /// A key: `{k}` (hex or PEM text) or `{k}_file` (a key file).
    fn key(&self, k: &str) -> CliResult<Option<KeyArg>> {
        match (self.str(k)?, self.str(&format!("{k}_file"))?) {
            (Some(_), Some(_)) => Err(CliError::usage(format!("give {k:?} or \"{k}_file\", not both"))),
            (Some(t), None) => Ok(Some(KeyArg::Text(t))),
            (None, Some(f)) => Ok(Some(KeyArg::File(f))),
            (None, None) => Ok(None),
        }
    }

    fn req_key(&self, k: &str) -> CliResult<KeyArg> {
        self.key(k)?.ok_or_else(|| CliError::usage(format!("field {k:?} or \"{k}_file\" is required")))
    }

    /// An input path; stdin is the request stream.
    fn input(&self) -> CliResult<String> {
        let p = self.req_str("input")?;
        if p == "-" {
            return Err(CliError::usage("\"input\": standard input carries the requests; give a file"));
        }
        Ok(p)
    }
}

fn op_sign(ctx: &Ctx, r: &Req) -> CliResult<Value> {
    let message = match (r.str("message")?, r.str("message_hex")?) {
        (Some(_), Some(_)) => return Err(CliError::usage("give \"message\" or \"message_hex\", not both")),
        (Some(m), None) => m.into_bytes(),
        (None, Some(h)) => {
            apcaw::keys::from_hex(&h).ok_or_else(|| CliError::usage("field \"message_hex\": expected hex digits"))?
        }
        (None, None) => return Err(CliError::usage("field \"message\" or \"message_hex\" is required")),
    };
    let output = r.req_str("output")?;
    if output == "-" {
        return Err(CliError::usage("\"output\": standard output carries the replies; give a file"));
    }
    let job = SignJob {
        input: r.input()?,
        output,
        key: r.req_key("secret_key")?,
        message,
        profile: r.choice("profile")?.unwrap_or(SignProfile::Wb),
        legacy: r.bool("legacy")?,
        segment: r.count("segment")?,
        closed_loop: !r.bool("no_closed_loop")?,
        sidecar: r.bool("sidecar")?,
        codec: r.choice::<OutCodec>("codec")?,
        channel: r.uint("channel")?.map(|n| n as usize),
        overwrite: ctx.overwrite || r.bool("overwrite")?,
    };
    let notes = std::cell::RefCell::new(Vec::new());
    let s = sign_job(ctx, &job, &|n| notes.borrow_mut().push(Value::from(n)))?;
    let mut v = s.report;
    if let Value::Object(m) = &mut v {
        m.insert("notes".into(), Value::Array(notes.into_inner()));
    }
    Ok(v)
}

fn verify_fields(r: &Req) -> CliResult<VerifyJob> {
    Ok(VerifyJob {
        input: r.input()?,
        profile: VerifyProfile::profile(r.choice("profile")?),
        legacy: r.bool("legacy")?,
        resync: r.bool("resync")?,
        scan: r.count("scan")?,
        channel: r.uint("channel")?.map(|n| n as usize),
    })
}

fn with_notes(mut v: Value, notes: &[String]) -> Value {
    if let Value::Object(m) = &mut v {
        m.insert("notes".into(), json!(notes));
    }
    v
}

fn op_verify(ctx: &Ctx, r: &Req) -> CliResult<Value> {
    let job = verify_fields(r)?;
    if job.scan.is_some() && job.resync {
        return Err(CliError::usage("\"scan\" and \"resync\" cannot be combined"));
    }
    let pk = keyfile::public(&r.req_key("public_key")?)?;
    let (x, o) = verify_job(ctx, &job, &pk)?;
    Ok(with_notes(o.json(&job.input), &x.notes))
}

fn op_inspect(ctx: &Ctx, r: &Req) -> CliResult<Value> {
    let input = r.input()?;
    let pk = keyfile::public(&r.req_key("public_key")?)?;
    let x = crate::cmd::load(ctx, &input, r.uint("channel")?.map(|n| n as usize))?;
    let rep = inspect::inspect_samples(&x.samples, &pk, r.bool("legacy")?)?;
    Ok(with_notes(inspect::report_json(&input, &rep), &x.notes))
}

fn op_layout(r: &Req) -> CliResult<Value> {
    let seed = match (r.key("public_key")?, r.get("seed")) {
        (Some(_), Some(_)) => return Err(CliError::usage("give a public key or \"seed\", not both")),
        (Some(k), None) => layout_seed(keyfile::public(&k)?.as_bytes()),
        (None, Some(s)) => layout::check_seed(s.as_i64().map_or(-1, i128::from))?,
        (None, None) => {
            return Err(CliError::usage("field \"public_key\", \"public_key_file\" or \"seed\" is required"))
        }
    };
    Ok(layout::report(seed, &layout::profiles(r.choice("profile")?)).0)
}

fn op_keygen(ctx: &Ctx, r: &Req) -> CliResult<Value> {
    keygen::keygen_files(
        &r.req_str("secret_out")?,
        &r.req_str("public_out")?,
        r.bool("pem")?,
        ctx.overwrite || r.bool("overwrite")?,
    )
}

/// Handle one request line: the reply, and whether to stop.
pub fn handle(ctx: &Ctx, line: &str) -> (Value, bool) {
    let parsed: Result<Value, _> = serde_json::from_str(line);
    let (id, req) = match parsed {
        Ok(Value::Object(m)) => (m.get("id").cloned().unwrap_or(Value::Null), m),
        Ok(_) => return (error(Value::Null, &CliError::usage("a request must be a JSON object")), false),
        Err(e) => return (error(Value::Null, &CliError::usage(format!("invalid JSON: {e}"))), false),
    };
    let r = Req(&req);
    let op = match r.req_str("op") {
        Ok(op) => op,
        Err(e) => return (error(id, &e), false),
    };
    let res = panic::catch_unwind(AssertUnwindSafe(|| match op.as_str() {
        "version" => Ok(json!({
            "name": "apcaw",
            "version": env!("CARGO_PKG_VERSION"),
            "format": apcaw::params::FORMAT,
            "protocol": PROTOCOL,
        })),
        "keygen" => op_keygen(ctx, &r),
        "sign" => op_sign(ctx, &r),
        "verify" => op_verify(ctx, &r),
        "inspect" => op_inspect(ctx, &r),
        "layout" => op_layout(&r),
        "selftest" => selftest::run_checks().map(|c| selftest::report_json(&c)),
        "shutdown" => Ok(json!({})),
        other => Err(CliError::usage(format!("unknown op {other:?}"))),
    }))
    .unwrap_or_else(|_| Err(CliError::fail(format!("internal error in {op:?}"))));
    let reply = match res {
        Ok(result) => json!({"id": id, "ok": true, "result": result}),
        Err(e) => error(id, &e),
    };
    (reply, op == "shutdown")
}

fn error(id: Value, e: &CliError) -> Value {
    json!({"id": id, "ok": false, "error": {"code": e.code(), "message": e.message()}})
}

pub fn run(ctx: &Ctx) -> CliResult<i32> {
    let stdin = io::stdin().lock();
    let mut out = io::stdout().lock();
    let broken = |e: io::Error| CliError::io(format!("serve: {e}"));
    for line in stdin.lines() {
        let line = line.map_err(broken)?;
        if line.trim().is_empty() {
            continue;
        }
        let (reply, stop) = handle(ctx, &line);
        ctx.ui.debug(|| format!("serve: {}", if reply["ok"] == true { "ok" } else { "error" }));
        writeln!(out, "{}", to_py_json(&reply, None)).and_then(|_| out.flush()).map_err(broken)?;
        if stop {
            return Ok(EXIT_OK);
        }
    }
    Ok(EXIT_OK)
}
