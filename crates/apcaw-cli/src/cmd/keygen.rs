// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw keygen`: a fresh Ed25519 key pair, the secret written with mode 0600.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde_json::{json, Value};

use apcaw::layout_seed;

use crate::cli::KeygenArgs;
use crate::cmd::Ctx;
use crate::errors::{py_os_error, CliError, CliResult, EXIT_OK};

/// Generate a key pair into `secret_out` / `public_out`; the report (never the secret).
pub fn keygen_files(secret_out: &str, public_out: &str, pem: bool, overwrite: bool) -> CliResult<Value> {
    let kp = apcaw::keygen();
    let (sk_data, pk_data) = if pem {
        (kp.secret.to_pem().into_bytes(), kp.public.to_pem().into_bytes())
    } else {
        (kp.secret.seed().to_vec(), kp.public.as_bytes().to_vec())
    };
    for p in [secret_out, public_out] {
        if Path::new(p).exists() && !overwrite {
            return Err(CliError::usage(format!("{p} exists (use --force to overwrite)")));
        }
    }
    write_secret(secret_out, &sk_data)
        .map_err(|e| CliError::io(format!("cannot write key: {}", py_os_error(&e, secret_out))))?;
    fs::write(public_out, &pk_data)
        .map_err(|e| CliError::io(format!("cannot write key: {}", py_os_error(&e, public_out))))?;
    Ok(json!({
        "public_key": kp.public.to_hex(),
        "layout_seed": layout_seed(kp.public.as_bytes()),
        "secret_out": secret_out,
        "public_out": public_out,
        "format": if pem { "pem" } else { "raw" },
    }))
}

/// Create or truncate `path` readable by the owner only (also when it existed with wider permissions).
fn write_secret(path: &str, data: &[u8]) -> std::io::Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        o.mode(0o600);
        let mut f = o.open(path)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        o.open(path)?.write_all(data)
    }
}

pub fn run(ctx: &Ctx, a: &KeygenArgs) -> CliResult<i32> {
    let r = keygen_files(&a.secret_out, &a.public_out, a.pem, ctx.overwrite)?;
    if ctx.ui.json {
        ctx.ui.json(&r);
    } else {
        if !ctx.ui.quiet {
            ctx.ui.line(&format!("public key {}", r["public_key"].as_str().unwrap_or_default()));
            ctx.ui.line(&format!("layout seed {}", r["layout_seed"]));
        }
        ctx.ui.line(&format!("wrote {} (secret, mode 0600) and {}", a.secret_out, a.public_out));
    }
    Ok(EXIT_OK)
}
