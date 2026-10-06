// SPDX-License-Identifier: BSD-2-Clause
//! Key material from files (the CLI) or strings (the `serve` protocol), with
//! the reference's messages: an unreadable file is an I/O error (exit 3),
//! malformed contents a usage error (exit 2).

use apcaw::{PublicKey, SecretKey};

use crate::errors::{strerror, CliError, CliResult};

/// Where a key comes from.
#[derive(Debug, Clone)]
pub enum KeyArg {
    /// A key file: raw 32 bytes, 64 hex digits or PEM.
    File(String),
    /// Key text: 64 hex digits or PEM (raw bytes cannot travel in text).
    Text(String),
}

fn read(path: &str, what: &str) -> CliResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| CliError::io(format!("cannot read {what} {path}: {}", strerror(&e))))
}

fn text(s: &str, what: &str) -> CliResult<Vec<u8>> {
    if s.len() == 32 {
        // a 32-character string would otherwise be taken as raw key bytes
        return Err(CliError::usage(format!("{what}: expected 64 hex digits or PEM")));
    }
    Ok(s.as_bytes().to_vec())
}

/// Load a secret key.
pub fn secret(k: &KeyArg) -> CliResult<SecretKey> {
    const WHAT: &str = "secret key";
    let (data, label) = match k {
        KeyArg::File(p) => (read(p, WHAT)?, p.as_str()),
        KeyArg::Text(s) => (text(s, WHAT)?, WHAT),
    };
    SecretKey::parse(&data).map_err(|e| CliError::usage(format!("{label}: {e}")))
}

/// Load a public key.
pub fn public(k: &KeyArg) -> CliResult<PublicKey> {
    const WHAT: &str = "public key";
    let (data, label) = match k {
        KeyArg::File(p) => (read(p, WHAT)?, p.as_str()),
        KeyArg::Text(s) => (text(s, WHAT)?, WHAT),
    };
    PublicKey::parse(&data).map_err(|e| CliError::usage(format!("{label}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_errors_have_the_reference_codes() {
        let e = public(&KeyArg::File("/nonexistent/k.pub".into())).unwrap_err();
        assert_eq!(e.code(), 3);
        assert_eq!(e.message(), "cannot read public key /nonexistent/k.pub: No such file or directory");
        let e = public(&KeyArg::Text("zz".into())).unwrap_err();
        assert_eq!(e.code(), 2);
        assert!(e.message().starts_with("public key: "), "{}", e.message());
        assert_eq!(public(&KeyArg::Text("a".repeat(32))).unwrap_err().code(), 2);
        let pk = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
        assert_eq!(public(&KeyArg::Text(pk.into())).unwrap().to_hex(), pk);
        let sk = secret(&KeyArg::Text("00".repeat(32))).unwrap();
        assert_eq!(sk.public_key().to_hex(), "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    }
}
