// SPDX-License-Identifier: BSD-2-Clause
//! Ed25519 keys (RFC 8032) with raw, hex and PEM encodings (format §2).
//!
//! Verification is `ed25519-dalek`'s non-strict `verify`: the cofactorless
//! RFC 8032 equation `[s]B = R + [k]A` checked by re-encoding `R`, with a
//! canonical `s < L` required. This is the acceptance rule of OpenSSL, which
//! Python `cryptography` uses. `verify_strict` would additionally reject
//! small-order keys and `R`; it is not used so both implementations accept
//! exactly the same signatures.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::{Error, Result};

const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
const PKCS8_PREFIX: [u8; 16] =
    [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// An Ed25519 secret key (the 32-byte RFC 8032 seed). Zeroized on drop.
#[derive(Clone)]
pub struct SecretKey(SigningKey);

/// An Ed25519 public key as its raw 32-byte encoding. The bytes need not be a
/// valid curve point: the layout seed is derived from the bytes, and signature
/// checks under an invalid point simply fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

/// A secret key and its public key.
#[derive(Clone, Debug)]
pub struct Keypair {
    /// Secret half.
    pub secret: SecretKey,
    /// Public half.
    pub public: PublicKey,
}

/// A fresh key pair from the operating system's CSPRNG.
pub fn keygen() -> Keypair {
    let sk = SecretKey(SigningKey::generate(&mut rand_core::OsRng));
    Keypair { public: sk.public_key(), secret: sk }
}

/// The key pair of a 32-byte RFC 8032 seed.
pub fn keygen_from_seed(seed: [u8; 32]) -> Keypair {
    let sk = SecretKey::from_seed(seed);
    Keypair { public: sk.public_key(), secret: sk }
}

impl SecretKey {
    /// Secret key of a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        SecretKey(SigningKey::from_bytes(&seed))
    }

    /// The 32-byte seed.
    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Deterministic RFC 8032 signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }

    /// Parse raw 32 bytes, 64 hex digits or a PKCS#8 PEM (`BEGIN PRIVATE KEY`).
    pub fn parse(data: &[u8]) -> Result<Self> {
        let seed = parse_key(data, "PRIVATE KEY", |der| der_key(der, &[0x04, 0x22, 0x04, 0x20]))?;
        Ok(SecretKey::from_seed(seed))
    }

    /// Lower-case hex of the seed.
    pub fn to_hex(&self) -> String {
        to_hex(&self.seed())
    }

    /// PKCS#8 PEM.
    pub fn to_pem(&self) -> String {
        let mut der = PKCS8_PREFIX.to_vec();
        der.extend_from_slice(&self.seed());
        pem("PRIVATE KEY", &der)
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl PublicKey {
    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse raw 32 bytes, 64 hex digits or an SPKI PEM (`BEGIN PUBLIC KEY`).
    pub fn parse(data: &[u8]) -> Result<Self> {
        parse_key(data, "PUBLIC KEY", |der| der_key(der, &[0x03, 0x21, 0x00])).map(PublicKey)
    }

    /// Cofactorless RFC 8032 verification (`ed25519-dalek` `verify`, the rule
    /// OpenSSL and Python `cryptography` apply). `false` for an invalid point.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> bool {
        match VerifyingKey::from_bytes(&self.0) {
            Ok(vk) => vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok(),
            Err(_) => false,
        }
    }

    /// Lower-case hex.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// SubjectPublicKeyInfo PEM.
    pub fn to_pem(&self) -> String {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(&self.0);
        pem("PUBLIC KEY", &der)
    }
}

/// Lower-case hex of bytes.
pub fn to_hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * b.len());
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// Parse hex (ASCII whitespace around it is ignored).
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    s.as_bytes().chunks_exact(2).map(|p| Some((nib(p[0])? << 4) | nib(p[1])?)).collect()
}

/// The Python reference's order: exactly 32 bytes are raw; text starting with
/// `-----BEGIN` (after leading whitespace) is PEM; otherwise 64 hex digits
/// after trimming ASCII whitespace.
fn parse_key(data: &[u8], label: &str, der: impl Fn(&[u8]) -> Option<[u8; 32]>) -> Result<[u8; 32]> {
    let kind = if label == "PRIVATE KEY" { "secret" } else { "public" };
    if data.len() == 32 {
        return Ok(data.try_into().unwrap());
    }
    if data.trim_ascii_start().starts_with(b"-----BEGIN") {
        let what =
            if kind == "secret" { "an unencrypted Ed25519 private key PEM" } else { "an Ed25519 public key PEM" };
        let t = std::str::from_utf8(data).map_err(|_| Error::InvalidKey(format!("not {what}: not UTF-8")))?.trim();
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let body = t
            .strip_prefix(begin.as_str())
            .and_then(|r| r.split(end.as_str()).next())
            .ok_or_else(|| Error::InvalidKey(format!("not {what}: expected a '{begin}' block")))?;
        let bytes = base64_decode(body).ok_or_else(|| Error::InvalidKey(format!("not {what}: bad base64")))?;
        return der(&bytes).ok_or_else(|| {
            let short = if kind == "secret" { "private" } else { "public" };
            Error::InvalidKey(format!("PEM {short} key is not Ed25519"))
        });
    }
    let t = data.trim_ascii();
    if t.len() == 64 {
        if let Some(b) = std::str::from_utf8(t).ok().and_then(from_hex) {
            return Ok(b.try_into().unwrap());
        }
    }
    Err(Error::InvalidKey(format!("malformed {kind} key ({} bytes; expected raw 32 B, 64 hex, or PEM)", data.len())))
}

/// Find the Ed25519 OID, then `tag` followed by the 32 key bytes.
fn der_key(der: &[u8], tag: &[u8]) -> Option<[u8; 32]> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let oid = der.windows(OID_ED25519.len()).position(|w| w == OID_ED25519)?;
    let rest = &der[oid + OID_ED25519.len()..];
    let at = rest.windows(tag.len()).position(|w| w == tag)?;
    rest.get(at + tag.len()..at + tag.len() + 32)?.try_into().ok()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn pem(label: &str, der: &[u8]) -> String {
    let mut b = String::new();
    for chunk in der.chunks(3) {
        let n = chunk.iter().fold(0u32, |acc, &x| (acc << 8) | x as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                b.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                b.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut nbits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
        if c == b'=' {
            break;
        }
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Some(out)
}
