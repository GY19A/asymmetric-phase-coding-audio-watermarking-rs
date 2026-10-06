// SPDX-License-Identifier: BSD-2-Clause
//! Signed payload, bit packing, header and per-channel stream (format §4, §5).

use crate::error::{Error, Result};
use crate::keys::SecretKey;
use crate::params::{replicas, HEADER_BITS, MAX_MSG_LEN, SIG_LEN};
use crate::rs;

/// `C = be16(len M) || M || Ed25519(sk, M)`.
pub fn container(sk: &SecretKey, msg: &[u8]) -> Result<Vec<u8>> {
    if msg.len() > MAX_MSG_LEN {
        return Err(Error::MessageTooLong { len: msg.len(), max: MAX_MSG_LEN });
    }
    let mut c = Vec::with_capacity(2 + msg.len() + SIG_LEN);
    c.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    c.extend_from_slice(msg);
    c.extend_from_slice(&sk.sign(msg));
    Ok(c)
}

/// `payload = RS_encode(C)`, `len(M) + 96` bytes.
pub fn build(sk: &SecretKey, msg: &[u8]) -> Result<Vec<u8>> {
    Ok(rs::encode(&container(sk, msg)?))
}

/// Bytes to bits, MSB first (`np.unpackbits`).
pub fn unpack_bits(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1)).collect()
}

/// Bits (0/1) to bytes, MSB first (`np.packbits`); the length must be a multiple of 8.
pub fn pack_bits(bits: &[u8]) -> Vec<u8> {
    assert_eq!(bits.len() % 8, 0, "bit count not a multiple of 8");
    bits.chunks_exact(8).map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | (b & 1))).collect()
}

/// Header `h = be32(n_bits)` unpacked MSB first.
pub fn header_bits(n_bits: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (i, b) in h.iter_mut().enumerate() {
        *b = ((n_bits >> (31 - i)) & 1) as u8;
    }
    h
}

/// `h‖h‖h‖b^r` for a channel of `cap` bits with at most `max_reps` replicas;
/// `Capacity` if not even one copy of the body fits after the header.
pub fn stream(body: &[u8], cap: usize, max_reps: usize, channel: &'static str) -> Result<Vec<u8>> {
    let r = replicas(cap, body.len(), max_reps).ok_or(Error::Capacity {
        channel,
        capacity: cap,
        needed: HEADER_BITS + body.len(),
        body: body.len(),
    })?;
    let h = header_bits(body.len() as u32);
    let mut s = Vec::with_capacity(HEADER_BITS + r * body.len());
    for _ in 0..3 {
        s.extend_from_slice(&h);
    }
    for _ in 0..r {
        s.extend_from_slice(body);
    }
    Ok(s)
}

/// Split a decoded `C` into message and signature if its be16 length is
/// consistent with the decoded length (`len(C) == 2 + be16 + 64`).
pub fn open(c: &[u8]) -> Option<(&[u8], [u8; 64])> {
    if c.len() < 2 + SIG_LEN {
        return None;
    }
    let m = u16::from_be_bytes([c[0], c[1]]) as usize;
    if c.len() != 2 + m + SIG_LEN {
        return None;
    }
    let sig: [u8; 64] = c[2 + m..].try_into().ok()?;
    Some((&c[2..2 + m], sig))
}
