// SPDX-License-Identifier: BSD-2-Clause
//! Reed–Solomon over GF(2^8) identical to `reedsolo.RSCodec(30)` for one codeword (format §4).
//!
//! Field: primitive polynomial `0x11d`, generator `α = 2`. Code: 30 parity
//! symbols, first consecutive root `α^0`, systematic, word length up to 255
//! (a single reedsolo chunk). A word is a polynomial whose first byte is the
//! highest-degree coefficient, so position `p` of an `n`-byte word has locator
//! `X = α^(n-1-p)`.
//!
//! The decoder is errors-only Berlekamp–Massey, Chien search restricted to the
//! word's own positions, Forney, and a final syndrome check, the same steps as
//! `reedsolo.rs_correct_msg`. With minimum distance 31, any decoder that
//! returns a codeword within distance 15 and fails otherwise agrees with
//! reedsolo on success, output and corrected count.

use std::sync::OnceLock;

/// Parity symbols.
pub const NSYM: usize = 30;
/// Longest word (one GF(2^8) codeword).
pub const MAX_WORD: usize = 255;

/// Why a received word did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsError {
    /// Empty input, or a single word longer than 255 symbols.
    Length,
    /// The error locator degree exceeds 15.
    TooManyErrors,
    /// Chien search found a different number of roots than the locator degree.
    Locate,
    /// The corrected word still has a non-zero syndrome.
    Correct,
}

struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
    gen: [u8; NSYM + 1],
}

fn gf() -> &'static Gf {
    static GF: OnceLock<Gf> = OnceLock::new();
    GF.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (i, e) in exp.iter_mut().enumerate().take(255) {
            *e = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        let mut g = Gf { exp, log, gen: [0; NSYM + 1] };
        // g(x) = prod_{i<30} (x - α^i), highest degree first.
        let mut gen = vec![1u8];
        for i in 0..NSYM {
            let root = g.exp[i];
            let mut next = vec![0u8; gen.len() + 1];
            for (j, &c) in gen.iter().enumerate() {
                next[j] ^= c;
                next[j + 1] ^= g.mul(c, root);
            }
            gen = next;
        }
        g.gen.copy_from_slice(&gen);
        g
    })
}

impl Gf {
    #[inline]
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
        }
    }

    #[inline]
    fn div(&self, a: u8, b: u8) -> u8 {
        debug_assert!(b != 0);
        if a == 0 {
            0
        } else {
            self.exp[self.log[a as usize] as usize + 255 - self.log[b as usize] as usize]
        }
    }

    /// `α^e` for any integer exponent.
    #[inline]
    fn pow_alpha(&self, e: i64) -> u8 {
        self.exp[e.rem_euclid(255) as usize]
    }

    /// Evaluate a low-degree-first polynomial.
    fn eval_low(&self, p: &[u8], x: u8) -> u8 {
        p.iter().rev().fold(0u8, |acc, &c| self.mul(acc, x) ^ c)
    }

    /// `S_j = r(α^j)`, `j = 0..30`.
    fn syndromes(&self, word: &[u8]) -> [u8; NSYM] {
        let mut s = [0u8; NSYM];
        for (j, sj) in s.iter_mut().enumerate() {
            let x = self.exp[j];
            *sj = word.iter().fold(0u8, |acc, &c| self.mul(acc, x) ^ c);
        }
        s
    }
}

/// Systematic encode: `msg || parity(30)`. Panics if `msg.len() > 225`.
pub fn encode(msg: &[u8]) -> Vec<u8> {
    assert!(msg.len() + NSYM <= MAX_WORD, "RS message longer than 225 bytes");
    let g = gf();
    let mut rem = [0u8; NSYM];
    for &b in msg {
        let coef = b ^ rem[0];
        rem.copy_within(1.., 0);
        rem[NSYM - 1] = 0;
        if coef != 0 {
            for (r, &gc) in rem.iter_mut().zip(&g.gen[1..]) {
                *r ^= g.mul(gc, coef);
            }
        }
    }
    let mut out = Vec::with_capacity(msg.len() + NSYM);
    out.extend_from_slice(msg);
    out.extend_from_slice(&rem);
    out
}

/// Errors-only decode of one word of 1..=255 symbols. Returns the message
/// part and the number of corrected symbols (`len(errata_pos)` in reedsolo).
///
/// As in reedsolo, a word of at most 30 symbols has an empty message part: it
/// "decodes" iff it has at most 15 non-zero symbols (the only codeword of that
/// length is all-zero).
pub fn decode(word: &[u8]) -> Result<(Vec<u8>, usize), RsError> {
    let n = word.len();
    if n == 0 || n > MAX_WORD {
        return Err(RsError::Length);
    }
    let g = gf();
    let synd = g.syndromes(word);
    if synd.iter().all(|&s| s == 0) {
        return Ok((word[..n.saturating_sub(NSYM)].to_vec(), 0));
    }

    // Berlekamp–Massey, polynomials low degree first.
    let mut c = vec![0u8; NSYM + 1];
    let mut b = vec![0u8; NSYM + 1];
    c[0] = 1;
    b[0] = 1;
    let (mut l, mut m, mut bd) = (0usize, 1usize, 1u8);
    for k in 0..NSYM {
        let mut d = synd[k];
        for i in 1..=l {
            d ^= g.mul(c[i], synd[k - i]);
        }
        if d == 0 {
            m += 1;
            continue;
        }
        let coef = g.div(d, bd);
        let t = c.clone();
        for i in 0..=NSYM - m {
            c[i + m] ^= g.mul(coef, b[i]);
        }
        if 2 * l <= k {
            l = k + 1 - l;
            b = t;
            bd = d;
            m = 1;
        } else {
            m += 1;
        }
    }
    let deg = c.iter().rposition(|&x| x != 0).unwrap_or(0);
    if 2 * deg > NSYM {
        return Err(RsError::TooManyErrors);
    }
    let lambda = &c[..=deg];

    // Chien search over the word's own positions only.
    let mut pos = Vec::with_capacity(deg);
    for i in 0..n {
        if g.eval_low(lambda, g.pow_alpha(-(i as i64))) == 0 {
            pos.push(n - 1 - i);
        }
    }
    if pos.len() != deg {
        return Err(RsError::Locate);
    }

    // Forney with first consecutive root 0: e = X * Ω(X^-1) / Λ'(X^-1),
    // Ω = S·Λ mod x^30.
    let mut omega = [0u8; NSYM];
    for (i, o) in omega.iter_mut().enumerate() {
        for j in 0..=i.min(deg) {
            *o ^= g.mul(lambda[j], synd[i - j]);
        }
    }
    let mut out = word.to_vec();
    for &p in &pos {
        let xe = (n - 1 - p) as i64;
        let x = g.pow_alpha(xe);
        let xinv = g.pow_alpha(-xe);
        let mut dl = 0u8;
        let mut xp = 1u8; // xinv^(i-1) for odd i
        let xinv2 = g.mul(xinv, xinv);
        for i in (1..=deg).step_by(2) {
            dl ^= g.mul(lambda[i], xp);
            xp = g.mul(xp, xinv2);
        }
        if dl == 0 {
            return Err(RsError::Locate);
        }
        let e = g.mul(x, g.div(g.eval_low(&omega, xinv), dl));
        out[p] ^= e;
    }
    if g.syndromes(&out).iter().any(|&s| s != 0) {
        return Err(RsError::Correct);
    }
    out.truncate(n.saturating_sub(NSYM));
    Ok((out, pos.len()))
}

/// `reedsolo.RSCodec(30).decode` of any length: consecutive chunks of 255
/// symbols (the last one shorter) decoded independently, messages
/// concatenated, corrected counts summed. The first failing chunk fails the
/// whole input. Only the header path can present more than 255 bytes.
pub fn decode_chunked(data: &[u8]) -> Result<(Vec<u8>, usize), RsError> {
    let mut msg = Vec::with_capacity(data.len());
    let mut corrected = 0;
    for chunk in data.chunks(MAX_WORD) {
        let (m, c) = decode(chunk)?;
        msg.extend_from_slice(&m);
        corrected += c;
    }
    Ok((msg, corrected))
}
