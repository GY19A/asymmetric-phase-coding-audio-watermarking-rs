// SPDX-License-Identifier: BSD-2-Clause
//! Soft reading (format §7) and header-independent verification (format §8).
//!
//! The order of work, the global de-duplication of candidate byte strings and
//! the three work counters follow the Python reference (`apcaw.verify`)
//! exactly, so a rejected file reports the same `candidates_tried`,
//! `rs_passes` and `sig_checks` in both implementations.

use std::collections::HashSet;

use serde::{Serialize, Serializer};

use crate::embed::{check_input, mean_abs, mean_log};
use crate::error::Result;
use crate::keys::PublicKey;
use crate::layout::Layout;
use crate::params::{replicas, Channel, Options, Profile, Verifier, GROUP, HEADER_BITS};
use crate::payload;
use crate::rs;
use crate::stft::{abs, angle, Stft};

/// Body bits of the smallest payload (empty message): `8 * 96`.
pub const MIN_PAYLOAD_BITS: usize = 8 * 96;

/// Which step of §8 produced the accepted candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Path {
    /// The majority-voted header length.
    Header,
    /// The protocol length search.
    Search,
    /// The optional offset search.
    Resync,
}

impl Path {
    /// JSON / report name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Path::Header => "header",
            Path::Search => "search",
            Path::Resync => "resync",
        }
    }
}

/// Outcome of a verification. A file without a valid watermark under the
/// given key is `verified == false`; every other field then explains why.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    /// An Ed25519 signature under the public key checked.
    pub verified: bool,
    /// The signed message (raw bytes), when verified.
    pub message: Option<Vec<u8>>,
    /// Channel of the accepted candidate.
    pub channel: Option<Channel>,
    /// Profile id under which decoding succeeded.
    pub profile: Option<&'static str>,
    /// Step that produced the accepted candidate.
    pub path: Option<Path>,
    /// Reed–Solomon symbols corrected in the accepted candidate.
    pub rs_corrected: Option<usize>,
    /// Body length `|b|` of the accepted candidate in bits.
    pub payload_bits: Option<usize>,
    /// Distinct candidate byte strings handed to the RS decoder.
    pub candidates_tried: usize,
    /// Of those, how many RS-decoded.
    pub rs_passes: usize,
    /// Of those, how many had a consistent length field, so Ed25519 ran.
    pub sig_checks: usize,
    /// `"ok"` or a human-readable rejection reason.
    pub reason: String,
}

impl VerifyReport {
    /// A rejection without any work done (bad call, unusable input).
    pub fn rejected(reason: impl Into<String>) -> Self {
        VerifyReport {
            verified: false,
            message: None,
            channel: None,
            profile: None,
            path: None,
            rs_corrected: None,
            payload_bits: None,
            candidates_tried: 0,
            rs_passes: 0,
            sig_checks: 0,
            reason: reason.into(),
        }
    }

    /// The message as text, invalid UTF-8 replaced by U+FFFD (Python
    /// `decode("utf-8", errors="replace")`).
    pub fn message_text(&self) -> Option<String> {
        self.message.as_ref().map(|m| String::from_utf8_lossy(m).into_owned())
    }

    /// The message as lower-case hex.
    pub fn message_hex(&self) -> Option<String> {
        self.message.as_ref().map(|m| crate::keys::to_hex(m))
    }
}

/// JSON keys in the order of the Python CLI: `verified, message, message_hex,
/// channel, profile, path, rs_corrected, payload_bits, candidates_tried,
/// rs_passes, sig_checks, reason`.
impl Serialize for VerifyReport {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut m = s.serialize_struct("VerifyReport", 12)?;
        m.serialize_field("verified", &self.verified)?;
        m.serialize_field("message", &self.message_text())?;
        m.serialize_field("message_hex", &self.message_hex())?;
        m.serialize_field("channel", &self.channel)?;
        m.serialize_field("profile", &self.profile)?;
        m.serialize_field("path", &self.path)?;
        m.serialize_field("rs_corrected", &self.rs_corrected)?;
        m.serialize_field("payload_bits", &self.payload_bits)?;
        m.serialize_field("candidates_tried", &self.candidates_tried)?;
        m.serialize_field("rs_passes", &self.rs_passes)?;
        m.serialize_field("sig_checks", &self.sig_checks)?;
        m.serialize_field("reason", &self.reason)?;
        m.end()
    }
}

// ---------------------------------------------------------------------------------------------
// Soft reading
// ---------------------------------------------------------------------------------------------

/// Soft values of both channels over their full capacity (format §7).
#[derive(Debug, Clone, PartialEq)]
pub struct Soft {
    /// `sin(angle X[Kp[s], gG])`, `groups * Bp` values; 0 where `|X| < tau`.
    pub phase: Vec<f64>,
    /// `-cos(π d / Δ)`, `groups * Bm` values; 0 where both bins are silent.
    pub magnitude: Vec<f64>,
}

/// Phase soft values of frames `f0..` of `spec`.
pub(crate) fn phase_soft(spec: &Stft, f0: usize, layout: &Layout, profile: &Profile, tau: f64) -> Vec<f64> {
    let groups = spec.frames.saturating_sub(f0) / GROUP;
    let bp = profile.bp();
    let mut out = Vec::with_capacity(groups * bp);
    for g in 0..groups {
        let f = f0 + g * GROUP;
        for &k in &layout.phase_bins {
            let c = spec.at(k, f);
            let v = angle(c).sin();
            out.push(if tau > 0.0 && abs(c) < tau { 0.0 } else { v });
        }
    }
    debug_assert_eq!(out.len(), groups * bp);
    out
}

/// Magnitude soft values of frames `f0..` of `spec`.
pub(crate) fn mag_soft(spec: &Stft, f0: usize, layout: &Layout, profile: &Profile, tau: f64) -> Vec<f64> {
    let groups = spec.frames.saturating_sub(f0) / GROUP;
    let mut out = Vec::with_capacity(groups * profile.bm());
    for g in 0..groups {
        let f = f0 + g * GROUP;
        for &[k1, k2] in &layout.mag_pairs {
            let d = mean_log(spec, k1, f) - mean_log(spec, k2, f);
            let v = -(std::f64::consts::PI * d / profile.delta).cos();
            let silent = tau > 0.0 && mean_abs(spec, k1, f) < tau && mean_abs(spec, k2, f) < tau;
            out.push(if silent { 0.0 } else { v });
        }
    }
    out
}

/// Soft values of a signal under a layout (format §7). `samples` are mono 44.1 kHz.
pub fn read_soft(samples: &[f64], layout: &Layout, profile: &Profile, erasure_tau: f64) -> Soft {
    let spec = Stft::analyze(samples, crate::params::n_frames(samples.len()));
    Soft {
        phase: phase_soft(&spec, 0, layout, profile, erasure_tau),
        magnitude: mag_soft(&spec, 0, layout, profile, erasure_tau),
    }
}

/// `Σ_j soft[96 + j·nbits ..][..nbits]` for `j < r`, summed in replica order.
pub fn combine_body(soft: &[f64], nbits: usize, r: usize) -> Vec<f64> {
    let mut acc = soft[HEADER_BITS..HEADER_BITS + nbits].to_vec();
    for j in 1..r {
        let rep = &soft[HEADER_BITS + j * nbits..HEADER_BITS + (j + 1) * nbits];
        for (a, &v) in acc.iter_mut().zip(rep) {
            *a += v;
        }
    }
    acc
}

/// ℓ from the majority of the three 32-bit header copies (`None` below 96 values).
pub fn header_length(soft: &[f64]) -> Option<u32> {
    if soft.len() < HEADER_BITS {
        return None;
    }
    let mut v = 0u32;
    for i in 0..32 {
        let h = soft[i] + soft[32 + i] + soft[64 + i];
        v = (v << 1) | (h > 0.0) as u32;
    }
    Some(v)
}

/// Hard decision `soft > 0`, packed MSB first. `bits.len()` is a multiple of 8.
fn hard_bytes(bits: &[f64]) -> Vec<u8> {
    bits.chunks_exact(8).map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | (b > 0.0) as u8)).collect()
}

/// One candidate of §8: the step that produced it, `|b|` and the packed bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Header or search.
    pub path: Path,
    /// Body length in bits.
    pub nbits: usize,
    /// Hard-decided payload bytes.
    pub bytes: Vec<u8>,
}

/// Candidates of one channel's soft stream in §8 order.
pub fn candidates(soft: &[f64], max_replicas: usize, opt: &Options) -> Vec<Candidate> {
    let cap = soft.len();
    let make = |path, nbits: usize| Candidate {
        path,
        nbits,
        bytes: hard_bytes(&combine_body(soft, nbits, replicas(cap, nbits, max_replicas).expect("candidate fits"))),
    };
    let mut out = Vec::new();
    let ell = header_length(soft).map(|l| l as usize);
    let room = cap.saturating_sub(HEADER_BITS);
    if opt.verifier == Verifier::Header {
        // legacy HybridCoder rule
        if let Some(l) = ell {
            if l != 0 && l <= room && l % 8 == 0 {
                out.push(make(Path::Header, l));
            }
        }
        return out;
    }
    let hi = 8 * (HEADER_BITS + opt.max_msg_len);
    if let Some(l) = ell {
        if l % 8 == 0 && (MIN_PAYLOAD_BITS..=hi).contains(&l) && l <= room {
            out.push(make(Path::Header, l));
        }
    }
    for m in 0..=opt.max_msg_len {
        let nb = 8 * (m + HEADER_BITS);
        if cap < HEADER_BITS || room < nb {
            break;
        }
        out.push(make(Path::Search, nb));
    }
    out
}

/// Result of opening one candidate (Python `parse_payload`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// RS decoded, length consistent and signature valid.
    pub ok: bool,
    /// The message, when `ok`.
    pub message: Option<Vec<u8>>,
    /// Reed–Solomon decoding succeeded.
    pub rs_ok: bool,
    /// The length field was consistent, so Ed25519 was evaluated.
    pub sig_checked: bool,
    /// Symbols corrected, when RS decoded.
    pub rs_corrected: Option<usize>,
}

/// RS-decode (reedsolo chunking), check the length field and the signature.
pub fn parse_payload(data: &[u8], pk: &PublicKey) -> Parsed {
    let Ok((c, ncorr)) = rs::decode_chunked(data) else {
        return Parsed { ok: false, message: None, rs_ok: false, sig_checked: false, rs_corrected: None };
    };
    let Some((m, sig)) = payload::open(&c) else {
        return Parsed { ok: false, message: None, rs_ok: true, sig_checked: false, rs_corrected: Some(ncorr) };
    };
    let ok = pk.verify(m, &sig);
    Parsed { ok, message: ok.then(|| m.to_vec()), rs_ok: true, sig_checked: true, rs_corrected: Some(ncorr) }
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

/// State of one verify call: global de-duplication plus the work counters.
pub(crate) struct Search<'a> {
    pk: &'a PublicKey,
    opt: &'a Options,
    pub(crate) profiles: Vec<(Profile, Layout)>,
    seen: HashSet<Vec<u8>>,
    candidates_tried: usize,
    rs_passes: usize,
    sig_checks: usize,
    any_candidate_possible: bool,
}

impl<'a> Search<'a> {
    pub(crate) fn new(pk: &'a PublicKey, opt: &'a Options, profiles: &[Profile]) -> Self {
        let seed = opt.seed.unwrap_or_else(|| crate::layout::layout_seed(pk.as_bytes()));
        Search {
            pk,
            opt,
            profiles: profiles.iter().map(|p| (*p, Layout::from_seed(seed, p))).collect(),
            seen: HashSet::new(),
            candidates_tried: 0,
            rs_passes: 0,
            sig_checks: 0,
            any_candidate_possible: false,
        }
    }

    /// §8 steps 1–3 on frames `f0..` of `spec` for every profile; the first acceptance wins.
    pub(crate) fn run(&mut self, spec: &Stft, f0: usize, path_override: Option<Path>) -> Option<VerifyReport> {
        let tau = self.opt.erasure_tau;
        // (phase bins, soft) of the previous profile: identical phase layouts give identical
        // phase candidates, which de-duplication would skip one by one anyway.
        let mut prev_phase: Option<(Vec<usize>, usize)> = None;
        for i in 0..self.profiles.len() {
            let (profile, layout) = self.profiles[i].clone();
            let key = (layout.phase_bins.clone(), profile.rp);
            let phase_repeat = prev_phase.as_ref() == Some(&key);
            prev_phase = Some(key);
            for channel in Channel::ALL {
                let soft = match channel {
                    Channel::Phase if phase_repeat => {
                        // Same soft values and replica limit: every candidate is already
                        // seen and `any_candidate_possible` is unchanged.
                        continue;
                    }
                    Channel::Phase => phase_soft(spec, f0, &layout, &profile, tau),
                    Channel::Magnitude => mag_soft(spec, f0, &layout, &profile, tau),
                };
                if soft.len() >= HEADER_BITS + MIN_PAYLOAD_BITS {
                    self.any_candidate_possible = true;
                }
                let cands = candidates(&soft, profile.max_replicas(channel), self.opt);
                if let Some(r) = self.try_all(&cands, channel, &profile, path_override) {
                    return Some(r);
                }
            }
        }
        None
    }

    /// Parse the unseen candidates (in parallel when enabled), then account
    /// for them in order, stopping at the first acceptance.
    fn try_all(
        &mut self,
        cands: &[Candidate],
        channel: Channel,
        profile: &Profile,
        path_override: Option<Path>,
    ) -> Option<VerifyReport> {
        // The header candidate first on its own: for a signed file it is usually the answer.
        let split = cands.first().map_or(0, |c| (c.path == Path::Header) as usize);
        for part in [&cands[..split], &cands[split..]] {
            let mut batch = HashSet::new();
            let fresh: Vec<&Candidate> =
                part.iter().filter(|c| !self.seen.contains(&c.bytes) && batch.insert(&c.bytes)).collect();
            let parsed = parse_all(&fresh, self.pk);
            for (c, p) in fresh.into_iter().zip(parsed) {
                self.seen.insert(c.bytes.clone());
                self.candidates_tried += 1;
                self.rs_passes += p.rs_ok as usize;
                self.sig_checks += p.sig_checked as usize;
                if p.ok {
                    return Some(VerifyReport {
                        verified: true,
                        message: p.message,
                        channel: Some(channel),
                        profile: Some(profile.id),
                        path: Some(path_override.unwrap_or(c.path)),
                        rs_corrected: p.rs_corrected,
                        payload_bits: Some(c.nbits),
                        candidates_tried: self.candidates_tried,
                        rs_passes: self.rs_passes,
                        sig_checks: self.sig_checks,
                        reason: "ok".into(),
                    });
                }
            }
        }
        None
    }

    pub(crate) fn failure(&self, n_samples: usize) -> VerifyReport {
        let reason = if self.candidates_tried == 0 {
            if !self.any_candidate_possible {
                format!(
                    "too short: {n_samples} samples cannot carry the smallest payload ({} bits per channel)",
                    HEADER_BITS + MIN_PAYLOAD_BITS
                )
            } else {
                "no candidate: header length invalid and search disabled".to_string()
            }
        } else if self.sig_checks > 0 {
            format!(
                "signature invalid ({} candidate(s) passed RS with a consistent length; none verified under this public key)",
                self.sig_checks
            )
        } else if self.rs_passes > 0 {
            format!("length field inconsistent ({} RS-decodable candidate(s))", self.rs_passes)
        } else {
            format!("no candidate passed RS decoding ({} tried)", self.candidates_tried)
        };
        VerifyReport {
            candidates_tried: self.candidates_tried,
            rs_passes: self.rs_passes,
            sig_checks: self.sig_checks,
            ..VerifyReport::rejected(reason)
        }
    }
}

fn parse_all(cands: &[&Candidate], pk: &PublicKey) -> Vec<Parsed> {
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        if cands.len() > 1 {
            return cands.par_iter().map(|c| parse_payload(&c.bytes, pk)).collect();
        }
    }
    cands.iter().map(|c| parse_payload(&c.bytes, pk)).collect()
}

/// Verify `samples` (mono, 44100 Hz) against `pk` (format §8).
///
/// `profile = None` tries WB then NB. `resync = true` adds the offset
/// search, run only when the plain alignment does not verify. Never fails:
/// a bad call (wrong rate, invalid options) is a rejection whose `reason`
/// says why; use [`try_verify`] to get those as errors.
pub fn verify(
    samples: &[f64],
    sr: u32,
    pk: &PublicKey,
    profile: Option<&Profile>,
    opt: &Options,
    resync: bool,
) -> VerifyReport {
    try_verify(samples, sr, pk, profile, opt, resync).unwrap_or_else(|e| VerifyReport::rejected(e.to_string()))
}

/// [`verify`] with invalid calls reported as errors.
pub fn try_verify(
    samples: &[f64],
    sr: u32,
    pk: &PublicKey,
    profile: Option<&Profile>,
    opt: &Options,
    resync: bool,
) -> Result<VerifyReport> {
    check_rate(samples, sr)?;
    opt.validate()?;
    let profiles: Vec<Profile> = match profile {
        Some(p) => {
            p.validate()?;
            vec![*p]
        }
        None => Profile::ALL.to_vec(),
    };
    let mut st = Search::new(pk, opt, &profiles);
    let spec = Stft::analyze(samples, crate::params::n_frames(samples.len()));
    if let Some(r) = st.run(&spec, 0, None) {
        return Ok(r);
    }
    if resync {
        if let Some(r) = crate::resync::resync_search(samples, &mut st) {
            return Ok(r);
        }
    }
    Ok(st.failure(samples.len()))
}

/// Verification only rejects a wrong rate; non-finite samples simply decode to nothing.
fn check_rate(samples: &[f64], sr: u32) -> Result<()> {
    match check_input(samples, sr) {
        Err(e @ crate::Error::SampleRate(_)) => Err(e),
        _ => Ok(()),
    }
}
