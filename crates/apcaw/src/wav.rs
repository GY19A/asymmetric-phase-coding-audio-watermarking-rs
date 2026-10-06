// SPDX-License-Identifier: BSD-2-Clause
//! WAV helpers for tools (feature `wav`). The protocol core does no I/O.
//!
//! The reader is a small tolerant RIFF parser: PCM 8/16/24/32-bit, IEEE float
//! 32/64-bit, `WAVE_FORMAT_EXTENSIBLE`, odd-sized chunks, and a data size of
//! `0` / `0xFFFFFFFF` or larger than the file (a WAV streamed through a pipe),
//! which is read to the end. Integer PCM `v` reads as `v / 2^(bits-1)`, so
//! PCM16 is exactly `int16 / 32768` as in the Python reference.
//!
//! The writer produces the canonical 44-byte-header PCM16 file of Python's
//! `wave` module (byte-identical), or 24-bit PCM / 32-bit float.

use std::io::Cursor;

use crate::error::{Error, Result};

/// Sample encoding of a WAV file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleFormat {
    /// Integer PCM of the given bit depth (8 is unsigned).
    Int(u16),
    /// IEEE float of the given bit depth (32 or 64).
    Float(u16),
}

/// A decoded WAV file.
#[derive(Debug, Clone, PartialEq)]
pub struct Audio {
    /// Sample rate in Hz.
    pub rate: u32,
    /// Channel count.
    pub channels: usize,
    /// Encoding of the file.
    pub format: SampleFormat,
    /// Interleaved samples, integer PCM scaled to `[-1, 1)`.
    pub samples: Vec<f64>,
}

impl Audio {
    /// Frames (samples per channel).
    pub fn frames(&self) -> usize {
        self.samples.len() / self.channels.max(1)
    }

    /// One channel (`Some(i)`, 0-based) or the channel mean (`None`), summed
    /// left to right and divided by the channel count.
    pub fn mono(&self, channel: Option<usize>) -> Result<Vec<f64>> {
        let ch = self.channels;
        if let Some(i) = channel {
            if i >= ch {
                return Err(Error::InvalidInput(format!(
                    "channel {i} requested but the input has {ch} channel(s) (0-based)"
                )));
            }
            return Ok(self.samples.iter().skip(i).step_by(ch).copied().collect());
        }
        if ch == 1 {
            return Ok(self.samples.clone());
        }
        Ok(self
            .samples
            .chunks_exact(ch)
            .map(|f| {
                let mut acc = f[0];
                for &v in &f[1..] {
                    acc += v;
                }
                acc / ch as f64
            })
            .collect())
    }
}

fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Decode a WAV file held in memory.
pub fn read_wav(bytes: &[u8]) -> Result<Audio> {
    let bad = |m: &str| Error::Wav(m.to_string());
    if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
        return Err(bad("not a RIFF/WAVE file"));
    }
    let mut pos = 12;
    let mut fmt: Option<(u16, usize, u32, u16)> = None;
    while pos + 8 <= bytes.len() {
        let id = &bytes[pos..pos + 4];
        let size = u32le(bytes, pos + 4) as usize;
        let body = pos + 8;
        if id == b"fmt " {
            if size < 16 || body + 16 > bytes.len() {
                return Err(bad("truncated fmt chunk"));
            }
            let mut tag = u16le(bytes, body);
            let channels = u16le(bytes, body + 2) as usize;
            let rate = u32le(bytes, body + 4);
            let bits = u16le(bytes, body + 14);
            if tag == 0xFFFE {
                if size < 40 || body + 40 > bytes.len() {
                    return Err(bad("truncated WAVE_FORMAT_EXTENSIBLE fmt chunk"));
                }
                tag = u16le(bytes, body + 24); // first two bytes of the sub-format GUID
            }
            fmt = Some((tag, channels, rate, bits));
        } else if id == b"data" {
            let (tag, channels, rate, bits) = fmt.ok_or_else(|| bad("data chunk before fmt chunk"))?;
            let format = match (tag, bits) {
                (1, 8 | 16 | 24 | 32) => SampleFormat::Int(bits),
                (3, 32 | 64) => SampleFormat::Float(bits),
                _ => {
                    return Err(Error::Wav(format!(
                        "unsupported encoding (format tag {tag}, {bits} bits); convert with ffmpeg"
                    )))
                }
            };
            if channels == 0 {
                return Err(bad("zero channels"));
            }
            if rate == 0 {
                return Err(bad("zero sample rate"));
            }
            let avail = bytes.len() - body;
            // streamed WAVs carry 0 or 0xFFFFFFFF: read to the end
            let len = if size == 0 || size > avail { avail } else { size };
            let width = bits as usize / 8;
            let frame = width * channels;
            let data = &bytes[body..body + len - len % frame];
            let samples = decode(data, format);
            return Ok(Audio { rate, channels, format, samples });
        }
        pos = body.saturating_add(size).saturating_add(size & 1);
    }
    Err(bad(if fmt.is_none() { "no fmt chunk" } else { "no data chunk" }))
}

fn decode(data: &[u8], format: SampleFormat) -> Vec<f64> {
    match format {
        SampleFormat::Int(8) => data.iter().map(|&v| (v as f64 - 128.0) / 128.0).collect(),
        SampleFormat::Int(16) => {
            data.chunks_exact(2).map(|c| i16::from_le_bytes([c[0], c[1]]) as f64 / 32768.0).collect()
        }
        SampleFormat::Int(24) => data
            .chunks_exact(3)
            .map(|c| (i32::from_le_bytes([0, c[0], c[1], c[2]]) >> 8) as f64 / 8_388_608.0)
            .collect(),
        SampleFormat::Int(_) => data
            .chunks_exact(4)
            .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]) as f64 / 2_147_483_648.0)
            .collect(),
        SampleFormat::Float(32) => {
            data.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]) as f64).collect()
        }
        SampleFormat::Float(_) => data.chunks_exact(8).map(|c| f64::from_le_bytes(c.try_into().unwrap())).collect(),
    }
}

/// Read a WAV file from disk.
pub fn read_wav_file(path: &std::path::Path) -> Result<Audio> {
    let bytes = std::fs::read(path).map_err(|e| Error::Io(format!("cannot read {}: {e}", path.display())))?;
    read_wav(&bytes)
}

/// Output encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Codec {
    /// 16-bit PCM (the reference's output format).
    #[default]
    Pcm16,
    /// 24-bit PCM.
    Pcm24,
    /// 32-bit IEEE float (not clipped).
    F32,
}

/// Format §6 quantization: clip to `[-1, 32767/32768]`, `round(y · 32768)`
/// half-to-even (numpy `np.round`). NaN maps to 0.
pub fn quantize_pcm16(y: &[f64]) -> Vec<i16> {
    const HI: f64 = 32767.0 / 32768.0;
    y.iter().map(|&v| (v.clamp(-1.0, HI) * 32768.0).round_ties_even() as i16).collect()
}

/// The 24-bit analogue of [`quantize_pcm16`].
pub fn quantize_pcm24(y: &[f64]) -> Vec<i32> {
    const S: f64 = 8_388_608.0;
    const HI: f64 = (S - 1.0) / S;
    y.iter().map(|&v| (v.clamp(-1.0, HI) * S).round_ties_even() as i32).collect()
}

/// Encode mono samples as a WAV file in memory.
pub fn write_wav(y: &[f64], rate: u32, codec: Codec) -> Vec<u8> {
    let (bits, fmt) = match codec {
        Codec::Pcm16 => (16, hound::SampleFormat::Int),
        Codec::Pcm24 => (24, hound::SampleFormat::Int),
        Codec::F32 => (32, hound::SampleFormat::Float),
    };
    let spec = hound::WavSpec { channels: 1, sample_rate: rate, bits_per_sample: bits, sample_format: fmt };
    let mut out = Cursor::new(Vec::with_capacity(44 + y.len() * bits as usize / 8));
    {
        let mut w = hound::WavWriter::new(&mut out, spec).expect("in-memory WAV header");
        match codec {
            Codec::Pcm16 => {
                let mut w16 = w.get_i16_writer(y.len() as u32);
                for q in quantize_pcm16(y) {
                    w16.write_sample(q);
                }
                w16.flush().expect("in-memory WAV");
            }
            Codec::Pcm24 => {
                for q in quantize_pcm24(y) {
                    w.write_sample(q).expect("in-memory WAV");
                }
            }
            Codec::F32 => {
                for &v in y {
                    w.write_sample(v as f32).expect("in-memory WAV");
                }
            }
        }
        w.finalize().expect("in-memory WAV");
    }
    out.into_inner()
}
