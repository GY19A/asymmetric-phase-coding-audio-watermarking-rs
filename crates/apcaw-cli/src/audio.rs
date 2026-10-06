// SPDX-License-Identifier: BSD-2-Clause
//! Audio in and out of the tools.
//!
//! Input: WAV (PCM 8/16/24/32-bit, float 32/64, `WAVE_FORMAT_EXTENSIBLE`,
//! streamed headers) is decoded in-process; everything else goes through
//! ffmpeg (`pcm_f64le` WAV on a pipe). Multichannel audio is downmixed by
//! the channel mean unless a channel is picked, and rates other than
//! 44100 Hz are resampled by ffmpeg (`aresample`). Every such conversion is
//! reported as a note, never silent (format §1).
//!
//! Output: 16-bit PCM WAV (the reference's format), 24-bit PCM, 32-bit
//! float, or 16-bit FLAC through ffmpeg.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use apcaw::wav::{read_wav, write_wav, Codec, SampleFormat};
use apcaw::SAMPLE_RATE;

use crate::errors::{strerror, CliError, CliResult};

/// External programs.
#[derive(Debug, Clone)]
pub struct Tools {
    /// ffmpeg (`--ffmpeg`, `APCAW_FFMPEG`).
    pub ffmpeg: OsString,
    /// ffprobe (`--ffprobe`, `APCAW_FFPROBE`), used for `-v` diagnostics only.
    pub ffprobe: OsString,
}

/// Decoded input, mono at 44100 Hz.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// Mono samples at 44100 Hz.
    pub samples: Vec<f64>,
    /// Sample rate of the source.
    pub source_rate: u32,
    /// Channels of the source.
    pub channels: usize,
    /// `"wav"` (decoded in-process) or `"ffmpeg"`.
    pub decoder: &'static str,
    /// Source encoding, e.g. `pcm_s16le`.
    pub encoding: String,
    /// Conversions applied (downmix, resampling), in order.
    pub notes: Vec<String>,
}

impl Loaded {
    /// Duration in seconds.
    pub fn seconds(&self) -> f64 {
        self.samples.len() as f64 / SAMPLE_RATE as f64
    }
}

/// Output encodings of `sign`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutCodec {
    /// 16-bit PCM WAV (default; what the reference writes)
    #[value(name = "pcm_s16le", alias = "pcm16", alias = "s16")]
    Pcm16,
    /// 24-bit PCM WAV
    #[value(name = "pcm_s24le", alias = "pcm24", alias = "s24")]
    Pcm24,
    /// 32-bit float WAV (not clipped)
    #[value(name = "f32", alias = "pcm_f32le", alias = "float")]
    F32,
    /// 16-bit FLAC (lossless, through ffmpeg)
    #[value(name = "flac")]
    Flac,
}

impl OutCodec {
    pub fn name(self) -> &'static str {
        match self {
            OutCodec::Pcm16 => "pcm_s16le",
            OutCodec::Pcm24 => "pcm_s24le",
            OutCodec::F32 => "f32",
            OutCodec::Flac => "flac",
        }
    }

    /// The codec implied by an output name: FLAC for `*.flac`, else 16-bit WAV.
    pub fn for_path(path: &str) -> OutCodec {
        let flac = Path::new(path).extension().is_some_and(|e| e.eq_ignore_ascii_case("flac"));
        if flac {
            OutCodec::Flac
        } else {
            OutCodec::Pcm16
        }
    }

    /// Samples the encoding clips (outside `[-1, max]`, as the reference counts them).
    pub fn clipped(self, y: &[f64]) -> usize {
        let hi = match self {
            OutCodec::Pcm16 | OutCodec::Flac => 32767.0 / 32768.0,
            OutCodec::Pcm24 => 8_388_607.0 / 8_388_608.0,
            OutCodec::F32 => return 0,
        };
        y.iter().filter(|&&v| !(-1.0..=hi).contains(&v)).count()
    }
}

// ---------------------------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------------------------

/// The bytes of `path` (`-` is standard input), with the reference's messages.
pub fn read_input(path: &str) -> CliResult<Vec<u8>> {
    if path == "-" {
        let mut b = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut b)
            .map_err(|e| CliError::io(format!("cannot read standard input: {}", strerror(&e))))?;
        return Ok(b);
    }
    if !Path::new(path).is_file() {
        return Err(CliError::io(format!("cannot read {path}: no such file")));
    }
    fs::read(path).map_err(|e| CliError::io(format!("cannot read {path}: {}", strerror(&e))))
}

/// Whether `b` starts like a RIFF/WAVE file.
fn looks_like_wav(b: &[u8]) -> bool {
    b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WAVE"
}

/// Decode `path` (`-` for standard input) to mono 44100 Hz.
pub fn load(path: &str, channel: Option<usize>, tools: &Tools) -> CliResult<Loaded> {
    if path == "-" {
        let b = read_input(path)?;
        return decode(&b, path, None, channel, tools);
    }
    if !Path::new(path).is_file() {
        return Err(CliError::io(format!("cannot read {path}: no such file")));
    }
    // peek: WAV is read whole and decoded here, anything else is left to ffmpeg
    let mut head = [0u8; 12];
    let n = fs::File::open(path)
        .and_then(|mut f| read_up_to(&mut f, &mut head))
        .map_err(|e| CliError::io(format!("cannot read {path}: {}", strerror(&e))))?;
    if looks_like_wav(&head[..n]) {
        let b = read_input(path)?;
        decode(&b, path, Some(Path::new(path)), channel, tools)
    } else {
        decode(&[], path, Some(Path::new(path)), channel, tools)
    }
}

fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Decode audio held in `bytes` (or, when `bytes` is empty and `file` is
/// given, the file itself through ffmpeg). `name` is used in messages.
pub fn decode(
    bytes: &[u8],
    name: &str,
    file: Option<&Path>,
    channel: Option<usize>,
    tools: &Tools,
) -> CliResult<Loaded> {
    let mut notes = Vec::new();
    let ((audio, codec), decoder) = if looks_like_wav(bytes) {
        match read_wav(bytes) {
            Ok(a) => ((a, None), "wav"),
            // a WAV encoding the reader does not handle (ADPCM, mu-law, ...): ffmpeg may
            Err(e) => match ffmpeg_decode(bytes, file, tools) {
                Ok(a) => (a, "ffmpeg"),
                Err(_) => return Err(CliError::io(format!("cannot read {name}: {e}"))),
            },
        }
    } else {
        let a = ffmpeg_decode(bytes, file, tools).map_err(|e| {
            let wav = if matches!(e, ToolError::Missing(..)) { "not a WAV file and " } else { "" };
            CliError::io(format!("cannot read {name}: {wav}{e}"))
        })?;
        (a, "ffmpeg")
    };
    let encoding = codec.unwrap_or_else(|| match audio.format {
        SampleFormat::Int(8) => "pcm_u8".to_string(),
        SampleFormat::Int(b) => format!("pcm_s{b}le"),
        SampleFormat::Float(b) => format!("pcm_f{b}le"),
    });
    if audio.channels == 0 {
        return Err(CliError::io(format!("cannot read {name}: no audio channels")));
    }
    let mono = audio
        .mono(channel)
        .map_err(|e| CliError::usage(format!("{name}: {}", e.to_string().trim_start_matches("invalid input: "))))?;
    if audio.channels > 1 && channel.is_none() {
        notes.push(format!("downmixed {} channels to mono (channel mean)", audio.channels));
    }
    let samples = if audio.rate == SAMPLE_RATE {
        mono
    } else {
        if audio.rate == 0 {
            return Err(CliError::io(format!("cannot read {name}: sample rate 0")));
        }
        let y = ffmpeg_resample(&mono, audio.rate, tools).map_err(|e| {
            CliError::io(format!("cannot resample {name} ({} Hz -> {SAMPLE_RATE} Hz): {e}", audio.rate))
        })?;
        notes.push(format!("resampled {} Hz -> {SAMPLE_RATE} Hz (ffmpeg aresample)", audio.rate));
        y
    };
    Ok(Loaded { samples, source_rate: audio.rate, channels: audio.channels, decoder, encoding, notes })
}

/// A failed external tool run.
#[derive(Debug)]
pub enum ToolError {
    /// The program could not be started.
    Missing(OsString, io::Error),
    /// It exited unsuccessfully; the last line of its stderr.
    Failed(String),
    /// Its output could not be parsed.
    Output(String),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolError::Missing(p, e) if e.kind() == io::ErrorKind::NotFound => write!(
                f,
                "ffmpeg not found ({}); install ffmpeg or pass --ffmpeg PATH / set APCAW_FFMPEG",
                p.to_string_lossy()
            ),
            ToolError::Missing(p, e) => write!(f, "cannot run {}: {}", p.to_string_lossy(), strerror(e)),
            ToolError::Failed(m) => write!(f, "ffmpeg failed: {m}"),
            ToolError::Output(m) => write!(f, "{m}"),
        }
    }
}

/// Run `prog args`, feeding `input` on stdin; its stdout.
/// Run a tool; its stdout and stderr.
fn run_tool(prog: &OsStr, args: &[&OsStr], input: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), ToolError> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ToolError::Missing(prog.to_os_string(), e))?;
    let stdin = child.stdin.take();
    let out = std::thread::scope(|s| {
        if let (Some(mut w), Some(data)) = (stdin, input) {
            // the tool may stop reading early (bad data): a broken pipe is its error to report
            s.spawn(move || {
                let _ = w.write_all(data);
            });
        }
        child.wait_with_output()
    })
    .map_err(|e| ToolError::Failed(strerror(&e)))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim();
        let why = match (last, out.status.code()) {
            ("", Some(c)) => format!("exit status {c}"),
            ("", None) => "killed by a signal".to_string(),
            (l, _) => l.to_string(),
        };
        return Err(ToolError::Failed(why));
    }
    Ok((out.stdout, out.stderr))
}

/// ffmpeg input argument for a file (`file:` so that names with `:` are not protocols).
fn file_arg(p: &Path) -> OsString {
    let mut s = OsString::from("file:");
    s.push(p.as_os_str());
    s
}

/// The codec of the first audio stream in ffmpeg's `-v info` stream listing
/// (`Stream #0:0: Audio: mp3 (mp3float), 44100 Hz, ...`).
fn source_codec(stderr: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(stderr);
    let input = s.split("Output #0").next().unwrap_or_default();
    let rest = input.split_once("Audio: ")?.1;
    let codec: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    (!codec.is_empty()).then_some(codec)
}

/// Decode with ffmpeg to float64 WAV, all channels, the source rate; also
/// the source codec when ffmpeg names it.
fn ffmpeg_decode(
    bytes: &[u8],
    file: Option<&Path>,
    tools: &Tools,
) -> Result<(apcaw::wav::Audio, Option<String>), ToolError> {
    let (src, input) = match file {
        Some(p) if bytes.is_empty() => (file_arg(p), None),
        _ => (OsString::from("pipe:0"), Some(bytes)),
    };
    let args: Vec<&OsStr> = [
        OsStr::new("-nostdin"),
        OsStr::new("-hide_banner"),
        OsStr::new("-nostats"),
        // `info` for the stream listing that names the source codec
        OsStr::new("-v"),
        OsStr::new("info"),
        OsStr::new("-i"),
        &src,
        OsStr::new("-map"),
        OsStr::new("0:a:0"),
        OsStr::new("-c:a"),
        OsStr::new("pcm_f64le"),
        OsStr::new("-f"),
        OsStr::new("wav"),
        OsStr::new("pipe:1"),
    ]
    .to_vec();
    let args: Vec<&OsStr> = if input.is_some() {
        // `-nostdin` would keep ffmpeg from reading the piped data
        args.into_iter().skip(1).collect()
    } else {
        args
    };
    let (out, err) = run_tool(&tools.ffmpeg, &args, input)?;
    let audio = read_wav(&out).map_err(|e| ToolError::Output(format!("ffmpeg output: {e}")))?;
    Ok((audio, source_codec(&err)))
}

/// Resample mono float64 samples from `rate` to 44100 Hz with ffmpeg's `aresample`.
fn ffmpeg_resample(x: &[f64], rate: u32, tools: &Tools) -> Result<Vec<f64>, ToolError> {
    let raw: Vec<u8> = x.iter().flat_map(|v| v.to_le_bytes()).collect();
    let ar = rate.to_string();
    let filt = format!("aresample={SAMPLE_RATE}");
    let args = [
        "-hide_banner",
        "-v",
        "error",
        "-f",
        "f64le",
        "-ar",
        ar.as_str(),
        "-ac",
        "1",
        "-i",
        "pipe:0",
        "-af",
        filt.as_str(),
        "-f",
        "f64le",
        "-ac",
        "1",
        "pipe:1",
    ];
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let (out, _) = run_tool(&tools.ffmpeg, &args, Some(&raw))?;
    if out.len() % 8 != 0 {
        return Err(ToolError::Output(format!("ffmpeg returned {} bytes, not float64 samples", out.len())));
    }
    Ok(out.chunks_exact(8).map(|c| f64::from_le_bytes(c.try_into().expect("8-byte chunk"))).collect())
}

/// `ffprobe` description of the input's first audio stream (codec, rate,
/// channels, duration), for `-v`; `None` when ffprobe is unavailable.
pub fn probe(path: &str, tools: &Tools) -> Option<String> {
    if path == "-" {
        return None;
    }
    let src = file_arg(Path::new(path));
    let args: Vec<&OsStr> = [
        OsStr::new("-v"),
        OsStr::new("error"),
        OsStr::new("-select_streams"),
        OsStr::new("a:0"),
        OsStr::new("-show_entries"),
        OsStr::new("stream=codec_name,sample_rate,channels:format=format_name,duration"),
        OsStr::new("-of"),
        OsStr::new("compact=p=0"),
        &src,
    ]
    .to_vec();
    let (out, _) = run_tool(&tools.ffprobe, &args, None).ok()?;
    let s = String::from_utf8_lossy(&out);
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    (!s.is_empty()).then_some(s)
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

/// Encode mono 44100 Hz samples.
pub fn encode(y: &[f64], codec: OutCodec, tools: &Tools) -> CliResult<Vec<u8>> {
    let wav = |c| write_wav(y, SAMPLE_RATE, c);
    match codec {
        OutCodec::Pcm16 => Ok(wav(Codec::Pcm16)),
        OutCodec::Pcm24 => Ok(wav(Codec::Pcm24)),
        OutCodec::F32 => Ok(wav(Codec::F32)),
        OutCodec::Flac => {
            let pcm = wav(Codec::Pcm16);
            let args: Vec<&OsStr> =
                ["-hide_banner", "-v", "error", "-f", "wav", "-i", "pipe:0", "-c:a", "flac", "-f", "flac", "pipe:1"]
                    .iter()
                    .map(OsStr::new)
                    .collect();
            let (mut flac, _) = run_tool(&tools.ffmpeg, &args, Some(&pcm))
                .map_err(|e| CliError::io(format!("cannot encode FLAC: {e}")))?;
            set_flac_total_samples(&mut flac, y.len() as u64);
            Ok(flac)
        }
    }
}

/// Fill in STREAMINFO's total-samples field, which ffmpeg leaves 0
/// ("unknown") when it writes to a pipe and cannot seek back; libsndfile
/// then refuses the file. Returns whether the field was set.
fn set_flac_total_samples(flac: &mut [u8], n: u64) -> bool {
    // "fLaC", then the STREAMINFO block (type 0, 34 bytes); the 36-bit count
    // is the low nibble of byte 21 and bytes 22..26
    let streaminfo = flac.len() >= 42 && flac.starts_with(b"fLaC") && flac[4] & 0x7f == 0 && flac[5..8] == [0, 0, 34];
    if !streaminfo || n >= 1 << 36 || flac[21] & 0x0f != 0 || flac[22..26] != [0; 4] {
        return false;
    }
    flac[21] |= (n >> 32) as u8;
    flac[22..26].copy_from_slice(&(n as u32).to_be_bytes());
    true
}

// ---------------------------------------------------------------------------------------------
// Temporary files
// ---------------------------------------------------------------------------------------------

/// Temporary files to delete when the process is interrupted.
static TEMPS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Delete the registered temporary files (the SIGINT handler).
pub fn remove_temps() {
    if let Ok(mut t) = TEMPS.lock() {
        for p in t.drain(..) {
            let _ = fs::remove_file(p);
        }
    }
}

/// A temporary file next to an output, `.{name}.tmp{pid}` as the reference
/// names it; deleted on drop (and on Ctrl-C) unless renamed into place.
#[derive(Debug)]
pub struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// Temporary sibling of `out`.
    pub fn beside(out: &Path) -> io::Result<TempFile> {
        let abs = std::path::absolute(out)?;
        let dir = abs.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"));
        let mut name = OsString::from(".");
        name.push(abs.file_name().unwrap_or(OsStr::new("output")));
        name.push(format!(".tmp{}", std::process::id()));
        let path = dir.join(name);
        if let Ok(mut t) = TEMPS.lock() {
            t.push(path.clone());
        }
        Ok(TempFile { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rename into place (atomic within a file system).
    pub fn persist(self, to: &Path) -> io::Result<()> {
        fs::rename(&self.path, to)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
        if let Ok(mut t) = TEMPS.lock() {
            t.retain(|p| p != &self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_from_name_and_clipping() {
        assert_eq!(OutCodec::for_path("a/b.FLAC"), OutCodec::Flac);
        assert_eq!(OutCodec::for_path("b.wav"), OutCodec::Pcm16);
        assert_eq!(OutCodec::for_path("-"), OutCodec::Pcm16);
        let y = [-1.0, -1.0000001, 32767.0 / 32768.0, 0.99999, 1.0];
        assert_eq!(OutCodec::Pcm16.clipped(&y), 3);
        assert_eq!(OutCodec::Pcm24.clipped(&y), 2);
        assert_eq!(OutCodec::F32.clipped(&y), 0);
    }

    #[test]
    fn flac_total_samples_is_filled_in() {
        // the head of `ffmpeg -f flac pipe:1` output: 44100 Hz, mono, 16 bits, 0 samples
        let mut h = b"fLaC\x00\x00\x00\x22\x12\x00\x12\x00\x00\x00\x00\x00\x24\x15\x0a\xc4\x40\xf0".to_vec();
        h.resize(42, 0);
        let mut f = h.clone();
        assert!(set_flac_total_samples(&mut f, 0x1_2345_6789));
        assert_eq!(f[18..26], [0x0a, 0xc4, 0x40, 0xf1, 0x23, 0x45, 0x67, 0x89]);
        assert_eq!(f[..18], h[..18]);
        // a count already there, or no STREAMINFO: untouched
        let g = f.clone();
        assert!(!set_flac_total_samples(&mut f, 5));
        assert_eq!(f, g);
        let mut w = b"RIFF".to_vec();
        w.resize(42, 0);
        assert!(!set_flac_total_samples(&mut w, 5));
    }

    #[test]
    fn source_codec_from_the_stream_listing() {
        let err = b"Input #0, mp3, from 'file:s.mp3':\n  Duration: 00:00:10.03, start: 0.025057, bitrate: 128 kb/s\n  \
                    Stream #0:0: Audio: mp3 (mp3float), 44100 Hz, mono, fltp, 128 kb/s\n\
                    Output #0, wav, to 'pipe:1':\n    Stream #0:0: Audio: pcm_f64le, 44100 Hz, mono, dbl\n";
        assert_eq!(source_codec(err).as_deref(), Some("mp3"));
        assert_eq!(source_codec(b"Output #0, wav:\n  Stream #0:0: Audio: pcm_f64le\n"), None);
        assert_eq!(source_codec(b""), None);
    }

    #[test]
    fn temp_file_is_removed_unless_persisted() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/scratch");
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("unit_temp.wav");
        let t = TempFile::beside(&out).unwrap();
        assert!(t.path().file_name().unwrap().to_string_lossy().starts_with(".unit_temp.wav.tmp"));
        fs::write(t.path(), b"x").unwrap();
        let p = t.path().to_path_buf();
        drop(t);
        assert!(!p.exists());
        let t = TempFile::beside(&out).unwrap();
        fs::write(t.path(), b"y").unwrap();
        t.persist(&out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"y");
        fs::remove_file(&out).unwrap();
    }
}
