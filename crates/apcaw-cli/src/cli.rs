// SPDX-License-Identifier: BSD-2-Clause
//! Command-line syntax (clap). The subcommands and their flags follow the
//! Python reference CLI; see docs/CLI.md for the full `--help`.

use std::ffi::OsString;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use crate::audio::OutCodec;

pub const EXIT_CODES_HELP: &str = "\
Exit codes:
  0    success; VERIFIED
  1    NOT VERIFIED; signing failed (incl. the closed-loop check); selftest failed
  2    usage error: bad arguments, malformed key, message too long, output exists
  3    I/O error: unreadable input or key, undecodable audio, ffmpeg failure, write failure
  130  interrupted (temporary files are removed)

Input is any file ffmpeg reads (WAV is decoded in-process); `-i -` reads standard input.
Non-44.1 kHz input is resampled and multichannel input downmixed, each with a note.";

/// APC audio watermarking (apcaw-v1): sign audio with an Ed25519 key, verify with the public key.
#[derive(Debug, Parser)]
#[command(
    name = "apcaw",
    version,
    about,
    after_help = EXIT_CODES_HELP,
    subcommand_required = true,
    arg_required_else_help = true,
    max_term_width = 100
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Cmd,
}

/// Options accepted before or after the subcommand.
#[derive(Debug, Args)]
#[command(next_help_heading = "Global options")]
pub struct Global {
    /// More detail on stderr (repeatable)
    #[arg(short, long, action = ArgAction::Count, global = true, conflicts_with = "quiet")]
    pub verbose: u8,
    /// Only the result line: no notes, no details
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Machine-readable output (the keys of the Python CLI's --json)
    #[arg(long, global = true)]
    pub json: bool,
    /// Worker threads [default: all cores]
    #[arg(long, global = true, value_name = "N", value_parser = at_least_one)]
    pub threads: Option<usize>,
    /// No ANSI colours (also NO_COLOR=1, TERM=dumb, or when not a terminal)
    #[arg(long, global = true)]
    pub no_color: bool,
    /// ffmpeg executable
    #[arg(long, global = true, value_name = "PATH", env = "APCAW_FFMPEG", default_value = "ffmpeg")]
    pub ffmpeg: OsString,
    /// ffprobe executable (optional; input diagnostics at -v)
    #[arg(long, global = true, value_name = "PATH", env = "APCAW_FFPROBE", default_value = "ffprobe")]
    pub ffprobe: OsString,
    /// Overwrite existing output files
    #[arg(short = 'y', long = "overwrite", visible_alias = "force", global = true)]
    pub overwrite: bool,
}

fn at_least_one(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(0) => Err("must be at least 1".into()),
        Ok(n) => Ok(n),
        Err(e) => Err(e.to_string()),
    }
}

/// `--profile` of `sign`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum SignProfile {
    /// Wide band: phase bins 60..300, magnitude bins 100..340
    Wb,
    /// Narrow band (8 kHz-band speech): magnitude bins 16..168
    Nb,
    /// nb when less than 5% of the energy lies above 4 kHz, else wb
    Auto,
}

/// `--profile` of the verifying commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum VerifyProfile {
    /// Wide band only
    Wb,
    /// Narrow band only
    Nb,
    /// wb, then nb (the default)
    Auto,
}

impl VerifyProfile {
    pub fn profile(p: Option<VerifyProfile>) -> Option<apcaw::Profile> {
        match p {
            Some(VerifyProfile::Wb) => Some(apcaw::Profile::WB),
            Some(VerifyProfile::Nb) => Some(apcaw::Profile::NB),
            Some(VerifyProfile::Auto) | None => None,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Generate an Ed25519 key pair
    Keygen(KeygenArgs),
    /// Embed a signed message (closed loop: the written file must verify)
    Sign(SignArgs),
    /// Verify a file against a public key
    Verify(VerifyArgs),
    /// Verify many files, one JSON object per line (NDJSON) on stdout
    BatchVerify(BatchArgs),
    /// Capacity, header lengths and soft-value statistics
    Inspect(InspectArgs),
    /// Print the key-derived layout
    Layout(LayoutArgs),
    /// Check this build against the embedded reference vectors
    Selftest,
    /// Time sign and verify on a file (1 thread and N threads)
    Bench(BenchArgs),
    /// JSON-lines server on stdin/stdout (protocol in docs/CLI.md)
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Secret key output (mode 0600)
    #[arg(long, value_name = "PATH")]
    pub secret_out: String,
    /// Public key output
    #[arg(long, value_name = "PATH")]
    pub public_out: String,
    /// PKCS#8 / SPKI PEM instead of raw 32 bytes
    #[arg(long)]
    pub pem: bool,
}

/// Input selection shared by the commands that read audio.
#[derive(Debug, Clone, Args)]
pub struct ChannelArg {
    /// Use channel N (0-based) instead of the channel mean
    #[arg(long, value_name = "N")]
    pub channel: Option<usize>,
}

#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("msg").required(true).args(["message", "message_file"]))]
pub struct SignArgs {
    /// Input audio (`-` for stdin)
    #[arg(short, long, value_name = "PATH")]
    pub input: String,
    /// Output file (`-` for WAV on stdout)
    #[arg(short, long, value_name = "PATH")]
    pub output: String,
    /// Secret key (raw 32 B, 64 hex digits, or PEM)
    #[arg(short, long, value_name = "PATH")]
    pub key: String,
    /// Message (UTF-8, at most 159 bytes)
    #[arg(short, long, value_name = "TEXT")]
    pub message: Option<OsString>,
    /// Read the message bytes from a file
    #[arg(long, value_name = "PATH")]
    pub message_file: Option<String>,
    /// Profile
    #[arg(long, value_enum, ignore_case = true, default_value = "wb")]
    pub profile: SignProfile,
    /// Legacy configuration (layout seed 42, 8-frame phase write, zeroed tail, no erasure)
    #[arg(long)]
    pub legacy: bool,
    /// Sign each block of K groups separately (Rust extension; verify with --scan) [K: 26]
    #[arg(long, value_name = "K", num_args = 0..=1, default_missing_value = "26", value_parser = at_least_one)]
    pub segment: Option<usize>,
    /// Do not re-read and verify the written file
    #[arg(long)]
    pub no_closed_loop: bool,
    /// Also write the sign report as JSON to OUTPUT.apcaw.json
    #[arg(long)]
    pub sidecar: bool,
    /// Output encoding [default: pcm_s16le, flac for *.flac]
    #[arg(long, value_enum)]
    pub codec: Option<OutCodec>,
    #[command(flatten)]
    pub channel: ChannelArg,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Input audio (`-` for stdin)
    #[arg(short, long, value_name = "PATH")]
    pub input: String,
    /// Public key (raw 32 B, 64 hex digits, or PEM)
    #[arg(short = 'p', long, value_name = "PATH")]
    pub public_key: String,
    /// Profile [default: wb, then nb]
    #[arg(long, value_enum, ignore_case = true)]
    pub profile: Option<VerifyProfile>,
    /// Also search sample / frame offsets (cropped or shifted audio)
    #[arg(long)]
    pub resync: bool,
    /// Verify every group-aligned window of K groups (segmented signing; a group is 16384 samples) [K: 26]
    #[arg(long, value_name = "K", num_args = 0..=1, default_missing_value = "26",
          value_parser = at_least_one, conflicts_with = "resync")]
    pub scan: Option<usize>,
    /// Legacy verifier (header only, layout seed 42)
    #[arg(long, visible_alias = "legacy-verifier")]
    pub legacy: bool,
    #[command(flatten)]
    pub channel: ChannelArg,
}

#[derive(Debug, Args)]
pub struct BatchArgs {
    /// Public key (raw 32 B, 64 hex digits, or PEM)
    #[arg(short = 'p', long, value_name = "PATH")]
    pub public_key: String,
    /// Input files
    #[arg(value_name = "FILES", required = true)]
    pub files: Vec<String>,
    /// Files verified concurrently [default: --threads]
    #[arg(short, long, value_name = "N", value_parser = at_least_one)]
    pub jobs: Option<usize>,
    /// Profile [default: wb, then nb]
    #[arg(long, value_enum, ignore_case = true)]
    pub profile: Option<VerifyProfile>,
    /// Also search sample / frame offsets
    #[arg(long)]
    pub resync: bool,
    /// Legacy verifier (header only, layout seed 42)
    #[arg(long, visible_alias = "legacy-verifier")]
    pub legacy: bool,
    #[command(flatten)]
    pub channel: ChannelArg,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Input audio (`-` for stdin)
    #[arg(short, long, value_name = "PATH")]
    pub input: String,
    /// Public key (raw 32 B, 64 hex digits, or PEM)
    #[arg(short = 'p', long, value_name = "PATH")]
    pub public_key: String,
    /// Legacy configuration (layout seed 42, no silent-bin erasure)
    #[arg(long)]
    pub legacy: bool,
    #[command(flatten)]
    pub channel: ChannelArg,
}

#[derive(Debug, Args)]
#[command(group = clap::ArgGroup::new("source").required(true).args(["public_key", "seed"]))]
pub struct LayoutArgs {
    /// Public key (raw 32 B, 64 hex digits, or PEM)
    #[arg(short = 'p', long, value_name = "PATH")]
    pub public_key: Option<String>,
    /// Layout seed instead of a key
    #[arg(long, value_name = "SEED", allow_negative_numbers = true)]
    pub seed: Option<i128>,
    /// Only this profile
    #[arg(long, value_enum, ignore_case = true)]
    pub profile: Option<VerifyProfile>,
}

#[derive(Debug, Args)]
pub struct BenchArgs {
    /// Input audio (`-` for stdin)
    #[arg(short, long, value_name = "PATH")]
    pub input: String,
    /// Secret key [default: a fixed test key]
    #[arg(short, long, value_name = "PATH")]
    pub key: Option<String>,
    /// Message
    #[arg(short, long, value_name = "TEXT", default_value = "NIPS2026: Authenticity Token for Deepfake Defense")]
    pub message: String,
    /// Timed runs per measurement (after one warm-up)
    #[arg(long, value_name = "N", default_value = "10", value_parser = at_least_one)]
    pub repeat: usize,
    /// Profile
    #[arg(long, value_enum, ignore_case = true, default_value = "wb")]
    pub profile: SignProfile,
    /// Legacy configuration
    #[arg(long)]
    pub legacy: bool,
    #[command(flatten)]
    pub channel: ChannelArg,
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Serve JSON lines on stdin/stdout (the only transport)
    #[arg(long, required = true)]
    pub stdio: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn optional_values() {
        let c = Cli::try_parse_from(["apcaw", "verify", "-i", "a.wav", "-p", "k", "--scan"]).unwrap();
        let Cmd::Verify(v) = c.command else { panic!() };
        assert_eq!(v.scan, Some(26));
        let c = Cli::try_parse_from(["apcaw", "-q", "verify", "-i", "a", "-p", "k", "--scan", "3", "--profile", "NB"])
            .unwrap();
        let Cmd::Verify(v) = c.command else { panic!() };
        assert_eq!((v.scan, v.profile), (Some(3), Some(VerifyProfile::Nb)));
        assert!(c.global.quiet);
        assert!(Cli::try_parse_from(["apcaw", "verify", "-i", "a", "-p", "k", "--scan", "--resync"]).is_err());
        assert!(Cli::try_parse_from(["apcaw", "--threads", "0", "selftest"]).is_err());
        assert!(Cli::try_parse_from(["apcaw", "-v", "-q", "selftest"]).is_err());
        let c = Cli::try_parse_from(["apcaw", "layout", "--seed", "-1"]).unwrap();
        let Cmd::Layout(l) = c.command else { panic!() };
        assert_eq!(l.seed, Some(-1));
        let c = Cli::try_parse_from(["apcaw", "keygen", "--secret-out", "a", "--public-out", "b", "--force"]).unwrap();
        assert!(c.global.overwrite);
    }
}
