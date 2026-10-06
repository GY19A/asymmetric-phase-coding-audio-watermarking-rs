# Asymmetric Phase Coding Audio Watermarking: the Rust tool

**Sign audio with a secret key. Verify it with the public key alone.** `apcaw` embeds an Ed25519-signed message in the short-time spectrum of 44.1 kHz audio. It writes the message twice, once in the phase and once in the magnitude, and recovers it later from the samples. Verification needs the 32-byte public key and nothing else: no model weights, no registry, no network, no shared secret. The method is training-free.

This is a command-line tool in the spirit of ffmpeg. It reads and writes ordinary audio files, it is scriptable, and it returns exit codes a shell can branch on. The same codec is available as a Rust library and through a C ABI.

The tool implements format `apcaw-v1` (Appendix A of the paper) and is a byte-exact port of the [Python reference implementation](https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking):

- **the two implementations write byte-identical signed WAV files** for the same input, key and message;
- they return the same verification report, field for field, including the decoder's counters;
- key files are interchangeable.

The test suite checks this against the frozen conformance vectors of the Python reference and against fixtures produced by it.

- Paper: [NeurIPS 2026](https://neurips.cc/virtual/2026/loc/atlanta/poster/149813), [arXiv:2605.07241](https://arxiv.org/abs/2605.07241)
- Live demo: <https://gy19a.github.io/asymmetric-phase-coding-audio-watermarking-js/>
- Python reference: <https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking>; JavaScript: <https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking-js>

## Contents

1. [Install](#install)
2. [Five-minute tour](#five-minute-tour)
3. [Commands](#commands)
4. [Exit codes](#exit-codes)
5. [How it works](#how-it-works)
6. [Measured behavior](#measured-behavior)
7. [Performance](#performance)
8. [Library use](#library-use)
9. [Scope and limits](#scope-and-limits)
10. [Development](#development)
11. [Citation](#citation)
12. [License](#license)

## Install

You need Rust 1.80 or later. From this directory:

```bash
cargo build --release
./target/release/apcaw --help
```

To install into your Cargo bin directory:

```bash
cargo install --path crates/apcaw-cli
```

WAV input and output are handled in-process, so a WAV-only pipeline needs nothing else. `ffmpeg` on `PATH` is needed for three things:

- decoding every other input format (MP3, AAC, Opus, FLAC, ...);
- resampling inputs that are not at 44.1 kHz;
- writing FLAC.

The tool runs ffmpeg as a child process and does not link libav, so any recent build works. Point it at a specific binary with `--ffmpeg PATH` or `APCAW_FFMPEG`.

## Five-minute tour

This is a real run. `speech.wav` is a copy of `tests/media/0001_librispeech_8555-284447-0010.wav`, 10 s of LibriSpeech read speech.

**1. Make a key pair.** Keep the secret key; publish the public key.

```console
$ apcaw keygen --secret-out alice.sec --public-out alice.pub
public key 7fb93b19cb731d6232b8cdf56bcd12498ccf04a35ec6d5eabfd4dbc62c432a93
layout seed 590993974
wrote alice.sec (secret, mode 0600) and alice.pub
```

**2. Sign.** The tool embeds the message and writes a temporary file. It then reads that file back and verifies it, and only renames it into place if it verifies.

```console
$ apcaw sign -i speech.wav -o signed.wav -k alice.sec -m "NIPS2026: Authenticity Token for Deepfake Defense"
signed signed.wav: 49-byte message, profile wb, closed-loop verify ok (channel phase, path header)
  input     speech.wav: 10.00 s, 44100 Hz, mono, pcm_s16le (wav)
  payload   1160 body bits, layout seed 590993974
  phase     capacity 6240 bits, stream 1256 bits, 1 replica(s)
  magnitude capacity 3120 bits, stream 2416 bits, 2 replica(s)
  output    pcm_s16le, 441000 samples, 0 clipped
```

**3. Verify with the public key alone.**

```console
$ apcaw verify -i signed.wav -p alice.pub
VERIFIED  message='NIPS2026: Authenticity Token for Deepfake Defense'  channel=phase profile=wb path=header rs_corrected=0
  input     signed.wav: 10.00 s, 44100 Hz, mono, pcm_s16le (wav)
  message   49 bytes, hex 4e495053323032363a2041757468656e74696369747920546f6b656e20666f72204465657066616b6520446566656e7365
  payload   1160 body bits
  decoder   1 candidate(s), 1 RS-decoded, 1 signature check(s)
```

**4. The mark survives MP3 at 128 kb/s.**

```console
$ ffmpeg -hide_banner -loglevel error -i signed.wav -c:a libmp3lame -b:a 128k signed.mp3
$ apcaw verify -i signed.mp3 -p alice.pub; echo "exit code: $?"
VERIFIED  message='NIPS2026: Authenticity Token for Deepfake Defense'  channel=phase profile=wb path=header rs_corrected=0
  input     signed.mp3: 10.00 s, 44100 Hz, mono, mp3 (ffmpeg)
  message   49 bytes, hex 4e495053323032363a2041757468656e74696369747920546f6b656e20666f72204465657066616b6520446566656e7365
  payload   1160 body bits
  decoder   1 candidate(s), 1 RS-decoded, 1 signature check(s)
exit code: 0
```

**5. Someone else's key does not verify.** The exit code is 1.

```console
$ apcaw keygen --secret-out mallory.sec --public-out mallory.pub
public key 98debb31e1b5dd9771952258fd09e66b946e9b256dce26e8104bf730e4959aca
layout seed 591672866
wrote mallory.sec (secret, mode 0600) and mallory.pub
$ apcaw verify -i signed.mp3 -p mallory.pub; echo "exit code: $?"
NOT VERIFIED  no candidate passed RS decoding (460 tried)
  input     signed.mp3: 10.00 s, 44100 Hz, mono, mp3 (ffmpeg)
  decoder   460 candidate(s), 0 RS-decoded, 0 signature check(s)
exit code: 1
```

**6. Existing files are not overwritten** unless you pass `-y`.

```console
$ apcaw sign -i speech.wav -o signed.wav -k alice.sec -m "again"; echo "exit code: $?"
apcaw: signed.wav exists (use -y to overwrite)
exit code: 2
```

**7. Machine-readable output.** The report has the keys and key order of the Python CLI's `--json`.

```console
$ apcaw --json verify -i signed.mp3 -p alice.pub
{
  "file": "signed.mp3",
  "verified": true,
  "message": "NIPS2026: Authenticity Token for Deepfake Defense",
  "message_hex": "4e495053323032363a2041757468656e74696369747920546f6b656e20666f72204465657066616b6520446566656e7365",
  "channel": "phase",
  "profile": "wb",
  "path": "header",
  "rs_corrected": 0,
  "payload_bits": 1160,
  "candidates_tried": 1,
  "rs_passes": 1,
  "sig_checks": 1,
  "reason": "ok"
}
```

In a script, branch on the exit code:

```bash
apcaw -q verify -i "$1" -p alice.pub
rc=$?
if [ $rc = 0 ]; then
  echo "$1: signed by alice"
elif [ $rc = 1 ]; then
  echo "$1: no valid signature under this key"
else
  echo "$1: could not be checked (exit $rc)" >&2
fi
```

## Commands

| Command | Purpose |
| --- | --- |
| `apcaw keygen` | Generate an Ed25519 key pair. The secret key is written with mode 0600; `--pem` writes PEM instead of raw bytes. |
| `apcaw sign` | Embed a signed message. Closed loop by default: the written file must verify. |
| `apcaw verify` | Verify a file against a public key. `--resync` searches shifted or cropped audio; `--scan` reads segmented files. |
| `apcaw batch-verify` | Verify many files, printing one JSON object per line. The exit code is the worst per-file code. |
| `apcaw inspect` | Print capacity, header lengths and soft-value statistics of a file. |
| `apcaw layout` | Print the key-derived layout, from a public key or a seed. |
| `apcaw selftest` | Check this build against the embedded reference vectors (15 checks). |
| `apcaw bench` | Time sign and verify on a file, on 1 thread and on N threads. |
| `apcaw serve --stdio` | JSON-lines server on stdin and stdout, for use from other languages. |

The global flags are:

- `-v`/`--verbose`, `-q`/`--quiet`, `--json` and `--no-color`;
- `--threads N`;
- `--ffmpeg PATH` and `--ffprobe PATH`;
- `-y`/`--overwrite`, which has the alias `--force`.

`-i -` reads from standard input. `sign -o -` writes the WAV to standard output and all text to standard error.

The signing options that matter most:

| Option | Effect |
| --- | --- |
| `-m TEXT` / `--message-file PATH` | The message, at most 159 bytes. |
| `--profile wb\|nb\|auto` | `wb` (the default) uses 1.3–7.3 kHz. `nb` moves the magnitude channel to 0.35–3.6 kHz, for audio band-limited to 8 kHz. `auto` picks `nb` when less than 5% of the energy lies above 4 kHz. |
| `--codec pcm_s16le\|pcm_s24le\|f32\|flac` | The output encoding. The default is 16-bit PCM WAV, which is what the reference writes; a `.flac` output name selects FLAC. |
| `--legacy` | The legacy configuration: layout seed 42, 8-frame phase write, zeroed tail, no silent-bin erasure. It exists to reproduce the paper's legacy numbers. |
| `--segment [K]` | Sign every block of K groups independently (K = 26 by default, about 9.7 s). Verify with `verify --scan`. |

Every command, flag and JSON field is documented in [`docs/CLI.md`](docs/CLI.md), together with the full `--help` output.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `verify`: VERIFIED. |
| `1` | NOT VERIFIED. Also `sign` when the input cannot carry the mark or the closed-loop check fails, and `selftest` when a check fails. |
| `2` | Usage error: bad arguments, malformed key, message too long, output exists. |
| `3` | I/O error: unreadable input or key, undecodable audio, ffmpeg missing or failed, write failure. |
| `130` | Interrupted (Ctrl-C). Temporary files are removed. |

The split between `1` and `3` is deliberate. A script must be able to tell "this file carries no valid signature under this key" from "I could not read this file". The first is an answer; the second is a failure.

## How it works

### Frames and groups

The signal is cut into frames of 2048 samples, with no overlap and a rectangular window. Eight consecutive frames form a group (16384 samples, 0.37 s). A 10 s clip has 26 groups. Samples after the last whole frame are copied unchanged.

### Payload

The message `M` (at most 159 bytes) is signed with Ed25519 and framed as a single Reed–Solomon codeword:

```
C       = len(M) as 2 bytes || M || Ed25519 signature (64 bytes)
payload = C || RS parity (30 bytes)
```

- A 49-byte message gives `(2 + 49 + 64 + 30) · 8 = 1160` payload bits.
- The code over GF(2^8) corrects up to 15 byte errors.
- A 32-bit header carrying the payload length is repeated three times in front of the payload.
- The payload itself is repeated as often as the channel's capacity allows, up to a per-channel limit.

### Public layout

The layout seed is derived from the public key: the first 8 bytes of `SHA-256(public key)`, modulo 2^32. It seeds numpy's MT19937 generator, which shuffles the phase bins and the magnitude bin pairs. The layout depends only on the public key, so anyone who can verify can also compute it.

### Two channels

- **Phase.** In the first frame of every group, the phase of 240 bins (1.3–6.5 kHz) is set to `+π/2` for a 1 bit and `-π/2` for a 0 bit.
- **Magnitude.** For 120 bin pairs, the difference of the two bins' mean log-magnitudes over the group's eight frames is quantized to an odd or even multiple of 1 nat (quantization index modulation). In the `wb` profile the pairs cover 2.2–7.3 kHz.

A 10 s clip therefore carries 6240 phase bits and 3120 magnitude bits. Both channels are computed from the original spectrum and combined into one output.

A message needs room in both channels:

- a 49-byte message needs 11 groups, about 4.1 s;
- shorter clips are refused before anything is written.

### Verification

The verifier never needs the message length or any side information. For each profile (`wb`, then `nb`) and each channel (phase, then magnitude), it proceeds as follows:

1. It reads the header and decodes the payload at that length.
2. If that fails, it tries every possible message length from 0 to 159.
3. A candidate is accepted only if Reed–Solomon decoding succeeds, the embedded length field agrees with the decoded length, and the Ed25519 signature verifies under the public key.

The first accepted candidate wins. A false accept requires an Ed25519 forgery. Silent bins, which carry no information, are read as erasures rather than as confident zeros.

`--resync` adds a search over sample offsets 0..2047 and frame skips 0..10, for audio that was shifted or trimmed at the start.

## Measured behavior

Each of the three LibriSpeech clips in `tests/media/` was signed with the conformance key and a 49-byte message, processed with ffmpeg, and verified by the release binary. Each cell is a separate run. `rs N` is the number of Reed–Solomon byte corrections.

| Processing | Clip 0000 | Clip 0001 | Clip 0002 |
| --- | --- | --- | --- |
| none (signed WAV) | VERIFIED, rs 11 | VERIFIED, rs 0 | VERIFIED, rs 0 |
| FLAC | VERIFIED, rs 11 | VERIFIED, rs 0 | VERIFIED, rs 0 |
| MP3 128 kb/s | VERIFIED (magnitude), rs 7 | VERIFIED, rs 2 | VERIFIED, rs 1 |
| MP3 64 kb/s | NOT VERIFIED | VERIFIED, rs 12 | VERIFIED (magnitude), rs 1 |
| AAC 128 kb/s | VERIFIED (magnitude), rs 10 | VERIFIED, rs 0 | VERIFIED, rs 3 |
| Opus 96 kb/s | VERIFIED (magnitude), rs 15 | VERIFIED, rs 1 | VERIFIED, rs 5 |
| resampled to 48 kHz | VERIFIED, rs 9 | VERIFIED, rs 0 | VERIFIED, rs 0 |
| gain -6 dB | NOT VERIFIED | VERIFIED, rs 1 | VERIFIED, rs 0 |
| first 5 s only | VERIFIED, rs 11 | VERIFIED, rs 0 | VERIFIED, rs 0 |
| delayed by 5000 samples | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED |
| delayed by 5000 samples, `--resync` | VERIFIED, rs 11 | VERIFIED, rs 0 | VERIFIED, rs 0 |

Where no channel is named, the phase channel verified.

Clip 0000 is the weakest of the three. Frames 2 to 6 of its first group are digital silence, so a clean signed copy already needs 11 corrections, and MP3 at 64 kb/s or a 6 dB gain reduction push it past the limit of 15.

The Python reference CLI was run on the same files. Its reports agree with the Rust ones on every file it can read: the verdict, the channel, the number of corrections, the candidate and signature-check counters, and the reason. That includes the two failures of clip 0000, the 48 kHz resample and the `--resync` runs. It cannot read the AAC files at all, because its audio reader, libsndfile, has no AAC decoder.

Negative controls, each running the real verifier:

| Input | Result | Exit |
| --- | --- | --- |
| Signed file after MP3 128 kb/s, wrong public key | `NOT VERIFIED  no candidate passed RS decoding (460 tried)` | 1 |
| Unsigned original | `NOT VERIFIED  signature invalid (1 candidate(s) passed RS with a consistent length; ...)`, 2 candidates for clip 0002 | 1 |
| Sign 10 s of digital silence | `signing failed: the written file does not verify (...); nothing written to x1.wav` | 1 |
| Sign a 2 s clip | `signing failed: too short: 88200 samples give 5 groups; profile wb needs 1256 bits per channel (...)` | 1 |
| Missing file | `cannot read missing.wav: no such file` | 3 |
| Not an audio file | `cannot read test.pub: ffmpeg failed: ... Invalid data found when processing input` | 3 |

The failed signs left no output file behind.

On unsigned audio, the reason is "signature invalid" rather than "no candidate passed RS decoding". The magnitude channel of unmarked speech reads mostly zero bits. The all-zero word is a valid Reed–Solomon codeword, and it looks like an empty message. So each magnitude layout that decodes to it costs one signature check, which fails: one check for clips 0000 and 0001, and two for clip 0002, where both the `wb` and the `nb` layout reach it. The Python reference reports the same counters.

A `NOT VERIFIED` result is not proof of forgery. Degradation, misalignment, a wrong key and unmarked audio all produce it.

## Performance

Measured on a 16-core desktop CPU with a release build; the machine was under other load, so these numbers are upper bounds.

Library calls on 10 s clips (`apcaw bench`, mean of 50 runs after a warm-up), next to the Python reference's `sign` and `verify` on the same clips and machine (mean of 20 runs, Python 3.12, numpy 2.5):

| Clip | Rust 1 thread: sign / verify / total | Python: sign / verify / total | Speed-up |
| --- | --- | --- | --- |
| 0000 | 1.83 / 0.91 / 2.74 ms | 9.75 / 2.22 / 11.97 ms | 4.4x |
| 0001 | 1.74 / 0.87 / 2.60 ms | 8.97 / 2.03 / 11.00 ms | 4.2x |
| 0002 | 1.53 / 0.78 / 2.31 ms | 8.88 / 1.96 / 10.84 ms | 4.7x |

Sign plus verify of 10 s of audio takes under 3 ms on one thread, more than 3600 times faster than real time. Both sides were measured; neither number is an estimate. At 10 s per clip there is little work to parallelize: 32 threads give 2.6–2.8 ms.

Whole-process runs of the CLI on clip 0001, mean of 20 runs. These include process start, decoding, the closed loop and the write:

| Command | Wall time |
| --- | --- |
| `sign` (WAV in, WAV out, closed loop), 1 thread | 11.8 ms |
| `sign`, all threads | 15.7 ms |
| `verify` of the signed WAV, 1 thread | 4.5 ms |
| `verify` of the MP3, 1 thread | 42.2 ms, mostly ffmpeg's decode |
| `verify` of the MP3, wrong public key | 45.8 ms |
| `verify --resync` of the MP3, wrong public key, 1 thread | 1497 ms (40202 candidates) |
| `verify --resync` of the MP3, wrong public key, 32 threads | 432 ms |

The exhaustive resync search is the only expensive operation. It is off by default.

## Library use

The codec lives in the `apcaw` crate. It works on mono `f64` samples at 44100 Hz and does no I/O. WAV reading and writing (`apcaw::wav`) sit behind the default `wav` feature. Parallel verification (`rayon`) sits behind the default `parallel` feature.

```toml
[dependencies]
apcaw = { path = "crates/apcaw" }
```

```rust
use apcaw::{keygen_from_seed, sign, verify, Options, Profile};
let kp = keygen_from_seed([7u8; 32]);
// 10 s of white noise at -20 dBFS (any 44.1 kHz mono signal works)
let mut s = 1u32;
let x: Vec<f64> = (0..441_000)
    .map(|_| {
        s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (s as f64 / 4_294_967_296.0 - 0.5) * 0.2
    })
    .collect();
let y = sign(&x, 44_100, &kp.secret, b"hello", &Profile::WB, &Options::v1()).unwrap();
let r = verify(&y, 44_100, &kp.public, None, &Options::v1(), false);
assert!(r.verified);
assert_eq!(r.message.as_deref(), Some(&b"hello"[..]));
```

This example is the crate's doctest, so it is compiled and run by `cargo test`.

`sign` returns float samples. To write the 16-bit file the reference writes, use `apcaw::wav::write_wav(&y, 44_100, Codec::Pcm16)`. It clips to `[-1, 32767/32768]` and rounds half to even. A careful caller then verifies what was written, as the CLI does.

### C

The same crate builds `libapcaw.a` and `libapcaw.so`, with the header in [`include/apcaw.h`](include/apcaw.h). The API is:

- `apcaw_keygen` and `apcaw_public_key`;
- `apcaw_sign_f64`;
- `apcaw_verify_f64`, which returns the JSON report of `apcaw verify --json` without the `file` key;
- `apcaw_last_error` and `apcaw_string_free`.

[`examples/c/verify.c`](examples/c/verify.c) is built and run by the test suite:

```bash
cargo build --release -p apcaw
cc -O2 -Iinclude examples/c/verify.c target/release/libapcaw.a -lpthread -ldl -lm -o verify
./verify                          # key generation, sign and verify round trip
./verify signed.wav "$(xxd -p -c 64 alice.pub)"
```

## Scope and limits

- **The signature binds the message, not the audio.** A verified file proves that the holder of the secret key signed this message and that the mark survived. It does not prove that the audio around the mark is unmodified.
- **The time grid matters.** Plain `verify` expects the frame grid of the signed file. Audio that was delayed or trimmed at the start needs `--resync`, which recovers offsets within one frame plus up to 10 whole frames. Larger head trims and time-stretching are out of scope.
- **Robustness depends on the content.** Silence carries nothing. A clip with silent stretches, like clip 0000 above, has less margin. Signing digital silence fails by design instead of shipping an unverifiable file.
- **One codeword.** Messages are at most 159 bytes, and a 49-byte message needs about 4.1 s of audio.
- **44.1 kHz mono.** The codec works at 44100 Hz on one channel. The CLI resamples other rates and downmixes multichannel input to the channel mean, and says so. Resampling is done by ffmpeg in this tool and by scipy in the reference, so resampled inputs give slightly different samples in the two.
- **Segmented signing** (`--segment`, `--scan`) is an optional extension of the format that only this implementation provides. `--scan` finds blocks on the 16384-sample group grid.
- **These numbers are not a benchmark.** The measurements above come from three clips and one machine. They explain the mechanism. The results reported in the paper were measured with the Python reference implementation and are not inherited here.

## Development

```bash
cargo test --workspace --release                        # 80 tests and 1 doctest
cargo clippy --workspace --all-targets -- -D warnings   # also run with --all-features, and for -p apcaw --no-default-features
cargo fmt --all --check
./target/release/apcaw selftest                         # 15 checks against the embedded vectors
```

The test suite checks the port against the frozen conformance vectors in `crates/apcaw/vectors/`
(a checked copy of the vectors in the [Python reference](https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking)) and against reference
fixtures in `crates/apcaw/tests/fixtures/`, produced by the Python reference, numpy and reedsolo.

## Citation

```bibtex
@inproceedings{yang2026apc,
  title     = {Asymmetric Phase Coding Audio Watermarking},
  author    = {Yang, Guang and Liu, Fengchen and Ghasemian, Amir and Wang, Zhong and
               Mehrabi, Ninareh and Hosseinmardi, Homa},
  booktitle = {Advances in Neural Information Processing Systems (NeurIPS)},
  year      = {2026}
}
```

## License

Copyright (c) 2026, Guang Yang (guangyang19@ucla.edu).

Released under the [BSD 2-Clause License](LICENSE), the same license as the Python reference implementation.

The test clips in `tests/media/` are excerpts of the LibriSpeech corpus (Panayotov et al., ICASSP 2015), which is licensed CC BY 4.0. See [`tests/media/ATTRIBUTION.txt`](tests/media/ATTRIBUTION.txt).
