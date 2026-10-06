# Asymmetric Phase Coding Audio Watermarking: Rust

**Sign audio with a secret key. Verify it with the public key alone.**

Rust implementation of APC audio watermarking (format `apcaw-v1`): a library, the `apcaw`
command-line tool and a C ABI. An Ed25519-signed message is embedded in the STFT phase and
magnitude of 44.1 kHz audio. A verifier that holds only the 32-byte public key recovers the
message and checks the signature. It needs no original, no model weights, no registry and no
shared secret.

- Paper: [NeurIPS 2026](https://neurips.cc/virtual/2026/loc/atlanta/poster/149813),
  [arXiv:2605.07241](https://arxiv.org/abs/2605.07241)
- Live demo: <https://gy19a.github.io/asymmetric-phase-coding-audio-watermarking-js/>
- Python reference: <https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking>
- JavaScript library and demo: <https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking-js>

This is a byte-exact port of the Python reference. For the same input, key and message, the two
write byte-identical signed WAV files and return the same verification report, field for field.
Key files are interchangeable. Sign plus verify of 10 s of audio takes under 3 ms on one thread.

## Install

Rust 1.80 or later:

```sh
cargo build --release                      # ./target/release/apcaw
cargo install --path crates/apcaw-cli      # or install into ~/.cargo/bin
```

- WAV input and output are handled in-process.
- `ffmpeg` on `PATH` is needed only to decode other formats (MP3, AAC, Opus, FLAC, ...), to
  resample inputs that are not 44.1 kHz, and to write FLAC. Use `--ffmpeg PATH` to pick a binary.
- Multichannel input is downmixed to mono, with a notice.

## Command line

```sh
apcaw keygen --secret-out alice.sec --public-out alice.pub [--pem]
apcaw sign   -i speech.wav -o signed.wav -k alice.sec -m "message" [--profile wb|nb|auto]
apcaw verify -i signed.mp3 -p alice.pub [--resync] [--json]
apcaw batch-verify -p alice.pub a.wav b.mp3 ...
apcaw inspect -i signed.wav -p alice.pub
apcaw layout -p alice.pub | --seed N
apcaw selftest
apcaw bench -i speech.wav
apcaw serve --stdio
```

`sign` is closed loop: it reads the written file back and keeps it only if it verifies. Existing
files are not overwritten without `-y`. `--json` gives the same keys as the Python CLI.

Exit codes: 0 verified, 1 not verified, 2 usage error (including a malformed key or an existing
output), 3 I/O error, 130 interrupted. A script can therefore tell "no valid signature under this
key" from "could not read this file". Every command, flag and JSON field is documented, with real
transcripts, in [`docs/CLI.md`](docs/CLI.md).

## Library

```toml
[dependencies]
apcaw = { git = "https://github.com/GY19A/asymmetric-phase-coding-audio-watermarking-rs" }
```

```rust
use apcaw::wav::{read_wav_file, write_wav, Codec};
use apcaw::{keygen_from_seed, sign, verify, Options, Profile};

let kp = keygen_from_seed([7u8; 32]);
let x = read_wav_file("speech.wav".as_ref())?.mono(None)?;   // 44.1 kHz input
let y = sign(&x, 44_100, &kp.secret, b"hello", &Profile::WB, &Options::v1())?;
let r = verify(&y, 44_100, &kp.public, None, &Options::v1(), false);
assert_eq!(r.message.as_deref(), Some(&b"hello"[..]));
std::fs::write("signed.wav", write_wav(&y, 44_100, Codec::Pcm16))?;
```

The codec works on `f64` samples and does no I/O. `apcaw::wav` (default feature `wav`) reads and
writes WAV; parallel verification sits behind the default feature `parallel`.

The same crate builds `libapcaw.a` and `libapcaw.so` for C, with the header
[`include/apcaw.h`](include/apcaw.h). `apcaw_verify_f64` returns the JSON report of
`apcaw verify --json`. [`examples/c/verify.c`](examples/c/verify.c) is built and run by the tests.

## How it works

- **Phase channel.** Each bit sets the phase of one key-selected STFT cell per group of eight
  frames to +π/2 (bit 1) or −π/2 (bit 0). The verifier reads the sign of sin φ.
- **Magnitude channel.** Each bit moves the log-level difference of a key-selected bin pair to an
  odd (1) or even (0) multiple of one nat. The verifier reads its parity.
- **Payload.** Length, message and a 64-byte Ed25519 signature, protected by 30 Reed-Solomon
  parity bytes (up to 15 byte errors repaired).
- **Layout.** The bins and pairs come from a shuffle seeded by the SHA-256 of the public key, so
  the verifier rebuilds the layout from the key and nothing is stored or sent.
- **Acceptance.** A candidate is accepted only if its Ed25519 signature verifies. A false accept
  requires an Ed25519 forgery.

The full format is specified in Appendix A of the paper. `--segment` and `verify --scan` (sign
and read independent blocks of a long file) are an extension that only this implementation has.

## Tests

```sh
cargo test --workspace --release
cargo clippy --workspace --all-targets -- -D warnings
./target/release/apcaw selftest            # checks against the embedded reference vectors
```

The suite checks the port against the conformance vectors in `crates/apcaw/vectors/` (a checked
copy of the vectors in the Python reference) and against fixtures produced by the Python
reference, numpy and reedsolo. The CLI tests need `ffmpeg` with libmp3lame.

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

BSD 2-Clause, see [`LICENSE`](LICENSE). Copyright (c) 2026, Guang Yang (guangyang19@ucla.edu).

The test clips in `tests/media/` are excerpts of LibriSpeech (Panayotov et al., ICASSP 2015),
licensed CC BY 4.0; see `tests/media/ATTRIBUTION.txt`.
