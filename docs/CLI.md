# `apcaw` command-line reference

This document covers the `apcaw` command-line tool of the Rust implementation of the `apcaw-v1` audio watermark (the paper, Appendix A). It describes the conventions every command shares, each command with a real run, the JSON reports, segmented signing, and the `serve --stdio` protocol for other programs. The full `--help` text is reproduced at the end.

Every transcript here is real output of the release build (`apcaw 1.0.0`) on the clips in `tests/media/`. It was captured on 2026-09-28 with `NO_COLOR=1`. `speech.wav` is a copy of `tests/media/0001_librispeech_8555-284447-0010.wav`, and `alice.sec`/`alice.pub` come from `apcaw keygen`. Hex strings longer than a line are shortened with `...` only where noted.

## Contents

1. [Conventions](#conventions)
2. [Exit codes](#exit-codes)
3. [Commands](#commands)
4. [JSON reports](#json-reports)
5. [Segmented signing and `--scan`](#segmented-signing-and---scan)
6. [The `serve --stdio` protocol](#the-serve---stdio-protocol)
7. [Full `--help` output](#full---help-output)

## Conventions

### Input

- `-i PATH` accepts any file ffmpeg can read. WAV is decoded in-process: PCM 8, 16, 24 and 32 bit, float 32 and 64, `WAVE_FORMAT_EXTENSIBLE`, and streamed headers. Every other format is decoded by ffmpeg to float64 WAV on a pipe.
- `-i -` reads standard input.
- The core accepts 44100 Hz mono only, so the CLI converts other input first and prints a note for each conversion on stderr. Nothing is converted silently (format §1):
  - Multichannel input is downmixed to the channel mean. `--channel N` (0-based) selects one channel instead.
  - Other sample rates are resampled to 44100 Hz with ffmpeg's `aresample` filter.

  ```
  $ apcaw sign -y -i st48.wav -o s48.wav -k alice.sec -m resampled
  apcaw: note: downmixed 2 channels to mono (channel mean)
  apcaw: note: resampled 48000 Hz -> 44100 Hz (ffmpeg aresample)
  signed s48.wav: 9-byte message, profile wb, closed-loop verify ok (channel phase, path header)
    input     st48.wav: 10.00 s, 48000 Hz, 2 channels, pcm_s16le (wav)
    payload   840 body bits, layout seed 590993974
    phase     capacity 6240 bits, stream 936 bits, 1 replica(s)
    magnitude capacity 3120 bits, stream 2616 bits, 3 replica(s)
    output    pcm_s16le, 441000 samples, 0 clipped
  ```

- A signed file is always 44100 Hz mono.
- ffmpeg is needed only for non-WAV input, resampling and FLAC output. A pipeline that stays in 44.1 kHz WAV runs without it.
- ffprobe is optional. It is used only for the diagnostics printed at `-v`.
- Point the tool at specific executables with `--ffmpeg PATH` / `APCAW_FFMPEG` and `--ffprobe PATH` / `APCAW_FFPROBE`.

### Output

- `sign -o PATH` writes 16-bit PCM WAV by default: the reference's format, with the canonical 44-byte header.
  - `--codec` selects another encoding: `pcm_s24le`, `f32` (32-bit float, not clipped), or `flac` (16-bit FLAC through ffmpeg).
  - A `.flac` output name selects FLAC automatically.
- Quantization to integer PCM clips to `[-1, 32767/32768]` and rounds half to even. This is exactly what the Python reference does through numpy and libsndfile.
- The signed audio is written to a temporary sibling `.NAME.tmpPID`. It is read back and verified (the closed loop, format §9), and only then renamed into place.
  - If the closed loop fails, the command is interrupted, or an error occurs, nothing is left at the output path.
- `-o -` writes the WAV to standard output. All text then goes to stderr.
- An existing output file is refused with exit code 2 unless `-y` (`--overwrite`, alias `--force`) is given. This is stricter than the Python reference, which overwrites.

### Text and JSON

- Human output is one result line followed by indented detail lines.
  - `-q` prints the result line only.
  - `-v` adds `apcaw: debug:` lines on stderr: what ffprobe reports about the input, how it was decoded, sign timings, and one line per `serve` request.

    ```
    $ apcaw -v verify -i signed.mp3 -p alice.pub
    apcaw: debug: ffprobe signed.mp3: codec_name=mp3|sample_rate=44100|channels=1 format_name=mp3|duration=10.031020
    apcaw: debug: signed.mp3: 44100 Hz, 1 channel(s), mp3 via ffmpeg; 441000 samples at 44100 Hz
    VERIFIED  message='NIPS2026: Authenticity Token for Deepfake Defense'  channel=phase profile=wb path=header rs_corrected=0
    ...
    ```
  - Notes (`apcaw: note: ...`) and errors (`apcaw: ...`) go to stderr.
- `--json` prints one JSON object on stdout instead. It is pretty-printed for single commands and one object per line for `batch-verify` and `serve`.
  - Keys and their order are those of the Python CLI's `--json`.
  - Strings are ASCII-escaped and floats are printed the way Python's `json.dumps` prints them, so the two tools' reports can be compared as text.
- Colour is used only on a terminal. `--no-color`, `NO_COLOR=1` and `TERM=dumb` turn it off.

### Keys

- A secret key file holds a raw 32-byte Ed25519 seed, 64 hex digits, or PKCS#8 PEM.
- A public key file holds 32 raw bytes, 64 hex digits, or SPKI PEM. Surrounding whitespace in hex files is ignored.
- `keygen` writes raw keys, or PEM with `--pem`. The secret key is created with mode 0600.
- A malformed key is a usage error (exit 2). An unreadable key file is an I/O error (exit 3).

### Threads

- `--threads N` sizes the worker pool; the default is all cores.
- The parallel parts are:
  - the forward and inverse STFT, frame by frame;
  - the verifier's candidate decoding (Reed–Solomon and Ed25519) in the protocol length search;
  - the resync offset scan;
  - the files of `batch-verify` (`--jobs`).
- Results, including the verifier's counters, do not depend on the thread count: candidates are generated in parallel but accounted for in the reference's order.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `verify`: VERIFIED. |
| `1` | NOT VERIFIED; signing failed (the input cannot carry the mark, or the closed-loop check failed); `selftest` failed. |
| `2` | Usage error: bad arguments, malformed key, message too long, output exists. |
| `3` | I/O error: unreadable input or key, undecodable audio, ffmpeg missing or failed, write failure. |
| `130` | Interrupted (Ctrl-C). Temporary files are removed. |

Codes 1 and 3 are deliberately separate:

- 1 means the file was read and carries no valid signature under this key. That is an answer.
- 3 means the file could not be read. That is a failure.

`batch-verify` exits with the worst code over its files (3 > 2 > 1 > 0).

```
$ apcaw verify -i nothere.wav -p alice.pub
apcaw: cannot read nothere.wav: no such file
[exit 3]
$ apcaw verify -i signed.wav -p signed.wav
apcaw: signed.wav: malformed public key (882044 bytes; expected raw 32 B, 64 hex, or PEM)
[exit 2]
```

## Commands

### `keygen`

```
$ apcaw keygen --secret-out alice.sec --public-out alice.pub
public key 7fb93b19cb731d6232b8cdf56bcd12498ccf04a35ec6d5eabfd4dbc62c432a93
layout seed 590993974
wrote alice.sec (secret, mode 0600) and alice.pub
```

The layout seed is `SHA-256(public key)[0:8]` read big-endian, modulo 2^32 (format §2). It is public.

### `sign`

`sign` embeds the message, writes the output, reads the written file back through the same decoder `verify` uses, and exits 0 only if the result verifies.

```
$ apcaw sign -i speech.wav -o signed.wav -k alice.sec -m "NIPS2026: Authenticity Token for Deepfake Defense"
signed signed.wav: 49-byte message, profile wb, closed-loop verify ok (channel phase, path header)
  input     speech.wav: 10.00 s, 44100 Hz, mono, pcm_s16le (wav)
  payload   1160 body bits, layout seed 590993974
  phase     capacity 6240 bits, stream 1256 bits, 1 replica(s)
  magnitude capacity 3120 bits, stream 2416 bits, 2 replica(s)
  output    pcm_s16le, 441000 samples, 0 clipped
```

Options:

- `-m TEXT` or `--message-file PATH` gives the message: at most 159 bytes, taken as raw bytes.
- `--profile wb|nb|auto` chooses the profile.
  - `wb` is the default.
  - `nb` targets speech captured in an 8 kHz band.
  - `auto` picks `nb` when less than 5% of the energy lies above 4 kHz, and reports the measured fraction:

    ```
    $ apcaw sign -i speech.wav -o sp.flac -k alice.sec -m flac --profile auto
    signed sp.flac: 4-byte message, profile nb, closed-loop verify ok (channel phase, path header)
      input     speech.wav: 10.00 s, 44100 Hz, mono, pcm_s16le (wav)
      profile   auto -> nb (energy above 4 kHz 0.80% < 5%)
      payload   800 body bits, layout seed 590993974
      phase     capacity 6240 bits, stream 896 bits, 1 replica(s)
      magnitude capacity 1976 bits, stream 1696 bits, 2 replica(s)
      output    flac, 441000 samples, 0 clipped
    ```

- `--legacy` reproduces the legacy configuration: layout seed 42, the phase written to all 8 frames of a group, a zero-filled tail, no silent-bin erasure, and the header-only verifier. Verify such files with `verify --legacy`.
- `--no-closed-loop` skips the read-back check. This is not recommended.
- `--sidecar` also writes the JSON sign report to `OUTPUT.apcaw.json`. The mark is self-contained, and no sidecar is needed to verify.
- `--segment [K]` signs every block of K groups separately; see [Segmented signing](#segmented-signing-and---scan).

`sign` fails with exit 1 when the input cannot carry the stream.

- Both channels must hold one full copy of the stream.
- Under `wb`, a group carries 240 phase bits and 120 magnitude bits.
- A 49-byte message (a 1256-bit stream) therefore needs 11 groups, or 4.09 s:

```
$ apcaw sign -i short4.wav -o short4_s.wav -k alice.sec -m "NIPS2026: Authenticity Token for Deepfake Defense"
apcaw: signing failed: too short: 176400 samples give 10 groups; profile wb needs 1256 bits per channel (phase cap 2400, magnitude cap 1200)
[exit 1]
```

The same message signs a 4.1 s cut.

Piping works in both directions:

```
$ cat speech.wav | apcaw sign -i - -o - -k alice.sec -m piped > st.wav
signed -: 5-byte message, profile wb, closed-loop verify ok (channel phase, path header)
  input     -: 10.00 s, 44100 Hz, mono, pcm_s16le (wav)
  payload   808 body bits, layout seed 590993974
  phase     capacity 6240 bits, stream 904 bits, 1 replica(s)
  magnitude capacity 3120 bits, stream 2520 bits, 3 replica(s)
  output    pcm_s16le, 441000 samples, 0 clipped, standard output
$ apcaw -q verify -i st.wav -p alice.pub
VERIFIED  message='piped'  channel=phase profile=wb path=header rs_corrected=0
```

### `verify`

```
$ apcaw verify -i signed.mp3 -p alice.pub
VERIFIED  message='NIPS2026: Authenticity Token for Deepfake Defense'  channel=phase profile=wb path=header rs_corrected=0
  input     signed.mp3: 10.00 s, 44100 Hz, mono, mp3 (ffmpeg)
  message   49 bytes, hex 4e495053323032363a2041757468656e74696369747920546f6b656e20666f72204465657066616b6520446566656e7365
  payload   1160 body bits
  decoder   1 candidate(s), 1 RS-decoded, 1 signature check(s)
```

The result line matches the Python reference's result line character for character. The message is quoted like Python's `repr`.

How the verifier searches:

- Without `--profile` it tries `wb`, then `nb`. Within each profile it tries the phase channel first, then the magnitude channel.
- For each channel it tries the voted header length first (`path=header`), then every message length from 0 to 159 bytes (`path=search`). The first candidate whose Reed–Solomon decoding, length field and Ed25519 signature all check out wins (format §8).

The two profiles share the phase layout. An `nb`-signed file therefore normally verifies as `profile=wb channel=phase`, in both implementations:

```
$ apcaw -q verify -i sp.flac -p alice.pub
VERIFIED  message='flac'  channel=phase profile=wb path=header rs_corrected=0
$ apcaw -q verify -i sp.flac -p alice.pub --profile nb
VERIFIED  message='flac'  channel=phase profile=nb path=header rs_corrected=0
```

A wrong key, an unsigned file and heavy damage all give NOT VERIFIED with exit 1, and the reason says how far decoding got:

```
$ apcaw verify -i signed.mp3 -p mallory.pub
NOT VERIFIED  no candidate passed RS decoding (460 tried)
  input     signed.mp3: 10.00 s, 44100 Hz, mono, mp3 (ffmpeg)
  decoder   460 candidate(s), 0 RS-decoded, 0 signature check(s)
```

A wrong key usually already fails Reed–Solomon decoding, because the layout is derived from the public key.

Options:

- `--resync` adds the decoder-side offset search of format §8. It tries sample offsets `0..2047` and whole-frame skips `0..10`, and decodes the 8 best-aligned candidates. It finds a mark in audio that was cropped or delayed by an arbitrary number of samples. Its cost is paid only when the plain search fails:
  - 0.4 s on 32 threads (1.5 s on one) for a 10 s file under a wrong key;
  - 25.7 s in the Python reference for a similar case.
- `--legacy` (alias `--legacy-verifier`) is the legacy verifier: header path only, layout seed 42.
- `--scan [K]` verifies a segmented file; see below. It cannot be combined with `--resync`.

### `batch-verify`

`batch-verify` verifies many files concurrently (`--jobs N`, default `--threads`):

- It prints one JSON line per file, in the order given.
- An unreadable file gets its own line with an `error` field and does not stop the batch.
- A summary goes to stderr.

```
$ apcaw batch-verify -p alice.pub signed.wav signed.mp3 speech.wav
{"file": "signed.wav", "verified": true, "message": "NIPS2026: Authenticity Token for Deepfake Defense", "message_hex": "4e49...6e7365", "channel": "phase", "profile": "wb", "path": "header", "rs_corrected": 0, "payload_bits": 1160, "candidates_tried": 1, "rs_passes": 1, "sig_checks": 1, "reason": "ok"}
{"file": "signed.mp3", "verified": true, "message": "NIPS2026: Authenticity Token for Deepfake Defense", "message_hex": "4e49...6e7365", "channel": "phase", "profile": "wb", "path": "header", "rs_corrected": 0, "payload_bits": 1160, "candidates_tried": 1, "rs_passes": 1, "sig_checks": 1, "reason": "ok"}
{"file": "speech.wav", "verified": false, "message": null, "message_hex": null, "channel": null, "profile": null, "path": null, "rs_corrected": null, "payload_bits": null, "candidates_tried": 460, "rs_passes": 63, "sig_checks": 1, "reason": "signature invalid (1 candidate(s) passed RS with a consistent length; none verified under this public key)"}
batch-verify: 2/3 verified
[exit 1]
```

(`message_hex` shortened here.)

The unsigned file shows why the signature check matters. The protocol search hands 460 candidates to the Reed–Solomon decoder. 63 of them decode, because with distance 31 a random word is sometimes within 15 symbols of a codeword. One of those even has a consistent length field. Ed25519 rejects it.

### `inspect`

`inspect` prints capacity, the voted header length and soft-value statistics for both channels under both profiles. These are the reference's lines and JSON.

```
$ apcaw inspect -i signed.wav -p alice.pub
signed.wav: 441000 samples, 215 frames, seed 590993974
  wb phase     capacity  6240  header_length 1160  mean|soft| over 1256 bits 0.9988  erased 0
  wb magnitude capacity  3120  header_length 1160  mean|soft| over 2416 bits 0.9952  erased 0
  nb phase     capacity  6240  header_length 1160  mean|soft| over 1256 bits 0.9988  erased 0
  nb magnitude capacity  1976  header_length 32768  mean|soft| over 1976 bits 0.8212  erased 0
```

The `nb magnitude` row reads the `wb`-signed file with the `nb` pair layout, so its header is noise.

### `layout`

```
$ apcaw layout -p alice.pub --profile nb
seed 590993974
  nb Kp[:8] [241, 254, 150, 260, 239, 99, 261, 126]  pairs[:4] [[126, 127], [112, 113], [108, 109], [32, 33]]
```

- `--seed N` prints the layout of a raw seed (for example `--seed 42` for legacy).
- `--json` prints the full `phase_bins` and `mag_pairs` arrays.

### `selftest`

`selftest` runs checks against vectors compiled into the binary:

- the reference's eleven checks, from the same `selftest.json` that the Python reference bundles;
- the signed conformance clips, byte for byte against their MANIFEST sha256;
- the MP3-transcoded vector;
- the negative controls.

```
$ apcaw selftest
PASS  keygen
PASS  seed_from_pk
PASS  mt19937  (5 seeds)
PASS  signal
PASS  layout  (10 seed/profile pairs)
PASS  payload  (4 messages)
PASS  stream
PASS  reed-solomon  (15 corrupted codewords)
PASS  sign  (max abs diff 2.5e-16 (tol 1e-09))
PASS  verify
PASS  verify-wrong-key
PASS  clip_A sign v1  (sha256 5f066cb38a79026d, clip_A_signed_v1.wav)
PASS  clip_A sign legacy  (sha256 9e8945bcb40e6ac2, clip_A_signed_legacy.wav)
PASS  clip_A verify after mp3  (channel phase, rs_corrected 2)
PASS  negatives  (2 cases, verifier counters)
selftest passed
```

### `bench`

`bench` times in-process `sign` and `verify` of one file (no file I/O, no closed loop). It reports the mean of `--repeat` runs after a warm-up, in a 1-thread pool and in a `--threads` pool:

```
$ apcaw bench -i tests/media/0000_librispeech_5639-40744-0030.wav --repeat 50
bench tests/media/0000_librispeech_5639-40744-0030.wav: 10.00 s of audio, profile wb, mean of 50 run(s) after a warm-up
  input     tests/media/0000_librispeech_5639-40744-0030.wav: 10.00 s, 44100 Hz, mono, pcm_s16le (wav)
  threads 1   sign    1.54 ms  verify    0.80 ms  total    2.34 ms  (4275x real time)
              sign median 1.46 min 1.41, verify median 0.75 min 0.73
  threads 32  sign    1.94 ms  verify    0.91 ms  total    2.85 ms  (3513x real time)
              sign median 1.88 min 1.52, verify median 0.88 min 0.70
```

## JSON reports

### `verify --json`

`verify --json` uses the keys of the Python CLI, in the same order. `batch-verify` lines, the `serve` verify result, and the C function `apcaw_verify_f64` (without `file`) use the same keys.

| Key | Type | Meaning |
| --- | --- | --- |
| `file` | string | The input path as given. |
| `verified` | bool | An Ed25519 signature under this public key was found. |
| `message` | string or null | The signed message, decoded as UTF-8 (invalid sequences replaced). |
| `message_hex` | string or null | The exact message bytes. |
| `channel` | `"phase"`, `"magnitude"` or null | Channel of the accepted candidate. |
| `profile` | `"wb"`, `"nb"` or null | Profile under which it decoded. |
| `path` | `"header"`, `"search"`, `"resync"` or null | Voted header length, protocol length search, or offset search. |
| `rs_corrected` | int or null | Reed–Solomon symbols corrected. |
| `payload_bits` | int or null | Body length in bits, `8 * (len(message) + 96)`. |
| `candidates_tried` | int | Distinct candidate codewords handed to the RS decoder. |
| `rs_passes` | int | Of those, how many decoded. |
| `sig_checks` | int | Of those, how many had a consistent length field, so Ed25519 ran. |
| `reason` | string | `"ok"` or why verification failed. |

The rejection reasons are, in order of how far decoding got:

- `too short: ...`
- `no candidate passed RS decoding (N tried)`
- `length field inconsistent (N RS-decodable candidate(s))`
- `signature invalid (N candidate(s) passed RS with a consistent length; none verified under this public key)`

### `sign --json`

```
$ apcaw --json sign -i speech.wav -o j.wav -k alice.sec -m json
{
  "signed": true,
  "file": "j.wav",
  "input": "speech.wav",
  "message_len": 4,
  "message_hex": "6a736f6e",
  "profile": "wb",
  "profile_auto": null,
  "legacy": false,
  "codec": "pcm_s16le",
  "clipped": 0,
  "closed_loop": {
    "verified": true,
    "channel": "phase",
    "path": "header",
    "profile": "wb",
    "rs_corrected": 1
  },
  "segment": null,
  "sign": {
    "profile": "wb",
    "seed": 590993974,
    "message_len": 4,
    "body_bits": 800,
    "frames": 215,
    "groups": 26,
    "phase_capacity": 6240,
    "phase_stream": 896,
    "phase_replicas": 1,
    "mag_capacity": 3120,
    "mag_stream": 2496,
    "mag_replicas": 3
  }
}
```

The fields in detail:

- `profile_auto` is `{"hf_fraction": ..., "chosen": ...}` under `--profile auto`.
- `closed_loop` is null with `--no-closed-loop`.
- `clipped` counts samples outside `[-1, 32767/32768]` before quantization.
- `segment` describes the blocks under `--segment`.

The Python CLI's `sign` has no `--json`, so this report is specific to the Rust tool. It is also the content of the `--sidecar` file.

## Segmented signing and `--scan`

`--segment [K]` embeds the complete stream independently in every block of K groups, where a group is 8 frames, or 16384 samples (format §10). The default K = 26 groups is 9.66 s. Each block verifies on its own, so a clip cut out of a long recording still carries the mark if it contains one whole block.

`verify --scan [K]` applies the verifier to group-aligned windows of K groups and reports every block that verifies. Segmented mode is an extension of the Rust tool (the format marks it optional). The Python reference and the paper's experiments use the unsegmented mode.

```
$ apcaw sign -i long.wav -o long_signed.wav -k alice.sec -m "segmented demo" --segment
signed long_signed.wav: 14-byte message, profile wb, 3 segment(s) of 26 groups, closed-loop verify ok
  input     long.wav: 30.00 s, 44100 Hz, mono, pcm_s16le (wav)
  payload   880 body bits, layout seed 590993974
  phase     capacity 6240 bits, stream 976 bits, 1 replica(s) per segment
  magnitude capacity 3120 bits, stream 2736 bits, 3 replica(s) per segment
  segments  3 of 4 block(s) signed (a trailing partial block is left unsigned)
  output    pcm_s16le, 1323000 samples, 0 clipped
$ ffmpeg -hide_banner -loglevel error -i long_signed.wav -c:a libmp3lame -b:a 128k long_signed_full.mp3
$ apcaw verify -i long_signed_full.mp3 -p alice.pub --scan
VERIFIED  3 block(s) of 26 groups
  input     long_signed_full.mp3: 30.00 s, 44100 Hz, mono, mp3 (ffmpeg)
  block     groups 0..26 (0.00-9.66 s): VERIFIED  message='segmented demo'  channel=phase profile=wb path=header rs_corrected=14
  block     groups 26..52 (9.66-19.32 s): VERIFIED  message='segmented demo'  channel=phase profile=wb path=header rs_corrected=3
  block     groups 52..78 (19.32-28.98 s): VERIFIED  message='segmented demo'  channel=phase profile=wb path=header rs_corrected=4
  scan      4 window(s) of 26 groups over 80 groups
$ ffmpeg -hide_banner -loglevel error -i long_signed.wav -af atrim=start_sample=425984 cut26.wav
$ apcaw verify -i cut26.wav -p alice.pub --scan
VERIFIED  2 block(s) of 26 groups
  input     cut26.wav: 20.34 s, 44100 Hz, mono, pcm_s16le (wav)
  block     groups 0..26 (0.00-9.66 s): VERIFIED  message='segmented demo'  channel=phase profile=wb path=header rs_corrected=0
  block     groups 26..52 (9.66-19.32 s): VERIFIED  message='segmented demo'  channel=phase profile=wb path=header rs_corrected=0
  scan      3 window(s) of 26 groups over 54 groups
```

Here `long.wav` is the three test clips concatenated, and `cut26.wav` drops the first block (26 × 16384 = 425984 samples).

**Alignment.**

- The scan windows start at multiples of 16384 samples from the first sample of the input. The scan does not search sample offsets.
- A cut at a group boundary keeps every later block on the grid, as above. A cut anywhere else moves every block off it:

  ```
  $ ffmpeg -hide_banner -loglevel error -ss 7.3 -i long_signed.wav -c:a libmp3lame -b:a 128k long_signed.mp3
  $ apcaw verify -i long_signed.mp3 -p alice.pub --scan
  NOT VERIFIED  no window of 26 groups verified (37 tried)
    input     long_signed.mp3: 22.70 s, 44100 Hz, mono, mp3 (ffmpeg)
    scan      37 window(s) of 26 groups over 61 groups
  [exit 1]
  ```

- Combining `--scan` with `--resync` is refused as a usage error. For arbitrarily cropped audio, cut out a window of at least K groups and run `verify --resync` on it.

**Plain verify.** Plain `verify` of a segmented file reads the first block, because its layout indices restart at sample 0.

**JSON.** With `--json`, a scan prints `{file, verified, segment_groups, groups, windows_tried, blocks: [{start_group, groups, start_sample, end_sample, start_seconds, report}]}`, where each `report` is a verify report without `file`.

## The `serve --stdio` protocol

`apcaw serve --stdio` is a long-running process for programs that want to call the tool without starting a process per file, or without linking the C ABI. It reads one JSON request per line on stdin and writes one JSON reply per line on stdout.

### Framing

- **Encoding.** UTF-8 JSON, one object per line, terminated by `\n`. Blank lines are skipped.
- **Order.** Replies come in request order. Requests are handled one at a time, and each reply is flushed before the next line is read.
- **Shutdown.** The server exits with code 0 on end of input or after replying to `{"op": "shutdown"}`. Lines after a shutdown are not read.
- **Global options.** The options given before `serve` apply to every request: `--threads`, `--ffmpeg`, `--ffprobe`, and `-y`, which allows overwriting for all requests.
- **Stderr.** Diagnostics at `-v` go to stderr. Nothing else is written there.
- **Revision.** The protocol revision is `1`, reported by the `version` op.

### Requests and replies

```
request:  {"id": <any JSON value>, "op": "<name>", <fields>...}
success:  {"id": <same>, "ok": true,  "result": {...}}
failure:  {"id": <same>, "ok": false, "error": {"code": 1|2|3, "message": "..."}}
```

- `id` is echoed unchanged. It is optional and null when absent.
- The error `code` is the exit code the equivalent command would have returned:
  - `1`: signing failed, including the closed-loop check;
  - `2`: usage error — unknown op, missing or mistyped field, malformed key, message too long, output exists;
  - `3`: I/O error.
- A line that is not valid JSON, or not a JSON object, gets a code-2 error with `"id": null`.
- An internal error (a panic) in an op is caught and reported as code 1, `internal error in "<op>"`. The server keeps running.
- **NOT VERIFIED is a result, not an error.** A verify of an unsigned file replies `"ok": true` with `"verified": false`.

Field rules:

- A field whose value is `null` counts as absent.
- The short aliases `path` (for `input`), `pk` (for `public_key`) and `sk` (for `secret_key`) are accepted, so `{"op": "verify", "path": "a.wav", "pk": "<64 hex>"}` works.
- Paths are relative to the server's working directory.
- `"-"` is rejected for `input` and `output`, because stdin and stdout carry the protocol.
- Keys are given in one of two forms, not both:
  - inline as text in `public_key` / `secret_key` (64 hex digits or PEM);
  - as a path in `public_key_file` / `secret_key_file` (raw, hex or PEM).
- Boolean fields default to false.

### Operations

| op | Fields (required in bold) | Result |
| --- | --- | --- |
| `version` | none | `{name, version, format, protocol}` |
| `keygen` | **`secret_out`**, **`public_out`**, `pem`, `overwrite` | `{public_key, layout_seed, secret_out, public_out, format}` |
| `sign` | **`input`**, **`output`**, **`secret_key`** or **`secret_key_file`**, **`message`** (UTF-8) or **`message_hex`**, `profile` (`wb`/`nb`/`auto`), `legacy`, `segment` (K ≥ 1), `no_closed_loop`, `sidecar`, `codec` (`pcm_s16le`/`pcm_s24le`/`f32`/`flac`), `channel`, `overwrite` | the `sign --json` report plus `notes` |
| `verify` | **`input`**, **`public_key`** or **`public_key_file`**, `profile` (`wb`/`nb`/`auto`), `legacy`, `resync`, `scan` (K ≥ 1), `channel` | the `verify --json` report (or the scan report) plus `notes` |
| `inspect` | **`input`**, **`public_key`** or **`public_key_file`**, `legacy`, `channel` | the `inspect --json` report plus `notes` |
| `layout` | **`public_key`**, **`public_key_file`** or **`seed`**, `profile` | `{seed, wb: {phase_bins, mag_pairs}, nb: {...}}` (only the requested profile with `profile`) |
| `selftest` | none | `{passed, checks: [{name, passed, detail}]}` (a failed check is `"passed": false`, not an error) |
| `shutdown` | none | `{}`, then the server exits |

- `notes` lists the input conversions (downmix, resampling) that the CLI would print as notes.
- `segment` and `scan` take the block length K explicitly. There is no implicit default in the protocol.

### Example session

`requests.jsonl` (`$PK` expanded to alice's public key in hex):

```
{"id": 1, "op": "version"}
{"id": 2, "op": "verify", "path": "signed.wav", "pk": "$PK"}
{"id": 3, "op": "sign", "input": "speech.wav", "output": "out.wav", "secret_key_file": "alice.sec", "message": "hello from serve"}
{"id": 4, "op": "verify", "input": "out.wav", "public_key_file": "alice.pub", "profile": "wb"}
{"id": 5, "op": "verify", "input": "speech.wav", "public_key_file": "alice.pub"}
{"id": 6, "op": "sign", "input": "speech.wav", "output": "out.wav", "secret_key_file": "alice.sec", "message": "again"}
{"id": 7, "op": "verify", "input": "missing.wav", "public_key_file": "alice.pub"}
{"id": 8, "op": "frobnicate"}
not json

{"id": 9, "op": "shutdown"}
{"id": 10, "op": "version"}
```

`apcaw serve --stdio < requests.jsonl` wrote the following and exited 0, with nothing on stderr. Request 10 was never read.

```
{"id": 1, "ok": true, "result": {"name": "apcaw", "version": "1.0.0", "format": "apcaw-v1", "protocol": 1}}
{"id": 2, "ok": true, "result": {"file": "signed.wav", "verified": true, "message": "NIPS2026: Authenticity Token for Deepfake Defense", "message_hex": "4e495053323032363a2041757468656e74696369747920546f6b656e20666f72204465657066616b6520446566656e7365", "channel": "phase", "profile": "wb", "path": "header", "rs_corrected": 0, "payload_bits": 1160, "candidates_tried": 1, "rs_passes": 1, "sig_checks": 1, "reason": "ok", "notes": []}}
{"id": 3, "ok": true, "result": {"signed": true, "file": "out.wav", "input": "speech.wav", "message_len": 16, "message_hex": "68656c6c6f2066726f6d207365727665", "profile": "wb", "profile_auto": null, "legacy": false, "codec": "pcm_s16le", "clipped": 0, "closed_loop": {"verified": true, "channel": "phase", "path": "header", "profile": "wb", "rs_corrected": 0}, "segment": null, "sign": {"profile": "wb", "seed": 590993974, "message_len": 16, "body_bits": 896, "frames": 215, "groups": 26, "phase_capacity": 6240, "phase_stream": 992, "phase_replicas": 1, "mag_capacity": 3120, "mag_stream": 2784, "mag_replicas": 3}, "notes": []}}
{"id": 4, "ok": true, "result": {"file": "out.wav", "verified": true, "message": "hello from serve", "message_hex": "68656c6c6f2066726f6d207365727665", "channel": "phase", "profile": "wb", "path": "header", "rs_corrected": 0, "payload_bits": 896, "candidates_tried": 1, "rs_passes": 1, "sig_checks": 1, "reason": "ok", "notes": []}}
{"id": 5, "ok": true, "result": {"file": "speech.wav", "verified": false, "message": null, "message_hex": null, "channel": null, "profile": null, "path": null, "rs_corrected": null, "payload_bits": null, "candidates_tried": 460, "rs_passes": 63, "sig_checks": 1, "reason": "signature invalid (1 candidate(s) passed RS with a consistent length; none verified under this public key)", "notes": []}}
{"id": 6, "ok": false, "error": {"code": 2, "message": "out.wav exists (use -y to overwrite)"}}
{"id": 7, "ok": false, "error": {"code": 3, "message": "cannot read missing.wav: no such file"}}
{"id": 8, "ok": false, "error": {"code": 2, "message": "unknown op \"frobnicate\""}}
{"id": null, "ok": false, "error": {"code": 2, "message": "invalid JSON: expected ident at line 1 column 2"}}
{"id": 9, "ok": true, "result": {}}
```

More replies from a second session, showing the field rules:

```
{"id": "a", "op": "keygen", "secret_out": "k2.sec", "public_out": "k2.pub"}
{"id": "a", "ok": true, "result": {"public_key": "260f11523ddaea7f757e6375ec866b85815cc6a7cc9602bdd4dff7b87bfe53fb", "layout_seed": 3938962251, "secret_out": "k2.sec", "public_out": "k2.pub", "format": "raw"}}

{"id": "d", "op": "verify", "input": "-", "pk": "$PK"}
{"id": "d", "ok": false, "error": {"code": 2, "message": "\"input\": standard input carries the requests; give a file"}}

{"id": "e", "op": "verify", "input": "signed.wav", "public_key": "$PK", "public_key_file": "alice.pub"}
{"id": "e", "ok": false, "error": {"code": 2, "message": "give \"public_key\" or \"public_key_file\", not both"}}

[1, 2]
{"id": null, "ok": false, "error": {"code": 2, "message": "a request must be a JSON object"}}
```

A minimal client in Python:

```python
import json, subprocess
p = subprocess.Popen(["apcaw", "serve", "--stdio"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, text=True)
def call(**req):
    p.stdin.write(json.dumps(req) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())
print(call(id=1, op="verify", path="signed.wav", pk=open("alice.pub", "rb").read().hex()))
call(op="shutdown")
```

## Full `--help` output

These are the real help texts of `apcaw 1.0.0`, captured with `NO_COLOR=1 COLUMNS=100`. The `Global options` block is the same for every subcommand, so it is shown once, under `apcaw --help`.

### `apcaw --help`

```text
ffmpeg-style command-line tool for Asymmetric Phase Coding Audio Watermarking (apcaw-v1)

Usage: apcaw [OPTIONS] <COMMAND>

Commands:
  keygen        Generate an Ed25519 key pair
  sign          Embed a signed message (closed loop: the written file must verify)
  verify        Verify a file against a public key
  batch-verify  Verify many files, one JSON object per line (NDJSON) on stdout
  inspect       Capacity, header lengths and soft-value statistics
  layout        Print the key-derived layout
  selftest      Check this build against the embedded reference vectors
  bench         Time sign and verify on a file (1 thread and N threads)
  serve         JSON-lines server on stdin/stdout (protocol in docs/CLI.md)
  help          Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

Global options:
  -v, --verbose...      More detail on stderr (repeatable)
  -q, --quiet           Only the result line: no notes, no details
      --json            Machine-readable output (the keys of the Python CLI's --json)
      --threads <N>     Worker threads [default: all cores]
      --no-color        No ANSI colours (also NO_COLOR=1, TERM=dumb, or when not a terminal)
      --ffmpeg <PATH>   ffmpeg executable [env: APCAW_FFMPEG=] [default: ffmpeg]
      --ffprobe <PATH>  ffprobe executable (optional; input diagnostics at -v) [env: APCAW_FFPROBE=]
                        [default: ffprobe]
  -y, --overwrite       Overwrite existing output files [aliases: --force]

Exit codes:
  0    success; VERIFIED
  1    NOT VERIFIED; signing failed (incl. the closed-loop check); selftest failed
  2    usage error: bad arguments, malformed key, message too long, output exists
  3    I/O error: unreadable input or key, undecodable audio, ffmpeg failure, write failure
  130  interrupted (temporary files are removed)

Input is any file ffmpeg reads (WAV is decoded in-process); `-i -` reads standard input.
Non-44.1 kHz input is resampled and multichannel input downmixed, each with a note.
```

### `apcaw keygen --help`

```text
Generate an Ed25519 key pair

Usage: apcaw keygen [OPTIONS] --secret-out <PATH> --public-out <PATH>

Options:
      --secret-out <PATH>  Secret key output (mode 0600)
      --public-out <PATH>  Public key output
      --pem                PKCS#8 / SPKI PEM instead of raw 32 bytes
  -h, --help               Print help
```

### `apcaw sign --help`

```text
Embed a signed message (closed loop: the written file must verify)

Usage: apcaw sign [OPTIONS] --input <PATH> --output <PATH> --key <PATH> <--message <TEXT>|--message-file <PATH>>

Options:
  -i, --input <PATH>
          Input audio (`-` for stdin)

  -o, --output <PATH>
          Output file (`-` for WAV on stdout)

  -k, --key <PATH>
          Secret key (raw 32 B, 64 hex digits, or PEM)

  -m, --message <TEXT>
          Message (UTF-8, at most 159 bytes)

      --message-file <PATH>
          Read the message bytes from a file

      --profile <PROFILE>
          Profile

          Possible values:
          - wb:   Wide band: phase bins 60..300, magnitude bins 100..340
          - nb:   Narrow band (8 kHz-band speech): magnitude bins 16..168
          - auto: nb when less than 5% of the energy lies above 4 kHz, else wb
          
          [default: wb]

      --legacy
          Legacy configuration (layout seed 42, 8-frame phase write, zeroed tail, no erasure)

      --segment [<K>]
          Sign each block of K groups separately (Rust extension; verify with --scan) [K: 26]

      --no-closed-loop
          Do not re-read and verify the written file

      --sidecar
          Also write the sign report as JSON to OUTPUT.apcaw.json

      --codec <CODEC>
          Output encoding [default: pcm_s16le, flac for *.flac]

          Possible values:
          - pcm_s16le: 16-bit PCM WAV (default; what the reference writes)
          - pcm_s24le: 24-bit PCM WAV
          - f32:       32-bit float WAV (not clipped)
          - flac:      16-bit FLAC (lossless, through ffmpeg)

      --channel <N>
          Use channel N (0-based) instead of the channel mean

  -h, --help
          Print help (see a summary with '-h')
```

### `apcaw verify --help`

```text
Verify a file against a public key

Usage: apcaw verify [OPTIONS] --input <PATH> --public-key <PATH>

Options:
  -i, --input <PATH>
          Input audio (`-` for stdin)

  -p, --public-key <PATH>
          Public key (raw 32 B, 64 hex digits, or PEM)

      --profile <PROFILE>
          Profile [default: wb, then nb]

          Possible values:
          - wb:   Wide band only
          - nb:   Narrow band only
          - auto: wb, then nb (the default)

      --resync
          Also search sample / frame offsets (cropped or shifted audio)

      --scan [<K>]
          Verify every group-aligned window of K groups (segmented signing; a group is 16384
          samples) [K: 26]

      --legacy
          Legacy verifier (header only, layout seed 42)
          
          [aliases: --legacy-verifier]

      --channel <N>
          Use channel N (0-based) instead of the channel mean

  -h, --help
          Print help (see a summary with '-h')
```

### `apcaw batch-verify --help`

```text
Verify many files, one JSON object per line (NDJSON) on stdout

Usage: apcaw batch-verify [OPTIONS] --public-key <PATH> <FILES>...

Arguments:
  <FILES>...
          Input files

Options:
  -p, --public-key <PATH>
          Public key (raw 32 B, 64 hex digits, or PEM)

  -j, --jobs <N>
          Files verified concurrently [default: --threads]

      --profile <PROFILE>
          Profile [default: wb, then nb]

          Possible values:
          - wb:   Wide band only
          - nb:   Narrow band only
          - auto: wb, then nb (the default)

      --resync
          Also search sample / frame offsets

      --legacy
          Legacy verifier (header only, layout seed 42)
          
          [aliases: --legacy-verifier]

      --channel <N>
          Use channel N (0-based) instead of the channel mean

  -h, --help
          Print help (see a summary with '-h')
```

### `apcaw inspect --help`

```text
Capacity, header lengths and soft-value statistics

Usage: apcaw inspect [OPTIONS] --input <PATH> --public-key <PATH>

Options:
  -i, --input <PATH>       Input audio (`-` for stdin)
  -p, --public-key <PATH>  Public key (raw 32 B, 64 hex digits, or PEM)
      --legacy             Legacy configuration (layout seed 42, no silent-bin erasure)
      --channel <N>        Use channel N (0-based) instead of the channel mean
  -h, --help               Print help
```

### `apcaw layout --help`

```text
Print the key-derived layout

Usage: apcaw layout [OPTIONS] <--public-key <PATH>|--seed <SEED>>

Options:
  -p, --public-key <PATH>
          Public key (raw 32 B, 64 hex digits, or PEM)

      --seed <SEED>
          Layout seed instead of a key

      --profile <PROFILE>
          Only this profile

          Possible values:
          - wb:   Wide band only
          - nb:   Narrow band only
          - auto: wb, then nb (the default)

  -h, --help
          Print help (see a summary with '-h')
```

### `apcaw selftest --help`

```text
Check this build against the embedded reference vectors

Usage: apcaw selftest [OPTIONS]

Options:
  -h, --help  Print help
```

### `apcaw bench --help`

```text
Time sign and verify on a file (1 thread and N threads)

Usage: apcaw bench [OPTIONS] --input <PATH>

Options:
  -i, --input <PATH>
          Input audio (`-` for stdin)

  -k, --key <PATH>
          Secret key [default: a fixed test key]

  -m, --message <TEXT>
          Message
          
          [default: "NIPS2026: Authenticity Token for Deepfake Defense"]

      --repeat <N>
          Timed runs per measurement (after one warm-up)
          
          [default: 10]

      --profile <PROFILE>
          Profile

          Possible values:
          - wb:   Wide band: phase bins 60..300, magnitude bins 100..340
          - nb:   Narrow band (8 kHz-band speech): magnitude bins 16..168
          - auto: nb when less than 5% of the energy lies above 4 kHz, else wb
          
          [default: wb]

      --legacy
          Legacy configuration

      --channel <N>
          Use channel N (0-based) instead of the channel mean

  -h, --help
          Print help (see a summary with '-h')
```

### `apcaw serve --help`

```text
JSON-lines server on stdin/stdout (protocol in docs/CLI.md)

Usage: apcaw serve [OPTIONS] --stdio

Options:
      --stdio  Serve JSON lines on stdin/stdout (the only transport)
  -h, --help   Print help
```
