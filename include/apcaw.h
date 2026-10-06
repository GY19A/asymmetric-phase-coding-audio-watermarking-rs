/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * apcaw -- C ABI of the Rust implementation of the apcaw-v1 audio watermark.
 *
 * Link against libapcaw.a (plus -lpthread -ldl -lm on Linux) or libapcaw.so.
 *
 * Conventions
 *   - Keys are raw 32-byte buffers (Ed25519 secret seed / public key).
 *   - Samples are mono double at 44100 Hz; other rates are rejected.
 *   - int results: 0 success, 1 signing failed for a reason tied to the input
 *     (too short, message too long, ...), -1 invalid arguments, -2 internal
 *     error. apcaw_last_error() then describes the failure (per thread).
 *   - Strings returned by the library are released with apcaw_string_free();
 *     apcaw_version() and apcaw_last_error() are not freed by the caller.
 */
#ifndef APCAW_H
#define APCAW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Library version, e.g. "1.0.0". */
const char *apcaw_version(void);

/* Message of the last failure on the calling thread ("" if none). Valid until
 * the next failing call on the same thread. */
const char *apcaw_last_error(void);

/* New key pair from the OS random number generator. */
int apcaw_keygen(uint8_t sk_out[32], uint8_t pk_out[32]);

/* Public key of a 32-byte secret seed. */
int apcaw_public_key(const uint8_t sk[32], uint8_t pk_out[32]);

/* Sign n samples at rate sr with msg[0..msg_len) (at most 159 bytes) and
 * write n watermarked samples to out (out may equal samples). profile is
 * "wb", "nb" or NULL (wb). legacy != 0 selects the legacy configuration.
 * The caller quantizes (format: clip to [-1, 32767/32768], round half to even)
 * and should verify the written file (closed loop). */
int apcaw_sign_f64(const double *samples, size_t n, uint32_t sr, const uint8_t sk[32],
                   const uint8_t *msg, size_t msg_len, const char *profile, int legacy,
                   double *out);

/* Verify n samples at rate sr against pk. profile NULL (or "auto") tries wb
 * then nb; legacy != 0 uses the legacy verifier and seed 42; resync != 0
 * adds the offset search. Returns a JSON object with the keys of
 * `apcaw verify --json` except "file":
 *   {"verified":true,"message":"...","message_hex":"...","channel":"phase",
 *    "profile":"wb","path":"header","rs_corrected":0,"payload_bits":1160,
 *    "candidates_tried":1,"rs_passes":1,"sig_checks":1,"reason":"ok"}
 * A wrong rate is a rejection ("verified":false with the reason). Returns NULL
 * only on invalid arguments. Free the result with apcaw_string_free(). */
char *apcaw_verify_f64(const double *samples, size_t n, uint32_t sr, const uint8_t pk[32],
                       const char *profile, int legacy, int resync);

/* Release a string returned by apcaw_verify_f64 (NULL is ignored). */
void apcaw_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* APCAW_H */
