/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * apcaw C ABI example.
 *
 *   verify                 key generation, signing and verification round trip on noise
 *   verify FILE.wav PK_HEX verify a 16-bit PCM mono 44.1 kHz WAV against a hex public key
 *
 * Exit status: 0 verified / round trip ok, 1 not verified, 2 usage, 3 I/O.
 *
 *   cc -O2 -Iinclude examples/c/verify.c target/release/libapcaw.a -lpthread -ldl -lm -o verify
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apcaw.h"

static int verified(const char *json) { return json && strstr(json, "\"verified\":true") != NULL; }

static int round_trip(void) {
    uint8_t sk[32], pk[32], pk2[32], sk2[32];
    const char *msg = "hello from C";
    size_t n = 441000; /* 10 s */
    double *x = malloc(n * sizeof *x), *y = malloc(n * sizeof *y);
    uint32_t s = 1;
    int ok;
    char *r;

    if (!x || !y) return 3;
    if (apcaw_keygen(sk, pk) != 0 || apcaw_keygen(sk2, pk2) != 0) {
        fprintf(stderr, "keygen: %s\n", apcaw_last_error());
        return 3;
    }
    for (size_t i = 0; i < n; i++) { /* white noise at -20 dBFS */
        s = s * 1664525u + 1013904223u;
        x[i] = ((double)s / 4294967296.0 - 0.5) * 0.2;
    }
    if (apcaw_sign_f64(x, n, 44100, sk, (const uint8_t *)msg, strlen(msg), "wb", 0, y) != 0) {
        fprintf(stderr, "sign: %s\n", apcaw_last_error());
        return 1;
    }
    r = apcaw_verify_f64(y, n, 44100, pk, NULL, 0, 0);
    printf("apcaw %s\nright key: %s\n", apcaw_version(), r ? r : apcaw_last_error());
    ok = verified(r) && strstr(r, "\"message\":\"hello from C\"") != NULL;
    apcaw_string_free(r);
    r = apcaw_verify_f64(y, n, 44100, pk2, NULL, 0, 0);
    printf("wrong key: %s\n", r ? r : apcaw_last_error());
    ok = ok && r && !verified(r);
    apcaw_string_free(r);
    r = apcaw_verify_f64(y, n, 48000, pk, NULL, 0, 0);
    printf("48 kHz:    %s\n", r ? r : apcaw_last_error());
    ok = ok && r && !verified(r);
    apcaw_string_free(r);
    free(x);
    free(y);
    printf("round trip %s\n", ok ? "ok" : "FAILED");
    return ok ? 0 : 1;
}

static uint32_t u32le(const unsigned char *b) { return b[0] | b[1] << 8 | b[2] << 16 | (uint32_t)b[3] << 24; }

/* Minimal RIFF reader: 16-bit PCM, mono, 44100 Hz. */
static double *read_pcm16(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long len;
    size_t pos = 12;
    int fmt_ok = 0;

    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    b = malloc(len > 0 ? (size_t)len : 1);
    if (!b || len < 12 || fread(b, 1, (size_t)len, f) != (size_t)len || memcmp(b, "RIFF", 4) || memcmp(b + 8, "WAVE", 4)) {
        fclose(f);
        free(b);
        return NULL;
    }
    fclose(f);
    while (pos + 8 <= (size_t)len) {
        uint32_t size = u32le(b + pos + 4);
        const unsigned char *body = b + pos + 8;
        if (!memcmp(b + pos, "fmt ", 4) && size >= 16)
            fmt_ok = body[0] == 1 && body[2] == 1 && u32le(body + 4) == 44100 && body[14] == 16;
        if (!memcmp(b + pos, "data", 4) && fmt_ok) {
            size_t avail = (size_t)len - pos - 8, m = (size > avail ? avail : size) / 2;
            double *x = malloc((m ? m : 1) * sizeof *x);
            for (size_t i = 0; x && i < m; i++) x[i] = (int16_t)(body[2 * i] | body[2 * i + 1] << 8) / 32768.0;
            *n = m;
            free(b);
            return x;
        }
        pos += 8 + size + (size & 1);
    }
    free(b);
    return NULL;
}

int main(int argc, char **argv) {
    uint8_t pk[32];
    size_t n = 0;
    double *x;
    char *r;
    int ok;

    if (argc == 1) return round_trip();
    if (argc != 3 || strlen(argv[2]) != 64) {
        fprintf(stderr, "usage: %s [FILE.wav PUBLIC_KEY_HEX]\n", argv[0]);
        return 2;
    }
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(argv[2] + 2 * i, "%2x", &v) != 1) {
            fprintf(stderr, "bad public key hex\n");
            return 2;
        }
        pk[i] = (uint8_t)v;
    }
    x = read_pcm16(argv[1], &n);
    if (!x) {
        fprintf(stderr, "cannot read %s (16-bit PCM mono 44.1 kHz WAV expected)\n", argv[1]);
        return 3;
    }
    r = apcaw_verify_f64(x, n, 44100, pk, NULL, 0, 0);
    free(x);
    if (!r) {
        fprintf(stderr, "verify: %s\n", apcaw_last_error());
        return 2;
    }
    printf("%s\n", r);
    ok = verified(r);
    apcaw_string_free(r);
    return ok ? 0 : 1;
}
