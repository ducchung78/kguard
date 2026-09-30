/*
 * sha256.h — Minimal SHA-256 implementation (no OpenSSL dependency)
 */
#ifndef KGUARD_SHA256_H
#define KGUARD_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LENGTH 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_LENGTH]);

/* Convenience: hash a single buffer */
void sha256_hash(const void *data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]);

/* Format digest as hex string (buf must be >= 65 bytes) */
void sha256_hex(const uint8_t digest[SHA256_DIGEST_LENGTH], char *buf);

#endif /* KGUARD_SHA256_H */
