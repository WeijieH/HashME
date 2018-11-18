#pragma once
#include "Common.h"
#include "Formats.h"

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define FF(a, b, c, d, x, s)           \
    {                                  \
        (a) += F((b), (c), (d)) + (x); \
        (a) = ROTL32((a), (s));        \
    }
#define GG(a, b, c, d, x, s)                                  \
    {                                                         \
        (a) += G((b), (c), (d)) + (x) + (uint32_t)0x5a827999; \
        (a) = ROTL32((a), (s));                               \
    }
#define HH(a, b, c, d, x, s)                                  \
    {                                                         \
        (a) += H((b), (c), (d)) + (x) + (uint32_t)0x6ed9eba1; \
        (a) = ROTL32((a), (s));                               \
    }

extern unsigned char* md4_MemBlock(const unsigned char* buf, size_t size, HASH_ctx* ctx);

extern void md4_final_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize);
extern void md4_update_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize);
extern void md4_init_file(HASH_ctx* ctx, uint64_t filesize);
