#include "MD4.h"

void md4_init(HASH_ctx* ctx)
{
    ctx->length_ = 0;
    ctx->unprocessed_ = 0;

    /* initialize state */
    ctx->MD4_hash_[0] = 0x67452301;
    ctx->MD4_hash_[1] = 0xefcdab89;
    ctx->MD4_hash_[2] = 0x98badcfe;
    ctx->MD4_hash_[3] = 0x10325476;
}

void md4_init_file(HASH_ctx* ctx, uint64_t filesize)
{
    ctx->MD4_unprocessed_ = filesize;

    /* initialize state */
    ctx->MD4_hash_[0] = 0x67452301;
    ctx->MD4_hash_[1] = 0xefcdab89;
    ctx->MD4_hash_[2] = 0x98badcfe;
    ctx->MD4_hash_[3] = 0x10325476;
}

void md4_process_block(uint32_t state[4], const uint32_t block[MD4_BLOCK_SIZE / 4])
{
    register unsigned a, b, c, d;
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];

    FF(a, b, c, d, block[0], 3);   /* 1 */
    FF(d, a, b, c, block[1], 7);   /* 2 */
    FF(c, d, a, b, block[2], 11);  /* 3 */
    FF(b, c, d, a, block[3], 19);  /* 4 */
    FF(a, b, c, d, block[4], 3);   /* 5 */
    FF(d, a, b, c, block[5], 7);   /* 6 */
    FF(c, d, a, b, block[6], 11);  /* 7 */
    FF(b, c, d, a, block[7], 19);  /* 8 */
    FF(a, b, c, d, block[8], 3);   /* 9 */
    FF(d, a, b, c, block[9], 7);   /* 10 */
    FF(c, d, a, b, block[10], 11); /* 11 */
    FF(b, c, d, a, block[11], 19); /* 12 */
    FF(a, b, c, d, block[12], 3);  /* 13 */
    FF(d, a, b, c, block[13], 7);  /* 14 */
    FF(c, d, a, b, block[14], 11); /* 15 */
    FF(b, c, d, a, block[15], 19); /* 16 */

    GG(a, b, c, d, block[0], 3);   /* 17 */
    GG(d, a, b, c, block[4], 5);   /* 18 */
    GG(c, d, a, b, block[8], 9);   /* 19 */
    GG(b, c, d, a, block[12], 13); /* 20 */
    GG(a, b, c, d, block[1], 3);   /* 21 */
    GG(d, a, b, c, block[5], 5);   /* 22 */
    GG(c, d, a, b, block[9], 9);   /* 23 */
    GG(b, c, d, a, block[13], 13); /* 24 */
    GG(a, b, c, d, block[2], 3);   /* 25 */
    GG(d, a, b, c, block[6], 5);   /* 26 */
    GG(c, d, a, b, block[10], 9);  /* 27 */
    GG(b, c, d, a, block[14], 13); /* 28 */
    GG(a, b, c, d, block[3], 3);   /* 29 */
    GG(d, a, b, c, block[7], 5);   /* 30 */
    GG(c, d, a, b, block[11], 9);  /* 31 */
    GG(b, c, d, a, block[15], 13); /* 32 */

    HH(a, b, c, d, block[0], 3);   /* 33 */
    HH(d, a, b, c, block[8], 9);   /* 34 */
    HH(c, d, a, b, block[4], 11);  /* 35 */
    HH(b, c, d, a, block[12], 15); /* 36 */
    HH(a, b, c, d, block[2], 3);   /* 37 */
    HH(d, a, b, c, block[10], 9);  /* 38 */
    HH(c, d, a, b, block[6], 11);  /* 39 */
    HH(b, c, d, a, block[14], 15); /* 40 */
    HH(a, b, c, d, block[1], 3);   /* 41 */
    HH(d, a, b, c, block[9], 9);   /* 42 */
    HH(c, d, a, b, block[5], 11);  /* 43 */
    HH(b, c, d, a, block[13], 15); /* 44 */
    HH(a, b, c, d, block[3], 3);   /* 45 */
    HH(d, a, b, c, block[11], 9);  /* 46 */
    HH(c, d, a, b, block[7], 11);  /* 47 */
    HH(b, c, d, a, block[15], 15); /* 48 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md4_update(HASH_ctx* ctx, const unsigned char* buf, size_t size)
{
    ctx->length_ += size;
    while (size >= MD4_BLOCK_SIZE)
    {
        md4_process_block(ctx->MD4_hash_, reinterpret_cast<const uint32_t*>(buf));
        buf += MD4_BLOCK_SIZE;
        size -= MD4_BLOCK_SIZE;
    }

    ctx->unprocessed_ = size;
}

void md4_update_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize)
{
    size_t i;
    for (i = 0; i < bufsize; i += MD4_BLOCK_SIZE)
    {
        md4_process_block(ctx->MD4_hash_, reinterpret_cast<const uint32_t*>(buf));
        buf += MD4_BLOCK_SIZE;
        ctx->MD4_unprocessed_ -= MD4_BLOCK_SIZE;
    }
    return;
}

void md4_final(HASH_ctx* ctx, const unsigned char* buf, size_t size)
{
    uint32_t message[MD4_BLOCK_SIZE / 4];
    if (ctx->unprocessed_)
    {
        memcpy(message, buf + size - ctx->unprocessed_, static_cast<size_t>(ctx->unprocessed_));
    }
    uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
    uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;
    message[index] &= ~(0xFFFFFFFF << shift);
    message[index++] ^= 0x80 << shift;
    if (index > 14)
    {
        while (index < 16)
        {
            message[index++] = 0;
        }

        md4_process_block(ctx->MD4_hash_, message);
        index = 0;
    }
    while (index < 14)
    {
        message[index++] = 0;
    }
    uint64_t data_len = (ctx->length_) << 3;
    message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
    message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);
    md4_process_block(ctx->MD4_hash_, message);
    memcpy(&ctx->MD4_result, &ctx->MD4_hash_, MD4_HASH_SIZE);
}

void md4_final_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize)
{
    while (ctx->MD4_unprocessed_ >= MD4_BLOCK_SIZE)
    {
        md4_process_block(ctx->MD4_hash_, reinterpret_cast<const uint32_t*>(buf));
        buf += MD4_BLOCK_SIZE;
        ctx->MD4_unprocessed_ -= MD4_BLOCK_SIZE;
    }

    uint32_t message[MD4_BLOCK_SIZE / 4];

    if (ctx->MD4_unprocessed_)
    {
        memcpy(message, buf, static_cast<size_t>(ctx->MD4_unprocessed_));
    }

    uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
    uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

    message[index] &= ~(0xFFFFFFFF << shift);
    message[index++] ^= 0x80 << shift;

    if (index > 14)
    {
        while (index < 16)
        {
            message[index++] = 0;
        }

        md4_process_block(ctx->MD4_hash_, message);
        index = 0;
    }

    while (index < 14)
    {
        message[index++] = 0;
    }

    uint64_t data_len = (ctx->length_) << 3;

    message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
    message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);
    md4_process_block(ctx->MD4_hash_, message);
    memcpy(&ctx->MD4_result, &ctx->MD4_hash_, MD4_HASH_SIZE);
}

unsigned char* md4_MemBlock(const unsigned char* buf, size_t size, HASH_ctx* ctx)
{
    md4_init(ctx);
    md4_update(ctx, buf, size);
    md4_final(ctx, buf, size);
    return ctx->MD4_result;
}
