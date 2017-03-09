#include "SHA2.h"

void sha224_init(HASH_ctx *ctx) {
  ctx->length_ = 0;
  ctx->unprocessed_ = 0;

  ctx->SHA224_hash_[0] = 0xc1059ed8;
  ctx->SHA224_hash_[1] = 0x367cd507;
  ctx->SHA224_hash_[2] = 0x3070dd17;
  ctx->SHA224_hash_[3] = 0xf70e5939;
  ctx->SHA224_hash_[4] = 0xffc00b31;
  ctx->SHA224_hash_[5] = 0x68581511;
  ctx->SHA224_hash_[6] = 0x64f98fa7;
  ctx->SHA224_hash_[7] = 0xbefa4fa4;
}

void sha224_init_file(HASH_ctx *ctx, uint64_t filesize) {
  ctx->SHA224_unprocessed_ = filesize;

  ctx->SHA224_hash_[0] = 0xc1059ed8;
  ctx->SHA224_hash_[1] = 0x367cd507;
  ctx->SHA224_hash_[2] = 0x3070dd17;
  ctx->SHA224_hash_[3] = 0xf70e5939;
  ctx->SHA224_hash_[4] = 0xffc00b31;
  ctx->SHA224_hash_[5] = 0x68581511;
  ctx->SHA224_hash_[6] = 0x64f98fa7;
  ctx->SHA224_hash_[7] = 0xbefa4fa4;
}

void sha224_process_block(uint32_t hash[8],
                          const uint32_t block[SHA224_BLOCK_SIZE / 4]) {
  uint32_t w[64];
  uint32_t wv[8];
  uint32_t t1, t2;
  int j;

  swap_uint32_memcpy(w, block, SHA224_BLOCK_SIZE);

  for (j = 16; j < 64; j++) {
    w[j] = SHA2_F4(w[j - 2]) + w[j - 7] + SHA2_F3(w[j - 15]) + w[j - 16];
  }

  for (j = 0; j < 8; j++) {
    wv[j] = hash[j];
  }

  for (j = 0; j < 64; j++) {
    t1 = wv[7] + SHA2_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6]) + SHA2[j] + w[j];
    t2 = SHA2_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
    wv[7] = wv[6];
    wv[6] = wv[5];
    wv[5] = wv[4];
    wv[4] = wv[3] + t1;
    wv[3] = wv[2];
    wv[2] = wv[1];
    wv[1] = wv[0];
    wv[0] = t1 + t2;
  }

  for (j = 0; j < 8; j++) {
    hash[j] += wv[j];
  }
}

void sha224_update(HASH_ctx *ctx, const unsigned char *buf, uint32_t size) {
  ctx->length_ += size;

  while (size >= SHA224_BLOCK_SIZE) {
    sha224_process_block(ctx->SHA224_hash_,
                         reinterpret_cast<const uint32_t *>(buf));
    buf += SHA224_BLOCK_SIZE;
    size -= SHA224_BLOCK_SIZE;
  }

  ctx->unprocessed_ = size;
}

void sha224_update_file(HASH_ctx *ctx, const unsigned char *buf,
                        size_t bufsize) {
  size_t i;
  for (i = 0; i < bufsize; i += SHA224_BLOCK_SIZE) {
    sha224_process_block(ctx->SHA224_hash_,
                         reinterpret_cast<const uint32_t *>(buf));
    buf += SHA224_BLOCK_SIZE;
    ctx->SHA224_unprocessed_ -= SHA224_BLOCK_SIZE;
  }
  return;
}

void sha224_final(HASH_ctx *ctx, const unsigned char *msg, size_t size) {
  uint32_t message[SHA224_BLOCK_SIZE / 4];

  if (ctx->unprocessed_) {
    memcpy(message, msg + size - ctx->unprocessed_,
           static_cast<size_t>(ctx->unprocessed_));
  }

  uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
  uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

  message[index] &= ~(0xFFFFFFFF << shift);
  message[index++] ^= 0x80 << shift;

  if (index > 14) {
    while (index < 16) {
      message[index++] = 0;
    }

    sha224_process_block(ctx->SHA224_hash_, message);
    index = 0;
  }

  while (index < 14) {
    message[index++] = 0;
  }

  // length in bit = length in char * 8
  uint64_t data_len = (ctx->length_) << 3;
  data_len = SWAP_UINT64(data_len);

  message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
  message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);

  sha224_process_block(ctx->SHA224_hash_, message);

  swap_uint32_memcpy(&ctx->SHA224_result, &ctx->SHA224_hash_, SHA224_HASH_SIZE);
}

void sha224_final_file(HASH_ctx *ctx, const unsigned char *buf,
                       size_t bufsize) {
  while (ctx->SHA224_unprocessed_ >= SHA224_BLOCK_SIZE) {
    sha224_process_block(ctx->SHA224_hash_,
                         reinterpret_cast<const uint32_t *>(buf));
    buf += SHA224_BLOCK_SIZE;
    ctx->SHA224_unprocessed_ -= SHA224_BLOCK_SIZE;
  }
  uint32_t message[SHA224_BLOCK_SIZE / 4];

  if (ctx->SHA224_unprocessed_) {
    memcpy(message, buf, static_cast<size_t>(ctx->SHA224_unprocessed_));
  }

  uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
  uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

  message[index] &= ~(0xFFFFFFFF << shift);
  message[index++] ^= 0x80 << shift;

  if (index > 14) {
    while (index < 16) {
      message[index++] = 0;
    }

    sha224_process_block(ctx->SHA224_hash_, message);
    index = 0;
  }

  while (index < 14) {
    message[index++] = 0;
  }

  uint64_t data_len = (ctx->length_) << 3;

  data_len = SWAP_UINT64(data_len);

  message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
  message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);

  sha224_process_block(ctx->SHA224_hash_, message);

  swap_uint32_memcpy(&ctx->SHA224_result, &ctx->SHA224_hash_, SHA224_HASH_SIZE);
}

unsigned char *sha224_MemBlock(const unsigned char *msg, size_t size,
                               HASH_ctx *ctx) {
  sha224_init(ctx);
  sha224_update(ctx, msg, size);
  sha224_final(ctx, msg, size);
  return ctx->SHA224_result;
}