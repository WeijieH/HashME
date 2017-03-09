#include "SHA3.h"

void sha384_init(HASH_ctx *ctx) {
  ctx->length_ = 0;
  ctx->unprocessed_ = 0;

  ctx->SHA384_hash_[0] = 0xcbbb9d5dc1059ed8ULL;
  ctx->SHA384_hash_[1] = 0x629a292a367cd507ULL;
  ctx->SHA384_hash_[2] = 0x9159015a3070dd17ULL;
  ctx->SHA384_hash_[3] = 0x152fecd8f70e5939ULL;
  ctx->SHA384_hash_[4] = 0x67332667ffc00b31ULL;
  ctx->SHA384_hash_[5] = 0x8eb44a8768581511ULL;
  ctx->SHA384_hash_[6] = 0xdb0c2e0d64f98fa7ULL;
  ctx->SHA384_hash_[7] = 0x47b5481dbefa4fa4ULL;
}

void sha384_init_file(HASH_ctx *ctx, uint64_t filesize) {
  ctx->SHA384_unprocessed_ = filesize;

  ctx->SHA384_hash_[0] = 0xcbbb9d5dc1059ed8ULL;
  ctx->SHA384_hash_[1] = 0x629a292a367cd507ULL;
  ctx->SHA384_hash_[2] = 0x9159015a3070dd17ULL;
  ctx->SHA384_hash_[3] = 0x152fecd8f70e5939ULL;
  ctx->SHA384_hash_[4] = 0x67332667ffc00b31ULL;
  ctx->SHA384_hash_[5] = 0x8eb44a8768581511ULL;
  ctx->SHA384_hash_[6] = 0xdb0c2e0d64f98fa7ULL;
  ctx->SHA384_hash_[7] = 0x47b5481dbefa4fa4ULL;
}

// size uint64 = 8
void sha384_process_block(uint64_t hash[8],
                          const uint64_t block[SHA384_BLOCK_SIZE / 8]) {
  uint64_t w[80];
  uint64_t wv[8];
  uint64_t t1, t2;
  int j;

  swap_uint64_memcpy(w, block, SHA384_BLOCK_SIZE);
  for (j = 16; j < 80; j++) {
    w[j] = SHA3_F4(w[j - 2]) + w[j - 7] + SHA3_F3(w[j - 15]) + w[j - 16];
  }
  for (j = 0; j < 8; j++) {
    wv[j] = hash[j];
  }
  for (j = 0; j < 80; j++) {
    t1 = wv[7] + SHA3_F2(wv[4]) + SHA3_CH(wv[4], wv[5], wv[6]) + SHA3[j] + w[j];
    t2 = SHA3_F1(wv[0]) + SHA3_MAJ(wv[0], wv[1], wv[2]);
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

void sha384_update(HASH_ctx *ctx, const unsigned char *buf, uint32_t size) {
  ctx->length_ += size;

  while (size >= SHA384_BLOCK_SIZE) {
    sha384_process_block(ctx->SHA384_hash_,
                         reinterpret_cast<const uint64_t *>(buf));
    buf += SHA384_BLOCK_SIZE;
    size -= SHA384_BLOCK_SIZE;
  }

  ctx->unprocessed_ = size;
}

void sha384_update_file(HASH_ctx *ctx, const unsigned char *buf,
                        size_t bufsize) {
  size_t i;
  for (i = 0; i < bufsize; i += SHA384_BLOCK_SIZE) {
    sha384_process_block(ctx->SHA384_hash_,
                         reinterpret_cast<const uint64_t *>(buf));
    buf += SHA384_BLOCK_SIZE;
    ctx->SHA384_unprocessed_ -= SHA384_BLOCK_SIZE;
  }
  return;
}

void sha384_final(HASH_ctx *ctx, const unsigned char *msg, size_t size) {
  uint64_t message[SHA384_BLOCK_SIZE / 8];

  if (ctx->unprocessed_) {
    memcpy(message, msg + size - ctx->unprocessed_,
           static_cast<size_t>(ctx->unprocessed_));
  }

  // The final SHA3 block size will be 0~127, then devide by 8 (sizeof uint64)
  // to get index
  uint32_t index = ((uint64_t)ctx->length_ & 127) >> 3;
  // shift of uint64 will be ranged from 0 to 7, times 8 to convert the unit to
  // bit
  uint32_t shift = ((uint64_t)ctx->length_ & 7) * 8;

  message[index] &= ~(0xFFFFFFFFFFFFFFFFULL << shift);
  message[index++] ^= 0x80ULL << shift;

  if (index > 14) {
    while (index < 16) {
      message[index++] = 0;
    }

    sha384_process_block(ctx->SHA384_hash_, message);
    index = 0;
  }

  while (index < 14) {
    message[index++] = 0;
  }

  // length in bit = length in char * 8
  uint64_t data_len = (ctx->length_) << 3;
  data_len = SWAP_UINT64(data_len);

  // store the size, only consider data_len < 2^64, so message[14] is always 0
  message[14] = 0x0ULL;
  message[15] = data_len;

  sha384_process_block(ctx->SHA384_hash_, message);

  swap_uint64_memcpy(&ctx->SHA384_result, &ctx->SHA384_hash_, SHA384_HASH_SIZE);
}

void sha384_final_file(HASH_ctx *ctx, const unsigned char *buf,
                       size_t bufsize) {
  while (ctx->SHA384_unprocessed_ >= SHA384_BLOCK_SIZE) {
    sha384_process_block(ctx->SHA384_hash_,
                         reinterpret_cast<const uint64_t *>(buf));
    buf += SHA384_BLOCK_SIZE;
    ctx->SHA384_unprocessed_ -= SHA384_BLOCK_SIZE;
  }
  uint64_t message[SHA384_BLOCK_SIZE / 8];

  if (ctx->SHA384_unprocessed_) {
    memcpy(message, buf, static_cast<size_t>(ctx->SHA384_unprocessed_));
  }

  // The final SHA3 block size will be 0~127, then devide by 8 (sizeof uint64)
  // to get index
  uint32_t index = ((uint64_t)ctx->length_ & 127) >> 3;
  // shift of uint64 will be ranged from 0 to 7, times 8 to convert the unit to
  // bit
  uint32_t shift = ((uint64_t)ctx->length_ & 7) * 8;

  message[index] &= ~(0xFFFFFFFFFFFFFFFFULL << shift);
  message[index++] ^= 0x80ULL << shift;

  if (index > 14) {
    while (index < 16) {
      message[index++] = 0;
    }

    sha384_process_block(ctx->SHA384_hash_, message);
    index = 0;
  }

  while (index < 14) {
    message[index++] = 0;
  }

  // length in bit = length in char * 8
  uint64_t data_len = (ctx->length_) << 3;
  data_len = SWAP_UINT64(data_len);

  // store the size, only consider data_len < 2^64, so message[14] is always 0
  message[14] = 0x0ULL;
  message[15] = data_len;

  sha384_process_block(ctx->SHA384_hash_, message);

  swap_uint64_memcpy(&ctx->SHA384_result, &ctx->SHA384_hash_, SHA384_HASH_SIZE);
}

unsigned char *sha384_MemBlock(const unsigned char *msg, size_t size,
                               HASH_ctx *ctx) {
  sha384_init(ctx);
  sha384_update(ctx, msg, size);
  sha384_final(ctx, msg, size);
  return ctx->SHA384_result;
}