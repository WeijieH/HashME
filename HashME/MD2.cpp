#include "MD2.h"
//http://www.oryx-embedded.com/doc/md2_8c_source.html



void md2_process_block(HASH_ctx *ctx, const uint8_t data[MD2_BLOCK_SIZE])
{
	int j, k, t;
	
	for (j = 0; j < 16; ++j) {
		ctx->MD2_hash_[j + 16] = data[j];
		ctx->MD2_hash_[j + 32] = (ctx->MD2_hash_[j + 16] ^ ctx->MD2_hash_[j]);
	}

	t = 0;
	for (j = 0; j < 18; ++j) {
		for (k = 0; k < 48; ++k) {
			ctx->MD2_hash_[k] ^= MD2[t];
			t = ctx->MD2_hash_[k];
		}
		t = (t + j) & 0xFF;
	}

	t = ctx->MD2_result[15];
	for (j = 0; j < 16; ++j) {
		ctx->MD2_result[j] ^= MD2[data[j] ^ t];
		t = ctx->MD2_result[j];
	}
}

void md2_init(HASH_ctx *ctx)
{
	int i;
	for (i = 0; i < 48; ++i)
		ctx->MD2_hash_[i] = 0;
	for (i = 0; i < 16; ++i)
		ctx->MD2_result[i] = 0;	
}

void md2_init_file(HASH_ctx *ctx, uint64_t filesize)
{
	int i;
	for (i = 0; i < 48; ++i)
		ctx->MD2_hash_[i] = 0;
	for (i = 0; i < 16; ++i)
		ctx->MD2_result[i] = 0;

	ctx->MD2_unprocessed_ = filesize;
}

void md2_update(HASH_ctx *ctx, const unsigned char* buf, size_t size)
{
	ctx->unprocessed_ = size;
	while (ctx->unprocessed_ >= MD2_BLOCK_SIZE)
	{		
		md2_process_block(ctx, reinterpret_cast<const uint8_t *>(buf));
		buf += MD2_BLOCK_SIZE;
		ctx->unprocessed_ -= MD2_BLOCK_SIZE;
	}	
}

void md2_update_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize)
{
	size_t i;
	for (i = 0; i < bufsize; i += MD2_BLOCK_SIZE)
	{
		md2_process_block(ctx, reinterpret_cast<const uint8_t *>(buf));
		buf += MD2_BLOCK_SIZE;
		ctx->MD2_unprocessed_ -= MD2_BLOCK_SIZE;
	}
	return;
}

void md2_final(HASH_ctx *ctx, const unsigned char *buf, size_t size)
{
	int to_pad;
	uint8_t message[MD2_BLOCK_SIZE];

	to_pad = MD2_BLOCK_SIZE - (uint32_t)ctx->unprocessed_;
	for (int i = 0; i < ctx->unprocessed_; i++)
	{
		message[i] = buf[size - ctx->unprocessed_ + i];
	}
	for (int i = (uint32_t)ctx->unprocessed_; i < MD2_BLOCK_SIZE; i++)
	{
		message[i] = to_pad;
	}
	

	md2_process_block(ctx, message);
	md2_process_block(ctx, ctx->MD2_result);

	memcpy(ctx->MD2_result, ctx->MD2_hash_, MD2_BLOCK_SIZE);
}

void md2_final_file(HASH_ctx *ctx, const unsigned char *buf, size_t size)
{
	while (ctx->MD2_unprocessed_ >= MD2_BLOCK_SIZE)
	{
		md2_process_block(ctx, reinterpret_cast<const uint8_t *>(buf));
		buf += MD2_BLOCK_SIZE;
		ctx->MD2_unprocessed_ -= MD2_BLOCK_SIZE;
	}
	int to_pad;
	uint8_t message[MD2_BLOCK_SIZE];
	size_t i;
	to_pad = MD2_BLOCK_SIZE - (uint32_t)ctx->MD2_unprocessed_;
	for (i = 0; i < ctx->MD2_unprocessed_; i++)
	{
		message[i] = buf[i];
	}
	for (i = (uint32_t)ctx->MD2_unprocessed_; i < MD2_BLOCK_SIZE; i++)
	{
		message[i] = to_pad;
	}


	md2_process_block(ctx, message);
	md2_process_block(ctx, ctx->MD2_result);

	memcpy(ctx->MD2_result, ctx->MD2_hash_, MD2_BLOCK_SIZE);
}

//计算一个内存数据的MD2值
unsigned char *md2_MemBlock(const unsigned char *buf,
	size_t size,
	HASH_ctx* ctx)
{
	md2_init(ctx);
	md2_update(ctx, buf, size);
	md2_final(ctx, buf, size);
	return ctx->MD2_result;
}