#pragma once
#include "Common.h"
#include "Formats.h"


/*!
@brief      求内存块BUFFER的SHA1值
@return     unsigned char* 返回的的结果
@param[in]  buf    求SHA1的内存BUFFER指针
@param[in]  size   BUFFER长度
@param[out] HASH_ctx* Hash scture
*/
extern unsigned char *sha1_MemBlock(const unsigned char *buf,
	size_t size,
	HASH_ctx* ctx);

extern void sha1_final_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize);
extern void sha1_update_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize);
extern void sha1_init_file(HASH_ctx *ctx, uint64_t filesize);

