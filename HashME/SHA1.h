#pragma once
#include "Common.h"
#include "Formats.h"


/*!
@brief      ���ڴ��BUFFER��SHA1ֵ
@return     unsigned char* ���صĵĽ��
@param[in]  buf    ��SHA1���ڴ�BUFFERָ��
@param[in]  size   BUFFER����
@param[out] HASH_ctx* Hash scture
*/
extern unsigned char *sha1_MemBlock(const unsigned char *buf,
	size_t size,
	HASH_ctx* ctx);

extern void sha1_final_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize);
extern void sha1_update_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize);
extern void sha1_init_file(HASH_ctx *ctx, uint64_t filesize);

