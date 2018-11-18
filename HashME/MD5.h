#pragma once
#include "Common.h"
#include "Formats.h"

/*!
@brief      MD5 hashing for a memery block
@return     unsigned char* point to result
@param[in]  buf    point to menery block buffer
@param[in]  size   length of BUFFER
@param[out] result result
*/
extern unsigned char* md5_MemBlock(const unsigned char* buf, size_t size, HASH_ctx* ctx);

extern void md5_final_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize);
extern void md5_update_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize);
extern void md5_init_file(HASH_ctx* ctx, uint64_t filesize);
