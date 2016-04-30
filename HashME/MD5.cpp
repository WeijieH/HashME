#include "MD5.h"



//================================================================================================
//MD5


/*
@brief      initize MD5 context
@param      ctx
*/
static void md5_init(HASH_ctx *ctx)
{
	ctx->length_ = 0;
	ctx->unprocessed_ = 0;

	/* initialize state */
	ctx->MD5_hash_[0] = 0x67452301;
	ctx->MD5_hash_[1] = 0xefcdab89;
	ctx->MD5_hash_[2] = 0x98badcfe;
	ctx->MD5_hash_[3] = 0x10325476;
}

void md5_init_file(HASH_ctx *ctx, uint64_t filesize)
{
	ctx->MD5_unprocessed_ = filesize;

	/* initialize state */
	ctx->MD5_hash_[0] = 0x67452301;
	ctx->MD5_hash_[1] = 0xefcdab89;
	ctx->MD5_hash_[2] = 0x98badcfe;
	ctx->MD5_hash_[3] = 0x10325476;
}

#ifdef x86ASM
void md5_process_block_x86asm(uint32_t state[4], const uint32_t block[MD5_BLOCK_SIZE / 4])
{

	/*
	* Storage usage:
	*   Bytes  Location  Description
	*       4  eax       MD5 state variable A
	*       4  ebx       MD5 state variable B
	*       4  ecx       MD5 state variable C
	*       4  edx       MD5 state variable D
	*       4  esi       Temporary for calculation per round
	*       4  edi       Temporary for calculation per round
	*       4  ebp       Base address of block array argument (read-only)
	*       4  esp       x86 stack pointer
	*       4  [esp+ 0]  Caller's value of ebp
	*       4  [esp+ 4]  Address of state
	*/

#define ROUND0(a, b, c, d, k, s, t)  \
		{\
		_asm mov  esi, c		\
		_asm add  a, dword ptr [ebp+k*4]\
		_asm xor  esi, d		\
		_asm and  esi, b		\
		_asm xor  esi, d		\
		_asm lea  a, dword ptr [esi+a+t]\
		_asm rol  a, s			\
		_asm add  a, b			\
		}
		

#define ROUND1(a, b, c, d, k, s, t)  \
		{\
		_asm mov  esi, d        \
		_asm mov  edi, d        \
		_asm add  a, dword ptr [ebp+k*4]\
		_asm not  esi           \
		_asm and  edi, b        \
		_asm and  esi, c        \
		_asm or   esi, edi      \
		_asm lea  a, dword ptr [esi+a+t]\
		_asm rol  a, s          \
		_asm add  a, b			\
		}

#define ROUND2(a, b, c, d, k, s, t)  \
		{\
		_asm mov  esi, c		\
		_asm add  a, dword ptr [ebp+k*4]\
		_asm xor  esi, d		\
		_asm xor  esi, b		\
		_asm lea  a, dword ptr [esi+a+t]\
		_asm rol  a, s			\
		_asm add  a, b			\
		}

#define ROUND3(a, b, c, d, k, s, t)  \
		{\
		_asm mov  esi, d        \
		_asm not  esi           \
		_asm add  a, dword ptr [ebp+k*4]\
		_asm or   esi, b        \
		_asm xor  esi, c        \
		_asm lea  a, dword ptr [esi+a+t]\
		_asm rol  a, s          \
		_asm add  a, b			\
		}
	
	_asm
	{
		// Save resisters in windows
		sub  esp, 8
		mov  dword ptr[esp + 0], ebp
		

		/* Load arguments */
		mov  esi, state
		mov  dword ptr[esp + 4], esi	//Save the pointer to state
		mov  ebp, block
		mov  eax, dword ptr[esi + 0]/* a */
		mov  ebx, dword ptr[esi + 4]/* b */
		mov  ecx, dword ptr[esi + 8]/* c */
		mov  edx, dword ptr[esi + 12]/* d */
	}

								  /* 64 rounds of hashing */
			ROUND0(eax, ebx, ecx, edx, 0, 7, 0xD76AA478)
			ROUND0(edx, eax, ebx, ecx, 1, 12, 0xE8C7B756)
			ROUND0(ecx, edx, eax, ebx, 2, 17, 0x242070DB)
			ROUND0(ebx, ecx, edx, eax, 3, 22, 0xC1BDCEEE)
			ROUND0(eax, ebx, ecx, edx, 4, 7, 0xF57C0FAF)
			ROUND0(edx, eax, ebx, ecx, 5, 12, 0x4787C62A)
			ROUND0(ecx, edx, eax, ebx, 6, 17, 0xA8304613)
			ROUND0(ebx, ecx, edx, eax, 7, 22, 0xFD469501)
			ROUND0(eax, ebx, ecx, edx, 8, 7, 0x698098D8)
			ROUND0(edx, eax, ebx, ecx, 9, 12, 0x8B44F7AF)
			ROUND0(ecx, edx, eax, ebx, 10, 17, 0xFFFF5BB1)
			ROUND0(ebx, ecx, edx, eax, 11, 22, 0x895CD7BE)
			ROUND0(eax, ebx, ecx, edx, 12, 7, 0x6B901122)
			ROUND0(edx, eax, ebx, ecx, 13, 12, 0xFD987193)
			ROUND0(ecx, edx, eax, ebx, 14, 17, 0xA679438E)
			ROUND0(ebx, ecx, edx, eax, 15, 22, 0x49B40821)
			ROUND1(eax, ebx, ecx, edx, 1, 5, 0xF61E2562)
			ROUND1(edx, eax, ebx, ecx, 6, 9, 0xC040B340)
			ROUND1(ecx, edx, eax, ebx, 11, 14, 0x265E5A51)
			ROUND1(ebx, ecx, edx, eax, 0, 20, 0xE9B6C7AA)
			ROUND1(eax, ebx, ecx, edx, 5, 5, 0xD62F105D)
			ROUND1(edx, eax, ebx, ecx, 10, 9, 0x02441453)
			ROUND1(ecx, edx, eax, ebx, 15, 14, 0xD8A1E681)
			ROUND1(ebx, ecx, edx, eax, 4, 20, 0xE7D3FBC8)
			ROUND1(eax, ebx, ecx, edx, 9, 5, 0x21E1CDE6)
			ROUND1(edx, eax, ebx, ecx, 14, 9, 0xC33707D6)
			ROUND1(ecx, edx, eax, ebx, 3, 14, 0xF4D50D87)
			ROUND1(ebx, ecx, edx, eax, 8, 20, 0x455A14ED)
			ROUND1(eax, ebx, ecx, edx, 13, 5, 0xA9E3E905)
			ROUND1(edx, eax, ebx, ecx, 2, 9, 0xFCEFA3F8)
			ROUND1(ecx, edx, eax, ebx, 7, 14, 0x676F02D9)
			ROUND1(ebx, ecx, edx, eax, 12, 20, 0x8D2A4C8A)
			ROUND2(eax, ebx, ecx, edx, 5, 4, 0xFFFA3942)
			ROUND2(edx, eax, ebx, ecx, 8, 11, 0x8771F681)
			ROUND2(ecx, edx, eax, ebx, 11, 16, 0x6D9D6122)
			ROUND2(ebx, ecx, edx, eax, 14, 23, 0xFDE5380C)
			ROUND2(eax, ebx, ecx, edx, 1, 4, 0xA4BEEA44)
			ROUND2(edx, eax, ebx, ecx, 4, 11, 0x4BDECFA9)
			ROUND2(ecx, edx, eax, ebx, 7, 16, 0xF6BB4B60)
			ROUND2(ebx, ecx, edx, eax, 10, 23, 0xBEBFBC70)
			ROUND2(eax, ebx, ecx, edx, 13, 4, 0x289B7EC6)
			ROUND2(edx, eax, ebx, ecx, 0, 11, 0xEAA127FA)
			ROUND2(ecx, edx, eax, ebx, 3, 16, 0xD4EF3085)
			ROUND2(ebx, ecx, edx, eax, 6, 23, 0x04881D05)
			ROUND2(eax, ebx, ecx, edx, 9, 4, 0xD9D4D039)
			ROUND2(edx, eax, ebx, ecx, 12, 11, 0xE6DB99E5)
			ROUND2(ecx, edx, eax, ebx, 15, 16, 0x1FA27CF8)
			ROUND2(ebx, ecx, edx, eax, 2, 23, 0xC4AC5665)
			ROUND3(eax, ebx, ecx, edx, 0, 6, 0xF4292244)
			ROUND3(edx, eax, ebx, ecx, 7, 10, 0x432AFF97)
			ROUND3(ecx, edx, eax, ebx, 14, 15, 0xAB9423A7)
			ROUND3(ebx, ecx, edx, eax, 5, 21, 0xFC93A039)
			ROUND3(eax, ebx, ecx, edx, 12, 6, 0x655B59C3)
			ROUND3(edx, eax, ebx, ecx, 3, 10, 0x8F0CCC92)
			ROUND3(ecx, edx, eax, ebx, 10, 15, 0xFFEFF47D)
			ROUND3(ebx, ecx, edx, eax, 1, 21, 0x85845DD1)
			ROUND3(eax, ebx, ecx, edx, 8, 6, 0x6FA87E4F)
			ROUND3(edx, eax, ebx, ecx, 15, 10, 0xFE2CE6E0)
			ROUND3(ecx, edx, eax, ebx, 6, 15, 0xA3014314)
			ROUND3(ebx, ecx, edx, eax, 13, 21, 0x4E0811A1)
			ROUND3(eax, ebx, ecx, edx, 4, 6, 0xF7537E82)
			ROUND3(edx, eax, ebx, ecx, 11, 10, 0xBD3AF235)
			ROUND3(ecx, edx, eax, ebx, 2, 15, 0x2AD7D2BB)
			ROUND3(ebx, ecx, edx, eax, 9, 21, 0xEB86D391)

		_asm 
		{
			/* Save updated state */	
			mov esi, dword ptr[esp + 4] 
			add dword ptr[0 + esi], eax
			add dword ptr[4 + esi], ebx
			add dword ptr[8 + esi], ecx
			add dword ptr[12 + esi], edx

			// Restore resisters
			mov  ebp, dword ptr[esp + 0]
			add esp, 8			
		}		
}
#endif


/*!
@brief      Process 64 byte little ending data block
@param      state, pointer to the hash from privous step
@param      block, pointer to the data
*/
static void md5_process_block(uint32_t state[4], const uint32_t block[MD5_BLOCK_SIZE / 4])
{
	/* First, define four auxiliary functions that each take as input
	* three 32-bit words and returns a 32-bit word.*/

	/* F(x,y,z) = ((y XOR z) AND x) XOR z - is faster then original version */
#define MD5_F(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

	/* transformations for rounds 1, 2, 3, and 4. */
#define MD5_ROUND1(a, b, c, d, x, s, ac) { \
        (a) += MD5_F((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }
#define MD5_ROUND2(a, b, c, d, x, s, ac) { \
        (a) += MD5_G((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }
#define MD5_ROUND3(a, b, c, d, x, s, ac) { \
        (a) += MD5_H((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }
#define MD5_ROUND4(a, b, c, d, x, s, ac) { \
        (a) += MD5_I((b), (c), (d)) + (x) + (ac); \
        (a) = ROTL32((a), (s)); \
        (a) += (b); \
    }

	register unsigned a, b, c, d;
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	const uint32_t *x = NULL;

	
#if BYTES_ORDER == LITTLE_ENDIAN
	x = block;
#else
	uint32_t swap_block[MD5_BLOCK_SIZE / 4];
	swap_uint32_memcpy(swap_block, block, 64);
	x = swap_block;
#endif


	MD5_ROUND1(a, b, c, d, x[0], 7, 0xd76aa478);
	MD5_ROUND1(d, a, b, c, x[1], 12, 0xe8c7b756);
	MD5_ROUND1(c, d, a, b, x[2], 17, 0x242070db);
	MD5_ROUND1(b, c, d, a, x[3], 22, 0xc1bdceee);
	MD5_ROUND1(a, b, c, d, x[4], 7, 0xf57c0faf);
	MD5_ROUND1(d, a, b, c, x[5], 12, 0x4787c62a);
	MD5_ROUND1(c, d, a, b, x[6], 17, 0xa8304613);
	MD5_ROUND1(b, c, d, a, x[7], 22, 0xfd469501);
	MD5_ROUND1(a, b, c, d, x[8], 7, 0x698098d8);
	MD5_ROUND1(d, a, b, c, x[9], 12, 0x8b44f7af);
	MD5_ROUND1(c, d, a, b, x[10], 17, 0xffff5bb1);
	MD5_ROUND1(b, c, d, a, x[11], 22, 0x895cd7be);
	MD5_ROUND1(a, b, c, d, x[12], 7, 0x6b901122);
	MD5_ROUND1(d, a, b, c, x[13], 12, 0xfd987193);
	MD5_ROUND1(c, d, a, b, x[14], 17, 0xa679438e);
	MD5_ROUND1(b, c, d, a, x[15], 22, 0x49b40821);

	MD5_ROUND2(a, b, c, d, x[1], 5, 0xf61e2562);
	MD5_ROUND2(d, a, b, c, x[6], 9, 0xc040b340);
	MD5_ROUND2(c, d, a, b, x[11], 14, 0x265e5a51);
	MD5_ROUND2(b, c, d, a, x[0], 20, 0xe9b6c7aa);
	MD5_ROUND2(a, b, c, d, x[5], 5, 0xd62f105d);
	MD5_ROUND2(d, a, b, c, x[10], 9, 0x2441453);
	MD5_ROUND2(c, d, a, b, x[15], 14, 0xd8a1e681);
	MD5_ROUND2(b, c, d, a, x[4], 20, 0xe7d3fbc8);
	MD5_ROUND2(a, b, c, d, x[9], 5, 0x21e1cde6);
	MD5_ROUND2(d, a, b, c, x[14], 9, 0xc33707d6);
	MD5_ROUND2(c, d, a, b, x[3], 14, 0xf4d50d87);
	MD5_ROUND2(b, c, d, a, x[8], 20, 0x455a14ed);
	MD5_ROUND2(a, b, c, d, x[13], 5, 0xa9e3e905);
	MD5_ROUND2(d, a, b, c, x[2], 9, 0xfcefa3f8);
	MD5_ROUND2(c, d, a, b, x[7], 14, 0x676f02d9);
	MD5_ROUND2(b, c, d, a, x[12], 20, 0x8d2a4c8a);

	MD5_ROUND3(a, b, c, d, x[5], 4, 0xfffa3942);
	MD5_ROUND3(d, a, b, c, x[8], 11, 0x8771f681);
	MD5_ROUND3(c, d, a, b, x[11], 16, 0x6d9d6122);
	MD5_ROUND3(b, c, d, a, x[14], 23, 0xfde5380c);
	MD5_ROUND3(a, b, c, d, x[1], 4, 0xa4beea44);
	MD5_ROUND3(d, a, b, c, x[4], 11, 0x4bdecfa9);
	MD5_ROUND3(c, d, a, b, x[7], 16, 0xf6bb4b60);
	MD5_ROUND3(b, c, d, a, x[10], 23, 0xbebfbc70);
	MD5_ROUND3(a, b, c, d, x[13], 4, 0x289b7ec6);
	MD5_ROUND3(d, a, b, c, x[0], 11, 0xeaa127fa);
	MD5_ROUND3(c, d, a, b, x[3], 16, 0xd4ef3085);
	MD5_ROUND3(b, c, d, a, x[6], 23, 0x4881d05);
	MD5_ROUND3(a, b, c, d, x[9], 4, 0xd9d4d039);
	MD5_ROUND3(d, a, b, c, x[12], 11, 0xe6db99e5);
	MD5_ROUND3(c, d, a, b, x[15], 16, 0x1fa27cf8);
	MD5_ROUND3(b, c, d, a, x[2], 23, 0xc4ac5665);

	MD5_ROUND4(a, b, c, d, x[0], 6, 0xf4292244);
	MD5_ROUND4(d, a, b, c, x[7], 10, 0x432aff97);
	MD5_ROUND4(c, d, a, b, x[14], 15, 0xab9423a7);
	MD5_ROUND4(b, c, d, a, x[5], 21, 0xfc93a039);
	MD5_ROUND4(a, b, c, d, x[12], 6, 0x655b59c3);
	MD5_ROUND4(d, a, b, c, x[3], 10, 0x8f0ccc92);
	MD5_ROUND4(c, d, a, b, x[10], 15, 0xffeff47d);
	MD5_ROUND4(b, c, d, a, x[1], 21, 0x85845dd1);
	MD5_ROUND4(a, b, c, d, x[8], 6, 0x6fa87e4f);
	MD5_ROUND4(d, a, b, c, x[15], 10, 0xfe2ce6e0);
	MD5_ROUND4(c, d, a, b, x[6], 15, 0xa3014314);
	MD5_ROUND4(b, c, d, a, x[13], 21, 0x4e0811a1);
	MD5_ROUND4(a, b, c, d, x[4], 6, 0xf7537e82);
	MD5_ROUND4(d, a, b, c, x[11], 10, 0xbd3af235);
	MD5_ROUND4(c, d, a, b, x[2], 15, 0x2ad7d2bb);
	MD5_ROUND4(b, c, d, a, x[9], 21, 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}


/*!
@brief      process the part of the data larger than 64 byte
@param[out] ctx  hash strcture
@param[in]  buf  pointer to the data
@param[in]  size total length of the data
*/
static void md5_update(HASH_ctx *ctx, const unsigned char *buf, size_t size)
{
	ctx->length_ = size;	
	//process until the unprocessed data length smaller than 64 byte
	while (size >= MD5_BLOCK_SIZE)
	{
#ifdef x86ASM
		md5_process_block_x86asm(ctx->MD5_hash_, reinterpret_cast<const uint32_t *>(buf));
#else
		md5_process_block(ctx->MD5_hash_, reinterpret_cast<const uint32_t *>(buf));
#endif
		// move the pointer to next 64 byte data
		buf += MD5_BLOCK_SIZE;
		// the unprocessed size of data
		size -= MD5_BLOCK_SIZE;
	}
	ctx->unprocessed_ = size;	
}

void md5_update_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize)
{
	size_t i;
	for (i = 0; i < bufsize; i += MD5_BLOCK_SIZE)
	{		
#ifdef x86ASM
		md5_process_block_x86asm(ctx->MD5_hash_, reinterpret_cast<const uint32_t *>(buf));
#else
		md5_process_block(ctx->MD5_hash_, reinterpret_cast<const uint32_t *>(buf));
#endif
		buf += MD5_BLOCK_SIZE;
		ctx->MD5_unprocessed_ -= MD5_BLOCK_SIZE;
	}	
	return;
}


/*!
@brief      padding and process the end of the data
@param[in]  ctx    hash strcture
@param[in]  buf    pointer to the original data
@param[in]  size   size of the buffer (data)
@param[out] result, finial result
*/
static void md5_final(HASH_ctx *ctx, const unsigned char *buf, size_t size)
{
	uint32_t message[MD5_BLOCK_SIZE / 4];

	//Save the unprocessed data
	if (ctx->unprocessed_)
	{
		memcpy(message, buf + size - ctx->unprocessed_, static_cast<size_t>(ctx->unprocessed_));
	}

	//Find the position for padding, "& 63" to find the length of unprocessed part. ">> 2" to devided by 4 since sizeof (uint_32) is 4
	uint32_t index = ((uint32_t)ctx->length_ & 63) >> 2;
	//Find the padding shift, "& 3" to find the modrate of 4, "* 8" to converte byte to the bit
	uint32_t shift = ((uint32_t)ctx->length_ & 3) * 8;

	//padding data, 0x80 = 1000 0000 bin
	message[index] &= ~(0xFFFFFFFF << shift);
	message[index++] ^= 0x80 << shift;

	//if the size of the padded data is larger then 14, no room for length padding. process now
	if (index > 14)
	{
		while (index < 16)
		{
			message[index++] = 0;
		}
#ifdef x86ASM
		md5_process_block_x86asm(ctx->MD5_hash_, message);
#else
		md5_process_block(ctx->MD5_hash_, message);
#endif		
		index = 0;
	}

	//if the size of the padded data is small than 14, pad 0 until 14
	while (index < 14)
	{
		message[index++] = 0;
	}

	//the length for padding. "<< 3" = "* 8", convert byte to bit
	uint64_t data_len = (ctx->length_) << 3;

	//length is little endian
#if BYTES_ORDER != LITTLE_ENDIAN
	data_len = SWAP_UINT64(data_len);
#endif
	//pading the length, lower part goes to [14], higher to [15]
	message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
	message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);


#ifdef x86ASM
	 md5_process_block_x86asm(ctx->MD5_hash_, message);
#else
	md5_process_block(ctx->MD5_hash_, message);
#endif

	//result is little endian, save result
#if BYTES_ORDER == LITTLE_ENDIAN
	memcpy(&ctx->MD5_result, &ctx->MD5_hash_, MD5_HASH_SIZE);
#else
	swap_uint32_memcpy(result, &ctx->MD5_hash_, MD5_HASH_SIZE);
#endif	
}

void md5_final_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize)
{
	//for file processing, make sure the remain part size is smaller than 64 byte
	while (ctx->MD5_unprocessed_ >= MD5_BLOCK_SIZE)
	{
#ifdef x86ASM
		md5_process_block_x86asm(ctx->MD5_hash_, reinterpret_cast<const uint32_t *>(buf));
#else
		md5_process_block(ctx->MD5_hash_, reinterpret_cast<const uint32_t *>(buf));
#endif
		buf += MD5_BLOCK_SIZE;
		ctx->MD5_unprocessed_ -= MD5_BLOCK_SIZE;
	}

	uint32_t message[MD5_BLOCK_SIZE / 4];

	if (ctx->MD5_unprocessed_)
	{
		memcpy(message, buf, static_cast<size_t>(ctx->MD5_unprocessed_));
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
#ifdef x86ASM
		md5_process_block_x86asm(ctx->MD5_hash_, message);
#else
		md5_process_block(ctx->MD5_hash_, message);
#endif
		index = 0;
	}

	while (index < 14)
	{
		message[index++] = 0;
	}

	uint64_t data_len = (ctx->length_) << 3;

#if BYTES_ORDER != LITTLE_ENDIAN
	data_len = SWAP_UINT64(data_len);
#endif

	message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
	message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);

	md5_process_block(ctx->MD5_hash_, message);

#if BYTES_ORDER == LITTLE_ENDIAN
	memcpy(&ctx->MD5_result, &ctx->MD5_hash_, MD5_HASH_SIZE);
#else
	swap_uint32_memcpy(&ctx->MD5_result, &ctx->MD5_hash_, MD5_HASH_SIZE);
#endif

}


unsigned char *md5_MemBlock(const unsigned char *buf,
	size_t size,
	HASH_ctx* ctx)
{		
	md5_init(ctx);
	md5_update(ctx, buf, size);
	md5_final(ctx, buf, size);
	return ctx->MD5_result;
}