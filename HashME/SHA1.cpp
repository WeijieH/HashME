#include "SHA1.h"


//================================================================================================
//SHA1
//Reference (Chinese): http://www.cnblogs.com/fullsail/archive/2013/02/22/2921505.html



static void sha1_init(HASH_ctx *ctx)
{
	ctx->length_ = 0;
	ctx->unprocessed_ = 0;
	// Magic numbers
	ctx->SHA1_hash_[0] = 0x67452301;
	ctx->SHA1_hash_[1] = 0xefcdab89;
	ctx->SHA1_hash_[2] = 0x98badcfe;
	ctx->SHA1_hash_[3] = 0x10325476;
	ctx->SHA1_hash_[4] = 0xc3d2e1f0;
}

void sha1_init_file(HASH_ctx *ctx, uint64_t filesize)
{
	ctx->SHA1_unprocessed_ = filesize;

	/* initialize state */
	ctx->SHA1_hash_[0] = 0x67452301;
	ctx->SHA1_hash_[1] = 0xefcdab89;
	ctx->SHA1_hash_[2] = 0x98badcfe;
	ctx->SHA1_hash_[3] = 0x10325476;
	ctx->SHA1_hash_[4] = 0xc3d2e1f0;
}

// SHA1 asm
// Reference: https://www.nayuki.io/page/fast-sha1-hash-implementation-in-x86-assembly
#ifdef x86ASM
void sha1_process_block_x86asm(uint32_t state[5], const uint32_t block[SHA1_BLOCK_SIZE / 4])
{
	/*
	* Storage usage:
	*   Bytes  Location  Description
	*       4  eax       SHA-1 state variable A
	*       4  ebx       SHA-1 state variable B
	*       4  ecx       SHA-1 state variable C
	*       4  edx       SHA-1 state variable D
	*       4  ebp       SHA-1 state variable E
	*       4  esi       Temporary for calculation per round
	*       4  edi       (First 16 rounds) base address of block array argument (read-only); (last 64 rounds) temporary for calculation per round
	*       4  esp       x86 stack pointer
	*      64  [esp+ 0]  Circular buffer of most recent 16 key schedule items, 4 bytes each
	*       4  [esp+64]  Caller's value of ebp
	*       4  [esp+68]  Pointer to state
	*/

#define ROUND0a(a, b, c, d, e, i)  \
	{\
		_asm mov    esi, dword ptr [edi + i*4]	\
		_asm bswap  esi							\
		_asm mov    dword ptr [esp + i*4], esi	\
		_asm add    e, esi						\
		_asm mov    esi, c						\
		_asm xor    esi, d						\
		_asm and    esi, b						\
		_asm xor    esi, d						\
		_asm rol	b, 30						\
		_asm lea	e, dword ptr[e + esi + 0x5A827999]		\
		_asm mov	esi, a						\
		_asm rol	esi, 5						\
		_asm add	e, esi						\
	}

#define ROUND0b(a, b, c, d, e, i)\
	{\
		_asm mov  esi, dword ptr [esp + ((i-3)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-8)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-14)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-16)&15)*4]		\
		_asm rol  esi, 1									\
		_asm add  e, esi									\
		_asm mov  dword ptr[esp + (i&15)*4], esi 			\
		_asm mov  esi, c		\
		_asm xor  esi, d		\
		_asm and  esi, b		\
		_asm xor  esi, d		\
		_asm rol  b, 30							\
		_asm lea  e, dword ptr[e + esi + 0x5A827999]		\
		_asm mov  esi, a						\
		_asm rol  esi, 5						\
		_asm add  e, esi						\
	}

#define ROUND1(a, b, c, d, e, i)  \
	{\
		_asm mov  esi, dword ptr [esp + ((i- 3)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i- 8)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i- 14)&15)*4]	\
		_asm xor  esi, dword ptr [esp + ((i- 16)&15)*4]	\
		_asm rol  esi, 1									\
		_asm add  e, esi									\
		_asm mov  dword ptr[esp + (i&15)*4], esi			\
		_asm mov  esi, b		\
		_asm xor  esi, c		\
		_asm xor  esi, d		\
		_asm rol  b, 30							\
		_asm lea  e, dword ptr [e + esi + 0x6ED9EBA1]		\
		_asm mov  esi, a						\
		_asm rol  esi, 5						\
		_asm add  e, esi						\
	}

#define ROUND2(a, b, c, d, e, i)  \
	{\
		_asm mov  esi, dword ptr [esp + ((i-3)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-8)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-14)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-16)&15)*4]		\
		_asm rol  esi, 1									\
		_asm add  e, esi									\
		_asm mov  dword ptr[esp + (i&15)*4], esi			\
		_asm mov  esi, c		\
		_asm mov  edi, c		\
		_asm or   esi, d		\
		_asm and  esi, b		\
		_asm and  edi, d		\
		_asm or   esi, edi	\
		_asm rol  b, 30							\
		_asm lea  e, dword ptr[e + esi + 0x8F1BBCDC]		\
		_asm mov  esi, a						\
		_asm rol  esi, 5						\
		_asm add  e, esi						\
	}

#define ROUND3(a, b, c, d, e, i)  \
	{\
		_asm mov  esi, dword ptr [esp + ((i-3)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-8)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-14)&15)*4]		\
		_asm xor  esi, dword ptr [esp + ((i-16)&15)*4]		\
		_asm rol  esi, 1									\
		_asm add  e, esi									\
		_asm mov  dword ptr[esp + (i&15)*4], esi			\
		_asm mov  esi, b		\
		_asm xor  esi, c		\
		_asm xor  esi, d		\
		_asm rol  b, 30							\
		_asm lea  e, dword ptr[e + esi + 0xCA62C1D6]		\
		_asm mov  esi, a						\
		_asm rol  esi, 5						\
		_asm add  e, esi						\
	}

_asm
{
	/* Save registers */
	sub    esp, 72
	mov    dword ptr [esp + 64], ebp

	/* Load arguments */
	mov		esi, state
	mov     dword ptr[esp + 68], esi
	mov		edi, block
	mov		eax, dword ptr[esi + 0]/* a */
	mov		ebx, dword ptr[esi + 4]/* b */
	mov		ecx, dword ptr[esi + 8]/* c */
	mov		edx, dword ptr[esi + 12]/* d */
	mov		ebp, dword ptr[esi + 16]/* e */
}
/* 80 rounds of hashing */

ROUND0a(eax, ebx, ecx, edx, ebp, 0)
ROUND0a(ebp, eax, ebx, ecx, edx, 1)
ROUND0a(edx, ebp, eax, ebx, ecx, 2)
ROUND0a(ecx, edx, ebp, eax, ebx, 3)
ROUND0a(ebx, ecx, edx, ebp, eax, 4)
ROUND0a(eax, ebx, ecx, edx, ebp, 5)
ROUND0a(ebp, eax, ebx, ecx, edx, 6)
ROUND0a(edx, ebp, eax, ebx, ecx, 7)
ROUND0a(ecx, edx, ebp, eax, ebx, 8)
ROUND0a(ebx, ecx, edx, ebp, eax, 9)
ROUND0a(eax, ebx, ecx, edx, ebp, 10)
ROUND0a(ebp, eax, ebx, ecx, edx, 11)
ROUND0a(edx, ebp, eax, ebx, ecx, 12)
ROUND0a(ecx, edx, ebp, eax, ebx, 13)
ROUND0a(ebx, ecx, edx, ebp, eax, 14)
ROUND0a(eax, ebx, ecx, edx, ebp, 15)
ROUND0b(ebp, eax, ebx, ecx, edx, 16)
ROUND0b(edx, ebp, eax, ebx, ecx, 17)
ROUND0b(ecx, edx, ebp, eax, ebx, 18)
ROUND0b(ebx, ecx, edx, ebp, eax, 19)
ROUND1(eax, ebx, ecx, edx, ebp, 20)
ROUND1(ebp, eax, ebx, ecx, edx, 21)
ROUND1(edx, ebp, eax, ebx, ecx, 22)
ROUND1(ecx, edx, ebp, eax, ebx, 23)
ROUND1(ebx, ecx, edx, ebp, eax, 24)
ROUND1(eax, ebx, ecx, edx, ebp, 25)
ROUND1(ebp, eax, ebx, ecx, edx, 26)
ROUND1(edx, ebp, eax, ebx, ecx, 27)
ROUND1(ecx, edx, ebp, eax, ebx, 28)
ROUND1(ebx, ecx, edx, ebp, eax, 29)
ROUND1(eax, ebx, ecx, edx, ebp, 30)
ROUND1(ebp, eax, ebx, ecx, edx, 31)
ROUND1(edx, ebp, eax, ebx, ecx, 32)
ROUND1(ecx, edx, ebp, eax, ebx, 33)
ROUND1(ebx, ecx, edx, ebp, eax, 34)
ROUND1(eax, ebx, ecx, edx, ebp, 35)
ROUND1(ebp, eax, ebx, ecx, edx, 36)
ROUND1(edx, ebp, eax, ebx, ecx, 37)
ROUND1(ecx, edx, ebp, eax, ebx, 38)
ROUND1(ebx, ecx, edx, ebp, eax, 39)
ROUND2(eax, ebx, ecx, edx, ebp, 40)
ROUND2(ebp, eax, ebx, ecx, edx, 41)
ROUND2(edx, ebp, eax, ebx, ecx, 42)
ROUND2(ecx, edx, ebp, eax, ebx, 43)
ROUND2(ebx, ecx, edx, ebp, eax, 44)
ROUND2(eax, ebx, ecx, edx, ebp, 45)
ROUND2(ebp, eax, ebx, ecx, edx, 46)
ROUND2(edx, ebp, eax, ebx, ecx, 47)
ROUND2(ecx, edx, ebp, eax, ebx, 48)
ROUND2(ebx, ecx, edx, ebp, eax, 49)
ROUND2(eax, ebx, ecx, edx, ebp, 50)
ROUND2(ebp, eax, ebx, ecx, edx, 51)
ROUND2(edx, ebp, eax, ebx, ecx, 52)
ROUND2(ecx, edx, ebp, eax, ebx, 53)
ROUND2(ebx, ecx, edx, ebp, eax, 54)
ROUND2(eax, ebx, ecx, edx, ebp, 55)
ROUND2(ebp, eax, ebx, ecx, edx, 56)
ROUND2(edx, ebp, eax, ebx, ecx, 57)
ROUND2(ecx, edx, ebp, eax, ebx, 58)
ROUND2(ebx, ecx, edx, ebp, eax, 59)
ROUND3(eax, ebx, ecx, edx, ebp, 60)
ROUND3(ebp, eax, ebx, ecx, edx, 61)
ROUND3(edx, ebp, eax, ebx, ecx, 62)
ROUND3(ecx, edx, ebp, eax, ebx, 63)
ROUND3(ebx, ecx, edx, ebp, eax, 64)
ROUND3(eax, ebx, ecx, edx, ebp, 65)
ROUND3(ebp, eax, ebx, ecx, edx, 66)
ROUND3(edx, ebp, eax, ebx, ecx, 67)
ROUND3(ecx, edx, ebp, eax, ebx, 68)
ROUND3(ebx, ecx, edx, ebp, eax, 69)
ROUND3(eax, ebx, ecx, edx, ebp, 70)
ROUND3(ebp, eax, ebx, ecx, edx, 71)
ROUND3(edx, ebp, eax, ebx, ecx, 72)
ROUND3(ecx, edx, ebp, eax, ebx, 73)
ROUND3(ebx, ecx, edx, ebp, eax, 74)
ROUND3(eax, ebx, ecx, edx, ebp, 75)
ROUND3(ebp, eax, ebx, ecx, edx, 76)
ROUND3(edx, ebp, eax, ebx, ecx, 77)
ROUND3(ecx, edx, ebp, eax, ebx, 78)
ROUND3(ebx, ecx, edx, ebp, eax, 79)




_asm
{
	/* Save updated state */
	mov    esi, dword ptr[esp + 68]
	add    dword ptr[esi + 0], eax
	add    dword ptr[esi + 4], ebx
	add    dword ptr[esi + 8], ecx
	add    dword ptr[esi + 12], edx
	add    dword ptr[esi + 16], ebp

	/* Restore registers */
	mov    ebp, dword ptr[esp + 64]
	add    esp, 72	
}

}
#endif



static void sha1_process_block(uint32_t hash[5], const uint32_t block[SHA1_BLOCK_SIZE / 4])
{
	size_t        t;
	uint32_t      wblock[80];
	uint32_t      a, b, c, d, e, temp;

#if BYTES_ORDER == LITTLE_ENDIAN
	swap_uint32_memcpy(wblock, block, SHA1_BLOCK_SIZE);
#else
	memcpy(wblock, block, SHA1_BLOCK_SIZE);
#endif

	for (t = 16; t < 80; t++)
	{
		wblock[t] = ROTL32(wblock[t - 3] ^ wblock[t - 8] ^ wblock[t - 14] ^ wblock[t - 16], 1);
	}

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	for (t = 0; t < 20; t++)
	{
		/* the following is faster than ((B & C) | ((~B) & D)) */
		temp = ROTL32(a, 5) + (((c ^ d) & b) ^ d)
			+ e + wblock[t] + 0x5A827999;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	for (t = 20; t < 40; t++)
	{
		temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[t] + 0x6ED9EBA1;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	for (t = 40; t < 60; t++)
	{
		temp = ROTL32(a, 5) + ((b & c) | (b & d) | (c & d))
			+ e + wblock[t] + 0x8F1BBCDC;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	for (t = 60; t < 80; t++)
	{
		temp = ROTL32(a, 5) + (b ^ c ^ d) + e + wblock[t] + 0xCA62C1D6;
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}



static void sha1_update(HASH_ctx *ctx,
	const unsigned char *buf,
	size_t size)
{

	ctx->length_ += size;

	//64 byte block
	while (size >= SHA1_BLOCK_SIZE)
	{
#ifdef x86ASM
		sha1_process_block_x86asm(ctx->SHA1_hash_, reinterpret_cast<const uint32_t *>(buf));
#else
		sha1_process_block(ctx->SHA1_hash_, reinterpret_cast<const uint32_t *>(buf));
#endif
		buf += SHA1_BLOCK_SIZE;
		size -= SHA1_BLOCK_SIZE;
	}

	ctx->unprocessed_ = size;
}

void sha1_update_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize)
{
	size_t i;
	for (i = 0; i < bufsize; i += SHA1_BLOCK_SIZE)
	{
#ifdef x86ASM
		sha1_process_block_x86asm(ctx->SHA1_hash_, reinterpret_cast<const uint32_t *>(buf));
#else
		sha1_process_block(ctx->SHA1_hash_, reinterpret_cast<const uint32_t *>(buf));
#endif
		buf += SHA1_BLOCK_SIZE;
		ctx->SHA1_unprocessed_ -= SHA1_BLOCK_SIZE;
	}
	return;
}


//Same as MD5
static void sha1_final(HASH_ctx *ctx,
	const unsigned char *msg,
	size_t size)
{

	uint32_t message[SHA1_BLOCK_SIZE / 4];


	if (ctx->unprocessed_)
	{
		memcpy(message, msg + size - ctx->unprocessed_, static_cast<size_t>(ctx->unprocessed_));
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
		sha1_process_block_x86asm(ctx->SHA1_hash_, message);
#else
		sha1_process_block(ctx->SHA1_hash_, message);
#endif
		index = 0;
	}


	while (index < 14)
	{
		message[index++] = 0;
	}


	uint64_t data_len = (ctx->length_) << 3;

#if BYTES_ORDER == LITTLE_ENDIAN
	data_len = SWAP_UINT64(data_len);
#endif

	message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFFULL);
	message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);
#ifdef x86ASM
	sha1_process_block_x86asm(ctx->SHA1_hash_, message);
#else
	sha1_process_block(ctx->SHA1_hash_, message);
#endif

#if BYTES_ORDER == LITTLE_ENDIAN
	swap_uint32_memcpy(&ctx->SHA1_result, &ctx->SHA1_hash_, SHA1_HASH_SIZE);
#else
	memcpy(&ctx->SHA1_result, &ctx->hash_, SHA1_HASH_SIZE);
#endif
}


void sha1_final_file(HASH_ctx *ctx, const unsigned char *buf, size_t bufsize)
{
	while (ctx->SHA1_unprocessed_ >= SHA1_BLOCK_SIZE)
	{
#ifdef x86ASM
		sha1_process_block_x86asm(ctx->SHA1_hash_, reinterpret_cast<const uint32_t *>(buf));
#else
		sha1_process_block(ctx->SHA1_hash_, reinterpret_cast<const uint32_t *>(buf));
#endif
		buf += SHA1_BLOCK_SIZE;
		ctx->SHA1_unprocessed_ -= SHA1_BLOCK_SIZE;
	}
	uint32_t message[SHA1_BLOCK_SIZE / 4];
	
	if (ctx->SHA1_unprocessed_)
	{
		memcpy(message, buf, static_cast<size_t>(ctx->SHA1_unprocessed_));
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
		sha1_process_block_x86asm(ctx->SHA1_hash_, message);
#else
		sha1_process_block(ctx->SHA1_hash_, message);
#endif
		index = 0;
	}

	
	while (index < 14)
	{
		message[index++] = 0;
	}

	uint64_t data_len = (ctx->length_) << 3;
	
#if BYTES_ORDER == LITTLE_ENDIAN
	data_len = SWAP_UINT64(data_len);
#endif

	message[14] = (uint32_t)(data_len & 0x00000000FFFFFFFF);
	message[15] = (uint32_t)((data_len & 0xFFFFFFFF00000000ULL) >> 32);

#ifdef x86ASM
	sha1_process_block_x86asm(ctx->SHA1_hash_, message);
#else
	sha1_process_block(ctx->SHA1_hash_, message);
#endif

#if BYTES_ORDER == LITTLE_ENDIAN
	swap_uint32_memcpy(&ctx->SHA1_result, &ctx->SHA1_hash_, SHA1_HASH_SIZE);
#else
	memcpy(&ctx->SHA1_result, &ctx->hash_, SHA1_HASH_SIZE);
#endif
}


//SHA1 for a memory block
unsigned char *sha1_MemBlock(const unsigned char *msg,
	size_t size,
	HASH_ctx* ctx)
{	
	sha1_init(ctx);
	sha1_update(ctx, msg, size);
	sha1_final(ctx, msg, size);
	return ctx->SHA1_result;
}
