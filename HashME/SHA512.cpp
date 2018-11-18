#include "SHA3.h"

void sha512_init(HASH_ctx* ctx)
{
    ctx->length_ = 0;
    ctx->unprocessed_ = 0;

    ctx->SHA512_hash_[0] = 0x6a09e667f3bcc908ULL;
    ctx->SHA512_hash_[1] = 0xbb67ae8584caa73bULL;
    ctx->SHA512_hash_[2] = 0x3c6ef372fe94f82bULL;
    ctx->SHA512_hash_[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->SHA512_hash_[4] = 0x510e527fade682d1ULL;
    ctx->SHA512_hash_[5] = 0x9b05688c2b3e6c1fULL;
    ctx->SHA512_hash_[6] = 0x1f83d9abfb41bd6bULL;
    ctx->SHA512_hash_[7] = 0x5be0cd19137e2179ULL;
}

void sha512_init_file(HASH_ctx* ctx, uint64_t filesize)
{
    ctx->SHA512_unprocessed_ = filesize;

    ctx->SHA512_hash_[0] = 0x6a09e667f3bcc908ULL;
    ctx->SHA512_hash_[1] = 0xbb67ae8584caa73bULL;
    ctx->SHA512_hash_[2] = 0x3c6ef372fe94f82bULL;
    ctx->SHA512_hash_[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->SHA512_hash_[4] = 0x510e527fade682d1ULL;
    ctx->SHA512_hash_[5] = 0x9b05688c2b3e6c1fULL;
    ctx->SHA512_hash_[6] = 0x1f83d9abfb41bd6bULL;
    ctx->SHA512_hash_[7] = 0x5be0cd19137e2179ULL;
}

void sha512_process_block(uint64_t hash[8], const uint64_t block[SHA512_BLOCK_SIZE / 8])
{
    uint64_t w[80];
    uint64_t register wv[8];
    uint64_t register t1, t2;
    int j;

    swap_uint64_memcpy(w, block, SHA512_BLOCK_SIZE);
    for (j = 16; j < 80; j++)
    {
        w[j] = SHA3_F4(w[j - 2]) + w[j - 7] + SHA3_F3(w[j - 15]) + w[j - 16];
    }
    for (j = 0; j < 8; j++)
    {
        wv[j] = hash[j];
    }
    for (j = 0; j < 80; j++)
    {
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
    for (j = 0; j < 8; j++)
    {
        hash[j] += wv[j];
    }
}

// void sha512_process_block_asmx86(uint64_t hash[8], const uint64_t
// block[SHA512_BLOCK_SIZE / 8])
//{
//	/*
//	* Storage usage:
//	*   Bytes  Location    Description
//	*       4  eax         Temporary base address of state or block array
// arguments 	*       4  ecx         Old value of esp 	*       4  esp
// x86 stack pointer 	*      64  [esp+ 0]    SHA-512 state variables
// A,B,C,D,E,F,G,H (8 bytes each) 	*     128  [esp+64]    Circular buffer
// of most recent 16 key schedule items, 8 bytes each 	*      56  mm0..mm6
// Temporary for calculation per round 	*       8  mm7         Control value for
// byte endian reversal 	*      64  xmm0..xmm3  Temporary for copying or
// calculation
//	*/
//
//	#define SCHED(i)  qword ptr[((i)&15)*8+64+esp]
//	#define STATE(i)  qword ptr[i*8+esp]
//
//	#define RORQ(reg, shift, temp)  \
//		{\
//			_asm movq   temp, reg         	\
//			_asm psllq  temp, 64-shift	  	\
//			_asm psrlq  reg, shift        	\
//			_asm por    reg, temp			\
//		}
//
//
//	#define ROUNDTAIL(i, a, b, c, d, e, f, g, h)  \
//		{\
//			/* Part 0 */ \
//			_asm paddq  mm0, STATE(h)			\
//			_asm movq   mm1, STATE(e)			\
//			_asm movq   mm2, mm1				\
//			_asm movq   mm3, mm1				\
//			RORQ(mm1, 18, mm4) \
//			RORQ(mm2, 41, mm5) \
//			RORQ(mm3, 14, mm6) \
//			_asm pxor   mm1, mm2				\
//			_asm pxor   mm1, mm3				\
//			_asm paddq  mm0, qword ptr[SHA3+i*8] \
//			_asm movq   mm2, STATE(g)			\
//			_asm pxor   mm2, STATE(f)			\
//			_asm pand   mm2, STATE(e)			\
//			_asm pxor   mm2, STATE(g)			\
//			_asm paddq  mm0, mm1				\
//			_asm paddq  mm0, mm2				\
//			/* Part 1 */ \
//			_asm movq   mm1, STATE(d)			\
//			_asm paddq  mm1, mm0				\
//			_asm movq   STATE(d), mm1			\
//			/* Part 2 */ \
//			_asm movq   mm1, STATE(a)			\
//			_asm movq   mm2, mm1				\
//			_asm movq   mm3, mm1				\
//			RORQ(mm1, 39, mm4) \
//			RORQ(mm2, 34, mm5) \
//			RORQ(mm3, 28, mm6) \
//			_asm pxor   mm1, mm2				\
//			_asm pxor   mm1, mm3				\
//			_asm movq   mm2, STATE(c)			\
//			_asm paddq  mm0, mm1				\
//			_asm movq   mm3, mm2				\
//			_asm por    mm3, STATE(b)			\
//			_asm pand   mm2, STATE(b)			\
//			_asm pand   mm3, STATE(a)			\
//			_asm por    mm3, mm2				\
//			_asm paddq  mm0, mm3				\
//			_asm movq   STATE(h), mm0			\	
//		}
//
//	#define ROUNDa(i, a, b, c, d, e, f, g, h)  \
//		{\
//			_asm movq    mm0, qword ptr[i*8+eax]		\
//			_asm pshufb  mm0, mm7         	\
//			_asm movq    SCHED(i), mm0   	\
//			ROUNDTAIL(i, a, b, c, d, e, f, g, h)\
//		}
//
//
//	#define ROUNDb(i, a, b, c, d, e, f, g, h)  \
//		{\
//			_asm movq   mm0, SCHED(i-16)		\
//			_asm paddq  mm0, SCHED(i- 7)		\
//			_asm movq   mm1, SCHED(i-15)		\
//			_asm movq   mm2, mm1				\
//			_asm movq   mm3, mm1				\
//			RORQ(mm1, 1, mm5)          			\
//			RORQ(mm2, 8, mm4)          			\
//			_asm psrlq  mm3, 7 \
//			_asm pxor   mm2, mm3				\
//			_asm pxor   mm1, mm2				\
//			_asm paddq  mm0, mm1				\
//			_asm movq   mm1, SCHED(i- 2)		\
//			_asm movq   mm2, mm1				\
//			_asm movq   mm3, mm1				\
//			_asm RORQ(mm1, 19, mm5)				\
//			_asm RORQ(mm2, 61, mm4)				\
//			_asm psrlq  mm3, 6 \
//			_asm pxor   mm2, mm3				\
//			_asm pxor   mm1, mm2				\
//			_asm paddq  mm0, mm1				\
//			_asm movq   SCHED(i), mm0			\
//			ROUNDTAIL(i, a, b, c, d, e, f, g, h)\
//	}
//
//	_asm
//	{
//		/* Allocate 16-byte aligned scratch space */
//		mov   ecx, esp
//		sub   esp, 192
//		and esp, ~0xF
//
//		/* Copy state */
//		mov   eax, dword ptr[ecx + 4]
//		movdqu xmm0, qword ptr[eax + 0]
//		movdqu xmm1, qword ptr[eax + 16]
//		movdqu xmm2, qword ptr[eax + 32]
//		movdqu xmm3, qword ptr[eax + 48]
//
//		/* Do 80 rounds of hashing */
//		mov   eax, dword ptr[ecx + 8]
//		movq  mm7, 0x0001020304050607ULL
//	}
//	ROUNDa(0, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDa(1, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDa(2, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDa(3, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDa(4, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDa(5, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDa(6, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDa(7, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDa(8, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDa(9, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDa(10, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDa(11, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDa(12, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDa(13, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDa(14, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDa(15, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(16, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(17, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(18, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(19, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(20, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(21, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(22, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(23, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(24, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(25, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(26, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(27, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(28, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(29, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(30, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(31, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(32, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(33, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(34, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(35, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(36, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(37, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(38, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(39, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(40, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(41, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(42, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(43, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(44, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(45, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(46, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(47, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(48, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(49, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(50, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(51, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(52, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(53, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(54, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(55, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(56, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(57, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(58, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(59, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(60, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(61, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(62, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(63, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(64, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(65, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(66, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(67, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(68, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(69, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(70, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(71, 1, 2, 3, 4, 5, 6, 7, 0)
//	ROUNDb(72, 0, 1, 2, 3, 4, 5, 6, 7)
//	ROUNDb(73, 7, 0, 1, 2, 3, 4, 5, 6)
//	ROUNDb(74, 6, 7, 0, 1, 2, 3, 4, 5)
//	ROUNDb(75, 5, 6, 7, 0, 1, 2, 3, 4)
//	ROUNDb(76, 4, 5, 6, 7, 0, 1, 2, 3)
//	ROUNDb(77, 3, 4, 5, 6, 7, 0, 1, 2)
//	ROUNDb(78, 2, 3, 4, 5, 6, 7, 0, 1)
//	ROUNDb(79, 1, 2, 3, 4, 5, 6, 7, 0)
//
//	_asm
//	{
//		/* Add to state */
//		mov eax, dword ptr[ecx + 4]
//		movdqu xmm0, [eax + 0]
//		movdqu xmm1, [eax + 16]
//		movdqu xmm2, [eax + 32]
//		movdqu xmm3, [eax + 48]
//
//		/* Clean up */
//		emms
//		mov esp, ecx
//	}
//}

void sha512_update(HASH_ctx* ctx, const unsigned char* buf, uint32_t size)
{
    ctx->length_ += size;

    while (size >= SHA512_BLOCK_SIZE)
    {
        sha512_process_block(ctx->SHA512_hash_, reinterpret_cast<const uint64_t*>(buf));
        buf += SHA512_BLOCK_SIZE;
        size -= SHA512_BLOCK_SIZE;
    }

    ctx->unprocessed_ = size;
}

void sha512_update_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize)
{
    size_t i;
    for (i = 0; i < bufsize; i += SHA512_BLOCK_SIZE)
    {
        sha512_process_block(ctx->SHA512_hash_, reinterpret_cast<const uint64_t*>(buf));
        buf += SHA512_BLOCK_SIZE;
        ctx->SHA512_unprocessed_ -= SHA512_BLOCK_SIZE;
    }
    return;
}

void sha512_final(HASH_ctx* ctx, const unsigned char* msg, size_t size)
{
    uint64_t message[SHA512_BLOCK_SIZE / 8];

    if (ctx->unprocessed_)
    {
        memcpy(message, msg + size - ctx->unprocessed_, static_cast<size_t>(ctx->unprocessed_));
    }

    uint32_t index = ((uint64_t)ctx->length_ & 127) >> 3;
    uint32_t shift = ((uint64_t)ctx->length_ & 7) * 8;

    message[index] &= ~(0xFFFFFFFFFFFFFFFFULL << shift);
    message[index++] ^= 0x80ULL << shift;

    if (index > 14)
    {
        while (index < 16)
        {
            message[index++] = 0;
        }

        sha512_process_block(ctx->SHA384_hash_, message);
        index = 0;
    }

    while (index < 14)
    {
        message[index++] = 0;
    }

    // length in bit = length in char * 8
    uint64_t data_len = (ctx->length_) << 3;
    data_len = SWAP_UINT64(data_len);

    // store the size, only consider data_len < 2^64, so message[14] is always 0
    message[14] = 0x0ULL;
    message[15] = data_len;

    sha512_process_block(ctx->SHA512_hash_, message);

    swap_uint64_memcpy(&ctx->SHA512_result, &ctx->SHA512_hash_, SHA512_HASH_SIZE);
}

void sha512_final_file(HASH_ctx* ctx, const unsigned char* buf, size_t bufsize)
{
    while (ctx->SHA512_unprocessed_ >= SHA512_BLOCK_SIZE)
    {
        sha512_process_block(ctx->SHA512_hash_, reinterpret_cast<const uint64_t*>(buf));
        buf += SHA512_BLOCK_SIZE;
        ctx->SHA512_unprocessed_ -= SHA512_BLOCK_SIZE;
    }
    uint64_t message[SHA512_BLOCK_SIZE / 8];

    if (ctx->SHA512_unprocessed_)
    {
        memcpy(message, buf, static_cast<size_t>(ctx->SHA512_unprocessed_));
    }

    // The final SHA3 block size will be 0~127, then devide by 8 (sizeof uint64)
    // to get index
    uint32_t index = ((uint64_t)ctx->length_ & 127) >> 3;
    // shift of uint64 will be ranged from 0 to 7, times 8 to convert the unit to
    // bit
    uint32_t shift = ((uint64_t)ctx->length_ & 7) * 8;

    message[index] &= ~(0xFFFFFFFFFFFFFFFFULL << shift);
    message[index++] ^= 0x80ULL << shift;

    if (index > 14)
    {
        while (index < 16)
        {
            message[index++] = 0;
        }

        sha512_process_block(ctx->SHA512_hash_, message);
        index = 0;
    }

    while (index < 14)
    {
        message[index++] = 0;
    }

    // length in bit = length in char * 8
    uint64_t data_len = (ctx->length_) << 3;
    data_len = SWAP_UINT64(data_len);

    // store the size, only consider data_len < 2^64, so message[14] is always 0
    message[14] = 0x0ULL;
    message[15] = data_len;

    sha512_process_block(ctx->SHA512_hash_, message);

    swap_uint64_memcpy(&ctx->SHA512_result, &ctx->SHA512_hash_, SHA512_HASH_SIZE);
}

unsigned char* sha512_MemBlock(const unsigned char* msg, size_t size, HASH_ctx* ctx)
{
    sha512_init(ctx);
    sha512_update(ctx, msg, size);
    sha512_final(ctx, msg, size);
    return ctx->SHA512_result;
}
