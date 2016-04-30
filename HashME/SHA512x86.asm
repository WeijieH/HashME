void sha512_compress(uint64_t state[8], const uint8_t block[128])
{
	/* 
	 * Storage usage:
	 *   Bytes  Location    Description
	 *       4  eax         Temporary base address of state or block array arguments
	 *       4  ecx         Old value of esp
	 *       4  esp         x86 stack pointer
	 *      64  [esp+ 0]    SHA-512 state variables A,B,C,D,E,F,G,H (8 bytes each)
	 *     128  [esp+64]    Circular buffer of most recent 16 key schedule items, 8 bytes each
	 *      56  mm0..mm6    Temporary for calculation per round
	 *       8  mm7         Control value for byte endian reversal
	 *      64  xmm0..xmm3  Temporary for copying or calculation
	 */
	
	#define SCHED(i)  [((i)&0xF)*8+64+esp]
	#define STATE(i)  [i*8+esp]
	
	#define RORQ(reg, shift, temp)  \
	{\
		_asm movq   temp, reg         	\
		_asm psllq  temp, 64-shift	  	\
		_asm psrlq  reg, shift        	\
		_asm por    reg, temp			\
	}
		
	
	#define ROUNDTAIL(i, a, b, c, d, e, f, g, h)  \
	{\
		/* Part 0 */						\
		_asm paddq  mm0, STATE(h)				\
		_asm movq   mm1, STATE(e)				\
		_asm movq   mm2, mm1						\
		_asm movq   mm3, mm1						\
		RORQ(mm1, 18, mm4)					\
		RORQ(mm2, 41, mm5)					\
		RORQ(mm3, 14, mm6)					\
		_asm pxor   mm1, mm2						\
		_asm pxor   mm1, mm3						\
		_asm paddq  mm0, SHA3[i*8]		\
		_asm movq   mm2, STATE(g)				\
		_asm pxor   mm2, STATE(f)				\
		_asm pand   mm2, STATE(e)				\
		_asm pxor   mm2, STATE(g)				\
		_asm paddq  mm0, mm1						\
		_asm paddq  mm0, mm2						\
		/* Part 1 */						\
		_asm movq   mm1, STATE(d)				\
		_asm paddq  mm1, mm0						\
		_asm movq   STATE(d), mm1				\
		/* Part 2 */						\
		_asm movq   mm1, STATE(a)				\
		_asm movq   mm2, mm1						\
		_asm movq   mm3, mm1						\
		RORQ(mm1, 39, mm4)					\
		RORQ(mm2, 34, mm5)					\
		RORQ(mm3, 28, mm6)					\
		_asm pxor   mm1, mm2						\
		_asm pxor   mm1, mm3						\
		_asm movq   mm2, STATE(c)				\
		_asm paddq  mm0, mm1						\
		_asm movq   mm3, mm2						\
		_asm por    mm3, STATE(b)				\
		_asm pand   mm2, STATE(b)				\
		_asm pand   mm3, STATE(a)				\
		_asm por    mm3, mm2						\
		_asm paddq  mm0, mm3						\
		_asm movq   STATE(h), mm0				\	
	}
	
	#define ROUNDa(i, a, b, c, d, e, f, g, h)  \
	{\
		_asm movq    mm0, [i*8+eax]		\
		_asm pshufb  mm0, mm7         	\
		_asm movq    SCHED(i), mm0   	\
		ROUNDTAIL(i, a, b, c, d, e, f, g, h)\
	}
		
	
	#define ROUNDb(i, a, b, c, d, e, f, g, h)  \
	{\
		_asm movq   mm0, SCHED(i-16)			\
		_asm paddq  mm0, SCHED(i- 7)			\
		_asm movq   mm1, SCHED(i-15)			\
		_asm movq   mm2, mm1					\
		_asm movq   mm3, mm1					\
		RORQ(mm1, 1, mm5)          		\
		RORQ(mm2, 8, mm4)          		\
		_asm psrlq  mm3, 7					\
		_asm pxor   mm2, mm3					\
		_asm pxor   mm1, mm2					\
		_asm paddq  mm0, mm1					\
		_asm movq   mm1, SCHED(i- 2)			\
		_asm movq   mm2, mm1					\
		_asm movq   mm3, mm1					\
		_asm RORQ(mm1, 19, mm5)				\
		_asm RORQ(mm2, 61, mm4)				\
		_asm psrlq  mm3, 6					\
		_asm pxor   mm2, mm3					\
		_asm pxor   mm1, mm2					\
		_asm paddq  mm0, mm1					\
		_asm movq   SCHED(i), mm0			\
		ROUNDTAIL(i, a, b, c, d, e, f, g, h)\
	}
				
	_asm
	{
	/* Allocate 16-byte aligned scratch space */
	mov   ecx, esp
	sub   esp, 192
	and   esp, ~0xF
	
	/* Copy state */
	mov   eax, dword ptr [ecx+4]
	movdqu xmm0, [eax + 0]
	movdqu xmm1, [eax + 16]
	movdqu xmm2, [eax + 32]
	movdqu xmm3, [eax + 48]
	
	/* Do 80 rounds of hashing */
	mov   eax, dword ptr [ecx + 8]
	movq  mm7, 0x0001020304050607ULL
	}
	ROUNDa( 0, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDa( 1, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDa( 2, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDa( 3, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDa( 4, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDa( 5, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDa( 6, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDa( 7, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDa( 8, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDa( 9, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDa(10, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDa(11, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDa(12, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDa(13, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDa(14, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDa(15, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(16, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(17, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(18, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(19, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(20, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(21, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(22, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(23, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(24, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(25, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(26, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(27, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(28, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(29, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(30, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(31, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(32, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(33, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(34, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(35, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(36, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(37, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(38, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(39, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(40, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(41, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(42, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(43, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(44, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(45, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(46, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(47, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(48, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(49, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(50, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(51, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(52, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(53, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(54, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(55, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(56, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(57, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(58, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(59, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(60, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(61, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(62, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(63, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(64, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(65, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(66, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(67, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(68, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(69, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(70, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(71, 1, 2, 3, 4, 5, 6, 7, 0)
	ROUNDb(72, 0, 1, 2, 3, 4, 5, 6, 7)
	ROUNDb(73, 7, 0, 1, 2, 3, 4, 5, 6)
	ROUNDb(74, 6, 7, 0, 1, 2, 3, 4, 5)
	ROUNDb(75, 5, 6, 7, 0, 1, 2, 3, 4)
	ROUNDb(76, 4, 5, 6, 7, 0, 1, 2, 3)
	ROUNDb(77, 3, 4, 5, 6, 7, 0, 1, 2)
	ROUNDb(78, 2, 3, 4, 5, 6, 7, 0, 1)
	ROUNDb(79, 1, 2, 3, 4, 5, 6, 7, 0)
	
	_asm
	{
	/* Add to state */
	movl   eax, dword ptr [ecx + 4]
	movdqu xmm0, [eax + 0]
	movdqu xmm1, [eax + 16]
	movdqu xmm2, [eax + 32]
	movdqu xmm3, [eax + 48]
	
	/* Clean up */
	emms
	mov   esp, ecx
	}
}