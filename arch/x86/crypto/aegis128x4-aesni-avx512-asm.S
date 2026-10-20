/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * VAES + AVX512 implementation of AEGIS-128X4
 *
 * AEGIS-128X4 is the 4-way parallel variant of AEGIS-128L defined in
 * draft-irtf-cfrg-aegis-aead.  Each of the eight state words is a 512-bit
 * vector holding the corresponding word of four independent AEGIS-128L
 * states, one per 128-bit lane, so that every AES round in the update function
 * is computed with a single VAESENC on a zmm register.
 *
 * Based on the libaegis AVX512 implementation
 * (https://github.com/aegis-aead/libaegis).
 *
 * Copyright (c) 2023-2026 Frank Denis
 * Copyright (c) 2026 Antonio Quartulli <antonio@mandelbit.com>
 */

#include <linux/linkage.h>

#define STATE0		%zmm0
#define STATE1		%zmm1
#define STATE2		%zmm2
#define STATE3		%zmm3
#define STATE4		%zmm4
#define STATE5		%zmm5
#define STATE6		%zmm6
#define STATE7		%zmm7
#define MSG0		%zmm8
#define MSG1		%zmm9
#define T0		%zmm10
#define T1		%zmm11
#define T2		%zmm12
#define T3		%zmm13
#define ZERO		%zmm15
#define ZERO_XMM	%xmm15

/* Size of the AEGIS-128X4 rate, i.e. of the data absorbed by one update */
#define RATE		128

.section .rodata.cst32.aegis128x4_const, "aM", @progbits, 32
.align 16
.Laegis128x4_const_0:
	.byte 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d
	.byte 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
.Laegis128x4_const_1:
	.byte 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1
	.byte 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd

/*
 * Per-lane context injected during initialization: byte 0 is the lane index,
 * byte 1 is the number of lanes minus one.
 */
.section .rodata.cst64.aegis128x4_ctx, "aM", @progbits, 64
.align 64
.Laegis128x4_ctx:
	.octa 0x0300
	.octa 0x0301
	.octa 0x0302
	.octa 0x0303

.text

/*
 * aegis128x4_update
 * input:
 *   STATE[0-7] - input state
 *   m0, m1     - message vectors (128 bytes in total)
 *   ZERO       - all-zeroes vector
 * output:
 *   STATE[0-7] - output state (same positions)
 * changed:
 *   T0, T1
 *
 * AESENC(x, k) == AESENC(x, 0) ^ k, therefore the two words that absorb the
 * message are computed as AESENC(x, 0) ^ S ^ M with a single VPTERNLOGQ, which
 * also allows updating every state word in place.
 */
.macro aegis128x4_update m0, m1
	vaesenc		ZERO, STATE7, T0
	vaesenc		ZERO, STATE3, T1
	vaesenc		STATE7, STATE6, STATE7
	vaesenc		STATE6, STATE5, STATE6
	vaesenc		STATE5, STATE4, STATE5
	vpternlogq	$0x96, \m1, T1, STATE4
	vaesenc		STATE3, STATE2, STATE3
	vaesenc		STATE2, STATE1, STATE2
	vaesenc		STATE1, STATE0, STATE1
	vpternlogq	$0x96, \m0, T0, STATE0
.endm

/*
 * Initialize STATE[0-7] from the key at KEYP and the nonce at IVP, and set
 * ZERO.  Changed: MSG0, MSG1, T0-T2.
 */
.macro aegis128x4_init
	vpxor		ZERO_XMM, ZERO_XMM, ZERO_XMM

	/* broadcast nonce and key to the four lanes: */
	vbroadcasti32x4	(IVP), MSG0
	vbroadcasti32x4	(KEYP), MSG1

	/* load the constants: */
	vbroadcasti32x4	.Laegis128x4_const_0(%rip), STATE2
	vbroadcasti32x4	.Laegis128x4_const_1(%rip), STATE1
	vmovdqa64	.Laegis128x4_ctx(%rip), T2

	vpxorq		MSG0, MSG1, STATE0	/* key ^ nonce */
	vmovdqa64	STATE0, STATE4		/* key ^ nonce */
	vmovdqa64	STATE1, STATE3		/* c1 */
	vpxorq		STATE2, MSG1, STATE5	/* key ^ c0 */
	vpxorq		STATE1, MSG1, STATE6	/* key ^ c1 */
	vmovdqa64	STATE5, STATE7		/* key ^ c0 */

	/* update 10 times with nonce / key: */
	.rept 10
	vpxorq		T2, STATE3, STATE3
	vpxorq		T2, STATE7, STATE7
	aegis128x4_update MSG0, MSG1
	.endr
.endm

/*
 * Encrypt (\enc=1) or decrypt (\enc=0) the 128 bytes in MSG0/MSG1 in place
 * using the keystream of the current state:
 *   z0 = S1 ^ S6 ^ (S2 & S3)
 *   z1 = S2 ^ S5 ^ (S6 & S7)
 * On encryption the result goes to T2/T3 and MSG0/MSG1 keep the plaintext.
 * On decryption MSG0/MSG1 are replaced by the plaintext.
 */
.macro crypt_msg enc
.if \enc
	vmovdqa64	STATE2, T2
	vmovdqa64	STATE6, T3
	vpternlogq	$0x6a, MSG0, STATE3, T2		/* (A & B) ^ C */
	vpternlogq	$0x6a, MSG1, STATE7, T3
	vpternlogq	$0x96, STATE6, STATE1, T2
	vpternlogq	$0x96, STATE5, STATE2, T3
.else
	vpternlogq	$0x78, STATE3, STATE2, MSG0	/* A ^ (B & C) */
	vpternlogq	$0x78, STATE7, STATE6, MSG1
	vpternlogq	$0x96, STATE6, STATE1, MSG0
	vpternlogq	$0x96, STATE5, STATE2, MSG1
.endif
.endm

/*
 * Encrypt or decrypt the 128-byte block at SRC into DST and absorb the
 * plaintext.  Changed: MSG0, MSG1, T0-T3.
 */
.macro crypt_block enc
	vmovdqu64	0x00(SRC), MSG0
	vmovdqu64	0x40(SRC), MSG1
	crypt_msg	\enc
.if \enc
	vmovdqu64	T2, 0x00(DST)
	vmovdqu64	T3, 0x40(DST)
.else
	vmovdqu64	MSG0, 0x00(DST)
	vmovdqu64	MSG1, 0x40(DST)
.endif
	aegis128x4_update MSG0, MSG1
.endm

/*
 * Encrypt or decrypt the partial block at SRC into DST and absorb the
 * zero-padded plaintext.  %k1 and %k2 must hold the masks set up by
 * tail_masks.  Changed: MSG0, MSG1, T0-T3.
 */
.macro crypt_tail enc
	/* masked loads zero the padding and never fault past the end */
	vmovdqu8	0x00(SRC), MSG0{%k1}{z}
	vmovdqu8	0x40(SRC), MSG1{%k2}{z}
	crypt_msg	\enc
.if \enc
	vmovdqu8	T2, 0x00(DST){%k1}
	vmovdqu8	T3, 0x40(DST){%k2}
.else
	vmovdqu8	MSG0, 0x00(DST){%k1}
	vmovdqu8	MSG1, 0x40(DST){%k2}
	/* zero the keystream bytes past the end before absorbing: */
	vmovdqu8	MSG0, MSG0{%k1}{z}
	vmovdqu8	MSG1, MSG1{%k2}{z}
.endif
	aegis128x4_update MSG0, MSG1
.endm

/*
 * Encrypt or decrypt LEN bytes (nonzero multiple of RATE) from SRC to DST,
 * advancing SRC and DST.  LEN is zero on exit.
 */
.macro crypt_loop enc
.Lcrypt\@:
	crypt_block	\enc
	add		$RATE, SRC
	add		$RATE, DST
	sub		$RATE, LEN
	jnz		.Lcrypt\@
.endm

/* Absorb the 128-byte block at \src. */
.macro ad_block src
	vmovdqu64	0x00(\src), MSG0
	vmovdqu64	0x40(\src), MSG1
	aegis128x4_update MSG0, MSG1
.endm

.macro load_state
	vmovdqu64	0x000(STATEP), STATE0
	vmovdqu64	0x040(STATEP), STATE1
	vmovdqu64	0x080(STATEP), STATE2
	vmovdqu64	0x0c0(STATEP), STATE3
	vmovdqu64	0x100(STATEP), STATE4
	vmovdqu64	0x140(STATEP), STATE5
	vmovdqu64	0x180(STATEP), STATE6
	vmovdqu64	0x1c0(STATEP), STATE7
.endm

.macro store_state
	vmovdqu64	STATE0, 0x000(STATEP)
	vmovdqu64	STATE1, 0x040(STATEP)
	vmovdqu64	STATE2, 0x080(STATEP)
	vmovdqu64	STATE3, 0x0c0(STATEP)
	vmovdqu64	STATE4, 0x100(STATEP)
	vmovdqu64	STATE5, 0x140(STATEP)
	vmovdqu64	STATE6, 0x180(STATEP)
	vmovdqu64	STATE7, 0x1c0(STATEP)
.endm

/*
 * Set %k1 and %k2 to the byte masks covering the first \len bytes of a
 * 128-byte block, split into its two 64-byte halves.  1 <= \len <= 127.
 * \len is a 32-bit register and \len64 its 64-bit alias; both are clobbered,
 * as well as %rax and %r11.
 */
.macro tail_masks len, len64
	mov		$-1, %rax
	bzhi		\len64, %rax, %r11	/* bzhi only uses bits [7:0] */
	kmovq		%r11, %k1
	xor		%r11d, %r11d
	sub		$64, \len
	cmovl		%r11d, \len
	bzhi		\len64, %rax, %rax
	kmovq		%rax, %k2
.endm

/*
 * XOR the four 128-bit lanes of the zmm register \z together into the xmm
 * register \x (the low part of \z).  \y is the ymm alias of \z.
 */
.macro fold_lanes z, y, x, tmpy, tmpx
	vextracti64x4	$1, \z, \tmpy
	vpxor		\tmpy, \y, \y
	vextracti128	$1, \y, \tmpx
	vpxor		\tmpx, \x, \x
.endm

/*
 * Finalize and XOR the tag into the first AUTHSIZE (16 or 32) bytes at
 * TAG_XOR, then return.  ASSOCLEN and CRYPTLEN are 32-bit registers.
 * Changed: %rax, %r9, MSG0 and all the state.
 */
.macro aegis128x4_final_and_ret
	/* t = S2 ^ (LE64(assoclen * 8) || LE64(cryptlen * 8)) in each lane */
	mov		ASSOCLEN, %eax
	shl		$3, %rax
	mov		CRYPTLEN, %r9d
	shl		$3, %r9
	vmovq		%rax, %xmm8
	vpinsrq		$1, %r9, %xmm8, %xmm8
	vshufi64x2	$0, MSG0, MSG0, MSG0
	vpxorq		STATE2, MSG0, MSG0

	.rept 7
	aegis128x4_update MSG0, MSG0
	.endr

	cmp		$16, AUTHSIZE
	jne		.Lfinal_256\@

	/* tag = fold(S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6) */
	vpternlogq	$0x96, STATE2, STATE1, STATE0
	vpternlogq	$0x96, STATE4, STATE3, STATE0
	vpternlogq	$0x96, STATE6, STATE5, STATE0
	fold_lanes	STATE0, %ymm0, %xmm0, %ymm10, %xmm10
	vpxor		0x00(TAG_XOR), %xmm0, %xmm0
	vmovdqu		%xmm0, 0x00(TAG_XOR)
	vzeroupper	// This is needed after using ymm or zmm registers.
	RET

.Lfinal_256\@:
	/* tag = fold(S0 ^ S1 ^ S2 ^ S3) || fold(S4 ^ S5 ^ S6 ^ S7) */
	vpternlogq	$0x96, STATE2, STATE1, STATE0
	vpxorq		STATE3, STATE0, STATE0
	vpternlogq	$0x96, STATE6, STATE5, STATE4
	vpxorq		STATE7, STATE4, STATE4
	fold_lanes	STATE0, %ymm0, %xmm0, %ymm10, %xmm10
	fold_lanes	STATE4, %ymm4, %xmm4, %ymm11, %xmm11
	vpxor		0x00(TAG_XOR), %xmm0, %xmm0
	vpxor		0x10(TAG_XOR), %xmm4, %xmm4
	vmovdqu		%xmm0, 0x00(TAG_XOR)
	vmovdqu		%xmm4, 0x10(TAG_XOR)
	vzeroupper	// This is needed after using ymm or zmm registers.
	RET
.endm

/*
 * void aegis128x4_aesni_avx512_init(struct aegis128x4_state *state,
 *				     const u8 key[AEGIS128X4_KEY_SIZE],
 *				     const u8 iv[AEGIS128X4_NONCE_SIZE]);
 */
SYM_FUNC_START(aegis128x4_aesni_avx512_init)
	.set STATEP, %rdi
	.set KEYP, %rsi
	.set IVP, %rdx

	aegis128x4_init
	store_state
	vzeroupper	// This is needed after using ymm or zmm registers.
	RET
SYM_FUNC_END(aegis128x4_aesni_avx512_init)

/*
 * void aegis128x4_aesni_avx512_ad(struct aegis128x4_state *state,
 *				   const u8 *data, unsigned int len);
 *
 * len must be a multiple of 128.
 */
SYM_FUNC_START(aegis128x4_aesni_avx512_ad)
	.set STATEP, %rdi
	.set SRC, %rsi
	.set LEN, %edx

	test		LEN, LEN
	jz		.Lad_out

	vpxor		ZERO_XMM, ZERO_XMM, ZERO_XMM
	load_state
.Lad_loop:
	ad_block	SRC
	add		$RATE, SRC
	sub		$RATE, LEN
	jnz		.Lad_loop

	store_state
	vzeroupper	// This is needed after using ymm or zmm registers.
.Lad_out:
	RET
SYM_FUNC_END(aegis128x4_aesni_avx512_ad)

/*
 * void aegis128x4_aesni_avx512_enc(struct aegis128x4_state *state,
 *				    const u8 *src, u8 *dst, unsigned int len);
 * void aegis128x4_aesni_avx512_dec(struct aegis128x4_state *state,
 *				    const u8 *src, u8 *dst, unsigned int len);
 *
 * len must be nonzero and a multiple of 128.
 */
.macro aegis128x4_crypt enc
	.set STATEP, %rdi
	.set SRC, %rsi
	.set DST, %rdx
	.set LEN, %ecx

	vpxor		ZERO_XMM, ZERO_XMM, ZERO_XMM
	load_state
	crypt_loop	\enc
	store_state
	vzeroupper	// This is needed after using ymm or zmm registers.
	RET
.endm

SYM_FUNC_START(aegis128x4_aesni_avx512_enc)
	aegis128x4_crypt 1
SYM_FUNC_END(aegis128x4_aesni_avx512_enc)

SYM_FUNC_START(aegis128x4_aesni_avx512_dec)
	aegis128x4_crypt 0
SYM_FUNC_END(aegis128x4_aesni_avx512_dec)

/*
 * void aegis128x4_aesni_avx512_enc_tail(struct aegis128x4_state *state,
 *					 const u8 *src, u8 *dst,
 *					 unsigned int len);
 * void aegis128x4_aesni_avx512_dec_tail(struct aegis128x4_state *state,
 *					 const u8 *src, u8 *dst,
 *					 unsigned int len);
 *
 * 1 <= len < 128.
 */
.macro aegis128x4_crypt_tail enc
	.set STATEP, %rdi
	.set SRC, %rsi
	.set DST, %rdx

	tail_masks	%ecx, %rcx
	vpxor		ZERO_XMM, ZERO_XMM, ZERO_XMM
	load_state
	crypt_tail	\enc
	store_state
	vzeroupper	// This is needed after using ymm or zmm registers.
	RET
.endm

SYM_FUNC_START(aegis128x4_aesni_avx512_enc_tail)
	aegis128x4_crypt_tail 1
SYM_FUNC_END(aegis128x4_aesni_avx512_enc_tail)

SYM_FUNC_START(aegis128x4_aesni_avx512_dec_tail)
	aegis128x4_crypt_tail 0
SYM_FUNC_END(aegis128x4_aesni_avx512_dec_tail)

/*
 * void aegis128x4_aesni_avx512_final(struct aegis128x4_state *state,
 *				      u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
 *				      unsigned int assoclen,
 *				      unsigned int cryptlen,
 *				      unsigned int authsize);
 *
 * authsize must be 16 or 32.  The computed tag is XOR'ed into the first
 * authsize bytes of tag_xor.
 */
SYM_FUNC_START(aegis128x4_aesni_avx512_final)
	.set STATEP, %rdi
	.set TAG_XOR, %rsi
	.set ASSOCLEN, %edx
	.set CRYPTLEN, %ecx
	.set AUTHSIZE, %r8d

	vpxor		ZERO_XMM, ZERO_XMM, ZERO_XMM
	load_state
	aegis128x4_final_and_ret
SYM_FUNC_END(aegis128x4_aesni_avx512_final)

/*
 * void aegis128x4_aesni_avx512_enc_oneshot(const u8 key[AEGIS128X4_KEY_SIZE],
 *					    const u8 iv[AEGIS128X4_NONCE_SIZE],
 *					    const u8 *ad, unsigned int adlen,
 *					    const u8 *src, u8 *dst,
 *					    unsigned int len,
 *					    u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
 *					    unsigned int authsize);
 * void aegis128x4_aesni_avx512_dec_oneshot(...same arguments...);
 *
 * Process a whole request whose associated data and payload are each
 * contiguous, keeping the state in registers throughout.  Any adlen and len
 * are allowed.  authsize must be 16 or 32, and the computed tag is XOR'ed into
 * the first authsize bytes of tag_xor.
 */
.macro aegis128x4_oneshot enc
	.set KEYP, %rdi
	.set IVP, %rsi
	.set ADP, %rdx
	.set ASSOCLEN, %r10d
	.set SRC, %r8
	.set DST, %r9
	.set LEN, %ecx
	.set TAILLEN, %esi

	mov		%ecx, ASSOCLEN
	aegis128x4_init			/* KEYP and IVP are free after this */

	/* absorb the associated data: */
	cmp		$RATE, %ecx
	jb		.Lad_tail\@
.Lad_loop\@:
	ad_block	ADP
	add		$RATE, ADP
	sub		$RATE, %ecx
	cmp		$RATE, %ecx
	jae		.Lad_loop\@
.Lad_tail\@:
	test		%ecx, %ecx
	jz		.Lad_done\@
	tail_masks	%ecx, %rcx
	vmovdqu8	0x00(ADP), MSG0{%k1}{z}
	vmovdqu8	0x40(ADP), MSG1{%k2}{z}
	aegis128x4_update MSG0, MSG1
.Lad_done\@:

	/*
	 * en/decrypt the payload; len, tag_xor and authsize are passed on the
	 * stack at 8(%rsp), 16(%rsp) and 24(%rsp) respectively.
	 */
	mov		8(%rsp), LEN
	mov		LEN, TAILLEN
	and		$RATE - 1, TAILLEN
	and		$~(RATE - 1), LEN
	jz		.Lcrypt_tail\@
	crypt_loop	\enc
.Lcrypt_tail\@:
	test		TAILLEN, TAILLEN
	jz		.Lcrypt_done\@
	tail_masks	TAILLEN, %rsi
	crypt_tail	\enc
.Lcrypt_done\@:

	.set TAG_XOR, %rdi
	.set CRYPTLEN, %ecx
	.set AUTHSIZE, %r8d
	mov		16(%rsp), TAG_XOR
	mov		8(%rsp), CRYPTLEN
	mov		24(%rsp), AUTHSIZE
	aegis128x4_final_and_ret
.endm

SYM_FUNC_START(aegis128x4_aesni_avx512_enc_oneshot)
	aegis128x4_oneshot 1
SYM_FUNC_END(aegis128x4_aesni_avx512_enc_oneshot)

SYM_FUNC_START(aegis128x4_aesni_avx512_dec_oneshot)
	aegis128x4_oneshot 0
SYM_FUNC_END(aegis128x4_aesni_avx512_dec_oneshot)
