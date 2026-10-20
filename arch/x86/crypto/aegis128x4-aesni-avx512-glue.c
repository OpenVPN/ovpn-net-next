// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * The AEGIS-128X4 Authenticated-Encryption Algorithm
 *   Glue for VAES + AVX512 implementation
 *
 * Based on the AEGIS-128 AES-NI glue code and on libaegis
 * (https://github.com/aegis-aead/libaegis).
 *
 * Copyright (c) 2017-2018 Ondrej Mosnacek <omosnacek@gmail.com>
 * Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
 * Copyright (c) 2023-2026 Frank Denis
 * Copyright (c) 2026 Antonio Quartulli <antonio@mandelbit.com>
 */

#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <asm/fpu/api.h>

#define AEGIS128X4_LANES 4
/* the rate: number of bytes absorbed by each update */
#define AEGIS128X4_BLOCK_SIZE (32 * AEGIS128X4_LANES)
#define AEGIS128X4_NONCE_SIZE 16
#define AEGIS128X4_STATE_BLOCKS 8
#define AEGIS128X4_KEY_SIZE 16
#define AEGIS128X4_MIN_AUTH_SIZE 16
#define AEGIS128X4_MAX_AUTH_SIZE 32
/* largest request processed with the state kept in registers */
#define AEGIS128X4_FAST_MAX_LEN SZ_64K

struct aegis128x4_state {
	u8 blocks[AEGIS128X4_STATE_BLOCKS][16 * AEGIS128X4_LANES];
};

struct aegis128x4_ctx {
	u8 key[AEGIS128X4_KEY_SIZE];
};

asmlinkage void aegis128x4_aesni_avx512_init(struct aegis128x4_state *state,
					     const u8 key[AEGIS128X4_KEY_SIZE],
					     const u8 iv[AEGIS128X4_NONCE_SIZE]);

asmlinkage void aegis128x4_aesni_avx512_ad(struct aegis128x4_state *state,
					   const u8 *data, unsigned int len);

asmlinkage void aegis128x4_aesni_avx512_enc(struct aegis128x4_state *state,
					    const u8 *src, u8 *dst,
					    unsigned int len);

asmlinkage void aegis128x4_aesni_avx512_dec(struct aegis128x4_state *state,
					    const u8 *src, u8 *dst,
					    unsigned int len);

asmlinkage void aegis128x4_aesni_avx512_enc_tail(struct aegis128x4_state *state,
						 const u8 *src, u8 *dst,
						 unsigned int len);

asmlinkage void aegis128x4_aesni_avx512_dec_tail(struct aegis128x4_state *state,
						 const u8 *src, u8 *dst,
						 unsigned int len);

asmlinkage void aegis128x4_aesni_avx512_final(struct aegis128x4_state *state,
					      u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
					      unsigned int assoclen,
					      unsigned int cryptlen,
					      unsigned int authsize);

asmlinkage void
aegis128x4_aesni_avx512_enc_oneshot(const u8 key[AEGIS128X4_KEY_SIZE],
				    const u8 iv[AEGIS128X4_NONCE_SIZE],
				    const u8 *ad, unsigned int adlen,
				    const u8 *src, u8 *dst, unsigned int len,
				    u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
				    unsigned int authsize);

asmlinkage void
aegis128x4_aesni_avx512_dec_oneshot(const u8 key[AEGIS128X4_KEY_SIZE],
				    const u8 iv[AEGIS128X4_NONCE_SIZE],
				    const u8 *ad, unsigned int adlen,
				    const u8 *src, u8 *dst, unsigned int len,
				    u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
				    unsigned int authsize);

static void
crypto_aegis128x4_aesni_avx512_process_ad(struct aegis128x4_state *state,
					  struct scatterlist *sg_src,
					  unsigned int assoclen)
{
	struct scatter_walk walk;
	u8 buf[AEGIS128X4_BLOCK_SIZE];
	unsigned int pos = 0;

	scatterwalk_start(&walk, sg_src);
	while (assoclen != 0) {
		unsigned int size = scatterwalk_next(&walk, assoclen);
		const u8 *src = walk.addr;
		unsigned int left = size;

		if (pos + size >= AEGIS128X4_BLOCK_SIZE) {
			if (pos > 0) {
				unsigned int fill = AEGIS128X4_BLOCK_SIZE - pos;

				memcpy(buf + pos, src, fill);
				aegis128x4_aesni_avx512_ad(state, buf,
							   AEGIS128X4_BLOCK_SIZE);
				pos = 0;
				left -= fill;
				src += fill;
			}

			aegis128x4_aesni_avx512_ad(state, src,
						   round_down(left,
							      AEGIS128X4_BLOCK_SIZE));
			src += round_down(left, AEGIS128X4_BLOCK_SIZE);
			left %= AEGIS128X4_BLOCK_SIZE;
		}

		memcpy(buf + pos, src, left);
		pos += left;
		assoclen -= size;

		scatterwalk_done_src(&walk, size);
	}

	if (pos > 0) {
		memset(buf + pos, 0, AEGIS128X4_BLOCK_SIZE - pos);
		aegis128x4_aesni_avx512_ad(state, buf, AEGIS128X4_BLOCK_SIZE);
	}
}

static __always_inline void
crypto_aegis128x4_aesni_avx512_process_crypt(struct aegis128x4_state *state,
					     const u8 *src, u8 *dst,
					     unsigned int len, bool enc)
{
	if (enc)
		aegis128x4_aesni_avx512_enc(state, src, dst, len);
	else
		aegis128x4_aesni_avx512_dec(state, src, dst, len);
}

static __always_inline void
crypto_aegis128x4_aesni_avx512_process_tail(struct aegis128x4_state *state,
					    const u8 *src, u8 *dst,
					    unsigned int len, bool enc)
{
	if (enc)
		aegis128x4_aesni_avx512_enc_tail(state, src, dst, len);
	else
		aegis128x4_aesni_avx512_dec_tail(state, src, dst, len);
}

static int crypto_aegis128x4_aesni_avx512_setkey(struct crypto_aead *aead,
						 const u8 *key,
						 unsigned int keylen)
{
	struct aegis128x4_ctx *ctx = crypto_aead_ctx(aead);

	if (keylen != AEGIS128X4_KEY_SIZE)
		return -EINVAL;

	memcpy(ctx->key, key, AEGIS128X4_KEY_SIZE);

	return 0;
}

static int crypto_aegis128x4_aesni_avx512_setauthsize(struct crypto_aead *tfm,
						      unsigned int authsize)
{
	/* only full 128-bit and 256-bit tags are defined for AEGIS-128X */
	if (authsize != AEGIS128X4_MIN_AUTH_SIZE &&
	    authsize != AEGIS128X4_MAX_AUTH_SIZE)
		return -EINVAL;
	return 0;
}

/*
 * Generic path, for requests whose associated data or payload are split across
 * several scatterlist entries, or that exceed AEGIS128X4_FAST_MAX_LEN.  Kept
 * out of line so that the fast path doesn't reserve the on-stack state.
 */
static noinline int
crypto_aegis128x4_aesni_avx512_crypt_slow(struct aead_request *req,
					  u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
					  unsigned int cryptlen, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct aegis128x4_ctx *ctx = crypto_aead_ctx(tfm);
	struct skcipher_walk walk;
	struct aegis128x4_state state;
	unsigned int nbytes, full;
	int err;

	if (enc)
		err = skcipher_walk_aead_encrypt(&walk, req, false);
	else
		err = skcipher_walk_aead_decrypt(&walk, req, false);
	if (err)
		return err;

	/*
	 * Since the AEGIS-128X4 state lives in vector registers, try to do
	 * everything in a single kernel FPU section: close it and start a new
	 * one only between data segments, like the AES-GCM glue does.
	 */
	kernel_fpu_begin();

	aegis128x4_aesni_avx512_init(&state, ctx->key, req->iv);
	crypto_aegis128x4_aesni_avx512_process_ad(&state, req->src,
						  req->assoclen);

	while (unlikely((nbytes = walk.nbytes) < walk.total)) {
		/*
		 * Non-last segment: the skcipher_walk guarantees at least
		 * chunksize bytes, process all the complete blocks and let the
		 * walk carry over the rest.
		 */
		nbytes = round_down(nbytes, AEGIS128X4_BLOCK_SIZE);
		crypto_aegis128x4_aesni_avx512_process_crypt(&state,
							     walk.src.virt.addr,
							     walk.dst.virt.addr,
							     nbytes, enc);
		kernel_fpu_end();
		err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
		if (err)
			goto out;
		kernel_fpu_begin();
	}

	/* Last segment: process all remaining data, then finalize. */
	full = round_down(nbytes, AEGIS128X4_BLOCK_SIZE);
	if (full)
		crypto_aegis128x4_aesni_avx512_process_crypt(&state,
							     walk.src.virt.addr,
							     walk.dst.virt.addr,
							     full, enc);
	if (nbytes > full)
		crypto_aegis128x4_aesni_avx512_process_tail(&state,
							    walk.src.virt.addr + full,
							    walk.dst.virt.addr + full,
							    nbytes - full, enc);
	aegis128x4_aesni_avx512_final(&state, tag_xor, req->assoclen, cryptlen,
				      crypto_aead_authsize(tfm));
	kernel_fpu_end();
	if (nbytes)
		err = skcipher_walk_done(&walk, 0);
out:
	memzero_explicit(&state, sizeof(state));
	return err;
}

/*
 * Return the address of the @len bytes found at offset @skip of @sg, or NULL
 * if they are not contiguous in a single entry.  This driver is 64-bit only,
 * so there is no highmem and an entry spanning several pages is virtually
 * contiguous in the direct map.
 */
static __always_inline u8 *
crypto_aegis128x4_aesni_avx512_sg_linear(struct scatterlist *sg,
					 unsigned int skip, unsigned int len)
{
	while (skip >= sg->length) {
		skip -= sg->length;
		sg = sg_next(sg);
	}

	if (sg->length - skip < len)
		return NULL;

	return sg_virt(sg) + skip;
}

static __always_inline int
crypto_aegis128x4_aesni_avx512_crypt(struct aead_request *req,
				     u8 tag_xor[AEGIS128X4_MAX_AUTH_SIZE],
				     unsigned int cryptlen, bool enc)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct aegis128x4_ctx *ctx = crypto_aead_ctx(tfm);
	unsigned int assoclen = req->assoclen;
	const u8 *ad = NULL, *src = NULL;
	u8 *dst = NULL;

	/*
	 * Fast path: the associated data is contiguous in the first source
	 * scatterlist entry and the payload is contiguous in a single entry
	 * (e.g. a linear skb, even larger than a page), so the whole request
	 * can be processed by a single assembly call that keeps the state in
	 * registers.  Bound the request size to limit the time spent with
	 * preemption disabled.
	 */
	if (unlikely(assoclen > AEGIS128X4_FAST_MAX_LEN ||
		     cryptlen > AEGIS128X4_FAST_MAX_LEN - assoclen))
		goto slow;

	if (assoclen) {
		if (unlikely(req->src->length < assoclen))
			goto slow;
		ad = sg_virt(req->src);
	}

	if (cryptlen) {
		src = crypto_aegis128x4_aesni_avx512_sg_linear(req->src,
							       assoclen,
							       cryptlen);
		if (unlikely(!src))
			goto slow;

		if (req->dst == req->src)
			dst = (u8 *)src;
		else
			dst = crypto_aegis128x4_aesni_avx512_sg_linear(req->dst,
								       assoclen,
								       cryptlen);
		if (unlikely(!dst))
			goto slow;
	}

	kernel_fpu_begin();
	if (enc)
		aegis128x4_aesni_avx512_enc_oneshot(ctx->key, req->iv, ad,
						    assoclen, src, dst,
						    cryptlen, tag_xor,
						    crypto_aead_authsize(tfm));
	else
		aegis128x4_aesni_avx512_dec_oneshot(ctx->key, req->iv, ad,
						    assoclen, src, dst,
						    cryptlen, tag_xor,
						    crypto_aead_authsize(tfm));
	kernel_fpu_end();
	return 0;

slow:
	return crypto_aegis128x4_aesni_avx512_crypt_slow(req, tag_xor,
							 cryptlen, enc);
}

static int crypto_aegis128x4_aesni_avx512_encrypt(struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	u8 tag[AEGIS128X4_MAX_AUTH_SIZE] = {};
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen;
	int err;

	err = crypto_aegis128x4_aesni_avx512_crypt(req, tag, cryptlen, true);
	if (err)
		return err;

	scatterwalk_map_and_copy(tag, req->dst, req->assoclen + cryptlen,
				 authsize, 1);
	return 0;
}

static int crypto_aegis128x4_aesni_avx512_decrypt(struct aead_request *req)
{
	static const u8 zeros[AEGIS128X4_MAX_AUTH_SIZE] = {};

	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	u8 tag[AEGIS128X4_MAX_AUTH_SIZE];
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int cryptlen = req->cryptlen - authsize;
	int err;

	scatterwalk_map_and_copy(tag, req->src, req->assoclen + cryptlen,
				 authsize, 0);

	err = crypto_aegis128x4_aesni_avx512_crypt(req, tag, cryptlen, false);
	if (err)
		return err;

	return crypto_memneq(tag, zeros, authsize) ? -EBADMSG : 0;
}

static struct aead_alg crypto_aegis128x4_aesni_avx512_alg = {
	.setkey = crypto_aegis128x4_aesni_avx512_setkey,
	.setauthsize = crypto_aegis128x4_aesni_avx512_setauthsize,
	.encrypt = crypto_aegis128x4_aesni_avx512_encrypt,
	.decrypt = crypto_aegis128x4_aesni_avx512_decrypt,

	.ivsize = AEGIS128X4_NONCE_SIZE,
	.maxauthsize = AEGIS128X4_MAX_AUTH_SIZE,
	.chunksize = AEGIS128X4_BLOCK_SIZE,

	.base = {
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct aegis128x4_ctx),
		.cra_priority = 800,

		.cra_name = "aegis128x4",
		.cra_driver_name = "aegis128x4-aesni-avx512",

		.cra_module = THIS_MODULE,
	}
};

static int __init crypto_aegis128x4_aesni_avx512_module_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_AVX2) ||
	    !boot_cpu_has(X86_FEATURE_AVX512F) ||
	    !boot_cpu_has(X86_FEATURE_AVX512BW) ||
	    !boot_cpu_has(X86_FEATURE_VAES) ||
	    !boot_cpu_has(X86_FEATURE_BMI2) ||
	    !cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
			       XFEATURE_MASK_AVX512, NULL))
		return -ENODEV;

	return crypto_register_aead(&crypto_aegis128x4_aesni_avx512_alg);
}

static void __exit crypto_aegis128x4_aesni_avx512_module_exit(void)
{
	crypto_unregister_aead(&crypto_aegis128x4_aesni_avx512_alg);
}

module_init(crypto_aegis128x4_aesni_avx512_module_init);
module_exit(crypto_aegis128x4_aesni_avx512_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antonio Quartulli <antonio@mandelbit.com>");
MODULE_DESCRIPTION("AEGIS-128X4 AEAD algorithm -- VAES+AVX512 implementation");
MODULE_ALIAS_CRYPTO("aegis128x4");
MODULE_ALIAS_CRYPTO("aegis128x4-aesni-avx512");
