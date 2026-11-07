// SPDX-License-Identifier: GPL-2.0-only
/* TEST: AES-GCM on linear buffers with the x86 VAES-AVX512 assembly, see
 * gcm_lib.h; the call sequence follows gcm_crypt() in
 * arch/x86/crypto/aesni-intel_glue.c
 */

#include <asm/fpu/api.h>
#include <asm/cpufeature.h>
#include <linux/build_bug.h>
#include <linux/printk.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "gcm_lib.h"

asmlinkage void ovpn_gcm_precompute_vaes_avx512(struct ovpn_gcm_key *key);
asmlinkage void ovpn_gcm_aad_update_vaes_avx512(const struct ovpn_gcm_key *key,
					       u8 ghash_acc[16], const u8 *aad,
					       int aadlen);
asmlinkage void ovpn_gcm_enc_update_vaes_avx512(const struct ovpn_gcm_key *key,
					       const u32 le_ctr[4],
					       u8 ghash_acc[16], const u8 *src,
					       u8 *dst, int datalen);
asmlinkage void ovpn_gcm_dec_update_vaes_avx512(const struct ovpn_gcm_key *key,
					       const u32 le_ctr[4],
					       u8 ghash_acc[16], const u8 *src,
					       u8 *dst, int datalen);
asmlinkage void ovpn_gcm_enc_final_vaes_avx512(const struct ovpn_gcm_key *key,
					      const u32 le_ctr[4],
					      u8 ghash_acc[16],
					      u64 total_aadlen,
					      u64 total_datalen);
asmlinkage bool __must_check
ovpn_gcm_dec_final_vaes_avx512(const struct ovpn_gcm_key *key,
			      const u32 le_ctr[4], const u8 ghash_acc[16],
			      u64 total_aadlen, u64 total_datalen,
			      const u8 tag[16], int taglen);

static_assert(offsetof(struct ovpn_gcm_key, base.aes_key.len) == 0);
static_assert(offsetof(struct ovpn_gcm_key, base.aes_key.k.rndkeys) == 16);
static_assert(offsetof(struct ovpn_gcm_key, h_powers) == 320);
static_assert(offsetof(struct ovpn_gcm_key, padding) == 576);

/* the CPU features aesni-intel requires for its VAES-AVX512 GCM */
bool ovpn_gcm_lib_usable(void)
{
	return boot_cpu_has(X86_FEATURE_VAES) &&
	       boot_cpu_has(X86_FEATURE_VPCLMULQDQ) &&
	       boot_cpu_has(X86_FEATURE_AVX512BW) &&
	       boot_cpu_has(X86_FEATURE_AVX512VL) &&
	       boot_cpu_has(X86_FEATURE_BMI2) &&
	       !boot_cpu_has(X86_FEATURE_PREFER_YMM) &&
	       cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM |
				 XFEATURE_MASK_AVX512, NULL);
}

/* process context, SIMD usable */
int ovpn_gcm_setkey(struct ovpn_gcm_key *key, const u8 *raw, unsigned int len)
{
	int err;

	err = aes_prepareenckey(&key->base.aes_key, raw, len);
	if (err)
		return err;

	kernel_fpu_begin();
	ovpn_gcm_precompute_vaes_avx512(key);
	kernel_fpu_end();
	pr_info_once("ovpn gcm-lib: active\n");
	return 0;
}

static void ovpn_gcm_ctr_init(u32 le_ctr[4], const u8 iv[12])
{
	le_ctr[0] = 2;
	le_ctr[1] = get_unaligned_be32(iv + 8);
	le_ctr[2] = get_unaligned_be32(iv + 4);
	le_ctr[3] = get_unaligned_be32(iv + 0);
}

int ovpn_gcm_decrypt(const struct ovpn_gcm_key *key, u8 *data,
		     unsigned int len, const u8 *aad, unsigned int aad_len,
		     const u8 iv[12], const u8 tag[16])
{
	u8 ghash_acc[16] = {};
	u32 le_ctr[4];
	bool ok;

	ovpn_gcm_ctr_init(le_ctr, iv);

	kernel_fpu_begin();
	ovpn_gcm_aad_update_vaes_avx512(key, ghash_acc, aad, aad_len);
	ovpn_gcm_dec_update_vaes_avx512(key, le_ctr, ghash_acc, data, data, len);
	ok = ovpn_gcm_dec_final_vaes_avx512(key, le_ctr, ghash_acc, aad_len, len,
					   tag, 16);
	kernel_fpu_end();

	return ok ? 0 : -EBADMSG;
}

void ovpn_gcm_encrypt(const struct ovpn_gcm_key *key, u8 *dst, const u8 *src,
		      unsigned int len, const u8 *aad, unsigned int aad_len,
		      const u8 iv[12], u8 tag[16])
{
	u8 ghash_acc[16] = {};
	u32 le_ctr[4];

	ovpn_gcm_ctr_init(le_ctr, iv);

	kernel_fpu_begin();
	ovpn_gcm_aad_update_vaes_avx512(key, ghash_acc, aad, aad_len);
	ovpn_gcm_enc_update_vaes_avx512(key, le_ctr, ghash_acc, src, dst, len);
	ovpn_gcm_enc_final_vaes_avx512(key, le_ctr, ghash_acc, aad_len, len);
	kernel_fpu_end();

	memcpy(tag, ghash_acc, 16);
}
