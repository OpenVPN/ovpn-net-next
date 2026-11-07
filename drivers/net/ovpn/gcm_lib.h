/* SPDX-License-Identifier: GPL-2.0-only */
/* TEST: AES-GCM on linear buffers with the x86 VAES-AVX512 assembly, called
 * directly instead of through the crypto API, as an arch hook of the AES-GCM
 * library would
 */

#ifndef _NET_OVPN_GCM_LIB_H_
#define _NET_OVPN_GCM_LIB_H_

#include <crypto/aes.h>
#include <linux/types.h>

/* layout expected by gcm-vaes-avx512.S (struct aes_gcm_key_vaes_avx512) */
struct ovpn_gcm_key {
	struct {
		struct aes_enckey aes_key;
		u32 rfc4106_nonce;
	} base __aligned(16);
	u64 h_powers[16][2] __aligned(64);
	u64 padding[3][2];
};

bool ovpn_gcm_lib_usable(void);
int ovpn_gcm_setkey(struct ovpn_gcm_key *key, const u8 *raw, unsigned int len);
int ovpn_gcm_decrypt(const struct ovpn_gcm_key *key, u8 *data,
		     unsigned int len, const u8 *aad, unsigned int aad_len,
		     const u8 iv[12], const u8 tag[16]);
void ovpn_gcm_encrypt(const struct ovpn_gcm_key *key, u8 *dst, const u8 *src,
		      unsigned int len, const u8 *aad, unsigned int aad_len,
		      const u8 iv[12], u8 tag[16]);

#endif /* _NET_OVPN_GCM_LIB_H_ */
