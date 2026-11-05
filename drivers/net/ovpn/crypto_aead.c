// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2020-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/skbuff.h>
#include <linux/skbuff_ref.h>
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/page_pool/helpers.h>
#include <net/sock.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "main.h"
#include "io.h"
#include "pktid.h"
#include "crypto_aead.h"
#include "crypto.h"
#include "peer.h"
#include "proto.h"
#include "skb.h"

#define ALG_NAME_AES		"gcm(aes)"
#define ALG_NAME_CHACHAPOLY	"rfc7539(chacha20,poly1305)"
#define ALG_NAME_AEGIS128X4	"aegis128x4"

/* largest IV accepted: the AEGIS-128X family uses a 128-bit nonce, which
 * gets the 96-bit OpenVPN nonce zero-padded
 */
#define OVPN_AEAD_MAX_IV_SIZE	16

static int ovpn_aead_encap_overhead(const struct ovpn_crypto_key_slot *ks)
{
	return  OVPN_OPCODE_SIZE +			/* OP header size */
		sizeof(u32) +				/* Packet ID */
		crypto_aead_authsize(ks->encrypt);	/* Auth Tag */
}

/**
 * ovpn_aead_crypto_tmp_size - compute the size of a temporary object containing
 *			       an AEAD request structure with extra space for SG
 *			       and IV.
 * @tfm: the AEAD cipher handle
 * @nents: the number of scatterlist entries
 *
 * This function calculates the size of a contiguous memory block that includes
 * the initialization vector (IV), the AEAD request, and an array of scatterlist
 * entries. For alignment considerations, the IV is placed first, followed by
 * the request, and then the scatterlist.
 * Additional alignment is applied according to the requirements of the
 * underlying structures.
 *
 * Return: the size of the temporary memory that needs to be allocated
 */
static unsigned int ovpn_aead_crypto_tmp_size(struct crypto_aead *tfm,
					      const unsigned int nents)
{
	unsigned int len = crypto_aead_ivsize(tfm);

	/* min size for a buffer of ivsize, aligned to alignmask */
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	/* round up to the next multiple of the crypto ctx alignment */
	len = ALIGN(len, crypto_tfm_ctx_alignment());

	/* reserve space for the AEAD request */
	len += sizeof(struct aead_request) + crypto_aead_reqsize(tfm);
	/* round up to the next multiple of the scatterlist alignment */
	len = ALIGN(len, __alignof__(struct scatterlist));

	/* add enough space for the scatterlist entries */
	len += array_size(sizeof(struct scatterlist), nents);
	return len;
}

/**
 * ovpn_aead_crypto_tmp_iv - retrieve the pointer to the IV within a temporary
 *			     buffer allocated using ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @tmp: a pointer to the beginning of the temporary buffer
 *
 * This function retrieves a pointer to the initialization vector (IV) in the
 * temporary buffer. If the AEAD cipher specifies an IV size, the pointer is
 * adjusted using the AEAD's alignment mask to ensure proper alignment.
 *
 * Returns: a pointer to the IV within the temporary buffer
 */
static u8 *ovpn_aead_crypto_tmp_iv(struct crypto_aead *aead, void *tmp)
{
	return likely(crypto_aead_ivsize(aead)) ?
		      PTR_ALIGN((u8 *)tmp, crypto_aead_alignmask(aead) + 1) :
		      tmp;
}

/**
 * ovpn_aead_crypto_tmp_req - retrieve the pointer to the AEAD request structure
 *			      within a temporary buffer allocated using
 *			      ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @iv: a pointer to the initialization vector in the temporary buffer
 *
 * This function computes the location of the AEAD request structure that
 * immediately follows the IV in the temporary buffer and it ensures the request
 * is aligned to the crypto transform context alignment.
 *
 * Returns: a pointer to the AEAD request structure
 */
static struct aead_request *ovpn_aead_crypto_tmp_req(struct crypto_aead *aead,
						     const u8 *iv)
{
	return (void *)PTR_ALIGN(iv + crypto_aead_ivsize(aead),
				 crypto_tfm_ctx_alignment());
}

/**
 * ovpn_aead_crypto_req_sg - locate the scatterlist following the AEAD request
 *			     within a temporary buffer allocated using
 *			     ovpn_aead_crypto_tmp_size
 * @aead: the AEAD cipher handle
 * @req: a pointer to the AEAD request structure in the temporary buffer
 *
 * This function computes the starting address of the scatterlist that is
 * allocated immediately after the AEAD request structure. It aligns the pointer
 * based on the alignment requirements of the scatterlist structure.
 *
 * Returns: a pointer to the scatterlist
 */
static struct scatterlist *ovpn_aead_crypto_req_sg(struct crypto_aead *aead,
						   struct aead_request *req)
{
	return (void *)ALIGN((unsigned long)(req + 1) +
			     crypto_aead_reqsize(aead),
			     __alignof__(struct scatterlist));
}

/* fits the requests of all the supported algorithms, rfc7539 included */
#define OVPN_AEAD_SCRATCH_SIZE 1024

struct ovpn_aead_scratch {
	local_lock_t bh_lock;
	u8 buf[OVPN_AEAD_SCRATCH_SIZE] ____cacheline_aligned;
};

static DEFINE_PER_CPU(struct ovpn_aead_scratch, ovpn_aead_rx_scratches) = {
	.bh_lock = INIT_LOCAL_LOCK(bh_lock),
};

static DEFINE_PER_CPU(struct ovpn_aead_scratch, ovpn_aead_tx_scratches) = {
	.bh_lock = INIT_LOCAL_LOCK(bh_lock),
};

/* A synchronous AEAD operation with BHs disabled completes before another one
 * can start on this CPU, so it can use a per-CPU buffer instead of
 * allocating one for each packet. Returns NULL if it can't.
 */
static void *ovpn_aead_scratch_get(struct ovpn_aead_scratch __percpu *s,
				   bool sync, unsigned int size)
{
	if (!sync || !in_softirq() || in_hardirq() ||
	    size > OVPN_AEAD_SCRATCH_SIZE)
		return NULL;

	local_lock_nested_bh(&s->bh_lock);
	return this_cpu_ptr(s)->buf;
}

static void ovpn_aead_scratch_put(struct ovpn_aead_scratch __percpu *s,
				  bool used)
{
	if (used)
		local_unlock_nested_bh(&s->bh_lock);
}

/* allocate IV, request, scatterlist entries and caller scratch space in one
 * block. *@scratch tells whether the TX scratch buffer was used: then it must
 * be released with ovpn_aead_scratch_put() once crypto_aead_encrypt()
 * returned. Otherwise the block is freed with @skb's control block, or by the
 * caller through *@heap if there is no @skb.
 */
static struct aead_request *ovpn_aead_request_alloc(struct crypto_aead *aead,
						    struct sk_buff *skb,
						    unsigned int nents,
						    unsigned int extra, bool sync,
						    u8 **iv, bool *scratch,
						    void **heap)
{
	unsigned int size = ovpn_aead_crypto_tmp_size(aead, nents) + extra;
	struct aead_request *req;
	void *tmp;

	tmp = ovpn_aead_scratch_get(&ovpn_aead_tx_scratches, sync, size);
	*scratch = tmp;
	if (!tmp) {
		tmp = kmalloc(size, GFP_ATOMIC);
		if (unlikely(!tmp))
			return ERR_PTR(-ENOMEM);

		if (skb)
			ovpn_skb_cb(skb)->crypto_tmp = tmp;
		else
			*heap = tmp;
	}

	*iv = ovpn_aead_crypto_tmp_iv(aead, tmp);
	req = ovpn_aead_crypto_tmp_req(aead, *iv);

	return req;
}

static void ovpn_aead_encrypt_header(struct ovpn_peer *peer,
				     struct ovpn_crypto_key_slot *ks,
				     u32 pktid, u8 *iv, u8 *data)
{
	u32 op;

	/* concat 4 bytes packet id and 8 bytes nonce tail into 12 bytes
	 * nonce
	 */
	ovpn_pktid_aead_write(pktid, ks->nonce_tail_xmit, iv);
	/* algorithms with a larger IV get the nonce zero-padded */
	if (crypto_aead_ivsize(ks->encrypt) > OVPN_NONCE_SIZE)
		memset(iv + OVPN_NONCE_SIZE, 0,
		       crypto_aead_ivsize(ks->encrypt) - OVPN_NONCE_SIZE);

	/* add the packet opcode and wire nonce (the packet ID) as associated
	 * data, with one store so that the 8-byte loads that follow (the copy
	 * into the UDP GSO aggregate, the AEAD) can be forwarded from it
	 */
	op = ovpn_opcode_compose(OVPN_DATA_V2, ks->key_id, peer->tx_id);
	BUILD_BUG_ON(sizeof(op) != OVPN_OPCODE_SIZE);
	BUILD_BUG_ON(OVPN_OPCODE_SIZE + OVPN_NONCE_WIRE_SIZE != sizeof(u64));
	put_unaligned_be64((u64)op << 32 | pktid, data);
}

/* Prepare the TCP prefix in reserved headroom so it participates in AEAD.
 * The send path pushes these bytes without changing the authenticated values.
 */
static int ovpn_aead_encrypt_tcp_header(struct sk_buff *skb, u16 gso_size)
{
	struct ovpn_tcp_hdr *hdr = (void *)(skb->data - sizeof(*hdr));

	BUILD_BUG_ON(sizeof(*hdr) != 4);
	if (unlikely(skb->len > OVPN_TCP_MAX_RECORD))
		return -EMSGSIZE;

	hdr->len = htons(skb->len + sizeof(hdr->gso_size));
	hdr->gso_size = htons(gso_size);
	return 0;
}

int ovpn_aead_encrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->encrypt);
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	unsigned int aad_len = OVPN_AAD_SIZE;
	int nfrags, ret;
	bool scratch;
	u32 pktid;
	u8 *aad, *iv;

	/* Sample AEAD header format:
	 * 48000001 00000005 7e7046bd 444a7e28 cc6387b1 64a4d6c1 380275a...
	 * [ OP32 ] [seq # ] [             auth tag            ] [ payload ... ]
	 *          [4-byte
	 *          IV head]
	 */

	/* check that there's enough headroom in the skb for packet
	 * encapsulation
	 */
	if (unlikely(skb_cow_head(skb, OVPN_HEAD_ROOM)))
		return -ENOBUFS;

	/* get number of skb frags and ensure that packet data is writable */
	nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags > MAX_SKB_FRAGS)) {
		ret = skb_linearize(skb);
		if (unlikely(ret))
			return ret;
		nfrags = 1;
	}

	req = ovpn_aead_request_alloc(ks->encrypt, skb, nfrags + 2, 0,
				      ks->encrypt_sync, &iv, &scratch, NULL);
	if (IS_ERR(req))
		return PTR_ERR(req);
	sg = ovpn_aead_crypto_req_sg(ks->encrypt, req);

	/* sg table:
	 * 0: optional TCP prefix, op, wire nonce (AD),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* build scatterlist to encrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, 0, skb->len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "encrypt: cannot map skb to sg: %d\n", ret);
		goto out;
	}

	/* append auth_tag onto scatterlist */
	__skb_push(skb, tag_size);
	sg_set_buf(sg + ret + 1, skb->data, tag_size);

	/* make space for the additional data and push it to the front */
	__skb_push(skb, OVPN_AAD_SIZE);
	aad = skb->data;
	if (ovpn_skb_cb(skb)->tcp_packets) {
		ret = ovpn_aead_encrypt_tcp_header(skb, 0);
		if (unlikely(ret))
			goto out;
		aad -= sizeof(struct ovpn_tcp_hdr);
		aad_len = OVPN_TCP_AAD_SIZE;
	}

	/* obtain the packet ID used by both the nonce and associated data */
	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret < 0))
		goto out;
	ovpn_aead_encrypt_header(peer, ks, pktid, iv, skb->data);

	/* AEAD Additional data */
	sg_set_buf(sg, aad, aad_len);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_post, skb);
	aead_request_set_crypt(req, sg, sg,
			       skb->len - ovpn_aead_encap_overhead(ks), iv);
	aead_request_set_ad(req, aad_len);

	/* encrypt it */
	ret = crypto_aead_encrypt(req);
out:
	ovpn_aead_scratch_put(&ovpn_aead_tx_scratches, scratch);
	return ret;
}

/* Write the AAD at @offset of the UDP GSO aggregate @skb, whose data lives in
 * page frags allocated by ovpn_gso_alloc() (never net_iov). The common case, a
 * range within one lowmem frag, takes a single fixed-size copy:
 * skb_store_bits() ends in a variable-length memcpy(), a string operation
 * even for 8 bytes.
 */
static int ovpn_skb_store_aad(struct sk_buff *skb, unsigned int offset,
			      const u8 *aad)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int start = skb_headlen(skb), end, i;
	const skb_frag_t *frag;

	for (i = 0; offset >= start && i < shinfo->nr_frags; i++) {
		frag = &shinfo->frags[i];
		end = start + skb_frag_size(frag);
		if (offset < end) {
			if (offset + OVPN_AAD_SIZE > end ||
			    PageHighMem(skb_frag_page(frag)))
				break;
			memcpy(skb_frag_address(frag) + (offset - start), aad,
			       OVPN_AAD_SIZE);
			return 0;
		}
		start = end;
	}

	return skb_store_bits(skb, offset, aad, OVPN_AAD_SIZE);
}

/* Encrypt one segment, either the segment skb @skb or, without @skb, the
 * @len bytes at @buf, into its range at @offset of the UDP GSO skb. Without
 * @skb the transform must be synchronous.
 */
static int __ovpn_aead_encrypt_udp_gso(struct ovpn_peer *peer,
				       struct ovpn_crypto_key_slot *ks,
				       struct sk_buff *skb, const u8 *buf,
				       unsigned int len,
				       struct sk_buff *gso_skb,
				       unsigned int offset, u32 pktid)
{
	const unsigned int dst_nents = skb_shinfo(gso_skb)->nr_frags + 4;
	const unsigned int src_nents = skb ? skb_shinfo(skb)->nr_frags + 2 : 2;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	unsigned int payload_off;
	void *heap = NULL;
	int dst_idx, ret;
	bool scratch;
	u8 *aad, *iv;

	if (skb) {
		/* each input records the shared peer and key for the common
		 * completion path but their references remain owned by the
		 * output aggregate
		 */
		ovpn_skb_cb(skb)->peer = peer;
		ovpn_skb_cb(skb)->ks = ks;
	} else if (unlikely(!ks->encrypt_sync)) {
		DEBUG_NET_WARN_ON_ONCE(1);
		return -EINVAL;
	}

	req = ovpn_aead_request_alloc(ks->encrypt, skb, src_nents + dst_nents,
				      OVPN_AAD_SIZE, ks->encrypt_sync, &iv,
				      &scratch, &heap);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(ks->encrypt, req);
	dst = src + src_nents;
	aad = (u8 *)(dst + dst_nents);

	ovpn_aead_encrypt_header(peer, ks, pktid, iv, aad);

	ret = ovpn_skb_store_aad(gso_skb, offset, aad);
	if (unlikely(ret < 0))
		goto out;

	/* encrypt out of place from the original segmented skb directly into
	 * its final range in the UDP GSO skb
	 */
	sg_init_table(src, src_nents);
	sg_set_buf(src, aad, OVPN_AAD_SIZE);
	if (skb) {
		ret = skb_to_sgvec_nomark(skb, src + 1, 0, len);
		if (unlikely(ret < 0))
			goto out;
	} else {
		sg_set_buf(src + 1, buf, len);
		ret = 1;
	}
	sg_mark_end(&src[ret]);

	sg_init_table(dst, dst_nents);
	ret = skb_to_sgvec_nomark(gso_skb, dst, offset, OVPN_AAD_SIZE);
	if (unlikely(ret < 0))
		goto out;
	dst_idx = ret;

	payload_off = offset + OVPN_AAD_SIZE + OVPN_AUTH_TAG_SIZE;
	ret = skb_to_sgvec_nomark(gso_skb, dst + dst_idx, payload_off, len);
	if (unlikely(ret < 0))
		goto out;
	dst_idx += ret;

	ret = skb_to_sgvec_nomark(gso_skb, dst + dst_idx,
				  offset + OVPN_AAD_SIZE, OVPN_AUTH_TAG_SIZE);
	if (unlikely(ret < 0))
		goto out;
	dst_idx += ret;
	sg_mark_end(&dst[dst_idx - 1]);

	aead_request_set_tfm(req, ks->encrypt);
	/* without @skb the transform is synchronous: no callback */
	aead_request_set_callback(req, 0, skb ? ovpn_encrypt_post : NULL, skb);
	aead_request_set_crypt(req, src, dst, len, iv);
	aead_request_set_ad(req, OVPN_AAD_SIZE);

	ret = crypto_aead_encrypt(req);
out:
	ovpn_aead_scratch_put(&ovpn_aead_tx_scratches, scratch);
	kfree(heap);
	return ret;
}

int ovpn_aead_encrypt_udp_gso(struct ovpn_peer *peer,
			      struct ovpn_crypto_key_slot *ks, struct sk_buff *skb,
			      struct sk_buff *gso_skb, unsigned int offset,
			      u32 pktid)
{
	return __ovpn_aead_encrypt_udp_gso(peer, ks, skb, NULL, skb->len,
					   gso_skb, offset, pktid);
}

int ovpn_aead_encrypt_udp_gso_buf(struct ovpn_peer *peer,
				  struct ovpn_crypto_key_slot *ks,
				  const u8 *buf, unsigned int len,
				  struct sk_buff *gso_skb, unsigned int offset,
				  u32 pktid)
{
	return __ovpn_aead_encrypt_udp_gso(peer, ks, NULL, buf, len, gso_skb,
					   offset, pktid);
}

/* Count read-only payload storage, including ordinary GRO frag lists. Match
 * skb_to_sgvec_nomark()'s nesting limit before allocating its scatterlist.
 */
static int ovpn_skb_nsg(const struct sk_buff *skb, unsigned int depth)
{
	unsigned int nents = !!skb_headlen(skb) + skb_shinfo(skb)->nr_frags;
	const struct sk_buff *frag;
	int ret;

	if (unlikely(depth >= 24))
		return -EMSGSIZE;

	skb_walk_frags(skb, frag) {
		ret = ovpn_skb_nsg(frag, depth + 1);
		if (unlikely(ret < 0))
			return ret;
		nents += ret;
	}

	return nents;
}

int ovpn_aead_encrypt_tcp_gso(struct ovpn_peer *peer,
			      struct ovpn_crypto_key_slot *ks,
			      struct sk_buff *skb, struct sk_buff *gso_skb)
{
	const unsigned int dst_nents = skb_shinfo(gso_skb)->nr_frags + 2;
	struct scatterlist *src, *dst;
	struct aead_request *req;
	int src_nents, mapped, ret;
	bool scratch;
	u8 *aad, *iv;
	u32 pktid;

	ret = ovpn_aead_encrypt_tcp_header(gso_skb, skb_shinfo(skb)->gso_size);
	if (unlikely(ret))
		return ret;
	aad = gso_skb->data - sizeof(struct ovpn_tcp_hdr);

	src_nents = ovpn_skb_nsg(skb, 0);
	if (unlikely(src_nents < 0))
		return src_nents;
	/* TCP prefix, opcode and packet ID as AAD */
	src_nents++;
	req = ovpn_aead_request_alloc(ks->encrypt, skb, src_nents + dst_nents,
				      0, false, &iv, &scratch, NULL);
	if (IS_ERR(req))
		return PTR_ERR(req);
	src = ovpn_aead_crypto_req_sg(ks->encrypt, req);
	dst = src + src_nents;

	/* Read the original GSO skb without COW, checksum completion or
	 * segmentation. Its pages may still belong to the inner TCP sender.
	 */
	sg_init_table(src, src_nents);
	sg_set_buf(src, aad, OVPN_TCP_AAD_SIZE);
	mapped = skb_to_sgvec_nomark(skb, src + 1, 0, skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_mark_end(src + mapped);

	/* Keep AAD/tag in the linear head and write the encrypted inner packet
	 * directly into pages sent by MSG_SPLICE_PAGES.
	 */
	sg_init_table(dst, dst_nents);
	sg_set_buf(dst, aad, OVPN_TCP_AAD_SIZE);
	mapped = skb_to_sgvec_nomark(gso_skb, dst + 1, OVPN_DATA_V2_OVERHEAD,
				     skb->len);
	if (unlikely(mapped < 0))
		return mapped;
	sg_set_buf(dst + mapped + 1, gso_skb->data + OVPN_AAD_SIZE,
		   OVPN_AUTH_TAG_SIZE);
	sg_mark_end(dst + mapped + 1);

	ret = ovpn_pktid_xmit_next(&ks->pid_xmit, &pktid);
	if (unlikely(ret))
		return ret;
	ovpn_aead_encrypt_header(peer, ks, pktid, iv, gso_skb->data);

	aead_request_set_tfm(req, ks->encrypt);
	aead_request_set_callback(req, 0, ovpn_encrypt_tcp_gso_post, skb);
	aead_request_set_crypt(req, src, dst, skb->len, iv);
	aead_request_set_ad(req, OVPN_TCP_AAD_SIZE);

	return crypto_aead_encrypt(req);
}

/**
 * ovpn_aead_decrypt_pp_copy - make a paged record private by copying its
 *			       fragments into pages of the per-CPU RX pool
 * @skb: the received record
 *
 * The received fragments may still be referenced, and even modified, by
 * others, therefore they are copied once and released: the AEAD only reads
 * and writes memory owned by ovpn. Unlike skb_cow_data, the copy goes into
 * recycled order-0 pages instead of a freshly allocated (and possibly high
 * order) linear head.
 *
 * Only records too large for a linear head of one page, whose head is
 * private and not backed by a page pool page, are handled: smaller ones are
 * cheaply linearized by skb_cow_data. Any other record is left unchanged.
 *
 * Return: the number of scatterlist entries needed by the record if it was
 * copied, 0 otherwise
 */
static int ovpn_aead_decrypt_pp_copy(struct sk_buff *skb)
{
	unsigned int len, offset, truesize, remaining = skb->data_len;
	unsigned int headlen = skb_headlen(skb), new_truesize = 0;
	skb_frag_t frags[MAX_SKB_FRAGS];
	struct skb_shared_info *shinfo;
	struct page_pool *pool;
	struct page *page;
	int i, nr_frags = 0;

	if (!skb_is_nonlinear(skb) || skb_cloned(skb) ||
	    skb_has_frag_list(skb) ||
	    DIV_ROUND_UP(remaining, PAGE_SIZE) + 1 > MAX_SKB_FRAGS)
		return 0;

	/* the linear head skb_cow_data would allocate fits in one page */
	if (SKB_HEAD_ALIGN(skb_headroom(skb) + skb->len) <= PAGE_SIZE)
		return 0;

	/* switching the skb to page pool semantics must not affect its head */
	if (skb->head_frag && !skb->pp_recycle &&
	    page_pool_page_is_pp(virt_to_head_page(skb->head)))
		return 0;

	/* zerocopy fragments are released (and copied) by skb_cow_data */
	if (skb_zcopy(skb))
		return 0;

	/* the per-CPU pool can only be used by one context at a time */
	local_bh_disable();
	local_lock_nested_bh(&ovpn_rx_pools->bh_lock);
	pool = this_cpu_ptr(ovpn_rx_pools)->pool;
	while (remaining) {
		len = min_t(unsigned int, remaining, PAGE_SIZE);
		truesize = len;
		page = page_pool_dev_alloc(pool, &offset, &truesize);
		if (unlikely(!page))
			break;

		skb_frag_fill_page_desc(&frags[nr_frags++], page, offset, len);
		new_truesize += truesize;
		remaining -= len;
	}
	local_unlock_nested_bh(&ovpn_rx_pools->bh_lock);
	local_bh_enable();

	if (unlikely(remaining))
		goto err;

	/* read the received fragments exactly once */
	offset = headlen;
	for (i = 0; i < nr_frags; i++) {
		len = skb_frag_size(&frags[i]);
		if (unlikely(skb_copy_bits(skb, offset,
					   skb_frag_address(&frags[i]), len)))
			goto err;
		offset += len;
	}

	shinfo = skb_shinfo(skb);
	for (i = 0; i < shinfo->nr_frags; i++)
		__skb_frag_unref(&shinfo->frags[i], skb->pp_recycle);
	memcpy(shinfo->frags, frags, nr_frags * sizeof(*frags));
	shinfo->nr_frags = nr_frags;
	shinfo->flags &= ~SKBFL_SHARED_FRAG;

	/* like pskb_expand_head, don't change the size of a charged skb.
	 * The received fragments are accounted as their payload size only,
	 * which overestimates the new size
	 */
	if (!skb->sk || skb->destructor == sock_edemux)
		skb->truesize += new_truesize - skb->data_len;
	skb_mark_for_recycle(skb);

	/* head and new fragments */
	return nr_frags + 1;
err:
	/* the skb is unchanged: let skb_cow_data try */
	for (i = 0; i < nr_frags; i++)
		page_pool_put_full_page(pool, skb_frag_page(&frags[i]), false);
	return 0;
}

int ovpn_aead_decrypt(struct ovpn_peer *peer, struct ovpn_crypto_key_slot *ks,
		      struct sk_buff *skb, bool tcp)
{
	const unsigned int tag_size = crypto_aead_authsize(ks->decrypt);
	unsigned int payload_offset, tmp_size;
	unsigned int aad_len = OVPN_AAD_SIZE;
	int ret, payload_len, nfrags;
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	bool scratch;
	void *tmp;
	u8 *aad, *iv;

	payload_offset = OVPN_AAD_SIZE + tag_size;
	payload_len = skb->len - payload_offset;

	ovpn_skb_cb(skb)->payload_offset = payload_offset;
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;

	/* sanity check on packet size, payload size must be >= 0 */
	if (unlikely(payload_len < 0))
		return -EINVAL;

	/* Prepare the skb data buffer to be accessed up until the auth tag.
	 * This is required because this area is directly mapped into the sg
	 * list.
	 */
	if (unlikely(!pskb_may_pull(skb, payload_offset)))
		return -ENODATA;

	/* get number of skb frags and ensure that packet data is writable:
	 * the data of paged records is copied into private pool pages,
	 * anything else is copied into a private head when needed
	 */
	nfrags = ovpn_aead_decrypt_pp_copy(skb);
	if (!nfrags)
		nfrags = skb_cow_data(skb, 0, &trailer);
	if (unlikely(nfrags < 0))
		return nfrags;

	if (unlikely(nfrags + 2 > (MAX_SKB_FRAGS + 2)))
		return -ENOSPC;

	/* temporary memory for iv, sg and req */
	tmp_size = ovpn_aead_crypto_tmp_size(ks->decrypt, nfrags + 2);
	tmp = ovpn_aead_scratch_get(&ovpn_aead_rx_scratches, ks->decrypt_sync,
				    tmp_size);
	scratch = tmp;
	if (!tmp) {
		tmp = kmalloc(tmp_size, GFP_ATOMIC);
		if (unlikely(!tmp))
			return -ENOMEM;

		ovpn_skb_cb(skb)->crypto_tmp = tmp;
	}

	iv = ovpn_aead_crypto_tmp_iv(ks->decrypt, tmp);
	req = ovpn_aead_crypto_tmp_req(ks->decrypt, iv);
	sg = ovpn_aead_crypto_req_sg(ks->decrypt, req);

	/* sg table:
	 * 0: optional TCP prefix, op, wire nonce (AD),
	 * 1, 2, 3, ..., n: payload,
	 * n+1: auth_tag (len=tag_size)
	 */
	sg_init_table(sg, nfrags + 2);

	/* TCP framing is contiguous with the opcode and packet ID. Save its
	 * segment size, but do not use it until authentication succeeds.
	 */
	aad = skb->data;
	if (tcp) {
		const struct ovpn_tcp_hdr *hdr;

		aad -= sizeof(*hdr);
		hdr = (const struct ovpn_tcp_hdr *)aad;
		aad_len = OVPN_TCP_AAD_SIZE;
		ovpn_skb_cb(skb)->gso_size = ntohs(hdr->gso_size);
	}
	sg_set_buf(sg, aad, aad_len);

	/* build scatterlist to decrypt packet payload */
	ret = skb_to_sgvec_nomark(skb, sg + 1, payload_offset, payload_len);
	if (unlikely(ret < 0)) {
		netdev_err(peer->ovpn->dev,
			   "decrypt: cannot map skb to sg: %d\n", ret);
		goto out;
	}

	/* append auth_tag onto scatterlist */
	sg_set_buf(sg + ret + 1, skb->data + OVPN_AAD_SIZE, tag_size);

	/* copy nonce into IV buffer */
	memcpy(iv, skb->data + OVPN_OPCODE_SIZE, OVPN_NONCE_WIRE_SIZE);
	memcpy(iv + OVPN_NONCE_WIRE_SIZE, ks->nonce_tail_recv,
	       OVPN_NONCE_TAIL_SIZE);
	if (crypto_aead_ivsize(ks->decrypt) > OVPN_NONCE_SIZE)
		memset(iv + OVPN_NONCE_SIZE, 0,
		       crypto_aead_ivsize(ks->decrypt) - OVPN_NONCE_SIZE);

	/* setup async crypto operation */
	aead_request_set_tfm(req, ks->decrypt);
	aead_request_set_callback(req, 0, ovpn_decrypt_post, skb);
	aead_request_set_crypt(req, sg, sg, payload_len + tag_size, iv);

	aead_request_set_ad(req, aad_len);

	/* decrypt it */
	ret = crypto_aead_decrypt(req);
out:
	ovpn_aead_scratch_put(&ovpn_aead_rx_scratches, scratch);
	return ret;
}

/* Initialize a struct crypto_aead object */
static struct crypto_aead *ovpn_aead_init(const char *title,
					  const char *alg_name,
					  const unsigned char *key,
					  unsigned int keylen)
{
	struct crypto_aead *aead;
	int ret;

	aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		pr_err("%s crypto_alloc_aead failed, err=%d\n", title, ret);
		aead = NULL;
		goto error;
	}

	ret = crypto_aead_setkey(aead, key, keylen);
	if (ret) {
		pr_err("%s crypto_aead_setkey size=%u failed, err=%d\n", title,
		       keylen, ret);
		goto error;
	}

	ret = crypto_aead_setauthsize(aead, OVPN_AUTH_TAG_SIZE);
	if (ret) {
		pr_err("%s crypto_aead_setauthsize failed, err=%d\n", title,
		       ret);
		goto error;
	}

	/* the OpenVPN nonce is OVPN_NONCE_SIZE bytes; algorithms with a larger
	 * IV (up to OVPN_AEAD_MAX_IV_SIZE) get it zero-padded
	 */
	if (crypto_aead_ivsize(aead) < OVPN_NONCE_SIZE ||
	    crypto_aead_ivsize(aead) > OVPN_AEAD_MAX_IV_SIZE) {
		pr_err("%s unsupported IV size %u\n", title,
		       crypto_aead_ivsize(aead));
		ret = -EINVAL;
		goto error;
	}

	pr_debug("********* Cipher %s (%s)\n", alg_name, title);
	pr_debug("*** IV size=%u\n", crypto_aead_ivsize(aead));
	pr_debug("*** req size=%u\n", crypto_aead_reqsize(aead));
	pr_debug("*** block size=%u\n", crypto_aead_blocksize(aead));
	pr_debug("*** auth size=%u\n", crypto_aead_authsize(aead));
	pr_debug("*** alignmask=0x%x\n", crypto_aead_alignmask(aead));

	return aead;

error:
	crypto_free_aead(aead);
	return ERR_PTR(ret);
}

static void ovpn_aead_crypto_key_slot_free(struct ovpn_crypto_key_slot *ks)
{
	crypto_free_aead(ks->encrypt);
	crypto_free_aead(ks->decrypt);
}

static void ovpn_aead_crypto_key_slot_free_work(struct work_struct *work)
{
	struct ovpn_crypto_key_slot *ks;

	ks = container_of(to_rcu_work(work), struct ovpn_crypto_key_slot,
			  free_work);
	ovpn_aead_crypto_key_slot_free(ks);
	kfree(ks);
}

struct ovpn_crypto_key_slot *
ovpn_aead_crypto_key_slot_new(const struct ovpn_key_config *kc)
{
	struct ovpn_crypto_key_slot *ks = NULL;
	const char *alg_name;
	int ret;

	/* validate crypto alg */
	switch (kc->cipher_alg) {
	case OVPN_CIPHER_ALG_AES_GCM:
		alg_name = ALG_NAME_AES;
		break;
	case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
		alg_name = ALG_NAME_CHACHAPOLY;
		break;
	case OVPN_CIPHER_ALG_AEGIS128X4:
		alg_name = ALG_NAME_AEGIS128X4;
		break;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (kc->encrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE ||
	    kc->decrypt.nonce_tail_size != OVPN_NONCE_TAIL_SIZE)
		return ERR_PTR(-EINVAL);

	/* build the key slot */
	ks = kmalloc_obj(*ks);
	if (!ks)
		return ERR_PTR(-ENOMEM);

	ks->encrypt = NULL;
	ks->decrypt = NULL;
	INIT_RCU_WORK(&ks->free_work, ovpn_aead_crypto_key_slot_free_work);
	kref_init(&ks->refcount);
	ks->key_id = kc->key_id;

	ks->encrypt = ovpn_aead_init("encrypt", alg_name,
				     kc->encrypt.cipher_key,
				     kc->encrypt.cipher_key_size);
	if (IS_ERR(ks->encrypt)) {
		ret = PTR_ERR(ks->encrypt);
		ks->encrypt = NULL;
		goto destroy_ks;
	}

	ks->decrypt = ovpn_aead_init("decrypt", alg_name,
				     kc->decrypt.cipher_key,
				     kc->decrypt.cipher_key_size);
	if (IS_ERR(ks->decrypt)) {
		ret = PTR_ERR(ks->decrypt);
		ks->decrypt = NULL;
		goto destroy_ks;
	}
	ks->encrypt_sync = !crypto_tfm_is_async(crypto_aead_tfm(ks->encrypt));
	ks->decrypt_sync = !crypto_tfm_is_async(crypto_aead_tfm(ks->decrypt));

	memcpy(ks->nonce_tail_xmit, kc->encrypt.nonce_tail,
	       OVPN_NONCE_TAIL_SIZE);
	memcpy(ks->nonce_tail_recv, kc->decrypt.nonce_tail,
	       OVPN_NONCE_TAIL_SIZE);

	/* init packet ID generation/validation */
	ovpn_pktid_xmit_init(&ks->pid_xmit);
	ovpn_pktid_recv_init(&ks->pid_recv);

	return ks;

destroy_ks:
	ovpn_aead_crypto_key_slot_free(ks);
	kfree(ks);
	return ERR_PTR(ret);
}

enum ovpn_cipher_alg ovpn_aead_crypto_alg(struct ovpn_crypto_key_slot *ks)
{
	const char *alg_name;

	if (!ks->encrypt)
		return OVPN_CIPHER_ALG_NONE;

	alg_name = crypto_tfm_alg_name(crypto_aead_tfm(ks->encrypt));

	if (!strcmp(alg_name, ALG_NAME_AES))
		return OVPN_CIPHER_ALG_AES_GCM;
	else if (!strcmp(alg_name, ALG_NAME_CHACHAPOLY))
		return OVPN_CIPHER_ALG_CHACHA20_POLY1305;
	else if (!strcmp(alg_name, ALG_NAME_AEGIS128X4))
		return OVPN_CIPHER_ALG_AEGIS128X4;
	else
		return OVPN_CIPHER_ALG_NONE;
}
