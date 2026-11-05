/* SPDX-License-Identifier: GPL-2.0-only */
/* OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#ifndef _NET_OVPN_OVPN_H_
#define _NET_OVPN_OVPN_H_

#include <linux/cache.h>
#include <linux/prefetch.h>

/* DATA_V2 header size with AEAD encryption */
#define OVPN_HEAD_ROOM (OVPN_DATA_V2_OVERHEAD +				   \
			max(sizeof(struct udphdr), sizeof(struct tcphdr)) +\
			max(sizeof(struct ipv6hdr), sizeof(struct iphdr)))

/* max padding required by encryption */
#define OVPN_MAX_PADDING 16

#define OVPN_KEEPALIVE_SIZE 16
extern const unsigned char ovpn_keepalive_message[OVPN_KEEPALIVE_SIZE];

static inline void ovpn_skb_prefetchw_linear(const struct sk_buff *skb)
{
	unsigned long addr = (unsigned long)skb->data;
	unsigned long end = addr + skb_headlen(skb);

	/* crypto overwrites data in place, so request write ownership of each
	 * linear cache line before the AEAD implementation reaches it
	 */
	for (; addr < end; addr = ALIGN(addr + 1, L1_CACHE_BYTES))
		prefetchw((void *)addr);
}

netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev);
int ovpn_tx_segs_alloc(void);
void ovpn_tx_segs_free(void);

void ovpn_recv_record(struct ovpn_peer *peer, struct sk_buff *skb, bool tcp);
void ovpn_recv(struct ovpn_peer *peer, struct sk_buff *skb, bool tcp);
void ovpn_rx_batch_begin(struct ovpn_peer *peer);
void ovpn_rx_batch_end(void);
void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
		       const unsigned int len);

void ovpn_encrypt_post(void *data, int ret);
void ovpn_encrypt_tcp_gso_post(void *data, int ret);
void ovpn_decrypt_post(void *data, int ret);

#endif /* _NET_OVPN_OVPN_H_ */
