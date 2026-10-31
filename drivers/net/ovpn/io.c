// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	James Yonan <james@openvpn.net>
 *		Antonio Quartulli <antonio@openvpn.net>
 */

#include <crypto/aead.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/gro_cells.h>
#include <net/gso.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "ovpnpriv.h"
#include "peer.h"
#include "io.h"
#include "bind.h"
#include "crypto.h"
#include "crypto_aead.h"
#include "netlink.h"
#include "proto.h"
#include "tcp.h"
#include "udp.h"
#include "skb.h"
#include "socket.h"

const unsigned char ovpn_keepalive_message[OVPN_KEEPALIVE_SIZE] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/* Leave room for the largest outer network header. The strict inequality in
 * is_skb_forwardable also requires staying one byte below gso_max_size.
 */
#define OVPN_UDP_GSO_MAX_PAYLOAD	(GSO_LEGACY_MAX_SIZE -		\
					 sizeof(struct ipv6hdr) -	\
					 sizeof(struct udphdr) - 1)
/**
 * ovpn_is_keepalive - check if skb contains a keepalive message
 * @skb: packet to check
 *
 * Assumes that the first byte of skb->data is defined.
 *
 * Return: true if skb contains a keepalive or false otherwise
 */
static bool ovpn_is_keepalive(struct sk_buff *skb)
{
	if (*skb->data != ovpn_keepalive_message[0])
		return false;

	if (skb->len != OVPN_KEEPALIVE_SIZE)
		return false;

	if (!pskb_may_pull(skb, OVPN_KEEPALIVE_SIZE))
		return false;

	return !memcmp(skb->data, ovpn_keepalive_message, OVPN_KEEPALIVE_SIZE);
}

/* Reconstruct inner offload state only from authenticated, bounded headers.
 * The segment size comes from the wire; derive the count from the payload.
 */
static int ovpn_tcp_gso_restore(struct sk_buff *skb, u16 gso_size)
{
	unsigned int thoff = 0, hdr_len, payload_len, gso_type;
	struct tcphdr *th;

	if (skb->protocol == htons(ETH_P_IP)) {
		const struct iphdr *iph = ip_hdr(skb);

		thoff = iph->ihl * 4;
		if (thoff < sizeof(*iph) || iph->protocol != IPPROTO_TCP ||
		    ip_is_fragment(iph) || ntohs(iph->tot_len) != skb->len)
			return -EINVAL;
		gso_type = SKB_GSO_TCPV4;
	} else {
		const struct ipv6hdr *iph = ipv6_hdr(skb);
		int flags = IP6_FH_F_AUTH;

		if (ntohs(iph->payload_len) + sizeof(*iph) != skb->len ||
		    ipv6_find_hdr(skb, &thoff, -1, NULL, &flags) != IPPROTO_TCP ||
		    (flags & IP6_FH_F_FRAG))
			return -EINVAL;
		gso_type = SKB_GSO_TCPV6;
	}

	if (!pskb_may_pull(skb, thoff + sizeof(*th)))
		return -EINVAL;
	skb_set_transport_header(skb, thoff);
	th = tcp_hdr(skb);
	if (th->doff < sizeof(*th) / 4 || th->syn || th->rst || th->urg)
		return -EINVAL;
	hdr_len = thoff + th->doff * 4;
	if (!pskb_may_pull(skb, hdr_len) || skb->len <= hdr_len)
		return -EINVAL;

	/* Match TCP GRO completion: restore the pseudo-header checksum seed
	 * and let the stack complete per-segment checksums when needed.
	 */
	th = tcp_hdr(skb);
	if (skb->protocol == htons(ETH_P_IP))
		th->check = ~tcp_v4_check(skb->len - thoff, ip_hdr(skb)->saddr,
					  ip_hdr(skb)->daddr, 0);
	else
		th->check = ~tcp_v6_check(skb->len - thoff, &ipv6_hdr(skb)->saddr,
					  &ipv6_hdr(skb)->daddr, 0);
	skb->csum_start = skb_headroom(skb) + thoff;
	skb->csum_offset = offsetof(struct tcphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	/* A short, single-segment input only needs checksum completion. */
	payload_len = skb->len - hdr_len;
	if (payload_len > gso_size) {
		skb_shinfo(skb)->gso_type = gso_type | SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_size = gso_size;
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(payload_len, gso_size);
	}

	return 0;
}

/* RX bookkeeping of the records a CPU delivers from one GRO list or one
 * parallel job: the peer's stats and references are updated once per batch
 * instead of with atomics on every record
 */
struct ovpn_rx_batch {
	struct ovpn_peer *peer;
	unsigned int bytes;
	unsigned int packets;
	unsigned int puts;
};

static DEFINE_PER_CPU(struct ovpn_rx_batch, ovpn_rx_batches);

/**
 * ovpn_rx_batch_begin - start batching the RX bookkeeping of a peer
 * @peer: the peer the following records belong to
 *
 * Must be called with BHs disabled, which must stay disabled until
 * ovpn_rx_batch_end().
 */
void ovpn_rx_batch_begin(struct ovpn_peer *peer)
{
	struct ovpn_rx_batch *b = this_cpu_ptr(&ovpn_rx_batches);

	DEBUG_NET_WARN_ON_ONCE(!in_softirq() || b->peer);
	b->peer = peer;
	b->bytes = 0;
	b->packets = 0;
	b->puts = 0;
}

/**
 * ovpn_rx_batch_end - flush the batched RX bookkeeping
 *
 * Must be called with BHs still disabled since ovpn_rx_batch_begin(). The
 * batched peer references are released last: the peer may be gone once this
 * returns.
 */
void ovpn_rx_batch_end(void)
{
	struct ovpn_rx_batch *b = this_cpu_ptr(&ovpn_rx_batches);
	struct ovpn_peer *peer = b->peer;

	b->peer = NULL;
	if (b->packets)
		ovpn_peer_stats_add_rx(&peer->vpn_stats, b->bytes, b->packets);
	if (b->puts)
		ovpn_peer_put_many(peer, b->puts);
}

/* the batch open for @peer on this CPU, if any. A batch is only open while
 * its owner keeps BHs disabled, so any other context that sees it with BHs
 * disabled (in_softirq() is also true then) is the owner's own call chain;
 * a hard IRQ completing crypto must not use it
 */
static struct ovpn_rx_batch *ovpn_rx_batch_get(struct ovpn_peer *peer)
{
	struct ovpn_rx_batch *b;

	if (!in_softirq() || in_hardirq())
		return NULL;

	b = this_cpu_ptr(&ovpn_rx_batches);
	return b->peer == peer ? b : NULL;
}

static void ovpn_rx_peer_put(struct ovpn_peer *peer)
{
	struct ovpn_rx_batch *b = ovpn_rx_batch_get(peer);

	if (b)
		b->puts++;
	else
		ovpn_peer_put(peer);
}

/* Called after decrypt to write the IP packet to the device.
 * This method is expected to manage/free the skb.
 */
static void ovpn_netdev_write(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_rx_batch *b;
	unsigned int pkt_len, packets = 1;
	int ret;

	/* skb hash for transport packet no longer valid after decapsulation */
	skb_clear_hash(skb);

	/* post-decrypt scrub -- prepare to inject encapsulated packet onto the
	 * interface, based on __skb_tunnel_rx() in dst.h
	 */
	skb->dev = peer->ovpn->dev;
	skb_set_queue_mapping(skb, 0);
	skb_scrub_packet(skb, true);

	/* network header reset in ovpn_decrypt_post() */
	skb_reset_mac_header(skb);
	skb_reset_inner_headers(skb);

	/* cause packet to be "received" by the interface */
	pkt_len = skb->len;
	if (skb_is_gso(skb)) {
		packets = skb_shinfo(skb)->gso_segs;
		pkt_len += (packets - 1) * skb_tcp_all_headers(skb);
	}
	/* we may get here in process context in case of TCP connections,
	 * therefore we have to disable BHs to ensure gro_cells_receive()
	 * and dev_dstats_rx_add() do not get corrupted or enter deadlock
	 */
	local_bh_disable();
	ret = gro_cells_receive(&peer->ovpn->gro_cells, skb);
	if (likely(ret == NET_RX_SUCCESS)) {
		/* update RX stats with the size of decrypted packet */
		b = ovpn_rx_batch_get(peer);
		if (b) {
			b->bytes += pkt_len;
			b->packets += packets;
		} else {
			ovpn_peer_stats_add_rx(&peer->vpn_stats, pkt_len,
					       packets);
		}
		ovpn_dev_dstats_rx_add(peer->ovpn->dev, pkt_len, packets);
	}
	local_bh_enable();
}

void ovpn_decrypt_post(void *data, int ret)
{
	struct ovpn_crypto_key_slot *ks;
	unsigned int payload_offset = 0;
	struct sk_buff *skb = data;
	struct ovpn_socket *sock;
	struct ovpn_peer *peer;
	u16 gso_size;
	__be16 proto;
	__be32 *pid;

	/* crypto is happening asynchronously. this function will be called
	 * again later by the crypto callback with a proper return code
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	payload_offset = ovpn_skb_cb(skb)->payload_offset;
	gso_size = ovpn_skb_cb(skb)->gso_size;
	ks = ovpn_skb_cb(skb)->ks;
	peer = ovpn_skb_cb(skb)->peer;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret < 0))
		goto drop;

	/* PID sits after the op */
	pid = (__force __be32 *)(skb->data + OVPN_OPCODE_SIZE);
	ret = ovpn_pktid_recv(&ks->pid_recv, ntohl(*pid), 0);
	if (unlikely(ret < 0)) {
		net_err_ratelimited("%s: PKT ID RX error for peer %u: %d\n",
				    netdev_name(peer->ovpn->dev), peer->id,
				    ret);
		goto drop;
	}

	/* keep track of last received authenticated packet for keepalive */
	WRITE_ONCE(peer->last_recv, ktime_get_boottime_seconds());

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (sock && sock->sk->sk_protocol == IPPROTO_UDP)
		/* check if this peer changed local or remote endpoint */
		ovpn_peer_endpoints_update(peer, skb);
	rcu_read_unlock();

	/* point to encapsulated IP packet */
	__skb_pull(skb, payload_offset);

	/* Discard outer offload state before reconstructing the inner packet.
	 * The packet was authenticated by the AEAD decryption, therefore it
	 * can't have been corrupted while travelling between the peers: skip
	 * the software checksum verification of all its layers, like
	 * wireguard does. A reconstructed GSO packet switches to
	 * CHECKSUM_PARTIAL below.
	 */
	skb->encapsulation = 0;
	skb_gso_reset(skb);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = SKB_MAX_CSUM_LEVEL;
	skb_reset_transport_header(skb);

	/* check if this is a valid datapacket that has to be delivered to the
	 * ovpn interface
	 */
	skb_reset_network_header(skb);
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto)) {
		/* check if null packet */
		if (unlikely(!pskb_may_pull(skb, 1))) {
			net_info_ratelimited("%s: NULL packet received from peer %u\n",
					     netdev_name(peer->ovpn->dev),
					     peer->id);
			goto drop;
		}

		if (!gso_size && ovpn_is_keepalive(skb)) {
			net_dbg_ratelimited("%s: ping received from peer %u\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id);
			/* we drop the packet, but this is not a failure */
			consume_skb(skb);
			goto drop_nocount;
		}

		net_info_ratelimited("%s: unsupported protocol received from peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		goto drop;
	}
	skb->protocol = proto;
	if (gso_size && ovpn_tcp_gso_restore(skb, gso_size))
		goto drop;

	/* perform Reverse Path Filtering (RPF) */
	if (unlikely(!ovpn_peer_check_by_src(peer->ovpn, skb, peer))) {
		if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI6c\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ipv6_hdr(skb)->saddr);
		else
			net_dbg_ratelimited("%s: RPF dropped packet from peer %u, src: %pI4\n",
					    netdev_name(peer->ovpn->dev),
					    peer->id, &ip_hdr(skb)->saddr);
		goto drop;
	}

	ovpn_netdev_write(peer, skb);
	/* skb is passed to upper layer - don't free it */
	skb = NULL;
drop:
	if (unlikely(skb))
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
	kfree_skb(skb);
drop_nocount:
	if (likely(ks))
		ovpn_crypto_key_slot_put(ks);
	ovpn_rx_peer_put(peer);
}

/* decrypt a record and forward it to the device, its link stats already
 * accounted by the caller
 */
void ovpn_recv_record(struct ovpn_peer *peer, struct sk_buff *skb, bool tcp)
{
	struct ovpn_crypto_key_slot *ks;
	u8 key_id;

	/* get the key slot matching the key ID in the received packet */
	key_id = ovpn_key_id_from_skb(skb);
	ks = ovpn_crypto_key_id_to_slot(&peer->crypto, key_id);
	if (unlikely(!ks)) {
		net_info_ratelimited("%s: no available key for peer %u, key-id: %u\n",
				     netdev_name(peer->ovpn->dev), peer->id,
				     key_id);
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
		kfree_skb(skb);
		ovpn_peer_put(peer);
		return;
	}

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_decrypt_post(skb, ovpn_aead_decrypt(peer, ks, skb, tcp));
}

/* RX path entry point: decrypt packet and forward it to the device */
void ovpn_recv(struct ovpn_peer *peer, struct sk_buff *skb, bool tcp)
{
	ovpn_peer_stats_increment_rx(&peer->link_stats, skb->len);
	ovpn_recv_record(peer, skb, tcp);
}

static void ovpn_encrypt_key_exhausted(struct ovpn_peer *peer,
				       struct ovpn_crypto_key_slot *ks)
{
	netdev_warn(peer->ovpn->dev, "killing key %u for peer %u\n",
		    ks->key_id, peer->id);
	if (ovpn_crypto_kill_key(&peer->crypto, ks->key_id))
		/* let userspace know so that a new key must be negotiated */
		ovpn_nl_key_swap_notify(peer, ks->key_id);
}

void ovpn_encrypt_post(void *data, int ret)
{
	unsigned int orig_len, packets = 1;
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *skb = data;
	struct ovpn_socket *sock;
	struct ovpn_cb *batch_cb;
	struct ovpn_peer *peer;
	struct sk_buff *batch;

	/* encryption is happening asynchronously. This function will be
	 * called later by the crypto callback with a proper return value
	 */
	if (unlikely(ret == -EINPROGRESS))
		return;

	/* ordinary encryption leaves batch zeroed; a GSO input uses it to find
	 * the aggregate whose lifetime is shared by all segment requests
	 */
	batch = ovpn_skb_cb(skb)->batch;
	peer = ovpn_skb_cb(skb)->peer;
	ks = ovpn_skb_cb(skb)->ks;
	packets = ovpn_skb_cb(skb)->tcp_packets ?: 1;

	/* crypto is done, cleanup skb CB and its members */
	kfree(ovpn_skb_cb(skb)->crypto_tmp);

	if (unlikely(ret == -ERANGE)) {
		/* we ran out of IVs and we must kill the key as it can't be
		 * used anymore
		 */
		ovpn_encrypt_key_exhausted(peer, ks);
	}

	if (batch) {
		batch_cb = ovpn_skb_cb(batch);
		/* every segment publishes its result before releasing its
		 * pending count and only the final completion continues with
		 * the aggregate
		 */
		if (unlikely(ret < 0)) {
			atomic_set(&batch_cb->batch_state.failed, 1);
			kfree_skb(skb);
		} else {
			/* the encrypted data now lives in the aggregate */
			consume_skb(skb);
		}
		if (!atomic_dec_and_test(&batch_cb->batch_state.pending))
			return;

		skb = batch;
		packets = skb_shinfo(batch)->gso_segs;
		if (unlikely(atomic_read(&batch_cb->batch_state.failed)))
			goto err;

		/* reaching the final callback with no sticky failure means
		 * every segment completed successfully
		 */
		ret = 0;
	}

	if (unlikely(ret < 0))
		goto err;

	skb_mark_not_on_list(skb);
	orig_len = skb->len;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	if (unlikely(!sock))
		goto err_unlock;

	switch (sock->sk->sk_protocol) {
	case IPPROTO_UDP:
		ovpn_udp_send_skb(peer, sock->sk, skb);
		break;
	case IPPROTO_TCP:
		ovpn_tcp_send_skb(peer, sock->sk, skb);
		break;
	default:
		/* no transport configured yet */
		goto err_unlock;
	}

	ovpn_peer_stats_add_tx(&peer->link_stats, orig_len, packets);
	/* keep track of last sent packet for keepalive */
	WRITE_ONCE(peer->last_sent, ktime_get_boottime_seconds());
	/* skb passed down the stack - don't free it */
	skb = NULL;
err_unlock:
	rcu_read_unlock();
err:
	if (unlikely(skb))
		ovpn_dev_dstats_tx_dropped(peer->ovpn->dev, packets);
	kfree_skb(skb);
	if (likely(ks))
		ovpn_crypto_key_slot_put(ks);
	ovpn_peer_put(peer);
}

/* One request owns the input and output, with no UDP batch completion state.
 * The output owns the peer/key references used by the ordinary send path.
 */
void ovpn_encrypt_tcp_gso_post(void *data, int ret)
{
	struct sk_buff *skb = data;
	struct sk_buff *gso_skb;

	if (unlikely(ret == -EINPROGRESS))
		return;

	gso_skb = ovpn_skb_cb(skb)->tcp_gso;
	kfree(ovpn_skb_cb(skb)->crypto_tmp);
	consume_skb(skb);
	ovpn_encrypt_post(gso_skb, ret);
}

/* Prepare the output control block and hold its peer and primary key.
 * Completion releases both references, once per ordinary packet or aggregate.
 */
static struct ovpn_crypto_key_slot *
ovpn_encrypt_prepare(struct ovpn_peer *peer, struct sk_buff *skb,
		     unsigned int tcp_packets)
{
	struct ovpn_crypto_key_slot *ks;

	/* get primary key to be used for encrypting data */
	ks = ovpn_crypto_key_slot_primary(&peer->crypto);
	if (unlikely(!ks))
		return NULL;

	/* the caller already owns a peer reference, so failure indicates a
	 * broken reference lifetime elsewhere
	 */
	if (unlikely(!ovpn_peer_hold(peer))) {
		DEBUG_NET_WARN_ON_ONCE(1);
		ovpn_crypto_key_slot_put(ks);
		return NULL;
	}

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(skb)->peer = peer;
	ovpn_skb_cb(skb)->ks = ks;
	ovpn_skb_cb(skb)->tcp_packets = tcp_packets;

	return ks;
}

static bool ovpn_peer_uses_tcp(struct ovpn_peer *peer)
{
	struct ovpn_socket *sock;
	bool tcp;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	tcp = sock && sock->sk->sk_protocol == IPPROTO_TCP;
	rcu_read_unlock();

	return tcp;
}

static bool ovpn_encrypt_one(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;

	ks = ovpn_encrypt_prepare(peer, skb, ovpn_peer_uses_tcp(peer));
	if (unlikely(!ks))
		return false;

	ovpn_encrypt_post(skb, ovpn_aead_encrypt(peer, ks, skb));
	return true;
}

static void ovpn_skb_prefetch_frag(const struct sk_buff *skb)
{
	unsigned long addr, end;
	const skb_frag_t *frag;

	if (!skb_shinfo(skb)->nr_frags)
		return;

	frag = &skb_shinfo(skb)->frags[0];
	/* prefetch requires a directly accessible kernel virtual address */
	addr = (unsigned long)skb_frag_address_safe(frag);
	if (!addr)
		return;

	end = addr + skb_frag_size(frag);
	/* the linear head was just touched by segmentation, so prefetch the
	 * first shared payload frag without repeating crypto's full sg walk
	 */
	for (; addr < end; addr = ALIGN(addr + 1, L1_CACHE_BYTES))
		prefetch((void *)addr);
}

static bool ovpn_encrypt_udp_gso_queue(struct sk_buff_head *skbs,
				       struct ovpn_peer *peer,
				       struct sk_buff *batch,
				       unsigned int segments)
{
	unsigned int offset = 0, i, len;
	struct ovpn_crypto_key_slot *ks;
	struct sk_buff *skb;
	u32 first_pktid;
	int ret;

	/* acquire all shared state before removing the first input skb so that
	 * failure can leave the queue intact for the ordinary transmit path
	 */
	ks = ovpn_encrypt_prepare(peer, batch, 0);
	if (unlikely(!ks))
		return false;

	/* reserve the complete range before dequeuing any input skb so that a
	 * failure leaves the ordinary transmit path available as a fallback
	 */
	if (unlikely(ovpn_pktid_xmit_range(&ks->pid_xmit, segments,
					   &first_pktid))) {
		ovpn_encrypt_key_exhausted(peer, ks);
		ovpn_crypto_key_slot_put(ks);
		ovpn_peer_put(peer);
		return false;
	}

	atomic_set(&ovpn_skb_cb(batch)->batch_state.pending, segments);
	atomic_set(&ovpn_skb_cb(batch)->batch_state.failed, 0);

	for (i = 0; i < segments; i++) {
		skb = __skb_dequeue(skbs);
		len = skb->len + OVPN_DATA_V2_OVERHEAD;

		/* overlap fetching the next segment's shared payload with
		 * encryption of the current segment
		 */
		if (i + 1 < segments)
			ovpn_skb_prefetch_frag(skb_peek(skbs));

		memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
		ovpn_skb_cb(skb)->batch = batch;
		ret = ovpn_aead_encrypt_udp_gso(peer, ks, skb, batch, offset,
						first_pktid + i);
		ovpn_encrypt_post(skb, ret);
		offset += len;
	}

	return true;
}

static struct sk_buff *ovpn_gso_alloc(const struct sk_buff *skb,
				      unsigned int head_len,
				      unsigned int data_len)
{
	struct sk_buff *gso_skb;
	int ret;

	gso_skb = alloc_skb_with_frags(OVPN_HEAD_ROOM + head_len, data_len,
				       SKB_FRAG_PAGE_ORDER, &ret, GFP_ATOMIC);
	if (unlikely(!gso_skb))
		return NULL;

	skb_reserve(gso_skb, OVPN_HEAD_ROOM);
	skb_put(gso_skb, head_len);
	gso_skb->len += data_len;
	gso_skb->data_len = data_len;
	gso_skb->priority = skb->priority;

	/* Keep the originating socket's send-buffer accounting active until
	 * the output is transmitted. This also preserves its cached TX queue.
	 */
	if (skb->sk && is_skb_wmem(skb))
		skb_set_owner_w(gso_skb, skb->sk);

	return gso_skb;
}

static struct sk_buff *ovpn_udp_gso_alloc(const struct sk_buff *first_segment,
					  unsigned int batch_len,
					  unsigned int segments)
{
	struct sk_buff *gso_skb;

	gso_skb = ovpn_gso_alloc(first_segment, 0, batch_len);
	if (unlikely(!gso_skb))
		return NULL;

	skb_copy_hash(gso_skb, first_segment);
#ifdef CONFIG_XPS
	/* keep the aggregate on the TX queue selected for the original flow
	 * otherwise async crypto completion on another CPU could move the flow
	 * to a different queue and cause delay or reordering
	 */
	gso_skb->sender_cpu = first_segment->sender_cpu;
#endif

	skb_shinfo(gso_skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(gso_skb)->gso_size = first_segment->len +
					OVPN_DATA_V2_OVERHEAD;
	skb_shinfo(gso_skb)->gso_segs = segments;

	return gso_skb;
}

/* send skb to connected peer, if any */
static void ovpn_send(struct ovpn_priv *ovpn, struct sk_buff *skb,
		      struct ovpn_peer *peer)
{
	struct sk_buff *curr, *next;

	/* this might be a GSO-segmented skb list: process each skb
	 * independently
	 */
	skb_list_walk_safe(skb, curr, next) {
		/* encrypting this segment can hide the cost of fetching the
		 * next segment's data into the cache
		 */
		if (next)
			ovpn_skb_prefetchw_linear(next);

		if (unlikely(!ovpn_encrypt_one(peer, curr))) {
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			kfree_skb(curr);
		}
	}

	ovpn_peer_put(peer);
}

/* encrypt fixed-size input segments into one or more UDP GSO aggregates */
static void ovpn_send_udp_gso(struct sk_buff_head *skbs, struct ovpn_peer *peer)
{
	unsigned int max_segs = 1, seg_len, batch_len, segs;
	struct sk_buff *batch;

	seg_len = skb_peek(skbs)->len + OVPN_DATA_V2_OVERHEAD;
	max_segs = min_t(unsigned int, UDP_MAX_SEGMENTS,
			 OVPN_UDP_GSO_MAX_PAYLOAD / seg_len);

	/* if even two encrypted skbs cannot fit, leave the whole queue for the
	 * ordinary transmit path
	 */
	if (max_segs < 2)
		return;

	/* An input GSO skb might be prduce more than max_segs segments so we
	 * consume as many as we can for each iteration. A final single skb, or
	 * the whole remainder after an allocation failure, stays queued and
	 * fallback to the ordinary transmit path.
	 */
	while (skb_queue_len(skbs) > 1) {
		segs = min_t(unsigned int, skb_queue_len(skbs), max_segs);

		/* all but the final input skb have the same length, so start
		 * with the full-size calculation and adjust only the final
		 * group below
		 */
		batch_len = segs * (skb_peek(skbs)->len +
				    OVPN_DATA_V2_OVERHEAD);
		if (segs == skb_queue_len(skbs))
			batch_len -= skb_peek(skbs)->len -
				     skb_peek_tail(skbs)->len;

		batch = ovpn_udp_gso_alloc(skb_peek(skbs), batch_len, segs);
		if (unlikely(!batch))
			return;

		if (unlikely(!ovpn_encrypt_udp_gso_queue(skbs, peer,
							 batch, segs))) {
			kfree_skb(batch);
			return;
		}
	}
}

static bool ovpn_peer_supports_udp_gso(struct ovpn_peer *peer)
{
	struct ovpn_socket *sock;
	bool udp_gso;

	rcu_read_lock();
	sock = rcu_dereference(peer->sock);
	/* UDP GSO requires checksums. These socket settings can change after
	 * we decide to batch, but an already-built batch remains checksummed.
	 * Linux's ordinary UDP GSO path makes the same choice.
	 */
	udp_gso = sock && sock->sk->sk_protocol == IPPROTO_UDP &&
		  !sock->sk->sk_no_check_tx && !udp_get_no_check6_tx(sock->sk);
	rcu_read_unlock();

	return udp_gso;
}

/* The transmit stack validates GSO geometry, including DODGY inputs. Only
 * check whether the wire format can represent this skb's offload semantics.
 */
static bool ovpn_tcp_gso_eligible(const struct sk_buff *skb,
				  unsigned int *segments, unsigned int *hdr_len)
{
	const struct skb_shared_info *shinfo = skb_shinfo(skb);
	unsigned int type = shinfo->gso_type & ~SKB_GSO_DODGY;
	unsigned int payload_len;

	if (skb->encapsulation || skb->len > OVPN_TCP_GSO_MAX_INNER ||
	    skb->ip_summed != CHECKSUM_PARTIAL)
		return false;

	if (type != SKB_GSO_TCPV4 && type != SKB_GSO_TCPV6)
		return false;

	*hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
	payload_len = skb->len - *hdr_len;
	*segments = DIV_ROUND_UP(payload_len, shinfo->gso_size);

	return true;
}

/* Returning false leaves the input owned by the segmentation fallback. */
static bool ovpn_send_tcp_gso(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct ovpn_crypto_key_slot *ks;
	unsigned int segments, hdr_len;
	struct sk_buff *gso_skb;
	int ret;

	if (!ovpn_peer_uses_tcp(peer) ||
	    !ovpn_tcp_gso_eligible(skb, &segments, &hdr_len))
		return false;

	gso_skb = ovpn_gso_alloc(skb, OVPN_DATA_V2_OVERHEAD, skb->len);
	if (unlikely(!gso_skb))
		return false;

	ks = ovpn_encrypt_prepare(peer, gso_skb, segments);
	if (unlikely(!ks)) {
		kfree_skb(gso_skb);
		return false;
	}

	/* Account the same inner bytes as software segmentation, including
	 * replicated IP/TCP headers. The link path counts ciphertext bytes.
	 */
	ovpn_peer_stats_add_tx(&peer->vpn_stats,
			       skb->len + (segments - 1) * hdr_len, segments);

	memset(ovpn_skb_cb(skb), 0, sizeof(struct ovpn_cb));
	ovpn_skb_cb(skb)->tcp_gso = gso_skb;
	ret = ovpn_aead_encrypt_tcp_gso(peer, ks, skb, gso_skb);
	ovpn_encrypt_tcp_gso_post(skb, ret);
	return true;
}

/* Whether to segment a GSO packet into linear skbs. skb_segment() then
 * computes the inner checksum of each segment while copying its payload, and
 * the AEAD encrypts one contiguous buffer per segment. With page fragments
 * instead, each segment takes a separate checksum pass and reaches the AEAD as
 * two chunks, its headers and its payload, which costs the AEAD more than the
 * whole copy. Only segments fitting in a page are built linear: larger ones
 * would need high-order atomic allocations, and their per-byte costs dominate
 * anyway. The linear head bounds the headers skb_segment() copies.
 */
static bool ovpn_gso_linear(const struct sk_buff *skb)
{
	return SKB_HEAD_ALIGN(skb_headroom(skb) + skb_headlen(skb) +
			      skb_shinfo(skb)->gso_size) <= PAGE_SIZE;
}

/* Send user data to the network
 */
netdev_tx_t ovpn_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ovpn_priv *ovpn = netdev_priv(dev);
	struct sk_buff *segments, *curr, *next;
	const bool gso_in = skb_is_gso(skb);
	struct sk_buff_head skb_list;
	netdev_features_t features;
	unsigned int tx_bytes = 0;
	struct ovpn_peer *peer;
	bool gso_out;
	__be16 proto;
	int ret;

	/* Make skb metadata private before modifying it or acquiring TX refs.
	 * Packet data can remain shared for out-of-place encryption.
	 */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ovpn_dev_dstats_tx_dropped(dev, 1);
		return NETDEV_TX_OK;
	}

	/* A frag-list GSO skb already stores complete segments as child skbs.
	 * Keep those children on the ordinary in-place encryption path instead
	 * of copying them into a replacement UDP GSO skb.
	 *
	 * GSO_BY_FRAGS input must remain on that path too because its variable
	 * segment sizes cannot be represented by one UDP GSO output size.
	 */
	gso_out = gso_in &&
		  !(skb_shinfo(skb)->gso_type & SKB_GSO_FRAGLIST) &&
		  skb_shinfo(skb)->gso_size != GSO_BY_FRAGS;

	/* reset netfilter state */
	nf_reset_ct(skb);

	/* verify IP header size in network packet */
	proto = ovpn_ip_check_protocol(skb);
	if (unlikely(!proto || skb->protocol != proto))
		goto drop_no_peer;

	/* retrieve peer serving the destination IP of this packet */
	peer = ovpn_peer_get_by_dst(ovpn, skb);
	if (unlikely(!peer)) {
		switch (skb->protocol) {
		case htons(ETH_P_IP):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI4\n",
					    netdev_name(ovpn->dev),
					    &ip_hdr(skb)->daddr);
			break;
		case htons(ETH_P_IPV6):
			net_dbg_ratelimited("%s: no peer to send data to dst=%pI6c\n",
					    netdev_name(ovpn->dev),
					    &ipv6_hdr(skb)->daddr);
			break;
		}
		goto drop_no_peer;
	}
	/* dst was needed for peer selection - it can now be dropped */
	skb_dst_drop(skb);

	/* if this is an eligible GSO skb and we're using TCP as transport
	 * protocol, try to send it without prior segmentation
	 */
	if (gso_in && ovpn_send_tcp_gso(peer, skb)) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}

	if (gso_in) {
		/* force software segmentation and calculate each checksum */
		features = netif_skb_features(skb);
		features &= ~(NETIF_F_GSO_MASK | NETIF_F_CSUM_MASK);
		/* frag-list children would only be linearized, not checksummed */
		if (gso_out && ovpn_gso_linear(skb))
			features &= ~NETIF_F_SG;
		segments = skb_gso_segment(skb, features);
		if (IS_ERR(segments)) {
			ret = PTR_ERR(segments);
			net_err_ratelimited("%s: cannot segment payload packet: %d\n",
					    netdev_name(dev), ret);
			goto drop;
		}

		if (segments) {
			consume_skb(skb);
			skb = segments;
		} else {
			/* nothing to segment: send the packet as it is */
			skb_gso_reset(skb);
		}
	}

	/* from this moment on, "skb" might be a list */

	__skb_queue_head_init(&skb_list);
	skb_list_walk_safe(skb, curr, next) {
		skb_mark_not_on_list(curr);

		curr = skb_share_check(curr, GFP_ATOMIC);
		if (unlikely(!curr)) {
			net_err_ratelimited("%s: skb_share_check failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			gso_out = false;
			continue;
		}

		/* NETIF_F_HW_CSUM requires completing partial checksums */
		if (unlikely(curr->ip_summed == CHECKSUM_PARTIAL &&
			     skb_csum_hwoffload_help(curr, 0) < 0)) {
			net_err_ratelimited("%s: skb_checksum_help failed for payload packet\n",
					    netdev_name(dev));
			ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
			kfree_skb(curr);
			gso_out = false;
			continue;
		}

		/* only count what we actually send */
		tx_bytes += curr->len;
		__skb_queue_tail(&skb_list, curr);
	}

	/* no segments survived: don't jump to 'drop' because we already
	 * incremented the counter for each failure in the loop
	 */
	if (unlikely(skb_queue_empty(&skb_list))) {
		ovpn_peer_put(peer);
		return NETDEV_TX_OK;
	}

	ovpn_peer_stats_increment_tx(&peer->vpn_stats, tx_bytes);

	if (gso_out && skb_queue_len(&skb_list) > 1 &&
	    ovpn_peer_supports_udp_gso(peer))
		ovpn_send_udp_gso(&skb_list, peer);

	skb_list.prev->next = NULL;
	ovpn_send(ovpn, skb_list.next, peer);

	return NETDEV_TX_OK;

drop:
	ovpn_peer_put(peer);
drop_no_peer:
	ovpn_dev_dstats_tx_dropped(ovpn->dev, 1);
	skb_tx_error(skb);
	kfree_skb_list(skb);
	return NETDEV_TX_OK;
}

/**
 * ovpn_xmit_special - encrypt and transmit an out-of-band message to peer
 * @peer: peer to send the message to
 * @data: message content
 * @len: message length
 *
 * Assumes that caller holds a reference to peer, which will be
 * passed to ovpn_send()
 */
void ovpn_xmit_special(struct ovpn_peer *peer, const void *data,
		       const unsigned int len)
{
	struct ovpn_priv *ovpn;
	struct sk_buff *skb;

	ovpn = peer->ovpn;
	if (unlikely(!ovpn)) {
		ovpn_peer_put(peer);
		return;
	}

	skb = alloc_skb(256 + len, GFP_ATOMIC);
	if (unlikely(!skb)) {
		ovpn_peer_put(peer);
		return;
	}

	skb_reserve(skb, 128);
	skb->priority = TC_PRIO_BESTEFFORT;
	__skb_put_data(skb, data, len);

	ovpn_send(ovpn, skb, peer);
}
