// SPDX-License-Identifier: GPL-2.0
/*  OpenVPN data channel offload
 *
 *  Copyright (C) 2019-2025 OpenVPN, Inc.
 *
 *  Author:	Antonio Quartulli <antonio@openvpn.net>
 */

#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <net/addrconf.h>
#include <net/dst_cache.h>
#include <net/gro.h>
#include <net/route.h>
#include <net/transp_v6.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>

#include "ovpnpriv.h"
#include "main.h"
#include "bind.h"
#include "io.h"
#include "peer.h"
#include "proto.h"
#include "socket.h"
#include "udp.h"

/* like UDP and TCP frag-list GRO */
#define OVPN_UDP_GRO_CNT_MAX 64

static bool ovpn_udp_gro_header(struct sk_buff *skb, u32 *header)
{
	const unsigned int offset = skb_gro_offset(skb);

	/* GRO replaces its frag0 pointer after holding an skb, so keep the
	 * openvpn header linear for later candidate comparisons
	 */
	if (!pskb_may_pull(skb, offset + OVPN_OPCODE_SIZE))
		return false;

	*header = get_unaligned_be32(skb->data + offset);
	return true;
}

static struct sk_buff *ovpn_udp_gro_receive_fraglist(struct sock *sk,
						     struct list_head *head,
						     struct sk_buff *skb)
{
	const unsigned int gso_size = skb_gro_len(skb);
	struct sk_buff *p, *pp = NULL;
	u32 header, header2;
	int ret = 0, nhoff;
	bool flush;

	/* A packet that cannot join an aggregate (not a data record, or an
	 * existing GSO packet) must not overtake the records of the same
	 * flow that GRO is still holding: complete those first, as the other
	 * GRO handlers do.
	 */
	if (!ovpn_udp_gro_header(skb, &header) ||
	    FIELD_GET(OVPN_OPCODE_PKTTYPE_MASK, header) != OVPN_DATA_V2 ||
	    skb_is_gso(skb)) {
		NAPI_GRO_CB(skb)->flush = 1;
		list_for_each_entry(p, head, list)
			if (NAPI_GRO_CB(p)->same_flow)
				return p;
		return NULL;
	}

	/* the record is decrypted only after its aggregate is delivered: start
	 * fetching its linear data now, one record at a time
	 */
	ovpn_skb_prefetchw_linear(skb);

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		/* match opcode, key ID and peer ID: a different header on the
		 * same transport flow (e.g. after a key change) completes the
		 * held aggregate instead of overtaking it, and the new record
		 * starts the next one
		 */
		if (!ovpn_udp_gro_header(p, &header2) || header != header2)
			return p;

		/* GRO has already matched the outer addresses and UDP ports;
		 * check the remaining outer IP fields
		 */
		nhoff = skb_transport_offset(p) -
			NAPI_GRO_CB(p)->network_offset;
		flush = __gro_receive_network_flush(udp_hdr(skb), udp_hdr(p), p,
						    nhoff, false);

		/* The first record determines the nominal GSO size. A shorter
		 * final record may follow it, but a larger record cannot.
		 * Checksum metadata must also be uniform because the aggregate
		 * exposes only one checksum state.
		 */
		if (gso_size > skb_shinfo(p)->gso_size || flush ||
		    skb->ip_summed != p->ip_summed ||
		    skb->csum_level != p->csum_level) {
			pp = p;
		} else {
			/* skb_gro_receive_list pulls the headers already
			 * processed by GRO before linking this skb to the
			 * record list so we have to manually preserve the
			 * outer network header location for later handling
			 */
			nhoff = NAPI_GRO_CB(skb)->network_offset;
			skb_set_network_header(skb, nhoff);
			ret = skb_gro_receive_list(p, skb);
		}

		/* complete the aggregate if the append failed, or after
		 * appending a shorter final record, or after reaching the
		 * record-count limit
		 */
		if (ret || gso_size != skb_shinfo(p)->gso_size ||
		    NAPI_GRO_CB(p)->count >= OVPN_UDP_GRO_CNT_MAX)
			pp = p;

		return pp;
	}

	return NULL;
}

static int ovpn_udp_gro_complete(struct sock *sk, struct sk_buff *skb,
				 int nhoff)
{
	/* udp_gro_complete has already marked this as a UDP tunnel GSO packet.
	 * Keep that type so UDP passes the aggregate directly to the encap cb,
	 * where the original record skbs are detached.
	 */
	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;

	/* Each outer UDP checksum was either validated (or accepted in case of
	 * checksumless UDP) before its record was merged in
	 * skb_gro_checksum_validate_zero_check.
	 * The checksum in the aggregate cannot describe the concatenation of
	 * independent UDP payloads, so we preserve the validation result.
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = 0;
	skb->csum_valid = 0;

	return 0;
}

/* skb_gro_receive_list keeps the first openvpn record in 'skb' and links the
 * remaining records through fraglist. Here we segment by detaching that list
 * before delivering the records individually, and remove the child skbs from
 * the head skb's length and memory accounting so the head describes only the
 * first record again.
 */
static struct sk_buff *ovpn_udp_gro_detach(struct sk_buff *skb,
					   unsigned int *count,
					   unsigned int *len)
{
	unsigned int data_len = 0, truesize = 0, n = 0;
	struct sk_buff *curr, *list;
	int ret;

	*count = 0;
	*len = 0;

	/* IP reassembly may also use fraglist, but it is not a record batch */
	if (!skb_is_gso(skb) ||
	    !(skb_shinfo(skb)->gso_type &
	      (SKB_GSO_UDP_TUNNEL | SKB_GSO_UDP_TUNNEL_CSUM)))
		return NULL;

	if (unlikely(!skb_shinfo(skb)->frag_list))
		return NULL;

	/* packet taps may have cloned the aggregate before it reached UDP, so
	 * make shared info private before removing its fraglist
	 */
	ret = skb_unclone(skb, GFP_ATOMIC);
	if (unlikely(ret))
		return ERR_PTR(ret);

	list = skb_shinfo(skb)->frag_list;

	for (curr = list; curr; curr = curr->next) {
		data_len += curr->len;
		truesize += curr->truesize;
		n++;
	}

	skb_shinfo(skb)->frag_list = NULL;
	skb->len -= data_len;
	skb->data_len -= data_len;
	skb->truesize -= truesize;

	*count = n;
	*len = data_len;
	return list;
}

static void ovpn_udp_recv(struct ovpn_peer *peer, struct sk_buff *skb)
{
	struct sk_buff *list, *next;
	unsigned int n, list_len;

	list = ovpn_udp_gro_detach(skb, &n, &list_len);
	if (IS_ERR(list)) {
		ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
		kfree_skb(skb);
		ovpn_peer_put(peer);
		return;
	}
	skb->next = list;

	/* account the link stats of the whole list at once, and give each
	 * further record its own peer reference: the caller's covers the
	 * first one
	 */
	ovpn_peer_stats_add_rx(&peer->link_stats, skb->len + list_len, n + 1);
	if (n)
		ovpn_peer_hold_many(peer, n);

	/* the records completed here release the peer and update its stats
	 * once, at the end
	 */
	ovpn_rx_batch_begin(peer);

	skb_list_walk_safe(skb, skb, next)
	{
		/* skb_unclone can leave fraglist children shared with a packet
		 * tap, so make each skb header private before changing its
		 * list pointer or control block. skb_cow_data makes the packet
		 * data writable later in the decrypt path.
		 */
		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb)) {
			ovpn_dev_dstats_rx_dropped(peer->ovpn->dev);
			/* this record's reference; the batched ones keep the
			 * peer alive
			 */
			ovpn_peer_put(peer);
			continue;
		}

		skb_mark_not_on_list(skb);

		ovpn_recv_record(peer, skb, false);
	}

	ovpn_rx_batch_end();
}

/* Retrieve the corresponding ovpn object from a UDP socket
 * rcu_read_lock must be held on entry
 */
static struct ovpn_socket *ovpn_socket_from_udp_sock(struct sock *sk)
{
	struct ovpn_socket *ovpn_sock;

	if (unlikely(READ_ONCE(udp_sk(sk)->encap_type) != UDP_ENCAP_OVPNINUDP))
		return NULL;

	ovpn_sock = rcu_dereference_sk_user_data(sk);
	if (unlikely(!ovpn_sock))
		return NULL;

	/* make sure that sk matches our stored transport socket */
	if (unlikely(!ovpn_sock->sk || sk != ovpn_sock->sk))
		return NULL;

	return ovpn_sock;
}

/**
 * ovpn_udp_encap_recv - Start processing a received UDP packet.
 * @sk: socket over which the packet was received
 * @skb: the received packet
 *
 * If the first byte of the payload is:
 * - DATA_V2 the packet is accepted for further processing,
 * - DATA_V1 the packet is dropped as not supported,
 * - anything else the packet is forwarded to the UDP stack for
 *   delivery to user space.
 *
 * Return:
 *  0 if skb was consumed or dropped
 * >0 if skb should be passed up to userspace as UDP (packet not consumed)
 * <0 if skb should be resubmitted as proto -N (packet not consumed)
 */
static int ovpn_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct ovpn_socket *ovpn_sock;
	struct ovpn_priv *ovpn;
	struct ovpn_peer *peer;
	u32 peer_id;
	u8 opcode;

	ovpn_sock = ovpn_socket_from_udp_sock(sk);
	if (unlikely(!ovpn_sock)) {
		net_err_ratelimited("ovpn: %s invoked on non ovpn socket\n",
				    __func__);
		goto drop_noovpn;
	}

	ovpn = ovpn_sock->ovpn;
	if (unlikely(!ovpn)) {
		net_err_ratelimited("ovpn: cannot obtain ovpn object from UDP socket\n");
		goto drop_noovpn;
	}

	/* Make sure the first 4 bytes of the skb data buffer after the UDP
	 * header are accessible.
	 * They are required to fetch the OP code, the key ID and the peer ID.
	 */
	if (unlikely(!pskb_may_pull(skb, sizeof(struct udphdr) +
				    OVPN_OPCODE_SIZE))) {
		net_dbg_ratelimited("%s: packet too small from UDP socket\n",
				    netdev_name(ovpn->dev));
		goto drop;
	}

	opcode = ovpn_opcode_from_skb(skb, sizeof(struct udphdr));
	if (unlikely(opcode != OVPN_DATA_V2)) {
		/* DATA_V1 is not supported */
		if (opcode == OVPN_DATA_V1)
			goto drop;

		/* unknown or control packet: let it bubble up to userspace */
		return 1;
	}

	peer_id = ovpn_peer_id_from_skb(skb, sizeof(struct udphdr));
	/* some OpenVPN server implementations send data packets with the
	 * peer-id set to UNDEF. In this case we skip the peer lookup by peer-id
	 * and we try with the transport address
	 */
	if (peer_id == OVPN_PEER_ID_UNDEF)
		peer = ovpn_peer_get_by_transp_addr(ovpn, skb);
	else
		peer = ovpn_peer_get_by_id(ovpn, peer_id);

	if (unlikely(!peer))
		goto drop;

	/* pop off outer UDP header */
	__skb_pull(skb, sizeof(struct udphdr));
	ovpn_udp_recv(peer, skb);
	return 0;

drop:
	ovpn_dev_dstats_rx_dropped(ovpn->dev);
drop_noovpn:
	kfree_skb(skb);
	return 0;
}

static bool ovpn_route_key_equal(const struct ovpn_route_key *a,
				 const struct ovpn_route_key *b)
{
	return a->mark == b->mark && a->sport == b->sport;
}

/**
 * ovpn_dst_cache_check_key - reset peer dst cache after key changes
 * @peer: the peer owning the dst cache
 * @cache: the cache that might need to be reset
 * @key: the route key for the packet being transmitted
 *
 * Reset the peer dst cache if it was populated for a different route key.
 */
static void ovpn_dst_cache_check_key(struct ovpn_peer *peer,
				     struct dst_cache *cache,
				     const struct ovpn_route_key *key)
{
	struct ovpn_route_key old_key;
	unsigned int seq;

	/* snapshot the saved key before deciding whether the cache matches */
	do {
		seq = read_seqcount_begin(&peer->route_key_seq);
		old_key = peer->route_key;
	} while (read_seqcount_retry(&peer->route_key_seq, seq));

	/* nothing changed: the current cache can be reused */
	if (likely(ovpn_route_key_equal(&old_key, key)))
		return;

	/* recheck under lock because another path may have updated the key */
	spin_lock_bh(&peer->lock);
	if (!ovpn_route_key_equal(&peer->route_key, key)) {
		write_seqcount_begin(&peer->route_key_seq);
		peer->route_key = *key;
		dst_cache_reset(cache);
		write_seqcount_end(&peer->route_key_seq);
	}
	spin_unlock_bh(&peer->lock);
}

/**
 * ovpn_dst_cache_current - check whether a route lookup matches peer state
 * @peer: the peer owning the bind and dst cache
 * @bind: the RCU bind used for the route lookup
 * @key: the route key used for the route lookup
 *
 * Check that @bind is still the current peer bind and that @key still matches
 * the peer route key. The caller must hold @peer->lock. The TX path keeps
 * @bind inside an RCU read-side critical section, so pointer identity is enough
 * to detect whether the bind was replaced while the route lookup was running.
 *
 * Return: true if the lookup result still matches the current peer state and
 * may update the dst cache or replace the bind.
 */
static bool ovpn_dst_cache_current(const struct ovpn_peer *peer,
				   const struct ovpn_bind *bind,
				   const struct ovpn_route_key *key)
{
	const struct ovpn_bind *curr_bind;

	lockdep_assert_held(&peer->lock);

	curr_bind = rcu_dereference_protected(peer->bind,
					      lockdep_is_held(&peer->lock));

	return curr_bind == bind &&
	       ovpn_route_key_equal(key, &peer->route_key);
}

/**
 * ovpn_udp4_output - send IPv4 packet over udp socket
 * @peer: the destination peer
 * @bind: the binding related to the destination peer
 * @cache: dst cache
 * @sk: the socket to send the packet over
 * @skb: the packet to send
 * @key: the route key snapshot used for cache validation and flow lookup
 *
 * Return: 0 on success or a negative error code otherwise
 */
static int ovpn_udp4_output(struct ovpn_peer *peer, struct ovpn_bind *bind,
			    struct dst_cache *cache, struct sock *sk,
			    struct sk_buff *skb,
			    const struct ovpn_route_key *key)
{
	struct sockaddr_storage remote;
	struct in_addr local = {};
	bool reset_local = false;
	struct rtable *rt;
	struct flowi4 fl = {
		.saddr = bind->local.ipv4.s_addr,
		.daddr = bind->remote.in4.sin_addr.s_addr,
		.fl4_sport = key->sport,
		.fl4_dport = bind->remote.in4.sin_port,
		.flowi4_proto = sk->sk_protocol,
		.flowi4_mark = key->mark,
	};
	int ret;

	local_bh_disable();
	rt = dst_cache_get_ip4(cache, &fl.saddr);
	if (rt)
		goto transmit;

	if (fl.saddr && unlikely(!inet_confirm_addr(sock_net(sk), NULL, 0,
						    fl.saddr, RT_SCOPE_HOST))) {
		/* The learned local address is not usable anymore.
		 * Retry with source address autoselection.
		 */
		fl.saddr = 0;
		reset_local = true;
	}

	rt = ip_route_output_flow(sock_net(sk), &fl, sk);
	if (IS_ERR(rt) && PTR_ERR(rt) == -EINVAL) {
		fl.saddr = 0;
		reset_local = true;

		rt = ip_route_output_flow(sock_net(sk), &fl, sk);
	}

	if (IS_ERR(rt)) {
		ret = PTR_ERR(rt);
		net_dbg_ratelimited("%s: no route to host %pISpc: %d\n",
				    netdev_name(peer->ovpn->dev),
				    &bind->remote.in4,
				    ret);
		goto err;
	}

	/* avoid storing a stale cache or local address */
	spin_lock_bh(&peer->lock);
	if (likely(ovpn_dst_cache_current(peer, bind, key))) {
		if (!reset_local) {
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
			spin_unlock_bh(&peer->lock);
			goto transmit;
		}

		/* invalidate per-CPU dst entries that may still carry
		 * the stale source
		 */
		dst_cache_reset(cache);

		/* preserve the current remote */
		memcpy(&remote, &bind->remote, sizeof(struct sockaddr_in));
		/* The current packet already has a valid wildcard-source route.
		 * If replacing the bind fails, leave the stale local in place;
		 * a later cache miss will retry the repair.
		 */
		ovpn_peer_reset_sockaddr(peer, &remote, &local);
	}
	spin_unlock_bh(&peer->lock);

transmit:
	/* an already-built UDP GSO needs a checksum seed even if the socket's
	 * no-check option changed while encryption was in flight
	 */
	udp_tunnel_xmit_skb(rt, sk, skb, fl.saddr, fl.daddr, 0,
			    ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport,
			    fl.fl4_dport, false,
			    !skb_is_gso(skb) && sk->sk_no_check_tx, 0);
	ret = 0;
err:
	local_bh_enable();
	return ret;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * ovpn_udp6_output - send IPv6 packet over udp socket
 * @peer: the destination peer
 * @bind: the binding related to the destination peer
 * @cache: dst cache
 * @sk: the socket to send the packet over
 * @skb: the packet to send
 * @key: the route key snapshot used for cache validation and flow lookup
 *
 * Return: 0 on success or a negative error code otherwise
 */
static int ovpn_udp6_output(struct ovpn_peer *peer, struct ovpn_bind *bind,
			    struct dst_cache *cache, struct sock *sk,
			    struct sk_buff *skb,
			    const struct ovpn_route_key *key)
{
	struct in6_addr local = in6addr_any;
	struct sockaddr_storage remote;
	bool reset_local = false;
	struct dst_entry *dst;
	int ret;

	struct flowi6 fl = {
		.saddr = bind->local.ipv6,
		.daddr = bind->remote.in6.sin6_addr,
		.fl6_sport = key->sport,
		.fl6_dport = bind->remote.in6.sin6_port,
		.flowi6_proto = sk->sk_protocol,
		.flowi6_mark = key->mark,
		.flowi6_oif = bind->remote.in6.sin6_scope_id,
	};

	local_bh_disable();
	dst = dst_cache_get_ip6(cache, &fl.saddr);
	if (dst)
		goto transmit;

	if (!ipv6_addr_any(&fl.saddr) &&
	    unlikely(!ipv6_chk_addr(sock_net(sk), &fl.saddr, NULL, 0))) {
		/* The learned local address is not usable anymore.
		 * Retry with source address autoselection.
		 */
		fl.saddr = in6addr_any;
		reset_local = true;
	}

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl, NULL);
	if (IS_ERR(dst)) {
		ret = PTR_ERR(dst);
		net_dbg_ratelimited("%s: no route to host %pISpc: %d\n",
				    netdev_name(peer->ovpn->dev),
				    &bind->remote.in6, ret);
		goto err;
	}

	/* avoid storing a stale cache or local address */
	spin_lock_bh(&peer->lock);
	if (likely(ovpn_dst_cache_current(peer, bind, key))) {
		if (!reset_local) {
			dst_cache_set_ip6(cache, dst, &fl.saddr);
			spin_unlock_bh(&peer->lock);
			goto transmit;
		}

		/* invalidate per-CPU dst entries that may still carry
		 * the stale source
		 */
		dst_cache_reset(cache);

		/* preserve the current remote */
		memcpy(&remote, &bind->remote, sizeof(struct sockaddr_in6));
		/* The current packet already has a valid wildcard-source route.
		 * If replacing the bind fails, leave the stale local in place;
		 * a later cache miss will retry the repair.
		 */
		ovpn_peer_reset_sockaddr(peer, &remote, &local);
	}
	spin_unlock_bh(&peer->lock);

transmit:
	/* user IPv6 packets may be larger than the transport interface
	 * MTU (after encapsulation), however, since they are locally
	 * generated we should ensure they get fragmented.
	 * Setting the ignore_df flag to 1 will instruct ip6_fragment() to
	 * fragment packets if needed.
	 *
	 * NOTE: this is not needed for IPv4 because we pass df=0 to
	 * udp_tunnel_xmit_skb()
	 */
	skb->ignore_df = 1;
	/* keep checksum offload enabled for an in-flight UDP GSO batch even if
	 * the socket's no-check option has changed since batch creation
	 */
	udp_tunnel6_xmit_skb(dst, sk, skb, skb->dev, &fl.saddr, &fl.daddr, 0,
			     ip6_dst_hoplimit(dst), 0, fl.fl6_sport,
			     fl.fl6_dport,
			     !skb_is_gso(skb) && udp_get_no_check6_tx(sk), 0);
	ret = 0;
err:
	local_bh_enable();
	return ret;
}
#endif

/**
 * ovpn_udp_output - transmit skb using udp-tunnel
 * @peer: the destination peer
 * @cache: dst cache
 * @sk: the socket to send the packet over
 * @skb: the packet to send
 * @key: route key snapshot used for cache validation and flow lookup
 *
 * rcu_read_lock should be held on entry.
 * On return, the skb is consumed.
 *
 * Return: 0 on success or a negative error code otherwise
 */
static int ovpn_udp_output(struct ovpn_peer *peer, struct dst_cache *cache,
			   struct sock *sk, struct sk_buff *skb,
			   struct ovpn_route_key *key)
{
	struct ovpn_bind *bind;
	struct sock *owner;
	int ret;

	/* set sk to null if skb is already orphaned */
	if (!skb->destructor)
		skb->sk = NULL;

	/* A TCP segment encrypted on its own still carries the TCP destructor,
	 * while segments encrypted into a UDP GSO aggregate are charged with
	 * sock_wfree (see ovpn_gso_alloc). Charge it the same way, so that a
	 * receiver can tell they belong to the same flow: e.g. veth orphans
	 * anything but sock_wfree skbs before GRO, which compares skb->sk.
	 * The new charge is taken first, as it is what keeps the socket alive
	 * once the TCP one is released. Like for the segments consumed by an
	 * aggregate, the TCP charge is completed right away.
	 * Pure ACKs only differ by their destructor, which releases the same
	 * charge as sock_wfree does for TCP sockets.
	 */
	if (skb->destructor == tcp_wfree) {
		owner = skb->sk;
		refcount_add(skb->truesize, &owner->sk_wmem_alloc);
		skb_orphan(skb);
		skb->sk = owner;
		skb->destructor = sock_wfree;
	} else if (skb->destructor == __sock_wfree) {
		skb->destructor = sock_wfree;
	}

	rcu_read_lock();
	bind = rcu_dereference(peer->bind);
	if (unlikely(!bind)) {
		net_warn_ratelimited("%s: no bind for remote peer %u\n",
				     netdev_name(peer->ovpn->dev), peer->id);
		ret = -ENODEV;
		goto out;
	}

	switch (bind->remote.in4.sin_family) {
	case AF_INET:
		ret = ovpn_udp4_output(peer, bind, cache, sk, skb, key);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		ret = ovpn_udp6_output(peer, bind, cache, sk, skb, key);
		break;
#endif
	default:
		ret = -EAFNOSUPPORT;
		break;
	}

out:
	rcu_read_unlock();
	return ret;
}

/**
 * ovpn_udp_send_skb - prepare skb and send it over via UDP
 * @peer: the destination peer
 * @sk: peer socket
 * @skb: the packet to send
 */
void ovpn_udp_send_skb(struct ovpn_peer *peer, struct sock *sk,
		       struct sk_buff *skb)
{
	struct ovpn_route_key key = {
		.mark = READ_ONCE(sk->sk_mark),
		.sport = READ_ONCE(inet_sk(sk)->inet_sport),
	};
	int ret;

	skb->dev = peer->ovpn->dev;
	skb->mark = key.mark;
	if (skb_is_gso(skb)) {
		/* udp_tunnel_xmit_skb installs the outer UDP header after this
		 * function returns: point CHECKSUM_PARTIAL at that future
		 * header so both hw and sw UDP GSO can complete the checksum.
		 */
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb->csum_start = skb_headroom(skb) - sizeof(struct udphdr);
		skb->csum_offset = offsetof(struct udphdr, check);
	} else {
		/* no checksum performed at this layer */
		skb->ip_summed = CHECKSUM_NONE;
	}

	ovpn_dst_cache_check_key(peer, &peer->dst_cache, &key);

	/* crypto layer -> transport (UDP) */
	ret = ovpn_udp_output(peer, &peer->dst_cache, sk, skb, &key);
	if (unlikely(ret < 0))
		kfree_skb(skb);
}

static void ovpn_udp_encap_destroy(struct sock *sk)
{
	struct ovpn_socket *sock;
	struct ovpn_priv *ovpn;

	rcu_read_lock();
	sock = rcu_dereference_sk_user_data(sk);
	if (!sock || !sock->ovpn) {
		rcu_read_unlock();
		return;
	}
	ovpn = sock->ovpn;
	rcu_read_unlock();

	ovpn_peers_free(ovpn, sk, OVPN_DEL_PEER_REASON_TRANSPORT_DISCONNECT);
}

/**
 * ovpn_udp_socket_attach - set udp-tunnel CBs on socket and link it to ovpn
 * @ovpn_sock: socket to configure
 * @sock: the socket container to be passed to setup_udp_tunnel_sock()
 * @ovpn: the openvp instance to link
 *
 * After invoking this function, the sock will be controlled by ovpn so that
 * any incoming packet may be processed by ovpn first.
 *
 * Return: 0 on success or a negative error code otherwise
 */
int ovpn_udp_socket_attach(struct ovpn_socket *ovpn_sock, struct socket *sock,
			   struct ovpn_priv *ovpn)
{
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = ovpn_sock,
		.encap_type = UDP_ENCAP_OVPNINUDP,
		.encap_rcv = ovpn_udp_encap_recv,
		.encap_destroy = ovpn_udp_encap_destroy,
		.gro_receive = ovpn_udp_gro_receive_fraglist,
		.gro_complete = ovpn_udp_gro_complete,
	};
	struct ovpn_socket *old_data;
	int ret;

	/* make sure no pre-existing encapsulation handler exists */
	rcu_read_lock();
	old_data = rcu_dereference_sk_user_data(ovpn_sock->sk);
	if (!old_data) {
		/* socket is currently unused - we can take it */
		rcu_read_unlock();
		setup_udp_tunnel_sock(sock_net(ovpn_sock->sk), sock->sk, &cfg);
		return 0;
	}

	/* socket is in use. We need to understand if it's owned by this ovpn
	 * instance or by something else.
	 * In the former case, we can increase the refcounter and happily
	 * use it, because the same UDP socket is expected to be shared among
	 * different peers.
	 *
	 * Unlikely TCP, a single UDP socket can be used to talk to many remote
	 * hosts and therefore openvpn instantiates one only for all its peers
	 */
	if ((READ_ONCE(udp_sk(ovpn_sock->sk)->encap_type) == UDP_ENCAP_OVPNINUDP) &&
	    old_data->ovpn == ovpn) {
		netdev_dbg(ovpn->dev,
			   "provided socket already owned by this interface\n");
		ret = -EALREADY;
	} else {
		netdev_dbg(ovpn->dev,
			   "provided socket already taken by other user\n");
		ret = -EBUSY;
	}
	rcu_read_unlock();

	return ret;
}

/**
 * ovpn_udp_socket_detach - clean udp-tunnel status for this socket
 * @ovpn_sock: the socket to clean
 */
void ovpn_udp_socket_detach(struct ovpn_socket *ovpn_sock)
{
	struct sock *sk = ovpn_sock->sk;

	udp_tunnel_cleanup_gro(sk);

	/* Re-enable multicast loopback */
	inet_set_bit(MC_LOOP, sk);
	/* Disable CHECKSUM_UNNECESSARY to CHECKSUM_COMPLETE conversion */
	inet_dec_convert_csum(sk);

	WRITE_ONCE(udp_sk(sk)->encap_type, 0);
	WRITE_ONCE(udp_sk(sk)->encap_rcv, NULL);
	WRITE_ONCE(udp_sk(sk)->encap_destroy, NULL);
	WRITE_ONCE(udp_sk(sk)->gro_receive, NULL);
	WRITE_ONCE(udp_sk(sk)->gro_complete, NULL);

	rcu_assign_sk_user_data(sk, NULL);
}
