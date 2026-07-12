// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Android port contributor:
  Copyright (c) 2014-2015, Haofeng "Rick" Lei <ricklei@gmail.com>
  All rights reserved.
*/

/**
   \file

   Functions for sending packets
*/


#include "fastd.h"
#include "peer.h"
#include "turn.h"

#include <sys/uio.h>

#define FASTD_ETHERTYPE_ARP 0x0806
#define FASTD_ETHERTYPE_IPV6 0x86dd
#define FASTD_ARP_PACKET_MIN_LEN 28
#define FASTD_IPV6_HEADER_LEN 40
#define FASTD_IPV6_NEXT_HEADER_OFFSET 6
#define FASTD_IPV6_PAYLOAD_OFFSET FASTD_IPV6_HEADER_LEN
#define FASTD_IPPROTO_ICMPV6 58
#define FASTD_ICMPV6_ND_MIN_LEN 24
#define FASTD_ICMPV6_NEIGHBOR_SOLICITATION 135
#define FASTD_ICMPV6_NEIGHBOR_ADVERTISEMENT 136


/** Adds packet info to ancillary control messages */
static inline void add_pktinfo(struct msghdr *msg, const fastd_peer_address_t *local_addr) {
#ifdef __ANDROID__
	/* PKTINFO will mess with Android VpnService.protect(socket) */
	if (conf.android_integration)
		return;
#endif
	if (!local_addr)
		return;

	struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + msg->msg_controllen);

#ifdef USE_PKTINFO
	if (local_addr->sa.sa_family == AF_INET) {
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

		msg->msg_controllen += cmsg->cmsg_len;

		struct in_pktinfo pktinfo = {};
		pktinfo.ipi_spec_dst = local_addr->in.sin_addr;
		memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
		return;
	}
#endif

	if (local_addr->sa.sa_family == AF_INET6) {
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

		msg->msg_controllen += cmsg->cmsg_len;

		struct in6_pktinfo pktinfo = {};
		pktinfo.ipi6_addr = local_addr->in6.sin6_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
			pktinfo.ipi6_ifindex = local_addr->in6.sin6_scope_id;

		memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
	}
}

/** Sends a packet */
void fastd_send(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_buffer_t *buffer, size_t stat_size) {
	if (!sock)
		exit_bug("send: sock == NULL");

	if (!fastd_socket_is_open(sock)) {
		pr_debug2("not sending packet on a closed socket");
		fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		return;
	}

	bool current_exact_udp_punch = false;
	if (!stat_size && peer)
		current_exact_udp_punch = fastd_peer_is_current_punch_candidate(peer, remote_addr);

	bool current_socket_matches_punch =
		fastd_socket_is_hole_punch(sock) && fastd_peer_address_equal(&sock->peer_addr, remote_addr);

	if (fastd_tcp_send(peer, (fastd_socket_t *)sock, local_addr, remote_addr, buffer, stat_size))
		return;

	if (!stat_size && current_exact_udp_punch && !current_socket_matches_punch) {
		fastd_udp_punch_send(peer, sock, remote_addr, buffer);
		return;
	}

	if (!stat_size && !current_exact_udp_punch)
		fastd_udp_punch_send(peer, sock, remote_addr, buffer);

	if (fastd_turn_send(peer, sock, local_addr, remote_addr, buffer, stat_size))
		return;

	struct msghdr msg = {};
	uint8_t cbuf[1024] __attribute__((aligned(8))) = {};
	fastd_peer_address_t remote_addr6;

	switch (remote_addr->sa.sa_family) {
	case AF_INET:
		msg.msg_name = (void *)&remote_addr->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		msg.msg_name = (void *)&remote_addr->in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;

	default:
		exit_bug("unsupported address family");
	}

	if (sock->bound_addr->sa.sa_family == AF_INET6) {
		remote_addr6 = *remote_addr;
		fastd_peer_address_widen(&remote_addr6);

		msg.msg_name = (void *)&remote_addr6.in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	}

	struct iovec iov = { .iov_base = buffer->data, .iov_len = buffer->len };

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = 0;

	add_pktinfo(&msg, local_addr);

	if (!msg.msg_controllen)
		msg.msg_control = NULL;

	int ret = sendmsg(sock->fd.fd, &msg, 0);

	if (ret < 0 && msg.msg_controllen) {
		switch (errno) {
		case EINVAL:
		case ENETUNREACH:
			pr_debug2("sendmsg: %s (trying again without pktinfo)", strerror(errno));

			if (peer && !fastd_peer_handshake_scheduled(peer))
				fastd_peer_schedule_handshake_default(peer);

			msg.msg_control = NULL;
			msg.msg_controllen = 0;

			ret = sendmsg(sock->fd.fd, &msg, 0);
		}
	}

	if (ret < 0) {
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
			pr_debug2_errno("sendmsg");
			fastd_stats_add(peer, STAT_TX_DROPPED, stat_size);
			break;

		case ENETDOWN:
		case ENETUNREACH:
		case EHOSTUNREACH:
			pr_debug_errno("sendmsg");
			fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
			break;

		default:
			pr_warn_errno("sendmsg");
			fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		}
	} else {
		fastd_stats_add(peer, STAT_TX, stat_size);
	}
}

/** Encrypts and sends a payload packet to all peers */
static inline void send_all(fastd_buffer_t *buffer, fastd_peer_t *source) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, i);
		if (dest == source || !fastd_peer_is_established(dest))
			continue;

		/* optimization, primarily for TUN mode: don't duplicate the buffer for the last (or only) peer */
		if (i == VECTOR_LEN(ctx.peers) - 1) {
			conf.protocol->send(dest, buffer);
			return;
		}

		conf.protocol->send(dest, fastd_buffer_dup(buffer, conf.encrypt_headroom));
	}

	fastd_buffer_free(buffer);
}

/** Returns whether the configured mode carries Ethernet frames */
static inline bool ethernet_mode(void) {
	return conf.mode == MODE_TAP || conf.mode == MODE_MULTITAP;
}

/** Returns the Ethernet type carried by a TAP frame */
static uint16_t ethertype(const fastd_buffer_t *buffer) {
	uint16_t proto;
	memcpy(&proto, buffer->data + offsetof(fastd_eth_header_t, proto), sizeof(proto));
	return ntohs(proto);
}

/** Returns true if a frame is safe to relay for address-resolution bootstrap */
static bool is_address_resolution_frame(const fastd_buffer_t *buffer) {
	switch (ethertype(buffer)) {
	case FASTD_ETHERTYPE_ARP:
		return buffer->len >= sizeof(fastd_eth_header_t) + FASTD_ARP_PACKET_MIN_LEN;

	case FASTD_ETHERTYPE_IPV6: {
		if (buffer->len < sizeof(fastd_eth_header_t) + FASTD_IPV6_HEADER_LEN + FASTD_ICMPV6_ND_MIN_LEN)
			return false;

		const uint8_t *ipv6 = (const uint8_t *)buffer->data + sizeof(fastd_eth_header_t);
		if (ipv6[FASTD_IPV6_NEXT_HEADER_OFFSET] != FASTD_IPPROTO_ICMPV6)
			return false;

		uint8_t icmpv6_type = ipv6[FASTD_IPV6_PAYLOAD_OFFSET];
		return icmpv6_type == FASTD_ICMPV6_NEIGHBOR_SOLICITATION ||
		       icmpv6_type == FASTD_ICMPV6_NEIGHBOR_ADVERTISEMENT;
	}

	default:
		return false;
	}
}

/** Returns true if a peer may receive a controlled NAT traversal data relay packet */
static bool peer_may_receive_data_relay(const fastd_peer_t *source, const fastd_peer_t *dest) {
	return dest != source && fastd_peer_is_established(dest) && fastd_peer_get_nat_traversal(dest);
}

/** Relays address-resolution frames to established NAT traversal peers */
static bool relay_address_resolution(fastd_buffer_t *buffer, fastd_peer_t *source) {
	fastd_eth_addr_t dest_addr = fastd_buffer_dest_address(buffer);

	if (!(dest_addr.data[0] & 1))
		return false;

	if (!is_address_resolution_frame(buffer))
		return false;

	size_t n_peers = VECTOR_LEN(ctx.peers);
	fastd_peer_t *last = NULL;
	size_t limit = conf.punch_max_packets;
	if (!n_peers || !limit)
		return false;

	size_t start = ctx.punch_data_relay_address_resolution_cursor % n_peers;
	size_t last_index = start;
	size_t selected = 0;
	size_t i;
	for (i = 0; i < n_peers && selected < limit; i++) {
		size_t index = (start + i) % n_peers;
		fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, index);
		if (!peer_may_receive_data_relay(source, dest))
			continue;

		last = dest;
		last_index = index;
		selected++;
	}

	if (!last)
		return false;

	ctx.punch_data_relay_address_resolution_cursor = (last_index + 1) % n_peers;
	ctx.punch_data_relay_attempts++;
	ctx.punch_data_relay_address_resolution_attempts++;
	selected = 0;
	for (i = 0; i < n_peers; i++) {
		size_t index = (start + i) % n_peers;
		fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, index);
		if (!peer_may_receive_data_relay(source, dest))
			continue;

		selected++;
		fastd_punch_note_peer_pair_demand(source, dest);
		ctx.punch_data_relay_packets++;
		ctx.punch_data_relay_bytes += buffer->len;
		ctx.punch_data_relay_address_resolution_packets++;
		ctx.punch_data_relay_address_resolution_bytes += buffer->len;

		if (dest == last) {
			conf.protocol->send(dest, buffer);
			return true;
		}

		conf.protocol->send(dest, fastd_buffer_dup(buffer, conf.encrypt_headroom));
		if (selected >= limit)
			exit_bug("address-resolution relay exceeded selected destination");
	}

	exit_bug("address-resolution relay lost selected destination");
}

/** Handles sending of a payload packet to a single peer in TAP mode */
static inline bool send_data_tap_single(fastd_buffer_t *buffer, fastd_peer_t *source) {
	if (conf.mode != MODE_TAP)
		return false;

	if (buffer->len < sizeof(fastd_eth_header_t)) {
		pr_debug("truncated ethernet packet");
		fastd_buffer_free(buffer);
		return true;
	}

	if (!source) {
		fastd_eth_addr_t src_addr = fastd_buffer_source_address(buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(NULL, src_addr);
	}

	fastd_eth_addr_t dest_addr = fastd_buffer_dest_address(buffer);
	if (!fastd_eth_addr_is_unicast(dest_addr))
		return false;

	fastd_peer_t *dest;
	bool found = fastd_peer_find_by_eth_addr(dest_addr, &dest);

	if (!found)
		return false;

	if (!dest || dest == source) {
		fastd_buffer_free(buffer);
		return true;
	}

	if (!fastd_peer_is_established(dest) && dest->direct_relay && fastd_peer_is_established(dest->direct_relay))
		dest = dest->direct_relay;
	else if (source && dest)
		fastd_punch_note_peer_pair_demand(source, dest);

	conf.protocol->send(dest, buffer);
	return true;
}

/** Handles controlled NAT traversal data relay of a learned unicast TAP packet */
bool fastd_send_data_relay(fastd_buffer_t *buffer, fastd_peer_t *source) {
	if (!fastd_peer_get_punch_data_relay() || !ethernet_mode() || !source ||
	    !fastd_peer_is_established(source) || !fastd_peer_get_nat_traversal(source) ||
	    buffer->len < sizeof(fastd_eth_header_t))
		return false;

	fastd_eth_addr_t dest_addr = fastd_buffer_dest_address(buffer);
	if (!fastd_eth_addr_is_unicast(dest_addr))
		return relay_address_resolution(buffer, source);

	fastd_peer_t *dest;
	if (!fastd_peer_find_by_eth_addr(dest_addr, &dest) || !dest || dest == source ||
	    !fastd_peer_get_nat_traversal(dest))
		return false;

	ctx.punch_data_relay_attempts++;
	fastd_punch_note_peer_pair_demand(source, dest);
	if (!fastd_peer_is_established(dest)) {
		ctx.punch_data_relay_unavailable++;
		fastd_buffer_free(buffer);
		return true;
	}

	ctx.punch_data_relay_packets++;
	ctx.punch_data_relay_bytes += buffer->len;
	conf.protocol->send(dest, buffer);
	return true;
}

/** Sends a buffer of payload data to other peers */
void fastd_send_data(fastd_buffer_t *buffer, fastd_peer_t *source, fastd_peer_t *dest) {
	if (dest) {
		conf.protocol->send(dest, buffer);
		return;
	}

	if (send_data_tap_single(buffer, source))
		return;

	/* TUN mode or multicast packet */
	send_all(buffer, source);
}
