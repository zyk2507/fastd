// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Automatic port mapping helpers
*/


#include "port_mapping.h"
#include "async.h"
#include "peer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <unistd.h>


#ifdef WITH_STATUS_SOCKET
#include <json-c/json.h>
#endif

#ifdef WITH_NATPMP
#include <natpmp.h>
#endif

#ifdef WITH_UPNP_IGD
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnpdev.h>
#include <miniupnpc/upnperrors.h>
#endif

#ifdef WITH_PCP
#include <net/route.h>
#endif

#ifdef WITH_UPNP_IGD
/* Some miniupnpc development packages expose UPNP_GetValidIGD() but not the
 * named return constants. Keep the local fallback in sync with miniupnpc.h. */
#ifndef UPNP_NO_IGD
#define UPNP_NO_IGD 0
#endif
#ifndef UPNP_CONNECTED_IGD
#define UPNP_CONNECTED_IGD 1
#endif
#ifndef UPNP_PRIVATEIP_IGD
#define UPNP_PRIVATEIP_IGD 2
#endif
#ifndef UPNP_DISCONNECTED_IGD
#define UPNP_DISCONNECTED_IGD 3
#endif
#endif


#define FASTD_NATPMP_RETRY_INTERVAL 300000
#define FASTD_UPNP_DISCOVER_DELAY 2000
#define FASTD_UPNP_RETRY_INTERVAL 300000
#define FASTD_PCP_RETRY_INTERVAL 300000
#define FASTD_PCP_REQUEST_TIMEOUT 1000
#define FASTD_PCP_MAX_RETRIES 4
#define FASTD_PCP_PORT 5351
#define FASTD_PCP_VERSION 2
#define FASTD_PCP_OPCODE_MAP 1
#define FASTD_PCP_RESPONSE_OPCODE_MAP 0x81
#define FASTD_PCP_RESULT_SUCCESS 0
#define FASTD_PCP_PROTOCOL_UDP 17
#define FASTD_PCP_MAP_PACKET_LEN 60


/** A single UDP port that should be mapped */
typedef struct fastd_port_mapping_entry {
	uint16_t port;     /**< The local UDP port in host byte order */
	bool use_natpmp;   /**< Specifies if this port should be mapped using NAT-PMP */
	bool use_upnp_igd; /**< Specifies if this port should be mapped using UPnP IGD */
	bool use_pcp;      /**< Specifies if this port should be mapped using PCP */
	bool fixed_natpmp; /**< Specifies if this port is used by a fixed socket with NAT-PMP enabled */
	bool fixed_upnp_igd; /**< Specifies if this port is used by a fixed socket with UPnP IGD enabled */
	bool fixed_pcp; /**< Specifies if this port is used by a fixed socket with PCP enabled */
	uint16_t dynamic_natpmp_refs; /**< Number of dynamic listeners using NAT-PMP for this port */
	uint16_t dynamic_upnp_igd_refs; /**< Number of dynamic listeners using UPnP IGD for this port */
	uint16_t dynamic_pcp_refs; /**< Number of dynamic listeners using PCP for this port */

#ifdef WITH_NATPMP
	uint16_t natpmp_public_port; /**< The NAT-PMP mapped public UDP port in host byte order */
	uint32_t natpmp_lifetime;    /**< The current NAT-PMP mapping lifetime in seconds */
	bool natpmp_mapped;          /**< Specifies if the last NAT-PMP mapping request was successful */
#endif

#ifdef WITH_UPNP_IGD
	uint16_t upnp_public_port; /**< The UPnP IGD mapped public UDP port in host byte order */
	bool upnp_mapped;          /**< Specifies if the UPnP IGD mapping request was successful */
#endif

#ifdef WITH_PCP
	uint8_t pcp_nonce[12]; /**< The stable PCP MAP nonce for this mapping */
	uint16_t pcp_public_port; /**< The PCP mapped public UDP port in host byte order */
	uint32_t pcp_lifetime; /**< The current PCP mapping lifetime in seconds */
	fastd_peer_address_t pcp_external_addr; /**< The PCP mapped external IPv4 address */
	bool pcp_nonce_valid; /**< Specifies if pcp_nonce has been initialized */
	bool pcp_mapped;      /**< Specifies if the last PCP MAP request was successful */
#endif
} fastd_port_mapping_entry_t;

/** Global automatic port mapping state */
struct fastd_port_mapping {
	bool natpmp_requested;   /**< Specifies if NAT-PMP is requested by peer configuration */
	bool upnp_igd_requested; /**< Specifies if UPnP IGD is requested by peer configuration */
	bool pcp_requested;      /**< Specifies if PCP is requested by peer configuration */
	bool use_natpmp;         /**< Specifies if NAT-PMP should be used for at least one port */
	bool use_upnp_igd;       /**< Specifies if UPnP IGD should be used for at least one port */
	bool use_pcp;            /**< Specifies if PCP should be used for at least one port */

#ifdef WITH_NATPMP
	natpmp_t natpmp;      /**< libnatpmp context */
	fastd_poll_fd_t fd;   /**< The NAT-PMP control socket */
	fastd_task_t natpmp_task; /**< NAT-PMP retry or renewal task */
	bool initialized;     /**< Specifies if natpmp has been initialized */
	bool request_pending; /**< Specifies if a NAT-PMP request is in flight */
	size_t current;       /**< The mapping currently being requested */
#endif

#ifdef WITH_UPNP_IGD
	struct UPNPUrls upnp_urls;               /**< UPnP IGD control URLs */
	struct IGDdatas upnp_data;               /**< UPnP IGD service metadata */
	fastd_peer_address_t upnp_external_addr; /**< External address reported by the UPnP IGD */
	char upnp_lanaddr[64];                   /**< LAN address selected by UPNP_GetValidIGD() */
	pthread_mutex_t upnp_mutex;              /**< Synchronizes the background discovery worker lifecycle */
	uint64_t upnp_generation;                /**< Rejects results produced for a replaced mapping state */
	fastd_task_t upnp_task;                   /**< Schedules a retry after a failed discovery */
	bool upnp_initialized;                   /**< Specifies if upnp_urls has been initialized */
	bool upnp_worker_running;                /**< Specifies if a blocking discovery worker is active */
	bool upnp_stopping;                      /**< Prevents a stopped mapping state from accepting results */
#endif

#ifdef WITH_PCP
	fastd_poll_fd_t pcp_fd;              /**< The PCP control socket */
	fastd_task_t pcp_task;               /**< PCP retry or renewal task */
	fastd_peer_address_t pcp_server_addr; /**< The PCP server address */
	bool pcp_initialized;                /**< Specifies if the PCP control socket has been initialized */
	bool pcp_request_pending;            /**< Specifies if a PCP MAP request is in flight */
	size_t pcp_current;                  /**< The mapping currently being requested */
	uint8_t pcp_retries;                 /**< Retransmissions of the current PCP request */
#endif

#ifdef WITH_TESTS
	bool test_no_backend_activation; /**< Suppresses real gateway calls in unit tests */
#endif

	VECTOR(fastd_port_mapping_entry_t) mappings; /**< Configured UDP port mappings */
};

static void compact_unused_mappings(fastd_port_mapping_t *mapping);
static void activate_mapping_backends(fastd_port_mapping_t *mapping);


/** Returns a port mapping entry or NULL if the port is not in the mapping list */
static fastd_port_mapping_entry_t *find_mapping(const fastd_port_mapping_t *mapping, uint16_t port) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (entry->port == port)
			return entry;
	}

	return NULL;
}

/** Refreshes the effective backend flags of a mapping entry */
static void update_entry_backends(fastd_port_mapping_entry_t *entry) {
	entry->use_natpmp = entry->fixed_natpmp || entry->dynamic_natpmp_refs;
	entry->use_upnp_igd = entry->fixed_upnp_igd || entry->dynamic_upnp_igd_refs;
	entry->use_pcp = entry->fixed_pcp || entry->dynamic_pcp_refs;
}

/** Returns true if a mapping entry is still referenced by any socket */
static bool entry_has_users(const fastd_port_mapping_entry_t *entry) {
	return entry->fixed_natpmp || entry->fixed_upnp_igd || entry->dynamic_natpmp_refs ||
	       entry->dynamic_upnp_igd_refs || entry->fixed_pcp || entry->dynamic_pcp_refs;
}

/** Recomputes global backend use flags after entries changed */
static void recompute_mapping_backends(fastd_port_mapping_t *mapping) {
	mapping->use_natpmp = false;
	mapping->use_upnp_igd = false;
	mapping->use_pcp = false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		const fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		mapping->use_natpmp |= entry->use_natpmp;
		mapping->use_upnp_igd |= entry->use_upnp_igd;
		mapping->use_pcp |= entry->use_pcp;
	}
}

/** Returns true if a socket can be mapped through IPv4 gateway protocols */
static bool socket_is_mappable(const fastd_socket_t *sock) {
	if (!sock || !sock->bound_addr)
		return false;

	if (!sock->addr)
		return sock->type == SOCKET_TYPE_UDP && (sock->punch_public_listener ||
							 sock->punch_listener_mapping_registered) &&
		       sock->bound_addr->sa.sa_family == AF_INET;

	if (sock->bound_addr->sa.sa_family == AF_INET6 && sock->addr->addr.sa.sa_family != AF_UNSPEC)
		return false;

	return sock->bound_addr->sa.sa_family == AF_INET || sock->bound_addr->sa.sa_family == AF_INET6;
}

/** Returns true if a peer might use a socket with the given address family */
static bool peer_uses_socket_family(const fastd_peer_t *peer, sa_family_t family) {
	if (fastd_peer_is_floating(peer))
		return true;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		const fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		if (remote->hostname) {
			if (remote->address.sa.sa_family == AF_UNSPEC || remote->address.sa.sa_family == family)
				return true;
		} else if (remote->address.sa.sa_family == family) {
			return true;
		}
	}

	return false;
}

/** Returns true if a socket can receive packets for a peer */
static bool peer_uses_socket(const fastd_peer_t *peer, const fastd_socket_t *sock) {
	if (fastd_peer_is_floating(peer))
		return true;

	if (sock->addr->addr.sa.sa_family == AF_UNSPEC)
		return peer_uses_socket_family(peer, AF_INET);

	return peer_uses_socket_family(peer, sock->addr->addr.sa.sa_family);
}

/** Collects the port mapping backends enabled for peers that might use this socket */
static void socket_enabled_backends(
	const fastd_socket_t *sock, bool *use_natpmp, bool *use_upnp_igd, bool *use_pcp) {
	if (fastd_allow_verify()) {
		fastd_port_mapping_mode_t mode = fastd_peer_get_port_mapping_mode(NULL);
		*use_natpmp |= fastd_port_mapping_uses_natpmp(mode);
		*use_upnp_igd |= fastd_port_mapping_uses_upnp_igd(mode);
		*use_pcp |= fastd_port_mapping_uses_pcp(mode);
	}

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		const fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_is_enabled(peer))
			continue;

		fastd_port_mapping_mode_t mode = fastd_peer_get_port_mapping_mode(peer);
		if (mode == PORT_MAPPING_OFF)
			continue;

		if (peer_uses_socket(peer, sock)) {
			*use_natpmp |= fastd_port_mapping_uses_natpmp(mode);
			*use_upnp_igd |= fastd_port_mapping_uses_upnp_igd(mode);
			*use_pcp |= fastd_port_mapping_uses_pcp(mode);
		}
	}
}

/** Adds an IPv4-compatible socket's bound UDP port to the mapping list */
static void
add_socket_mapping(
	fastd_port_mapping_t *mapping, const fastd_socket_t *sock, bool use_natpmp, bool use_upnp_igd,
	bool use_pcp) {
	if (!socket_is_mappable(sock))
		return;

	uint16_t port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
	if (!port)
		return;

	fastd_port_mapping_entry_t *entry = find_mapping(mapping, port);
	if (!entry) {
		VECTOR_ADD(mapping->mappings, ((fastd_port_mapping_entry_t){ .port = port }));
		entry = &VECTOR_INDEX(mapping->mappings, VECTOR_LEN(mapping->mappings) - 1);
	}

	entry->fixed_natpmp |= use_natpmp;
	entry->fixed_upnp_igd |= use_upnp_igd;
	entry->fixed_pcp |= use_pcp;
	update_entry_backends(entry);
	recompute_mapping_backends(mapping);
}

/** Adds a runtime UDP punch listener's bound port to the mapping list */
static bool add_dynamic_socket_mapping(
	fastd_port_mapping_t *mapping, const fastd_socket_t *sock, bool use_natpmp, bool use_upnp_igd,
	bool use_pcp) {
	if (!socket_is_mappable(sock) || (!use_natpmp && !use_upnp_igd && !use_pcp))
		return false;

	uint16_t port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
	if (!port)
		return false;

	fastd_port_mapping_entry_t *entry = find_mapping(mapping, port);
	if (!entry) {
		VECTOR_ADD(mapping->mappings, ((fastd_port_mapping_entry_t){ .port = port }));
		entry = &VECTOR_INDEX(mapping->mappings, VECTOR_LEN(mapping->mappings) - 1);
	}

	if (use_natpmp && entry->dynamic_natpmp_refs != UINT16_MAX)
		entry->dynamic_natpmp_refs++;
	if (use_upnp_igd && entry->dynamic_upnp_igd_refs != UINT16_MAX)
		entry->dynamic_upnp_igd_refs++;
	if (use_pcp && entry->dynamic_pcp_refs != UINT16_MAX)
		entry->dynamic_pcp_refs++;

	update_entry_backends(entry);
	recompute_mapping_backends(mapping);
	return entry->use_natpmp || entry->use_upnp_igd || entry->use_pcp;
}

/** Collects mappable UDP ports from fixed sockets enabled by peer configuration */
static void collect_socket_mappings(fastd_port_mapping_t *mapping) {
	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		const fastd_socket_t *sock = &ctx.socks[i];

		if (!socket_is_mappable(sock))
			continue;

		bool use_natpmp = false, use_upnp_igd = false, use_pcp = false;
		socket_enabled_backends(sock, &use_natpmp, &use_upnp_igd, &use_pcp);
		if (!use_natpmp && !use_upnp_igd && !use_pcp)
			continue;

		add_socket_mapping(mapping, sock, use_natpmp, use_upnp_igd, use_pcp);
	}
}

/** Determines which port mapping backends are requested by peer configuration */
static void collect_enabled_backends(fastd_port_mapping_t *mapping) {
	fastd_port_mapping_mode_t default_mode = fastd_peer_get_port_mapping_mode(NULL);
	if (fastd_allow_verify() && default_mode != PORT_MAPPING_OFF) {
		mapping->natpmp_requested |= fastd_port_mapping_uses_natpmp(default_mode);
		mapping->upnp_igd_requested |= fastd_port_mapping_uses_upnp_igd(default_mode);
		mapping->pcp_requested |= fastd_port_mapping_uses_pcp(default_mode);
	}

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		const fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_is_enabled(peer))
			continue;

		fastd_port_mapping_mode_t mode = fastd_peer_get_port_mapping_mode(peer);
		mapping->natpmp_requested |= fastd_port_mapping_uses_natpmp(mode);
		mapping->upnp_igd_requested |= fastd_port_mapping_uses_upnp_igd(mode);
		mapping->pcp_requested |= fastd_port_mapping_uses_pcp(mode);
	}
}

/** Sets a peer address port from host byte order */
static void set_mapped_address_port(fastd_peer_address_t *addr, uint16_t port) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->in.sin_port = htons(port);
		return;

	case AF_INET6:
		addr->in6.sin6_port = htons(port);
		return;
	}
}


#ifdef WITH_NATPMP

/** Schedules the NAT-PMP task, replacing an existing timeout if necessary */
static void schedule_natpmp_task(fastd_port_mapping_t *mapping, fastd_timeout_t timeout) {
	if (fastd_task_scheduled(&mapping->natpmp_task))
		fastd_task_unschedule(&mapping->natpmp_task);

	fastd_task_schedule(&mapping->natpmp_task, TASK_TYPE_NATPMP, timeout);
}

/** Returns a human-readable string for a libnatpmp return code */
static const char *natpmp_error(int ret) {
	switch (ret) {
	case NATPMP_ERR_INVALIDARGS:
		return "invalid arguments";
	case NATPMP_ERR_SOCKETERROR:
		return "socket error";
	case NATPMP_ERR_CANNOTGETGATEWAY:
		return "can't get default gateway";
	case NATPMP_ERR_CLOSEERR:
		return "close error";
	case NATPMP_ERR_RECVFROM:
		return "recvfrom failed";
	case NATPMP_ERR_NOPENDINGREQ:
		return "no pending request";
	case NATPMP_ERR_NOGATEWAYSUPPORT:
		return "gateway does not support NAT-PMP";
	case NATPMP_ERR_CONNECTERR:
		return "connect failed";
	case NATPMP_ERR_WRONGPACKETSOURCE:
		return "packet not received from gateway";
	case NATPMP_ERR_SENDERR:
		return "send failed";
	case NATPMP_ERR_FCNTLERROR:
		return "fcntl failed";
	case NATPMP_ERR_GETTIMEOFDAYERR:
		return "gettimeofday failed";
	case NATPMP_ERR_UNSUPPORTEDVERSION:
		return "unsupported NAT-PMP version";
	case NATPMP_ERR_UNSUPPORTEDOPCODE:
		return "unsupported NAT-PMP opcode";
	case NATPMP_ERR_UNDEFINEDERROR:
		return "gateway returned an undefined error";
	case NATPMP_ERR_NOTAUTHORIZED:
		return "gateway refused authorization";
	case NATPMP_ERR_NETWORKFAILURE:
		return "gateway reported a network failure";
	case NATPMP_ERR_OUTOFRESOURCES:
		return "gateway is out of resources";
	default:
		return "unknown error";
	}
}

/** Schedules the next pending NAT-PMP request timeout */
static void schedule_request_timeout(fastd_port_mapping_t *mapping) {
	struct timeval timeout;
	int ret = getnatpmprequesttimeout(&mapping->natpmp, &timeout);
	if (ret < 0) {
		pr_debug("unable to get NAT-PMP request timeout: %s", natpmp_error(ret));
		schedule_natpmp_task(mapping, ctx.now + FASTD_NATPMP_RETRY_INTERVAL);
		return;
	}

	int64_t delay = timeout.tv_sec * 1000 + (timeout.tv_usec + 999) / 1000;
	schedule_natpmp_task(mapping, ctx.now + delay);
}

/** Schedules a retry after a failed NAT-PMP mapping attempt */
static void schedule_retry(fastd_port_mapping_t *mapping) {
	mapping->request_pending = false;
	mapping->current = 0;
	compact_unused_mappings(mapping);
	schedule_natpmp_task(mapping, ctx.now + FASTD_NATPMP_RETRY_INTERVAL);
}

/** Returns the delay after which the active NAT-PMP mappings should be renewed */
static int64_t renewal_delay(const fastd_port_mapping_t *mapping) {
	uint32_t lifetime = FASTD_NATPMP_LIFETIME;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		const fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (entry->natpmp_mapped && entry->natpmp_lifetime && entry->natpmp_lifetime < lifetime)
			lifetime = entry->natpmp_lifetime;
	}

	int64_t delay = (int64_t)lifetime * 1000 / 2;
	return delay > 1000 ? delay : 1000;
}

/** Starts a NAT-PMP mapping request for a given mapping index */
static void request_mapping(fastd_port_mapping_t *mapping, size_t i) {
	compact_unused_mappings(mapping);

	while (i < VECTOR_LEN(mapping->mappings) && !VECTOR_INDEX(mapping->mappings, i).use_natpmp)
		i++;

	if (i >= VECTOR_LEN(mapping->mappings)) {
		mapping->request_pending = false;
		mapping->current = 0;
		schedule_natpmp_task(mapping, ctx.now + renewal_delay(mapping));
		return;
	}

	mapping->current = i;
	fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
	uint16_t public_port = entry->natpmp_public_port ? entry->natpmp_public_port : entry->port;

	int ret = sendnewportmappingrequest(
		&mapping->natpmp, NATPMP_PROTOCOL_UDP, entry->port, public_port, FASTD_NATPMP_LIFETIME);
	if (ret < 0) {
		pr_warn("unable to send NAT-PMP request for UDP port %u: %s", entry->port, natpmp_error(ret));
		schedule_retry(mapping);
		return;
	}

	mapping->request_pending = true;
	schedule_request_timeout(mapping);
}

/** Sends a best-effort NAT-PMP deletion request for one active mapping */
static void release_natpmp_mapping_entry(fastd_port_mapping_entry_t *entry) {
	if (!entry->natpmp_mapped)
		return;

	natpmp_t natpmp;
	if (initnatpmp(&natpmp, 0, 0) >= 0) {
		sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, entry->port, entry->natpmp_public_port, 0);
		closenatpmp(&natpmp);
	}

	entry->natpmp_mapped = false;
	entry->natpmp_public_port = 0;
	entry->natpmp_lifetime = 0;
}

/** Handles the result of a NAT-PMP request */
static void handle_mapping_response(fastd_port_mapping_t *mapping, const natpmpresp_t *response) {
	fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, mapping->current);

	if (response->type != NATPMP_RESPTYPE_UDPPORTMAPPING) {
		pr_warn("received unexpected NAT-PMP response type %u", response->type);
		schedule_retry(mapping);
		return;
	}

	if (response->pnu.newportmapping.privateport != entry->port) {
		pr_warn("received NAT-PMP response for unexpected UDP port %u",
			response->pnu.newportmapping.privateport);
		schedule_retry(mapping);
		return;
	}

	uint16_t public_port = response->pnu.newportmapping.mappedpublicport;
	uint32_t lifetime = response->pnu.newportmapping.lifetime;

	if (!public_port) {
		pr_warn("NAT-PMP returned public UDP port 0 for local UDP port %u", entry->port);
		schedule_retry(mapping);
		return;
	}

	if (!lifetime) {
		pr_warn("NAT-PMP returned a zero lifetime for UDP port %u", entry->port);
		schedule_retry(mapping);
		return;
	}

	entry->natpmp_mapped = true;
	entry->natpmp_public_port = public_port;
	entry->natpmp_lifetime = lifetime;

	if (!entry->use_natpmp) {
		release_natpmp_mapping_entry(entry);
		request_mapping(mapping, mapping->current + 1);
		return;
	}

	if (entry->natpmp_public_port == entry->port) {
		pr_verbose("mapped UDP port %u using NAT-PMP", entry->port);
	} else {
		pr_warn("NAT-PMP mapped local UDP port %u to different public port %u", entry->port,
			entry->natpmp_public_port);
	}

	request_mapping(mapping, mapping->current + 1);
}

/** Handles a pending NAT-PMP request */
static void handle_pending_request(fastd_port_mapping_t *mapping) {
	if (!mapping->initialized)
		return;

	if (!mapping->request_pending) {
		request_mapping(mapping, 0);
		return;
	}

	natpmpresp_t response;
	int ret = readnatpmpresponseorretry(&mapping->natpmp, &response);
	if (ret == NATPMP_TRYAGAIN) {
		schedule_request_timeout(mapping);
		return;
	}

	if (ret < 0) {
		pr_warn("NAT-PMP request for UDP port %u failed: %s",
			VECTOR_INDEX(mapping->mappings, mapping->current).port, natpmp_error(ret));
		schedule_retry(mapping);
		return;
	}

	mapping->request_pending = false;
	handle_mapping_response(mapping, &response);
	compact_unused_mappings(mapping);
}

/** Initializes automatic NAT-PMP port mapping */
static void init_natpmp(fastd_port_mapping_t *mapping) {
	int ret = initnatpmp(&mapping->natpmp, 0, 0);
	if (ret < 0) {
		pr_warn("unable to initialize NAT-PMP: %s", natpmp_error(ret));
		return;
	}

	mapping->initialized = true;
	mapping->fd = FASTD_POLL_FD(POLL_TYPE_NATPMP, mapping->natpmp.s);
	fastd_poll_fd_register(&mapping->fd);

	request_mapping(mapping, 0);
}

/** Sends best-effort deletion requests for active NAT-PMP mappings */
static void release_natpmp_mappings(fastd_port_mapping_t *mapping) {
	if (!mapping->initialized)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (!entry->natpmp_mapped)
			continue;

		release_natpmp_mapping_entry(entry);
	}
}

/** Frees NAT-PMP state */
static void cleanup_natpmp(fastd_port_mapping_t *mapping) {
	if (fastd_task_scheduled(&mapping->natpmp_task))
		fastd_task_unschedule(&mapping->natpmp_task);

	release_natpmp_mappings(mapping);

	if (mapping->initialized) {
		fastd_poll_fd_close(&mapping->fd);
		mapping->initialized = false;
	}
}

#endif


#ifdef WITH_UPNP_IGD

static uint64_t next_upnp_generation;

/** Returns a human-readable string for a miniupnpc return code */
static const char *upnp_error(int ret) {
	const char *error = strupnperror(ret);
	return error ? error : "unknown error";
}

/** Formats a UDP port for miniupnpc calls */
static void format_port(char buf[static 6], uint16_t port) {
	snprintf(buf, 6, "%u", port);
}

/** Adds one UPnP IGD mapping */
static void add_upnp_mapping(fastd_port_mapping_t *mapping, fastd_port_mapping_entry_t *entry) {
	if (!mapping->upnp_initialized || !entry->use_upnp_igd || entry->upnp_mapped)
		return;

	char port[6];
	format_port(port, entry->port);

	int ret = UPNP_AddPortMapping(
		mapping->upnp_urls.controlURL, mapping->upnp_data.first.servicetype, port, port, mapping->upnp_lanaddr,
		"fastd", "UDP", NULL, "0");
	if (ret != UPNPCOMMAND_SUCCESS) {
		pr_warn("unable to add UPnP IGD mapping for UDP port %u: %s", entry->port, upnp_error(ret));
		return;
	}

	entry->upnp_mapped = true;
	entry->upnp_public_port = entry->port;
	pr_verbose("mapped UDP port %u using UPnP IGD", entry->port);
}

/** Sends a best-effort UPnP IGD deletion request for one active mapping */
static void release_upnp_mapping_entry(fastd_port_mapping_t *mapping, fastd_port_mapping_entry_t *entry) {
	if (!mapping->upnp_initialized || !entry->upnp_mapped)
		return;

	char port[6];
	format_port(port, entry->upnp_public_port);

	int ret = UPNP_DeletePortMapping(
		mapping->upnp_urls.controlURL, mapping->upnp_data.first.servicetype, port, "UDP", NULL);
	if (ret != UPNPCOMMAND_SUCCESS)
		pr_debug(
			"unable to delete UPnP IGD mapping for UDP port %u: %s", entry->upnp_public_port,
			upnp_error(ret));

	entry->upnp_mapped = false;
	entry->upnp_public_port = 0;
}

/** Stores the external address reported by the UPnP IGD, if it is parseable */
static void set_upnp_external_address(fastd_port_mapping_t *mapping, const char *wanaddr) {
	fastd_peer_address_t addr = {};

	if (inet_pton(AF_INET, wanaddr, &addr.in.sin_addr) == 1) {
		addr.in.sin_family = AF_INET;
	} else if (inet_pton(AF_INET6, wanaddr, &addr.in6.sin6_addr) == 1) {
		addr.in6.sin6_family = AF_INET6;
	} else {
		pr_debug("unable to parse UPnP IGD external address `%s'", wanaddr);
		return;
	}

	fastd_peer_address_simplify(&addr);
	mapping->upnp_external_addr = addr;
}

/** Adds UPnP IGD mappings for all configured ports */
static void add_upnp_mappings(fastd_port_mapping_t *mapping, const char *lanaddr) {
	strncpy(mapping->upnp_lanaddr, lanaddr, sizeof(mapping->upnp_lanaddr) - 1);
	mapping->upnp_lanaddr[sizeof(mapping->upnp_lanaddr) - 1] = 0;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		add_upnp_mapping(mapping, entry);
	}
}

/** Copies one miniupnpc result string into a fixed async message field */
static void copy_upnp_result_field(char *dest, size_t len, const char *src) {
	if (!len)
		return;

	snprintf(dest, len, "%s", src ? src : "");
}

typedef struct upnp_discovery_work {
	fastd_port_mapping_t *mapping;
	uint64_t generation;
} upnp_discovery_work_t;

/** Schedules another UPnP IGD discovery when the current one could not produce a usable result */
static void schedule_upnp_retry(fastd_port_mapping_t *mapping) {
	if (mapping->upnp_stopping || mapping->upnp_initialized || !mapping->use_upnp_igd)
		return;

	if (fastd_task_scheduled(&mapping->upnp_task))
		fastd_task_unschedule(&mapping->upnp_task);
	fastd_task_schedule(&mapping->upnp_task, TASK_TYPE_UPNP_IGD, ctx.now + FASTD_UPNP_RETRY_INTERVAL);
}

/** Marks a background UPnP discovery worker as finished */
static void upnp_discovery_worker_done(fastd_port_mapping_t *mapping) {
	pthread_mutex_lock(&mapping->upnp_mutex);
	mapping->upnp_worker_running = false;
	pthread_mutex_unlock(&mapping->upnp_mutex);
}

/** Performs the blocking miniupnpc discovery without blocking the event loop */
static void *upnp_discovery_worker(void *arg) {
	upnp_discovery_work_t *work = arg;
	fastd_async_upnp_igd_result_t result = {
		.generation = work->generation,
	};
	int discover_error = 0;
	struct UPNPDev *devlist =
		upnpDiscover(FASTD_UPNP_DISCOVER_DELAY, NULL, NULL, UPNP_LOCAL_PORT_ANY, 0, 2, &discover_error);
	if (!devlist) {
		result.discover_error = discover_error;
		goto done;
	}
	result.discovered = true;

	char lanaddr[64] = {};
	char wanaddr[64] = {};
	struct UPNPUrls urls = {};
	struct IGDdatas data = {};
	result.igd_result =
		UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
	freeUPNPDevlist(devlist);

	if (result.igd_result != UPNP_NO_IGD) {
		copy_upnp_result_field(result.control_url, sizeof(result.control_url), urls.controlURL);
		copy_upnp_result_field(result.service_type, sizeof(result.service_type), data.first.servicetype);
		copy_upnp_result_field(result.lanaddr, sizeof(result.lanaddr), lanaddr);
		copy_upnp_result_field(result.wanaddr, sizeof(result.wanaddr), wanaddr);
	}
	FreeUPNPUrls(&urls);

done:
	fastd_async_enqueue(ASYNC_TYPE_UPNP_IGD_RESULT, &result, sizeof(result));
	upnp_discovery_worker_done(work->mapping);
	free(work);
	return NULL;
}

/** Starts a background UPnP discovery worker when one is not already active */
static void start_upnp_discovery(fastd_port_mapping_t *mapping) {
	pthread_mutex_lock(&mapping->upnp_mutex);
	if (!mapping->use_upnp_igd || mapping->upnp_initialized || mapping->upnp_worker_running || mapping->upnp_stopping) {
		pthread_mutex_unlock(&mapping->upnp_mutex);
		return;
	}
	mapping->upnp_worker_running = true;
	pthread_mutex_unlock(&mapping->upnp_mutex);

	upnp_discovery_work_t *work = fastd_new(upnp_discovery_work_t);
	*work = (upnp_discovery_work_t){
		.mapping = mapping,
		.generation = mapping->upnp_generation,
	};

	pthread_t thread;
	int ret = pthread_create(&thread, &ctx.detached_thread, upnp_discovery_worker, work);
	if (ret) {
		pr_warn("unable to create UPnP discovery worker: %s", strerror(ret));
		upnp_discovery_worker_done(mapping);
		free(work);
		schedule_upnp_retry(mapping);
	}
}

/** Applies a completed UPnP discovery result in the main thread */
void fastd_port_mapping_handle_upnp_igd_result(const fastd_async_upnp_igd_result_t *result) {
	fastd_port_mapping_t *mapping = ctx.port_mapping;
	if (!mapping || !result)
		return;

	pthread_mutex_lock(&mapping->upnp_mutex);
	bool accepted = !mapping->upnp_stopping && mapping->upnp_generation == result->generation;
	pthread_mutex_unlock(&mapping->upnp_mutex);
	if (!accepted)
		return;

	if (!result->discovered) {
		pr_warn("unable to discover UPnP IGD devices: error %i", result->discover_error);
		schedule_upnp_retry(mapping);
		return;
	}

	switch (result->igd_result) {
	case UPNP_CONNECTED_IGD:
		pr_verbose("found UPnP IGD with external address %s", result->wanaddr);
		set_upnp_external_address(mapping, result->wanaddr);
		break;

	case UPNP_PRIVATEIP_IGD:
		pr_warn("found UPnP IGD, but its external address is private");
		break;

	case UPNP_DISCONNECTED_IGD:
		pr_warn("found UPnP IGD, but it is not connected");
		break;

	case UPNP_NO_IGD:
		pr_warn("no valid UPnP IGD found");
		schedule_upnp_retry(mapping);
		return;

	default:
		pr_warn("unable to use discovered UPnP device as IGD");
		schedule_upnp_retry(mapping);
		return;
	}

	if (!result->control_url[0] || !result->service_type[0] || !result->lanaddr[0]) {
		pr_warn("UPnP IGD discovery returned incomplete mapping information");
		schedule_upnp_retry(mapping);
		return;
	}

	mapping->upnp_urls.controlURL = fastd_strdup(result->control_url);
	copy_upnp_result_field(
		mapping->upnp_data.first.servicetype, sizeof(mapping->upnp_data.first.servicetype), result->service_type);
	mapping->upnp_initialized = true;
	add_upnp_mappings(mapping, result->lanaddr);
}

/** Sends best-effort deletion requests for active UPnP IGD mappings */
static void release_upnp_mappings(fastd_port_mapping_t *mapping) {
	if (!mapping->upnp_initialized)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (!entry->upnp_mapped)
			continue;

		release_upnp_mapping_entry(mapping, entry);
	}
}

/** Frees UPnP IGD state */
static void cleanup_upnp_igd(fastd_port_mapping_t *mapping) {
	if (fastd_task_scheduled(&mapping->upnp_task))
		fastd_task_unschedule(&mapping->upnp_task);

	pthread_mutex_lock(&mapping->upnp_mutex);
	mapping->upnp_stopping = true;
	while (mapping->upnp_worker_running) {
		pthread_mutex_unlock(&mapping->upnp_mutex);
		usleep(10000);
		pthread_mutex_lock(&mapping->upnp_mutex);
	}
	pthread_mutex_unlock(&mapping->upnp_mutex);

	release_upnp_mappings(mapping);

	if (mapping->upnp_initialized) {
		FreeUPNPUrls(&mapping->upnp_urls);
		mapping->upnp_initialized = false;
	}

	pthread_mutex_destroy(&mapping->upnp_mutex);
}

#endif


#ifdef WITH_PCP

/** Writes a big-endian 16-bit integer to a PCP packet */
static void pcp_write_u16(uint8_t *buf, size_t offset, uint16_t value) {
	uint16_t be = htons(value);
	memcpy(buf + offset, &be, sizeof(be));
}

/** Writes a big-endian 32-bit integer to a PCP packet */
static void pcp_write_u32(uint8_t *buf, size_t offset, uint32_t value) {
	uint32_t be = htobe32(value);
	memcpy(buf + offset, &be, sizeof(be));
}

/** Reads a big-endian 16-bit integer from a PCP packet */
static uint16_t pcp_read_u16(const uint8_t *buf, size_t offset) {
	uint16_t be;
	memcpy(&be, buf + offset, sizeof(be));
	return ntohs(be);
}

/** Reads a big-endian 32-bit integer from a PCP packet */
static uint32_t pcp_read_u32(const uint8_t *buf, size_t offset) {
	uint32_t be;
	memcpy(&be, buf + offset, sizeof(be));
	return be32toh(be);
}

/** Stores an IPv4 address using PCP's IPv4-mapped IPv6 representation */
static void pcp_write_ipv4_mapped(uint8_t out[16], const struct in_addr *addr) {
	memset(out, 0, 16);
	out[10] = 0xff;
	out[11] = 0xff;
	memcpy(out + 12, &addr->s_addr, sizeof(addr->s_addr));
}

/** Parses an IPv4-mapped IPv6 address from a PCP packet */
static bool pcp_read_ipv4_mapped(const uint8_t in[16], fastd_peer_address_t *addr) {
	static const uint8_t prefix[12] = {
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0xff, 0xff,
	};

	if (memcmp(in, prefix, sizeof(prefix)))
		return false;

	*addr = (fastd_peer_address_t){ .in = { .sin_family = AF_INET } };
	memcpy(&addr->in.sin_addr.s_addr, in + 12, sizeof(addr->in.sin_addr.s_addr));
	return true;
}

/** Returns a human-readable string for a PCP result code */
static const char *pcp_result_name(uint8_t result) {
	switch (result) {
	case 0:
		return "success";
	case 1:
		return "unsupported version";
	case 2:
		return "not authorized";
	case 3:
		return "malformed request";
	case 4:
		return "unsupported opcode";
	case 5:
		return "unsupported option";
	case 6:
		return "malformed option";
	case 7:
		return "network failure";
	case 8:
		return "no resources";
	case 9:
		return "unsupported protocol";
	case 10:
		return "user excess";
	case 11:
		return "cannot provide external address";
	case 12:
		return "address mismatch";
	case 13:
		return "excessive remote peers";
	default:
		return "unknown result";
	}
}

/** Schedules the PCP task, replacing an existing timeout if necessary */
static void schedule_pcp_task(fastd_port_mapping_t *mapping, fastd_timeout_t timeout) {
	if (fastd_task_scheduled(&mapping->pcp_task))
		fastd_task_unschedule(&mapping->pcp_task);

	fastd_task_schedule(&mapping->pcp_task, TASK_TYPE_PCP, timeout);
}

/** Reads the IPv4 default gateway from Linux's route table */
static bool get_default_gateway(fastd_peer_address_t *gateway) {
	FILE *fp = fopen("/proc/net/route", "r");
	if (!fp) {
		pr_warn_errno("unable to read /proc/net/route");
		return false;
	}

	char line[256];
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return false;
	}

	bool found = false;
	while (fgets(line, sizeof(line), fp)) {
		char iface[IFNAMSIZ] = {};
		unsigned long destination = 0, route_gateway = 0, flags = 0;

		if (sscanf(line, "%15s %lx %lx %lx", iface, &destination, &route_gateway, &flags) != 4)
			continue;

		if (destination || !route_gateway || !(flags & RTF_UP) || !(flags & RTF_GATEWAY))
			continue;

		*gateway = (fastd_peer_address_t){
			.in = {
				.sin_family = AF_INET,
				.sin_port = htons(FASTD_PCP_PORT),
				.sin_addr = { .s_addr = (in_addr_t)route_gateway },
			},
		};
		found = true;
		break;
	}

	fclose(fp);
	return found;
}

/** Initializes the stable MAP nonce for an entry */
static void ensure_pcp_nonce(fastd_port_mapping_entry_t *entry) {
	if (entry->pcp_nonce_valid)
		return;

	fastd_random_bytes(entry->pcp_nonce, sizeof(entry->pcp_nonce), false);
	entry->pcp_nonce_valid = true;
}

/** Builds one PCP MAP request */
static bool build_pcp_map_request(
	const fastd_port_mapping_entry_t *entry, uint32_t lifetime, const fastd_peer_address_t *client_addr,
	uint8_t *buf, size_t *len) {
	if (!entry || !client_addr || client_addr->sa.sa_family != AF_INET || !buf || !len ||
	    *len < FASTD_PCP_MAP_PACKET_LEN)
		return false;

	memset(buf, 0, FASTD_PCP_MAP_PACKET_LEN);
	buf[0] = FASTD_PCP_VERSION;
	buf[1] = FASTD_PCP_OPCODE_MAP;
	pcp_write_u32(buf, 4, lifetime);
	pcp_write_ipv4_mapped(buf + 8, &client_addr->in.sin_addr);
	memcpy(buf + 24, entry->pcp_nonce, sizeof(entry->pcp_nonce));
	buf[36] = FASTD_PCP_PROTOCOL_UDP;
	pcp_write_u16(buf, 40, entry->port);
	pcp_write_u16(buf, 42, entry->pcp_public_port ? entry->pcp_public_port : entry->port);

	if (entry->pcp_external_addr.sa.sa_family == AF_INET)
		pcp_write_ipv4_mapped(buf + 44, &entry->pcp_external_addr.in.sin_addr);

	*len = FASTD_PCP_MAP_PACKET_LEN;
	return true;
}

/** Returns the local address used by the PCP control socket */
static bool get_pcp_client_address(const fastd_port_mapping_t *mapping, fastd_peer_address_t *addr) {
	socklen_t len = sizeof(*addr);
	memset(addr, 0, sizeof(*addr));

	if (getsockname(mapping->pcp_fd.fd, &addr->sa, &len) || addr->sa.sa_family != AF_INET)
		return false;

	return true;
}

/** Sends a PCP MAP request for one entry */
static bool send_pcp_map_request(fastd_port_mapping_t *mapping, fastd_port_mapping_entry_t *entry, uint32_t lifetime) {
	fastd_peer_address_t client_addr = {};
	if (!get_pcp_client_address(mapping, &client_addr)) {
		pr_warn("unable to determine local address for PCP MAP request");
		return false;
	}

	ensure_pcp_nonce(entry);

	uint8_t buf[FASTD_PCP_MAP_PACKET_LEN];
	size_t len = sizeof(buf);
	if (!build_pcp_map_request(entry, lifetime, &client_addr, buf, &len))
		return false;

	ssize_t ret = send(mapping->pcp_fd.fd, buf, len, 0);
	if (ret < 0) {
		pr_warn_errno("unable to send PCP MAP request");
		return false;
	}

	if ((size_t)ret != len) {
		pr_warn("short PCP MAP request send for UDP port %u", entry->port);
		return false;
	}

	return true;
}

static void request_pcp_mapping(fastd_port_mapping_t *mapping, size_t i);
static void release_pcp_mapping_entry(fastd_port_mapping_t *mapping, fastd_port_mapping_entry_t *entry);

/** Schedules a retry after a failed PCP mapping attempt */
static void schedule_pcp_retry(fastd_port_mapping_t *mapping) {
	mapping->pcp_request_pending = false;
	mapping->pcp_current = 0;
	mapping->pcp_retries = 0;
	compact_unused_mappings(mapping);
	schedule_pcp_task(mapping, ctx.now + FASTD_PCP_RETRY_INTERVAL);
}

/** Returns the delay after which the active PCP mappings should be renewed */
static int64_t pcp_renewal_delay(const fastd_port_mapping_t *mapping) {
	uint32_t lifetime = FASTD_PCP_LIFETIME;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		const fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (entry->pcp_mapped && entry->pcp_lifetime && entry->pcp_lifetime < lifetime)
			lifetime = entry->pcp_lifetime;
	}

	int64_t delay = (int64_t)lifetime * 1000 / 2;
	return delay > 1000 ? delay : 1000;
}

/** Starts a PCP MAP request for a given mapping index */
static void request_pcp_mapping(fastd_port_mapping_t *mapping, size_t i) {
	compact_unused_mappings(mapping);

	while (i < VECTOR_LEN(mapping->mappings) && !VECTOR_INDEX(mapping->mappings, i).use_pcp)
		i++;

	if (i >= VECTOR_LEN(mapping->mappings)) {
		mapping->pcp_request_pending = false;
		mapping->pcp_current = 0;
		mapping->pcp_retries = 0;
		schedule_pcp_task(mapping, ctx.now + pcp_renewal_delay(mapping));
		return;
	}

	mapping->pcp_current = i;
	mapping->pcp_retries = 0;
	fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
	if (!send_pcp_map_request(mapping, entry, FASTD_PCP_LIFETIME)) {
		schedule_pcp_retry(mapping);
		return;
	}

	mapping->pcp_request_pending = true;
	schedule_pcp_task(mapping, ctx.now + FASTD_PCP_REQUEST_TIMEOUT);
}

/** Retransmits or fails the currently pending PCP request */
static void handle_pcp_timeout(fastd_port_mapping_t *mapping) {
	if (!mapping->pcp_request_pending) {
		request_pcp_mapping(mapping, 0);
		return;
	}

	if (mapping->pcp_current >= VECTOR_LEN(mapping->mappings)) {
		schedule_pcp_retry(mapping);
		return;
	}

	fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, mapping->pcp_current);
	if (!entry->use_pcp) {
		size_t current = mapping->pcp_current;
		mapping->pcp_request_pending = false;
		request_pcp_mapping(mapping, current);
		return;
	}

	if (mapping->pcp_retries >= FASTD_PCP_MAX_RETRIES) {
		pr_warn("PCP MAP request for UDP port %u timed out", entry->port);
		schedule_pcp_retry(mapping);
		return;
	}

	mapping->pcp_retries++;
	if (!send_pcp_map_request(mapping, entry, FASTD_PCP_LIFETIME)) {
		schedule_pcp_retry(mapping);
		return;
	}

	int64_t timeout = FASTD_PCP_REQUEST_TIMEOUT << mapping->pcp_retries;
	schedule_pcp_task(mapping, ctx.now + timeout);
}

/** Finds an entry matching a PCP MAP response */
static fastd_port_mapping_entry_t *find_pcp_response_entry(
	fastd_port_mapping_t *mapping, const uint8_t nonce[12], uint16_t internal_port) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (entry->pcp_nonce_valid && entry->port == internal_port &&
		    !memcmp(entry->pcp_nonce, nonce, sizeof(entry->pcp_nonce)))
			return entry;
	}

	return NULL;
}

/** Handles one PCP MAP response packet */
static bool handle_pcp_response_packet(fastd_port_mapping_t *mapping, const uint8_t *buf, size_t len) {
	if (len < FASTD_PCP_MAP_PACKET_LEN || buf[0] != FASTD_PCP_VERSION ||
	    buf[1] != FASTD_PCP_RESPONSE_OPCODE_MAP || buf[36] != FASTD_PCP_PROTOCOL_UDP)
		return false;

	uint16_t internal_port = pcp_read_u16(buf, 40);
	fastd_port_mapping_entry_t *entry = find_pcp_response_entry(mapping, buf + 24, internal_port);
	if (!entry)
		return false;

	bool pending_current = mapping->pcp_request_pending && mapping->pcp_current < VECTOR_LEN(mapping->mappings) &&
			       entry == &VECTOR_INDEX(mapping->mappings, mapping->pcp_current);
	uint8_t result = buf[3];

	if (result != FASTD_PCP_RESULT_SUCCESS) {
		entry->pcp_mapped = false;
		pr_warn("PCP MAP request for UDP port %u failed: %s", entry->port, pcp_result_name(result));
		if (pending_current) {
			size_t next_index = mapping->pcp_current + (entry_has_users(entry) ? 1 : 0);
			mapping->pcp_request_pending = false;
			request_pcp_mapping(mapping, next_index);
		}
		return true;
	}

	uint32_t lifetime = pcp_read_u32(buf, 4);
	uint16_t public_port = pcp_read_u16(buf, 42);
	fastd_peer_address_t external_addr = {};
	if (!lifetime || !public_port || !pcp_read_ipv4_mapped(buf + 44, &external_addr)) {
		pr_warn("received malformed PCP MAP success response for UDP port %u", entry->port);
		if (pending_current) {
			size_t next_index = mapping->pcp_current + (entry_has_users(entry) ? 1 : 0);
			mapping->pcp_request_pending = false;
			request_pcp_mapping(mapping, next_index);
		}
		return true;
	}

	entry->pcp_mapped = true;
	entry->pcp_public_port = public_port;
	entry->pcp_lifetime = lifetime;
	entry->pcp_external_addr = external_addr;

	if (!entry->use_pcp) {
		release_pcp_mapping_entry(mapping, entry);
	} else if (entry->pcp_public_port == entry->port) {
		pr_verbose("mapped UDP port %u using PCP", entry->port);
	} else {
		pr_warn("PCP mapped local UDP port %u to different public port %u", entry->port, entry->pcp_public_port);
	}

	if (pending_current) {
		size_t next_index = mapping->pcp_current + (entry_has_users(entry) ? 1 : 0);
		mapping->pcp_request_pending = false;
		request_pcp_mapping(mapping, next_index);
	}

	return true;
}

/** Initializes automatic PCP port mapping */
static void init_pcp(fastd_port_mapping_t *mapping) {
	if (!get_default_gateway(&mapping->pcp_server_addr)) {
		pr_warn("unable to determine default gateway for PCP");
		schedule_pcp_task(mapping, ctx.now + FASTD_PCP_RETRY_INTERVAL);
		return;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		pr_warn_errno("unable to open PCP socket");
		schedule_pcp_task(mapping, ctx.now + FASTD_PCP_RETRY_INTERVAL);
		return;
	}

	fastd_setnonblock(fd);
	if (connect(fd, &mapping->pcp_server_addr.sa, sizeof(mapping->pcp_server_addr.in))) {
		pr_warn_errno("unable to connect PCP socket to default gateway");
		close(fd);
		schedule_pcp_task(mapping, ctx.now + FASTD_PCP_RETRY_INTERVAL);
		return;
	}

	mapping->pcp_fd = FASTD_POLL_FD(POLL_TYPE_PCP, fd);
	fastd_poll_fd_register(&mapping->pcp_fd);
	mapping->pcp_initialized = true;
	request_pcp_mapping(mapping, 0);
}

/** Sends a best-effort PCP deletion request for one active mapping */
static void release_pcp_mapping_entry(fastd_port_mapping_t *mapping, fastd_port_mapping_entry_t *entry) {
	if (!entry->pcp_mapped)
		return;

	if (mapping->pcp_initialized)
		send_pcp_map_request(mapping, entry, 0);

	entry->pcp_mapped = false;
	entry->pcp_public_port = 0;
	entry->pcp_lifetime = 0;
	entry->pcp_external_addr.sa.sa_family = AF_UNSPEC;
}

/** Handles input on the PCP socket */
void fastd_port_mapping_handle_pcp(void) {
	if (!ctx.port_mapping || !ctx.port_mapping->pcp_initialized)
		return;

	uint8_t buf[128];
	while (true) {
		ssize_t ret = recv(ctx.port_mapping->pcp_fd.fd, buf, sizeof(buf), 0);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return;

			pr_warn_errno("unable to receive PCP response");
			schedule_pcp_retry(ctx.port_mapping);
			return;
		}

		if (!ret)
			return;

		if (!handle_pcp_response_packet(ctx.port_mapping, buf, (size_t)ret))
			pr_debug("ignoring unexpected PCP response packet");
	}
}

/** Handles PCP retry or renewal tasks */
void fastd_port_mapping_handle_pcp_task(void) {
	if (!ctx.port_mapping)
		return;

	if (!ctx.port_mapping->pcp_initialized) {
		init_pcp(ctx.port_mapping);
		return;
	}

	handle_pcp_timeout(ctx.port_mapping);
}

/** Sends best-effort deletion requests for active PCP mappings */
static void release_pcp_mappings(fastd_port_mapping_t *mapping) {
	if (!mapping->pcp_initialized)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		release_pcp_mapping_entry(mapping, entry);
	}
}

/** Frees PCP state */
static void cleanup_pcp(fastd_port_mapping_t *mapping) {
	if (fastd_task_scheduled(&mapping->pcp_task))
		fastd_task_unschedule(&mapping->pcp_task);

	release_pcp_mappings(mapping);

	if (mapping->pcp_initialized) {
		fastd_poll_fd_close(&mapping->pcp_fd);
		mapping->pcp_initialized = false;
	}
}

#else

void fastd_port_mapping_handle_pcp(void) {}
void fastd_port_mapping_handle_pcp_task(void) {}

#endif


/** Returns true if a mapping entry still has an active gateway lease */
static bool entry_has_active_lease(const fastd_port_mapping_entry_t *entry) {
#ifdef WITH_NATPMP
	if (entry->natpmp_mapped)
		return true;
#endif

#ifdef WITH_UPNP_IGD
	if (entry->upnp_mapped)
		return true;
#endif

#ifdef WITH_PCP
	if (entry->pcp_mapped)
		return true;
#endif

	return false;
}

/** Releases active leases for an entry that is no longer referenced */
static void release_entry_leases(fastd_port_mapping_t *mapping, fastd_port_mapping_entry_t *entry) {
#ifdef WITH_NATPMP
	release_natpmp_mapping_entry(entry);
#endif

#ifdef WITH_UPNP_IGD
	release_upnp_mapping_entry(mapping, entry);
#endif

#ifdef WITH_PCP
	release_pcp_mapping_entry(mapping, entry);
#endif
}

/** Removes disabled mapping entries whose leases have been released */
static void compact_unused_mappings(fastd_port_mapping_t *mapping) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings);) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (entry_has_users(entry)) {
			i++;
			continue;
		}

#ifdef WITH_NATPMP
		if (mapping->request_pending && mapping->current == i) {
			i++;
			continue;
		}
#endif

#ifdef WITH_PCP
		if (mapping->pcp_request_pending && mapping->pcp_current == i) {
			i++;
			continue;
		}
#endif

		release_entry_leases(mapping, entry);
		if (entry_has_active_lease(entry)) {
			i++;
			continue;
		}

		VECTOR_DELETE(mapping->mappings, i);

#ifdef WITH_NATPMP
		if (mapping->request_pending && mapping->current > i)
			mapping->current--;
#endif

#ifdef WITH_PCP
		if (mapping->pcp_request_pending && mapping->pcp_current > i)
			mapping->pcp_current--;
#endif
	}

	recompute_mapping_backends(mapping);
}

/** Starts or refreshes gateway backend work after the mapping set changed */
static void activate_mapping_backends(fastd_port_mapping_t *mapping) {
#ifdef WITH_TESTS
	if (mapping->test_no_backend_activation)
		return;
#endif

#ifdef WITH_NATPMP
	if (mapping->use_natpmp) {
		if (!mapping->initialized)
			init_natpmp(mapping);
		else if (!mapping->request_pending)
			request_mapping(mapping, 0);
	}
#endif

#ifdef WITH_UPNP_IGD
	if (mapping->use_upnp_igd) {
		if (!mapping->upnp_initialized)
			start_upnp_discovery(mapping);
		else {
			size_t i;
			for (i = 0; i < VECTOR_LEN(mapping->mappings); i++)
				add_upnp_mapping(mapping, &VECTOR_INDEX(mapping->mappings, i));
		}
	}
#endif

#ifdef WITH_PCP
	if (mapping->use_pcp) {
		if (!mapping->pcp_initialized)
			init_pcp(mapping);
		else if (!mapping->pcp_request_pending)
			request_pcp_mapping(mapping, 0);
	}
#endif
}

/** Clears dynamic socket-side registration flags after the global mapping state is torn down */
static void clear_dynamic_socket_mapping_flags(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);
		if (!sock || !sock->punch_listener_mapping_registered)
			continue;

		sock->punch_listener_mapping_registered = false;
		sock->punch_listener_port_mapped = false;
	}
}

#ifdef WITH_STATUS_SOCKET

/** Returns true if a peer address contains an IP endpoint */
static bool mapping_address_available(const fastd_peer_address_t *addr) {
	return addr && (addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
}

/** Returns a peer address string as a json_object *, allowing unavailable addresses */
static json_object *wrap_mapping_address_or_null(const fastd_peer_address_t *addr) {
	if (!mapping_address_available(addr))
		return NULL;

	char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
	fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), addr, NULL, false, false);
	return json_object_new_string(addr_buf);
}

/** Adds one backend name to an array when enabled */
static void add_backend_name(json_object *array, const char *name, bool enabled) {
	if (enabled)
		json_object_array_add(array, json_object_new_string(name));
}

/** Returns a backend name array for the provided flags */
static json_object *backend_name_array(bool natpmp, bool upnp_igd, bool pcp) {
	json_object *ret = json_object_new_array();
	add_backend_name(ret, "nat-pmp", natpmp);
	add_backend_name(ret, "upnp-igd", upnp_igd);
	add_backend_name(ret, "pcp", pcp);
	return ret;
}

/** Adds an endpoint string to the public endpoint list */
static void add_public_endpoint(
	json_object *array, const char *backend, const fastd_peer_address_t *addr, uint16_t port) {
	char endpoint[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
	char value[sizeof(endpoint) + 32];

	if (mapping_address_available(addr)) {
		fastd_peer_address_t endpoint_addr = *addr;
		set_mapped_address_port(&endpoint_addr, port);
		fastd_snprint_peer_address(endpoint, sizeof(endpoint), &endpoint_addr, NULL, false, false);
		snprintf(value, sizeof(value), "%s %s", backend, endpoint);
	} else {
		snprintf(value, sizeof(value), "%s port %u", backend, port);
	}

	json_object_array_add(array, json_object_new_string(value));
}

/** Returns the currently selected NAT-PMP port, if any */
static json_object *natpmp_current_port(const fastd_port_mapping_t *mapping) {
#ifdef WITH_NATPMP
	if (mapping && mapping->request_pending && mapping->current < VECTOR_LEN(mapping->mappings))
		return json_object_new_int(VECTOR_INDEX(mapping->mappings, mapping->current).port);
#endif

	return NULL;
}

/** Dumps NAT-PMP backend status */
static json_object *dump_natpmp_backend_status(const fastd_port_mapping_t *mapping) {
	json_object *ret = json_object_new_object();
#ifdef WITH_NATPMP
	json_object_object_add(ret, "compiled", json_object_new_boolean(true));
	json_object_object_add(ret, "requested", json_object_new_boolean(mapping && mapping->natpmp_requested));
	json_object_object_add(ret, "active", json_object_new_boolean(mapping && mapping->use_natpmp));
	json_object_object_add(ret, "initialized", json_object_new_boolean(mapping && mapping->initialized));
	json_object_object_add(ret, "request_pending", json_object_new_boolean(mapping && mapping->request_pending));
	json_object_object_add(ret, "current_port", natpmp_current_port(mapping));
#else
	json_object_object_add(ret, "compiled", json_object_new_boolean(false));
	json_object_object_add(ret, "requested", json_object_new_boolean(mapping && mapping->natpmp_requested));
	json_object_object_add(ret, "active", json_object_new_boolean(false));
	json_object_object_add(ret, "initialized", json_object_new_boolean(false));
	json_object_object_add(ret, "request_pending", json_object_new_boolean(false));
	json_object_object_add(ret, "current_port", NULL);
#endif
	return ret;
}

/** Dumps UPnP IGD backend status */
static json_object *dump_upnp_backend_status(fastd_port_mapping_t *mapping) {
	json_object *ret = json_object_new_object();
#ifdef WITH_UPNP_IGD
	bool discovery_in_flight = false;
	if (mapping) {
		pthread_mutex_lock(&mapping->upnp_mutex);
		discovery_in_flight = mapping->upnp_worker_running;
		pthread_mutex_unlock(&mapping->upnp_mutex);
	}

	fastd_timeout_t retry_timeout =
		mapping && fastd_task_scheduled(&mapping->upnp_task)
			? fastd_task_timeout(&mapping->upnp_task)
			: FASTD_TIMEOUT_INV;
	json_object_object_add(ret, "compiled", json_object_new_boolean(true));
	json_object_object_add(ret, "requested", json_object_new_boolean(mapping && mapping->upnp_igd_requested));
	json_object_object_add(ret, "active", json_object_new_boolean(mapping && mapping->use_upnp_igd));
	json_object_object_add(ret, "initialized", json_object_new_boolean(mapping && mapping->upnp_initialized));
	json_object_object_add(ret, "discovery_in_flight", json_object_new_boolean(discovery_in_flight));
	json_object_object_add(
		ret, "retry_in",
		retry_timeout == FASTD_TIMEOUT_INV ? NULL : json_object_new_int64(retry_timeout > ctx.now ? retry_timeout - ctx.now : 0));
	json_object_object_add(
		ret, "external_address", mapping ? wrap_mapping_address_or_null(&mapping->upnp_external_addr) : NULL);
	json_object_object_add(
		ret, "lan_address",
		mapping && mapping->upnp_lanaddr[0] ? json_object_new_string(mapping->upnp_lanaddr) : NULL);
#else
	json_object_object_add(ret, "compiled", json_object_new_boolean(false));
	json_object_object_add(ret, "requested", json_object_new_boolean(mapping && mapping->upnp_igd_requested));
	json_object_object_add(ret, "active", json_object_new_boolean(false));
	json_object_object_add(ret, "initialized", json_object_new_boolean(false));
	json_object_object_add(ret, "discovery_in_flight", json_object_new_boolean(false));
	json_object_object_add(ret, "retry_in", NULL);
	json_object_object_add(ret, "external_address", NULL);
	json_object_object_add(ret, "lan_address", NULL);
#endif
	return ret;
}

#ifdef WITH_PCP
/** Returns the currently selected PCP port, if any */
static json_object *pcp_current_port(const fastd_port_mapping_t *mapping) {
	if (mapping && mapping->pcp_request_pending && mapping->pcp_current < VECTOR_LEN(mapping->mappings))
		return json_object_new_int(VECTOR_INDEX(mapping->mappings, mapping->pcp_current).port);

	return NULL;
}
#endif

/** Dumps PCP backend status */
static json_object *dump_pcp_backend_status(const fastd_port_mapping_t *mapping) {
	json_object *ret = json_object_new_object();
#ifdef WITH_PCP
	json_object_object_add(ret, "compiled", json_object_new_boolean(true));
	json_object_object_add(ret, "requested", json_object_new_boolean(mapping && mapping->pcp_requested));
	json_object_object_add(ret, "active", json_object_new_boolean(mapping && mapping->use_pcp));
	json_object_object_add(ret, "initialized", json_object_new_boolean(mapping && mapping->pcp_initialized));
	json_object_object_add(ret, "request_pending", json_object_new_boolean(mapping && mapping->pcp_request_pending));
	json_object_object_add(ret, "current_port", pcp_current_port(mapping));
	json_object_object_add(ret, "server", mapping ? wrap_mapping_address_or_null(&mapping->pcp_server_addr) : NULL);
	json_object_object_add(ret, "retries", json_object_new_int(mapping ? mapping->pcp_retries : 0));
#else
	json_object_object_add(ret, "compiled", json_object_new_boolean(false));
	json_object_object_add(ret, "requested", json_object_new_boolean(mapping && mapping->pcp_requested));
	json_object_object_add(ret, "active", json_object_new_boolean(false));
	json_object_object_add(ret, "initialized", json_object_new_boolean(false));
	json_object_object_add(ret, "request_pending", json_object_new_boolean(false));
	json_object_object_add(ret, "current_port", NULL);
	json_object_object_add(ret, "server", NULL);
	json_object_object_add(ret, "retries", json_object_new_int(0));
#endif
	return ret;
}

/** Dumps one mapping entry's NAT-PMP lease status */
static json_object *dump_natpmp_entry_status(const fastd_port_mapping_entry_t *entry, json_object *endpoints) {
	json_object *ret = json_object_new_object();
#ifdef WITH_NATPMP
	json_object_object_add(ret, "compiled", json_object_new_boolean(true));
	json_object_object_add(ret, "active", json_object_new_boolean(entry->use_natpmp));
	json_object_object_add(ret, "mapped", json_object_new_boolean(entry->natpmp_mapped));
	json_object_object_add(
		ret, "public_port", entry->natpmp_mapped ? json_object_new_int(entry->natpmp_public_port) : NULL);
	json_object_object_add(
		ret, "lifetime", entry->natpmp_mapped ? json_object_new_int64(entry->natpmp_lifetime) : NULL);
	if (entry->natpmp_mapped)
		add_public_endpoint(endpoints, "nat-pmp", NULL, entry->natpmp_public_port);
#else
	json_object_object_add(ret, "compiled", json_object_new_boolean(false));
	json_object_object_add(ret, "active", json_object_new_boolean(false));
	json_object_object_add(ret, "mapped", json_object_new_boolean(false));
	json_object_object_add(ret, "public_port", NULL);
	json_object_object_add(ret, "lifetime", NULL);
#endif
	return ret;
}

/** Dumps one mapping entry's UPnP IGD lease status */
static json_object *dump_upnp_entry_status(
	const fastd_port_mapping_t *mapping, const fastd_port_mapping_entry_t *entry, json_object *endpoints) {
	json_object *ret = json_object_new_object();
#ifdef WITH_UPNP_IGD
	json_object_object_add(ret, "compiled", json_object_new_boolean(true));
	json_object_object_add(ret, "active", json_object_new_boolean(entry->use_upnp_igd));
	json_object_object_add(ret, "mapped", json_object_new_boolean(entry->upnp_mapped));
	json_object_object_add(
		ret, "public_port", entry->upnp_mapped ? json_object_new_int(entry->upnp_public_port) : NULL);
	json_object_object_add(
		ret, "external_address",
		entry->upnp_mapped ? wrap_mapping_address_or_null(&mapping->upnp_external_addr) : NULL);
	if (entry->upnp_mapped)
		add_public_endpoint(endpoints, "upnp-igd", &mapping->upnp_external_addr, entry->upnp_public_port);
#else
	json_object_object_add(ret, "compiled", json_object_new_boolean(false));
	json_object_object_add(ret, "active", json_object_new_boolean(false));
	json_object_object_add(ret, "mapped", json_object_new_boolean(false));
	json_object_object_add(ret, "public_port", NULL);
	json_object_object_add(ret, "external_address", NULL);
#endif
	return ret;
}

/** Dumps one mapping entry's PCP lease status */
static json_object *dump_pcp_entry_status(const fastd_port_mapping_entry_t *entry UNUSED, json_object *endpoints UNUSED) {
	json_object *ret = json_object_new_object();
#ifdef WITH_PCP
	json_object_object_add(ret, "compiled", json_object_new_boolean(true));
	json_object_object_add(ret, "active", json_object_new_boolean(entry->use_pcp));
	json_object_object_add(ret, "mapped", json_object_new_boolean(entry->pcp_mapped));
	json_object_object_add(
		ret, "public_port", entry->pcp_mapped ? json_object_new_int(entry->pcp_public_port) : NULL);
	json_object_object_add(
		ret, "lifetime", entry->pcp_mapped ? json_object_new_int64(entry->pcp_lifetime) : NULL);
	json_object_object_add(
		ret, "external_address", entry->pcp_mapped ? wrap_mapping_address_or_null(&entry->pcp_external_addr) : NULL);
	if (entry->pcp_mapped)
		add_public_endpoint(endpoints, "pcp", &entry->pcp_external_addr, entry->pcp_public_port);
#else
	json_object_object_add(ret, "compiled", json_object_new_boolean(false));
	json_object_object_add(ret, "active", json_object_new_boolean(false));
	json_object_object_add(ret, "mapped", json_object_new_boolean(false));
	json_object_object_add(ret, "public_port", NULL);
	json_object_object_add(ret, "lifetime", NULL);
	json_object_object_add(ret, "external_address", NULL);
#endif
	return ret;
}

/** Dumps one port mapping entry */
static json_object *dump_port_mapping_entry(
	const fastd_port_mapping_t *mapping, const fastd_port_mapping_entry_t *entry) {
	json_object *ret = json_object_new_object();
	json_object *endpoints = json_object_new_array();

	json_object_object_add(ret, "local_port", json_object_new_int(entry->port));
	json_object_object_add(ret, "backends", backend_name_array(entry->use_natpmp, entry->use_upnp_igd, entry->use_pcp));

	json_object *fixed = json_object_new_object();
	json_object_object_add(fixed, "natpmp", json_object_new_boolean(entry->fixed_natpmp));
	json_object_object_add(fixed, "upnp_igd", json_object_new_boolean(entry->fixed_upnp_igd));
	json_object_object_add(fixed, "pcp", json_object_new_boolean(entry->fixed_pcp));
	json_object_object_add(ret, "fixed", fixed);

	json_object *dynamic_refs = json_object_new_object();
	json_object_object_add(dynamic_refs, "natpmp", json_object_new_int(entry->dynamic_natpmp_refs));
	json_object_object_add(dynamic_refs, "upnp_igd", json_object_new_int(entry->dynamic_upnp_igd_refs));
	json_object_object_add(dynamic_refs, "pcp", json_object_new_int(entry->dynamic_pcp_refs));
	json_object_object_add(ret, "dynamic_refs", dynamic_refs);

	json_object_object_add(ret, "natpmp", dump_natpmp_entry_status(entry, endpoints));
	json_object_object_add(ret, "upnp_igd", dump_upnp_entry_status(mapping, entry, endpoints));
	json_object_object_add(ret, "pcp", dump_pcp_entry_status(entry, endpoints));
	json_object_object_add(ret, "public_endpoints", endpoints);

	return ret;
}

/** Dumps automatic port mapping state for the status socket */
struct json_object *fastd_port_mapping_status(void) {
	fastd_port_mapping_t *mapping = ctx.port_mapping;
	json_object *ret = json_object_new_object();
	json_object *backend_status = json_object_new_object();
	json_object *mappings = json_object_new_array();

	json_object_object_add(ret, "available", json_object_new_boolean(mapping != NULL));
	json_object_object_add(
		ret, "requested",
		backend_name_array(
			mapping && mapping->natpmp_requested, mapping && mapping->upnp_igd_requested,
			mapping && mapping->pcp_requested));
	json_object_object_add(
		ret, "active",
		backend_name_array(
			mapping && mapping->use_natpmp, mapping && mapping->use_upnp_igd, mapping && mapping->use_pcp));
	json_object_object_add(ret, "mapping_count", json_object_new_int64(mapping ? VECTOR_LEN(mapping->mappings) : 0));

	json_object_object_add(backend_status, "natpmp", dump_natpmp_backend_status(mapping));
	json_object_object_add(backend_status, "upnp_igd", dump_upnp_backend_status(mapping));
	json_object_object_add(backend_status, "pcp", dump_pcp_backend_status(mapping));
	json_object_object_add(ret, "backends", backend_status);

	if (mapping) {
		size_t i;
		for (i = 0; i < VECTOR_LEN(mapping->mappings); i++)
			json_object_array_add(
				mappings, dump_port_mapping_entry(mapping, &VECTOR_INDEX(mapping->mappings, i)));
	}
	json_object_object_add(ret, "mappings", mappings);

	return ret;
}

#endif

/** Checks if the configured automatic port mapping support is available */
bool fastd_port_mapping_check(void) {
	return true;
}

/** Initializes automatic port mapping */
void fastd_port_mapping_init(void) {
	fastd_port_mapping_t *mapping = fastd_new0(fastd_port_mapping_t);

#ifdef WITH_UPNP_IGD
	if (pthread_mutex_init(&mapping->upnp_mutex, NULL))
		exit_errno("pthread_mutex_init");
	mapping->upnp_generation = ++next_upnp_generation;
	if (!mapping->upnp_generation)
		mapping->upnp_generation = ++next_upnp_generation;
#endif

	collect_enabled_backends(mapping);
	if (!mapping->natpmp_requested && !mapping->upnp_igd_requested && !mapping->pcp_requested) {

#ifdef WITH_UPNP_IGD
		pthread_mutex_destroy(&mapping->upnp_mutex);
#endif
		free(mapping);
		return;
	}

	collect_socket_mappings(mapping);
	if (!mapping->use_natpmp && !mapping->use_upnp_igd && !mapping->use_pcp) {
		pr_debug(
			"automatic port mapping is enabled, but no enabled peer uses a fixed IPv4 bind socket; "
			"dynamic punch listeners may still request mappings");
		ctx.port_mapping = mapping;
		return;
	}

	ctx.port_mapping = mapping;

#ifdef WITH_NATPMP
	if (mapping->use_natpmp)
		init_natpmp(mapping);
#endif

#ifdef WITH_UPNP_IGD
	if (mapping->use_upnp_igd)
		start_upnp_discovery(mapping);
#endif

#ifdef WITH_PCP
	if (mapping->use_pcp)
		init_pcp(mapping);
#endif
}

/** Reinitializes automatic port mapping after configuration changes */
void fastd_port_mapping_refresh(void) {
	fastd_port_mapping_cleanup();
	fastd_port_mapping_init();
}

/** Handles input on the NAT-PMP control socket */
void fastd_port_mapping_handle(void) {
#ifdef WITH_NATPMP
	if (ctx.port_mapping)
		handle_pending_request(ctx.port_mapping);
#endif
}

/** Handles NAT-PMP retry or renewal tasks */
void fastd_port_mapping_handle_task(void) {
#ifdef WITH_NATPMP
	if (ctx.port_mapping)
		handle_pending_request(ctx.port_mapping);
#endif
}

/** Handles a scheduled UPnP IGD discovery retry */
void fastd_port_mapping_handle_upnp_task(void) {
#ifdef WITH_UPNP_IGD
	if (ctx.port_mapping)
		start_upnp_discovery(ctx.port_mapping);
#endif
}

/** Registers a dynamic UDP socket for automatic port mapping */
bool fastd_port_mapping_register_socket(fastd_socket_t *sock) {
	if (!ctx.port_mapping || !sock || sock->punch_listener_mapping_registered)
		return false;

	bool use_natpmp = ctx.port_mapping->natpmp_requested;
	bool use_upnp_igd = ctx.port_mapping->upnp_igd_requested;
	bool use_pcp = ctx.port_mapping->pcp_requested;
	if (!add_dynamic_socket_mapping(ctx.port_mapping, sock, use_natpmp, use_upnp_igd, use_pcp))
		return false;

	sock->punch_listener_mapping_registered = true;
	activate_mapping_backends(ctx.port_mapping);
	return true;
}

/** Returns the external address for a mapped fixed UDP socket, if one is known */
bool fastd_port_mapping_get_external_address(const fastd_socket_t *sock, fastd_peer_address_t *addr) {
	if (!ctx.port_mapping || !socket_is_mappable(sock))
		return false;

	uint16_t local_port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
	fastd_port_mapping_entry_t *entry = find_mapping(ctx.port_mapping, local_port);
	if (!entry)
		return false;

	uint16_t public_port = 0;

#ifdef WITH_PCP
	if (entry->pcp_mapped) {
		*addr = entry->pcp_external_addr;
		set_mapped_address_port(addr, entry->pcp_public_port);
		return true;
	}
#endif

#ifdef WITH_NATPMP
	if (entry->natpmp_mapped)
		public_port = entry->natpmp_public_port;
#endif

#ifdef WITH_UPNP_IGD
	if (!public_port && entry->upnp_mapped)
		public_port = entry->upnp_public_port;
#endif

	if (!public_port)
		return false;

#ifdef WITH_UPNP_IGD
	if (entry->upnp_mapped && ctx.port_mapping->upnp_external_addr.sa.sa_family != AF_UNSPEC) {
		*addr = ctx.port_mapping->upnp_external_addr;
		set_mapped_address_port(addr, entry->upnp_public_port);
		return true;
	}
#endif

	if (!fastd_nat_get_public_address(addr))
		return false;

	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->in.sin_port = htons(public_port);
		return true;

	case AF_INET6:
		addr->in6.sin6_port = htons(public_port);
		return true;

	default:
		return false;
	}
}

/** Releases a dynamic UDP socket's automatic port mapping lease */
void fastd_port_mapping_release_socket(fastd_socket_t *sock) {
	if (!ctx.port_mapping || !sock || !sock->punch_listener_mapping_registered)
		return;

	if (socket_is_mappable(sock)) {
		uint16_t local_port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
		fastd_port_mapping_entry_t *entry = find_mapping(ctx.port_mapping, local_port);
		if (entry) {
			if (entry->dynamic_natpmp_refs)
				entry->dynamic_natpmp_refs--;
			if (entry->dynamic_upnp_igd_refs)
				entry->dynamic_upnp_igd_refs--;
			if (entry->dynamic_pcp_refs)
				entry->dynamic_pcp_refs--;
			update_entry_backends(entry);
			if (!entry_has_users(entry))
				release_entry_leases(ctx.port_mapping, entry);
		}
	}

	sock->punch_listener_mapping_registered = false;
	compact_unused_mappings(ctx.port_mapping);
}

/** Frees resources used by automatic port mapping */
void fastd_port_mapping_cleanup(void) {
	fastd_port_mapping_t *mapping = ctx.port_mapping;
	if (!mapping)
		return;

#ifdef WITH_NATPMP
	cleanup_natpmp(mapping);
#endif

#ifdef WITH_UPNP_IGD
	cleanup_upnp_igd(mapping);
#endif

#ifdef WITH_PCP
	cleanup_pcp(mapping);
#endif

	clear_dynamic_socket_mapping_flags();
	VECTOR_FREE(mapping->mappings);
	free(mapping);
	ctx.port_mapping = NULL;
}

#ifdef WITH_TESTS

/** Creates an isolated port mapping state for unit tests */
void fastd_port_mapping_test_begin(bool natpmp_requested, bool upnp_requested, bool pcp_requested) {
	ctx.port_mapping = fastd_new0(fastd_port_mapping_t);
	ctx.port_mapping->natpmp_requested = natpmp_requested;
	ctx.port_mapping->upnp_igd_requested = upnp_requested;
	ctx.port_mapping->pcp_requested = pcp_requested;
	ctx.port_mapping->test_no_backend_activation = true;

#ifdef WITH_UPNP_IGD
	if (pthread_mutex_init(&ctx.port_mapping->upnp_mutex, NULL))
		exit_errno("pthread_mutex_init");
	ctx.port_mapping->upnp_generation = ++next_upnp_generation;
	if (!ctx.port_mapping->upnp_generation)
		ctx.port_mapping->upnp_generation = ++next_upnp_generation;
#endif
}

/** Frees the isolated port mapping state created by fastd_port_mapping_test_begin() */
void fastd_port_mapping_test_end(void) {
	if (!ctx.port_mapping)
		return;

#ifdef WITH_UPNP_IGD
	if (fastd_task_scheduled(&ctx.port_mapping->upnp_task))
		fastd_task_unschedule(&ctx.port_mapping->upnp_task);
	pthread_mutex_destroy(&ctx.port_mapping->upnp_mutex);
#endif
	VECTOR_FREE(ctx.port_mapping->mappings);
	free(ctx.port_mapping);
	ctx.port_mapping = NULL;
}

#ifdef WITH_UPNP_IGD

/** Returns the isolated test mapping generation used to validate an async result */
uint64_t fastd_port_mapping_test_upnp_generation(void) {
	return ctx.port_mapping ? ctx.port_mapping->upnp_generation : 0;
}

/** Returns the scheduled isolated UPnP retry timeout, if any */
fastd_timeout_t fastd_port_mapping_test_upnp_retry_timeout(void) {
	if (!ctx.port_mapping)
		return FASTD_TIMEOUT_INV;

	return fastd_task_timeout(&ctx.port_mapping->upnp_task);
}

#endif

/** Returns the number of entries in the isolated test mapping state */
size_t fastd_port_mapping_test_entry_count(void) {
	return ctx.port_mapping ? VECTOR_LEN(ctx.port_mapping->mappings) : 0;
}

/** Looks up one entry in the isolated test mapping state */
bool fastd_port_mapping_test_get_entry(
	uint16_t port, bool *use_natpmp, bool *use_upnp_igd, bool *use_pcp, uint16_t *dynamic_natpmp_refs,
	uint16_t *dynamic_upnp_igd_refs, uint16_t *dynamic_pcp_refs) {
	if (!ctx.port_mapping)
		return false;

	fastd_port_mapping_entry_t *entry = find_mapping(ctx.port_mapping, port);
	if (!entry)
		return false;

	if (use_natpmp)
		*use_natpmp = entry->use_natpmp;
	if (use_upnp_igd)
		*use_upnp_igd = entry->use_upnp_igd;
	if (use_pcp)
		*use_pcp = entry->use_pcp;
	if (dynamic_natpmp_refs)
		*dynamic_natpmp_refs = entry->dynamic_natpmp_refs;
	if (dynamic_upnp_igd_refs)
		*dynamic_upnp_igd_refs = entry->dynamic_upnp_igd_refs;
	if (dynamic_pcp_refs)
		*dynamic_pcp_refs = entry->dynamic_pcp_refs;

	return true;
}

#ifdef WITH_PCP

/** Sets the deterministic PCP nonce for one isolated test mapping entry */
bool fastd_port_mapping_test_pcp_set_nonce(uint16_t port, const uint8_t nonce[12]) {
	if (!ctx.port_mapping || !nonce)
		return false;

	fastd_port_mapping_entry_t *entry = find_mapping(ctx.port_mapping, port);
	if (!entry)
		return false;

	memcpy(entry->pcp_nonce, nonce, sizeof(entry->pcp_nonce));
	entry->pcp_nonce_valid = true;
	return true;
}

/** Builds a PCP MAP request for one isolated test mapping entry */
bool fastd_port_mapping_test_pcp_build_request(
	uint16_t port, uint32_t lifetime, const fastd_peer_address_t *client_addr, uint8_t *buf, size_t *len) {
	if (!ctx.port_mapping)
		return false;

	fastd_port_mapping_entry_t *entry = find_mapping(ctx.port_mapping, port);
	if (!entry)
		return false;

	ensure_pcp_nonce(entry);
	return build_pcp_map_request(entry, lifetime, client_addr, buf, len);
}

/** Handles a PCP MAP response against the isolated test mapping state */
bool fastd_port_mapping_test_pcp_handle_response(const uint8_t *buf, size_t len) {
	return ctx.port_mapping && handle_pcp_response_packet(ctx.port_mapping, buf, len);
}

#else

bool fastd_port_mapping_test_pcp_set_nonce(UNUSED uint16_t port, UNUSED const uint8_t nonce[12]) {
	return false;
}

bool fastd_port_mapping_test_pcp_build_request(
	UNUSED uint16_t port, UNUSED uint32_t lifetime, UNUSED const fastd_peer_address_t *client_addr,
	UNUSED uint8_t *buf, UNUSED size_t *len) {
	return false;
}

bool fastd_port_mapping_test_pcp_handle_response(UNUSED const uint8_t *buf, UNUSED size_t len) {
	return false;
}

#endif

#endif
