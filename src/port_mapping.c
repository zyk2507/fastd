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
#include "peer.h"

#include <arpa/inet.h>


#ifdef WITH_NATPMP
#include <natpmp.h>
#endif

#ifdef WITH_UPNP_IGD
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnpdev.h>
#include <miniupnpc/upnperrors.h>
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


/** A single UDP port that should be mapped */
typedef struct fastd_port_mapping_entry {
	uint16_t port;     /**< The local UDP port in host byte order */
	bool use_natpmp;   /**< Specifies if this port should be mapped using NAT-PMP */
	bool use_upnp_igd; /**< Specifies if this port should be mapped using UPnP IGD */

#ifdef WITH_NATPMP
	uint16_t natpmp_public_port; /**< The NAT-PMP mapped public UDP port in host byte order */
	uint32_t natpmp_lifetime;    /**< The current NAT-PMP mapping lifetime in seconds */
	bool natpmp_mapped;          /**< Specifies if the last NAT-PMP mapping request was successful */
#endif

#ifdef WITH_UPNP_IGD
	uint16_t upnp_public_port; /**< The UPnP IGD mapped public UDP port in host byte order */
	bool upnp_mapped;          /**< Specifies if the UPnP IGD mapping request was successful */
#endif
} fastd_port_mapping_entry_t;

/** Global automatic port mapping state */
struct fastd_port_mapping {
	bool natpmp_requested;   /**< Specifies if NAT-PMP is requested by peer configuration */
	bool upnp_igd_requested; /**< Specifies if UPnP IGD is requested by peer configuration */
	bool use_natpmp;         /**< Specifies if NAT-PMP should be used for at least one port */
	bool use_upnp_igd;       /**< Specifies if UPnP IGD should be used for at least one port */

#ifdef WITH_NATPMP
	natpmp_t natpmp;      /**< libnatpmp context */
	fastd_poll_fd_t fd;   /**< The NAT-PMP control socket */
	fastd_task_t task;    /**< NAT-PMP retry or renewal task */
	bool initialized;     /**< Specifies if natpmp has been initialized */
	bool request_pending; /**< Specifies if a NAT-PMP request is in flight */
	size_t current;       /**< The mapping currently being requested */
#endif

#ifdef WITH_UPNP_IGD
	struct UPNPUrls upnp_urls;               /**< UPnP IGD control URLs */
	struct IGDdatas upnp_data;               /**< UPnP IGD service metadata */
	fastd_peer_address_t upnp_external_addr; /**< External address reported by the UPnP IGD */
	bool upnp_initialized;                   /**< Specifies if upnp_urls has been initialized */
#endif

	VECTOR(fastd_port_mapping_entry_t) mappings; /**< Configured UDP port mappings */
};


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

/** Returns true if a socket can be mapped through IPv4 gateway protocols */
static bool socket_is_mappable(const fastd_socket_t *sock) {
	if (!sock->addr || !sock->bound_addr)
		return false;

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
static void socket_enabled_backends(const fastd_socket_t *sock, bool *use_natpmp, bool *use_upnp_igd) {
	if (fastd_allow_verify()) {
		fastd_port_mapping_mode_t mode = fastd_peer_get_port_mapping_mode(NULL);
		*use_natpmp |= fastd_port_mapping_uses_natpmp(mode);
		*use_upnp_igd |= fastd_port_mapping_uses_upnp_igd(mode);
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
		}
	}
}

/** Adds an IPv4-compatible socket's bound UDP port to the mapping list */
static void
add_socket_mapping(fastd_port_mapping_t *mapping, const fastd_socket_t *sock, bool use_natpmp, bool use_upnp_igd) {
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

	entry->use_natpmp |= use_natpmp;
	entry->use_upnp_igd |= use_upnp_igd;
	mapping->use_natpmp |= use_natpmp;
	mapping->use_upnp_igd |= use_upnp_igd;
}

/** Collects mappable UDP ports from fixed sockets enabled by peer configuration */
static void collect_socket_mappings(fastd_port_mapping_t *mapping) {
	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		const fastd_socket_t *sock = &ctx.socks[i];

		if (!socket_is_mappable(sock))
			continue;

		bool use_natpmp = false, use_upnp_igd = false;
		socket_enabled_backends(sock, &use_natpmp, &use_upnp_igd);
		if (!use_natpmp && !use_upnp_igd)
			continue;

		add_socket_mapping(mapping, sock, use_natpmp, use_upnp_igd);
	}
}

/** Determines which port mapping backends are requested by peer configuration */
static void collect_enabled_backends(fastd_port_mapping_t *mapping) {
	fastd_port_mapping_mode_t default_mode = fastd_peer_get_port_mapping_mode(NULL);
	if (fastd_allow_verify() && default_mode != PORT_MAPPING_OFF) {
		mapping->natpmp_requested |= fastd_port_mapping_uses_natpmp(default_mode);
		mapping->upnp_igd_requested |= fastd_port_mapping_uses_upnp_igd(default_mode);
	}

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		const fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_is_enabled(peer))
			continue;

		fastd_port_mapping_mode_t mode = fastd_peer_get_port_mapping_mode(peer);
		mapping->natpmp_requested |= fastd_port_mapping_uses_natpmp(mode);
		mapping->upnp_igd_requested |= fastd_port_mapping_uses_upnp_igd(mode);
	}
}


#ifdef WITH_NATPMP

/** Schedules the NAT-PMP task, replacing an existing timeout if necessary */
static void schedule_natpmp_task(fastd_port_mapping_t *mapping, fastd_timeout_t timeout) {
	if (fastd_task_scheduled(&mapping->task))
		fastd_task_unschedule(&mapping->task);

	fastd_task_schedule(&mapping->task, TASK_TYPE_NATPMP, timeout);
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
		if (!entry->use_natpmp || !entry->natpmp_mapped)
			continue;

		natpmp_t natpmp;
		if (initnatpmp(&natpmp, 0, 0) < 0)
			continue;

		sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, entry->port, entry->natpmp_public_port, 0);
		closenatpmp(&natpmp);
	}
}

/** Frees NAT-PMP state */
static void cleanup_natpmp(fastd_port_mapping_t *mapping) {
	if (fastd_task_scheduled(&mapping->task))
		fastd_task_unschedule(&mapping->task);

	release_natpmp_mappings(mapping);

	if (mapping->initialized) {
		fastd_poll_fd_close(&mapping->fd);
		mapping->initialized = false;
	}
}

#endif


#ifdef WITH_UPNP_IGD

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

/** Returns a human-readable string for a miniupnpc return code */
static const char *upnp_error(int ret) {
	const char *error = strupnperror(ret);
	return error ? error : "unknown error";
}

/** Formats a UDP port for miniupnpc calls */
static void format_port(char buf[static 6], uint16_t port) {
	snprintf(buf, 6, "%u", port);
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
	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (!entry->use_upnp_igd)
			continue;

		char port[6];
		format_port(port, entry->port);

		int ret = UPNP_AddPortMapping(
			mapping->upnp_urls.controlURL, mapping->upnp_data.first.servicetype, port, port, lanaddr,
			"fastd", "UDP", NULL, "0");
		if (ret != UPNPCOMMAND_SUCCESS) {
			pr_warn("unable to add UPnP IGD mapping for UDP port %u: %s", entry->port, upnp_error(ret));
			continue;
		}

		entry->upnp_mapped = true;
		entry->upnp_public_port = entry->port;
		pr_verbose("mapped UDP port %u using UPnP IGD", entry->port);
	}
}

/** Initializes automatic UPnP IGD port mapping */
static void init_upnp_igd(fastd_port_mapping_t *mapping) {
	int discover_error = 0;
	struct UPNPDev *devlist =
		upnpDiscover(FASTD_UPNP_DISCOVER_DELAY, NULL, NULL, UPNP_LOCAL_PORT_ANY, 0, 2, &discover_error);
	if (!devlist) {
		pr_warn("unable to discover UPnP IGD devices: error %d", discover_error);
		return;
	}

	char lanaddr[64] = {};
	char wanaddr[64] = {};
	int ret = UPNP_GetValidIGD(
		devlist, &mapping->upnp_urls, &mapping->upnp_data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
	freeUPNPDevlist(devlist);

	switch (ret) {
	case UPNP_CONNECTED_IGD:
		pr_verbose("found UPnP IGD with external address %s", wanaddr);
		set_upnp_external_address(mapping, wanaddr);
		break;

	case UPNP_PRIVATEIP_IGD:
		pr_warn("found UPnP IGD, but its external address is private");
		break;

	case UPNP_DISCONNECTED_IGD:
		pr_warn("found UPnP IGD, but it is not connected");
		break;

	case UPNP_NO_IGD:
		pr_warn("no valid UPnP IGD found");
		return;

	default:
		pr_warn("unable to use discovered UPnP device as IGD");
		FreeUPNPUrls(&mapping->upnp_urls);
		return;
	}

	mapping->upnp_initialized = true;
	add_upnp_mappings(mapping, lanaddr);
}

/** Sends best-effort deletion requests for active UPnP IGD mappings */
static void release_upnp_mappings(fastd_port_mapping_t *mapping) {
	if (!mapping->upnp_initialized)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_port_mapping_entry_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (!entry->use_upnp_igd || !entry->upnp_mapped)
			continue;

		char port[6];
		format_port(port, entry->upnp_public_port);

		int ret = UPNP_DeletePortMapping(
			mapping->upnp_urls.controlURL, mapping->upnp_data.first.servicetype, port, "UDP", NULL);
		if (ret != UPNPCOMMAND_SUCCESS)
			pr_debug(
				"unable to delete UPnP IGD mapping for UDP port %u: %s", entry->upnp_public_port,
				upnp_error(ret));
	}
}

/** Frees UPnP IGD state */
static void cleanup_upnp_igd(fastd_port_mapping_t *mapping) {
	release_upnp_mappings(mapping);

	if (mapping->upnp_initialized) {
		FreeUPNPUrls(&mapping->upnp_urls);
		mapping->upnp_initialized = false;
	}
}

#endif


/** Checks if the configured automatic port mapping support is available */
bool fastd_port_mapping_check(void) {
	return true;
}

/** Initializes automatic port mapping */
void fastd_port_mapping_init(void) {
	fastd_port_mapping_t *mapping = fastd_new0(fastd_port_mapping_t);

	collect_enabled_backends(mapping);
	if (!mapping->natpmp_requested && !mapping->upnp_igd_requested) {
		free(mapping);
		return;
	}

	collect_socket_mappings(mapping);
	if (!mapping->use_natpmp && !mapping->use_upnp_igd) {
		pr_warn("automatic port mapping is enabled, but no enabled peer uses a fixed IPv4 bind socket");
		free(mapping);
		return;
	}

	ctx.port_mapping = mapping;

#ifdef WITH_NATPMP
	if (mapping->use_natpmp)
		init_natpmp(mapping);
#endif

#ifdef WITH_UPNP_IGD
	if (mapping->use_upnp_igd)
		init_upnp_igd(mapping);
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

/** Returns the external address for a mapped fixed UDP socket, if one is known */
bool fastd_port_mapping_get_external_address(const fastd_socket_t *sock, fastd_peer_address_t *addr) {
	if (!ctx.port_mapping || !socket_is_mappable(sock))
		return false;

	uint16_t local_port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
	fastd_port_mapping_entry_t *entry = find_mapping(ctx.port_mapping, local_port);
	if (!entry)
		return false;

	uint16_t public_port = 0;

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

	VECTOR_FREE(mapping->mappings);
	free(mapping);
	ctx.port_mapping = NULL;
}
