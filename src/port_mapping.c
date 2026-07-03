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


#ifdef WITH_NATPMP

#include <natpmp.h>


#define FASTD_NATPMP_RETRY_INTERVAL 300000


/** A single UDP port that should be mapped */
typedef struct fastd_natpmp_mapping {
	uint16_t port;        /**< The local UDP port in host byte order */
	uint16_t public_port; /**< The mapped public UDP port in host byte order */
	uint32_t lifetime;    /**< The current mapping lifetime in seconds */
	bool mapped;          /**< Specifies if the last mapping request was successful */
} fastd_natpmp_mapping_t;

/** Global NAT-PMP state */
struct fastd_port_mapping {
	natpmp_t natpmp;      /**< libnatpmp context */
	fastd_poll_fd_t fd;   /**< The NAT-PMP control socket */
	fastd_task_t task;    /**< Retry or renewal task */
	bool initialized;     /**< Specifies if natpmp has been initialized */
	bool request_pending; /**< Specifies if a NAT-PMP request is in flight */
	size_t current;       /**< The mapping currently being requested */

	VECTOR(fastd_natpmp_mapping_t) mappings; /**< Configured UDP port mappings */
};

/** Schedules the NAT-PMP task, replacing an existing timeout if necessary */
static void schedule_task(fastd_port_mapping_t *mapping, fastd_timeout_t timeout) {
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
		schedule_task(mapping, ctx.now + FASTD_NATPMP_RETRY_INTERVAL);
		return;
	}

	int64_t delay = timeout.tv_sec * 1000 + (timeout.tv_usec + 999) / 1000;
	schedule_task(mapping, ctx.now + delay);
}

/** Schedules a retry after a failed NAT-PMP mapping attempt */
static void schedule_retry(fastd_port_mapping_t *mapping) {
	mapping->request_pending = false;
	mapping->current = 0;
	schedule_task(mapping, ctx.now + FASTD_NATPMP_RETRY_INTERVAL);
}

/** Returns the delay after which the active mappings should be renewed */
static int64_t renewal_delay(const fastd_port_mapping_t *mapping) {
	uint32_t lifetime = FASTD_NATPMP_LIFETIME;

	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		const fastd_natpmp_mapping_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (entry->mapped && entry->lifetime && entry->lifetime < lifetime)
			lifetime = entry->lifetime;
	}

	int64_t delay = (int64_t)lifetime * 1000 / 2;
	return delay > 1000 ? delay : 1000;
}

/** Returns true if the port is already in the mapping list */
static bool has_mapping(const fastd_port_mapping_t *mapping, uint16_t port) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		if (VECTOR_INDEX(mapping->mappings, i).port == port)
			return true;
	}

	return false;
}

/** Adds an IPv4-compatible socket's bound UDP port to the NAT-PMP mapping list */
static void add_socket_mapping(fastd_port_mapping_t *mapping, const fastd_socket_t *sock) {
	if (!sock->addr || !sock->bound_addr)
		return;

	if (sock->bound_addr->sa.sa_family == AF_INET6 && sock->addr->addr.sa.sa_family != AF_UNSPEC)
		return;

	if (sock->bound_addr->sa.sa_family != AF_INET && sock->bound_addr->sa.sa_family != AF_INET6)
		return;

	uint16_t port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
	if (!port || has_mapping(mapping, port))
		return;

	VECTOR_ADD(mapping->mappings, ((fastd_natpmp_mapping_t){ .port = port }));
}

/** Starts a NAT-PMP mapping request for a given mapping index */
static void request_mapping(fastd_port_mapping_t *mapping, size_t i) {
	if (i >= VECTOR_LEN(mapping->mappings)) {
		mapping->request_pending = false;
		mapping->current = 0;
		schedule_task(mapping, ctx.now + renewal_delay(mapping));
		return;
	}

	mapping->current = i;
	fastd_natpmp_mapping_t *entry = &VECTOR_INDEX(mapping->mappings, i);
	uint16_t public_port = entry->public_port ? entry->public_port : entry->port;

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
	fastd_natpmp_mapping_t *entry = &VECTOR_INDEX(mapping->mappings, mapping->current);

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

	entry->mapped = true;
	entry->public_port = public_port;
	entry->lifetime = lifetime;

	if (entry->public_port == entry->port) {
		pr_verbose("mapped UDP port %u using NAT-PMP", entry->port);
	} else {
		pr_warn("NAT-PMP mapped local UDP port %u to different public port %u", entry->port,
			entry->public_port);
	}

	request_mapping(mapping, mapping->current + 1);
}

/** Handles a pending NAT-PMP request */
static void handle_pending_request(fastd_port_mapping_t *mapping) {
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

/** Sends best-effort deletion requests for active mappings */
static void release_mappings(fastd_port_mapping_t *mapping) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(mapping->mappings); i++) {
		fastd_natpmp_mapping_t *entry = &VECTOR_INDEX(mapping->mappings, i);
		if (!entry->mapped)
			continue;

		natpmp_t natpmp;
		if (initnatpmp(&natpmp, 0, 0) < 0)
			continue;

		sendnewportmappingrequest(&natpmp, NATPMP_PROTOCOL_UDP, entry->port, entry->public_port, 0);
		closenatpmp(&natpmp);
	}
}

/** Checks if the configured automatic port mapping support is available */
bool fastd_port_mapping_check(void) {
	return true;
}

/** Initializes automatic NAT-PMP port mapping */
void fastd_port_mapping_init(void) {
	if (!fastd_use_natpmp())
		return;

	fastd_port_mapping_t *mapping = fastd_new0(fastd_port_mapping_t);
	ctx.port_mapping = mapping;

	size_t i;
	for (i = 0; i < ctx.n_socks; i++)
		add_socket_mapping(mapping, &ctx.socks[i]);

	if (!VECTOR_LEN(mapping->mappings)) {
		pr_warn("NAT-PMP is enabled, but no fixed IPv4 bind sockets can be mapped");
		return;
	}

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

/** Handles input on the NAT-PMP control socket */
void fastd_port_mapping_handle(void) {
	if (ctx.port_mapping)
		handle_pending_request(ctx.port_mapping);
}

/** Handles NAT-PMP retry or renewal tasks */
void fastd_port_mapping_handle_task(void) {
	if (ctx.port_mapping)
		handle_pending_request(ctx.port_mapping);
}

/** Frees resources used by automatic NAT-PMP port mapping */
void fastd_port_mapping_cleanup(void) {
	fastd_port_mapping_t *mapping = ctx.port_mapping;
	if (!mapping)
		return;

	if (fastd_task_scheduled(&mapping->task))
		fastd_task_unschedule(&mapping->task);

	release_mappings(mapping);

	if (mapping->initialized) {
		fastd_poll_fd_close(&mapping->fd);
		mapping->initialized = false;
	}

	VECTOR_FREE(mapping->mappings);
	free(mapping);
	ctx.port_mapping = NULL;
}

#else

/** Checks if the configured automatic port mapping support is available */
bool fastd_port_mapping_check(void) {
	if (!conf.natpmp)
		return true;

	pr_error("config error: NAT-PMP port mapping is not supported by this build of fastd");
	return false;
}

void fastd_port_mapping_init(void) {}
void fastd_port_mapping_handle(void) {}
void fastd_port_mapping_handle_task(void) {}
void fastd_port_mapping_cleanup(void) {}

#endif
