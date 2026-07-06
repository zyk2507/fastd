// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   NAT behavior detection through STUN
*/

#include "nat_detect.h"
#include "peer.h"

#ifdef WITH_NAT_DETECT
#include <stun/stunagent.h>
#include <stun/usages/bind.h>
#endif

#include <netdb.h>
#include <unistd.h>


#define FASTD_NAT_INITIAL_DELAY 1000
#define FASTD_NAT_INTERVAL 60000
#define FASTD_NAT_STUN_TIMEOUT 1200
#define FASTD_NAT_STUN_BUFSIZE 512
#define FASTD_NAT_EXTRA_SAMPLES 4
#define FASTD_NAT_EASY_DELTA_LIMIT 64

#define FASTD_STUN_CHANGE_IP 0x04
#define FASTD_STUN_CHANGE_PORT 0x02


/** Global NAT detection state */
struct fastd_nat_detect {
	fastd_task_t task;         /**< Periodic detection task */
	pthread_mutex_t mutex;     /**< Protects worker and status fields */
	bool worker_running;       /**< true while a detection worker is active */
	bool stopping;             /**< true while cleanup is waiting for the worker */
	fastd_nat_status_t status; /**< Latest detection status */
};

#ifdef WITH_NAT_DETECT

/** Worker-owned STUN server snapshot */
typedef struct nat_server_snapshot {
	char *host;    /**< STUN server hostname or address */
	uint16_t port; /**< STUN server port */
} nat_server_snapshot_t;

/** Worker-owned NAT detection input */
typedef struct nat_worker {
	nat_server_snapshot_t *servers; /**< STUN servers to query */
	size_t n_servers;               /**< Number of STUN servers */
} nat_worker_t;

/** One successful STUN sample */
typedef struct nat_stun_sample {
	fastd_peer_address_t mapped; /**< Server-reflexive address reported by STUN */
} nat_stun_sample_t;

/** Result of a single STUN request */
typedef struct nat_stun_response {
	fastd_peer_address_t mapped; /**< Server-reflexive address reported by STUN */
	fastd_peer_address_t source; /**< Address that sent the STUN response */
} nat_stun_response_t;

#endif


/** Returns a human-readable NAT type name */
const char *fastd_nat_type_name(fastd_nat_type_t type) {
	switch (type) {
	case FASTD_NAT_UNKNOWN:
		return "unknown";

	case FASTD_NAT_OPEN_INTERNET:
		return "open-internet";

	case FASTD_NAT_NO_PAT:
		return "no-pat";

	case FASTD_NAT_FULL_CONE:
		return "full-cone";

	case FASTD_NAT_RESTRICTED:
		return "restricted";

	case FASTD_NAT_PORT_RESTRICTED:
		return "port-restricted";

	case FASTD_NAT_SYMMETRIC:
		return "symmetric";

	case FASTD_NAT_SYM_UDP_FIREWALL:
		return "symmetric-udp-firewall";

	case FASTD_NAT_SYMMETRIC_EASY_INC:
		return "symmetric-easy-inc";

	case FASTD_NAT_SYMMETRIC_EASY_DEC:
		return "symmetric-easy-dec";
	}

	return "unknown";
}

/** Adds one global STUN server to the configuration */
void fastd_nat_add_stun_server(const char *host, uint16_t port) {
	if (!host || !host[0] || !port)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(conf.stun_servers); i++) {
		const fastd_stun_server_t *server = &VECTOR_INDEX(conf.stun_servers, i);
		if (server->port == port && strequal(server->host, host))
			return;
	}

	VECTOR_ADD(
		conf.stun_servers, ((fastd_stun_server_t){
					   .host = fastd_strdup(host),
					   .port = port,
				   }));
}

/** Checks whether NAT detection can run with the current build */
bool fastd_nat_check(void) {
#ifndef WITH_NAT_DETECT
	if (VECTOR_LEN(conf.stun_servers)) {
		pr_error("global STUN server configured, but NAT detection is not supported by this build of fastd");
		return false;
	}
#endif

	return true;
}

#ifdef WITH_NAT_DETECT

/** Returns the sockaddr length for a peer address */
static socklen_t address_len(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);

	default:
		return 0;
	}
}

/** Converts a sockaddr to a fastd peer address */
static bool peer_address_from_sockaddr(fastd_peer_address_t *out, const struct sockaddr *sa) {
	memset(out, 0, sizeof(*out));

	switch (sa->sa_family) {
	case AF_INET:
		memcpy(&out->in, sa, sizeof(out->in));
		fastd_peer_address_simplify(out);
		return true;

	case AF_INET6:
		memcpy(&out->in6, sa, sizeof(out->in6));
		fastd_peer_address_simplify(out);
		return true;

	default:
		return false;
	}
}

/** Returns true if two peer addresses have the same IP address */
static bool address_ip_equal(const fastd_peer_address_t *a, const fastd_peer_address_t *b) {
	if (a->sa.sa_family != b->sa.sa_family)
		return false;

	switch (a->sa.sa_family) {
	case AF_INET:
		return a->in.sin_addr.s_addr == b->in.sin_addr.s_addr;

	case AF_INET6:
		return IN6_ARE_ADDR_EQUAL(&a->in6.sin6_addr, &b->in6.sin6_addr);

	default:
		return false;
	}
}

/** Returns the peer address port in host byte order */
static uint16_t address_port_host(const fastd_peer_address_t *addr) {
	return ntohs(fastd_peer_address_get_port(addr));
}

/** Sets the peer address port from host byte order */
static void set_address_port_host(fastd_peer_address_t *addr, uint16_t port) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->in.sin_port = htons(port);
		return;

	case AF_INET6:
		addr->in6.sin6_port = htons(port);
		return;

	default:
		return;
	}
}

/** Adds a STUN server to a worker snapshot, avoiding exact duplicates */
static void worker_add_server(nat_worker_t *work, const char *host, uint16_t port) {
	if (!host || !host[0] || !port)
		return;

	size_t i;
	for (i = 0; i < work->n_servers; i++) {
		if (work->servers[i].port == port && strequal(work->servers[i].host, host))
			return;
	}

	work->servers = fastd_realloc_array(work->servers, work->n_servers + 1, sizeof(nat_server_snapshot_t));
	work->servers[work->n_servers++] = (nat_server_snapshot_t){
		.host = fastd_strdup(host),
		.port = port,
	};
}

/** Creates a worker-owned snapshot of all configured STUN servers */
static nat_worker_t *create_worker(void) {
	nat_worker_t *work = fastd_new0(nat_worker_t);

	size_t i;
	for (i = 0; i < VECTOR_LEN(conf.stun_servers); i++) {
		const fastd_stun_server_t *server = &VECTOR_INDEX(conf.stun_servers, i);
		worker_add_server(work, server->host, server->port);
	}

	if (conf.realm.stun_host && conf.realm.stun_port)
		worker_add_server(work, conf.realm.stun_host, conf.realm.stun_port);

	return work;
}

/** Frees a worker snapshot */
static void free_worker(nat_worker_t *work) {
	if (!work)
		return;

	size_t i;
	for (i = 0; i < work->n_servers; i++)
		free(work->servers[i].host);

	free(work->servers);
	free(work);
}

/** Resolves a STUN server, preferring IPv4 for NAT4 diagnostics */
static bool resolve_server(fastd_peer_address_t *out, const nat_server_snapshot_t *server) {
	char port[16];
	snprintf(port, sizeof(port), "%u", server->port);

	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
#ifdef HAVE_AI_ADDRCONFIG
		.ai_flags = AI_ADDRCONFIG,
#endif
	};

	struct addrinfo *res = NULL;
	int ret = getaddrinfo(server->host, port, &hints, &res);
	if (ret) {
		pr_debug("unable to resolve STUN server `%s': %s", server->host, gai_strerror(ret));
		return false;
	}

	bool ok = false;
	const struct addrinfo *fallback = NULL;
	const struct addrinfo *ai;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;

		if (!fallback)
			fallback = ai;
		if (ai->ai_family == AF_INET) {
			fallback = ai;
			break;
		}
	}

	if (fallback)
		ok = peer_address_from_sockaddr(out, fallback->ai_addr);

	freeaddrinfo(res);
	return ok;
}

/** Opens a UDP socket bound to an ephemeral local port */
static int open_stun_socket(sa_family_t family) {
	int type = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
	type |= SOCK_CLOEXEC;
#endif

	int fd = socket(family == AF_INET6 ? PF_INET6 : PF_INET, type, IPPROTO_UDP);
	if (fd < 0) {
		pr_debug_errno("unable to create NAT detection socket");
		return -1;
	}

#ifndef SOCK_CLOEXEC
	if (fcntl(fd, F_SETFD, FD_CLOEXEC))
		pr_debug_errno("fcntl: unable to set FD_CLOEXEC on NAT detection socket");
#endif

	if (family == AF_INET6) {
		const int one = 1;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) {
			pr_debug_errno("setsockopt: unable to set IPV6_V6ONLY on NAT detection socket");
			goto error;
		}
	}

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_debug_errno("setsockopt: unable to set packet mark on NAT detection socket");
			goto error;
		}
	}
#endif

	fastd_peer_address_t bind_addr = {};
	if (family == AF_INET6)
		bind_addr.in6.sin6_family = AF_INET6;
	else
		bind_addr.in.sin_family = AF_INET;

	if (bind(fd, &bind_addr.sa, address_len(&bind_addr))) {
		pr_debug_errno("unable to bind NAT detection socket");
		goto error;
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting NAT detection socket");
		goto error;
	}
#endif

	return fd;

error:
	if (close(fd))
		pr_error_errno("close");
	return -1;
}

/** Determines the local address that would be used to reach a STUN server */
static bool get_route_local_address(fastd_peer_address_t *local, const fastd_peer_address_t *server, uint16_t port) {
	int fd = open_stun_socket(server->sa.sa_family);
	if (fd < 0)
		return false;

	bool ok = false;
	if (!connect(fd, &server->sa, address_len(server))) {
		fastd_peer_address_t addr = {};
		socklen_t len = sizeof(addr);
		if (!getsockname(fd, &addr.sa, &len) && peer_address_from_sockaddr(local, &addr.sa)) {
			set_address_port_host(local, port);
			ok = true;
		}
	}

	if (close(fd))
		pr_error_errno("close");

	return ok;
}

/** Builds a STUN binding request, optionally with RFC3489/RFC5780 CHANGE-REQUEST bits */
static bool build_stun_request(
	StunAgent *agent, StunMessage *request, uint8_t *buf, size_t *len, StunTransactionId id,
	uint32_t change_request) {
	stun_agent_init(
		agent, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_IGNORE_CREDENTIALS);

	if (!stun_agent_init_request(agent, request, buf, FASTD_NAT_STUN_BUFSIZE, STUN_BINDING))
		return false;

	stun_message_id(request, id);

	if (change_request && stun_message_append32(request, STUN_ATTRIBUTE_CHANGE_REQUEST, change_request) !=
				      STUN_MESSAGE_RETURN_SUCCESS)
		return false;

	*len = stun_agent_finish_message(agent, request, NULL, 0);
	if (!*len)
		return false;

	return true;
}

/** Performs one synchronous STUN binding request on an existing UDP socket */
static bool
stun_request(int fd, const fastd_peer_address_t *server, uint32_t change_request, nat_stun_response_t *response) {
	uint8_t request_buf[FASTD_NAT_STUN_BUFSIZE];
	StunAgent agent;
	StunMessage request;
	StunTransactionId id;
	size_t request_len = 0;

	if (!build_stun_request(&agent, &request, request_buf, &request_len, id, change_request))
		return false;

	ssize_t sent = sendto(fd, request_buf, request_len, 0, &server->sa, address_len(server));
	if (sent < 0 || (size_t)sent != request_len) {
		if (sent < 0)
			pr_debug_errno("NAT detection STUN sendto");
		stun_agent_forget_transaction(&agent, id);
		return false;
	}

	int64_t deadline = fastd_get_time() + FASTD_NAT_STUN_TIMEOUT;

	while (true) {
		int64_t now = fastd_get_time();
		if (now >= deadline)
			break;

		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN,
		};

		int ret = poll(&pfd, 1, deadline - now);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			pr_debug_errno("NAT detection STUN poll");
			break;
		}

		if (!ret)
			break;

		if (!(pfd.revents & POLLIN))
			continue;

		uint8_t response_buf[FASTD_NAT_STUN_BUFSIZE];
		struct sockaddr_storage source = {};
		socklen_t source_len = sizeof(source);
		ssize_t len =
			recvfrom(fd, response_buf, sizeof(response_buf), 0, (struct sockaddr *)&source, &source_len);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			pr_debug_errno("NAT detection STUN recvfrom");
			break;
		}

		StunMessage msg;
		StunValidationStatus status = stun_agent_validate(&agent, &msg, response_buf, len, NULL, NULL);
		if (status == STUN_VALIDATION_NOT_STUN || status == STUN_VALIDATION_UNMATCHED_RESPONSE)
			continue;
		if (status != STUN_VALIDATION_SUCCESS)
			break;

		struct sockaddr_storage mapped = {};
		socklen_t mapped_len = sizeof(mapped);
		struct sockaddr_storage alternate = {};
		socklen_t alternate_len = sizeof(alternate);

		StunUsageBindReturn bind_ret = stun_usage_bind_process(
			&msg, (struct sockaddr *)&mapped, &mapped_len, (struct sockaddr *)&alternate, &alternate_len);
		if (bind_ret != STUN_USAGE_BIND_RETURN_SUCCESS)
			break;

		if (!peer_address_from_sockaddr(&response->mapped, (struct sockaddr *)&mapped))
			break;
		if (!peer_address_from_sockaddr(&response->source, (struct sockaddr *)&source))
			break;

		return true;
	}

	stun_agent_forget_transaction(&agent, id);
	return false;
}

/** Records a mapped address sample and updates the public port range */
static void add_sample(
	nat_stun_sample_t *samples, size_t *n_samples, const fastd_peer_address_t *mapped, uint16_t *min_port,
	uint16_t *max_port) {
	samples[(*n_samples)++].mapped = *mapped;

	uint16_t port = address_port_host(mapped);
	if (!*min_port || port < *min_port)
		*min_port = port;
	if (port > *max_port)
		*max_port = port;
}

/** Returns true if all base samples report the same mapped endpoint */
static bool samples_are_stable(const nat_stun_sample_t *samples, size_t n_samples) {
	if (n_samples < 2)
		return false;

	size_t i;
	for (i = 1; i < n_samples; i++) {
		if (!fastd_peer_address_equal(&samples[0].mapped, &samples[i].mapped))
			return false;
	}

	return true;
}

/** Determines whether symmetric mappings have a simple increasing or decreasing public port direction */
static int detect_port_delta(const nat_stun_sample_t *samples, size_t n_samples) {
	if (n_samples < 3)
		return 0;

	int direction = 0;
	int sum = 0;
	size_t n_deltas = 0;

	size_t i;
	for (i = 1; i < n_samples; i++) {
		int delta = (int)address_port_host(&samples[i].mapped) - (int)address_port_host(&samples[i - 1].mapped);
		if (!delta)
			continue;
		if (delta > FASTD_NAT_EASY_DELTA_LIMIT || delta < -FASTD_NAT_EASY_DELTA_LIMIT)
			return 0;

		int this_direction = delta > 0 ? 1 : -1;
		if (direction && direction != this_direction)
			return 0;

		direction = this_direction;
		sum += delta;
		n_deltas++;
	}

	if (n_deltas < 2)
		return 0;

	return sum / (int)n_deltas;
}

/** Classifies the NAT type from collected STUN samples */
static fastd_nat_type_t classify_nat(
	const nat_stun_sample_t *base_samples, size_t n_base_samples, const nat_stun_sample_t *all_samples,
	size_t n_all_samples, const fastd_peer_address_t *local, bool have_local, bool change_ip_port, bool change_port,
	int *port_delta) {
	if (!n_base_samples)
		return FASTD_NAT_UNKNOWN;

	bool stable = samples_are_stable(base_samples, n_base_samples);
	if (!stable && n_base_samples >= 2) {
		*port_delta = detect_port_delta(all_samples, n_all_samples);
		if (*port_delta > 0)
			return FASTD_NAT_SYMMETRIC_EASY_INC;
		if (*port_delta < 0)
			return FASTD_NAT_SYMMETRIC_EASY_DEC;
		return FASTD_NAT_SYMMETRIC;
	}

	const fastd_peer_address_t *mapped = &base_samples[0].mapped;

	if (have_local && fastd_peer_address_equal(mapped, local))
		return change_ip_port ? FASTD_NAT_OPEN_INTERNET : FASTD_NAT_SYM_UDP_FIREWALL;

	if (have_local && address_ip_equal(mapped, local) && address_port_host(mapped) == address_port_host(local))
		return change_ip_port ? FASTD_NAT_OPEN_INTERNET : FASTD_NAT_SYM_UDP_FIREWALL;

	if (have_local && address_port_host(mapped) == address_port_host(local))
		return FASTD_NAT_NO_PAT;

	if (change_ip_port)
		return FASTD_NAT_FULL_CONE;

	if (change_port)
		return FASTD_NAT_RESTRICTED;

	if (n_base_samples >= 2)
		return FASTD_NAT_PORT_RESTRICTED;

	return FASTD_NAT_UNKNOWN;
}

#ifdef WITH_TESTS

/** Converts address samples to the worker-internal representation used by NAT classification */
static nat_stun_sample_t *samples_from_addresses(const fastd_peer_address_t *addresses, size_t n_addresses) {
	if (!n_addresses)
		return NULL;

	nat_stun_sample_t *samples = fastd_new0_array(n_addresses, nat_stun_sample_t);

	size_t i;
	for (i = 0; i < n_addresses; i++)
		samples[i].mapped = addresses[i];

	return samples;
}

/** Test wrapper for the easy-symmetric public port delta detector */
int fastd_nat_test_detect_port_delta(const fastd_peer_address_t *samples, size_t n_samples) {
	nat_stun_sample_t *test_samples = samples_from_addresses(samples, n_samples);
	int ret = detect_port_delta(test_samples, n_samples);
	free(test_samples);
	return ret;
}

/** Test wrapper for NAT classification without performing network I/O */
fastd_nat_type_t fastd_nat_test_classify(
	const fastd_peer_address_t *base_samples, size_t n_base_samples, const fastd_peer_address_t *all_samples,
	size_t n_all_samples, const fastd_peer_address_t *local, bool have_local, bool change_ip_port, bool change_port,
	int *port_delta) {
	nat_stun_sample_t *base = samples_from_addresses(base_samples, n_base_samples);
	nat_stun_sample_t *all = samples_from_addresses(all_samples, n_all_samples);
	fastd_peer_address_t empty_local = {};
	int local_delta = 0;
	int *delta = port_delta ? port_delta : &local_delta;

	fastd_nat_type_t ret = classify_nat(
		base, n_base_samples, all, n_all_samples, local ? local : &empty_local, have_local, change_ip_port,
		change_port, delta);

	free(all);
	free(base);
	return ret;
}

#endif

/** Runs one NAT detection pass */
static fastd_nat_status_t detect_nat(const nat_worker_t *work) {
	fastd_nat_status_t status = {
		.enabled = true,
		.type = FASTD_NAT_UNKNOWN,
		.servers = work->n_servers,
		.last_update = fastd_get_time(),
	};

	if (!work->n_servers)
		return status;

	fastd_peer_address_t *servers = fastd_new0_array(work->n_servers, fastd_peer_address_t);
	size_t n_servers = 0;

	size_t i;
	for (i = 0; i < work->n_servers; i++) {
		fastd_peer_address_t resolved;
		if (!resolve_server(&resolved, &work->servers[i]))
			continue;

		if (n_servers && resolved.sa.sa_family != servers[0].sa.sa_family)
			continue;

		servers[n_servers++] = resolved;
	}

	if (!n_servers) {
		free(servers);
		return status;
	}

	int fd = open_stun_socket(servers[0].sa.sa_family);
	if (fd < 0) {
		free(servers);
		return status;
	}

	struct sockaddr_storage bound = {};
	socklen_t bound_len = sizeof(bound);
	uint16_t local_port = 0;
	fastd_peer_address_t bound_addr = {};
	if (!getsockname(fd, (struct sockaddr *)&bound, &bound_len) &&
	    peer_address_from_sockaddr(&bound_addr, (struct sockaddr *)&bound))
		local_port = address_port_host(&bound_addr);

	fastd_peer_address_t local = {};
	bool have_local = local_port && get_route_local_address(&local, &servers[0], local_port);

	nat_stun_sample_t *base_samples = fastd_new0_array(n_servers, nat_stun_sample_t);
	nat_stun_sample_t *all_samples = fastd_new0_array(n_servers + FASTD_NAT_EXTRA_SAMPLES, nat_stun_sample_t);
	size_t n_base_samples = 0, n_all_samples = 0;
	uint16_t min_port = 0, max_port = 0;

	for (i = 0; i < n_servers; i++) {
		nat_stun_response_t response = {};
		if (!stun_request(fd, &servers[i], 0, &response))
			continue;

		add_sample(base_samples, &n_base_samples, &response.mapped, &min_port, &max_port);
		add_sample(all_samples, &n_all_samples, &response.mapped, &min_port, &max_port);
	}

	bool change_ip_port = false;
	bool change_port = false;

	if (n_base_samples) {
		nat_stun_response_t response = {};
		change_ip_port =
			stun_request(fd, &servers[0], FASTD_STUN_CHANGE_IP | FASTD_STUN_CHANGE_PORT, &response);
		change_port = stun_request(fd, &servers[0], FASTD_STUN_CHANGE_PORT, &response);
	}

	if (n_base_samples >= 2 && !samples_are_stable(base_samples, n_base_samples)) {
		for (i = 0; i < FASTD_NAT_EXTRA_SAMPLES; i++) {
			int sample_fd = open_stun_socket(servers[0].sa.sa_family);
			if (sample_fd < 0)
				continue;

			nat_stun_response_t response = {};
			if (stun_request(sample_fd, &servers[0], 0, &response))
				add_sample(all_samples, &n_all_samples, &response.mapped, &min_port, &max_port);

			if (close(sample_fd))
				pr_error_errno("close");
		}
	}

	if (close(fd))
		pr_error_errno("close");

	if (n_base_samples) {
		status.available = true;
		status.reflexive = base_samples[0].mapped;
		status.min_port = min_port;
		status.max_port = max_port;
		status.responses = n_all_samples;
		status.type = classify_nat(
			base_samples, n_base_samples, all_samples, n_all_samples, &local, have_local, change_ip_port,
			change_port, &status.port_delta);

		pr_verbose(
			"NAT detection: %s, public endpoint %I", fastd_nat_type_name(status.type), &status.reflexive);
	} else {
		pr_debug("NAT detection did not receive a STUN response");
	}

	free(all_samples);
	free(base_samples);
	free(servers);

	return status;
}

/** Publishes a worker result into the global state */
static void publish_result(const fastd_nat_status_t *status) {
	if (!ctx.nat_detect)
		return;

	pthread_mutex_lock(&ctx.nat_detect->mutex);
	if (!ctx.nat_detect->stopping)
		ctx.nat_detect->status = *status;
	ctx.nat_detect->worker_running = false;
	pthread_mutex_unlock(&ctx.nat_detect->mutex);
}

/** NAT detection worker entry point */
static void *nat_worker_thread(void *arg) {
	nat_worker_t *work = arg;
	fastd_nat_status_t status = detect_nat(work);
	publish_result(&status);
	free_worker(work);
	return NULL;
}

/** Starts a new detection worker if none is active */
static void start_worker(void) {
	nat_worker_t *work = create_worker();
	if (!work->n_servers) {
		free_worker(work);
		return;
	}

	pthread_mutex_lock(&ctx.nat_detect->mutex);
	if (ctx.nat_detect->worker_running || ctx.nat_detect->stopping) {
		pthread_mutex_unlock(&ctx.nat_detect->mutex);
		free_worker(work);
		return;
	}

	ctx.nat_detect->worker_running = true;
	pthread_mutex_unlock(&ctx.nat_detect->mutex);

	pthread_t thread;
	if (pthread_create(&thread, &ctx.detached_thread, nat_worker_thread, work)) {
		pr_error_errno("unable to create NAT detection worker");

		pthread_mutex_lock(&ctx.nat_detect->mutex);
		ctx.nat_detect->worker_running = false;
		pthread_mutex_unlock(&ctx.nat_detect->mutex);

		free_worker(work);
	}
}

#endif

/** Starts NAT detection */
void fastd_nat_init(void) {
#ifdef WITH_NAT_DETECT
	nat_worker_t *work = create_worker();
	bool enabled = work->n_servers;
	free_worker(work);

	if (!enabled)
		return;

	ctx.nat_detect = fastd_new0(fastd_nat_detect_t);
	if (pthread_mutex_init(&ctx.nat_detect->mutex, NULL))
		exit_errno("pthread_mutex_init");

	ctx.nat_detect->status = (fastd_nat_status_t){
		.enabled = true,
		.type = FASTD_NAT_UNKNOWN,
	};

	fastd_task_schedule(&ctx.nat_detect->task, TASK_TYPE_NAT_DETECT, ctx.now + FASTD_NAT_INITIAL_DELAY);
#endif
}

/** Runs periodic NAT detection maintenance */
void fastd_nat_handle_task(void) {
#ifdef WITH_NAT_DETECT
	if (!ctx.nat_detect)
		return;

	start_worker();
	fastd_task_schedule(&ctx.nat_detect->task, TASK_TYPE_NAT_DETECT, ctx.now + FASTD_NAT_INTERVAL);
#endif
}

/** Stops NAT detection */
void fastd_nat_cleanup(void) {
	if (!ctx.nat_detect)
		return;

	fastd_task_unschedule(&ctx.nat_detect->task);

#ifdef WITH_NAT_DETECT
	pthread_mutex_lock(&ctx.nat_detect->mutex);
	ctx.nat_detect->stopping = true;
	while (ctx.nat_detect->worker_running) {
		pthread_mutex_unlock(&ctx.nat_detect->mutex);
		usleep(10000);
		pthread_mutex_lock(&ctx.nat_detect->mutex);
	}
	pthread_mutex_unlock(&ctx.nat_detect->mutex);
	pthread_mutex_destroy(&ctx.nat_detect->mutex);
#endif

	free(ctx.nat_detect);
	ctx.nat_detect = NULL;
}

/** Returns a copy of the current NAT status */
bool fastd_nat_get_status(fastd_nat_status_t *status) {
	if (!ctx.nat_detect)
		return false;

#ifdef WITH_NAT_DETECT
	pthread_mutex_lock(&ctx.nat_detect->mutex);
	*status = ctx.nat_detect->status;
	pthread_mutex_unlock(&ctx.nat_detect->mutex);
#else
	*status = ctx.nat_detect->status;
#endif

	return status->enabled;
}

/** Returns the latest public endpoint, if available */
bool fastd_nat_get_public_address(fastd_peer_address_t *addr) {
	fastd_nat_status_t status;
	if (!fastd_nat_get_status(&status) || !status.available)
		return false;

	if (status.reflexive.sa.sa_family != AF_INET && status.reflexive.sa.sa_family != AF_INET6)
		return false;

	*addr = status.reflexive;
	return true;
}
