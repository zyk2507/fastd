// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Status socket support
*/


#include "types.h"


#ifdef WITH_STATUS_SOCKET

#include "method.h"
#include "offload/offload.h"
#include "peer.h"

#include <json-c/json.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>


/** Argument for dump_thread */
typedef struct dump_thread_arg {
	int fd;                   /**< The file descriptor of an accepted socket connection */
	struct json_object *json; /**< The JSON object to write to the status socket */
} dump_thread_arg_t;


/** Thread to write the status JSON to the status socket */
static void *dump_thread(void *p) {
	dump_thread_arg_t *arg = p;

	const char *str = json_object_to_json_string(arg->json);
	size_t left = strlen(str);

	while (left > 0) {
		ssize_t written = write(arg->fd, str, left);
		if (written < 0) {
			pr_error_errno("can't dump status: write");
			break;
		}

		left -= written;
		str += written;
	}

	close(arg->fd);
	json_object_put(arg->json);
	free(arg);

	return NULL;
}


/** Dumps a single traffic stat as a JSON object */
static json_object *dump_stat(const fastd_stats_t *stats, fastd_stat_type_t type) {
	struct json_object *ret = json_object_new_object();

	json_object_object_add(ret, "packets", json_object_new_int64(stats->packets[type]));
	json_object_object_add(ret, "bytes", json_object_new_int64(stats->bytes[type]));

	return ret;
}

/** Dumps a fastd_stats_t as a JSON object */
static json_object *dump_stats(const fastd_stats_t *stats) {
	struct json_object *statistics = json_object_new_object();

	json_object_object_add(statistics, "rx", dump_stat(stats, STAT_RX));
	json_object_object_add(statistics, "rx_reordered", dump_stat(stats, STAT_RX_REORDERED));

	json_object_object_add(statistics, "tx", dump_stat(stats, STAT_TX));
	json_object_object_add(statistics, "tx_dropped", dump_stat(stats, STAT_TX_DROPPED));
	json_object_object_add(statistics, "tx_error", dump_stat(stats, STAT_TX_ERROR));

	return statistics;
}

/** Reads all status data from a connected UNIX socket */
static char *read_status_json(const char *socket_path) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		exit_errno("status query: socket");

	struct sockaddr_un sa = {};
	size_t socket_path_len = strlen(socket_path);
	if (socket_path_len >= sizeof(sa.sun_path))
		exit_error("status query: socket path is too long");

	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, socket_path, socket_path_len + 1);

	if (connect(fd, (struct sockaddr *)&sa, offsetof(struct sockaddr_un, sun_path) + socket_path_len + 1))
		exit_errno("status query: connect");

	size_t len = 0, alloc = 4096;
	char *ret = fastd_alloc(alloc);

	while (true) {
		if (len + 4096 + 1 > alloc) {
			alloc *= 2;
			ret = fastd_realloc(ret, alloc);
		}

		ssize_t read_len = read(fd, ret + len, alloc - len - 1);
		if (read_len < 0)
			exit_errno("status query: read");

		if (read_len == 0)
			break;

		len += read_len;
	}

	if (close(fd))
		pr_warn_errno("status query: close");

	ret[len] = 0;
	return ret;
}

/** Returns an object member or NULL if it is missing or of the wrong type */
static json_object *get_object_member(json_object *object, const char *key) {
	json_object *ret;
	if (!object || !json_object_object_get_ex(object, key, &ret) || json_object_get_type(ret) != json_type_object)
		return NULL;

	return ret;
}

/** Returns an array member or NULL if it is missing or of the wrong type */
static json_object *get_array_member(json_object *object, const char *key) {
	json_object *ret;
	if (!object || !json_object_object_get_ex(object, key, &ret) || json_object_get_type(ret) != json_type_array)
		return NULL;

	return ret;
}

/** Returns a string member or NULL if it is missing or null */
static const char *get_string_member(json_object *object, const char *key) {
	json_object *ret;
	if (!object || !json_object_object_get_ex(object, key, &ret) || json_object_get_type(ret) == json_type_null)
		return NULL;

	return json_object_get_string(ret);
}

/** Returns an integer member or 0 if it is missing */
static int64_t get_int_member(json_object *object, const char *key) {
	json_object *ret;
	if (!object || !json_object_object_get_ex(object, key, &ret))
		return 0;

	return json_object_get_int64(ret);
}

/** Returns a boolean member or false if it is missing */
static bool get_bool_member(json_object *object, const char *key) {
	json_object *ret;
	if (!object || !json_object_object_get_ex(object, key, &ret) || json_object_get_type(ret) != json_type_boolean)
		return false;

	return json_object_get_boolean(ret);
}

/** Returns a counter from a statistics object */
static int64_t get_stat_counter(json_object *stats, const char *name, const char *counter) {
	return get_int_member(get_object_member(stats, name), counter);
}

/** Formats a millisecond duration */
static void format_duration(char buf[64], int64_t msec) {
	if (msec < 0)
		msec = 0;

	int64_t sec = msec / 1000;
	int64_t days = sec / 86400;
	sec %= 86400;
	int64_t hours = sec / 3600;
	sec %= 3600;
	int64_t minutes = sec / 60;
	sec %= 60;

	if (days)
		snprintf(buf, 64, "%lldd %02lld:%02lld:%02lld", (long long)days, (long long)hours,
			 (long long)minutes, (long long)sec);
	else if (hours)
		snprintf(buf, 64, "%lld:%02lld:%02lld", (long long)hours, (long long)minutes, (long long)sec);
	else
		snprintf(buf, 64, "%lld:%02lld", (long long)minutes, (long long)sec);
}

/** Formats a byte counter */
static void format_bytes(char buf[32], int64_t bytes) {
	static const char *const units[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double value = bytes;
	size_t unit = 0;

	while (value >= 1024 && unit < array_size(units) - 1) {
		value /= 1024;
		unit++;
	}

	if (unit == 0)
		snprintf(buf, 32, "%lld %s", (long long)bytes, units[unit]);
	else
		snprintf(buf, 32, "%.1f %s", value, units[unit]);
}

/** Prints a statistics line */
static void print_stat_line(const char *label, json_object *stats, const char *name) {
	char bytes[32];
	format_bytes(bytes, get_stat_counter(stats, name, "bytes"));

	printf("  %-12s %12s  %8lld packets\n", label, bytes, (long long)get_stat_counter(stats, name, "packets"));
}

/** Prints a compact traffic summary */
static void print_traffic_summary(json_object *stats) {
	print_stat_line("RX", stats, "rx");
	print_stat_line("TX", stats, "tx");
	print_stat_line("RX reorder", stats, "rx_reordered");
	print_stat_line("TX dropped", stats, "tx_dropped");
	print_stat_line("TX error", stats, "tx_error");
}

/** Prints a human-readable peer status */
static void print_peer_status(const char *key, json_object *peer) {
	const char *name = get_string_member(peer, "name");
	const char *address = get_string_member(peer, "address");
	json_object *connection = get_object_member(peer, "connection");
	bool established = connection != NULL;

	printf("  [%s] %s\n", established ? "up" : "down", name ? name : key);

	if (name)
		printf("       key:       %s\n", key);
	printf("       address:   %s\n", (address && *address) ? address : "-");

	const char *interface = get_string_member(peer, "interface");
	if (interface)
		printf("       interface: %s\n", interface);

	int64_t mtu = get_int_member(peer, "mtu");
	if (mtu)
		printf("       mtu:       %lld\n", (long long)mtu);

	if (!established) {
		putchar('\n');
		return;
	}

	char duration[64];
	format_duration(duration, get_int_member(connection, "established"));
	printf("       connected: %s\n", duration);

	json_object *tcp_punch = get_object_member(connection, "tcp_punch");
	bool tcp_punch_established = get_bool_member(tcp_punch, "established");

	const char *transport = get_string_member(connection, "transport");
	if (transport)
		printf("       transport: %s%s\n", transport, tcp_punch_established ? " (tcp-punch)" : "");

	const char *method = get_string_member(connection, "method");
	if (method)
		printf("       method:    %s\n", method);

	if (tcp_punch && (get_bool_member(tcp_punch, "enabled") || tcp_punch_established)) {
		printf("       tcp punch: %s", tcp_punch_established ? "established" : "enabled");

		int64_t local_port = get_int_member(tcp_punch, "local_port");
		int64_t remote_port = get_int_member(tcp_punch, "remote_port");
		if (tcp_punch_established && local_port && remote_port)
			printf(" (local %lld, remote %lld)", (long long)local_port, (long long)remote_port);

		putchar('\n');
	}

	json_object *stats = get_object_member(connection, "statistics");
	if (stats) {
		char rx[32], tx[32];
		format_bytes(rx, get_stat_counter(stats, "rx", "bytes"));
		format_bytes(tx, get_stat_counter(stats, "tx", "bytes"));
		printf("       traffic:   RX %s / TX %s\n", rx, tx);
	}

	json_object *macs = get_array_member(connection, "mac_addresses");
	if (macs && json_object_array_length(macs)) {
		printf("       macs:      ");

		size_t i;
		for (i = 0; i < json_object_array_length(macs); i++) {
			if (i)
				printf(", ");
			printf("%s", json_object_get_string(json_object_array_get_idx(macs, i)));
		}

		putchar('\n');
	}

	putchar('\n');
}

/** Prints a human-readable status dump */
static void print_status_human(json_object *json) {
	char duration[64];
	format_duration(duration, get_int_member(json, "uptime"));

	json_object *peers = get_object_member(json, "peers");
	size_t peer_count = 0, established_count = 0;

	if (peers) {
		json_object_object_foreach(peers, key, peer) {
			(void)key;
			peer_count++;
			if (get_object_member(peer, "connection"))
				established_count++;
		}
	}

	printf("fastd status\n");
	printf("============\n\n");
	printf("Uptime:    %s\n", duration);

	const char *interface = get_string_member(json, "interface");
	if (interface)
		printf("Interface: %s\n", interface);

	printf("Peers:     %zu total, %zu established\n\n", peer_count, established_count);

	json_object *stats = get_object_member(json, "statistics");
	if (stats) {
		printf("Traffic\n");
		print_traffic_summary(stats);
		putchar('\n');
	}

	if (!peers || !peer_count)
		return;

	printf("Peers\n");
	json_object_object_foreach(peers, key, peer) {
		print_peer_status(key, peer);
	}
}

/** Queries a status socket and prints its result */
void fastd_status_query(const char *socket_path, bool json_output) {
	char *status = read_status_json(socket_path);

	if (json_output) {
		fputs(status, stdout);
		if (!strlen(status) || status[strlen(status) - 1] != '\n')
			putchar('\n');
		free(status);
		return;
	}

	json_object *json = json_tokener_parse(status);
	if (!json || json_object_get_type(json) != json_type_object)
		exit_error("status query: daemon returned invalid JSON");

	print_status_human(json);

	json_object_put(json);
	free(status);
}

/** Returns a string as a json_object *, allows NULL to be passed */
static json_object *wrap_string_or_null(const char *str) {
	return str ? json_object_new_string(str) : NULL;
}

/** Dumps a peer's status as a JSON object */
static json_object *dump_peer(const fastd_peer_t *peer) {
	struct json_object *ret = json_object_new_object();

	/* '[' + IPv6 addresss + '%' + interface + ']:' + port + NUL */
	char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
	fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), &peer->address, NULL, false, false);

	json_object_object_add(ret, "name", wrap_string_or_null(peer->name));
	json_object_object_add(ret, "address", json_object_new_string(addr_buf));

	if (!ctx.iface) {
		const char *ifname = NULL;
		uint16_t mtu = 0;

		if (peer) {
			if (peer->offload) {
				peer->offload->get_iface(peer->offload_state, &ifname, &mtu);
			} else if (peer->iface) {
				ifname = peer->iface->name;
				mtu = peer->iface->mtu;
			}
		}

		json_object_object_add(ret, "interface", wrap_string_or_null(ifname));
		json_object_object_add(ret, "mtu", mtu ? json_object_new_int(mtu) : NULL);
	}

	struct json_object *connection = NULL;

	if (fastd_peer_is_established(peer)) {
		connection = json_object_new_object();

		json_object_object_add(connection, "established", json_object_new_int64(ctx.now - peer->established));
		json_object_object_add(
			connection, "transport",
			json_object_new_string(fastd_socket_is_tcp(peer->sock) ? "tcp" : "udp"));

		struct json_object *method = NULL;

		const fastd_method_info_t *method_info = conf.protocol->get_current_method(peer);

		if (method_info)
			method = json_object_new_string(method_info->name);

		json_object_object_add(connection, "method", method);

		struct json_object *tcp_punch = json_object_new_object();
		bool tcp_punch_established = fastd_socket_is_tcp_punch(peer->sock);
		json_object_object_add(tcp_punch, "enabled", json_object_new_boolean(fastd_peer_get_tcp_punch(peer)));
		json_object_object_add(tcp_punch, "established", json_object_new_boolean(tcp_punch_established));

		if (tcp_punch_established) {
			json_object_object_add(
				tcp_punch, "local_port",
				json_object_new_int(ntohs(fastd_peer_address_get_port(peer->sock->bound_addr))));
			json_object_object_add(
				tcp_punch, "remote_port",
				json_object_new_int(ntohs(fastd_peer_address_get_port(&peer->address))));
		}

		json_object_object_add(connection, "tcp_punch", tcp_punch);

		json_object_object_add(connection, "statistics", dump_stats(&peer->stats));

		if (conf.mode == MODE_TAP) {
			struct json_object *mac_addresses = json_object_new_array();
			json_object_object_add(connection, "mac_addresses", mac_addresses);

			size_t i;
			for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
				fastd_peer_eth_addr_t *addr = &VECTOR_INDEX(ctx.eth_addrs, i);

				if (addr->peer != peer)
					continue;

				const uint8_t *d = addr->addr.data;

				char eth_addr_buf[18];
				snprintf(
					eth_addr_buf, sizeof(eth_addr_buf), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1],
					d[2], d[3], d[4], d[5]);

				json_object_array_add(mac_addresses, json_object_new_string(eth_addr_buf));
			}
		}
	}

	json_object_object_add(ret, "connection", connection);

	return ret;
}

/** Dumps fastd's status to a connected socket */
static void dump_status(int fd) {
	struct json_object *json = json_object_new_object();

	json_object_object_add(json, "uptime", json_object_new_int64(ctx.now - ctx.started));

	if (ctx.iface)
		json_object_object_add(json, "interface", wrap_string_or_null(ctx.iface->name));

	json_object_object_add(json, "statistics", dump_stats(&ctx.stats));

	struct json_object *peers = json_object_new_object();
	json_object_object_add(json, "peers", peers);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_is_enabled(peer))
			continue;

		char buf[65];
		if (conf.protocol->describe_peer(peer, buf, sizeof(buf)))
			json_object_object_add(peers, buf, dump_peer(peer));
	}


	dump_thread_arg_t *arg = fastd_new(dump_thread_arg_t);

	arg->json = json;
	arg->fd = fd;

	pthread_t thread;
	if ((errno = pthread_create(&thread, &ctx.detached_thread, dump_thread, arg)) != 0) {
		pr_error_errno("unable to create status dump thread");

		close(arg->fd);
		json_object_put(arg->json);
		free(arg);
	}
}

/** Deletes the status socket file */
static void unlink_status_socket(void) {
	if (!conf.status_socket || ctx.status_fd.fd < 0)
		return;

	if (unlink(conf.status_socket))
		pr_warn_errno("unlink_status_socket: unlink");
}

static void status_socket_lock(void) {
	const char *lock_format = "%s.lock";

	size_t lockname_len = strlen(lock_format) + strlen(conf.status_socket) + 1;
	char lockname[lockname_len];
	snprintf(lockname, lockname_len, lock_format, conf.status_socket);

	int lock_fd = open(lockname, O_RDONLY | O_CREAT, 0600);
	if (lock_fd < 0)
		exit_errno("unable to open status socket lock file");

	if (flock(lock_fd, LOCK_EX | LOCK_NB)) {
		switch (errno) {
		case EWOULDBLOCK:
			exit_error("status socket already in use");

		default:
			exit_error("unable to set status socket lock");
		}
	}
}

/** Initialized the status socket */
void fastd_status_init(void) {
	if (!conf.status_socket) {
		ctx.status_fd.fd = -1;
		return;
	}

#ifdef USE_USER
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (conf.user || conf.group) {
		if (setegid(conf.gid) < 0)
			pr_debug_errno("setegid");
		if (seteuid(conf.uid) < 0)
			pr_debug_errno("seteuid");
	}
#endif

	status_socket_lock();

	if (unlink(conf.status_socket) == 0)
		pr_info("removing old status socket");
	else if (errno != ENOENT)
		pr_warn_errno("unable to remove old status socket");

	ctx.status_fd = FASTD_POLL_FD(POLL_TYPE_STATUS, socket(AF_UNIX, SOCK_STREAM, 0));
	if (ctx.status_fd.fd < 0)
		exit_errno("fastd_status_init: socket");


	size_t status_socket_len = strlen(conf.status_socket);
	size_t len = offsetof(struct sockaddr_un, sun_path) + status_socket_len + 1;
	uint8_t buf[len] __attribute__((aligned(__alignof__(struct sockaddr_un))));
	memset(buf, 0, offsetof(struct sockaddr_un, sun_path));

	struct sockaddr_un *sa = (struct sockaddr_un *)buf;

	sa->sun_family = AF_UNIX;
	memcpy(sa->sun_path, conf.status_socket, status_socket_len + 1);

	if (bind(ctx.status_fd.fd, (struct sockaddr *)sa, len)) {
		switch (errno) {
		case EADDRINUSE:
			exit_error("unable to create status socket: the path `%s' already exists", conf.status_socket);

		default:
			exit_errno("unable to create status socket");
		}
	}

	if (atexit(unlink_status_socket)) {
		pr_error_errno("atexit");
		unlink_status_socket();
		exit(1);
	}

	if (listen(ctx.status_fd.fd, 4))
		exit_errno("fastd_status_init: listen");


#ifdef USE_USER
	if (seteuid(uid) < 0)
		pr_debug_errno("seteuid");
	if (setegid(gid) < 0)
		pr_debug_errno("setegid");
#endif

	fastd_poll_fd_register(&ctx.status_fd);
}

/** Closes the status socket */
void fastd_status_close(void) {
	if (!conf.status_socket || ctx.status_fd.fd < 0)
		return;

	if (!fastd_poll_fd_close(&ctx.status_fd))
		pr_warn_errno("fastd_status_cleanup: close");

	unlink_status_socket();

	ctx.status_fd.fd = -1;
}

/** Handles a single connection on the status socket */
void fastd_status_handle(void) {
	int fd = accept(ctx.status_fd.fd, NULL, NULL);

	if (fd < 0) {
		pr_warn_errno("fastd_status_handle: accept");
		return;
	}

	dump_status(fd);
}

#endif
