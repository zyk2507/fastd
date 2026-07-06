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
#include "nat_detect.h"
#include "offload/offload.h"
#include "peer.h"

#include "dep/libfort/fort.h"

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
		snprintf(
			buf, 64, "%lldd %02lld:%02lld:%02lld", (long long)days, (long long)hours, (long long)minutes,
			(long long)sec);
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

/** Returns a display string for optional values */
static const char *value_or_dash(const char *value) {
	return value && *value ? value : "-";
}

/** Returns "on" or "off" for booleans */
static const char *onoff(bool value) {
	return value ? "on" : "off";
}

/** Formats an integer counter */
static void format_counter(char buf[32], int64_t value) {
	snprintf(buf, 32, "%lld", (long long)value);
}

/** Formats an optional integer counter */
static void format_optional_counter(char buf[32], int64_t value) {
	if (value)
		format_counter(buf, value);
	else
		snprintf(buf, 32, "-");
}

/** Formats a port range from NAT metadata */
static void format_port_range(char buf[64], json_object *nat) {
	if (!get_bool_member(nat, "available")) {
		snprintf(buf, 64, "-");
		return;
	}

	int64_t min_port = get_int_member(nat, "min_port");
	int64_t max_port = get_int_member(nat, "max_port");
	if (!min_port || !max_port) {
		snprintf(buf, 64, "-");
		return;
	}

	if (min_port == max_port)
		snprintf(buf, 64, "%lld", (long long)min_port);
	else
		snprintf(buf, 64, "%lld-%lld", (long long)min_port, (long long)max_port);
}

/** Formats an optional peer port */
static void format_peer_port(char buf[32], json_object *object, const char *key) {
	int64_t port = get_int_member(object, key);
	if (port)
		snprintf(buf, 32, "%lld", (long long)port);
	else
		snprintf(buf, 32, "-");
}

/** Returns a newly allocated comma-separated list of JSON array strings */
static char *join_string_array(json_object *array) {
	size_t len = array ? json_object_array_length(array) : 0;
	if (!len)
		return fastd_strdup("-");

	size_t alloc = 1;
	size_t i;
	for (i = 0; i < len; i++) {
		const char *str = json_object_get_string(json_object_array_get_idx(array, i));
		if (str)
			alloc += strlen(str);
		if (i)
			alloc += 2;
	}

	char *ret = fastd_alloc(alloc);
	char *pos = ret;
	size_t left = alloc;
	ret[0] = 0;

	for (i = 0; i < len; i++) {
		const char *str = json_object_get_string(json_object_array_get_idx(array, i));
		int written = snprintf(pos, left, "%s%s", i ? ", " : "", str ? str : "");
		if (written < 0 || (size_t)written >= left)
			break;
		pos += written;
		left -= written;
	}

	return ret;
}

/** Creates a libfort table with fastd's status style */
static ft_table_t *create_status_table(void) {
	ft_table_t *table = ft_create_table();
	if (!table)
		exit_error("status query: unable to create output table");

	ft_set_border_style(table, FT_NICE_STYLE);
	ft_set_cell_prop(table, FT_ANY_ROW, FT_ANY_COLUMN, FT_CPROP_LEFT_PADDING, 1);
	ft_set_cell_prop(table, FT_ANY_ROW, FT_ANY_COLUMN, FT_CPROP_RIGHT_PADDING, 1);

	return table;
}

/** Marks the last-written row as a table header */
static void mark_header_row(ft_table_t *table, size_t row) {
	ft_set_cell_prop(table, row, FT_ANY_COLUMN, FT_CPROP_ROW_TYPE, FT_ROW_HEADER);
}

/** Prints and destroys a libfort table */
static void print_status_table(const char *title, ft_table_t *table) {
	if (!table)
		return;

	if (ft_is_empty(table)) {
		ft_destroy_table(table);
		return;
	}

	if (title)
		printf("%s\n", title);

	const char *str = ft_to_string(table);
	if (!str) {
		ft_destroy_table(table);
		exit_error("status query: unable to render output table");
	}

	fputs(str, stdout);
	if (!strlen(str) || str[strlen(str) - 1] != '\n')
		putchar('\n');
	putchar('\n');

	ft_destroy_table(table);
}

/** Adds a two-column header row */
static void add_key_value_header(ft_table_t *table) {
	size_t row = ft_cur_row(table);
	ft_write_ln(table, "Item", "Value");
	mark_header_row(table, row);
}

/** Adds a row to a key/value table */
static void add_key_value_row(ft_table_t *table, const char *key, const char *value) {
	ft_write_ln(table, key, value_or_dash(value));
}

/** Prints the top-level fastd status summary */
static void print_overview_table(json_object *json, size_t peer_count, size_t established_count) {
	ft_table_t *table = create_status_table();
	add_key_value_header(table);

	char duration[64];
	format_duration(duration, get_int_member(json, "uptime"));
	add_key_value_row(table, "Uptime", duration);
	add_key_value_row(table, "Interface", get_string_member(json, "interface"));

	char peers[64];
	snprintf(peers, sizeof(peers), "%zu total, %zu established", peer_count, established_count);
	add_key_value_row(table, "Peers", peers);

	print_status_table("Overview", table);
}

/** Prints NAT detection status as a table */
static void print_nat_table(json_object *nat) {
	ft_table_t *table = create_status_table();
	add_key_value_header(table);

	if (!nat) {
		add_key_value_row(table, "Enabled", "off");
		add_key_value_row(table, "Type", "unknown");
		print_status_table("NAT", table);
		return;
	}

	bool available = get_bool_member(nat, "available");
	add_key_value_row(table, "Enabled", onoff(get_bool_member(nat, "enabled")));
	add_key_value_row(table, "Available", available ? "yes" : "no");
	add_key_value_row(table, "Type", value_or_dash(get_string_member(nat, "type")));
	add_key_value_row(table, "Public address", get_string_member(nat, "public_address"));

	char ports[64];
	format_port_range(ports, nat);
	add_key_value_row(table, "Port range", ports);

	char delta[32];
	if (available)
		format_counter(delta, get_int_member(nat, "port_delta"));
	else
		snprintf(delta, sizeof(delta), "-");
	add_key_value_row(table, "Port delta", delta);

	char servers[32], responses[32], age[64];
	format_counter(servers, get_int_member(nat, "servers"));
	format_counter(responses, get_int_member(nat, "responses"));
	add_key_value_row(table, "STUN servers", servers);
	add_key_value_row(table, "STUN responses", responses);

	if (available)
		format_duration(age, get_int_member(nat, "last_update_age"));
	else
		snprintf(age, sizeof(age), "-");
	add_key_value_row(table, "Last update age", age);

	print_status_table("NAT", table);
}

/** Prints punch control status as a table */
static void print_punch_table(json_object *punch) {
	if (!punch)
		return;

	ft_table_t *table = create_status_table();
	add_key_value_header(table);

	char value[32];
	add_key_value_row(table, "Control relay", onoff(get_bool_member(punch, "control_relay")));
	add_key_value_row(table, "Symmetric punch", onoff(get_bool_member(punch, "symmetric")));
	format_counter(value, get_int_member(punch, "max_sockets"));
	add_key_value_row(table, "Max sockets", value);
	format_counter(value, get_int_member(punch, "max_packets"));
	add_key_value_row(table, "Max packets", value);
	format_counter(value, get_int_member(punch, "active_candidates"));
	add_key_value_row(table, "Active candidates", value);
	format_counter(value, get_int_member(punch, "active_suppressions"));
	add_key_value_row(table, "Suppressed endpoints", value);

	json_object *counters = get_object_member(punch, "counters");
	if (counters) {
		static const char *const names[] = {
			"control_tx",		"control_rx",		"direct_handshakes",
			"direct_success",	"direct_failures",	"direct_suppressed",
			"udp_exact_tx",		"result_tx",		"result_rx",
			"result_accepted",	"result_handshake",	"result_suppressed",
			"result_no_peer",
		};

		size_t i;
		for (i = 0; i < array_size(names); i++) {
			format_counter(value, get_int_member(counters, names[i]));
			add_key_value_row(table, names[i], value);
		}
	}

	print_status_table("Punch", table);
}

/** Adds one traffic statistics row */
static void add_traffic_row(ft_table_t *table, const char *label, json_object *stats, const char *name) {
	char bytes[32], packets[32];
	format_bytes(bytes, get_stat_counter(stats, name, "bytes"));
	format_counter(packets, get_stat_counter(stats, name, "packets"));
	ft_write_ln(table, label, bytes, packets);
}

/** Prints a compact traffic summary table */
static void print_traffic_table(json_object *stats) {
	if (!stats)
		return;

	ft_table_t *table = create_status_table();
	size_t row = ft_cur_row(table);
	ft_write_ln(table, "Metric", "Bytes", "Packets");
	mark_header_row(table, row);
	ft_set_cell_prop(table, FT_ANY_ROW, 2, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);

	add_traffic_row(table, "RX", stats, "rx");
	add_traffic_row(table, "TX", stats, "tx");
	add_traffic_row(table, "RX reorder", stats, "rx_reordered");
	add_traffic_row(table, "TX dropped", stats, "tx_dropped");
	add_traffic_row(table, "TX error", stats, "tx_error");

	print_status_table("Traffic", table);
}

/** Returns the display name for a peer */
static const char *peer_display_name(const char *key, json_object *peer) {
	const char *name = get_string_member(peer, "name");
	return name && *name ? name : key;
}

/** Prints the peer list table */
static void print_peer_list_table(json_object *peers) {
	if (!peers || !json_object_object_length(peers))
		return;

	ft_table_t *table = create_status_table();
	size_t row = ft_cur_row(table);
	ft_write_ln(table, "State", "Peer", "Key", "Address", "Interface", "MTU");
	mark_header_row(table, row);
	ft_set_cell_prop(table, FT_ANY_ROW, 5, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);

	json_object_object_foreach(peers, key, peer) {
		json_object *connection = get_object_member(peer, "connection");
		const char *state = connection ? "up" : "down";
		const char *name = peer_display_name(key, peer);
		const char *interface = get_string_member(peer, "interface");

		char mtu[32];
		format_optional_counter(mtu, get_int_member(peer, "mtu"));

		ft_write_ln(
			table, state, name, key, value_or_dash(get_string_member(peer, "address")),
			value_or_dash(interface), mtu);
	}

	print_status_table("Peers", table);
}

/** Prints established connection details */
static void print_connection_table(json_object *peers) {
	if (!peers || !json_object_object_length(peers))
		return;

	ft_table_t *table = create_status_table();
	size_t row = ft_cur_row(table);
	ft_write_ln(table, "Peer", "Connected", "Transport", "Method", "RX", "TX", "MACs");
	mark_header_row(table, row);

	json_object_object_foreach(peers, key, peer) {
		json_object *connection = get_object_member(peer, "connection");
		if (!connection)
			continue;

		char connected[64], rx[32], tx[32];
		format_duration(connected, get_int_member(connection, "established"));

		json_object *stats = get_object_member(connection, "statistics");
		format_bytes(rx, stats ? get_stat_counter(stats, "rx", "bytes") : 0);
		format_bytes(tx, stats ? get_stat_counter(stats, "tx", "bytes") : 0);

		char *macs = join_string_array(get_array_member(connection, "mac_addresses"));
		ft_write_ln(
			table, peer_display_name(key, peer), connected, value_or_dash(get_string_member(connection, "transport")),
			value_or_dash(get_string_member(connection, "method")), rx, tx, macs);
		free(macs);
	}

	print_status_table("Connections", table);
}

/** Prints hole punching state for all peers */
static void print_hole_punch_table(json_object *peers) {
	if (!peers || !json_object_object_length(peers))
		return;

	ft_table_t *table = create_status_table();
	size_t row = ft_cur_row(table);
	ft_write_ln(
		table, "Peer", "State", "Mode", "Transport", "Local port", "Remote port", "Direct candidates",
		"Punch candidates", "Symmetric");
	mark_header_row(table, row);
	ft_set_cell_prop(table, FT_ANY_ROW, 4, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 5, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 6, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 7, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);

	json_object_object_foreach(peers, key, peer) {
		json_object *hole_punch = get_object_member(peer, "hole_punch");
		if (!hole_punch)
			continue;

		bool established = get_bool_member(hole_punch, "established");
		bool enabled = get_bool_member(hole_punch, "enabled");
		const char *state = established ? "established" : (enabled ? "enabled" : "off");

		char local_port[32], remote_port[32], direct_candidates[32], punch_candidates[32];
		format_peer_port(local_port, hole_punch, "local_port");
		format_peer_port(remote_port, hole_punch, "remote_port");
		format_counter(direct_candidates, get_int_member(hole_punch, "direct_candidates"));
		format_counter(punch_candidates, get_int_member(hole_punch, "punch_control_candidates"));

		ft_write_ln(
			table, peer_display_name(key, peer), state, value_or_dash(get_string_member(hole_punch, "mode")),
			value_or_dash(get_string_member(hole_punch, "transport")), local_port, remote_port,
			direct_candidates, punch_candidates, onoff(get_bool_member(hole_punch, "symmetric")));
	}

	print_status_table("Hole Punch", table);
}

/** Prints a human-readable status dump */
static void print_status_human(json_object *json) {
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

	print_overview_table(json, peer_count, established_count);
	print_nat_table(get_object_member(json, "nat"));
	print_punch_table(get_object_member(json, "punch"));
	print_traffic_table(get_object_member(json, "statistics"));
	print_peer_list_table(peers);
	print_connection_table(peers);
	print_hole_punch_table(peers);
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

/** Returns a string for a hole punching mode */
static const char *hole_punch_mode_name(fastd_hole_punch_mode_t mode) {
	switch (mode) {
	case HOLE_PUNCH_OFF:
		return "off";

	case HOLE_PUNCH_TCP:
		return "tcp";

	case HOLE_PUNCH_UDP:
		return "udp";

	case HOLE_PUNCH_AUTO:
		return "auto";

	default:
		return "unset";
	}
}

/** Dumps a peer's hole punching status as a JSON object */
static json_object *dump_hole_punch(const fastd_peer_t *peer) {
	fastd_hole_punch_mode_t mode = fastd_peer_get_hole_punch(peer);
	bool established =
		fastd_peer_is_established(peer) && (fastd_socket_is_hole_punch(peer->sock) || peer->direct_established);

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "mode", json_object_new_string(hole_punch_mode_name(mode)));
	json_object_object_add(ret, "enabled", json_object_new_boolean(mode != HOLE_PUNCH_OFF));
	json_object_object_add(ret, "established", json_object_new_boolean(established));
	json_object_object_add(ret, "symmetric", json_object_new_boolean(fastd_peer_get_punch_symmetric(peer)));
	json_object_object_add(
		ret, "direct_candidates", json_object_new_int64(fastd_peer_direct_candidate_count(peer)));
	json_object_object_add(
		ret, "punch_control_candidates",
		json_object_new_int64(
			fastd_peer_direct_candidate_count_by_source(peer, DIRECT_CANDIDATE_PUNCH_CONTROL)));

	if (established) {
		json_object_object_add(
			ret, "transport", json_object_new_string(fastd_socket_is_tcp(peer->sock) ? "tcp" : "udp"));
		json_object_object_add(
			ret, "local_port",
			json_object_new_int(ntohs(fastd_peer_address_get_port(peer->sock->bound_addr))));
		json_object_object_add(
			ret, "remote_port", json_object_new_int(ntohs(fastd_peer_address_get_port(&peer->address))));
	} else {
		json_object_object_add(ret, "transport", NULL);
		json_object_object_add(ret, "local_port", NULL);
		json_object_object_add(ret, "remote_port", NULL);
	}

	return ret;
}

/** Dumps NAT detection status as a JSON object */
static json_object *dump_nat(void) {
	fastd_nat_status_t status = {};
	struct json_object *ret = json_object_new_object();

	if (!fastd_nat_get_status(&status)) {
		json_object_object_add(ret, "enabled", json_object_new_boolean(false));
		json_object_object_add(ret, "available", json_object_new_boolean(false));
		json_object_object_add(ret, "type", json_object_new_string(fastd_nat_type_name(FASTD_NAT_UNKNOWN)));
		json_object_object_add(ret, "public_address", NULL);
		return ret;
	}

	json_object_object_add(ret, "enabled", json_object_new_boolean(status.enabled));
	json_object_object_add(ret, "available", json_object_new_boolean(status.available));
	json_object_object_add(ret, "type", json_object_new_string(fastd_nat_type_name(status.type)));

	if (status.available) {
		char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
		fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), &status.reflexive, NULL, false, false);
		json_object_object_add(ret, "public_address", json_object_new_string(addr_buf));
		json_object_object_add(ret, "min_port", json_object_new_int(status.min_port));
		json_object_object_add(ret, "max_port", json_object_new_int(status.max_port));
		json_object_object_add(ret, "port_delta", json_object_new_int(status.port_delta));
		json_object_object_add(ret, "responses", json_object_new_int64(status.responses));
		json_object_object_add(ret, "servers", json_object_new_int64(status.servers));
		json_object_object_add(ret, "last_update", json_object_new_int64(status.last_update));
		json_object_object_add(ret, "last_update_age", json_object_new_int64(ctx.now - status.last_update));
	} else {
		json_object_object_add(ret, "public_address", NULL);
		json_object_object_add(ret, "min_port", NULL);
		json_object_object_add(ret, "max_port", NULL);
		json_object_object_add(ret, "port_delta", NULL);
		json_object_object_add(ret, "responses", json_object_new_int64(status.responses));
		json_object_object_add(ret, "servers", json_object_new_int64(status.servers));
		json_object_object_add(ret, "last_update", NULL);
		json_object_object_add(ret, "last_update_age", NULL);
	}

	return ret;
}

/** Dumps punch control status as a JSON object */
static json_object *dump_punch(void) {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "control_relay", json_object_new_boolean(conf.punch_control_relay));
	json_object_object_add(ret, "symmetric", json_object_new_boolean(conf.punch_symmetric));
	json_object_object_add(ret, "max_sockets", json_object_new_int64(conf.punch_max_sockets));
	json_object_object_add(ret, "max_packets", json_object_new_int64(conf.punch_max_packets));

	size_t active_candidates = 0;
	size_t active_suppressions = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		active_candidates += fastd_peer_direct_candidate_count_by_source(
			VECTOR_INDEX(ctx.peers, i), DIRECT_CANDIDATE_PUNCH_CONTROL);
		active_suppressions += fastd_peer_punch_suppression_count(VECTOR_INDEX(ctx.peers, i));
	}
	json_object_object_add(ret, "active_candidates", json_object_new_int64(active_candidates));
	json_object_object_add(ret, "active_suppressions", json_object_new_int64(active_suppressions));

	struct json_object *counters = json_object_new_object();
	json_object_object_add(counters, "control_tx", json_object_new_int64(ctx.punch_control_tx));
	json_object_object_add(counters, "control_rx", json_object_new_int64(ctx.punch_control_rx));
	json_object_object_add(counters, "direct_handshakes", json_object_new_int64(ctx.punch_direct_handshakes));
	json_object_object_add(counters, "direct_success", json_object_new_int64(ctx.punch_direct_success));
	json_object_object_add(counters, "direct_failures", json_object_new_int64(ctx.punch_direct_failures));
	json_object_object_add(counters, "direct_suppressed", json_object_new_int64(ctx.punch_direct_suppressed));
	json_object_object_add(counters, "udp_exact_tx", json_object_new_int64(ctx.punch_udp_exact_tx));
	json_object_object_add(counters, "result_tx", json_object_new_int64(ctx.punch_result_tx));
	json_object_object_add(counters, "result_rx", json_object_new_int64(ctx.punch_result_rx));
	json_object_object_add(counters, "result_accepted", json_object_new_int64(ctx.punch_result_accepted));
	json_object_object_add(counters, "result_handshake", json_object_new_int64(ctx.punch_result_handshake));
	json_object_object_add(counters, "result_suppressed", json_object_new_int64(ctx.punch_result_suppressed));
	json_object_object_add(counters, "result_no_peer", json_object_new_int64(ctx.punch_result_no_peer));
	json_object_object_add(ret, "counters", counters);

	return ret;
}

/** Dumps a peer's status as a JSON object */
static json_object *dump_peer(const fastd_peer_t *peer) {
	struct json_object *ret = json_object_new_object();

	/* '[' + IPv6 addresss + '%' + interface + ']:' + port + NUL */
	char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
	fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), &peer->address, NULL, false, false);

	json_object_object_add(ret, "name", wrap_string_or_null(peer->name));
	json_object_object_add(ret, "address", json_object_new_string(addr_buf));

	struct json_object *hole_punch = dump_hole_punch(peer);
	json_object_object_add(ret, "hole_punch", hole_punch);

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
		json_object_object_add(connection, "hole_punch", json_object_get(hole_punch));

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
	json_object_object_add(json, "nat", dump_nat());
	json_object_object_add(json, "punch", dump_punch());

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
