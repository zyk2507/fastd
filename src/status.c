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
	bool tcp_available = get_bool_member(nat, "tcp_available");
	add_key_value_row(table, "Enabled", onoff(get_bool_member(nat, "enabled")));
	add_key_value_row(table, "UDP available", available ? "yes" : "no");
	add_key_value_row(table, "UDP type", value_or_dash(get_string_member(nat, "udp_type")));
	add_key_value_row(table, "UDP public address", get_string_member(nat, "udp_public_address"));
	add_key_value_row(table, "TCP available", tcp_available ? "yes" : "no");
	add_key_value_row(table, "TCP type", value_or_dash(get_string_member(nat, "tcp_type")));
	add_key_value_row(table, "TCP public address", get_string_member(nat, "tcp_public_address"));

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
	add_key_value_row(table, "Data relay", onoff(get_bool_member(punch, "data_relay")));
	add_key_value_row(table, "Symmetric punch", onoff(get_bool_member(punch, "symmetric")));
	format_counter(value, get_int_member(punch, "maintenance_interval"));
	add_key_value_row(table, "Maintenance interval", value);
	format_counter(value, get_int_member(punch, "announce_interval"));
	add_key_value_row(table, "Announce interval", value);
	format_counter(value, get_int_member(punch, "relay_interval"));
	add_key_value_row(table, "Relay interval", value);
	format_counter(value, get_int_member(punch, "max_sockets"));
	add_key_value_row(table, "Max sockets", value);
	format_counter(value, get_int_member(punch, "max_attempts"));
	add_key_value_row(table, "Max attempts", value);
	format_counter(value, get_int_member(punch, "max_packets"));
	add_key_value_row(table, "Max packets", value);
	format_counter(value, get_int_member(punch, "active_candidates"));
	add_key_value_row(table, "Active candidates", value);
	format_counter(value, get_int_member(punch, "active_suppressions"));
	add_key_value_row(table, "Suppressed endpoints", value);
	format_counter(value, get_int_member(punch, "active_relay_backoffs"));
	add_key_value_row(table, "Relay backoffs", value);

	json_object *task_summary = get_object_member(punch, "task_summary");
	if (task_summary) {
		format_counter(value, get_int_member(task_summary, "latest_tasks"));
		add_key_value_row(table, "Latest tasks", value);
		format_counter(value, get_int_member(task_summary, "waiting_tasks"));
		add_key_value_row(table, "Waiting tasks", value);
		format_counter(value, get_int_member(task_summary, "relay_tasks"));
		add_key_value_row(table, "Relay tasks", value);
		format_counter(value, get_int_member(task_summary, "handshake_sent"));
		add_key_value_row(table, "Handshake tasks", value);
	}

	json_object *task_manager = get_object_member(punch, "task_manager");
		if (task_manager) {
			static const char *const names[] = {
				"runs",		"pairs",	"collected",	"launched",
				"waiting",	"in_flight",	"blacklisted",	"suppressed",
				"aborted",	"recent_demand", "missing_metadata", "runtime_states",
				"history_count", "outcome_success", "outcome_failed", "outcome_busy",
			};

		size_t i;
		for (i = 0; i < array_size(names); i++) {
			format_counter(value, get_int_member(task_manager, names[i]));
			add_key_value_row(table, names[i], value);
		}
	}

	json_object *counters = get_object_member(punch, "counters");
	if (counters) {
		static const char *const names[] = {
			"control_tx",        "control_rx",        "direct_handshakes", "direct_success",
			"direct_failures",   "direct_suppressed", "udp_exact_tx",      "probe_tx",
			"probe_rx",          "probe_response_tx", "probe_matched",     "probe_handshakes",
			"result_tx",         "result_rx",         "result_accepted",   "result_handshake",
			"result_suppressed", "result_no_peer",    "result_busy",
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
			table, peer_display_name(key, peer), connected,
			value_or_dash(get_string_member(connection, "transport")),
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
		table, "Peer", "State", "Reason", "Mode", "Transport", "Local port", "Remote port",
		"Direct candidates", "Punch candidates", "Backup", "Symmetric");
	mark_header_row(table, row);
	ft_set_cell_prop(table, FT_ANY_ROW, 5, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 6, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 7, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 8, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);
	ft_set_cell_prop(table, FT_ANY_ROW, 9, FT_CPROP_TEXT_ALIGN, FT_ALIGNED_RIGHT);

	json_object_object_foreach(peers, key, peer) {
		json_object *hole_punch = get_object_member(peer, "hole_punch");
		if (!hole_punch)
			continue;

		char local_port[32], remote_port[32], direct_candidates[32], punch_candidates[32], backup[64];
		format_peer_port(local_port, hole_punch, "local_port");
		format_peer_port(remote_port, hole_punch, "remote_port");
		format_counter(direct_candidates, get_int_member(hole_punch, "direct_candidates"));
		format_counter(punch_candidates, get_int_member(hole_punch, "punch_control_candidates"));
		if (get_bool_member(hole_punch, "backup_established")) {
			char backup_remote_port[32];
			format_peer_port(backup_remote_port, hole_punch, "backup_remote_port");
			snprintf(
				backup, sizeof(backup), "%s:%s",
				value_or_dash(get_string_member(hole_punch, "backup_transport")), backup_remote_port);
		} else {
			snprintf(backup, sizeof(backup), "-");
		}

		ft_write_ln(
			table, peer_display_name(key, peer), value_or_dash(get_string_member(hole_punch, "path_state")),
			value_or_dash(get_string_member(hole_punch, "reason")),
			value_or_dash(get_string_member(hole_punch, "mode")),
			value_or_dash(get_string_member(hole_punch, "transport")), local_port, remote_port,
			direct_candidates, punch_candidates, backup, onoff(get_bool_member(hole_punch, "symmetric")));
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

/** Returns true if a peer address contains an IP endpoint */
static bool peer_address_available(const fastd_peer_address_t *addr) {
	return addr && (addr->sa.sa_family == AF_INET || addr->sa.sa_family == AF_INET6);
}

/** Returns a peer address string as a json_object *, allows unavailable addresses to be passed */
static json_object *wrap_peer_address_or_null(const fastd_peer_address_t *addr) {
	if (!peer_address_available(addr))
		return NULL;

	char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
	fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), addr, NULL, false, false);
	return json_object_new_string(addr_buf);
}

/** Returns an array of peer address strings */
static json_object *wrap_peer_address_array(const fastd_peer_address_t *addrs, size_t n_addrs) {
	struct json_object *ret = json_object_new_array();

	size_t i;
	for (i = 0; i < n_addrs; i++) {
		if (peer_address_available(&addrs[i]))
			json_object_array_add(ret, wrap_peer_address_or_null(&addrs[i]));
	}

	return ret;
}

/** Returns an array of punch endpoint address strings */
static json_object *wrap_punch_endpoint_address_array(const fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints) {
	struct json_object *ret = json_object_new_array();

	size_t i;
	for (i = 0; i < n_endpoints; i++) {
		if (peer_address_available(&endpoints[i].address))
			json_object_array_add(ret, wrap_peer_address_or_null(&endpoints[i].address));
	}

	return ret;
}

/** Returns detailed per-endpoint NAT metadata */
static json_object *wrap_punch_endpoint_detail_array(const fastd_peer_punch_endpoint_t *endpoints, size_t n_endpoints) {
	struct json_object *ret = json_object_new_array();

	size_t i;
	for (i = 0; i < n_endpoints; i++) {
		const fastd_peer_punch_endpoint_t *endpoint = &endpoints[i];
		if (!peer_address_available(&endpoint->address))
			continue;

		struct json_object *entry = json_object_new_object();
		json_object_object_add(entry, "endpoint", wrap_peer_address_or_null(&endpoint->address));
		json_object_object_add(entry, "type", json_object_new_string(fastd_nat_type_name(endpoint->nat_type)));
		json_object_object_add(entry, "min_port", json_object_new_int(endpoint->min_port));
		json_object_object_add(entry, "max_port", json_object_new_int(endpoint->max_port));
		json_object_object_add(entry, "port_delta", json_object_new_int(endpoint->port_delta));
		json_object_object_add(entry, "hard_symmetric_port_index", json_object_new_int64(endpoint->hard_sym_port_index));
		json_object_object_add(entry, "hard_symmetric_round", json_object_new_int64(endpoint->hard_sym_round));
		json_object_array_add(ret, entry);
	}

	return ret;
}

/** Returns the remaining lifetime of a timeout in milliseconds */
static int64_t timeout_remaining(fastd_timeout_t timeout) {
	if (timeout == FASTD_TIMEOUT_INV || fastd_timed_out(timeout))
		return 0;

	return timeout - ctx.now;
}

/** Returns the elapsed age of a timestamp in milliseconds */
static int64_t timeout_age(fastd_timeout_t timeout) {
	if (timeout == FASTD_TIMEOUT_INV || !timeout || timeout > ctx.now)
		return 0;

	return ctx.now - timeout;
}

/** Returns a string for a direct candidate source */
static const char *direct_candidate_source_name(fastd_peer_direct_candidate_source_t source) {
	switch (source) {
	case DIRECT_CANDIDATE_REALM:
		return "realm";

	case DIRECT_CANDIDATE_DISCOVERY:
		return "discovery";

	case DIRECT_CANDIDATE_PUNCH_CONTROL:
		return "punch-control";

	default:
		return "unknown";
	}
}

/** Returns a string for a punch task role */
static const char *punch_task_role_name(fastd_peer_punch_task_role_t role) {
	switch (role) {
	case PEER_PUNCH_TASK_ROLE_NONE:
		return "none";

	case PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT:
		return "relay-subject";

	case PEER_PUNCH_TASK_ROLE_RELAY_DEST:
		return "relay-destination";

	case PEER_PUNCH_TASK_ROLE_COMMAND_TARGET:
		return "command-target";

	case PEER_PUNCH_TASK_ROLE_RESULT_SENDER:
		return "result-sender";

	case PEER_PUNCH_TASK_ROLE_RESULT_SUBJECT:
		return "result-subject";

	default:
		return "unknown";
	}
}

/** Returns a string for a punch task command */
static const char *punch_task_command_name(fastd_peer_punch_task_command_t command) {
	switch (command) {
	case PEER_PUNCH_TASK_COMMAND_NONE:
		return "none";

	case PEER_PUNCH_TASK_COMMAND_CONE:
		return "cone";

	case PEER_PUNCH_TASK_COMMAND_EASY_SYM:
		return "easy-symmetric";

	case PEER_PUNCH_TASK_COMMAND_HARD_SYM:
		return "hard-symmetric";

	case PEER_PUNCH_TASK_COMMAND_BOTH_EASY_SYM:
		return "both-easy-symmetric";

	case PEER_PUNCH_TASK_COMMAND_TCP:
		return "tcp";

	default:
		return "unknown";
	}
}

/** Returns a string for a punch task result */
static const char *punch_task_result_name(fastd_peer_punch_task_result_t result) {
	switch (result) {
	case PEER_PUNCH_TASK_RESULT_NONE:
		return "none";

	case PEER_PUNCH_TASK_RESULT_ACCEPTED:
		return "accepted";

	case PEER_PUNCH_TASK_RESULT_HANDSHAKE:
		return "handshake";

	case PEER_PUNCH_TASK_RESULT_SUPPRESSED:
		return "suppressed";

	case PEER_PUNCH_TASK_RESULT_NO_PEER:
		return "no-peer";

	case PEER_PUNCH_TASK_RESULT_BUSY:
		return "busy";

	default:
		return "unknown";
	}
}

/** Returns a string for a peer-pair punch task stage */
static const char *punch_pair_task_stage_name(fastd_punch_pair_task_stage_t stage) {
	switch (stage) {
	case PUNCH_PAIR_TASK_STAGE_NONE:
		return "none";

	case PUNCH_PAIR_TASK_STAGE_COLLECTED:
		return "collected";

	case PUNCH_PAIR_TASK_STAGE_LAUNCHED:
		return "launched";

	case PUNCH_PAIR_TASK_STAGE_WAITING:
		return "waiting";

	case PUNCH_PAIR_TASK_STAGE_IN_FLIGHT:
		return "in-flight";

	case PUNCH_PAIR_TASK_STAGE_BLACKLISTED:
		return "blacklisted";

	case PUNCH_PAIR_TASK_STAGE_SUPPRESSED:
		return "suppressed";

	case PUNCH_PAIR_TASK_STAGE_MISSING_METADATA:
		return "missing-metadata";

	case PUNCH_PAIR_TASK_STAGE_ABORTED:
		return "aborted";

	case PUNCH_PAIR_TASK_STAGE_RESULT_ACCEPTED:
		return "result-accepted";

	case PUNCH_PAIR_TASK_STAGE_RESULT_HANDSHAKE:
		return "result-handshake";

	case PUNCH_PAIR_TASK_STAGE_RESULT_SUPPRESSED:
		return "result-suppressed";

	case PUNCH_PAIR_TASK_STAGE_RESULT_NO_PEER:
		return "result-no-peer";

	case PUNCH_PAIR_TASK_STAGE_RESULT_BUSY:
		return "result-busy";

	default:
		return "unknown";
	}
}

/** Returns a string for a punch task cause */
static const char *punch_task_cause_name(fastd_peer_punch_task_cause_t cause) {
	switch (cause) {
	case PEER_PUNCH_TASK_CAUSE_NONE:
		return "none";

	case PEER_PUNCH_TASK_CAUSE_RELAY_UDP:
		return "relay-udp-metadata";

	case PEER_PUNCH_TASK_CAUSE_RELAY_TCP:
		return "relay-tcp-metadata";

	case PEER_PUNCH_TASK_CAUSE_REMOTE_COMMAND:
		return "remote-command";

	case PEER_PUNCH_TASK_CAUSE_REMOTE_RESULT:
		return "remote-result";

	case PEER_PUNCH_TASK_CAUSE_MISSING_PEER:
		return "missing-peer";

	case PEER_PUNCH_TASK_CAUSE_VERIFIED_BACKUP:
		return "verified-backup";

	case PEER_PUNCH_TASK_CAUSE_LOCAL_POLICY:
		return "local-policy";

	case PEER_PUNCH_TASK_CAUSE_CANDIDATE_ADDED:
		return "candidate-added";

	case PEER_PUNCH_TASK_CAUSE_HANDSHAKE_SENT:
		return "handshake-sent";

	default:
		return "unknown";
	}
}

/** Returns a normalized direct candidate transport mask */
static uint8_t direct_candidate_transport_mask(uint8_t transports) {
	transports &= DIRECT_CANDIDATE_TRANSPORT_ANY;
	return transports ? transports : DIRECT_CANDIDATE_TRANSPORT_ANY;
}

/** Returns true if a direct candidate should be exposed as active status */
static bool direct_candidate_available(const fastd_peer_direct_candidate_t *candidate) {
	return peer_address_available(&candidate->remote) && candidate->timeout != FASTD_TIMEOUT_INV &&
	       !fastd_timed_out(candidate->timeout);
}

/** Returns true if a punch suppression/backoff entry should be exposed as active status */
static bool punch_suppression_available(const fastd_peer_punch_suppression_t *entry) {
	return peer_address_available(&entry->remote) && entry->timeout != FASTD_TIMEOUT_INV &&
	       !fastd_timed_out(entry->timeout);
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

/** Returns the user-visible hole-punch path state for a peer */
static const char *hole_punch_path_state(
	bool enabled, bool established, bool verified, bool proven, bool backup_established, bool backup_verified,
	bool backup_payload_proven) {
	if (!enabled)
		return "off";
	if (established && proven && backup_established && backup_verified && backup_payload_proven)
		return "direct-with-payload-backup";
	if (established && verified && backup_established && backup_verified)
		return "direct-with-backup";
	if (established && proven)
		return "direct-payload-proven";
	if (established && verified)
		return "direct-verified";
	if (established)
		return "direct-unverified";
	if (backup_established && backup_verified)
		return "backup-ready";
	if (backup_established)
		return "backup-unverified";

	return "not-direct";
}

/** Returns the most useful reason a peer is in its current hole-punch path state */
static const char *hole_punch_reason(
	const fastd_peer_t *peer, bool enabled, bool established, bool verified, bool proven, bool backup_established,
	bool backup_verified, bool backup_payload_proven) {
	bool udp_metadata = peer_address_available(&peer->punch_endpoint) && peer->punch_timeout != FASTD_TIMEOUT_INV &&
			    !fastd_timed_out(peer->punch_timeout);
	bool tcp_metadata = peer_address_available(&peer->tcp_punch_endpoint) &&
			    peer->tcp_punch_timeout != FASTD_TIMEOUT_INV &&
			    !fastd_timed_out(peer->tcp_punch_timeout);

	if (!enabled)
		return "hole-punch-disabled";
	if (!fastd_peer_get_nat_traversal(peer))
		return "nat-traversal-disabled";
	if (established && proven && backup_established && backup_verified && backup_payload_proven)
		return "active-and-backup-payload-ready";
	if (established && verified && backup_established && backup_verified)
		return "active-and-backup-verified";
	if (established && proven)
		return "active-path-carried-payload";
	if (established && verified)
		return "active-path-verified";
	if (established)
		return "active-path-awaiting-verification";
	if (backup_established && backup_verified)
		return "backup-ready-for-promotion";
	if (backup_established)
		return "backup-awaiting-verification";
	if (fastd_peer_punch_relay_backoff_count(peer))
		return "relay-backoff-active";
	if (fastd_peer_punch_suppression_count(peer))
		return "candidate-suppressed";
	if (fastd_peer_direct_candidate_count(peer))
		return "candidate-awaiting-handshake";
	if (udp_metadata || tcp_metadata)
		return "metadata-ready";

	return "missing-nat-metadata";
}

/** Dumps UDP punch metadata learned from a peer */
static json_object *dump_udp_punch_metadata(const fastd_peer_t *peer) {
	bool available = peer_address_available(&peer->punch_endpoint) && peer->punch_timeout != FASTD_TIMEOUT_INV &&
			 !fastd_timed_out(peer->punch_timeout);

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "available", json_object_new_boolean(available));
	json_object_object_add(ret, "type", json_object_new_string(fastd_nat_type_name(peer->punch_nat_type)));
	json_object_object_add(ret, "endpoint", available ? wrap_peer_address_or_null(&peer->punch_endpoint) : NULL);
	json_object_object_add(
		ret, "endpoints",
		available ? wrap_punch_endpoint_address_array(peer->punch_endpoints, peer->n_punch_endpoints) :
			    json_object_new_array());
	json_object_object_add(
		ret, "endpoint_details",
		available ? wrap_punch_endpoint_detail_array(peer->punch_endpoints, peer->n_punch_endpoints) :
			    json_object_new_array());
	json_object_object_add(ret, "min_port", available ? json_object_new_int(peer->punch_min_port) : NULL);
	json_object_object_add(ret, "max_port", available ? json_object_new_int(peer->punch_max_port) : NULL);
	json_object_object_add(ret, "port_delta", available ? json_object_new_int(peer->punch_port_delta) : NULL);
	json_object_object_add(
		ret, "listener_id", available && peer->punch_listener_id ? json_object_new_int64(peer->punch_listener_id) : NULL);
	json_object_object_add(ret, "expires_in", json_object_new_int64(timeout_remaining(peer->punch_timeout)));
	return ret;
}

/** Dumps TCP punch metadata learned from a peer */
static json_object *dump_tcp_punch_metadata(const fastd_peer_t *peer) {
	bool available = peer_address_available(&peer->tcp_punch_endpoint) && peer->tcp_punch_timeout != FASTD_TIMEOUT_INV &&
			 !fastd_timed_out(peer->tcp_punch_timeout);

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "available", json_object_new_boolean(available));
	json_object_object_add(ret, "type", json_object_new_string(fastd_nat_type_name(peer->tcp_punch_nat_type)));
	json_object_object_add(ret, "endpoint", available ? wrap_peer_address_or_null(&peer->tcp_punch_endpoint) : NULL);
	json_object_object_add(
		ret, "endpoints",
		available ? wrap_peer_address_array(peer->tcp_punch_endpoints, peer->n_tcp_punch_endpoints) :
			    json_object_new_array());
	json_object_object_add(ret, "min_port", available ? json_object_new_int(peer->tcp_punch_min_port) : NULL);
	json_object_object_add(ret, "max_port", available ? json_object_new_int(peer->tcp_punch_max_port) : NULL);
	json_object_object_add(ret, "expires_in", json_object_new_int64(timeout_remaining(peer->tcp_punch_timeout)));
	return ret;
}

/** Dumps the currently selected direct candidate cache */
static json_object *dump_current_direct_candidate(const fastd_peer_t *peer) {
	bool available = peer_address_available(&peer->direct_remote) &&
			 peer->direct_remote_timeout != FASTD_TIMEOUT_INV &&
			 !fastd_timed_out(peer->direct_remote_timeout);
	uint8_t transports = available ? direct_candidate_transport_mask(peer->direct_remote_transports) : 0;

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "available", json_object_new_boolean(available));
	json_object_object_add(ret, "endpoint", available ? wrap_peer_address_or_null(&peer->direct_remote) : NULL);
	json_object_object_add(
		ret, "source",
		available ? json_object_new_string(direct_candidate_source_name(peer->direct_remote_source)) : NULL);
	json_object_object_add(ret, "udp", json_object_new_boolean(transports & DIRECT_CANDIDATE_TRANSPORT_UDP));
	json_object_object_add(ret, "tcp", json_object_new_boolean(transports & DIRECT_CANDIDATE_TRANSPORT_TCP));
	json_object_object_add(ret, "exact_udp", json_object_new_boolean(available && peer->direct_remote_exact_udp));
	json_object_object_add(
		ret, "udp_punch_sockets",
		json_object_new_int64(available ? peer->direct_remote_udp_punch_sockets : 0));
	json_object_object_add(ret, "expires_in", json_object_new_int64(timeout_remaining(peer->direct_remote_timeout)));
	return ret;
}

/** Dumps one active direct candidate */
static json_object *dump_direct_candidate(const fastd_peer_direct_candidate_t *candidate) {
	uint8_t transports = direct_candidate_transport_mask(candidate->transports);

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "endpoint", wrap_peer_address_or_null(&candidate->remote));
	json_object_object_add(ret, "source", json_object_new_string(direct_candidate_source_name(candidate->source)));
	json_object_object_add(ret, "relay", candidate->relay ? wrap_string_or_null(candidate->relay->name) : NULL);
	json_object_object_add(ret, "udp", json_object_new_boolean(transports & DIRECT_CANDIDATE_TRANSPORT_UDP));
	json_object_object_add(ret, "tcp", json_object_new_boolean(transports & DIRECT_CANDIDATE_TRANSPORT_TCP));
	json_object_object_add(ret, "exact_udp", json_object_new_boolean(candidate->exact_udp_punch));
	json_object_object_add(ret, "udp_punch_sockets", json_object_new_int64(candidate->udp_punch_sockets));
	json_object_object_add(ret, "priority", json_object_new_int(candidate->priority));
	json_object_object_add(ret, "order", json_object_new_int(candidate->order));
	json_object_object_add(ret, "attempts", json_object_new_int64(candidate->attempts));
	json_object_object_add(ret, "expires_in", json_object_new_int64(timeout_remaining(candidate->timeout)));
	json_object_object_add(ret, "last_attempt_age", json_object_new_int64(timeout_age(candidate->last_attempt)));
	json_object_object_add(ret, "probe_expires_in", json_object_new_int64(timeout_remaining(candidate->probe_timeout)));
	json_object_object_add(
		ret, "payload_probe_expires_in", json_object_new_int64(timeout_remaining(candidate->payload_probe_timeout)));
	return ret;
}

/** Dumps active direct candidates for one peer */
static json_object *dump_direct_candidate_list(const fastd_peer_t *peer) {
	struct json_object *ret = json_object_new_array();

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->direct_candidates); i++) {
		const fastd_peer_direct_candidate_t *candidate = &VECTOR_INDEX(peer->direct_candidates, i);
		if (direct_candidate_available(candidate))
			json_object_array_add(ret, dump_direct_candidate(candidate));
	}

	return ret;
}

/** Dumps one active punch suppression or relay backoff entry */
static json_object *dump_punch_suppression_entry(const fastd_peer_punch_suppression_t *entry) {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "endpoint", wrap_peer_address_or_null(&entry->remote));
	json_object_object_add(ret, "expires_in", json_object_new_int64(timeout_remaining(entry->timeout)));
	return ret;
}

/** Dumps active punch suppression or relay backoff entries */
static json_object *dump_punch_suppression_list(
	const fastd_peer_punch_suppression_t *entries, size_t n_entries) {
	struct json_object *ret = json_object_new_array();

	size_t i;
	for (i = 0; i < n_entries; i++) {
		const fastd_peer_punch_suppression_t *entry = &entries[i];
		if (punch_suppression_available(entry))
			json_object_array_add(ret, dump_punch_suppression_entry(entry));
	}

	return ret;
}

/** Dumps the latest punch-control task snapshot for a peer */
static json_object *dump_last_punch_task(const fastd_peer_t *peer) {
	const fastd_peer_punch_task_t *task = &peer->last_punch_task;
	bool available = task->id != 0;

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "available", json_object_new_boolean(available));
	json_object_object_add(ret, "id", available ? json_object_new_int64(task->id) : NULL);
	json_object_object_add(ret, "updated_age", available ? json_object_new_int64(ctx.now - task->updated) : NULL);
	json_object_object_add(
		ret, "role", available ? json_object_new_string(punch_task_role_name(task->role)) : NULL);
	json_object_object_add(
		ret, "cause", available ? json_object_new_string(punch_task_cause_name(task->cause)) : NULL);
	json_object_object_add(
		ret, "command", available ? json_object_new_string(punch_task_command_name(task->command)) : NULL);
	json_object_object_add(
		ret, "result", available ? json_object_new_string(punch_task_result_name(task->result)) : NULL);
	json_object_object_add(
		ret, "next_retry_ms",
		available && task->next_retry != FASTD_TIMEOUT_INV ? json_object_new_int64(timeout_remaining(task->next_retry)) :
								      NULL);
	json_object_object_add(
		ret, "endpoint",
		available && peer_address_available(&task->endpoint) ? wrap_peer_address_or_null(&task->endpoint) : NULL);
	json_object_object_add(
		ret, "base_mapped_endpoint",
		available && task->base_mapped_available && peer_address_available(&task->base_mapped_endpoint)
			? wrap_peer_address_or_null(&task->base_mapped_endpoint)
			: NULL);
	json_object_object_add(
		ret, "base_mapped_port_mapped",
		available ? json_object_new_boolean(task->base_mapped_port_mapped) : NULL);
	json_object_object_add(
		ret, "base_mapped_listener_id",
		available && task->base_mapped_listener_id ? json_object_new_int64(task->base_mapped_listener_id) : NULL);
	json_object_object_add(ret, "packet_count", available ? json_object_new_int(task->packet_count) : NULL);
	json_object_object_add(ret, "candidate_count", available ? json_object_new_int(task->candidate_count) : NULL);
	json_object_object_add(ret, "candidates_sent", available ? json_object_new_int(task->candidates_sent) : NULL);
	json_object_object_add(ret, "order", available ? json_object_new_int(task->order) : NULL);
	json_object_object_add(
		ret, "udp_punch_sockets", available ? json_object_new_int64(task->udp_punch_sockets) : NULL);
	json_object_object_add(
		ret, "hard_symmetric_port_index",
		available ? json_object_new_int64(task->hard_sym_port_index) : NULL);
	json_object_object_add(
		ret, "hard_symmetric_next_port_index",
		available ? json_object_new_int64(task->hard_sym_next_port_index) : NULL);
	json_object_object_add(
		ret, "hard_symmetric_round", available ? json_object_new_int64(task->hard_sym_round) : NULL);
	json_object_object_add(ret, "wait_window_ms", available ? json_object_new_int64(task->wait_window_ms) : NULL);
	return ret;
}

/** Dumps a peer's hole punching status as a JSON object */
static json_object *dump_hole_punch(const fastd_peer_t *peer) {
	fastd_hole_punch_mode_t mode = fastd_peer_get_hole_punch(peer);
	bool established = fastd_peer_is_established(peer) && fastd_socket_is_open(peer->sock) &&
			   (fastd_socket_is_hole_punch(peer->sock) || peer->direct_established);
	bool verified = peer->active_path_timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(peer->active_path_timeout);
	bool proven = fastd_peer_active_path_proven(peer);
	bool backup_established = fastd_peer_has_backup_path(peer);
	bool backup_verified = fastd_peer_has_verified_backup_path(peer);

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "mode", json_object_new_string(hole_punch_mode_name(mode)));
	json_object_object_add(ret, "nat_traversal", json_object_new_boolean(fastd_peer_get_nat_traversal(peer)));
	json_object_object_add(ret, "enabled", json_object_new_boolean(mode != HOLE_PUNCH_OFF));
	json_object_object_add(ret, "established", json_object_new_boolean(established));
	json_object_object_add(ret, "verified", json_object_new_boolean(verified));
	json_object_object_add(ret, "proven", json_object_new_boolean(proven));
	json_object_object_add(ret, "backup_established", json_object_new_boolean(backup_established));
	json_object_object_add(ret, "backup_verified", json_object_new_boolean(backup_verified));
	json_object_object_add(ret, "backup_payload_proven", json_object_new_boolean(peer->backup_payload_proven));
	json_object_object_add(ret, "backup_probe_proven", json_object_new_boolean(peer->backup_probe_proven));
	json_object_object_add(
		ret, "path_state",
		json_object_new_string(hole_punch_path_state(
			mode != HOLE_PUNCH_OFF, established, verified, proven, backup_established, backup_verified,
			peer->backup_payload_proven)));
	json_object_object_add(
		ret, "reason",
		json_object_new_string(hole_punch_reason(
			peer, mode != HOLE_PUNCH_OFF, established, verified, proven, backup_established,
			backup_verified, peer->backup_payload_proven)));
	json_object_object_add(ret, "symmetric", json_object_new_boolean(fastd_peer_get_punch_symmetric(peer)));
	json_object_object_add(
		ret, "direct_candidates", json_object_new_int64(fastd_peer_direct_candidate_count(peer)));
	json_object_object_add(
		ret, "punch_control_candidates",
		json_object_new_int64(
			fastd_peer_direct_candidate_count_by_source(peer, DIRECT_CANDIDATE_PUNCH_CONTROL)));
	json_object_object_add(
		ret, "punch_suppressions", json_object_new_int64(fastd_peer_punch_suppression_count(peer)));
	json_object_object_add(ret, "relay_backoffs", json_object_new_int64(fastd_peer_punch_relay_backoff_count(peer)));
	json_object_object_add(ret, "hard_symmetric_port_index", json_object_new_int64(peer->punch_hard_sym_port_index));
	json_object_object_add(ret, "hard_symmetric_round", json_object_new_int64(peer->punch_hard_sym_round));
	json_object_object_add(ret, "udp_metadata", dump_udp_punch_metadata(peer));
	json_object_object_add(ret, "tcp_metadata", dump_tcp_punch_metadata(peer));
	json_object_object_add(ret, "current_direct_candidate", dump_current_direct_candidate(peer));
	json_object_object_add(ret, "direct_candidate_list", dump_direct_candidate_list(peer));
	json_object_object_add(
		ret, "punch_suppression_list",
		dump_punch_suppression_list(VECTOR_DATA(peer->punch_suppressions), VECTOR_LEN(peer->punch_suppressions)));
	json_object_object_add(
		ret, "relay_backoff_list",
		dump_punch_suppression_list(
			VECTOR_DATA(peer->punch_relay_backoffs), VECTOR_LEN(peer->punch_relay_backoffs)));
	json_object_object_add(ret, "last_punch_task", dump_last_punch_task(peer));

	if (established) {
		json_object_object_add(
			ret, "transport", json_object_new_string(fastd_socket_is_tcp(peer->sock) ? "tcp" : "udp"));
		json_object_object_add(
			ret, "local_port",
			json_object_new_int(ntohs(fastd_peer_address_get_port(&peer->local_address))));
		json_object_object_add(
			ret, "remote_port", json_object_new_int(ntohs(fastd_peer_address_get_port(&peer->address))));
	} else {
		json_object_object_add(ret, "transport", NULL);
		json_object_object_add(ret, "local_port", NULL);
		json_object_object_add(ret, "remote_port", NULL);
	}

	if (backup_established) {
		json_object_object_add(
			ret, "backup_transport",
			json_object_new_string(fastd_socket_is_tcp(peer->backup_sock) ? "tcp" : "udp"));
		json_object_object_add(
			ret, "backup_local_port",
			json_object_new_int(ntohs(fastd_peer_address_get_port(&peer->backup_local_address))));
		json_object_object_add(
			ret, "backup_remote_port",
			json_object_new_int(ntohs(fastd_peer_address_get_port(&peer->backup_address))));
	} else {
		json_object_object_add(ret, "backup_transport", NULL);
		json_object_object_add(ret, "backup_local_port", NULL);
		json_object_object_add(ret, "backup_remote_port", NULL);
	}

	return ret;
}

#ifdef WITH_TESTS

/** Test wrapper for a peer's hole punching status */
struct json_object *fastd_status_test_dump_hole_punch(const fastd_peer_t *peer) {
	return dump_hole_punch(peer);
}

#endif

/** Dumps NAT detection status as a JSON object */
static json_object *dump_nat(void) {
	fastd_nat_status_t status = {};
	struct json_object *ret = json_object_new_object();

	if (!fastd_nat_get_status(&status)) {
		json_object_object_add(ret, "enabled", json_object_new_boolean(false));
		json_object_object_add(ret, "available", json_object_new_boolean(false));
		json_object_object_add(ret, "type", json_object_new_string(fastd_nat_type_name(FASTD_NAT_UNKNOWN)));
		json_object_object_add(ret, "public_address", NULL);
		json_object_object_add(ret, "udp_type", json_object_new_string(fastd_nat_type_name(FASTD_NAT_UNKNOWN)));
		json_object_object_add(ret, "udp_public_address", NULL);
		json_object_object_add(ret, "udp_public_addresses", json_object_new_array());
		json_object_object_add(ret, "tcp_available", json_object_new_boolean(false));
		json_object_object_add(ret, "tcp_type", json_object_new_string(fastd_nat_type_name(FASTD_NAT_UNKNOWN)));
		json_object_object_add(ret, "tcp_public_address", NULL);
		json_object_object_add(ret, "tcp_public_addresses", json_object_new_array());
		return ret;
	}

	json_object_object_add(ret, "enabled", json_object_new_boolean(status.enabled));
	json_object_object_add(ret, "available", json_object_new_boolean(status.available));
	json_object_object_add(ret, "type", json_object_new_string(fastd_nat_type_name(status.type)));
	json_object_object_add(ret, "udp_type", json_object_new_string(fastd_nat_type_name(status.type)));
	json_object_object_add(ret, "tcp_available", json_object_new_boolean(status.tcp_available));
	json_object_object_add(ret, "tcp_type", json_object_new_string(fastd_nat_type_name(status.tcp_type)));

	if (status.available) {
		char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
		fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), &status.reflexive, NULL, false, false);
		json_object_object_add(ret, "public_address", json_object_new_string(addr_buf));
		json_object_object_add(ret, "udp_public_address", json_object_new_string(addr_buf));
		json_object_object_add(
			ret, "udp_public_addresses",
			wrap_peer_address_array(status.reflexive_addrs, status.n_reflexive_addrs));
		json_object_object_add(ret, "min_port", json_object_new_int(status.min_port));
		json_object_object_add(ret, "max_port", json_object_new_int(status.max_port));
		json_object_object_add(ret, "port_delta", json_object_new_int(status.port_delta));
		json_object_object_add(ret, "responses", json_object_new_int64(status.responses));
		json_object_object_add(ret, "servers", json_object_new_int64(status.servers));
		json_object_object_add(ret, "last_update", json_object_new_int64(status.last_update));
		json_object_object_add(ret, "last_update_age", json_object_new_int64(ctx.now - status.last_update));
	} else {
		json_object_object_add(ret, "public_address", NULL);
		json_object_object_add(ret, "udp_public_address", NULL);
		json_object_object_add(ret, "udp_public_addresses", json_object_new_array());
		json_object_object_add(ret, "min_port", NULL);
		json_object_object_add(ret, "max_port", NULL);
		json_object_object_add(ret, "port_delta", NULL);
		json_object_object_add(ret, "responses", json_object_new_int64(status.responses));
		json_object_object_add(ret, "servers", json_object_new_int64(status.servers));
		json_object_object_add(ret, "last_update", NULL);
		json_object_object_add(ret, "last_update_age", NULL);
	}

	if (status.tcp_available) {
		char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
		fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), &status.tcp_reflexive, NULL, false, false);
		json_object_object_add(ret, "tcp_public_address", json_object_new_string(addr_buf));
		json_object_object_add(
			ret, "tcp_public_addresses",
			wrap_peer_address_array(status.tcp_reflexive_addrs, status.n_tcp_reflexive_addrs));
		json_object_object_add(ret, "tcp_min_port", json_object_new_int(status.tcp_min_port));
		json_object_object_add(ret, "tcp_max_port", json_object_new_int(status.tcp_max_port));
		json_object_object_add(ret, "tcp_responses", json_object_new_int64(status.tcp_responses));
	} else {
		json_object_object_add(ret, "tcp_public_address", NULL);
		json_object_object_add(ret, "tcp_public_addresses", json_object_new_array());
		json_object_object_add(ret, "tcp_min_port", NULL);
		json_object_object_add(ret, "tcp_max_port", NULL);
		json_object_object_add(ret, "tcp_responses", json_object_new_int64(status.tcp_responses));
	}

	return ret;
}

/** Returns true if a UDP punch socket is active and should be exposed */
static bool udp_punch_socket_available(const fastd_socket_t *sock) {
	return sock && sock->type == SOCKET_TYPE_UDP && sock->hole_punch &&
	       sock->hole_punch_timeout != FASTD_TIMEOUT_INV && !fastd_timed_out(sock->hole_punch_timeout);
}

/** Dumps one active UDP punch socket */
static json_object *dump_udp_punch_socket(const fastd_socket_t *sock) {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(
		ret, "kind", json_object_new_string(sock->punch_public_listener ? "public-listener" : "peer-punch"));
	json_object_object_add(ret, "peer", sock->hole_punch_peer ? wrap_string_or_null(sock->hole_punch_peer->name) : NULL);
	json_object_object_add(ret, "peer_id", sock->hole_punch_peer ? json_object_new_int64(sock->hole_punch_peer->id) : NULL);
	json_object_object_add(ret, "remote", wrap_peer_address_or_null(&sock->peer_addr));
	json_object_object_add(ret, "public_endpoint", wrap_peer_address_or_null(&sock->punch_listener_public_addr));
	json_object_object_add(
		ret, "listener_id", sock->punch_listener_id ? json_object_new_int64(sock->punch_listener_id) : NULL);
	json_object_object_add(
		ret, "local",
		sock->bound_addr && peer_address_available(sock->bound_addr) ? wrap_peer_address_or_null(sock->bound_addr)
									     : NULL);
	json_object_object_add(ret, "expires_in", json_object_new_int64(timeout_remaining(sock->hole_punch_timeout)));
	json_object_object_add(ret, "selected_age", json_object_new_int64(timeout_age(sock->punch_listener_selected)));
	json_object_object_add(
		ret, "mapping_registered", json_object_new_boolean(sock->punch_listener_mapping_registered));
	json_object_object_add(ret, "port_mapped", json_object_new_boolean(sock->punch_listener_port_mapped));
	json_object_object_add(ret, "transaction_id", json_object_new_int64(sock->punch_transaction_id));
	return ret;
}

/** Dumps the UDP punch socket pool */
static json_object *dump_udp_punch_socket_pool(void) {
	struct json_object *ret = json_object_new_object();
	struct json_object *sockets = json_object_new_array();
	size_t active = 0;
	size_t public_listeners = 0;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.udp_punch_socks); i++) {
		const fastd_socket_t *sock = VECTOR_INDEX(ctx.udp_punch_socks, i);
		if (!udp_punch_socket_available(sock))
			continue;

		if (sock->punch_public_listener)
			public_listeners++;
		else
			active++;
		json_object_array_add(sockets, dump_udp_punch_socket(sock));
	}

	json_object_object_add(ret, "limit", json_object_new_int64(conf.punch_max_sockets));
	json_object_object_add(ret, "public_listener_limit", json_object_new_int64(DEFAULT_PUNCH_PUBLIC_LISTENERS));
	json_object_object_add(ret, "active", json_object_new_int64(active));
	json_object_object_add(ret, "public_listeners", json_object_new_int64(public_listeners));
	json_object_object_add(ret, "allocated", json_object_new_int64(VECTOR_LEN(ctx.udp_punch_socks)));
	json_object_object_add(ret, "sockets", sockets);
	return ret;
}

/** Dumps global punch-control task aggregation */
static json_object *dump_punch_task_summary(void) {
	size_t latest_tasks = 0;
	size_t waiting_tasks = 0;
	size_t relay_tasks = 0;
	size_t remote_result_tasks = 0;
	size_t candidate_added = 0;
	size_t handshake_sent = 0;
	size_t local_policy = 0;
	size_t result_accepted = 0;
	size_t result_handshake = 0;
	size_t result_suppressed = 0;
	size_t result_no_peer = 0;
	size_t result_busy = 0;
	int64_t min_next_retry = -1;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		const fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);
		const fastd_peer_punch_task_t *task = &peer->last_punch_task;
		if (!task->id)
			continue;

		latest_tasks++;
		if (task->next_retry != FASTD_TIMEOUT_INV && !fastd_timed_out(task->next_retry)) {
			int64_t remaining = timeout_remaining(task->next_retry);
			waiting_tasks++;
			if (min_next_retry < 0 || remaining < min_next_retry)
				min_next_retry = remaining;
		}

		switch (task->role) {
		case PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT:
		case PEER_PUNCH_TASK_ROLE_RELAY_DEST:
			relay_tasks++;
			break;

		case PEER_PUNCH_TASK_ROLE_RESULT_SENDER:
		case PEER_PUNCH_TASK_ROLE_RESULT_SUBJECT:
			remote_result_tasks++;
			break;

		default:
			break;
		}

		switch (task->cause) {
		case PEER_PUNCH_TASK_CAUSE_CANDIDATE_ADDED:
			candidate_added++;
			break;

		case PEER_PUNCH_TASK_CAUSE_HANDSHAKE_SENT:
			handshake_sent++;
			break;

		case PEER_PUNCH_TASK_CAUSE_LOCAL_POLICY:
			local_policy++;
			break;

		default:
			break;
		}

		switch (task->result) {
		case PEER_PUNCH_TASK_RESULT_ACCEPTED:
			result_accepted++;
			break;

		case PEER_PUNCH_TASK_RESULT_HANDSHAKE:
			result_handshake++;
			break;

		case PEER_PUNCH_TASK_RESULT_SUPPRESSED:
			result_suppressed++;
			break;

		case PEER_PUNCH_TASK_RESULT_NO_PEER:
			result_no_peer++;
			break;

		case PEER_PUNCH_TASK_RESULT_BUSY:
			result_busy++;
			break;

		default:
			break;
		}
	}

	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "latest_tasks", json_object_new_int64(latest_tasks));
	json_object_object_add(ret, "waiting_tasks", json_object_new_int64(waiting_tasks));
	json_object_object_add(ret, "relay_tasks", json_object_new_int64(relay_tasks));
	json_object_object_add(ret, "remote_result_tasks", json_object_new_int64(remote_result_tasks));
	json_object_object_add(ret, "candidate_added", json_object_new_int64(candidate_added));
	json_object_object_add(ret, "handshake_sent", json_object_new_int64(handshake_sent));
	json_object_object_add(ret, "local_policy", json_object_new_int64(local_policy));
	json_object_object_add(ret, "result_accepted", json_object_new_int64(result_accepted));
	json_object_object_add(ret, "result_handshake", json_object_new_int64(result_handshake));
	json_object_object_add(ret, "result_suppressed", json_object_new_int64(result_suppressed));
	json_object_object_add(ret, "result_no_peer", json_object_new_int64(result_no_peer));
	json_object_object_add(ret, "result_busy", json_object_new_int64(result_busy));
	json_object_object_add(
		ret, "next_retry_min_ms", min_next_retry >= 0 ? json_object_new_int64(min_next_retry) : NULL);
	return ret;
}

/** Returns a peer display name by runtime ID, if the peer still exists */
static json_object *wrap_peer_name_by_id(uint64_t id) {
	fastd_peer_t *peer = id ? fastd_peer_find_by_id(id) : NULL;
	return peer ? wrap_string_or_null(peer->name) : NULL;
}

/** Dumps one recent peer-pair task-manager lifecycle snapshot */
static json_object *dump_punch_pair_task(const fastd_punch_pair_task_t *task) {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "id", json_object_new_int64(task->id));
	json_object_object_add(ret, "updated_age", json_object_new_int64(timeout_age(task->updated)));
	json_object_object_add(ret, "stage", json_object_new_string(punch_pair_task_stage_name(task->stage)));
	json_object_object_add(ret, "peer_a_id", json_object_new_int64(task->peer_a_id));
	json_object_object_add(ret, "peer_b_id", json_object_new_int64(task->peer_b_id));
	json_object_object_add(ret, "peer_a", wrap_peer_name_by_id(task->peer_a_id));
	json_object_object_add(ret, "peer_b", wrap_peer_name_by_id(task->peer_b_id));
	json_object_object_add(ret, "subject_id", task->subject_id ? json_object_new_int64(task->subject_id) : NULL);
	json_object_object_add(
		ret, "destination_id", task->destination_id ? json_object_new_int64(task->destination_id) : NULL);
	json_object_object_add(ret, "subject", wrap_peer_name_by_id(task->subject_id));
	json_object_object_add(ret, "destination", wrap_peer_name_by_id(task->destination_id));
	json_object_object_add(ret, "candidates_sent", json_object_new_int(task->candidates_sent));
	json_object_object_add(ret, "backoff_skipped", json_object_new_int(task->backoff_skipped));
	json_object_object_add(ret, "budget_exhausted", json_object_new_boolean(task->budget_exhausted));
	json_object_object_add(
		ret, "next_retry_ms",
		task->next_retry != FASTD_TIMEOUT_INV && !fastd_timed_out(task->next_retry)
			? json_object_new_int64(timeout_remaining(task->next_retry))
			: NULL);
	return ret;
}

/** Dumps recent peer-pair task-manager lifecycle snapshots newest-first */
static json_object *dump_punch_pair_task_history(void) {
	struct json_object *ret = json_object_new_array();

	size_t i;
	for (i = 0; i < ctx.punch_pair_task_count; i++) {
		size_t pos = (ctx.punch_pair_task_pos + FASTD_PUNCH_PAIR_TASK_HISTORY - 1 - i) %
			     FASTD_PUNCH_PAIR_TASK_HISTORY;
		if (ctx.punch_pair_tasks[pos].id)
			json_object_array_add(ret, dump_punch_pair_task(&ctx.punch_pair_tasks[pos]));
	}

	return ret;
}

/** Dumps punch task-manager runtime counters */
static json_object *dump_punch_task_manager(void) {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "runs", json_object_new_int64(ctx.punch_task_manager_runs));
	json_object_object_add(ret, "pairs", json_object_new_int64(ctx.punch_task_manager_pairs));
	json_object_object_add(ret, "collected", json_object_new_int64(ctx.punch_task_manager_collected));
	json_object_object_add(ret, "launched", json_object_new_int64(ctx.punch_task_manager_launched));
	json_object_object_add(ret, "waiting", json_object_new_int64(ctx.punch_task_manager_waiting));
	json_object_object_add(ret, "in_flight", json_object_new_int64(ctx.punch_task_manager_in_flight));
	json_object_object_add(ret, "missing_metadata", json_object_new_int64(ctx.punch_task_manager_missing_metadata));
	json_object_object_add(ret, "blacklisted", json_object_new_int64(ctx.punch_task_manager_blacklisted));
	json_object_object_add(ret, "suppressed", json_object_new_int64(ctx.punch_task_manager_suppressed));
	json_object_object_add(ret, "aborted", json_object_new_int64(ctx.punch_task_manager_aborted));
	json_object_object_add(ret, "recent_demand", json_object_new_int64(ctx.punch_task_manager_recent_demand));
	json_object_object_add(ret, "runtime_states", json_object_new_int64(VECTOR_LEN(ctx.punch_pair_states)));
	json_object_object_add(ret, "runtime_limit", json_object_new_int64(FASTD_PUNCH_PAIR_STATE_LIMIT));
	json_object_object_add(ret, "budget_exhausted", json_object_new_int64(ctx.punch_task_manager_budget_exhausted));
	json_object_object_add(
		ret, "next_retry_min_ms",
		ctx.punch_task_manager_next_retry != FASTD_TIMEOUT_INV && !fastd_timed_out(ctx.punch_task_manager_next_retry)
			? json_object_new_int64(timeout_remaining(ctx.punch_task_manager_next_retry))
			: NULL);
	json_object_object_add(ret, "outcome_success", json_object_new_int64(ctx.punch_task_manager_outcome_success));
	json_object_object_add(ret, "outcome_failed", json_object_new_int64(ctx.punch_task_manager_outcome_failed));
	json_object_object_add(ret, "outcome_accepted", json_object_new_int64(ctx.punch_task_manager_outcome_accepted));
	json_object_object_add(ret, "outcome_handshake", json_object_new_int64(ctx.punch_task_manager_outcome_handshake));
	json_object_object_add(ret, "outcome_suppressed", json_object_new_int64(ctx.punch_task_manager_outcome_suppressed));
	json_object_object_add(ret, "outcome_no_peer", json_object_new_int64(ctx.punch_task_manager_outcome_no_peer));
	json_object_object_add(ret, "outcome_busy", json_object_new_int64(ctx.punch_task_manager_outcome_busy));
	json_object_object_add(ret, "history_limit", json_object_new_int64(FASTD_PUNCH_PAIR_TASK_HISTORY));
	json_object_object_add(ret, "history_count", json_object_new_int64(ctx.punch_pair_task_count));
	json_object_object_add(ret, "history", dump_punch_pair_task_history());
	return ret;
}

/** Dumps punch control status as a JSON object */
static json_object *dump_punch(void) {
	struct json_object *ret = json_object_new_object();
	json_object_object_add(ret, "nat_traversal", json_object_new_boolean(fastd_peer_get_nat_traversal(NULL)));
	json_object_object_add(ret, "control_relay", json_object_new_boolean(conf.punch_control_relay));
	json_object_object_add(ret, "data_relay", json_object_new_boolean(fastd_peer_get_punch_data_relay()));
	json_object_object_add(ret, "data_relay_explicit", json_object_new_boolean(conf.punch_data_relay.set));
	json_object_object_add(ret, "symmetric", json_object_new_boolean(conf.punch_symmetric));
	json_object_object_add(ret, "keepalive", json_object_new_boolean(conf.punch_keepalive));
	json_object_object_add(ret, "keepalive_interval", json_object_new_int64(conf.punch_keepalive_interval / 1000));
	json_object_object_add(
		ret, "maintenance_interval", json_object_new_int64(conf.punch_maintenance_interval / 1000));
	json_object_object_add(ret, "announce_interval", json_object_new_int64(conf.punch_announce_interval / 1000));
	json_object_object_add(ret, "relay_interval", json_object_new_int64(conf.punch_relay_interval / 1000));
	json_object_object_add(ret, "max_sockets", json_object_new_int64(conf.punch_max_sockets));
	json_object_object_add(ret, "max_packets", json_object_new_int64(conf.punch_max_packets));
	json_object_object_add(ret, "max_attempts", json_object_new_int64(conf.punch_max_attempts));
	json_object_object_add(ret, "max_backups", json_object_new_int64(conf.punch_max_backups));

	size_t active_candidates = 0;
	size_t active_suppressions = 0;
	size_t active_relay_backoffs = 0;
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		active_candidates += fastd_peer_direct_candidate_count_by_source(
			VECTOR_INDEX(ctx.peers, i), DIRECT_CANDIDATE_PUNCH_CONTROL);
		active_suppressions += fastd_peer_punch_suppression_count(VECTOR_INDEX(ctx.peers, i));
		active_relay_backoffs += fastd_peer_punch_relay_backoff_count(VECTOR_INDEX(ctx.peers, i));
	}
	json_object_object_add(ret, "active_candidates", json_object_new_int64(active_candidates));
	json_object_object_add(ret, "active_suppressions", json_object_new_int64(active_suppressions));
	json_object_object_add(ret, "active_relay_backoffs", json_object_new_int64(active_relay_backoffs));
	json_object_object_add(ret, "udp_punch_socket_pool", dump_udp_punch_socket_pool());
	json_object_object_add(ret, "task_summary", dump_punch_task_summary());
	json_object_object_add(ret, "task_manager", dump_punch_task_manager());

	struct json_object *counters = json_object_new_object();
	json_object_object_add(counters, "control_tx", json_object_new_int64(ctx.punch_control_tx));
	json_object_object_add(counters, "control_rx", json_object_new_int64(ctx.punch_control_rx));
	json_object_object_add(counters, "direct_handshakes", json_object_new_int64(ctx.punch_direct_handshakes));
	json_object_object_add(counters, "direct_success", json_object_new_int64(ctx.punch_direct_success));
	json_object_object_add(counters, "direct_failures", json_object_new_int64(ctx.punch_direct_failures));
	json_object_object_add(counters, "direct_suppressed", json_object_new_int64(ctx.punch_direct_suppressed));
	json_object_object_add(counters, "udp_exact_tx", json_object_new_int64(ctx.punch_udp_exact_tx));
	json_object_object_add(counters, "probe_tx", json_object_new_int64(ctx.punch_probe_tx));
	json_object_object_add(counters, "probe_rx", json_object_new_int64(ctx.punch_probe_rx));
	json_object_object_add(counters, "probe_response_tx", json_object_new_int64(ctx.punch_probe_response_tx));
	json_object_object_add(counters, "probe_matched", json_object_new_int64(ctx.punch_probe_matched));
	json_object_object_add(counters, "probe_handshakes", json_object_new_int64(ctx.punch_probe_handshakes));
	json_object_object_add(counters, "result_tx", json_object_new_int64(ctx.punch_result_tx));
	json_object_object_add(counters, "result_rx", json_object_new_int64(ctx.punch_result_rx));
	json_object_object_add(counters, "result_accepted", json_object_new_int64(ctx.punch_result_accepted));
	json_object_object_add(counters, "result_handshake", json_object_new_int64(ctx.punch_result_handshake));
	json_object_object_add(counters, "result_suppressed", json_object_new_int64(ctx.punch_result_suppressed));
	json_object_object_add(counters, "result_no_peer", json_object_new_int64(ctx.punch_result_no_peer));
	json_object_object_add(counters, "result_busy", json_object_new_int64(ctx.punch_result_busy));
	json_object_object_add(ret, "counters", counters);

	return ret;
}

#ifdef WITH_TESTS

/** Test wrapper for punch control status */
struct json_object *fastd_status_test_dump_punch(void) {
	return dump_punch();
}

#endif

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

		if (conf.mode == MODE_TAP || conf.mode == MODE_MULTITAP) {
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
