// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   External rendezvous support for peer hole punching
*/

#include "realm.h"
#include "async.h"
#include "nat_detect.h"
#include "peer.h"

#ifdef WITH_REALM
#include <curl/curl.h>
#include <json-c/json.h>
#include <stun/stunagent.h>
#include <stun/usages/bind.h>

#include <netdb.h>
#include <unistd.h>
#endif


#define FASTD_REALM_INTERVAL 5000
#define FASTD_REALM_STUN_INTERVAL 15000
#define FASTD_REALM_STUN_BUFSIZE 512
#define FASTD_REALM_HTTP_TIMEOUT 12L


/** Returns true if a metadata field is absent */
static bool field_empty(const char *str) {
	return !str || !str[0];
}

/** Runtime state for the realm rendezvous control plane */
struct fastd_realm_state {
	fastd_task_t task; /**< Periodic maintenance task */

#ifdef WITH_REALM
	pthread_mutex_t mutex; /**< Protects fields updated by worker threads */
	bool worker_running;   /**< true while a periodic HTTP worker is active */
	bool events_running;   /**< true while an SSE event worker is active */
	bool stopping;         /**< true while realm cleanup is waiting for workers */
	char *session_id;      /**< Current realm session token */

	StunAgent stun_agent;             /**< STUN transaction state */
	bool stun_pending;                /**< true while a STUN binding request is in flight */
	fastd_peer_address_t stun_server; /**< Resolved STUN server address */
	fastd_peer_address_t reflexive;   /**< Last server-reflexive UDP endpoint */
	fastd_timeout_t next_stun;        /**< Next time a STUN request should be sent */
#endif
};

#ifdef WITH_REALM

/** A dynamically-sized HTTP response body */
typedef struct realm_http_response {
	char *data; /**< Response bytes with a NUL terminator */
	size_t len; /**< Response length without the NUL terminator */
} realm_http_response_t;

/** A worker-owned snapshot of one peer's realm configuration */
typedef struct realm_peer_snapshot {
	char *realm; /**< Remote realm ID */
} realm_peer_snapshot_t;

/** Worker-owned snapshot of the realm configuration */
typedef struct realm_worker {
	char *server;       /**< Base URL */
	char *token;        /**< Shared bearer token */
	char *id;           /**< Own realm ID */
	char *session_id;   /**< Current session token, if any */
	char **addresses;   /**< Own candidate addresses formatted as addr:port */
	size_t n_addresses; /**< Number of own candidate addresses */

	realm_peer_snapshot_t *peers; /**< Peers to actively probe */
	size_t n_peers;               /**< Number of peer snapshots */
} realm_worker_t;

static char *format_address(const fastd_peer_address_t *addr);

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

/** Frees an HTTP response body */
static void free_http_response(realm_http_response_t *resp) {
	free(resp->data);
	*resp = (realm_http_response_t){};
}

/** Formats a byte array as lowercase hex */
static char *hex_encode(const uint8_t *data, size_t len) {
	static const char hexdigits[] = "0123456789abcdef";

	char *ret = fastd_alloc(2 * len + 1);
	size_t i;
	for (i = 0; i < len; i++) {
		ret[2 * i] = hexdigits[data[i] >> 4];
		ret[2 * i + 1] = hexdigits[data[i] & 0xf];
	}
	ret[2 * len] = 0;
	return ret;
}

/** Generates a random hex field */
static char *random_hex(size_t bytes) {
	uint8_t buf[bytes];
	fastd_random_bytes(buf, sizeof(buf), false);
	return hex_encode(buf, sizeof(buf));
}

/** Appends bytes from libcurl into a response buffer */
static size_t http_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
	realm_http_response_t *resp = userdata;
	size_t len = size * nmemb;

	resp->data = fastd_realloc(resp->data, resp->len + len + 1);
	memcpy(resp->data + resp->len, ptr, len);
	resp->len += len;
	resp->data[resp->len] = 0;

	return len;
}

/** Issues one JSON HTTP request using libcurl */
static bool http_json_request(
	const char *method, const char *url, const char *bearer, struct json_object *body,
	realm_http_response_t *response, long *status) {
	CURL *curl = curl_easy_init();
	if (!curl)
		return false;

	struct curl_slist *headers = NULL;
	const char *bearer_value = bearer ?: "";
	char *auth_header = fastd_alloc(strlen(bearer_value) + 23);
	sprintf(auth_header, "Authorization: Bearer %s", bearer_value);
	headers = curl_slist_append(headers, auth_header);
	free(auth_header);
	headers = curl_slist_append(headers, "Content-Type: application/json");

	const char *body_str = body ? json_object_to_json_string_ext(body, JSON_C_TO_STRING_PLAIN) : "";

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, FASTD_REALM_HTTP_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "fastd-realm/1");

	if (!strcmp(method, "POST")) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body_str));
	}

	CURLcode ret = curl_easy_perform(curl);
	if (ret == CURLE_OK)
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
	else
		pr_debug("realm HTTP request to `%s' failed: %s", url, curl_easy_strerror(ret));

	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	return ret == CURLE_OK;
}

/** Builds a realm API URL */
static char *realm_url(const realm_worker_t *work, const char *realm, const char *suffix) {
	const char *path = suffix ?: "";
	size_t server_len = strlen(work->server);
	bool slash = server_len && work->server[server_len - 1] == '/';

	char *ret = fastd_alloc(server_len + strlen(realm) + strlen(path) + 6);
	sprintf(ret, "%s%sv1/%s%s", work->server, slash ? "" : "/", realm, path);
	return ret;
}

/** Adds a string address to a JSON array, avoiding exact duplicates */
static void json_address_array_add_unique(struct json_object *addresses, const char *addr) {
	size_t i, len = json_object_array_length(addresses);
	for (i = 0; i < len; i++) {
		struct json_object *item = json_object_array_get_idx(addresses, i);
		if (strequal(json_object_get_string(item), addr))
			return;
	}

	json_object_array_add(addresses, json_object_new_string(addr));
}

/** Adds the currently best known own addresses to a JSON object */
static void json_add_addresses(struct json_object *obj, const realm_worker_t *work) {
	struct json_object *addresses = json_object_new_array();

	if (ctx.realm) {
		pthread_mutex_lock(&ctx.realm->mutex);
		if (ctx.realm->reflexive.sa.sa_family != AF_UNSPEC) {
			char *formatted = format_address(&ctx.realm->reflexive);
			if (formatted) {
				json_address_array_add_unique(addresses, formatted);
				free(formatted);
			}
		}
		pthread_mutex_unlock(&ctx.realm->mutex);
	}

	size_t i;
	for (i = 0; i < work->n_addresses; i++)
		json_address_array_add_unique(addresses, work->addresses[i]);

	json_object_object_add(obj, "addresses", addresses);
}

/** Parses a JSON object from an HTTP response */
static struct json_object *parse_json_response(const realm_http_response_t *response) {
	if (!response->data)
		return NULL;

	return json_tokener_parse(response->data);
}

/** Formats a fastd address as addr:port for JSON requests */
static char *format_address(const fastd_peer_address_t *addr) {
	char host[INET6_ADDRSTRLEN + IFNAMSIZ + 1];
	char port[16];

	if (getnameinfo(
		    &addr->sa, address_len(addr), host, sizeof(host), port, sizeof(port),
		    NI_NUMERICHOST | NI_NUMERICSERV))
		return NULL;

	if (addr->sa.sa_family == AF_INET6) {
		char *ret = fastd_alloc(strlen(host) + strlen(port) + 4);
		sprintf(ret, "[%s]:%s", host, port);
		return ret;
	}

	char *ret = fastd_alloc(strlen(host) + strlen(port) + 2);
	sprintf(ret, "%s:%s", host, port);
	return ret;
}

/** Returns true if an address can be advertised as a public candidate */
static bool address_is_advertisable(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return addr->in.sin_addr.s_addr != INADDR_ANY && addr->in.sin_port;

	case AF_INET6:
		return !IN6_IS_ADDR_UNSPECIFIED(&addr->in6.sin6_addr) && addr->in6.sin6_port;

	default:
		return false;
	}
}

/** Adds one formatted address to a worker snapshot */
static void worker_add_address(realm_worker_t *work, const fastd_peer_address_t *addr) {
	if (!address_is_advertisable(addr))
		return;

	char *formatted = format_address(addr);
	if (!formatted)
		return;

	work->addresses = fastd_realloc_array(work->addresses, work->n_addresses + 1, sizeof(char *));
	work->addresses[work->n_addresses++] = formatted;
}

/** Sets an address port from host byte order */
static void set_address_port(fastd_peer_address_t *addr, uint16_t port) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		addr->in.sin_port = htons(port);
		return;

	case AF_INET6:
		addr->in6.sin6_port = htons(port);
		return;
	}
}

/** Returns true if a NAT type preserves the local UDP source port */
static bool nat_type_preserves_port(fastd_nat_type_t type) {
	switch (type) {
	case FASTD_NAT_OPEN_INTERNET:
	case FASTD_NAT_NO_PAT:
	case FASTD_NAT_SYM_UDP_FIREWALL:
		return true;

	default:
		return false;
	}
}

/** Adds NAT-detected public addresses for fixed sockets when the detected NAT preserves ports */
static void worker_add_nat_addresses(realm_worker_t *work) {
	fastd_nat_status_t status = {};
	if (!fastd_nat_get_status(&status) || !status.available || !nat_type_preserves_port(status.type))
		return;

	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		const fastd_socket_t *sock = &ctx.socks[i];
		if (!sock->bound_addr || sock->bound_addr->sa.sa_family != status.reflexive.sa.sa_family)
			continue;

		uint16_t port = ntohs(fastd_peer_address_get_port(sock->bound_addr));
		if (!port)
			continue;

		fastd_peer_address_t addr = status.reflexive;
		set_address_port(&addr, port);
		worker_add_address(work, &addr);
	}
}

/** Parses an addr:port string into a fastd address */
static bool parse_address_string(fastd_peer_address_t *out, const char *str) {
	char host[INET6_ADDRSTRLEN + IFNAMSIZ + 1];
	char port[16];
	const char *port_start = NULL;

	if (str[0] == '[') {
		const char *end = strchr(str, ']');
		if (!end || end[1] != ':')
			return false;

		size_t host_len = (size_t)(end - str - 1);
		if (host_len >= sizeof(host))
			return false;

		memcpy(host, str + 1, host_len);
		host[host_len] = 0;
		port_start = end + 2;
	} else {
		const char *colon = strrchr(str, ':');
		if (!colon)
			return false;

		size_t host_len = (size_t)(colon - str);
		if (host_len >= sizeof(host))
			return false;

		memcpy(host, str, host_len);
		host[host_len] = 0;
		port_start = colon + 1;
	}

	if (strlen(port_start) >= sizeof(port))
		return false;
	strcpy(port, port_start);

	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
	};
	struct addrinfo *res = NULL;
	int ret = getaddrinfo(host, port, &hints, &res);
	if (ret)
		return false;

	bool ok = false;
	if (res)
		ok = peer_address_from_sockaddr(out, res->ai_addr);

	freeaddrinfo(res);
	return ok;
}

/** Resolves the configured STUN server */
static bool resolve_stun_server(void) {
	if (!conf.realm.stun_host || !conf.realm.stun_port || ctx.realm->stun_server.sa.sa_family != AF_UNSPEC)
		return ctx.realm->stun_server.sa.sa_family != AF_UNSPEC;

	char port[16];
	snprintf(port, sizeof(port), "%u", conf.realm.stun_port);

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
	};
	struct addrinfo *res = NULL;
	int ret = getaddrinfo(conf.realm.stun_host, port, &hints, &res);
	if (ret) {
		pr_warn("unable to resolve realm STUN server `%s': %s", conf.realm.stun_host, gai_strerror(ret));
		return false;
	}

	bool ok = false;
	if (res)
		ok = peer_address_from_sockaddr(&ctx.realm->stun_server, res->ai_addr);

	freeaddrinfo(res);
	return ok;
}

/** Sends a STUN binding request from fastd's real UDP socket */
static void send_stun_request(void) {
	if (!ctx.realm || !conf.realm.stun_host || !fastd_timed_out(ctx.realm->next_stun))
		return;

	ctx.realm->next_stun = ctx.now + FASTD_REALM_STUN_INTERVAL;

	if (!resolve_stun_server())
		return;

	fastd_socket_t *sock = ctx.sock_default_v4;
	if (!sock || sock->type != SOCKET_TYPE_UDP || sock->fd.fd < 0)
		return;

	uint8_t buf[FASTD_REALM_STUN_BUFSIZE];
	StunMessage msg;

	stun_agent_init(
		&ctx.realm->stun_agent, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389,
		STUN_AGENT_USAGE_USE_FINGERPRINT);

	size_t len = stun_usage_bind_create(&ctx.realm->stun_agent, &msg, buf, sizeof(buf));
	if (!len)
		return;

	ssize_t sent =
		sendto(sock->fd.fd, buf, len, 0, &ctx.realm->stun_server.sa, address_len(&ctx.realm->stun_server));
	if (sent < 0) {
		pr_debug_errno("realm STUN sendto");
		return;
	}

	ctx.realm->stun_pending = true;
	pr_debug("sent realm STUN binding request to %I", &ctx.realm->stun_server);
}

/** Stores a freshly returned session ID */
static void set_session_id(const char *session_id) {
	if (!ctx.realm || !session_id)
		return;

	pthread_mutex_lock(&ctx.realm->mutex);
	free(ctx.realm->session_id);
	ctx.realm->session_id = fastd_strdup(session_id);
	pthread_mutex_unlock(&ctx.realm->mutex);
}

/** Clears the current realm session ID */
static void clear_session_id(void) {
	if (!ctx.realm)
		return;

	pthread_mutex_lock(&ctx.realm->mutex);
	free(ctx.realm->session_id);
	ctx.realm->session_id = NULL;
	pthread_mutex_unlock(&ctx.realm->mutex);
}

/** Registers the local realm and returns a worker-owned session ID */
static char *register_realm(const realm_worker_t *work) {
	struct json_object *body = json_object_new_object();
	json_add_addresses(body, work);

	char *url = realm_url(work, work->id, "");
	realm_http_response_t response = {};
	long status = 0;
	bool ok = http_json_request("POST", url, work->token, body, &response, &status);
	free(url);
	json_object_put(body);

	if (!ok || status != 200) {
		free_http_response(&response);
		return NULL;
	}

	struct json_object *root = parse_json_response(&response);
	free_http_response(&response);
	if (!root)
		return NULL;

	struct json_object *session = NULL;
	const char *session_str = NULL;
	if (json_object_object_get_ex(root, "session_id", &session))
		session_str = json_object_get_string(session);

	char *ret = session_str ? fastd_strdup(session_str) : NULL;
	json_object_put(root);
	return ret;
}

/** Refreshes the local realm session */
static bool heartbeat_realm(const realm_worker_t *work) {
	if (!work->session_id)
		return false;

	struct json_object *body = json_object_new_object();
	json_add_addresses(body, work);

	char *url = realm_url(work, work->id, "/heartbeat");
	realm_http_response_t response = {};
	long status = 0;
	bool ok = http_json_request("POST", url, work->session_id, body, &response, &status);
	free(url);
	free_http_response(&response);
	json_object_put(body);

	return ok && status == 200;
}

/** Enqueues direct candidates from a JSON address array */
static void enqueue_address_candidates(const char *source_id, const char *source_key, struct json_object *addresses) {
	if (!json_object_is_type(addresses, json_type_array))
		return;

	fastd_async_realm_candidate_t candidate = {};
	if (source_id)
		strncpy(candidate.source_id, source_id, sizeof(candidate.source_id) - 1);
	if (source_key)
		strncpy(candidate.source_key, source_key, sizeof(candidate.source_key) - 1);

	size_t len = json_object_array_length(addresses);
	size_t i;
	for (i = 0; i < len && candidate.n_addr < FASTD_REALM_MAX_ADDRESSES; i++) {
		struct json_object *item = json_object_array_get_idx(addresses, i);
		const char *addr = json_object_get_string(item);
		if (!addr)
			continue;

		if (parse_address_string(&candidate.addr[candidate.n_addr], addr))
			candidate.n_addr++;
	}

	if (candidate.n_addr)
		fastd_async_enqueue(ASYNC_TYPE_REALM_CANDIDATE, &candidate, sizeof(candidate));
}

/** Enqueues direct candidates returned from a connect response */
static void enqueue_connect_candidates(const char *realm, struct json_object *root) {
	struct json_object *addresses = NULL;
	if (!json_object_object_get_ex(root, "addresses", &addresses))
		return;

	enqueue_address_candidates(realm, NULL, addresses);
}

/** Sends a connect request for one peer realm */
static void connect_peer_realm(const realm_worker_t *work, const char *realm) {
	char *nonce = random_hex(16);
	char *obfs = random_hex(32);

	struct json_object *body = json_object_new_object();
	json_add_addresses(body, work);
	json_object_object_add(body, "nonce", json_object_new_string(nonce));
	json_object_object_add(body, "obfs", json_object_new_string(obfs));

	char *url = realm_url(work, realm, "/connect");
	realm_http_response_t response = {};
	long status = 0;
	bool ok = http_json_request("POST", url, work->token, body, &response, &status);
	free(url);
	free(nonce);
	free(obfs);
	json_object_put(body);

	if (!ok || status != 200) {
		free_http_response(&response);
		return;
	}

	struct json_object *root = parse_json_response(&response);
	free_http_response(&response);
	if (!root)
		return;

	enqueue_connect_candidates(realm, root);
	json_object_put(root);
}

/** Posts the local fresh addresses for a pending connect attempt */
static void post_connect_response(const realm_worker_t *work, const char *nonce) {
	if (!work->session_id || !nonce)
		return;

	struct json_object *body = json_object_new_object();
	json_add_addresses(body, work);

	char suffix[FASTD_REALM_MAX_FIELD + 16];
	snprintf(suffix, sizeof(suffix), "/connects/%s", nonce);

	char *url = realm_url(work, work->id, suffix);
	realm_http_response_t response = {};
	long status = 0;
	http_json_request("POST", url, work->session_id, body, &response, &status);

	free(url);
	free_http_response(&response);
	json_object_put(body);
}

/** Handles one SSE punch event */
static void handle_punch_event(const realm_worker_t *work, const char *data) {
	struct json_object *root = json_tokener_parse(data);
	if (!root)
		return;

	struct json_object *addresses = NULL, *nonce = NULL, *source_id = NULL, *source_key = NULL;
	const char *source_id_str = NULL, *source_key_str = NULL, *nonce_str = NULL;

	if (json_object_object_get_ex(root, "source_id", &source_id))
		source_id_str = json_object_get_string(source_id);
	if (json_object_object_get_ex(root, "source_key", &source_key))
		source_key_str = json_object_get_string(source_key);
	if (json_object_object_get_ex(root, "nonce", &nonce))
		nonce_str = json_object_get_string(nonce);

	if (json_object_object_get_ex(root, "addresses", &addresses))
		enqueue_address_candidates(source_id_str, source_key_str, addresses);

	post_connect_response(work, nonce_str);
	json_object_put(root);
}

/** Streaming state for a single SSE connection */
typedef struct realm_sse_state {
	realm_worker_t *work; /**< Worker snapshot */
	char *line;           /**< Current input line */
	size_t line_len;      /**< Current input line length */
	char *event;          /**< Current SSE event name */
	char *data;           /**< Current SSE data field */
} realm_sse_state_t;

/** Returns true while realm workers should continue network I/O */
static bool realm_should_continue(void) {
	if (!ctx.realm)
		return false;

	pthread_mutex_lock(&ctx.realm->mutex);
	bool ret = !ctx.realm->stopping;
	pthread_mutex_unlock(&ctx.realm->mutex);
	return ret;
}

/** Clears one accumulated SSE event */
static void sse_clear_event(realm_sse_state_t *sse) {
	free(sse->event);
	free(sse->data);
	sse->event = NULL;
	sse->data = NULL;
}

/** Dispatches an accumulated SSE event */
static void sse_dispatch(realm_sse_state_t *sse) {
	if (strequal(sse->event, "punch") && sse->data)
		handle_punch_event(sse->work, sse->data);

	sse_clear_event(sse);
}

/** Stores one SSE field value */
static void sse_set_value(char **dst, const char *value) {
	free(*dst);
	*dst = fastd_strdup(value);
}

/** Appends one data line to the current SSE data buffer */
static void sse_append_data(realm_sse_state_t *sse, const char *value) {
	size_t old_len = sse->data ? strlen(sse->data) : 0;
	size_t value_len = strlen(value);
	size_t extra = old_len ? 1 : 0;

	sse->data = fastd_realloc(sse->data, old_len + extra + value_len + 1);
	if (extra)
		sse->data[old_len++] = '\n';
	memcpy(sse->data + old_len, value, value_len + 1);
}

/** Handles a complete SSE line */
static void sse_handle_line(realm_sse_state_t *sse) {
	if (!sse->line_len) {
		sse_dispatch(sse);
		return;
	}

	if (sse->line[0] == ':')
		return;

	char *colon = strchr(sse->line, ':');
	if (!colon)
		return;

	*colon = 0;
	const char *value = colon + 1;
	if (*value == ' ')
		value++;

	if (!strcmp(sse->line, "event"))
		sse_set_value(&sse->event, value);
	else if (!strcmp(sse->line, "data"))
		sse_append_data(sse, value);
}

/** Appends one byte to the current SSE input line */
static void sse_append_char(realm_sse_state_t *sse, char c) {
	sse->line = fastd_realloc(sse->line, sse->line_len + 2);
	sse->line[sse->line_len++] = c;
	sse->line[sse->line_len] = 0;
}

/** libcurl streaming write callback for SSE data */
static size_t sse_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
	realm_sse_state_t *sse = userdata;
	size_t len = size * nmemb;

	if (!realm_should_continue())
		return 0;

	size_t i;
	for (i = 0; i < len; i++) {
		char c = ptr[i];
		if (c == '\r')
			continue;

		if (c == '\n') {
			sse_handle_line(sse);
			free(sse->line);
			sse->line = NULL;
			sse->line_len = 0;
			continue;
		}

		sse_append_char(sse, c);
	}

	return len;
}

/** Aborts long-running libcurl work during shutdown */
static int curl_progress_cb(
	void *clientp, UNUSED curl_off_t dltotal, UNUSED curl_off_t dlnow, UNUSED curl_off_t ultotal,
	UNUSED curl_off_t ulnow) {
	(void)clientp;
	return realm_should_continue() ? 0 : 1;
}

/** Opens and processes the realm SSE stream */
static void run_events_stream(realm_worker_t *work) {
	if (!work->session_id)
		return;

	char *url = realm_url(work, work->id, "/events");
	CURL *curl = curl_easy_init();
	if (!curl) {
		free(url);
		return;
	}

	struct curl_slist *headers = NULL;
	char *auth_header = fastd_alloc(strlen(work->session_id) + 23);
	sprintf(auth_header, "Authorization: Bearer %s", work->session_id);
	headers = curl_slist_append(headers, auth_header);
	free(auth_header);
	headers = curl_slist_append(headers, "Accept: text/event-stream");

	realm_sse_state_t sse = { .work = work };

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sse_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sse);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 65L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "fastd-realm/1");
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, curl_progress_cb);

	(void)curl_easy_perform(curl);

	sse_clear_event(&sse);
	free(sse.line);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	free(url);
}

/** Frees a worker snapshot */
static void free_worker(realm_worker_t *work) {
	if (!work)
		return;

	size_t i;
	free(work->server);
	free(work->token);
	free(work->id);
	free(work->session_id);

	for (i = 0; i < work->n_addresses; i++)
		free(work->addresses[i]);
	free(work->addresses);

	for (i = 0; i < work->n_peers; i++)
		free(work->peers[i].realm);
	free(work->peers);

	free(work);
}

/** Marks the periodic HTTP worker as stopped */
static void worker_done(void) {
	if (!ctx.realm)
		return;

	pthread_mutex_lock(&ctx.realm->mutex);
	ctx.realm->worker_running = false;
	pthread_mutex_unlock(&ctx.realm->mutex);
}

/** Marks the SSE event worker as stopped */
static void event_worker_done(void) {
	if (!ctx.realm)
		return;

	pthread_mutex_lock(&ctx.realm->mutex);
	ctx.realm->events_running = false;
	pthread_mutex_unlock(&ctx.realm->mutex);
}

/** Periodic HTTP worker entry point */
static void *realm_worker_thread(void *arg) {
	realm_worker_t *work = arg;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	char *session_id = fastd_strdup(work->session_id);
	if (!session_id) {
		session_id = register_realm(work);
		if (session_id)
			set_session_id(session_id);
	}

	if (session_id) {
		free(work->session_id);
		work->session_id = fastd_strdup(session_id);
		if (!heartbeat_realm(work)) {
			clear_session_id();
			free(session_id);
			session_id = register_realm(work);
			if (session_id)
				set_session_id(session_id);
		}
	}

	size_t i;
	for (i = 0; i < work->n_peers; i++)
		connect_peer_realm(work, work->peers[i].realm);

	free(session_id);
	free_worker(work);
	worker_done();
	return NULL;
}

/** SSE event worker entry point */
static void *realm_event_thread(void *arg) {
	realm_worker_t *work = arg;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	run_events_stream(work);

	free_worker(work);
	event_worker_done();
	return NULL;
}

/** Creates a worker-owned snapshot of the current realm state */
static realm_worker_t *create_worker(void) {
	realm_worker_t *work = fastd_new0(realm_worker_t);
	work->server = fastd_strdup(conf.realm.server);
	work->token = fastd_strdup(conf.realm.token);
	work->id = fastd_strdup(conf.realm.id);

	pthread_mutex_lock(&ctx.realm->mutex);
	work->session_id = fastd_strdup(ctx.realm->session_id);
	if (ctx.realm->reflexive.sa.sa_family != AF_UNSPEC)
		worker_add_address(work, &ctx.realm->reflexive);
	pthread_mutex_unlock(&ctx.realm->mutex);

	worker_add_nat_addresses(work);

	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		fastd_peer_address_t mapped_addr;
		if (fastd_port_mapping_get_external_address(&ctx.socks[i], &mapped_addr))
			worker_add_address(work, &mapped_addr);
	}

	if (!work->n_addresses && ctx.sock_default_v4 && ctx.sock_default_v4->bound_addr)
		worker_add_address(work, ctx.sock_default_v4->bound_addr);

	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);
		if (!peer->realm || !fastd_peer_is_enabled(peer) || fastd_peer_is_established(peer))
			continue;

		work->peers = fastd_realloc_array(work->peers, work->n_peers + 1, sizeof(realm_peer_snapshot_t));
		work->peers[work->n_peers++].realm = fastd_strdup(peer->realm);
	}

	if (!work->n_addresses) {
		free_worker(work);
		return NULL;
	}

	return work;
}

/** Starts a periodic HTTP worker if none is running */
static void start_worker(void) {
	pthread_mutex_lock(&ctx.realm->mutex);
	if (ctx.realm->worker_running || ctx.realm->stopping) {
		pthread_mutex_unlock(&ctx.realm->mutex);
		return;
	}
	ctx.realm->worker_running = true;
	pthread_mutex_unlock(&ctx.realm->mutex);

	realm_worker_t *work = create_worker();
	if (!work) {
		worker_done();
		return;
	}

	pthread_t thread;
	if (pthread_create(&thread, &ctx.detached_thread, realm_worker_thread, work)) {
		pr_warn_errno("pthread_create");
		free_worker(work);
		worker_done();
	}
}

/** Starts the SSE event worker if there is a registered session */
static void start_events_worker(void) {
	pthread_mutex_lock(&ctx.realm->mutex);
	if (ctx.realm->events_running || ctx.realm->stopping || !ctx.realm->session_id) {
		pthread_mutex_unlock(&ctx.realm->mutex);
		return;
	}
	ctx.realm->events_running = true;
	pthread_mutex_unlock(&ctx.realm->mutex);

	realm_worker_t *work = create_worker();
	if (!work || !work->session_id) {
		free_worker(work);
		event_worker_done();
		return;
	}

	pthread_t thread;
	if (pthread_create(&thread, &ctx.detached_thread, realm_event_thread, work)) {
		pr_warn_errno("pthread_create");
		free_worker(work);
		event_worker_done();
	}
}

#endif


/** Returns true if any configured peer uses an external realm */
static bool realm_has_peers(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		if (VECTOR_INDEX(ctx.peers, i)->realm)
			return true;
	}

	return false;
}

/** Finds a peer by its configured realm ID */
static fastd_peer_t *find_peer_by_realm(const char *realm) {
	if (!realm)
		return NULL;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);
		if (strequal(peer->realm, realm))
			return peer;
	}

	return NULL;
}

/** Finds a peer by the protocol public key string, if the protocol supports parsing it */
static fastd_peer_t *find_peer_by_key_string(const char *key_string) {
	if (!key_string || !conf.protocol->read_key || !conf.protocol->find_peer)
		return NULL;

	fastd_protocol_key_t *key = conf.protocol->read_key(key_string);
	if (!key)
		return NULL;

	fastd_peer_t *peer = conf.protocol->find_peer(key);
	free(key);
	return peer;
}

/** Injects rendezvous-discovered direct candidates into the peer state */
void fastd_realm_add_candidate(
	const char *source_id, const char *source_key, const fastd_peer_address_t *addresses, size_t n_addresses) {
	if (!n_addresses)
		return;

	if (field_empty(source_id) && field_empty(source_key)) {
		size_t peer_idx;
		for (peer_idx = 0; peer_idx < VECTOR_LEN(ctx.peers); peer_idx++) {
			fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, peer_idx);
			if (!peer->realm || !fastd_peer_is_enabled(peer) || fastd_peer_is_established(peer))
				continue;

			size_t addr_idx;
			for (addr_idx = 0; addr_idx < n_addresses; addr_idx++)
				fastd_peer_add_direct_candidate(peer, NULL, &addresses[addr_idx], NULL, 0);
		}

		return;
	}

	fastd_peer_t *peer = find_peer_by_key_string(source_key);
	if (!peer)
		peer = find_peer_by_realm(source_id);

	if (!peer || !fastd_peer_is_enabled(peer))
		return;

	size_t i;
	for (i = 0; i < n_addresses; i++)
		fastd_peer_add_direct_candidate(peer, NULL, &addresses[i], NULL, 0);
}

/** Handles an inbound STUN response, if it belongs to the active realm transaction */
bool fastd_realm_handle_stun_response(
	UNUSED const fastd_peer_address_t *remote_addr, UNUSED const void *data, UNUSED size_t len) {
#ifdef WITH_REALM
	if (!ctx.realm || !ctx.realm->stun_pending || len < 20)
		return false;

	StunMessage msg;
	StunValidationStatus status = stun_agent_validate(&ctx.realm->stun_agent, &msg, data, len, NULL, NULL);
	if (status == STUN_VALIDATION_NOT_STUN)
		return false;

	if (status != STUN_VALIDATION_SUCCESS) {
		pr_debug("ignoring invalid realm STUN response from %I", remote_addr);
		return true;
	}

	struct sockaddr_storage mapped;
	socklen_t mapped_len = sizeof(mapped);
	struct sockaddr_storage alternate;
	socklen_t alternate_len = sizeof(alternate);

	StunUsageBindReturn ret = stun_usage_bind_process(
		&msg, (struct sockaddr *)&mapped, &mapped_len, (struct sockaddr *)&alternate, &alternate_len);
	if (ret != STUN_USAGE_BIND_RETURN_SUCCESS) {
		pr_debug("realm STUN response from %I did not contain a usable mapped address", remote_addr);
		return true;
	}

	if (!peer_address_from_sockaddr(&ctx.realm->reflexive, (struct sockaddr *)&mapped))
		return true;

	ctx.realm->stun_pending = false;
	pr_verbose("realm STUN discovered UDP endpoint %I", &ctx.realm->reflexive);
	return true;
#else
	return false;
#endif
}

/** Checks whether realm configuration is usable */
bool fastd_realm_check(void) {
	if (!realm_has_peers())
		return true;

	if (!conf.realm.server || !conf.realm.token || !conf.realm.id) {
		pr_error("realm peer configured, but no global `realm server' is configured");
		return false;
	}

#ifndef WITH_REALM
	pr_error("realm rendezvous is not supported by this build of fastd");
	return false;
#else
	return true;
#endif
}

/** Starts the realm rendezvous control plane */
void fastd_realm_init(void) {
	if (!realm_has_peers())
		return;

	ctx.realm = fastd_new0(fastd_realm_state_t);
#ifdef WITH_REALM
	if (pthread_mutex_init(&ctx.realm->mutex, NULL))
		exit_errno("pthread_mutex_init");
#endif
	fastd_task_schedule(&ctx.realm->task, TASK_TYPE_REALM, ctx.now + FASTD_REALM_INTERVAL);
}

/** Runs periodic realm maintenance */
void fastd_realm_handle_task(void) {
	if (!ctx.realm)
		return;

#ifdef WITH_REALM
	send_stun_request();
	start_worker();
	start_events_worker();
#endif

	fastd_task_schedule(&ctx.realm->task, TASK_TYPE_REALM, ctx.now + FASTD_REALM_INTERVAL);
}

/** Stops the realm rendezvous control plane */
void fastd_realm_cleanup(void) {
	if (!ctx.realm)
		return;

	fastd_task_unschedule(&ctx.realm->task);
#ifdef WITH_REALM
	pthread_mutex_lock(&ctx.realm->mutex);
	ctx.realm->stopping = true;
	while (ctx.realm->worker_running || ctx.realm->events_running) {
		pthread_mutex_unlock(&ctx.realm->mutex);
		usleep(10000);
		pthread_mutex_lock(&ctx.realm->mutex);
	}
	free(ctx.realm->session_id);
	ctx.realm->session_id = NULL;
	pthread_mutex_unlock(&ctx.realm->mutex);
	pthread_mutex_destroy(&ctx.realm->mutex);
#endif
	free(ctx.realm);
	ctx.realm = NULL;
}
