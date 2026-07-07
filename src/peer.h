// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Structures and functions for peer management
*/


#pragma once

#include "fastd.h"
#include "peer_group.h"


/** Maximum number of punch-control endpoints kept under temporary cooldown */
#define FASTD_PUNCH_SUPPRESSION_LIMIT 32

/** Cooldown for failed or rejected punch-control endpoints */
#define FASTD_PUNCH_SUPPRESSION_TIME 60000

/** The state of a peer */
typedef enum fastd_peer_state {
	STATE_INACTIVE = 0, /**< The peer is not active at the moment */
	STATE_PASSIVE,      /**< The peer is waiting for incoming connections */
	STATE_RESOLVING,    /**< The peer is currently resolving its first remote */
	STATE_HANDSHAKE,    /**< The peer has tried to perform a handshake */
	STATE_ESTABLISHED,  /**< The peer has established a connection */
} fastd_peer_state_t;

/** The config state of a peer */
typedef enum fastd_peer_config_state {
	CONFIG_NEW = 0,  /**< The peer is configured statically, but has not been enabled yet */
	CONFIG_STATIC,   /**< The peer is configured statically */
	CONFIG_DISABLED, /**< The peer is configured statically, but has been disabled because of a configuration error
			  */
#ifdef WITH_DYNAMIC_PEERS
	CONFIG_DYNAMIC, /**< The peer is configured dynamically (using a on-verify handler) */
#endif
} fastd_peer_config_state_t;

/** Source of a direct endpoint candidate */
typedef enum fastd_peer_direct_candidate_source {
	DIRECT_CANDIDATE_REALM = 0,     /**< External realm rendezvous */
	DIRECT_CANDIDATE_DISCOVERY,     /**< Authenticated relay endpoint discovery */
	DIRECT_CANDIDATE_PUNCH_CONTROL, /**< fastd punch control RPC */
} fastd_peer_direct_candidate_source_t;

/** Transport protocols a direct endpoint candidate may use */
typedef enum fastd_peer_direct_candidate_transport {
	DIRECT_CANDIDATE_TRANSPORT_UDP = 1u << 0, /**< Candidate may be used over UDP */
	DIRECT_CANDIDATE_TRANSPORT_TCP = 1u << 1, /**< Candidate may be used over TCP */
	DIRECT_CANDIDATE_TRANSPORT_ANY = DIRECT_CANDIDATE_TRANSPORT_UDP | DIRECT_CANDIDATE_TRANSPORT_TCP,
} fastd_peer_direct_candidate_transport_t;

/** One direct endpoint candidate for a peer */
typedef struct fastd_peer_direct_candidate {
	fastd_peer_address_t remote;                 /**< Remote endpoint */
	fastd_peer_t *relay;                         /**< Relay peer that announced the endpoint, if any */
	fastd_timeout_t timeout;                     /**< Expiry timeout */
	fastd_timeout_t last_attempt;                /**< Last handshake attempt timestamp */
	fastd_timeout_t probe_timeout;               /**< Timeout while a UDP punch probe has proven this candidate */
	fastd_timeout_t payload_probe_timeout;       /**< Rate limit for payload probes sent to this candidate */
	unsigned attempts;                           /**< Number of attempts sent to this candidate */
	uint8_t priority;                            /**< Selection priority */
	uint8_t order;                               /**< Stable order within one punch-control candidate batch */
	uint8_t transports;                          /**< DIRECT_CANDIDATE_TRANSPORT_* mask */
	fastd_peer_direct_candidate_source_t source; /**< Candidate source */
	bool exact_udp_punch;                        /**< Send UDP handshakes from a short-lived exact punch socket */
	unsigned udp_punch_sockets;                  /**< Number of short-lived UDP sockets to use for punch handshakes */
} fastd_peer_direct_candidate_t;

/** One temporarily suppressed punch endpoint after failed direct attempts */
typedef struct fastd_peer_punch_suppression {
	fastd_peer_address_t remote; /**< Suppressed remote endpoint */
	fastd_timeout_t timeout;     /**< Expiry timeout */
} fastd_peer_punch_suppression_t;

/** UDP endpoint metadata learned through punch-control NAT_INFO */
typedef struct fastd_peer_punch_endpoint {
	fastd_peer_address_t address;       /**< Public endpoint address */
	fastd_nat_type_t nat_type;          /**< NAT type reported with this endpoint */
	uint16_t min_port;                  /**< Lowest observed public port for this endpoint's NAT context */
	uint16_t max_port;                  /**< Highest observed public port for this endpoint's NAT context */
	int port_delta;                     /**< Public port delta for easy-symmetric prediction */
	uint32_t hard_sym_port_index;       /**< Endpoint-local hard-symmetric scan index */
	uint32_t hard_sym_round;            /**< Endpoint-local hard-symmetric scan round */
} fastd_peer_punch_endpoint_t;

/** Role of the peer in the latest punch-control task */
typedef enum fastd_peer_punch_task_role {
	PEER_PUNCH_TASK_ROLE_NONE = 0,        /**< No punch-control task has been recorded */
	PEER_PUNCH_TASK_ROLE_RELAY_SUBJECT,   /**< This peer's endpoint was relayed to another peer */
	PEER_PUNCH_TASK_ROLE_RELAY_DEST,      /**< A relay sent this peer a command for another peer */
	PEER_PUNCH_TASK_ROLE_COMMAND_TARGET,  /**< This peer was the local target of an incoming command */
	PEER_PUNCH_TASK_ROLE_RESULT_SENDER,   /**< This peer returned a punch result */
	PEER_PUNCH_TASK_ROLE_RESULT_SUBJECT,  /**< This peer was the subject of a returned punch result */
} fastd_peer_punch_task_role_t;

/** Punch-control command represented in peer task status */
typedef enum fastd_peer_punch_task_command {
	PEER_PUNCH_TASK_COMMAND_NONE = 0,          /**< No command */
	PEER_PUNCH_TASK_COMMAND_CONE,              /**< Cone or restricted NAT punching */
	PEER_PUNCH_TASK_COMMAND_EASY_SYM,          /**< One-sided easy-symmetric NAT prediction */
	PEER_PUNCH_TASK_COMMAND_HARD_SYM,          /**< Hard-symmetric bounded port scan */
	PEER_PUNCH_TASK_COMMAND_BOTH_EASY_SYM,     /**< Paired easy-symmetric prediction */
	PEER_PUNCH_TASK_COMMAND_TCP,               /**< TCP mapped-address punching */
} fastd_peer_punch_task_command_t;

/** Punch-control result represented in peer task status */
typedef enum fastd_peer_punch_task_result {
	PEER_PUNCH_TASK_RESULT_NONE = 0,       /**< No result */
	PEER_PUNCH_TASK_RESULT_ACCEPTED,       /**< Candidate accepted */
	PEER_PUNCH_TASK_RESULT_HANDSHAKE,      /**< Candidate accepted and handshake sent */
	PEER_PUNCH_TASK_RESULT_SUPPRESSED,     /**< Candidate suppressed by local policy */
	PEER_PUNCH_TASK_RESULT_NO_PEER,        /**< Subject peer is not configured locally */
	PEER_PUNCH_TASK_RESULT_BUSY,           /**< Target already has a verified path */
} fastd_peer_punch_task_result_t;

/** Reason why the latest punch-control task was recorded */
typedef enum fastd_peer_punch_task_cause {
	PEER_PUNCH_TASK_CAUSE_NONE = 0,          /**< No punch-control task cause */
	PEER_PUNCH_TASK_CAUSE_RELAY_UDP,         /**< Relay generated UDP punch commands from fresh NAT metadata */
	PEER_PUNCH_TASK_CAUSE_RELAY_TCP,         /**< Relay generated a TCP mapped-address command */
	PEER_PUNCH_TASK_CAUSE_REMOTE_COMMAND,    /**< A remote relay asked this peer to try an endpoint */
	PEER_PUNCH_TASK_CAUSE_REMOTE_RESULT,     /**< A remote peer returned a punch result */
	PEER_PUNCH_TASK_CAUSE_MISSING_PEER,      /**< Command referenced an unknown local peer */
	PEER_PUNCH_TASK_CAUSE_VERIFIED_BACKUP,   /**< A verified backup path made another punch unnecessary */
	PEER_PUNCH_TASK_CAUSE_LOCAL_POLICY,      /**< Local policy or cooldown rejected the candidate */
	PEER_PUNCH_TASK_CAUSE_CANDIDATE_ADDED,   /**< Candidate was accepted into the direct candidate set */
	PEER_PUNCH_TASK_CAUSE_HANDSHAKE_SENT,    /**< Candidate was accepted and immediately used for a handshake */
} fastd_peer_punch_task_cause_t;

/** Latest punch-control task snapshot for one peer */
typedef struct fastd_peer_punch_task {
	uint64_t id;                              /**< Local monotonic task ID */
	fastd_timeout_t updated;                  /**< Last task update timestamp */
	fastd_timeout_t next_retry;               /**< Earliest expected retry or outcome timeout */
	fastd_peer_address_t endpoint;            /**< Endpoint involved in the task */
	fastd_peer_punch_task_role_t role;        /**< Peer role in the task */
	fastd_peer_punch_task_cause_t cause;      /**< Reason this task snapshot was recorded */
	fastd_peer_punch_task_command_t command;  /**< Punch command type */
	fastd_peer_punch_task_result_t result;    /**< Latest result, if any */
	uint16_t packet_count;                    /**< Requested remote packet/socket count */
	uint16_t candidate_count;                 /**< Candidate endpoints generated for this task */
	uint16_t candidates_sent;                 /**< Candidate commands sent for this task */
	uint8_t order;                            /**< Candidate order from the relay batch */
	unsigned udp_punch_sockets;               /**< Local short-lived UDP sockets requested or used */
	uint32_t hard_sym_port_index;             /**< Hard-symmetric scan index at task start */
	uint32_t hard_sym_next_port_index;         /**< Hard-symmetric scan index after this task */
	uint32_t hard_sym_round;                  /**< Hard-symmetric scan round after this task */
	uint32_t wait_window_ms;                  /**< Expected short-term punch wait window in milliseconds */
	fastd_peer_address_t base_mapped_endpoint; /**< Base mapped listener endpoint returned by the target */
	uint32_t base_mapped_listener_id;        /**< Runtime listener ID returned by the target, if available */
	bool base_mapped_available;              /**< Whether base_mapped_endpoint is available */
	bool base_mapped_port_mapped;            /**< Whether base_mapped_endpoint came from explicit port mapping */
} fastd_peer_punch_task_t;

/** A peer's configuration and state */
struct fastd_peer {
	/* The following fields are more or less static configuration: */

	uint64_t id; /**< A unique ID assigned to each peer */

	char *name;                      /**< The peer's name */
	const fastd_peer_group_t *group; /**< The peer group the peer belongs to */
	const char *config_source_dir;   /**< The directory this peer's configuration was loaded from */

	VECTOR(fastd_remote_t) remotes; /**< The vector of the peer's remotes */
	bool floating;                  /**< Specifies if the peer has any floating remotes */
	char *realm;                    /**< Optional realm ID used for rendezvous-assisted direct attempts */

	fastd_peer_config_state_t config_state; /**< Specifies the way this peer was configured and if it is enabled */

	fastd_protocol_key_t *key;                   /**< The peer's public key */
	fastd_protocol_peer_state_t *protocol_state; /**< Protocol-specific peer state */

	char *ifname;                           /**< Peer-specific interface name */
	uint16_t mtu;                           /**< Peer-specific interface MTU */
	fastd_port_mapping_mode_t port_mapping; /**< Peer-specific automatic port mapping mode */
	fastd_peer_transport_t transport;       /**< Peer-specific transport protocol */
	fastd_hole_punch_mode_t hole_punch;     /**< Peer-specific hole punching mode */
	fastd_tristate_t nat_traversal;         /**< Peer-specific NAT traversal setting */
	fastd_tristate_t punch_symmetric;       /**< Peer-specific symmetric NAT punching strategy */
	fastd_tristate_t turn_relay;            /**< Peer-specific TURN relay setting */
	fastd_turn_server_t *turn_servers;      /**< Peer-specific TURN servers */

	/* Starting here, more dynamic fields follow: */

	fastd_iface_t *iface; /**< The interface this peer is associated with */
	/** The socket used by the peer. This can either be a common bound socket or a
	    dynamic, unbound socket that is used exclusively by this peer */
	fastd_socket_t *sock;
	const fastd_offload_t *offload;       /**< Datapath kernel offloading provider */
	fastd_offload_state_t *offload_state; /**< Datapath kernel offloading - provider-specific state */
	fastd_peer_address_t local_address;   /**< The local address used to communicate with this peer */
	fastd_peer_address_t address;         /**< The peers current address */

	fastd_peer_address_t last_handshake_address;          /**< The address the last handshake was sent to */
	fastd_peer_address_t last_handshake_response_address; /**< The address the last handshake was received from */
	fastd_peer_transport_t last_handshake_transport;      /**< The transport used for the last sent handshake */
	fastd_peer_transport_t last_handshake_response_transport; /**< Transport used for the last handshake response */
	ssize_t next_remote;                                  /**< An index into the field remotes or -1 */
	fastd_peer_transport_t transport_probe; /**< Transport currently probed for automatic transport mode */
	fastd_timeout_t turn_fallback_timeout;  /**< Timeout before automatic TURN fallback is used */

	fastd_peer_t *direct_relay;            /**< Relay peer used while a discovered direct path is unavailable */
	fastd_peer_address_t direct_remote;    /**< Relay-discovered direct peer endpoint */
	fastd_timeout_t direct_remote_timeout; /**< Timeout for the discovered direct endpoint */
	bool direct_established; /**< true if the current session was established using a direct candidate */
	fastd_peer_direct_candidate_source_t direct_remote_source; /**< Source of the cached direct endpoint */
	uint8_t direct_remote_transports;          /**< DIRECT_CANDIDATE_TRANSPORT_* mask for the cached endpoint */
	bool direct_remote_exact_udp;              /**< true if cached endpoint uses exact UDP punching */
	unsigned direct_remote_udp_punch_sockets;  /**< Number of cached UDP punch sockets to use */
	fastd_socket_t *backup_sock;               /**< Socket for an established backup path */
	fastd_peer_address_t backup_local_address; /**< Local address used by the backup path */
	fastd_peer_address_t backup_address;       /**< Remote address of the backup path */
	fastd_timeout_t backup_reset_timeout;      /**< Timeout after which the backup path is dropped */
	fastd_timeout_t backup_keepalive_timeout;  /**< Timeout for the next backup path keepalive */
	bool backup_direct_established; /**< true if the backup path was established using a direct candidate */
	fastd_peer_direct_candidate_source_t backup_direct_source; /**< Source of the backup direct endpoint */
	bool backup_path_verified; /**< true if the backup path has completed an authenticated exchange */
	bool backup_payload_proven; /**< true if the backup path has carried authenticated payload */
	bool backup_probe_proven; /**< true if the backup path has received an authenticated probe or keepalive */
	VECTOR(fastd_peer_direct_candidate_t) direct_candidates;   /**< Direct endpoint candidates */
	VECTOR(fastd_peer_punch_suppression_t) punch_suppressions; /**< Failed punch endpoints under cooldown */
	VECTOR(fastd_peer_punch_suppression_t) punch_relay_backoffs; /**< Endpoints temporarily rejected by this peer */
	fastd_timeout_t next_discovery_announce;                   /**< Rate limit for relay endpoint announcements */
	fastd_peer_address_t punch_endpoint;                       /**< Last endpoint announced through punch control */
	fastd_peer_punch_endpoint_t punch_endpoints[FASTD_NAT_MAX_PUBLIC_ENDPOINTS]; /**< Fresh UDP punch endpoints */
	size_t n_punch_endpoints;                                  /**< Number of fresh UDP punch endpoints */
	fastd_nat_type_t punch_nat_type;                           /**< Last NAT type announced through punch control */
	uint16_t punch_min_port;             /**< Lowest public port announced through punch control */
	uint16_t punch_max_port;             /**< Highest public port announced through punch control */
	int punch_port_delta;                /**< Public port delta announced through punch control */
	uint32_t punch_listener_id;          /**< Runtime public listener ID announced through punch control */
	fastd_timeout_t punch_timeout;       /**< Timeout for punch control metadata */
	fastd_peer_address_t tcp_punch_endpoint; /**< Last TCP endpoint announced through punch control */
	fastd_peer_address_t tcp_punch_endpoints[FASTD_NAT_MAX_PUBLIC_ENDPOINTS]; /**< Fresh TCP punch endpoints */
	size_t n_tcp_punch_endpoints;            /**< Number of fresh TCP punch endpoints */
	fastd_nat_type_t tcp_punch_nat_type;     /**< Last TCP NAT type announced through punch control */
	uint16_t tcp_punch_min_port;             /**< Lowest public TCP port announced through punch control */
	uint16_t tcp_punch_max_port;             /**< Highest public TCP port announced through punch control */
	fastd_timeout_t tcp_punch_timeout;       /**< Timeout for TCP punch control metadata */
	fastd_timeout_t next_punch_announce; /**< Rate limit for local punch metadata announcements */
	fastd_timeout_t next_punch_relay;    /**< Rate limit for relay-generated punch commands */
	uint32_t punch_hard_sym_port_index;  /**< Next hard-symmetric full-port-space scan index */
	uint32_t punch_hard_sym_round;       /**< Number of completed hard-symmetric full-port-space scan rounds */
	fastd_peer_punch_task_t last_punch_task; /**< Latest punch-control task status */
	bool punch_success_counted;          /**< true if the current punch-control session has been counted */
	fastd_peer_address_t payload_candidate_address; /**< Direct candidate that has carried payload data */
	fastd_timeout_t payload_candidate_timeout;      /**< Timeout for the payload-proven candidate */
	fastd_peer_address_t probe_candidate_address;   /**< Direct candidate with a matched UDP punch probe */
	fastd_timeout_t probe_candidate_timeout;        /**< Timeout for the probe-proven candidate */
	VECTOR(fastd_eth_addr_t) direct_macs;           /**< MAC addresses that should prefer this direct peer */

	fastd_peer_state_t state; /**< The peer's state */

	fastd_task_t task; /**< Task queue entry for periodic maintenance tasks */

	fastd_timeout_t next_handshake;         /**< The time of the next handshake */
	fastd_timeout_t last_handshake_timeout; /**< No handshakes are sent to the peer until this timeout has occured
						   to avoid flooding the peer */
	fastd_timeout_t last_handshake_response_timeout; /**< All handshakes from last_handshake_address will be ignored
							    until this timeout has occured */
	fastd_timeout_t establish_handshake_timeout; /**< A timeout during which all handshakes for this peer will be
							ignored after a new connection has been established */
	int64_t established;                         /**< The time this peer connection has been established */

	fastd_timeout_t reset_timeout;       /**< The timeout after which the peer is reset */
	fastd_timeout_t keepalive_timeout;   /**< The timeout after which a keepalive is sent to the peer */
	fastd_timeout_t active_path_timeout; /**< Timeout while the active transport path is considered verified */
	fastd_timeout_t active_path_proven_timeout; /**< Timeout while the active direct path has authenticated
						       traffic proof */
	fastd_timeout_t active_path_payload_seen; /**< Last time the active path received authenticated payload */
	bool active_path_payload_sent; /**< true after local payload was sent on the current active path */

	fastd_stats_t stats; /**< Traffic statistics */

	fastd_turn_peer_t *turn_peer; /**< TURN relay state */

#ifdef WITH_DYNAMIC_PEERS
	fastd_timeout_t verify_timeout; /**< Specifies the minimum time after which on-verify may be run again */
	fastd_timeout_t
		verify_valid_timeout; /**< Specifies how long a peer stays valid after a successful on-verify run */
#endif
};


/** An entry for a MAC address seen at another peer */
struct fastd_peer_eth_addr {
	fastd_eth_addr_t addr;   /**< The MAC address */
	fastd_peer_t *peer;      /**< The corresponding peer */
	fastd_timeout_t timeout; /**< Timeout after which the address entry will be purged */
};

/** A remote entry */
struct fastd_remote {
	char *hostname;               /**< The hostname or NULL */
	fastd_peer_address_t address; /**< The address; if hostname is set only sin.sin_port is used */

	size_t n_addresses;              /**< The size of the \e addresses array */
	size_t current_address;          /**< The index of the remote the next handshake will be sent to */
	fastd_peer_address_t *addresses; /**< The IP addresses the remote was resolved to */

	fastd_timeout_t last_resolve_timeout; /**< Timeout before the remote must not be resolved again */
};


bool fastd_peer_address_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2);
void fastd_peer_address_simplify(fastd_peer_address_t *addr);
void fastd_peer_address_widen(fastd_peer_address_t *addr);

bool fastd_peer_add(fastd_peer_t *peer);
void fastd_peer_reset(fastd_peer_t *peer);
void fastd_peer_delete(fastd_peer_t *peer);
void fastd_peer_free(fastd_peer_t *peer);
bool fastd_peer_set_established(fastd_peer_t *peer, const fastd_offload_t *offload);
bool fastd_peer_may_connect(fastd_peer_t *peer);
bool fastd_peer_nat_traversal_keepalive_enabled(const fastd_peer_t *peer);
unsigned fastd_peer_active_path_verify_interval(const fastd_peer_t *peer);
void fastd_peer_clear_keepalive(fastd_peer_t *peer);
void fastd_peer_handle_resolve(
	fastd_peer_t *peer, fastd_remote_t *remote, size_t n_addresses, const fastd_peer_address_t *addresses);
bool fastd_peer_owns_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_matches_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_claim_address(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, bool force);
bool fastd_peer_claim_backup_path(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr);
void fastd_peer_clear_backup_path(fastd_peer_t *peer);
bool fastd_peer_has_backup_path(const fastd_peer_t *peer);
bool fastd_peer_has_verified_backup_path(const fastd_peer_t *peer);
bool fastd_peer_is_backup_path(
	const fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr);
fastd_peer_t *fastd_peer_find_backup_path(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr);
fastd_peer_t *fastd_peer_find_direct_candidate(const fastd_peer_address_t *remote_addr);
fastd_peer_t *
fastd_peer_find_direct_candidate_transport(const fastd_peer_address_t *remote_addr, fastd_peer_transport_t transport);
fastd_peer_t *fastd_peer_find_endpoint_dependent_candidate_transport(
	const fastd_peer_address_t *remote_addr, fastd_peer_transport_t transport);
bool fastd_peer_promote_backup_path(fastd_peer_t *peer);
void fastd_peer_backup_seen(fastd_peer_t *peer);
void fastd_peer_clear_backup_keepalive(fastd_peer_t *peer);
bool fastd_peer_get_direct_candidate_source(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr,
	fastd_peer_direct_candidate_source_t *source);
bool fastd_peer_get_direct_candidate_source_transport(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, fastd_peer_transport_t transport,
	fastd_peer_direct_candidate_source_t *source);
bool fastd_peer_get_endpoint_dependent_candidate_source(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr,
	fastd_peer_direct_candidate_source_t *source);
bool fastd_peer_get_endpoint_dependent_candidate_source_transport(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, fastd_peer_transport_t transport,
	fastd_peer_direct_candidate_source_t *source);
bool fastd_peer_direct_candidate_preferred(
	const fastd_peer_t *peer, const fastd_peer_address_t *new_addr, const fastd_peer_address_t *old_addr);
bool fastd_peer_send_backup_handshake(fastd_peer_t *peer);
void fastd_peer_note_payload_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
bool fastd_peer_is_payload_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
void fastd_peer_note_probe_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
bool fastd_peer_is_probe_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
void fastd_peer_prove_active_path(fastd_peer_t *peer);
bool fastd_peer_active_path_proven(const fastd_peer_t *peer);
void fastd_peer_reset_socket(fastd_peer_t *peer);
void fastd_peer_schedule_handshake(fastd_peer_t *peer, int delay);
void fastd_peer_reschedule(fastd_peer_t *peer);
void fastd_peer_transport_failed(fastd_peer_t *peer, fastd_peer_transport_t transport);
fastd_peer_t *fastd_peer_find_by_id(uint64_t id);

void fastd_peer_set_shell_env(
	fastd_shell_env_t *env, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr);
void fastd_peer_exec_shell_command(
	const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr, bool sync);

void fastd_peer_eth_addr_add(fastd_peer_t *peer, fastd_eth_addr_t addr);
bool fastd_peer_find_by_eth_addr(const fastd_eth_addr_t addr, fastd_peer_t **peer);
void fastd_peer_add_direct_candidate(
	fastd_peer_t *peer, fastd_peer_t *relay, const fastd_peer_address_t *remote_addr, const fastd_eth_addr_t *macs,
	size_t n_macs);
void fastd_peer_add_direct_candidate_source(
	fastd_peer_t *peer, fastd_peer_t *relay, const fastd_peer_address_t *remote_addr, const fastd_eth_addr_t *macs,
	size_t n_macs, fastd_peer_direct_candidate_source_t source, uint8_t priority);
void fastd_peer_add_direct_candidate_source_transport(
	fastd_peer_t *peer, fastd_peer_t *relay, const fastd_peer_address_t *remote_addr, const fastd_eth_addr_t *macs,
	size_t n_macs, fastd_peer_direct_candidate_source_t source, uint8_t priority, uint8_t transports);
bool fastd_peer_add_punch_control_candidate(
	fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, uint8_t priority, bool exact_udp_punch,
	unsigned udp_punch_sockets, uint8_t order);
bool fastd_peer_add_punch_control_candidate_transport(
	fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, uint8_t priority, bool exact_udp_punch,
	unsigned udp_punch_sockets, uint8_t order, uint8_t transports);
bool fastd_peer_has_direct_candidate(const fastd_peer_t *peer);
size_t fastd_peer_direct_candidate_count(const fastd_peer_t *peer);
size_t
fastd_peer_direct_candidate_count_by_source(const fastd_peer_t *peer, fastd_peer_direct_candidate_source_t source);
bool fastd_peer_is_current_punch_control_candidate(
	const fastd_peer_t *peer, const fastd_peer_address_t *addr, bool *exact_udp_punch, unsigned *udp_punch_sockets);
bool fastd_peer_is_current_punch_control_candidate_transport(
	const fastd_peer_t *peer, const fastd_peer_address_t *addr, fastd_peer_transport_t transport,
	bool *exact_udp_punch, unsigned *udp_punch_sockets);
bool fastd_peer_is_current_punch_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_is_punch_control_candidate(
	const fastd_peer_t *peer, const fastd_peer_address_t *addr, bool *exact_udp_punch, unsigned *udp_punch_sockets);
bool fastd_peer_is_punch_control_candidate_transport(
	const fastd_peer_t *peer, const fastd_peer_address_t *addr, fastd_peer_transport_t transport,
	bool *exact_udp_punch, unsigned *udp_punch_sockets);
bool fastd_peer_is_punch_candidate(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_punch_candidate_suppressed(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
size_t fastd_peer_punch_suppression_count(const fastd_peer_t *peer);
void fastd_peer_suppress_punch_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
bool fastd_peer_punch_relay_backoff_active(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
fastd_timeout_t fastd_peer_punch_relay_backoff_timeout(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
size_t fastd_peer_punch_relay_backoff_count(const fastd_peer_t *peer);
void fastd_peer_add_punch_relay_backoff(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
bool fastd_peer_send_direct_handshake(fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_send_direct_handshake_transport(
	fastd_peer_t *peer, const fastd_peer_address_t *addr, fastd_peer_transport_t transport);

#ifdef WITH_TESTS
void fastd_peer_test_suppress_punch_candidate(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
void fastd_peer_test_count_direct_success(fastd_peer_t *peer, fastd_peer_direct_candidate_source_t source);
void fastd_peer_test_compact_direct_candidates(fastd_peer_t *peer);
#endif

void fastd_peer_handle_task(fastd_task_t *task);
void fastd_peer_eth_addr_cleanup(void);
void fastd_peer_reset_all(void);


/** Returns the port of a fastd_peer_address_t (in network byte order) */
static inline uint16_t fastd_peer_address_get_port(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return addr->in.sin_port;

	case AF_INET6:
		return addr->in6.sin6_port;

	default:
		return 0;
	}
}

/** Returns a random value in the range DEFAULT_HANDSHAKE_INTERVAL +/- DEFAULT_HANDSHAKE_JITTER */
static inline int fastd_peer_handshake_default_rand(void) {
	return fastd_rand(
		DEFAULT_HANDSHAKE_INTERVAL - DEFAULT_HANDSHAKE_JITTER,
		DEFAULT_HANDSHAKE_INTERVAL + DEFAULT_HANDSHAKE_JITTER);
}

/** Schedules a handshake with the default delay and jitter */
static inline void fastd_peer_schedule_handshake_default(fastd_peer_t *peer) {
	fastd_peer_schedule_handshake(peer, fastd_peer_handshake_default_rand());
}

/** Cancels a scheduled handshake */
static inline void fastd_peer_unschedule_handshake(fastd_peer_t *peer) {
	peer->next_handshake = FASTD_TIMEOUT_INV;
}

#ifdef WITH_DYNAMIC_PEERS
/** Call to signal that there is currently an asychronous on-verify command running for the peer */
static inline void fastd_peer_set_verifying(fastd_peer_t *peer) {
	peer->verify_timeout = ctx.now + MIN_VERIFY_INTERVAL;

	fastd_timeout_advance(&peer->reset_timeout, peer->verify_timeout);
}

/** Marks the peer verification as successful or failed */
static inline void fastd_peer_set_verified(fastd_peer_t *peer, bool ok) {
	peer->verify_valid_timeout = ctx.now + (ok ? VERIFY_VALID_TIME : 0);

	fastd_timeout_advance(&peer->reset_timeout, peer->verify_valid_timeout);
}
#endif

/** Checks if there's a handshake queued for the peer */
static inline bool fastd_peer_handshake_scheduled(fastd_peer_t *peer) {
	return (peer->next_handshake != FASTD_TIMEOUT_INV);
}

/** Checks if a peer is floating (is has at least one floating remote or no remotes at all) */
static inline bool fastd_peer_is_floating(const fastd_peer_t *peer) {
	return (!VECTOR_LEN(peer->remotes) || peer->floating);
}

/** Checks if a peer is not statically configured, but added after a on-verify run */
static inline bool fastd_peer_is_dynamic(UNUSED const fastd_peer_t *peer) {
#ifdef WITH_DYNAMIC_PEERS
	return peer->config_state == CONFIG_DYNAMIC;
#else
	return false;
#endif
}

/** Checks if a peer is enabled */
static inline bool fastd_peer_is_enabled(const fastd_peer_t *peer) {
	switch (peer->config_state) {
	case CONFIG_STATIC:
#ifdef WITH_DYNAMIC_PEERS
	case CONFIG_DYNAMIC:
#endif
		return true;
	default:
		return false;
	}
}

/** Returns the currently active remote entry */
static inline fastd_remote_t *fastd_peer_get_next_remote(fastd_peer_t *peer) {
	if (peer->next_remote < 0)
		return NULL;

	return &VECTOR_INDEX(peer->remotes, peer->next_remote);
}

/** Checks if the peer currently has an established connection */
static inline bool fastd_peer_is_established(const fastd_peer_t *peer) {
	switch (peer->state) {
	case STATE_ESTABLISHED:
		return true;

	default:
		return false;
	}
}

/** Signals that a valid packet was received from the peer */
static inline void fastd_peer_seen(fastd_peer_t *peer) {
	peer->reset_timeout = ctx.now + PEER_STALE_TIME;
}

/** Checks if a peer uses dynamic sockets (which means that each connection attempt uses a new socket) */
static inline bool fastd_peer_is_socket_dynamic(const fastd_peer_t *peer) {
	return (!peer->sock || !peer->sock->addr || peer->sock->type == SOCKET_TYPE_TCP_CONNECTION);
}

/** Returns the effective automatic port mapping mode for a peer */
static inline fastd_port_mapping_mode_t fastd_peer_get_port_mapping_mode(const fastd_peer_t *peer) {
	if (peer && peer->port_mapping)
		return peer->port_mapping;

	return fastd_peer_group_get_port_mapping_mode(peer ? peer->group : conf.peer_group);
}

/** Returns the effective transport protocol for a peer */
static inline fastd_peer_transport_t fastd_peer_get_transport(const fastd_peer_t *peer) {
	if (peer && peer->transport)
		return peer->transport;

	return fastd_peer_group_get_transport(peer ? peer->group : conf.peer_group);
}

/** Returns true if a configured transport accepts a concrete transport */
static inline bool fastd_peer_transport_allows(fastd_peer_transport_t configured, fastd_peer_transport_t concrete) {
	return configured == TRANSPORT_AUTO || configured == concrete;
}

/** Returns the effective hole punching mode for a peer */
static inline fastd_hole_punch_mode_t fastd_peer_get_hole_punch(const fastd_peer_t *peer) {
	if (peer && peer->hole_punch)
		return peer->hole_punch;

	return fastd_peer_group_get_hole_punch(peer ? peer->group : conf.peer_group);
}

/** Returns the effective NAT traversal setting for a peer */
static inline bool fastd_peer_get_nat_traversal(const fastd_peer_t *peer) {
	if (peer && peer->nat_traversal.set)
		return peer->nat_traversal.state;

	return fastd_peer_group_get_nat_traversal(peer ? peer->group : conf.peer_group);
}

/** Returns the effective punch data relay setting */
static inline bool fastd_peer_get_punch_data_relay(void) {
	if (conf.punch_data_relay.set)
		return conf.punch_data_relay.state;

	return conf.punch_control_relay || fastd_peer_get_nat_traversal(NULL);
}

/** Returns whether a peer may use deterministic hole punching for a transport */
static inline bool fastd_peer_hole_punch_allows(const fastd_peer_t *peer, fastd_peer_transport_t transport) {
	fastd_hole_punch_mode_t mode = fastd_peer_get_hole_punch(peer);

	switch (mode) {
	case HOLE_PUNCH_TCP:
		return transport == TRANSPORT_TCP;

	case HOLE_PUNCH_UDP:
		return transport == TRANSPORT_UDP;

	case HOLE_PUNCH_AUTO:
		return transport == TRANSPORT_TCP || transport == TRANSPORT_UDP;

	default:
		return false;
	}
}

/** Returns whether symmetric NAT punching strategies are enabled for a peer */
static inline bool fastd_peer_get_punch_symmetric(const fastd_peer_t *peer) {
	if (peer && peer->punch_symmetric.set)
		return peer->punch_symmetric.state;

	return conf.punch_symmetric;
}

/** Returns the effective TURN server list for a peer */
static inline const fastd_turn_server_t *fastd_peer_get_turn_servers(const fastd_peer_t *peer) {
	if (peer && peer->turn_servers)
		return peer->turn_servers;

	return fastd_peer_group_get_turn_servers(peer ? peer->group : conf.peer_group);
}

/** Returns the effective TURN relay setting for a peer */
static inline bool fastd_peer_get_turn_relay(const fastd_peer_t *peer) {
	if (peer && peer->turn_relay.set)
		return peer->turn_relay.state;

	if (peer && peer->nat_traversal.set)
		return peer->nat_traversal.state && fastd_peer_get_turn_servers(peer);

	if (fastd_peer_get_nat_traversal(peer) && fastd_peer_get_turn_servers(peer))
		return true;

	return fastd_peer_group_get_turn_relay(peer ? peer->group : conf.peer_group);
}

/** Returns the MTU to use for a peer */
static inline uint16_t fastd_peer_get_mtu(const fastd_peer_t *peer) {
	if (conf.mode == MODE_TAP)
		return conf.mtu;

	if (peer && peer->mtu)
		return peer->mtu;

	return conf.mtu;
}

/** Checks if a MAC address is a normal unicast address */
static inline bool fastd_eth_addr_is_unicast(fastd_eth_addr_t addr) {
	return ((addr.data[0] & 1) == 0);
}

/** Adds statistics for a single packet of a given size */
static inline void fastd_stats_add(UNUSED fastd_peer_t *peer, UNUSED fastd_stat_type_t stat, UNUSED size_t bytes) {
#ifdef WITH_STATUS_SOCKET
	if (!bytes)
		return;

	ctx.stats.packets[stat]++;
	ctx.stats.bytes[stat] += bytes;

	peer->stats.packets[stat]++;
	peer->stats.bytes[stat] += bytes;
#endif
}
