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

   \em fastd main header file defining most data structures
*/


#pragma once

#include "buffer.h"
#include "log.h"
#include "polling.h"
#include "sem.h"
#include "shell.h"
#include "task.h"
#include "util.h"
#include "vector.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <net/if.h>


/** An ethernet address */
struct __attribute__((packed)) fastd_eth_addr {
	uint8_t data[6]; /**< The bytes of the address */
};

/** An ethernet header */
struct __attribute__((packed)) fastd_eth_header {
	fastd_eth_addr_t dest;   /**< The destination MAC address field */
	fastd_eth_addr_t source; /**< The source MAC address field */
	uint16_t proto;          /**< The EtherType/length field */
};


/**
   A structure describing callbacks that define a handshake protocol

   Currently, only one such protocol, \em ec25519-fhmqvc, is defined.
*/
struct fastd_protocol {
	/** The name of the procotol */
	const char *name;

	/** Performs one-time initialization tasks for the protocol */
	fastd_protocol_config_t *(*init)(void);

	/** Sends a handshake to the given peer */
	void (*handshake_init)(
		fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
		fastd_peer_t *peer, unsigned flags);

	/** Handles a handshake for the given peer */
	void (*handshake_handle)(
		fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
		fastd_peer_t *peer, const fastd_handshake_t *handshake);

#ifdef WITH_DYNAMIC_PEERS
	/** Handles an asynchronous on-verify command return */
	void (*handle_verify_return)(
		fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
		const fastd_peer_address_t *remote_addr, const void *protocol_data, bool ok);
#endif


	/** Handles a received payload packet (performs decryption and validity check, etc.) */
	void (*handle_recv)(
		fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
		fastd_peer_t *peer, fastd_buffer_t *buffer);

	/** Sends a payload data packet to the given peer */
	void (*send)(fastd_peer_t *peer, fastd_buffer_t *buffer);

	/** Sends an authenticated internal control packet to the given peer */
	void (*send_control)(fastd_peer_t *peer, fastd_buffer_t *buffer);

	/** Promotes an established backup path to the active peer path */
	bool (*promote_backup_path)(fastd_peer_t *peer);

	/** Drops an established backup path */
	void (*drop_backup_path)(fastd_peer_t *peer);

	/** Sends a keepalive on an established backup path */
	void (*send_backup_keepalive)(fastd_peer_t *peer);


	/** Initializes the protocol state for a peer */
	void (*init_peer_state)(fastd_peer_t *peer);

	/** Resets the protocol state for a peer (resets active sessions etc.) */
	void (*reset_peer_state)(fastd_peer_t *peer);

	/** Frees the protocol state for a peer */
	void (*free_peer_state)(fastd_peer_t *peer);


	/** Initializes protocol-specific parts of a peer configuration */
	fastd_protocol_key_t *(*read_key)(const char *key);

	/** Checks a peer after reading its configuration */
	bool (*check_peer)(const fastd_peer_t *peer);

	/** Searches a peer identified by a specific key */
	fastd_peer_t *(*find_peer)(const fastd_protocol_key_t *key);

	/** Returns the length of the protocol's public key representation */
	size_t (*key_length)(void);

	/** Returns this instance's protocol public key */
	const void *(*get_own_key)(void);

	/** Returns a peer's protocol public key */
	const void *(*get_peer_key)(const fastd_peer_t *peer);

	/** Searches a peer identified by a raw public key */
	fastd_peer_t *(*find_peer_by_key_data)(const void *key, size_t len);

#ifdef WITH_DYNAMIC_PEERS
	/** Adds a dynamic peer identified by a raw public key */
	fastd_peer_t *(*add_dynamic_peer_by_key_data)(const void *key, size_t len);
#endif


	/** Retrieves information about the currently used encyption/authentication method of a connection with a peer
	 */
	const fastd_method_info_t *(*get_current_method)(const fastd_peer_t *peer);


	/** Generates a new keypair and outputs it */
	void (*generate_key)(void);

	/** Outputs the public key for the configured secret */
	void (*show_key)(void);


	/** Adds peer-specific environment variables to env */
	void (*set_shell_env)(fastd_shell_env_t *env, const fastd_peer_t *peer);

	/** Creates a human-readable representation of the peer */
	bool (*describe_peer)(const fastd_peer_t *peer, char *buf, size_t len);
};

/** An union storing an IPv4 or IPv6 address */
union fastd_peer_address {
	struct sockaddr sa;      /**< A sockaddr field (for access to sa_family) */
	struct sockaddr_in in;   /**< An IPv4 address */
	struct sockaddr_in6 in6; /**< An IPv6 address */
};

#define FASTD_BIND_DEFAULT_IPV4 (1U << 1)
#define FASTD_BIND_DEFAULT_IPV6 (1U << 2)
#define FASTD_BIND_DYNAMIC (1U << 3)

/** A linked list of addresses to bind to */
struct fastd_bind_address {
	fastd_bind_address_t *next; /**< The next address in the list */
	fastd_peer_address_t addr;  /**< The address to bind to */
	unsigned flags;             /**< FASTD_BIND_* flags */
	char *bindtodev;            /**< May contain an interface name to limit the bind to */
};

/** A queued TCP output frame */
struct fastd_tcp_frame {
	fastd_tcp_frame_t *next; /**< The next queued frame */
	size_t len;              /**< The length of the frame including the length prefix */
	size_t written;          /**< The number of bytes already written */
	size_t stat_size;        /**< The payload size to account in traffic statistics */
	fastd_peer_t *peer;      /**< The peer used for traffic statistics */
	uint8_t data[];          /**< The frame data */
};

/**
 * A socket descriptor
 *
 * Sockets come in three flavours:
 *
 * - Global sockets stored in \e ctx.socks. \e addr references a global bind
 *   address, \e peer and \e parent are NULL.
 * - Dynamic peer sockets used for a single connection (attempt).
 *   \e peer points at the peer, \e addr and \e parent are NULL.
 * - L2TP offload sockets. \e addr and peer are NULL,
 *   \e parent is the original socket which was used before offload setup.
 */
struct fastd_socket {
	fastd_poll_fd_t fd;               /**< The file descriptor for the socket */
	fastd_socket_type_t type;         /**< The socket type */
	const fastd_bind_address_t *addr; /**< The address this socket is supposed to be bound to (or NULL) */
	fastd_peer_address_t *bound_addr; /**< Address that was bound to (differs from addr when it has random port) */
	fastd_peer_t *peer;               /**< If the socket belongs to a single peer, contains that peer */
	fastd_socket_t *parent;           /**< Original of L2TP offload socket */
	fastd_socket_t *tcp_listener;     /**< TCP listener belonging to a UDP socket */
	fastd_peer_address_t peer_addr;   /**< Remote address of a TCP connection */
	fastd_peer_t *hole_punch_peer;    /**< Peer this unclaimed hole punching socket belongs to */
	bool hole_punch;                  /**< Whether this socket was created by active hole punching */
	bool deferred_free;               /**< Whether this dynamic socket is already queued for deferred free */
	bool punch_public_listener;       /**< Whether this UDP punch socket is a reusable public punch listener */
	bool punch_listener_port_mapped;  /**< Whether the listener endpoint came from explicit port mapping */
	bool punch_listener_mapping_registered; /**< Whether a dynamic port mapping lease is registered for this socket */
	uint32_t punch_listener_id;       /**< Stable runtime ID for reusable public punch listeners */
	uint32_t punch_transaction_id;    /**< Transaction ID for dedicated UDP punch probe packets */
	fastd_timeout_t punch_listener_selected; /**< Last time this public listener was selected */
	fastd_peer_address_t punch_listener_public_addr; /**< Public endpoint of this punch listener */

	uint8_t tcp_header[4]; /**< Partial TCP frame length prefix */
	size_t tcp_header_len; /**< Number of TCP frame prefix bytes read */
	size_t tcp_packet_len; /**< Current TCP frame packet length */
	size_t tcp_packet_pos; /**< Number of TCP frame packet bytes read */
	uint8_t *tcp_packet;   /**< Current partial TCP frame packet */

	fastd_tcp_frame_t *tcp_output_head; /**< First queued TCP output frame */
	fastd_tcp_frame_t *tcp_output_tail; /**< Last queued TCP output frame */
	size_t tcp_output_len;              /**< Number of queued TCP output bytes */
	bool tcp_connecting;                /**< Whether a non-blocking TCP connect is in progress */
	bool tcp_handling;                  /**< Whether this TCP connection is currently being handled */
	bool tcp_closed;                    /**< Whether this TCP connection has been closed while being handled */
	fastd_timeout_t tcp_timeout;        /**< Timeout for unauthenticated TCP connections */
	fastd_timeout_t hole_punch_timeout; /**< Timeout for unclaimed UDP hole punching sockets */
};

/** A TUN/TAP interface */
struct fastd_iface {
	fastd_poll_fd_t fd; /**< The file descriptor of the tunnel interface */
	char *name;         /**< The interface name */
	fastd_peer_t *peer; /**< The peer associated with the interface (if any) */
	uint16_t mtu;       /**< The MTU of the interface */
	bool cleanup;       /**< Determines if the interface should be deleted after use; not used on all platforms */
};

/** Realm rendezvous configuration */
struct fastd_realm_config {
	char *server;       /**< Base URL of the rendezvous server */
	char *token;        /**< Bearer token used for realm registration and connection requests */
	char *id;           /**< Realm ID advertised by this fastd instance */
	char *stun_host;    /**< Optional STUN server host used for UDP reflection */
	uint16_t stun_port; /**< Optional STUN server port */
};

/** Configured STUN server for NAT type detection */
struct fastd_stun_server {
	char *host;    /**< STUN server hostname or address */
	uint16_t port; /**< STUN server port */
};

/** Maximum number of public endpoints retained from NAT detection */
#define FASTD_NAT_MAX_PUBLIC_ENDPOINTS 8

/** NAT behavior classification */
typedef enum fastd_nat_type {
	FASTD_NAT_UNKNOWN = 0,        /**< No usable NAT classification is available */
	FASTD_NAT_OPEN_INTERNET,      /**< Directly reachable public endpoint */
	FASTD_NAT_NO_PAT,             /**< NAT changes the address but preserves the UDP port */
	FASTD_NAT_FULL_CONE,          /**< Endpoint-independent mapping and filtering */
	FASTD_NAT_RESTRICTED,         /**< Endpoint-independent mapping with address-restricted filtering */
	FASTD_NAT_PORT_RESTRICTED,    /**< Endpoint-independent mapping with address-and-port filtering */
	FASTD_NAT_SYMMETRIC,          /**< Endpoint-dependent mapping without predictable port direction */
	FASTD_NAT_SYM_UDP_FIREWALL,   /**< Public address with endpoint-dependent UDP filtering */
	FASTD_NAT_SYMMETRIC_EASY_INC, /**< Endpoint-dependent mapping with increasing public ports */
	FASTD_NAT_SYMMETRIC_EASY_DEC, /**< Endpoint-dependent mapping with decreasing public ports */
} fastd_nat_type_t;

/** Snapshot of the latest NAT detection result */
struct fastd_nat_status {
	bool enabled;                   /**< true if NAT detection is configured and running */
	bool available;                 /**< true if a successful STUN result is available */
	fastd_nat_type_t type;          /**< Detected NAT behavior */
	fastd_peer_address_t reflexive; /**< Latest server-reflexive UDP endpoint */
	fastd_peer_address_t reflexive_addrs[FASTD_NAT_MAX_PUBLIC_ENDPOINTS]; /**< Unique UDP reflexive endpoints */
	size_t n_reflexive_addrs;       /**< Number of unique UDP reflexive endpoints */
	uint16_t min_port;              /**< Lowest observed public UDP port, host byte order */
	uint16_t max_port;              /**< Highest observed public UDP port, host byte order */
	int port_delta;                 /**< Typical public port delta for easy symmetric NATs */
	size_t responses;               /**< Number of successful STUN responses used for classification */
	bool tcp_available;             /**< true if a successful TCP STUN result is available */
	fastd_nat_type_t tcp_type;      /**< Detected TCP NAT behavior */
	fastd_peer_address_t tcp_reflexive; /**< Latest server-reflexive TCP endpoint */
	fastd_peer_address_t tcp_reflexive_addrs[FASTD_NAT_MAX_PUBLIC_ENDPOINTS]; /**< Unique TCP reflexive endpoints */
	size_t n_tcp_reflexive_addrs;   /**< Number of unique TCP reflexive endpoints */
	uint16_t tcp_min_port;          /**< Lowest observed public TCP port, host byte order */
	uint16_t tcp_max_port;          /**< Highest observed public TCP port, host byte order */
	size_t tcp_responses;           /**< Number of successful TCP STUN responses used for classification */
	size_t servers;                 /**< Number of configured STUN servers in the worker snapshot */
	fastd_timeout_t last_update;    /**< Monotonic timestamp of the latest completed detection run */
};


/** Type of a traffic stat counter */
typedef enum fastd_stat_type {
	STAT_RX = 0,       /**< Reception statistics (total) */
	STAT_RX_REORDERED, /**< Reception statistics (reordered) */
	STAT_TX,           /**< Transmission statistics (OK) */
	STAT_TX_DROPPED,   /**< Transmission statistics (dropped because of full queues) */
	STAT_TX_ERROR,     /**< Transmission statistics (other errors) */
	STAT_MAX,          /**< (Number of defined stat types) */
} fastd_stat_type_t;

/** Some kind of network transfer statistics */
struct fastd_stats {
#ifdef WITH_STATUS_SOCKET
	uint64_t packets[STAT_MAX]; /**< The number of packets transferred */
	uint64_t bytes[STAT_MAX];   /**< The number of bytes transferred */
#endif
};


/** A data structure keeping track of an unknown addresses that a handshakes was received from recently */
struct fastd_handshake_timeout {
	fastd_peer_address_t address; /**< An address a handshake was received from */
	fastd_timeout_t timeout;      /**< Timeout until handshakes from this address are ignored */
};


/** The static configuration of \em fastd */
struct fastd_config {
	fastd_loglevel_t log_stderr_level; /**< The minimum loglevel of messages to print to stderr (or -1 to not print
					      any messages on stderr) */
	fastd_loglevel_t log_syslog_level; /**< The minimum loglevel of messages to print to syslog (or -1 to not print
					      any messages on syslog) */
	char *log_syslog_ident; /**< The identification string for messages sent to syslog (default: "fastd") */

	char *ifname;       /**< The configured interface name */
	bool iface_persist; /**< Configures if peer-specific interfaces should exist always, or only when there's an
			       established connection */

	size_t n_bind_addrs;              /**< Number of elements in bind_addrs */
	fastd_bind_address_t *bind_addrs; /**< Configured bind addresses */

	fastd_bind_address_t
		*bind_addr_default_v4; /**< Pointer to the bind address to be used for IPv4 connections by default */
	fastd_bind_address_t
		*bind_addr_default_v6; /**< Pointer to the bind address to be used for IPv6 connections by default */

	uint16_t mtu;      /**< The configured MTU */
	fastd_mode_t mode; /**< The configured mode of operation */

#ifdef USE_PACKET_MARK
	uint32_t packet_mark; /**< The configured packet mark (or 0) */
#endif
	bool forward;                      /**< Specifies if packet forwarding is enable */
	bool peer_discovery;               /**< Enables relay-assisted endpoint discovery for direct peer connections */
	bool punch_control_relay;          /**< Relays punch control messages without generic data-plane forwarding */
	fastd_tristate_t punch_data_relay; /**< Relays learned unicast TAP payloads for NAT traversal fallback */
	bool punch_symmetric;              /**< Enables symmetric NAT punch prediction and bounded scans */
	bool punch_keepalive;              /**< Enables periodic keepalives for NAT traversal paths */
	unsigned punch_keepalive_interval; /**< NAT traversal keepalive interval in milliseconds */
	unsigned punch_maintenance_interval; /**< Periodic maintenance interval in milliseconds */
	unsigned punch_announce_interval;    /**< Minimum interval between local punch NAT metadata announcements */
	unsigned punch_relay_interval;       /**< Minimum interval between relay-generated punch commands */
	unsigned punch_max_sockets;          /**< Maximum predicted or probed sockets per punch command */
	unsigned punch_max_packets;          /**< Maximum punch control messages relayed per maintenance interval */
	unsigned punch_max_attempts;         /**< Maximum handshake attempts for one punch-control endpoint */
	unsigned punch_max_backups;          /**< Maximum accepted backup paths kept alive for one peer */
	fastd_realm_config_t realm;          /**< External rendezvous configuration for peer hole punching */
	VECTOR(fastd_stun_server_t) stun_servers; /**< Global STUN servers used for NAT type detection */

	fastd_drop_caps_t drop_caps; /**< Specifies if and when to drop capabilities */

	struct {
		fastd_compression_algorithm_t algorithm; /**< Configured payload compression algorithm */
		int level;                               /**< Configured compression level */
	} compression;                                   /**< Payload compression configuration */

#ifdef USE_USER
	char *user;  /**< Specifies which user to switch to after initialization */
	char *group; /**< Can specify an alternative group to switch to */

	uid_t uid;       /**< The UID of the configured user */
	gid_t gid;       /**< The GID of the configured group */
	size_t n_groups; /**< The number of supplementary groups of the user */
	gid_t *groups;   /**< The supplementary groups of the configured user */
#endif

	const fastd_protocol_t *protocol;  /**< The handshake protocol */
	fastd_string_stack_t *method_list; /**< The list of configured method names */
	fastd_method_info_t *methods;      /**< The list of configured methods */

	size_t min_overhead;     /**< The minimum overhead of all configured methods */
	size_t max_overhead;     /**< The maximum overhead of all configured methods */
	size_t encrypt_headroom; /**< The minimum space a configured methods needs a the beginning of a source buffer to
				  *   encrypt */
	size_t decrypt_headroom; /**< The minimum space a configured methods needs a the beginning of a source buffer to
				  *   decrypt */

	char *secret; /**< The configured secret key */

	fastd_peer_group_t *peer_group; /**< The root peer group configuration */

	fastd_protocol_config_t *protocol_config; /**< The protocol-specific configuration */

	fastd_shell_command_t
		on_pre_up; /**< The command to execute before the initialization of the tunnel interface */
	fastd_shell_command_t on_post_down; /**< The command to execute after the destruction of the tunnel interface */
#ifdef WITH_DYNAMIC_PEERS
	fastd_shell_command_t on_verify;     /**< The command to execute to check if a connection from an unknown peer
						should be allowed */
	fastd_peer_group_t *on_verify_group; /**< The peer group to put dynamic peers into */
#endif

#ifdef WITH_STATUS_SOCKET
	char *status_socket; /**< The path of the status socket */
	bool show_status;    /**< Makes fastd query the configured status socket and exit */
	bool status_json;    /**< Makes --status print raw JSON instead of human-readable output */
#endif

#ifdef WITH_OFFLOAD_L2TP
	bool offload_l2tp; /**< Enable L2TP offloading */
#endif

#ifdef __ANDROID__
	bool android_integration; /**< Enable Android GUI integration features */
#endif

	bool daemon;    /**< Set to make fastd fork to the background after initialization */
	char *pid_file; /**< A filename to write fastd's PID to */

	bool hide_ip_addresses;  /**< Tells fastd to hide peers' IP address in the log output */
	bool hide_mac_addresses; /**< Tells fastd to hide peers' MAC address in the log output */

	bool machine_readable; /**< Supresses explanatory messages in the generate_key and show_key commands */
	bool generate_key;     /**< Makes fastd generate a new keypair and exit */
	bool show_key;         /**< Makes fastd output the public key for the configured secret and exit */
	bool verify_config;    /**< Does basic verification of the configuration and exits */
};


/** Maximum number of recent peer-pair punch tasks kept for status/debugging */
#define FASTD_PUNCH_PAIR_TASK_HISTORY 64

/** Maximum number of peer-pair punch runtime states kept by the task manager */
#define FASTD_PUNCH_PAIR_STATE_LIMIT 1024

/** Number of recently handled punch results remembered for duplicate suppression */
#define FASTD_PUNCH_RESULT_DEDUP_HISTORY 64

/** Lifecycle stage for one collected peer-pair punch task */
typedef enum fastd_punch_pair_task_stage {
	PUNCH_PAIR_TASK_STAGE_NONE = 0,      /**< No peer-pair task has been recorded */
	PUNCH_PAIR_TASK_STAGE_COLLECTED,     /**< Pair was eligible for punch command generation */
	PUNCH_PAIR_TASK_STAGE_LAUNCHED,      /**< Pair emitted at least one punch command */
	PUNCH_PAIR_TASK_STAGE_WAITING,       /**< Pair has metadata, but is waiting for the relay interval */
	PUNCH_PAIR_TASK_STAGE_IN_FLIGHT,     /**< Pair already has a punch task inside its outcome window */
	PUNCH_PAIR_TASK_STAGE_BLACKLISTED,   /**< Pair was held by relay backoff */
	PUNCH_PAIR_TASK_STAGE_SUPPRESSED,    /**< Pair was collected, but no command was emitted */
	PUNCH_PAIR_TASK_STAGE_MISSING_METADATA, /**< Pair lacks usable NAT metadata */
	PUNCH_PAIR_TASK_STAGE_METADATA_REQUESTED, /**< Pair lacks NAT metadata and peers were asked to refresh it */
	PUNCH_PAIR_TASK_STAGE_ABORTED,       /**< In-flight task expired before a usable outcome was observed */
	PUNCH_PAIR_TASK_STAGE_RESULT_ACCEPTED,  /**< Remote peer accepted a punch command */
	PUNCH_PAIR_TASK_STAGE_RESULT_HANDSHAKE, /**< Remote peer sent a handshake for a punch command */
	PUNCH_PAIR_TASK_STAGE_RESULT_SUPPRESSED, /**< Remote peer suppressed a punch command */
	PUNCH_PAIR_TASK_STAGE_RESULT_NO_PEER,   /**< Remote peer did not know the punch subject */
	PUNCH_PAIR_TASK_STAGE_RESULT_BUSY,      /**< Remote peer was busy with an existing verified path */
} fastd_punch_pair_task_stage_t;

/** Recent task-manager lifecycle snapshot for one peer pair */
typedef struct fastd_punch_pair_task {
	uint64_t id;                         /**< Local monotonic peer-pair task ID */
	fastd_timeout_t updated;             /**< Timestamp of this lifecycle snapshot */
	fastd_timeout_t next_retry;          /**< Earliest future retry time known for this pair */
	uint64_t peer_a_id;                  /**< Lower peer ID in the pair */
	uint64_t peer_b_id;                  /**< Higher peer ID in the pair */
	uint64_t subject_id;                 /**< Peer whose endpoint metadata was relayed, if applicable */
	uint64_t destination_id;             /**< Peer receiving the punch command, if applicable */
	fastd_punch_pair_task_stage_t stage; /**< Lifecycle stage */
	uint16_t candidates_sent;            /**< Candidate commands emitted for this pair */
	uint16_t backoff_skipped;            /**< Candidate commands skipped by relay backoff */
	bool budget_exhausted;               /**< true if the global packet budget stopped this run */
} fastd_punch_pair_task_t;

/** Runtime state for one peer pair managed by punch-control task scheduling */
typedef struct fastd_punch_pair_runtime {
	uint64_t peer_a_id;                    /**< Lower peer ID in the pair */
	uint64_t peer_b_id;                    /**< Higher peer ID in the pair */
	fastd_timeout_t updated;               /**< Last time this runtime entry changed */
	fastd_timeout_t in_flight_until;       /**< Outcome window for a launched task */
	fastd_timeout_t backoff_until;         /**< Pair-level retry suppression timeout */
	fastd_timeout_t recent_demand_until;   /**< Recent forwarded data demand window */
	uint64_t demand_seq;                   /**< Monotonic relayed data demand generation */
	uint64_t served_demand_seq;            /**< Latest demand generation covered by a launched task */
	uint16_t launch_count;                 /**< Number of task launches tracked for this pair */
	uint16_t abort_count;                  /**< Number of in-flight windows that expired */
	uint16_t result_count;                 /**< Number of remote command results observed */
	uint16_t busy_count;                   /**< Number of busy/suppressed/no-peer results observed */
} fastd_punch_pair_runtime_t;

/** Recently handled punch result key used to suppress legacy/extended duplicate result packets */
typedef struct fastd_punch_result_seen {
	fastd_timeout_t updated;       /**< Time the result was first handled */
	uint64_t sender_id;            /**< Peer that sent the result */
	uint64_t subject_id;           /**< Peer the result refers to, if locally known */
	uint64_t subject_key_hash;     /**< Hash of the result subject key */
	fastd_peer_address_t endpoint; /**< Endpoint reported by the result */
	uint16_t packet_count;         /**< Punch packet/socket count reported by the result */
	uint8_t result;                /**< fastd_punch_result_t value */
	uint8_t command_type;          /**< FASTD_PUNCH_SEND_* command type, if known */
	bool used;                     /**< true if this slot carries a valid key */
} fastd_punch_result_seen_t;


/** The dynamic state of \em fastd */
struct fastd_context {
	bool log_initialized; /**< true if the logging facilities have been properly initialized */

	int64_t started; /**< The timestamp when fastd was started */

	int64_t now; /**< The current monotonous timestamp in milliseconds after an arbitrary point in time */

	fastd_iface_t *iface; /**< The default tunnel interface */

	uint64_t next_peer_id;        /**< An monotonously increasing ID peers are identified with in some components */
	VECTOR(fastd_peer_t *) peers; /**< The currectly active peers */

#ifdef WITH_DYNAMIC_PEERS
	fastd_sem_t verify_limit; /**< Keeps track of the number of verifier threads */
#endif

#ifdef USE_EPOLL
	int epoll_fd; /**< The file descriptor for the epoll facility */
#else
	VECTOR(fastd_poll_fd_t *) fds; /**< Vector of file descriptors to poll on, indexed by the FD itself */
	VECTOR(struct pollfd) pollfds; /**< The vector of pollfds for all file descriptors */
#endif

#ifdef WITH_STATUS_SOCKET
	fastd_poll_fd_t status_fd; /**< The file descriptor of the status socket */
#endif

#ifdef WITH_OFFLOAD_L2TP
	fastd_offload_l2tp_t *offload_l2tp; /**< Global L2TP offload state */
#endif

	fastd_port_mapping_t *port_mapping; /**< Global automatic port mapping state */
	fastd_nat_detect_t *nat_detect;     /**< Global NAT behavior detection state */

	fastd_task_t turn_task;     /**< Drives the TURN relay GLib main context */
	fastd_realm_state_t *realm; /**< External rendezvous runtime state */

	uint64_t punch_control_tx;        /**< Number of punch control packets sent */
	uint64_t punch_control_rx;        /**< Number of punch control packets received */
	uint64_t punch_direct_handshakes; /**< Number of direct handshakes sent from punch control commands */
	uint64_t punch_direct_success;    /**< Number of direct sessions established from punch control candidates */
	uint64_t punch_direct_failures;   /**< Number of attempted punch control candidates that expired */
	uint64_t punch_direct_suppressed; /**< Number of punch control candidates suppressed after recent failures */
	uint64_t punch_udp_exact_tx;      /**< Number of exact-endpoint UDP punch packets sent */
	uint64_t punch_probe_tx;          /**< Number of UDP punch probe requests sent */
	uint64_t punch_probe_rx;          /**< Number of UDP punch probe packets received */
	uint64_t punch_probe_response_tx; /**< Number of UDP punch probe responses sent */
	uint64_t punch_probe_matched;     /**< Number of matched UDP punch probe responses */
	uint64_t punch_probe_handshakes;  /**< Number of handshakes sent after probe confirmation */
	uint64_t punch_result_tx;         /**< Number of punch result packets sent */
	uint64_t punch_result_rx;         /**< Number of punch result packets received */
	uint64_t punch_result_duplicates; /**< Number of duplicate punch result packets suppressed */
	uint64_t punch_result_accepted;   /**< Number of accepted punch result packets received */
	uint64_t punch_result_handshake;  /**< Number of handshake-sent punch result packets received */
	uint64_t punch_result_suppressed; /**< Number of suppressed punch result packets received */
	uint64_t punch_result_no_peer;    /**< Number of no-peer punch result packets received */
	uint64_t punch_result_busy;       /**< Number of busy punch result packets received */
	uint64_t punch_task_manager_runs; /**< Number of punch task-manager collection runs */
	uint64_t punch_task_manager_pairs; /**< Last task-manager run: established peer pairs considered */
	uint64_t punch_task_manager_collected; /**< Last task-manager run: pairs with a launchable punch direction */
	uint64_t punch_task_manager_launched; /**< Last task-manager run: pairs that emitted punch commands */
	uint64_t punch_task_manager_waiting; /**< Last task-manager run: pairs waiting for relay interval */
	uint64_t punch_task_manager_in_flight; /**< Last task-manager run: pairs waiting for an in-flight task */
	uint64_t punch_task_manager_missing_metadata; /**< Last task-manager run: pairs missing useful NAT metadata */
	uint64_t punch_task_manager_metadata_requests; /**< Last task-manager run: missing-metadata refresh requests */
	uint64_t punch_task_manager_metadata_relays; /**< Last task-manager run: peer metadata relayed to another peer */
	uint64_t punch_task_manager_blacklisted; /**< Last task-manager run: pairs held by relay backoff */
	uint64_t punch_task_manager_suppressed; /**< Last task-manager run: collected pairs that emitted no commands */
	uint64_t punch_task_manager_aborted; /**< Last task-manager run: in-flight tasks aborted during cleanup */
	uint64_t punch_task_manager_recent_demand; /**< Last task-manager run: pairs with recent forwarded traffic demand */
	uint64_t punch_task_manager_budget_exhausted; /**< Last task-manager run: packet budget was exhausted */
	fastd_timeout_t punch_task_manager_next_retry; /**< Last task-manager run: earliest future retry time */
	uint64_t punch_task_manager_outcome_success; /**< Direct paths established from punch-control candidates */
	uint64_t punch_task_manager_outcome_failed; /**< Attempted punch-control candidates that expired */
	uint64_t punch_task_manager_outcome_accepted; /**< Remote peers accepted relayed punch commands */
	uint64_t punch_task_manager_outcome_handshake; /**< Remote peers sent handshakes for relayed commands */
	uint64_t punch_task_manager_outcome_suppressed; /**< Remote peers suppressed relayed commands */
	uint64_t punch_task_manager_outcome_no_peer; /**< Remote peers reported missing punch subjects */
	uint64_t punch_task_manager_outcome_busy; /**< Remote peers reported busy punch targets */
	uint64_t next_punch_task_id;      /**< Monotonic ID for local punch-control task snapshots */
	uint64_t next_punch_pair_task_id; /**< Monotonic ID for task-manager peer-pair snapshots */
	fastd_punch_pair_task_t punch_pair_tasks[FASTD_PUNCH_PAIR_TASK_HISTORY]; /**< Recent peer-pair task snapshots */
	size_t punch_pair_task_pos;       /**< Next ring-buffer slot for peer-pair task snapshots */
	size_t punch_pair_task_count;     /**< Number of valid peer-pair task snapshots in the ring buffer */
	VECTOR(fastd_punch_pair_runtime_t) punch_pair_states; /**< Active punch-control peer-pair runtime states */
	fastd_punch_result_seen_t punch_result_seen[FASTD_PUNCH_RESULT_DEDUP_HISTORY]; /**< Recent result dedup keys */
	size_t punch_result_seen_pos;     /**< Next ring-buffer slot for punch result duplicate suppression */
	uint32_t next_punch_listener_id;  /**< Monotonic ID for reusable public punch listeners */

	bool has_floating; /**< Specifies if any of the configured peers have floating remotes */
	uint16_t max_mtu;  /**< The maximum MTU of all peer-specific interfaces */
	size_t max_buffer; /**< Maximum buffer size needed for any combination of peer MTU, method, or handshake */

	uint32_t peer_addr_ht_seed;           /**< The hash seed used for peer_addr_ht */
	size_t peer_addr_ht_size;             /**< The number of hash buckets in the peer address hashtable */
	size_t peer_addr_ht_used;             /**< The current number of entries in the peer address hashtable */
	VECTOR(fastd_peer_t *) *peer_addr_ht; /**< An array of hash buckets for the peer hash table */

	fastd_pqueue_t *task_queue;    /**< Priority queue of scheduled tasks */
	fastd_task_t next_maintenance; /**< Schedules the next maintenance call */

	VECTOR(pid_t) async_pids; /**< PIDs of asynchronously executed commands which still have to be reaped */
	fastd_poll_fd_t
		async_rfd; /**< The read side of the pipe used to send data from other threads to the main thread */
	int async_wfd;     /**< The write side of the pipe used to send data from other threads to the main thread */

	pthread_attr_t detached_thread; /**< pthread_attr_t for creating detached threads */

#ifdef __ANDROID__
	int android_ctrl_sock_fd; /**< The unix domain socket for communicating with Android GUI */
#endif

	FILE *urandom;  /**< /dev/urandom FILE */
	int ioctl_sock; /**< The global ioctl socket */

	size_t n_socks;                           /**< The number of sockets in socks */
	fastd_socket_t *socks;                    /**< Array of all sockets */
	VECTOR(fastd_socket_t *) tcp_socks;       /**< Allocated TCP connection sockets */
	VECTOR(fastd_socket_t *) udp_punch_socks; /**< Allocated unclaimed UDP hole punching sockets */
	VECTOR(fastd_socket_t *) deferred_socks;  /**< Closed dynamic sockets waiting for safe memory release */

	fastd_socket_t *sock_default_v4; /**< Points to the socket that is used for new outgoing IPv4 connections */
	fastd_socket_t *sock_default_v6; /**< Points to the socket that is used for new outgoing IPv6 connections */

	fastd_stats_t stats; /**< Traffic statistics */

	VECTOR(fastd_peer_eth_addr_t)
	eth_addrs; /**< Sorted vector of all known ethernet addresses with associated peers and timeouts */

	uint32_t unknown_handshake_seed; /**< Hash seed for the unknown handshake hashtables */
	fastd_handshake_timeout_t
		*unknown_handshakes[UNKNOWN_TABLES]; /**< Hash tables unknown addresses handshakes have been sent to */

	fastd_protocol_state_t *protocol_state; /**< Protocol-specific state */
};

/** A stack of strings */
struct fastd_string_stack {
	fastd_string_stack_t *next; /**< The next element of the stack */
	char str[];                 /**< Zero-terminated character data */
};


extern fastd_context_t ctx;
extern fastd_config_t conf;


void fastd_main(int argc, char *argv[]);


void fastd_send(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_buffer_t *buffer, size_t stat_size);
void fastd_send_data(fastd_buffer_t *buffer, fastd_peer_t *source, fastd_peer_t *dest);
bool fastd_send_data_relay(fastd_buffer_t *buffer, fastd_peer_t *source);

void fastd_receive_unknown_init(void);
void fastd_receive_unknown_free(void);
void fastd_receive_unknown_purge(fastd_peer_address_t addr);
void fastd_receive_packet(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_buffer_t *buffer);
void fastd_receive(fastd_socket_t *sock);
void fastd_handle_receive(fastd_peer_t *peer, fastd_buffer_t *buffer, bool reordered);

void fastd_close_all_fds(void);

void fastd_socket_bind_all(void);
fastd_socket_t *fastd_socket_open(fastd_peer_t *peer, int af);
fastd_socket_t *
fastd_socket_open_tcp(fastd_peer_t *peer, const fastd_socket_t *base_sock, const fastd_peer_address_t *remote_addr);
fastd_socket_t *fastd_socket_open_offload(fastd_socket_t *sock, const fastd_peer_address_t *local_addr);
void fastd_socket_close(fastd_socket_t *sock);
void fastd_socket_error(const fastd_socket_t *sock);
void fastd_socket_handle(fastd_socket_t *sock, bool input, bool output, bool error);
bool fastd_socket_is_open(const fastd_socket_t *sock);
bool fastd_socket_is_tcp(const fastd_socket_t *sock);
bool fastd_socket_is_hole_punch(const fastd_socket_t *sock);
void fastd_socket_update_tcp_listeners(void);
bool fastd_tcp_send(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const fastd_buffer_t *buffer, size_t stat_size);
bool fastd_udp_punch_send(
	fastd_peer_t *peer, const fastd_socket_t *sock, const fastd_peer_address_t *remote_addr,
	const fastd_buffer_t *buffer);
fastd_socket_t *fastd_udp_punch_find_socket(fastd_peer_t *peer, const fastd_peer_address_t *remote_addr);
bool fastd_udp_punch_select_listener(
	sa_family_t family, bool force_new, bool prefer_port_mapping, fastd_peer_address_t *public_addr,
	bool *port_mapped, uint32_t *listener_id);
void fastd_punch_probe_init_socket(fastd_socket_t *sock);
bool fastd_punch_probe_send(fastd_socket_t *sock, const fastd_peer_address_t *remote_addr);
bool fastd_punch_probe_handle(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	const uint8_t *data, size_t len);
void fastd_hole_punch_claim_socket(fastd_socket_t *sock);
void fastd_hole_punch_close_peer(fastd_peer_t *peer);
void fastd_udp_punch_maintenance(void);
void fastd_udp_punch_cleanup(void);
void fastd_socket_free_deferred(void);
void fastd_socket_free_dynamic(fastd_socket_t *sock);
void fastd_tcp_maintenance(void);
void fastd_tcp_cleanup(void);
void fastd_punch_note_peer_pair_demand(const fastd_peer_t *a, const fastd_peer_t *b);
void fastd_punch_cleanup(void);

void fastd_resolve_peer(fastd_peer_t *peer, fastd_remote_t *remote);

bool fastd_port_mapping_check(void);
void fastd_port_mapping_init(void);
void fastd_port_mapping_refresh(void);
void fastd_port_mapping_handle(void);
void fastd_port_mapping_handle_task(void);
bool fastd_port_mapping_register_socket(fastd_socket_t *sock);
bool fastd_port_mapping_get_external_address(const fastd_socket_t *sock, fastd_peer_address_t *addr);
void fastd_port_mapping_release_socket(fastd_socket_t *sock);
void fastd_port_mapping_cleanup(void);

bool fastd_turn_check(void);
void fastd_turn_handle_task(void);
void fastd_turn_cleanup(void);

void fastd_nat_add_stun_server(const char *host, uint16_t port);
bool fastd_nat_check(void);
void fastd_nat_init(void);
void fastd_nat_handle_task(void);
void fastd_nat_cleanup(void);
bool fastd_nat_get_status(fastd_nat_status_t *status);
bool fastd_nat_get_public_address(fastd_peer_address_t *addr);
bool fastd_nat_get_tcp_public_address(fastd_peer_address_t *addr);
bool fastd_nat_request_refresh(void);
const char *fastd_nat_type_name(fastd_nat_type_t type);

bool fastd_punch_handle_control(fastd_peer_t *peer, fastd_buffer_t *buffer);
void fastd_punch_maintenance(void);

#if defined(WITH_STATUS_SOCKET) && defined(WITH_TESTS)
struct json_object *fastd_status_test_dump_hole_punch(const fastd_peer_t *peer);
struct json_object *fastd_status_test_dump_punch(void);
#endif

#ifdef WITH_TESTS
bool fastd_socket_test_udp_punch_exact_family_supported(sa_family_t family);
bool fastd_socket_test_udp_punch_deterministic_family_supported(sa_family_t family);
bool fastd_socket_test_udp_punch_public_listener_available(const fastd_socket_t *sock);
size_t fastd_socket_test_udp_punch_public_listener_count(void);
size_t fastd_socket_test_udp_punch_active_socket_count(void);
bool fastd_socket_test_udp_punch_should_create_public_listener(
	size_t current_listener_count, bool has_reusable_listener, bool has_port_mapping_listener, bool force_new,
	bool prefer_port_mapping);
uint32_t fastd_socket_test_udp_punch_select_public_listener_id(sa_family_t family, bool prefer_port_mapping);
void fastd_port_mapping_test_begin(bool natpmp_requested, bool upnp_requested);
void fastd_port_mapping_test_end(void);
size_t fastd_port_mapping_test_entry_count(void);
bool fastd_port_mapping_test_get_entry(
	uint16_t port, bool *use_natpmp, bool *use_upnp_igd, uint16_t *dynamic_natpmp_refs,
	uint16_t *dynamic_upnp_igd_refs);
bool fastd_punch_probe_test_parse(
	const uint8_t *data, size_t len, uint8_t *type, uint32_t *transaction, size_t *key_len);
size_t fastd_punch_probe_test_build(uint8_t *out, size_t out_len, uint8_t type, uint32_t transaction, size_t key_len);
#endif

bool fastd_realm_check(void);
void fastd_realm_init(void);
void fastd_realm_handle_task(void);
void fastd_realm_cleanup(void);

bool fastd_iface_format_name(char ifname[IFNAMSIZ], const fastd_peer_t *peer);
fastd_iface_t *fastd_iface_open(fastd_peer_t *peer);
void fastd_iface_handle(fastd_iface_t *iface);
void fastd_iface_write(fastd_iface_t *iface, fastd_buffer_t *buffer);
void fastd_iface_close(fastd_iface_t *iface);
#ifdef __linux__
bool fastd_iface_set_mtu(const char *ifname, uint16_t mtu);
#endif

void fastd_random_init(void);
void fastd_random_bytes(void *buffer, size_t len, bool secure);
void fastd_random_cleanup(void);

int64_t fastd_get_time(void);


#ifdef __ANDROID__

int fastd_android_receive_tunfd(void);
void fastd_android_send_pid(void);
bool fastd_android_protect_socket(int fd);

#endif /* __ANDROID__ */


#ifdef WITH_CAPABILITIES

void fastd_cap_acquire(void);
void fastd_cap_reacquire_drop(void);

#else /* WITH_CAPABILITIES */

static inline void fastd_cap_acquire(void) {}
static inline void fastd_cap_reacquire_drop(void) {}

#endif /* WITH_CAPABILITIES */


#ifdef WITH_STATUS_SOCKET

void fastd_status_init(void);
void fastd_status_close(void);
void fastd_status_handle(void);
void fastd_status_query(const char *socket_path, bool json);

#else /* WITH_STATUS_SOCKET */

static inline void fastd_status_init(void) {}
static inline void fastd_status_close(void) {}
static inline void fastd_status_handle(void) {}

#endif /* WITH_STATUS_SOCKET */


/** Returns a random number between \a min (inclusively) and \a max (exclusively) */
static inline int fastd_rand(int min, int max) {
	unsigned int r = (unsigned int)random();
	return (r % (max - min) + min);
}

/** Sets the O_NONBLOCK flag on a file descriptor */
static inline void fastd_setnonblock(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		exit_errno("Getting file status flags failed: fcntl");

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		exit_errno("Setting file status flags failed: fcntl");
}


/** Returns the maximum payload size \em fastd is configured to transport */
static inline size_t fastd_max_payload(uint16_t mtu) {
	switch (conf.mode) {
	case MODE_TAP:
	case MODE_MULTITAP:
		return mtu + sizeof(fastd_eth_header_t);
	case MODE_TUN:
		return mtu;
	default:
		exit_bug("invalid mode");
	}
}


/** Returns the source address of an ethernet packet */
static inline fastd_eth_addr_t fastd_buffer_source_address(const fastd_buffer_t *buffer) {
	fastd_eth_addr_t ret;
	memcpy(&ret, buffer->data + offsetof(fastd_eth_header_t, source), sizeof(fastd_eth_addr_t));
	return ret;
}

/** Returns the destination address of an ethernet packet */
static inline fastd_eth_addr_t fastd_buffer_dest_address(const fastd_buffer_t *buffer) {
	fastd_eth_addr_t ret;
	memcpy(&ret, buffer->data + offsetof(fastd_eth_header_t, dest), sizeof(fastd_eth_addr_t));
	return ret;
}


/** Checks if a fastd_peer_address_t is an IPv6 link-local address */
static inline bool fastd_peer_address_is_v6_ll(const fastd_peer_address_t *addr) {
	return (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr));
}

/** Duplicates a string, creating a one-element string stack */
static inline fastd_string_stack_t *fastd_string_stack_dup(const char *str) {
	size_t str_len = strlen(str);
	fastd_string_stack_t *ret = fastd_alloc(alignto(sizeof(fastd_string_stack_t) + str_len + 1, 8));

	ret->next = NULL;

	memcpy(ret->str, str, str_len + 1);

	return ret;
}

/** Duplicates a string of a given maximum length, creating a one-element string stack */
static inline fastd_string_stack_t *fastd_string_stack_dupn(const char *str, size_t len) {
	size_t str_len = strnlen(str, len);
	fastd_string_stack_t *ret = fastd_alloc(alignto(sizeof(fastd_string_stack_t) + str_len + 1, 8));

	ret->next = NULL;

	memcpy(ret->str, str, str_len);
	ret->str[str_len] = 0;

	return ret;
}

/** Pushes the copy of a string onto the top of a string stack */
static inline fastd_string_stack_t *fastd_string_stack_push(fastd_string_stack_t *stack, const char *str) {
	size_t str_len = strlen(str);
	fastd_string_stack_t *ret = fastd_alloc(alignto(sizeof(fastd_string_stack_t) + str_len + 1, 8));

	ret->next = stack;

	memcpy(ret->str, str, str_len + 1);

	return ret;
}

/** Gets the head of string stack (or NULL if the stack is NULL) */
static inline const char *fastd_string_stack_get(const fastd_string_stack_t *stack) {
	return stack ? stack->str : NULL;
}

/** Checks if a string is contained in a string stack */
static inline bool fastd_string_stack_contains(const fastd_string_stack_t *stack, const char *str) {
	while (stack) {
		if (strcmp(stack->str, str) == 0)
			return true;

		stack = stack->next;
	}

	return false;
}

/** Frees a whole string stack */
static inline void fastd_string_stack_free(fastd_string_stack_t *str) {
	while (str) {
		fastd_string_stack_t *next = str->next;
		free(str);
		str = next;
	}
}

/**
   Checks if a timeout has occured

   @param timeout the time the timeout should occur

   @return true if the given timeout is before or equal to the current time

   \note The current time is updated only once per main loop iteration, after waiting for input.
*/
static inline bool fastd_timed_out(fastd_timeout_t timeout) {
	return timeout <= ctx.now;
}

/** Returns the minimum of two fastd_timeout_t values */
static inline fastd_timeout_t fastd_timeout_min(fastd_timeout_t a, fastd_timeout_t b) {
	return (a < b) ? a : b;
}

/** Updates a timeout, ensuring it can only increase */
static inline void fastd_timeout_advance(fastd_timeout_t *a, fastd_timeout_t v) {
	if (*a < v)
		*a = v;
}

/** Updates the current time */
static inline void fastd_update_time(void) {
	ctx.now = fastd_get_time();
}

/** Checks if a on-verify command is set */
static inline bool fastd_allow_verify(void) {
#ifdef WITH_DYNAMIC_PEERS
	return fastd_shell_command_isset(&conf.on_verify);
#else
	return false;
#endif
}

/** Returns true if L2TP offloading is enabled */
static inline bool fastd_use_offload_l2tp(void) {
#ifdef WITH_OFFLOAD_L2TP
	return conf.offload_l2tp;
#else
	return false;
#endif
}

/** Returns true if a port mapping mode uses NAT-PMP */
static inline bool fastd_port_mapping_uses_natpmp(fastd_port_mapping_mode_t mode) {
	return mode == PORT_MAPPING_NATPMP || mode == PORT_MAPPING_AUTO;
}

/** Returns true if a port mapping mode uses UPnP IGD */
static inline bool fastd_port_mapping_uses_upnp_igd(fastd_port_mapping_mode_t mode) {
	return mode == PORT_MAPPING_UPNP_IGD || mode == PORT_MAPPING_AUTO;
}

/** Returns true if android integration is enabled */
static inline bool fastd_use_android_integration(void) {
#ifdef __ANDROID__
	return conf.android_integration;
#else
	return false;
#endif
}
