// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Peer groups
*/


#pragma once

#include "fastd.h"


/**
   A group of peers

   Peer groups may be nested and form a tree
*/
struct fastd_peer_group {
	fastd_peer_group_t *next;     /**< The next sibling in the group tree */
	fastd_peer_group_t *parent;   /**< The group's parent group */
	fastd_peer_group_t *children; /**< The group's first child */

	char *name;                      /**< The group's name; NULL for the root group */
	fastd_string_stack_t *peer_dirs; /**< List of peer directories which belong to this group */

	int max_connections;           /**< The maximum number of connections to allow in this group; -1 for no limit */
	fastd_string_stack_t *methods; /**< The list of configured method names */
	fastd_port_mapping_mode_t port_mapping; /**< Automatic port mapping mode for peers in this group */
	fastd_peer_transport_t transport;       /**< Transport protocol for peers in this group */
	fastd_hole_punch_mode_t hole_punch;     /**< Hole punching mode for peers in this group */
	fastd_tristate_t nat_traversal;         /**< Whether peers in this group should use NAT traversal */
	fastd_tristate_t turn_relay;            /**< Whether peers in this group should use TURN relay */
	fastd_turn_server_t *turn_servers;      /**< TURN servers for peers in this group */

	fastd_shell_command_t on_up;   /**< The command to execute after the initialization of the tunnel interface */
	fastd_shell_command_t on_down; /**< The command to execute before the destruction of the tunnel interface */
	fastd_shell_command_t
		on_connect; /**< The command to execute before a handshake is sent to establish a new connection */
	fastd_shell_command_t on_establish;    /**< The command to execute when a new connection has been established */
	fastd_shell_command_t on_disestablish; /**< The command to execute when a connection has been disestablished */
};


/**
   Looks up an attribute in the peer group tree

   Returns a pointer to the attribute, going up the group tree to the first group
   where the attribute is not NULL if such a group exists.

   @param group		the peer group
   @param attr		the name of the member

   \hideinitializer
 */
#define fastd_peer_group_lookup(group, attr)              \
	({                                                \
		const fastd_peer_group_t *_grp = (group); \
                                                          \
		while (_grp->parent && !_grp->attr)       \
			_grp = _grp->parent;              \
                                                          \
		&_grp->attr;                              \
	})

/**
   Looks up an attribute in the peer group tree, for a given peer

   Returns a pointer to the attribute, going up the group tree to the first group
   where the attribute is not NULL if such a group exists. Uses the default group
   if no peer is given.

   @param peer		the peer
   @param attr		the name of the member

   \hideinitializer
 */
#define fastd_peer_group_lookup_peer(peer, attr)                                              \
	({                                                                                    \
		const fastd_peer_t *_peer = (peer);                                           \
		_peer ? fastd_peer_group_lookup(_peer->group, attr) : &conf.peer_group->attr; \
	})

/**
   Looks up an shell command attribute in the peer group tree, for a given peer

   Returns a pointer to the attribute, going up the group tree to the first group
   where the attribute is not NULL if such a group exists. Uses the default group
   if no peer is given.

   @param peer		the peer
   @param attr		the name of the shell command member

   \hideinitializer
 */
#define fastd_peer_group_lookup_peer_shell_command(peer, attr) \
	container_of(fastd_peer_group_lookup_peer(peer, attr.command), fastd_shell_command_t, command)

/** Returns the inherited automatic port mapping mode for a peer group */
static inline fastd_port_mapping_mode_t fastd_peer_group_get_port_mapping_mode(const fastd_peer_group_t *group) {
	return *fastd_peer_group_lookup(group, port_mapping);
}

/** Returns the inherited transport protocol for a peer group */
static inline fastd_peer_transport_t fastd_peer_group_get_transport(const fastd_peer_group_t *group) {
	return *fastd_peer_group_lookup(group, transport);
}

/** Returns the inherited hole punching mode for a peer group */
static inline fastd_hole_punch_mode_t fastd_peer_group_get_hole_punch(const fastd_peer_group_t *group) {
	return *fastd_peer_group_lookup(group, hole_punch);
}

/** Returns the inherited NAT traversal setting for a peer group */
static inline bool fastd_peer_group_get_nat_traversal(const fastd_peer_group_t *group) {
	while (group->parent && !group->nat_traversal.set)
		group = group->parent;

	return group->nat_traversal.state;
}

/** Returns the inherited TURN server list for a peer group */
static inline const fastd_turn_server_t *fastd_peer_group_get_turn_servers(const fastd_peer_group_t *group) {
	return *fastd_peer_group_lookup(group, turn_servers);
}

/** Returns the inherited TURN relay setting for a peer group */
static inline bool fastd_peer_group_get_turn_relay(const fastd_peer_group_t *group) {
	const fastd_peer_group_t *orig_group = group;

	while (group->parent && !group->turn_relay.set)
		group = group->parent;

	if (!group->turn_relay.set)
		return fastd_peer_group_get_nat_traversal(orig_group) && fastd_peer_group_get_turn_servers(orig_group);

	return group->turn_relay.state;
}
