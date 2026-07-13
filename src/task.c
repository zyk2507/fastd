// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Task queue
*/

#include "task.h"
#include "peer.h"


/** Performs periodic maintenance tasks */
static inline void maintenance(void) {
	fastd_peer_eth_addr_cleanup();
	fastd_tcp_maintenance();
	fastd_udp_punch_maintenance();
	fastd_punch_maintenance();
	fastd_task_reschedule_relative(&ctx.next_maintenance, conf.punch_maintenance_interval);
}

/** Handles one task */
static void handle_task(void) {
	fastd_task_t *task = container_of(ctx.task_queue, fastd_task_t, entry);
	fastd_pqueue_remove(ctx.task_queue);

	switch (task->type) {
	case TASK_TYPE_MAINTENANCE:
		maintenance();
		break;

	case TASK_TYPE_PEER:
		fastd_peer_handle_task(task);
		break;

	case TASK_TYPE_NATPMP:
		fastd_port_mapping_handle_task();
		break;

	case TASK_TYPE_UPNP_IGD:
		fastd_port_mapping_handle_upnp_task();
		break;

	case TASK_TYPE_PCP:
		fastd_port_mapping_handle_pcp_task();
		break;

	case TASK_TYPE_TURN:
		fastd_turn_handle_task();
		break;

	case TASK_TYPE_REALM:
		fastd_realm_handle_task();
		break;

	case TASK_TYPE_NAT_DETECT:
		fastd_nat_handle_task();
		break;

	default:
		exit_bug("unknown task type");
	}
}

/** Handles all tasks whose timeout has been reached */
void fastd_task_handle(void) {
	while (ctx.task_queue && fastd_timed_out(ctx.task_queue->value))
		handle_task();
}

/** Puts a task back into the queue with a new timeout */
void fastd_task_reschedule(fastd_task_t *task, fastd_timeout_t timeout) {
	task->entry.value = timeout;
	fastd_pqueue_insert(&ctx.task_queue, &task->entry);
}

/** Gets the timeout of the next task in the task queue */
fastd_timeout_t fastd_task_queue_timeout(void) {
	if (!ctx.task_queue)
		return FASTD_TIMEOUT_INV;

	return ctx.task_queue->value;
}
