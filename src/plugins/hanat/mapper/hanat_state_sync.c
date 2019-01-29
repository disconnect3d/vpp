/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hanat_state_sync.h"
#include "hanat_mapper_db.h"
#include "hanat_mapper.h"
#include <vnet/udp/udp.h>

#define foreach_hanat_state_sync_counter     \
_(RECV_ADD, "add-event-recv", 0)             \
_(RECV_DEL, "del-event-recv", 1)             \
_(RECV_KEEPALIVE, "keepalive-event-recv", 2) \
_(SEND_ADD, "add-event-send", 3)             \
_(SEND_DEL, "del-event-send", 4)             \
_(SEND_KEEPALIVE, "keepalive-event-send", 5)

typedef enum
{
#define _(N, s, v) HANAT_STATE_SYNC_COUNTER_##N = v,
  foreach_hanat_state_sync_counter
#undef _
  HANAT_STATE_SYNC_N_COUNTERS
} hanat_state_sync_counter_t;

typedef struct
{
  ip4_address_t ip_address;
  u16 port;
  vlib_buffer_t *state_sync_buffer;
  vlib_frame_t *state_sync_frame;
  u16 state_sync_count;
  u32 state_sync_next_event_offset;
} hanat_state_sync_failover_t;

typedef struct hanat_state_sync_main_s
{
  ip4_address_t src_ip_address;
  u16 src_port;
  u32 state_sync_path_mtu;
  vlib_simple_counter_main_t counters[HANAT_STATE_SYNC_N_COUNTERS];
  vlib_main_t *vlib_main;
  hanat_state_sync_failover_t *failovers;
} hanat_state_sync_main_t;

hanat_state_sync_main_t hanat_state_sync_main;
vlib_node_registration_t hanat_state_sync_process_node;

void
hanat_state_sync_init (vlib_main_t * vm)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;

  sm->src_ip_address.as_u32 = 0;
  sm->src_port = 0;

#define _(N, s, v) sm->counters[v].name = s;              \
  sm->counters[v].stat_segment_name = "/hanat-mapper/" s; \
  vlib_validate_simple_counter(&sm->counters[v], 0);      \
  vlib_zero_simple_counter(&sm->counters[v], 0);
  foreach_hanat_state_sync_counter
#undef _
    sm->vlib_main = vm;
}

int
hanat_state_sync_set_listener (ip4_address_t * addr, u16 port, u32 path_mtu)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;

  sm->src_ip_address.as_u32 = addr->as_u32;
  sm->src_port = port;
  sm->state_sync_path_mtu = path_mtu;

  udp_register_dst_port (sm->vlib_main, port, hanat_state_sync_node.index, 1);

  return 0;
}

int
hanat_state_sync_add_del_failover (ip4_address_t * addr, u16 port,
				   u32 * index, u8 is_add)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  hanat_state_sync_failover_t *failover = 0, *f;

  /* *INDENT-OFF* */
  pool_foreach (f, sm->failovers,
  ({
    if (f->ip_address.as_u32 == addr->as_u32 && f->port == port)
      {
        failover = f;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (is_add)
    {
      if (failover)
	return VNET_API_ERROR_VALUE_EXIST;

      if (!pool_elts (sm->failovers))
	vlib_process_signal_event (sm->vlib_main,
				   hanat_state_sync_process_node.index, 1, 0);

      pool_get (sm->failovers, failover);
      clib_memset (failover, 0, sizeof (*failover));
      failover->port = port;
      failover->ip_address.as_u32 = addr->as_u32;
      *index = failover - sm->failovers;
    }
  else
    {
      if (!failover)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      /* flush chached events */
      hanat_state_sync_event_add (0, 1, failover - sm->failovers, 0);
      pool_put (sm->failovers, failover);
    }

  return 0;
}

static void
hanat_state_sync_recv_add (hanat_state_sync_event_t * event, f64 now,
			   u32 thread_index)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  hanat_mapper_mapping_t *mapping;
  hanat_mapper_user_t *user;
  ip4_address_t in_l_addr, in_r_addr, out_l_addr, out_r_addr;
  u32 tenant_id, pool_id;

  vlib_increment_simple_counter (&sm->counters
				 [HANAT_STATE_SYNC_COUNTER_RECV_ADD],
				 thread_index, 0, 1);

  in_l_addr.as_u32 = event->in_l_addr;
  in_r_addr.as_u32 = event->in_r_addr;
  out_l_addr.as_u32 = event->out_l_addr;
  out_r_addr.as_u32 = event->out_r_addr;
  tenant_id = clib_net_to_host_u32 (event->tenant_id);
  pool_id = clib_net_to_host_u32 (event->pool_id);

  user = hanat_mapper_user_get (&nm->db, &in_l_addr, tenant_id);
  if (!user)
    {
      user = hanat_mapper_user_create (&nm->db, &in_l_addr, tenant_id);
      if (!user)
	{
	  clib_warning ("hanat-state-sync: user_create failed");
	  return;
	}
    }

  mapping =
    hanat_mapper_mapping_get (&nm->db, &in_l_addr, event->in_l_port,
			      event->protocol, tenant_id, 1);
  if (!mapping)
    {
      hanat_mapper_set_out_addr_and_port (pool_id, event->protocol,
					  &out_l_addr, event->out_l_port);

      mapping =
	hanat_mapper_mappig_create (&nm->db, &in_l_addr, event->in_l_port,
				    &out_l_addr, event->out_l_port,
				    event->protocol, pool_id, tenant_id, 0);

      if (!mapping)
	{
	  clib_warning ("hanat-state-sync: mappig_create failed");
	  return;
	}
    }

  session =
    hanat_mapper_session_create (&nm->db, mapping, &in_r_addr,
				 event->in_r_port, &out_r_addr,
				 event->out_r_port, user, now, 0, 0);
  if (!session)
    {
      clib_warning ("hanat-state-sync: session_create failed");
      return;
    }

  session_reset_timeout (nm, session, now);
}

static void
hanat_state_sync_recv_del (hanat_state_sync_event_t * event, u32 thread_index)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  ip4_address_t in_l_addr, in_r_addr;

  vlib_increment_simple_counter (&sm->counters
				 [HANAT_STATE_SYNC_COUNTER_RECV_DEL],
				 thread_index, 0, 1);

  in_l_addr.as_u32 = event->in_l_addr;
  in_r_addr.as_u32 = event->in_r_addr;

  session =
    hanat_mapper_session_get (&nm->db, &in_l_addr, event->in_l_port,
			      &in_r_addr, event->in_r_port, event->protocol,
			      clib_net_to_host_u32 (event->tenant_id), 1);

  if (session)
    hanat_mapper_session_free (&nm->db, session);
}

static void
hanat_state_sync_recv_keepalive (hanat_state_sync_event_t * event, f64 now,
				 u32 thread_index)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  ip4_address_t in_l_addr, in_r_addr;

  vlib_increment_simple_counter (&sm->counters
				 [HANAT_STATE_SYNC_COUNTER_RECV_KEEPALIVE],
				 thread_index, 0, 1);

  in_l_addr.as_u32 = event->in_l_addr;
  in_r_addr.as_u32 = event->in_r_addr;

  session =
    hanat_mapper_session_get (&nm->db, &in_l_addr, event->in_l_port,
			      &in_r_addr, event->in_r_port, event->protocol,
			      clib_net_to_host_u32 (event->tenant_id), 1);

  if (session)
    session_reset_timeout (nm, session, now);
}

void
hanat_state_sync_event_process (hanat_state_sync_event_t * event, f64 now,
				u32 thread_index)
{
  switch (event->event_type)
    {
    case HANAT_STATE_SYNC_ADD:
      hanat_state_sync_recv_add (event, now, thread_index);
      break;
    case HANAT_STATE_SYNC_DEL:
      hanat_state_sync_recv_del (event, thread_index);
      break;
    case HANAT_STATE_SYNC_KEEPALIVE:
      hanat_state_sync_recv_keepalive (event, now, thread_index);
      break;
    default:
      clib_warning ("Unsupported HA NAT state sync event type %d",
		    event->event_type);
      break;
    }
}

static inline void
hanat_state_sync_header_create (vlib_buffer_t * b, u32 * offset,
				u32 failover_index)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  hanat_state_sync_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  hanat_state_sync_failover_t *failover =
    pool_elt_at_index (sm->failovers, failover_index);

  b->current_data = 0;
  b->current_length = sizeof (*ip) + sizeof (*udp) + sizeof (*h);
  b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = 0;
  ip = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip + 1);
  h = (hanat_state_sync_message_header_t *) (udp + 1);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->flags_and_fragment_offset =
    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
  ip->src_address.as_u32 = sm->src_ip_address.as_u32;
  ip->dst_address.as_u32 = failover->ip_address.as_u32;
  udp->src_port = clib_host_to_net_u16 (sm->src_port);
  udp->dst_port = clib_host_to_net_u16 (failover->port);
  udp->checksum = 0;

  h->version = HANAT_STATE_SYNC_VERSION;
  h->rsvd = 0;
  h->count = 0;

  *offset =
    sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (hanat_state_sync_message_header_t);
}

static inline void
hanat_state_sync_send (vlib_frame_t * f, vlib_buffer_t * b,
		       u32 failover_index)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  hanat_state_sync_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  vlib_main_t *vm = sm->vlib_main;
  hanat_state_sync_failover_t *failover =
    pool_elt_at_index (sm->failovers, failover_index);

  ip = vlib_buffer_get_current (b);
  udp = ip4_next_header (ip);
  h = (hanat_state_sync_message_header_t *) (udp + 1);

  h->count = clib_host_to_net_u16 (failover->state_sync_count);

  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b->current_length - sizeof (*ip));

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
}

void
hanat_state_sync_event_add (hanat_state_sync_event_t * event, u8 do_flush,
			    u32 failover_index, u32 thread_index)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  vlib_main_t *vm = sm->vlib_main;
  vlib_buffer_t *b = 0;
  vlib_frame_t *f;
  u32 bi = ~0, offset;
  hanat_state_sync_failover_t *failover;

  if (pool_is_free_index (sm->failovers, failover_index))
    return;

  failover = pool_elt_at_index (sm->failovers, failover_index);

  b = failover->state_sync_buffer;

  if (PREDICT_FALSE (b == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	{
	  clib_warning ("HA NAT state sync can't allocate buffer");
	  return;
	}

      b = failover->state_sync_buffer = vlib_get_buffer (vm, bi);
      clib_memset (vnet_buffer (b), 0, sizeof (*vnet_buffer (b)));
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
      offset = 0;
    }
  else
    {
      bi = vlib_get_buffer_index (vm, b);
      offset = failover->state_sync_next_event_offset;
    }

  f = failover->state_sync_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      failover->state_sync_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (failover->state_sync_count == 0))
    hanat_state_sync_header_create (b, &offset, failover_index);

  if (PREDICT_TRUE (do_flush == 0))
    {
      clib_memcpy_fast (b->data + offset, event, sizeof (*event));
      offset += sizeof (*event);
      failover->state_sync_count++;
      b->current_length += sizeof (*event);

      switch (event->event_type)
	{
	case HANAT_STATE_SYNC_ADD:
	  vlib_increment_simple_counter (&sm->counters
					 [HANAT_STATE_SYNC_COUNTER_SEND_ADD],
					 thread_index, 0, 1);
	  break;
	case HANAT_STATE_SYNC_DEL:
	  vlib_increment_simple_counter (&sm->counters
					 [HANAT_STATE_SYNC_COUNTER_SEND_DEL],
					 thread_index, 0, 1);
	  break;
	case HANAT_STATE_SYNC_KEEPALIVE:
	  vlib_increment_simple_counter (&sm->counters
					 [HANAT_STATE_SYNC_COUNTER_SEND_DEL],
					 thread_index, 0, 1);
	  break;
	default:
	  break;
	}
    }

  if (PREDICT_FALSE
      (do_flush || offset + (sizeof (*event)) > sm->state_sync_path_mtu))
    {
      hanat_state_sync_send (f, b, failover_index);
      failover->state_sync_buffer = 0;
      failover->state_sync_frame = 0;
      failover->state_sync_count = 0;
      offset = 0;
    }

  failover->state_sync_next_event_offset = offset;
}

void
hanat_state_sync_flush (vlib_main_t * vm)
{
  hanat_state_sync_main_t *sm = &hanat_state_sync_main;
  u32 i;

  /* *INDENT-OFF* */
  pool_foreach_index (i, sm->failovers,
  ({
    hanat_state_sync_event_add (0, 1, i, vm->thread_index);
  }));
  /* *INDENT-ON* */
}

static uword
hanat_state_sync_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
			  vlib_frame_t * f)
{
  uword event_type;
  uword *event_data = 0;

  vlib_process_wait_for_event (vm);
  event_type = vlib_process_get_events (vm, &event_data);
  if (event_type)
    clib_warning ("bogus kickoff event received");
  vec_reset_length (event_data);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 5.0);
      event_type = vlib_process_get_events (vm, &event_data);
      vec_reset_length (event_data);
      hanat_state_sync_flush (vm);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hanat_state_sync_process_node) = {
    .function = hanat_state_sync_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "hanat-state-sync-process",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
