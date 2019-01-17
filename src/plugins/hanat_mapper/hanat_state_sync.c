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

#include <hanat_mapper/hanat_state_sync.h>
#include <hanat_mapper/hanat_mapper_db.h>
#include <hanat_mapper/hanat_mapper.h>

static void
hanat_state_sync_recv_add (hanat_state_sync_event_t * event, f64 now)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  hanat_mapper_mapping_t *mapping;
  hanat_mapper_user_t *user;
  ip4_address_t in_l_addr, in_r_addr, out_l_addr, out_r_addr;
  u32 tenant_id;

  in_l_addr.as_u32 = event->in_l_addr;
  in_r_addr.as_u32 = event->in_r_addr;
  out_l_addr.as_u32 = event->out_l_addr;
  out_r_addr.as_u32 = event->out_r_addr;
  tenant_id = clib_net_to_host_u32 (event->tenant_id);

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
      mapping =
	hanat_mapper_mappig_create (&nm->db, &in_l_addr, event->in_l_port,
				    &out_l_addr, event->out_l_port,
				    event->protocol, tenant_id, 0);

      if (!mapping)
	{
	  clib_warning ("hanat-state-sync: mappig_create failed");
	  return;
	}
    }

  session =
    hanat_mapper_session_create (&nm->db, mapping, &in_r_addr,
				 event->in_r_port, &out_r_addr,
				 event->out_r_port, user, now);
  if (!session)
    {
      clib_warning ("hanat-state-sync: session_create failed");
      return;
    }

  session_reset_timeout (nm, session, now);
}

static void
hanat_state_sync_recv_del (hanat_state_sync_event_t * event)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  ip4_address_t in_l_addr, in_r_addr;

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
hanat_state_sync_recv_keepalive (hanat_state_sync_event_t * event, f64 now)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  ip4_address_t in_l_addr, in_r_addr;

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
hanat_state_sync_event_process (hanat_state_sync_event_t * event, f64 now)
{
  switch (event->event_type)
    {
    case HANAT_STATE_SYNC_ADD:
      hanat_state_sync_recv_add (event, now);
      break;
    case HANAT_STATE_SYNC_DEL:
      hanat_state_sync_recv_del (event);
      break;
    case HANAT_STATE_SYNC_KEEPALIVE:
      hanat_state_sync_recv_keepalive (event, now);
      break;
    default:
      clib_warning ("Unsupported HA NAT state sync event type %d",
		    event->event_type);
      break;
    }
}

static inline void
hanat_state_sync_header_create (vlib_buffer_t * b, u32 * offset)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_state_sync_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;

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
  ip->src_address.as_u32 = nm->src_ip_address.as_u32;
  ip->dst_address.as_u32 = nm->failover_ip_address.as_u32;
  udp->src_port = clib_host_to_net_u16 (nm->src_port);
  udp->dst_port = clib_host_to_net_u16 (nm->failover_port);
  udp->checksum = 0;

  h->version = HANAT_STATE_SYNC_VERSION;
  h->rsvd = 0;
  h->count = 0;

  *offset =
    sizeof (ip4_header_t) + sizeof (udp_header_t) +
    sizeof (hanat_state_sync_message_header_t);
}

static inline void
hanat_state_sync_send (vlib_frame_t * f, vlib_buffer_t * b)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_state_sync_message_header_t *h;
  ip4_header_t *ip;
  udp_header_t *udp;
  vlib_main_t *vm = nm->vlib_main;

  ip = vlib_buffer_get_current (b);
  udp = ip4_next_header (ip);
  h = (hanat_state_sync_message_header_t *) (udp + 1);

  h->count = clib_host_to_net_u16 (nm->state_sync_count);

  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b->current_length - sizeof (*ip));

  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
}

void
hanat_state_sync_event_add (hanat_state_sync_event_t * event, u8 do_flush)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  vlib_main_t *vm = nm->vlib_main;
  vlib_buffer_t *b = 0;
  vlib_frame_t *f;
  u32 bi = ~0, offset;
  vlib_buffer_free_list_t *fl;

  b = nm->state_sync_buffer;

  if (PREDICT_FALSE (b == 0))
    {
      if (do_flush)
	return;

      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	{
	  clib_warning ("HA NAT state sync can't allocate buffer");
	  return;
	}

      b = nm->state_sync_buffer = vlib_get_buffer (vm, bi);
      clib_memset (vnet_buffer (b), 0, sizeof (*vnet_buffer (b)));
      fl =
	vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
      vlib_buffer_init_for_free_list (b, fl);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
      offset = 0;
    }
  else
    {
      bi = vlib_get_buffer_index (vm, b);
      offset = nm->state_sync_next_event_offset;
    }

  f = nm->state_sync_frame;
  if (PREDICT_FALSE (f == 0))
    {
      u32 *to_next;
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      nm->state_sync_frame = f;
      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;
    }

  if (PREDICT_FALSE (nm->state_sync_count == 0))
    hanat_state_sync_header_create (b, &offset);

  if (PREDICT_TRUE (do_flush == 0))
    {
      clib_memcpy_fast (b->data + offset, event, sizeof (*event));
      offset += sizeof (*event);
      nm->state_sync_count++;
      b->current_length += sizeof (*event);
    }

  if (PREDICT_FALSE
      (do_flush || offset + (sizeof (*event)) > nm->state_sync_path_mtu))
    {
      hanat_state_sync_send (f, b);
      nm->state_sync_buffer = 0;
      nm->state_sync_frame = 0;
      nm->state_sync_count = 0;
      offset = 0;
    }

  nm->state_sync_next_event_offset = offset;
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
      hanat_state_sync_event_add (0, 1);
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
