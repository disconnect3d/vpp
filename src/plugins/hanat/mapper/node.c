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

#include "hanat_mapper.h"
#include "hanat_state_sync.h"
#include <hanat/protocol/hanat_protocol.h>

typedef struct
{
  u32 next_index;
} hanat_mapper_trace_t;

static u8 *
format_hanat_mapper_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hanat_mapper_trace_t *t = va_arg (*args, hanat_mapper_trace_t *);

  s = format (s, "hanat-mapper: next index %d", t->next_index);

  return s;
}

typedef enum
{
  HANAT_MAPPER_NEXT_IP4_LOOKUP,
  HANAT_MAPPER_NEXT_DROP,
  HANAT_MAPPER_N_NEXT,
} hanat_mapper_next_t;

#define foreach_hanat_mapper_error \
_(PROCESSED, "pkts-processed") \
_(BAD_TLV, "pkts-bad-tlv")

typedef enum
{
#define _(sym, str) HANAT_MAPPER_ERROR_##sym,
  foreach_hanat_mapper_error
#undef _
    HANAT_MAPPER_N_ERROR,
} hanat_mapper_error_t;

static char *hanat_mapper_error_strings[] = {
#define _(sym, str) str,
  foreach_hanat_mapper_error
#undef _
};

typedef struct
{
  ip4_address_t addr;
  u32 event_count;
} hanat_state_sync_trace_t;

static u8 *
format_hanat_state_sync_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hanat_state_sync_trace_t *t = va_arg (*args, hanat_state_sync_trace_t *);

  s =
    format (s, "hanat-state-sync: %u events from %U", t->event_count,
	    format_ip4_address, &t->addr);

  return s;
}

typedef enum
{
  HANAT_STATE_SYNC_NEXT_IP4_LOOKUP,
  HANAT_STATE_SYNC_NEXT_DROP,
  HANAT_STATE_SYNC_N_NEXT,
} hanat_state_sync_next_t;

#define foreach_hanat_state_sync_error \
_(PROCESSED, "pkts-processed") \
_(BAD_VERSION, "bad-version")

typedef enum
{
#define _(sym, str) HANAT_STATE_SYNC_ERROR_##sym,
  foreach_hanat_state_sync_error
#undef _
    HANAT_STATE_SYNC_N_ERROR,
} hanat_state_sync_error_t;

static char *hanat_state_sync_error_strings[] = {
#define _(sym, str) str,
  foreach_hanat_state_sync_error
#undef _
};

vlib_node_registration_t hanat_mapper_node;
vlib_node_registration_t hanat_state_sync_node;

always_inline u32
hanat_session_get_failover_index (hanat_mapper_session_t * session)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_addr_pool_t *pool;
  hanat_mapper_mapping_t *mapping;

  mapping = pool_elt_at_index (nm->db.mappings, session->mapping_index);
  pool = get_pool_by_pool_id (mapping->pool_id);

  return pool->failover_index;
}

always_inline void
hanat_session_refresh_process (vlib_main_t * vm,
			       hanat_option_session_refresh_t * req)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;

  ip4_address_t in_l_addr, out_r_addr;
  u32 tenant_id;
  u8 protocol;
  u8 is_in2out;
  f64 now;
  hanat_state_sync_event_t event;
  u32 failover_index;

  in_l_addr = req->desc.sa;
  out_r_addr = req->desc.da;

  is_in2out = req->desc.in2out ? 1 : 0;

  protocol = ip_proto_to_hanat_mapper_proto (req->desc.proto);
  tenant_id = clib_net_to_host_u32 (req->desc.vni);

  session = hanat_mapper_session_get (&nm->db,
				      &in_l_addr, req->desc.sp,
				      &out_r_addr, req->desc.dp,
				      protocol, tenant_id, is_in2out);
  if (PREDICT_TRUE (session != 0))
    {
      // refresh session expiration timeout
      now = vlib_time_now (vm);
      session_reset_timeout (nm, session, now);
      // state sync
      failover_index = hanat_session_get_failover_index (session);
      if (failover_index != ~0)
	{
	  clib_memset (&event, 0, sizeof (event));
	  event.event_type = HANAT_STATE_SYNC_KEEPALIVE;
	  event.in_l_addr = in_l_addr.as_u32;
	  event.in_r_addr = out_r_addr.as_u32;
	  event.in_l_port = req->desc.sp;
	  event.in_r_port = req->desc.dp;
	  event.protocol = protocol;
	  event.tenant_id = tenant_id;
	  event.total_bytes = clib_host_to_net_u64 (session->total_bytes);
	  event.total_pkts = clib_host_to_net_u64 (session->total_pkts);
	  hanat_state_sync_event_add (&event, 0, 0, failover_index,
				      vm->thread_index);
	}
    }
}

always_inline int
hanat_in2out_add_or_get_session_and_mapping (f64 now,
					     hanat_option_session_request_t *
					     req, u8 protocol, u32 tenant_id,
					     u32 pool_id,
					     hanat_mapper_session_t **
					     session_out,
					     hanat_mapper_mapping_t **
					     mapping_out)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  hanat_mapper_mapping_t *mapping;
  hanat_mapper_user_t *user;

  ip4_address_t in_l_addr, out_l_addr, out_r_addr;
  u16 out_l_port;
  u8 is_new = 0;
  int rc;

  in_l_addr = req->desc.sa;
  out_r_addr = req->desc.da;

  mapping = hanat_mapper_mapping_get (&nm->db, &in_l_addr,
				      req->desc.sp, protocol, tenant_id, 1);
  if (!mapping)
    {
      rc = nm->alloc_addr_and_port (pool_id, protocol,
				    &out_l_addr, &out_l_port);
      if (rc)
	{
	  clib_warning ("hanat-protocol: in2out error alloc addr and port");
	  return 1;
	}

      mapping = hanat_mapper_mapping_create (&nm->db,
					     &in_l_addr, req->desc.sp,
					     &out_l_addr, out_l_port,
					     protocol, pool_id, tenant_id, 0);
      if (!mapping)
	{
	  clib_warning ("hanat-protocol: in2out error creating mapping");
	  hanat_mapper_free_out_addr_and_port (pool_id, protocol,
					       &out_l_addr, out_l_port);
	}
      is_new = 1;
    }

  user = hanat_mapper_user_get (&nm->db, &in_l_addr, tenant_id);
  if (!user)
    {
      user = hanat_mapper_user_create (&nm->db, &in_l_addr, tenant_id);
      if (!user)
	{
	  clib_warning ("hanat-protocol: failed creating user");
	  hanat_mapper_free_out_addr_and_port (pool_id, protocol,
					       &out_l_addr, out_l_port);
	  return 1;
	}
    }

  session = hanat_mapper_session_create (&nm->db, mapping,
					 &out_r_addr, req->desc.dp,
					 &out_r_addr, req->desc.dp,
					 user, now, req->opaque_data,
					 req->length - sizeof (*req));
  if (!session)
    {
      clib_warning ("hanat-protocol: failed creating session");
      if (is_new)
	{
	  hanat_mapper_free_out_addr_and_port (pool_id, protocol,
					       &out_l_addr, out_l_port);
	}
      return 1;
    }

  *session_out = session;
  *mapping_out = mapping;

  return 0;
}

always_inline int
hanat_out2in_add_or_get_session_and_mapping (f64 now,
					     hanat_option_session_request_t *
					     req, u8 protocol, u32 tenant_id,
					     hanat_mapper_session_t **
					     session_out,
					     hanat_mapper_mapping_t **
					     mapping_out)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_session_t *session;
  hanat_mapper_mapping_t *mapping;
  hanat_mapper_user_t *user;

  mapping = hanat_mapper_mapping_get (&nm->db, &req->desc.sa,
				      req->desc.sp, protocol, tenant_id, 0);
  if (!mapping)
    {
      clib_warning ("hanat-protocol: out2in no mapping");
      return 1;
    }

  user = hanat_mapper_user_get (&nm->db, &mapping->in_addr, tenant_id);
  if (!user)
    {
      clib_warning ("hanat-protocol: out2in no user");
      return 1;
    }

  session = hanat_mapper_session_create (&nm->db, mapping,
					 &req->desc.da, req->desc.dp,
					 &req->desc.da, req->desc.dp,
					 user, now, req->opaque_data,
					 req->length - sizeof (*req));
  if (!session)
    {
      clib_warning ("hanat-protocol: failed creating session");
      return 1;
    }

  *session_out = session;
  *mapping_out = mapping;

  return 0;
}

always_inline int
hanat_session_request_process (vlib_main_t * vm,
			       hanat_option_session_request_t * req,
			       hanat_option_session_binding_t * rsp)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_mapping_t *mapping = 0;
  hanat_mapper_session_t *session = 0;

  u32 tenant_id, pool_id, instructions;
  ip4_address_t in_l_addr, out_r_addr;
  f64 now = vlib_time_now (vm);
  u8 protocol, is_in2out;
  u8 opaque_data_len;
  int rc;
  hanat_state_sync_event_t event;
  u32 failover_index;

  is_in2out = req->desc.in2out ? 1 : 0;

  in_l_addr = req->desc.sa;
  out_r_addr = req->desc.da;

  protocol = ip_proto_to_hanat_mapper_proto (req->desc.proto);
  tenant_id = clib_net_to_host_u32 (req->desc.vni);
  pool_id = clib_net_to_host_u32 (req->pool_id);

  session = hanat_mapper_session_get (&nm->db,
				      &in_l_addr, req->desc.sp,
				      &out_r_addr, req->desc.dp,
				      protocol, tenant_id, is_in2out);
  // slow path, create session
  if (PREDICT_FALSE (!session))
    {
      if (is_in2out)
	{
	  rc = hanat_in2out_add_or_get_session_and_mapping (now,
							    req, protocol,
							    tenant_id,
							    pool_id, &session,
							    &mapping);
	  if (rc)
	    return 1;
	}
      else
	{
	  rc = hanat_out2in_add_or_get_session_and_mapping (now,
							    req, protocol,
							    tenant_id,
							    &session,
							    &mapping);
	  if (rc)
	    return 1;
	}
      // state sync
      failover_index = hanat_session_get_failover_index (session);
      if (failover_index != ~0)
	{
	  clib_memset (&event, 0, sizeof (event));
	  event.event_type = HANAT_STATE_SYNC_ADD;
	  event.in_l_addr = mapping->in_addr.as_u32;
	  event.in_r_addr = session->in_r_addr.as_u32;
	  event.in_l_port = mapping->in_port;
	  event.in_r_port = session->in_r_port;
	  event.out_l_addr = mapping->out_addr.as_u32;
	  event.out_r_addr = session->out_r_addr.as_u32;
	  event.out_l_port = mapping->out_port;
	  event.out_r_port = session->out_r_port;
	  event.tenant_id = clib_host_to_net_u32 (tenant_id);
	  event.pool_id = clib_host_to_net_u32 (pool_id);
	  event.protocol = protocol;
	  event.event_type = HANAT_STATE_SYNC_ADD;
	  event.opaque_len = (u8) vec_len (session->opaque_data);
	  hanat_state_sync_event_add (&event, session->opaque_data, 0,
				      failover_index, vm->thread_index);
	}
    }
  else
    mapping = pool_elt_at_index (nm->db.mappings, session->mapping_index);

  if (is_in2out)
    {
      instructions = HANAT_INSTR_SOURCE_ADDRESS | HANAT_INSTR_SOURCE_PORT;
      rsp->sa = mapping->out_addr;
      rsp->sp = mapping->out_port;
      rsp->da = session->out_r_addr;
      rsp->dp = session->out_r_port;
    }
  else
    {
      instructions = HANAT_INSTR_DESTINATION_ADDRESS |
	HANAT_INSTR_DESTINATION_PORT;
      rsp->sa = session->in_r_addr;
      rsp->sp = session->in_r_port;
      rsp->da = mapping->in_addr;
      rsp->dp = mapping->in_port;
    }

  // TODO: check udp0 buffer if it is large enought to hold the reply
  // more likely it would overrun MTU size than buffer size

  opaque_data_len = vec_len (session->opaque_data);

  rsp->type = HANAT_SESSION_BINDING;
  rsp->session_id = req->session_id;
  rsp->length = sizeof (*rsp) + opaque_data_len;
  rsp->instructions = clib_host_to_net_u32 (instructions);

  if (opaque_data_len > 0)
    clib_memcpy_fast (rsp->opaque_data, session->opaque_data,
		      opaque_data_len);

  // refresh session expiration timeout
  session_reset_timeout (nm, session, now);

  return 0;
}

always_inline int
hanat_packet_process (vlib_main_t * vm, udp_header_t * udp0,
		      hanat_header_t * ha0)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_option_session_binding_t *rsp_binding;
  hanat_option_session_decline_t *rsp_decline;
  u8 *cur, *end, *buf, type, length;
  u8 *request_buffer;
  u16 len;
  int rc;

  len = clib_net_to_host_u16 (udp0->length) - sizeof (*udp0);

  vec_validate (nm->request_buffers[vm->thread_index], len);
  request_buffer = (u8 *) nm->request_buffers[vm->thread_index];

  clib_memcpy_fast (request_buffer, ha0, len);

  cur = (u8 *) request_buffer + sizeof (*ha0);
  end = (u8 *) request_buffer + len;
  buf = (u8 *) ha0 + sizeof (*ha0);

  while (cur < end)
    {
      type = *cur;
      length = *(cur + 1);

      // length + cur must be smaller than end

      // if bad or unknown tlv occurs consider bad packet
      if (PREDICT_TRUE (type == HANAT_SESSION_REFRESH))
	{
	  hanat_option_session_refresh_t *tlv =
	    (hanat_option_session_refresh_t *) cur;
	  if (PREDICT_FALSE (length < sizeof (*tlv)))
	    {
	      // handle bad tlv
	      return 1;
	    }

	  hanat_session_refresh_process (vm, tlv);
	}
      else if (type == HANAT_SESSION_REQUEST)
	{
	  hanat_option_session_request_t *tlv =
	    (hanat_option_session_request_t *) cur;
	  if (PREDICT_FALSE (length < sizeof (*tlv)))
	    {
	      // handle bad tlv
	      return 1;
	    }

	  rc = hanat_session_request_process (vm, tlv,
					      (hanat_option_session_binding_t
					       *) buf);
	  if (PREDICT_FALSE (rc))
	    {
	      rsp_decline = (hanat_option_session_decline_t *) buf;

	      rsp_decline->type = HANAT_SESSION_DECLINE;
	      rsp_decline->session_id = tlv->session_id;
	      rsp_decline->length = sizeof (*rsp_decline);
	      rsp_decline->code = rc;

	      buf += rsp_decline->length;
	    }
	  else
	    {
	      rsp_binding = (hanat_option_session_binding_t *) buf;

	      buf += rsp_binding->length;
	    }
	}
      else
	{
	  // handle unknown tlv
	  return 1;
	}
      cur += length;
    }

  len = buf - (u8 *) ha0 + sizeof (*udp0);
  udp0->length = clib_host_to_net_u16 (len);

  return 0;
}

static uword
hanat_mapper_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ip4_main_t *i4m = &ip4_main;
  u8 host_config_ttl = i4m->host_config.ttl;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 ok_packets = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, src_addr0, dst_addr0;
	  u16 src_port0, dst_port0;
	  vlib_buffer_t *b0;
	  ip4_header_t *ip0;
	  udp_header_t *udp0;
	  hanat_header_t *ha0;
	  //u32 error0;

	  ip_csum_t sum0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ha0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*ip0));
	  ip0 = vlib_buffer_get_current (b0);

	  // REVIEW: bad TLV should be ignored / logged and good ones
	  // processed ?
	  if (PREDICT_TRUE (!hanat_packet_process (vm, udp0, ha0)))
	    {
	      next0 = HANAT_MAPPER_NEXT_IP4_LOOKUP;

	      src_addr0 = ip0->src_address.data_u32;
	      dst_addr0 = ip0->dst_address.data_u32;
	      ip0->src_address.data_u32 = dst_addr0;
	      ip0->dst_address.data_u32 = src_addr0;

	      sum0 = ip0->checksum;
	      sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				     ip4_header_t, ttl);
	      ip0->ttl = host_config_ttl;
	      ip0->checksum = ip_csum_fold (sum0);

	      udp0->checksum = 0;
	      src_port0 = udp0->src_port;
	      dst_port0 = udp0->dst_port;
	      udp0->src_port = dst_port0;
	      udp0->dst_port = src_port0;

	      ok_packets++;
	    }
	  else
	    {
	      next0 = HANAT_MAPPER_NEXT_DROP;
	      b0->error = node->errors[HANAT_MAPPER_ERROR_BAD_TLV];
	    }



	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hanat_mapper_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->next_index = next0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hanat_mapper_node.index,
			       HANAT_MAPPER_ERROR_PROCESSED, ok_packets);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hanat_mapper_node) = {
  .function = hanat_mapper_node_fn,
  .name = "hanat-mapper",
  .vector_size = sizeof (u32),
  .format_trace = format_hanat_mapper_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hanat_mapper_error_strings),
  .error_strings = hanat_mapper_error_strings,
  .n_next_nodes = HANAT_MAPPER_N_NEXT,
  .next_nodes = {
     [HANAT_MAPPER_NEXT_IP4_LOOKUP] = "ip4-lookup",
     [HANAT_MAPPER_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

static uword
hanat_state_sync_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 pkts_processed = 0;
  ip4_main_t *i4m = &ip4_main;
  u8 host_config_ttl = i4m->host_config.ttl;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, src_addr0, dst_addr0;;
	  vlib_buffer_t *b0;
	  hanat_state_sync_message_header_t *h0;
	  hanat_state_sync_event_t *e0;
	  u16 event_count0, src_port0, dst_port0, old_len0;
	  ip4_header_t *ip0;
	  udp_header_t *udp0;
	  ip_csum_t sum0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*ip0));
	  ip0 = vlib_buffer_get_current (b0);

	  next0 = HANAT_STATE_SYNC_NEXT_DROP;

	  if (h0->version != HANAT_STATE_SYNC_VERSION)
	    {
	      b0->error = node->errors[HANAT_STATE_SYNC_ERROR_BAD_VERSION];
	      goto done0;
	    }

	  event_count0 = clib_net_to_host_u16 (h0->count);
	  if (!event_count0 && (h0->flags & HANAT_STATE_SYNC_FLAG_ACK))
	    {
	      hanat_state_sync_ack_recv (h0->sequence_number);
	      b0->error = node->errors[HANAT_STATE_SYNC_ERROR_PROCESSED];
	      goto done0;
	    }

	  e0 = (hanat_state_sync_event_t *) (h0 + 1);

	  while (event_count0)
	    {
	      hanat_state_sync_event_process (e0, now, thread_index);
	      event_count0--;
	      e0 =
		(hanat_state_sync_event_t *) ((u8 *) e0 +
					      sizeof
					      (hanat_state_sync_event_t) +
					      e0->opaque_len);
	    }

	  next0 = HANAT_STATE_SYNC_NEXT_IP4_LOOKUP;
	  pkts_processed++;

	  b0->current_length = sizeof (*ip0) + sizeof (*udp0) + sizeof (*h0);

	  src_addr0 = ip0->src_address.data_u32;
	  dst_addr0 = ip0->dst_address.data_u32;
	  ip0->src_address.data_u32 = dst_addr0;
	  ip0->dst_address.data_u32 = src_addr0;
	  old_len0 = ip0->length;
	  ip0->length = clib_host_to_net_u16 (b0->current_length);

	  sum0 = ip0->checksum;
	  sum0 = ip_csum_update (sum0, ip0->ttl, host_config_ttl,
				 ip4_header_t, ttl);
	  ip0->ttl = host_config_ttl;
	  sum0 =
	    ip_csum_update (sum0, old_len0, ip0->length, ip4_header_t,
			    length);
	  ip0->checksum = ip_csum_fold (sum0);

	  udp0->checksum = 0;
	  src_port0 = udp0->src_port;
	  dst_port0 = udp0->dst_port;
	  udp0->src_port = dst_port0;
	  udp0->dst_port = src_port0;
	  udp0->length =
	    clib_host_to_net_u16 (b0->current_length - sizeof (*ip0));

	  h0->flags = HANAT_STATE_SYNC_FLAG_ACK;
	  h0->count = 0;
	  hanat_state_sync_ack_send_increment_counter (thread_index);

	done0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      hanat_state_sync_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      ip4_header_t *ip =
		(void *) (b0->data + vnet_buffer (b0)->l3_hdr_offset);
	      t->event_count = clib_net_to_host_u16 (h0->count);
	      t->addr.as_u32 = ip->src_address.data_u32;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, hanat_state_sync_node.index,
			       HANAT_STATE_SYNC_ERROR_PROCESSED,
			       pkts_processed);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (hanat_state_sync_node) = {
  .function = hanat_state_sync_node_fn,
  .name = "hanat-state-sync",
  .vector_size = sizeof (u32),
  .format_trace = format_hanat_state_sync_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (hanat_state_sync_error_strings),
  .error_strings = hanat_state_sync_error_strings,
  .n_next_nodes = HANAT_STATE_SYNC_N_NEXT,
  .next_nodes = {
     [HANAT_STATE_SYNC_NEXT_IP4_LOOKUP] = "ip4-lookup",
     [HANAT_STATE_SYNC_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
