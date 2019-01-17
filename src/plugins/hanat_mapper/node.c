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

#include <hanat_mapper/hanat_mapper.h>
#include <hanat_mapper/hanat_state_sync.h>

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

#define foreach_hanat_mapper_error              \
_(PROCESSED, "HA NAT mapper packets processed")

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

static u8 *
format_hanat_state_sync_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "hanat-state-sync: TODO");

  return s;
}

typedef enum
{
  HANAT_STATE_SYNC_NEXT_DROP,
  HANAT_STATE_SYNC_N_NEXT,
} hanat_state_sync_next_t;

#define foreach_hanat_state_sync_error              \
_(PROCESSED, "HA NAT state sync packets processed") \
_(BAD_VERSION, "HA NAT state sync bad version")

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

static uword
hanat_mapper_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next;
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
	  u32 bi0, next0, src_addr0, dst_addr0;
	  u16 src_port0, dst_port0;
	  vlib_buffer_t *b0;
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
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*ip0));
	  ip0 = vlib_buffer_get_current (b0);

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
			       HANAT_MAPPER_ERROR_PROCESSED,
			       frame->n_vectors);

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
hanat_state_sync_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next_drop;
  f64 now = vlib_time_now (vm);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next_drop;

      vlib_get_next_frame (vm, node, HANAT_STATE_SYNC_NEXT_DROP,
			   to_next_drop, n_left_to_next_drop);

      while (n_left_from > 0 && n_left_to_next_drop > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  hanat_state_sync_message_header_t *h0;
	  hanat_state_sync_event_t *e0;
	  u16 event_count0;
	  u32 error0;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next_drop[0] = bi0;
	  to_next_drop += 1;
	  n_left_to_next_drop -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);

	  if (h0->version != HANAT_STATE_SYNC_VERSION)
	    {
	      error0 = HANAT_STATE_SYNC_ERROR_BAD_VERSION;
	      goto done0;
	    }

	  error0 = HANAT_STATE_SYNC_ERROR_PROCESSED;
	  event_count0 = clib_net_to_host_u16 (h0->count);
	  e0 = (hanat_state_sync_event_t *) (h0 + 1);

	  while (event_count0)
	    {
	      hanat_state_sync_event_process (e0, now);
	      event_count0--;
	      e0++;
	    }

	done0:
	  b0->error = node->errors[error0];
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      //TODO
	    }

	}

      vlib_put_next_frame (vm, node, HANAT_STATE_SYNC_NEXT_DROP,
			   n_left_to_next_drop);
    }

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
