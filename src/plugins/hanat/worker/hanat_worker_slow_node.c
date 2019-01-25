/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
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

#include <arpa/inet.h>

#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp.h>
#ifndef HANAT_TEST
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_table.h>
#endif
#include "hanat_worker_db.h"
#include "../protocol/hanat_protocol.h"

static vlib_node_registration_t hanat_worker_slow_output_node;

/*
 * hanat-worker-slow NEXT nodes
 */
#define foreach_hanat_worker_slow_output_next	\
  _(IP4_LOOKUP, "ip4-lookup")			\
  _(DROP, "error-drop")

typedef enum {
#define _(s, n) HANAT_WORKER_SLOW_OUTPUT_NEXT_##s,
  foreach_hanat_worker_slow_output_next
#undef _
    HANAT_WORKER_SLOW_OUTPUT_N_NEXT,
} hanat_worker_slow_output_next_t;


#define foreach_hanat_worker_slow_input_next	\
  _(HANAT_CACHE, "hanat-worker")			\
  _(DROP, "error-drop")

typedef enum {
#define _(s, n) HANAT_WORKER_SLOW_INPUT_NEXT_##s,
  foreach_hanat_worker_slow_input_next
#undef _
    HANAT_WORKER_SLOW_INPUT_N_NEXT,
} hanat_worker_slow_input_next_t;

/*
 * Counters
 */
#define foreach_hanat_worker_slow_counters		\
  /* Must be first. */				\
  _(MAPPER_REQUEST, "mapper request")

typedef enum
{
#define _(sym, str) HANAT_WORKER_SLOW_##sym,
  foreach_hanat_worker_slow_counters
#undef _
    HANAT_WORKER_SLOW_N_ERROR,
} hanat_worker_slow_counters_t;

static char *hanat_worker_slow_counter_strings[] = {
#define _(sym,string) string,
  foreach_hanat_worker_slow_counters
#undef _
};

/*
 * Trace
 */
typedef struct {
  u32 sw_if_index;
} hanat_worker_slow_trace_t;

static u8 *
format_hanat_worker_slow_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  //hanat_worker_trace_t *t = va_arg (*args, hanat_worker_trace_t *);
  s = format (s, "HANAT SLOW WORKER");
  return s;
}

static vl_api_hanat_worker_if_mode_t
get_interface_mode(u32 sw_if_index)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 index = hm->interface_by_sw_if_index[sw_if_index];
  hanat_interface_t *interface = pool_elt_at_index(hm->interfaces, index);
  return interface->mode;
}

static u32
find_mapper (u32 sw_if_index, u32 fib_index, ip4_header_t *ip)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 mid = ~0;

  vl_api_hanat_worker_if_mode_t mode = get_interface_mode(sw_if_index);

  if (mode == HANAT_WORKER_IF_OUTSIDE ||
      mode == HANAT_WORKER_IF_DUAL) {
    hanat_pool_key_t key = { .as_u32[0] = fib_index,
			     .as_u32[1] = ip->dst_address.as_u32 };
    mid = hanat_lpm_64_lookup (&hm->pool_db, &key, 32);
  }
  if (mode == HANAT_WORKER_IF_INSIDE ||
      mode == HANAT_WORKER_IF_DUAL) {
    if (mid == ~0) {
      u32 i = ip->src_address.as_u32 % hm->pool_db.n_buckets;
      mid = hm->pool_db.lb_buckets[fib_index][i];
    }
  }
  return mid;
}

static int
send_hanat_protocol_request(vlib_main_t *vm, u32 fib_index, vlib_buffer_t *org_b, hanat_pool_entry_t *pe, hanat_session_t *session)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u16 len;

  /* Allocate buffer */
  u32 bi;
  vlib_buffer_t *b;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return -1;

  b = vlib_get_buffer (vm, bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
  b->flags |= org_b->flags & VLIB_BUFFER_IS_TRACED;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0; //fib_index;

  ip4_header_t *ip = vlib_buffer_get_current (b);
  ip->ip_version_and_header_length = 0x45;
  ip->flags_and_fragment_offset =
    clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
  ip->ttl = 64;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = pe->src.ip4.as_u32;
  ip->dst_address.as_u32 = pe->mapper.ip4.as_u32;
  ip->checksum = ip4_header_checksum (ip);
  len = sizeof(ip4_header_t);

  udp_header_t *udp = (udp_header_t *) (ip + 1);
  udp->src_port = htons(hm->udp_port);
  udp->dst_port = htons(pe->udp_port);
  len += sizeof (udp_header_t);

  hanat_header_t *hanat = (hanat_header_t *) (udp + 1);
  hanat->core_id = 0L;
  len += sizeof (hanat_header_t);

  hanat_option_session_request_t *req = (hanat_option_session_request_t *) (hanat + 1);
  req->type = HANAT_SESSION_REQUEST;
  req->length = sizeof(hanat_option_session_request_t);
  req->session_id = 0;
  req->pool_id = 0;

  req->desc.sa.as_u32 = session->key.sa.as_u32;
  req->desc.da.as_u32 = session->key.da.as_u32;
  req->desc.sp = session->key.sp;
  req->desc.dp = session->key.dp;
  req->desc.proto = session->key.proto;
  req->desc.vni = fib_index;

  len += sizeof (hanat_option_session_request_t);

  ip->length = htons(len);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = htons (len - sizeof(ip4_header_t));

  b->current_length = len;

  /* Add to frame */
  vlib_frame_t *f;
  u32 *to_next;
  f = vlib_get_frame_to_node (vm, hm->ip4_lookup_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, hm->ip4_lookup_node_index, f);
      
  vlib_node_increment_counter (vm, hanat_worker_slow_output_node.index,
			       HANAT_WORKER_SLOW_MAPPER_REQUEST, 1);
  return 0;
}

static uword
hanat_worker_slow_output (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 n_left_from, *from, *to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0, sw_if_index0, fib_index0;
	  ip4_header_t *ip0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];

	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
	  //u16 plen = ntohs(ip0->length);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							    sw_if_index0);
	  u32 mid0 = find_mapper(sw_if_index0, fib_index0, ip0);
	  
	  hanat_pool_entry_t *pe = pool_elt_at_index(hm->pool_db.pools, mid0);
	  if (pe) {
	    clib_warning("Found mapper %U", format_ip46_address, &pe->mapper);

	    hanat_session_t *s = hanat_worker_cache_add_incomplete(&hm->db, fib_index0, ip0, bi0);
	    send_hanat_protocol_request(vm, fib_index0, b0, pe, s);

	  } else {
	    clib_warning("Dropping packet");
	    next0 = HANAT_WORKER_SLOW_OUTPUT_NEXT_DROP;
	    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			       && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	      hanat_worker_slow_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	    }
	    to_next[0] = bi0;
	    to_next += 1;
	    n_left_to_next -= 1;
	    /* verify speculative enqueue, maybe switch current next frame */
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					     to_next, n_left_to_next,
					     bi0, next0);

	  }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  //send_protocol_requests();
  return frame->n_vectors;
}

/*
 * Receive instructions from mapper
 * Do hand-off to owning worker?
 * Single-thread at the moment?
 */
static uword
hanat_worker_slow_input (vlib_main_t * vm,
			 vlib_node_runtime_t * node,
			 vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hanat_worker_slow_output_node, static) = {
    .function = hanat_worker_slow_output,
    .name = "hanat-worker-slow-output",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = HANAT_WORKER_SLOW_N_ERROR,
    .error_strings = hanat_worker_slow_counter_strings,
    .n_next_nodes = HANAT_WORKER_SLOW_OUTPUT_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [HANAT_WORKER_SLOW_OUTPUT_NEXT_##s] = n,
     foreach_hanat_worker_slow_output_next
#undef _
    },
    .format_trace = format_hanat_worker_slow_trace,
};
VLIB_REGISTER_NODE(hanat_worker_slow_input_node, static) = {
    .function = hanat_worker_slow_input,
    .name = "hanat-worker-slow-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = HANAT_WORKER_SLOW_N_ERROR,
    .error_strings = hanat_worker_slow_counter_strings,
    .n_next_nodes = HANAT_WORKER_SLOW_INPUT_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [HANAT_WORKER_SLOW_INPUT_NEXT_##s] = n,
     foreach_hanat_worker_slow_input_next
#undef _
    },
    .format_trace = format_hanat_worker_slow_trace,
};
/* *INDENT-ON* */

void
hanat_worker_slow_init (vlib_main_t *vm)
{
  hanat_worker_main_t *hm = &hanat_worker_main;

  hm->udp_port = HANAT_WORKER_UDP_PORT;

  udp_register_dst_port (vm, HANAT_WORKER_UDP_PORT,
                         hanat_worker_slow_input_node.index, /* is_ip4 */ 1);

}
