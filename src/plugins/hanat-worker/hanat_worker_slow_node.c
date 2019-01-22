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

/*
 * hanat-worker-slow-path NEXT nodes
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
  _(FOOBAR, "cache hit")

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


/*
 *    Send mapper request to given mapper
 *    Separate requeste to each mapper.
 *    Initial implementation one packet per request
 *
 * For each packet:
 *   - find mapper
 *   - Allocate buffer if mapper doesn't have buffer from template
 *   -Fill buffer with request
 * Sends packets
 * 
 */
static u32
find_mapper (u32 sw_if_index, u32 fib_index, ip4_header_t *ip)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 mid;

  //mode = get_interface_mode(sw_if_index);
  // If inside interface, lookup in buckets
  // If outside interface, lookup in LPM
  // If dual mode, first LPM then buckets

  /* Assume dual mode interface for now */
  hanat_pool_key_t key = { .as_u32[0] = fib_index,
			   .as_u32[1] = ip->dst_address.as_u32 };

  mid = hanat_lpm_64_lookup (&hm->pool_db, &key, 32);
  if (mid == ~0) {
    u32 i = ip->src_address.as_u32 % hm->pool_db.n_buckets;
    mid = hm->pool_db.lb_buckets[fib_index][i];
  }
  return mid;
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
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
	  u16 plen = ntohs(ip0->length);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							    sw_if_index0);
	  u32 mid0 = find_mapper(sw_if_index0, fib_index0, ip0);
	  
	  hanat_pool_entry_t *pe = pool_elt_at_index(hm->pool_db.pools, mid0);
	  if (pe) {
	    clib_warning("Found mapper %U", format_ip46_address, &pe->mapper);
	    

	    /*
	     * Encap packet
	     */
	    ip4_header_t *ip40;
	    udp_header_t *udp0;
	    vlib_buffer_advance (b0, -sizeof (ip4_header_t) + sizeof(udp_header_t));
	    ip40 = vlib_buffer_get_current (b0);
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	    ip40->ip_version_and_header_length = 0x45;
	    ip40->ttl = 64;
	    ip40->protocol = IP_PROTOCOL_UDP;
	    /* fixup ip4 header length and checksum after-the-fact */
	    ip40->src_address.as_u32 = pe->src.ip4.as_u32;
	    ip40->dst_address.as_u32 = pe->mapper.ip4.as_u32;
	    ip40->checksum = ip4_header_checksum (ip40);

	    ip40->length = htons(plen + sizeof (ip4_header_t) + sizeof(udp_header_t));
	    ip40->checksum = ip4_header_checksum (ip40);
	    udp0 = (udp_header_t *)(ip40+1);
	    udp0->src_port = htons(hm->udp_port);
	    udp0->dst_port = htons(pe->udp_port);
	    udp0->length = htons(plen + sizeof(udp_header_t));
	    udp0->checksum = 0;
	    //hanat_header_t *ha0 = (hanat_header_t *)(udp0 + 1);
	    //ha0->command = HANAT_CACHE_MISS;
	    next0 = HANAT_WORKER_SLOW_OUTPUT_NEXT_IP4_LOOKUP;
	  } else {
	    next0 = HANAT_WORKER_SLOW_OUTPUT_NEXT_DROP;
	  }
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	    hanat_worker_slow_trace_t *t =
	      vlib_add_trace (vm, node, b0, sizeof (*t));
	  }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

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
