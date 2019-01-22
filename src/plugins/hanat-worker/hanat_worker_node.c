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

#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#ifndef HANAT_TEST
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_table.h>
#endif
#include "hanat_worker_db.h"

/*
 * hanat-worker NEXT nodes
 */
#define foreach_hanat_worker_next		\
  _(DROP, "error-drop")				\
  _(SLOW_PATH, "hanat-worker-slow-path")

typedef enum {
#define _(s, n) HANAT_WORKER_NEXT_##s,
  foreach_hanat_worker_next
#undef _
    HANAT_WORKER_N_NEXT,
} hanat_worker_next_t;

/*
 * Counters
 */
#define foreach_hanat_worker_counters		\
  _(CACHE_HIT_PACKETS, "cache hit")		\
  _(CACHE_MISS_PACKETS, "cache miss")

typedef enum
{
#define _(sym, str) HANAT_WORKER_##sym,
  foreach_hanat_worker_counters
#undef _
    HANAT_WORKER_N_ERROR,
} hanat_worker_counters_t;

static char *hanat_worker_counter_strings[] = {
#define _(sym,string) string,
  foreach_hanat_worker_counters
#undef _
};

/*
 * Trace
 */
typedef struct {
  u32 sw_if_index;
} hanat_worker_trace_t;

static u8 *
format_hanat_worker_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  //hanat_worker_trace_t *t = va_arg (*args, hanat_worker_trace_t *);
  s = format (s, "HANAT WORKER");
  return s;
}

static bool
transform_packet (hanat_session_entry_t *s, ip4_header_t *ip)
{
  ip_csum_t l4csum;

  /* Source address Destination address */
  if (s->instructions & HANAT_INSTR_DESTINATION_ADDRESS)
    ip->dst_address = s->post_da;
  if (s->instructions & HANAT_INSTR_SOURCE_ADDRESS)
    ip->src_address = s->post_sa;

  /* Header checksum */
  ip_csum_t csum = ip->checksum;
  csum = ip_csum_sub_even(csum, s->checksum);
  ip->checksum = ip_csum_fold(csum);

  /* L4 ports */
  if (ip->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ip4_next_header (ip);

    if (s->instructions & HANAT_INSTR_DESTINATION_PORT)
      tcp->dst_port = s->post_dp;
    if (s->instructions & HANAT_INSTR_SOURCE_PORT)
      tcp->src_port = s->post_sp;
    l4csum = tcp->checksum;
    l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
    tcp->checksum = ip_csum_fold(l4csum);

  } else if (ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header (ip);
    if (s->instructions & HANAT_INSTR_DESTINATION_PORT)
      udp->dst_port = s->post_dp;
    if (s->instructions & HANAT_INSTR_SOURCE_PORT)
      udp->src_port = s->post_sp;
    l4csum = udp->checksum;
    l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
    udp->checksum = ip_csum_fold(l4csum);
  }
  /* Falling through for other L4 protocols */
  return true;
}

static void
hanat_key_from_packet (u32 fib_index, ip4_header_t *ip, hanat_session_key_t *key)
{
  u16 sport = 0, dport = 0;
  if (ip->protocol == IP_PROTOCOL_TCP ||
      ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header (ip);
    sport = udp->src_port;
    dport = udp->dst_port;
  }

  key->sa = ip->src_address;
  key->da = ip->dst_address;
  key->proto = ip->protocol;
  key->fib_index = fib_index;
  key->sp = sport;
  key->dp = dport;
}


static bool
hanat_nat44_transform (hanat_db_t *db, u32 fib_index, ip4_header_t *ip, u32 *out_fib_index)
{
  hanat_session_key_t key;
  hanat_session_t *s;

  /* 6-tuple lookup */
  hanat_key_from_packet(fib_index, ip, &key);
  s = hanat_session_find(db, &key);
  if (!s)
    return false;
  *out_fib_index = s->entry.fib_index;
  return transform_packet(&s->entry, ip);
}

#ifndef HANAT_TEST
static uword
hanat_worker (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 n_left_from, *from, *to_next;
  //f64 now = vlib_time_now (vm);
  //u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  u32 cache_hit = 0, cache_miss = 0;

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

	  ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b0));
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							    sw_if_index0);

	  /*
	   * Lookup and do transform in cache, if miss send to slow path node
	   */
	  u32 out_fib_index0;
	  if (hanat_nat44_transform(&hm->db, fib_index0, ip0, &out_fib_index0)) {
	    vnet_feature_next(&next0, b0);
	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = out_fib_index0;
	    b0->error = node->errors[HANAT_WORKER_CACHE_HIT_PACKETS];
	    cache_hit++;
	  } else {
	    next0 = HANAT_WORKER_NEXT_SLOW_PATH;
	    b0->error = node->errors[HANAT_WORKER_CACHE_MISS_PACKETS];
	    cache_miss++;
	  }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	    hanat_worker_trace_t *t =
	      vlib_add_trace (vm, node, b0, sizeof (*t));
	  }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_error_count (vm, node->node_index,
		    HANAT_WORKER_CACHE_HIT_PACKETS, cache_hit);
  vlib_error_count (vm, node->node_index,
		    HANAT_WORKER_CACHE_MISS_PACKETS, cache_miss);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(hanat_worker_node) = {
    .function = hanat_worker,
    .name = "hanat-worker",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = HANAT_WORKER_N_ERROR,
    .error_strings = hanat_worker_counter_strings,
    .n_next_nodes = HANAT_WORKER_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [HANAT_WORKER_NEXT_##s] = n,
     foreach_hanat_worker_next
#undef _
    },
    .format_trace = format_hanat_worker_trace,
};

/* Hook up input features */
VNET_FEATURE_INIT (hanat_worker, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "hanat-worker",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

/* *INDENT-ON* */

#endif
