/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <stdbool.h>
#include <assert.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/fib/ip4_fib.h>
#include "flowrouter.h"
#include "flowrouter_inlines.h"

#define foreach_flowrouter_handoff_error		\
_(CONGESTION_DROP_SP, "congestion drop - slowpath")	\
_(CONGESTION_DROP_FP, "congestion drop - fastpath")	\
_(WRONG_THREAD, "wrong thread")

typedef enum
{
#define _(sym,str) FLOWROUTER_HANDOFF_ERROR_##sym,
  foreach_flowrouter_handoff_error
#undef _
    FLOWROUTER_HANDOFF_N_ERROR,
} flowrouter_handoff_error_t;

static char *flowrouter_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_flowrouter_handoff_error
#undef _
};

typedef struct {
  u32 next_worker_index;
  u32 trace_index;
} flowrouter_handoff_trace_t;

static u8 *
format_flowrouter_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowrouter_handoff_trace_t *t = va_arg (*args, flowrouter_handoff_trace_t *);

  s = format (s, "flowrouter-handoff: next-worker %d trace index %d",
	      t->next_worker_index, t->trace_index);
  return s;
}

VLIB_NODE_FN (flowrouter_handoff_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  flowrouter_main_t *fm = &flowrouter_main;
  u16 *next;
  u32 n_enq, n_left_from, *from;
  u32 do_handoff_fp = 0;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  u16 fastpath_indices[VLIB_FRAME_SIZE], *fi = fastpath_indices;
  u32 fastpath_buffers[VLIB_FRAME_SIZE], *fb = fastpath_buffers;
  u32 to_buffers[VLIB_FRAME_SIZE], *tb = to_buffers;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  flowrouter_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;

  u32 *bi;
  u32 thread_index = vm->thread_index;
  u32 no_fastpath = 0, no_slowpath = 0, no_to_buffers = 0;
  ip4_header_t *ip0;
  clib_bihash_kv_16_8_t kv;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);

  u32 fast_path_node_index = FLOWROUTER_NEXT_FASTPATH;

  while (n_left_from > 0) {
      u32 sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
    u32 fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
    u16 sport0 = vnet_buffer (b[0])->ip.reass.l4_src_port;
    u16 dport0 = vnet_buffer (b[0])->ip.reass.l4_dst_port;
    u32 iph_offset = vnet_buffer (b[0])->ip.reass.save_rewrite_length;

    clib_warning("SPORT %u DPORT %u Offset: %u", clib_net_to_host_u16(sport0), clib_net_to_host_u16(dport0), iph_offset);
    ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + iph_offset);

    flowrouter_calc_key (ip0, fib_index0, sport0, dport0, k);
    clib_memcpy_fast (&kv.key, k, 16);
    h[0] = clib_bihash_hash_16_8 (&kv);

    b += 1;
    k += 1;
    h += 1;
    n_left_from -= 1;
  }

  n_left_from = frame->n_vectors;
  h = hashes;
  k = keys;
  b = bufs;
  bi = from;
  next = nexts;

  while (n_left_from > 0) {
    if (PREDICT_TRUE (n_left_from >= 16))
      clib_bihash_prefetch_bucket_16_8 (&fm->flowhash, h[15]);

    if (PREDICT_TRUE (n_left_from >= 8))
      clib_bihash_prefetch_data_16_8 (&fm->flowhash, h[7]);

    clib_memcpy_fast (&kv.key, k, 16);

    /* 6-tuple lookup */
    if (clib_bihash_search_inline_with_hash_16_8 (&fm->flowhash, h[0], &kv)) {
      /* Punt to slowpath */
      u32 sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      flowrouter_interface_t *interface = flowrouter_interface_by_sw_if_index(sw_if_index0);

      switch (interface->cache_miss) {
      case FLOWROUTER_CACHE_MISS_FORWARD:
	vnet_feature_next((u32 *)&next[0], b[0]);
	break;
      case FLOWROUTER_CACHE_MISS_DROP:
	next[0] = FLOWROUTER_NEXT_DROP;
	break;
      case FLOWROUTER_CACHE_MISS_PUNT:
	next[0] = FLOWROUTER_NEXT_SLOWPATH;
	break;
      default:
	assert(0);
      }

      tb[0] = bi[0];
      tb += 1;
      next += 1;
      no_to_buffers++;
    } else {
      u32 to_thread = kv.value >> 32;
      if (to_thread == thread_index) {
	next[0] = fast_path_node_index;
	tb[0] = bi[0];
	tb += 1;
	next += 1;
	no_to_buffers++;
      } else {
	fi[0] = kv.value >> 32;
	do_handoff_fp++;
	fi += 1;
	fb[0] = bi[0];
	fb += 1;
      }
      no_fastpath++;
      u32 pool_index = kv.value & 0x00000000FFFFFFFF;
      vnet_buffer(b[0])->flowrouter.pool_index = pool_index;
    }

    //  next:
    n_left_from -= 1;
    k += 1;
    h += 1;
    b += 1;
    bi += 1;
  }

  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE))) {
    u32 i;
    b = bufs;

    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
	flowrouter_handoff_trace_t *t =
	  vlib_add_trace (vm, node, b[0], sizeof (*t));
	t->next_worker_index = 0;
	t->trace_index = vlib_buffer_get_trace_index (b[0]);

	b += 1;
      } else
	break;
    }
  }

  /* fastpath */
  if (do_handoff_fp > 0) {
    n_enq = vlib_buffer_enqueue_to_thread (vm, fast_path_node_index, fastpath_buffers, fastpath_indices,
					   do_handoff_fp, 1);
    if (n_enq < do_handoff_fp) {
      vlib_node_increment_counter (vm, node->node_index,
				   FLOWROUTER_HANDOFF_ERROR_CONGESTION_DROP_FP,
				   do_handoff_fp - n_enq);
    }
    vlib_increment_simple_counter (fm->counters + FLOWROUTER_COUNTER_HANDOFF_DIFFERENT_WORKER_FP, thread_index, 0, do_handoff_fp);
  }

  vlib_increment_simple_counter (fm->counters + FLOWROUTER_COUNTER_HANDOFF_FP, thread_index, 0, no_fastpath);
  vlib_increment_simple_counter (fm->counters + FLOWROUTER_COUNTER_HANDOFF_SLOWPATH, thread_index, 0, no_slowpath);

  vlib_buffer_enqueue_to_next (vm, node, to_buffers, nexts, no_to_buffers);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowrouter_handoff_node) = {
  .name = "flowrouter-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_flowrouter_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(flowrouter_handoff_error_strings),
  .error_strings = flowrouter_handoff_error_strings,
  .n_next_nodes = FLOWROUTER_N_NEXT,
  .next_nodes =
  {
   [FLOWROUTER_NEXT_DROP] = "error-drop",
   [FLOWROUTER_NEXT_ICMP_ERROR] = "ip4-icmp-error",
   [FLOWROUTER_NEXT_FASTPATH] = "flowrouter-fastpath",
   [FLOWROUTER_NEXT_SLOWPATH] = "flowrouter-slowpath",
  },
};

/* Hook up to potential feature arcs */

/* RX NAT on outside interface */
VNET_FEATURE_INIT (flowrouter_handoff1, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "flowrouter-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};

/* TX NAT on outside interface */
VNET_FEATURE_INIT (flowrouter_handoff2, static) = {
  .arc_name = "ip4-output",
  .node_name = "flowrouter-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
			       "ip4-sv-reassembly-output-feature"),
};

/* *INDENT-ON* */
