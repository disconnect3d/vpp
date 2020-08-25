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
#include <vnet/udp/udp.h>
#include "flowrouter.h"
#include "flowrouter_inlines.h"

/*
 * Counters
 */
#define foreach_flowrouter_fp_errors		\
  _(NO_ERROR, "success")			\
  _(NO_SESSION, "no session")

typedef enum
{
#define _(sym, str) FLOWROUTER_FP_ERROR_##sym,
  foreach_flowrouter_fp_errors
#undef _
    FLOWROUTER_FP_N_ERROR,
} flowrouter_fp_errors_t;

static char *flowrouter_fp_error_strings[] = {
#define _(sym,string) string,
  foreach_flowrouter_fp_errors
#undef _
};

/*
 * Trace
 */
typedef struct {
  u32 sw_if_index;
  u32 next_index;
  u32 pool_index;
} flowrouter_trace_t;

static u8 *
format_flowrouter_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowrouter_trace_t *t = va_arg (*args, flowrouter_trace_t *);

  s = format (s, "sw_if_index %d next index %d session %d ",
	      t->sw_if_index, t->next_index, t->pool_index);
  return s;
}

static inline void
flowrouter_session_update_lru (u32 thread_index, u32 pool_index, flowrouter_session_t * s)
{
#if 0
  flowrouter_main_t *um = &flowrouter_main;
  /* don't update too often - timeout is in a magnitude of seconds anyway */
  if (s->last_heard > s->last_lru_update + 1)  {
    clib_dlist_remove (um->lru_pool[thread_index], s->lru_index);
    clib_dlist_addtail (um->lru_pool[thread_index], s->lru_head_index, s->lru_index);
    s->last_lru_update = s->last_heard;
  }
#endif
}

static u32
execute (u32 pool_index, u32 thread_index, ip4_header_t *ip,
	 f64 now, u32 *out_fib_index)
{
  flowrouter_main_t *fm = &flowrouter_main;
  if (pool_is_free_index (fm->sessions_per_worker[thread_index], pool_index)) {
    return FLOWROUTER_FP_ERROR_NO_SESSION;
  }
  flowrouter_session_t *s = pool_elt_at_index (fm->sessions_per_worker[thread_index], pool_index);
  *out_fib_index = s->fib_index;

  enum flowrouter_session_state newstate = s->state, state = s->state;
  ip_csum_t l4csum;

  /* Source address Destination address */
  if (s->instructions & FLOWROUTER_INSTR_DESTINATION_ADDRESS)
    ip->dst_address = s->post_da;
  if (s->instructions & FLOWROUTER_INSTR_SOURCE_ADDRESS)
    ip->src_address = s->post_sa;

  /* Header checksum */
  /* XXX: Assumes that checksum needs to be updated */
  ip_csum_t csum = ip->checksum;
  csum = ip_csum_sub_even(csum, s->checksum);
  ip->checksum = ip_csum_fold(csum);
  ASSERT (ip->checksum == ip4_header_checksum (ip));

  /* L4 ports */
  if (ip->protocol == IP_PROTOCOL_TCP) {
    tcp_header_t *tcp = ip4_next_header (ip);

    if (s->instructions & FLOWROUTER_INSTR_DESTINATION_PORT)
      tcp->dst_port = s->post_dp;
    if (s->instructions & FLOWROUTER_INSTR_SOURCE_PORT)
      tcp->src_port = s->post_sp;
    l4csum = tcp->checksum;
    l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
    tcp->checksum = ip_csum_fold(l4csum);

    /*
     * TCP connection tracking
     */
    u32 timer = 0;
    if (s->instructions & FLOWROUTER_INSTR_TCP_CONN_TRACK) {
      if (tcp->flags & TCP_FLAG_SYN)
	newstate = FLOWROUTER_STATE_TCP_SYN_SEEN;
      else if (tcp->flags & TCP_FLAG_ACK && s->state == FLOWROUTER_STATE_TCP_SYN_SEEN)
	newstate = FLOWROUTER_STATE_TCP_ESTABLISHED;
      else if (tcp->flags & TCP_FLAG_FIN && s->state == FLOWROUTER_STATE_TCP_ESTABLISHED)
	newstate = FLOWROUTER_STATE_TCP_FIN_WAIT;
      else if (tcp->flags & TCP_FLAG_ACK && s->state == FLOWROUTER_STATE_TCP_FIN_WAIT)
	newstate = FLOWROUTER_STATE_TCP_CLOSED;
      else if (tcp->flags & TCP_FLAG_FIN && s->state == FLOWROUTER_STATE_TCP_CLOSE_WAIT)
	newstate = FLOWROUTER_STATE_TCP_LAST_ACK;
      else if (tcp->flags == 0 && s->state == FLOWROUTER_STATE_UNKNOWN)
	newstate = FLOWROUTER_STATE_TCP_ESTABLISHED;
      s->state = s->state != newstate ? newstate : s->state;
      if (newstate != state) {
	if (newstate >= FLOWROUTER_STATE_TCP_FIN_WAIT) {
	  timer = fm->tcp_transitory_timeout;
	  s->lru_head_index = fm->lru_head_index_tcp_transitory[thread_index];
	} else if (newstate == FLOWROUTER_STATE_TCP_ESTABLISHED) {
	  timer = fm->tcp_established_timeout;
	  s->lru_head_index = fm->lru_head_index_tcp_established[thread_index];
	}
	if (timer != s->timer) {
	  s->timer = timer;
	}
      }
    }
  } else if (ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header (ip);
    if (s->instructions & FLOWROUTER_INSTR_DESTINATION_PORT)
      udp->dst_port = s->post_dp;
    if (s->instructions & FLOWROUTER_INSTR_SOURCE_PORT)
      udp->src_port = s->post_sp;
    if (udp->checksum) {
      l4csum = udp->checksum;
      l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
      udp->checksum = ip_csum_fold(l4csum);
    }
  }
  /* Falling through for other L4 protocols */

  s->last_heard = now;
  flowrouter_session_update_lru(thread_index, pool_index, s);

  return FLOWROUTER_FP_ERROR_NO_ERROR;
}

VLIB_NODE_FN (flowrouter_fastpath_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  flowrouter_main_t *fm = &flowrouter_main;
  u16 *next;
  u32 n_left_from, *from;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  //u32 to_buffers[VLIB_FRAME_SIZE], *tb = to_buffers;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  flowrouter_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;

  u32 *bi;
  u32 thread_index = vm->thread_index;
  u32 no_cachemiss = 0, no_fastpath = 0;
  ip4_header_t *ip0;
  clib_bihash_kv_16_8_t kv;
  f64 now = vlib_time_now (vm);
  u32 out_fib_index0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);

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

      //      tb[0] = bi[0];
      //tb += 1;
      no_cachemiss++;
    } else {
      u32 errno0 = execute(kv.value, thread_index, ip0, now, &out_fib_index0);
      if (errno0 == 0) {
	//vnet_buffer (b[0])->sw_if_index[VLIB_TX] = out_fib_index0;
	no_fastpath++;
	vnet_feature_next((u32 *)next, b[0]);
      } else {
	next[0] = FLOWROUTER_NEXT_DROP;
	b[0]->error = node->errors[errno0];
      }

      //tb[0] = bi[0];
      //tb += 1;
    }
    next += 1;
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE))) {
	flowrouter_trace_t *t =
	  vlib_add_trace (vm, node, b[0], sizeof (*t));

    }

    //  next:
    n_left_from -= 1;
    k += 1;
    h += 1;
    b += 1;
    bi += 1;
  }

  vlib_increment_simple_counter (fm->counters + FLOWROUTER_COUNTER_FASTPATH_FORWARDED, thread_index, 0, no_fastpath);
  vlib_increment_simple_counter (fm->counters + FLOWROUTER_COUNTER_FASTPATH_CACHE_MISS, thread_index, 0, no_cachemiss);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(flowrouter_fastpath_node) = {
  .name = "flowrouter-fastpath",
  /* Takes a vector of packets. */
  .vector_size = sizeof(u32),
  .n_errors = FLOWROUTER_FP_N_ERROR,
  .error_strings = flowrouter_fp_error_strings,
  .format_trace = format_flowrouter_trace,
  .n_next_nodes = FLOWROUTER_N_NEXT,
  .next_nodes =
  {
   [FLOWROUTER_NEXT_DROP] = "error-drop",
   [FLOWROUTER_NEXT_ICMP_ERROR] = "ip4-icmp-error",
   [FLOWROUTER_NEXT_FASTPATH] = "flowrouter-fastpath",
   [FLOWROUTER_NEXT_SLOWPATH] = "flowrouter-slowpath",
   [FLOWROUTER_NEXT_IP4_LOOKUP] = "ip4-lookup",
  },
};

/* Hook up to potential feature arcs */

/* RX NAT on outside interface */
VNET_FEATURE_INIT (flowrouter_fastpath1, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "flowrouter-fastpath",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};

/* TX NAT on outside interface */
VNET_FEATURE_INIT (flowrouter_fastpath2, static) = {
  .arc_name = "ip4-output",
  .node_name = "flowrouter-fastpath",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa",
			       "ip4-sv-reassembly-output-feature"),
};

/* *INDENT-ON* */
