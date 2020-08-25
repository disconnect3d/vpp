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
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include "flowrouter.h"
#include "flowrouter_inlines.h"
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/fib/fib_table.h>
#include <vnet/buffer.h>

/*
 * Trace
 */
typedef struct {
  ip4_header_t *ip;
} flowrouter_trace_t;

static u8 *
format_flowrouter_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  flowrouter_trace_t *t = va_arg(*args, flowrouter_trace_t *);
  s = format (s, "FLOWROUTER SLOWPATH: %U", format_ip4_header, t->ip);
  return s;
}

/*
 * Errors
 */
#define foreach_flowrouter_slowpath_errors						\
  _(SESSION_CREATE_NOT_ALLOWED, "session create not allowed")		\
  _(ADDRESS_PORT_ALLOCATION_FAILED, "address and port allocation failed") \
  _(NO_SESSION, "no session")						\
  _(CREATE_FAILED, "create failed") \
  _(THREAD_NOT_ENABLED, "thread not enabled")

typedef enum
{
#define _(sym, str) FLOWROUTER_SLOWPATH_ERROR_##sym,
  foreach_flowrouter_slowpath_errors
#undef _
    FLOWROUTER_SLOWPATH_N_ERROR,
} flowrouter_slowpath_errors_t;

static char *flowrouter_slowpath_error_strings[] = {
#define _(sym,string) string,
  foreach_flowrouter_slowpath_errors
#undef _
};

#if 0

#define FLOWROUTER_PORT_ALLOC_MAX_RETRIES 5

/*
 * Register flowrouter on input path
 * Configuration
 * Deal with punted packets
 */

flowrouter_main_t flowrouter_main;


static inline bool
flowrouter_session_exists (clib_bihash_16_8_t *h, flowrouter_key_t *k)
{
  clib_bihash_kv_16_8_t value;

  if (clib_bihash_search_16_8 (h, (clib_bihash_kv_16_8_t *)k, &value)) {
    return false;
  }
  return true;
}

/*
 * Address and port allocation algorithm
 * - Pick an address from the outside pool modulo the inside source address
 *   This is to achieve some level of load balancing across the pool.
 * - Pick the same outside port and the inside port if possible
 * - If conflict, i.e. there is already a session X':x' -> Y:y,
 *   try the next port.
 * - If this fails more than 10 times, give up.
 */
static inline u16
get_port (flowrouter_pool_t *p, u16 port)
{
  if (p->psid_length == 0) {
    return port;
  }
  return (port & ~p->psid_mask) | p->psid;
}

/*
 * Assuming psid_offset = 0
 */
static inline u16
get_next_port (flowrouter_pool_t *p, u16 port)
{
  if (p->psid_length == 0) {
    return port <= 0xFFFF - 1 ? port + 1 : 1025;
  }
  return get_port(p, port <= p->psid_mask - 1 ? port + 1 : 1025);
}

static int
flowrouter_allocate_address_and_port (u32 thread_index, u32 vrf_id, u8 proto,
				      ip4_address_t *X, u16 x,
				      ip4_address_t *Y, u16 y,
				      ip4_address_t *X_marked, u16 *x_marked, u32 *conflicts,
				      flowrouter_key_t *k)
{
  flowrouter_main_t *um = &flowrouter_main;
  flowrouter_pool_t *p = flowrouter_pool_get(um->pool_per_thread[thread_index]);
  u32 address;
  u16 port = get_port(p, ntohs(x));
  int i = 0;

  address = ntohl(p->prefix.as_u32) | (ntohl(X->as_u32) % p->count);
  X_marked->as_u32 = htonl(address);

  flowrouter_calc_key2(Y, X_marked, proto, vrf_id, y, htons(port), k);
  while (1) {
    if (flowrouter_session_exists(&um->flowhash, k)) {
      *conflicts += 1;
      if (++i > FLOWROUTER_PORT_ALLOC_MAX_RETRIES)
	return -1;
      k->dp = htons(get_next_port(p, port));
      continue;
    }
    *x_marked = k->dp;
    return 0;
  }
}

/*
 * Verify that it is a session initiating packet
 */
static bool
flowrouter_session_tcp_initiation_prohibited (ip4_header_t *ip, enum flowrouter_session_state *state)
{
  tcp_header_t *tcp = ip4_next_header (ip);
  if (tcp->flags & TCP_FLAG_SYN) {
    *state = FLOWROUTER_STATE_TCP_SYN_SEEN;
    return false;
  }
  return true;
}

static u32
flowrouter_get_timer (u8 proto)
{
  flowrouter_main_t *um = &flowrouter_main;

  switch (proto) {
  case IP_PROTOCOL_ICMP:
    return um->icmp_timeout;
  case IP_PROTOCOL_UDP:
    return um->udp_timeout;
  case IP_PROTOCOL_TCP:
    return um->tcp_transitory_timeout;
  default:
    ;
  }
  return um->default_timeout;
}

static u32
flowrouter_get_lru_head_index (u8 proto, u32 thread_index)
{
  flowrouter_main_t *um = &flowrouter_main;

  switch (proto) {
  case IP_PROTOCOL_ICMP:
    return um->lru_head_index_icmp[thread_index];
  case IP_PROTOCOL_UDP:
    return um->lru_head_index_udp[thread_index];
  case IP_PROTOCOL_TCP:
    return um->lru_head_index_tcp_transitory[thread_index];
  default:
    ;
  }
  return um->lru_head_index_default[thread_index];
}

static void
flowrouter_session_delete (u32 thread_index, flowrouter_session_t *s)
{
  flowrouter_main_t *um = &flowrouter_main;

  pool_put_index (um->lru_pool[thread_index], s->lru_index);
  if (clib_bihash_add_del_16_8 (&um->flowhash, (clib_bihash_kv_16_8_t *)&s->in2out.k, 0)) {
    clib_warning("bihash delete in2out failed %u %U", s - um->sessions_per_worker[thread_index],
		 format_flowrouter_fp_session, &s->in2out);
  }
  if (clib_bihash_add_del_16_8 (&um->flowhash, (clib_bihash_kv_16_8_t *)&s->out2in.k, 0))
    clib_warning("bihash delete out2in failed");
  pool_put(um->sessions_per_worker[thread_index], s);
}

static inline void
flowrouter_session_scavenge_lru_list (u32 thread_index, f64 now, dlist_elt_t *lru_pool, u32 lru_head_index,
				      bool *scavenged)
{
  flowrouter_main_t *um = &flowrouter_main;
  u32 oldest_index = clib_dlist_remove_head (lru_pool, lru_head_index);
  if (oldest_index != ~0) {
    dlist_elt_t *oldest_elt = pool_elt_at_index (lru_pool, oldest_index);
    flowrouter_session_t *s = pool_elt_at_index (um->sessions_per_worker[thread_index],
					   oldest_elt->value);
    if (now >= s->last_heard + s->timer) {
      flowrouter_session_delete (thread_index, s);
      *scavenged = true;
    } else {
      clib_dlist_addhead (lru_pool, lru_head_index, oldest_index);
    }
  }
}

static void
flowrouter_session_scavenge (u32 thread_index, f64 now)
{
  flowrouter_main_t *um = &flowrouter_main;
  int i = 0;
  bool scavenged;
  do {
    scavenged = false;
#define _(n)								\
    flowrouter_session_scavenge_lru_list(thread_index, now, um->lru_pool[thread_index], \
				   um->lru_head_index_##n[thread_index], &scavenged);
    foreach_flowrouter_timers
#undef _
  } while (scavenged == true && ++i < 10); /* Scavenge up to timers * 10 sessions */
}

flowrouter_interface_t *
flowrouter_interface_by_sw_if_index (u32 sw_if_index)
{
  flowrouter_main_t *um = &flowrouter_main;

  if (sw_if_index > vec_len(um->interface_by_sw_if_index)) return 0;
  u32 index = um->interface_by_sw_if_index[sw_if_index];
  if (index == ~0) return 0;
  if (pool_is_free_index(um->interfaces, index)) return 0;
  return pool_elt_at_index(um->interfaces, index);
}

VLIB_NODE_FN (flowrouter_sp_i2o_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  u16 *next;
  u32 n_left_from, *from;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  flowrouter_main_t *um = &flowrouter_main;
  f64 now = vlib_time_now (vm);
  u32 thread_index = vm->thread_index;
  u32 conflicts = 0, created = 0;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_get_buffers(vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0) {
    u32 sw_if_index0, rx_fib_index0;
    ip4_header_t *ip0;

    if (um->sessions_per_worker[thread_index] == 0) {
      next[0] = FLOWROUTER_NEXT_DROP;
      b[0]->error = node->errors[FLOWROUTER_SP_ERROR_THREAD_NOT_ENABLED];
      goto trace0;
    }

    flowrouter_session_scavenge (thread_index, now);
    u32 iph_offset = vnet_buffer (b[0])->ip.reass.save_rewrite_length;
    ip0 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b[0]) + iph_offset);
    sw_if_index0 = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
    rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);

    /*
     * If RX interface == inside => NAT
     * If SA == pool address => NAT
     * Otherwise bypass (install entry?)
     */
    flowrouter_interface_t *interface = flowrouter_interface_by_sw_if_index(sw_if_index0);
    if (interface == 0 ||
	!interface->in2out ||
	(b[0]->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED && !flowrouter_is_pool_address(&ip0->src_address))) {
      clib_warning("Looks like we need to bypass");
      // XXX Counter
      vnet_feature_next((u32 *)next, b[0]);
      goto trace0;
    }

    /* Logic:
     *
     * - Allocate outside port and address
     * - Create in2out and out2in sessions
     * - Create fastpath in2out and out2in hashes
     * - Calculate instructions and checksum deltas
     * - Ship packet back to fastpath
     */

    /* Allocate external address and port */
    ip4_address_t X_marked;
    u16 x_marked;
    u16 sport = vnet_buffer (b[0])->ip.reass.l4_src_port;
    u16 dport = vnet_buffer (b[0])->ip.reass.l4_dst_port;
    enum flowrouter_session_state state0 = FLOWROUTER_STATE_UNKNOWN;
    bool has_ports0 = ip0->protocol == IP_PROTOCOL_TCP ||
      ip0->protocol == IP_PROTOCOL_UDP ? true : false;

    /*
     * Check if this packet should be allowed to create a session
     * XXX: Send TCP reset / ICMP?
     */
    if (has_ports0 && ip0->protocol == IP_PROTOCOL_TCP &&
	flowrouter_session_tcp_initiation_prohibited(ip0, &state0)) {
      next[0] = FLOWROUTER_NEXT_DROP;
      b[0]->error = node->errors[FLOWROUTER_SP_ERROR_SESSION_CREATE_NOT_ALLOWED];
      goto trace0;
    }

    clib_bihash_kv_16_8_t o2i_kv0;
    flowrouter_key_t *out2in_key0 = (flowrouter_key_t *)&o2i_kv0;

    int rv = flowrouter_allocate_address_and_port(thread_index,
						  rx_fib_index0, ip0->protocol,
						  &ip0->src_address, sport,
						  &ip0->dst_address, dport,
						  &X_marked, &x_marked, &conflicts,
						  out2in_key0);
    if (rv) {
      next[0] = FLOWROUTER_NEXT_DROP;
      b[0]->error = node->errors[FLOWROUTER_SP_ERROR_ADDRESS_PORT_ALLOCATION_FAILED];
      goto trace0;
    }

    clib_bihash_kv_16_8_t i2o_kv0;
    flowrouter_key_t *in2out_key0 = (flowrouter_key_t *)&i2o_kv0;

    /* Create FP sessions (in2out, out2in) */
    ip_csum_t l4_c0 = 0;
    flowrouter_instructions_t in2out_instr0, out2in_instr0;

    flowrouter_session_t *s0;
    pool_get(um->sessions_per_worker[thread_index], s0);
    u32 pool_index0 = s0 - um->sessions_per_worker[thread_index];

    /* in2out session */
    in2out_instr0 = FLOWROUTER_INSTR_SOURCE_ADDRESS;
    flowrouter_calc_key(ip0, rx_fib_index0, sport, dport, in2out_key0);

    /* out2in session */
    flowrouter_fp_session_t *i2o_fs0 = &s0->in2out;
    flowrouter_fp_session_t *o2i_fs0 = &s0->out2in;

    ip_csum_t c0 = l3_checksum_delta(in2out_instr0, &ip0->src_address, &X_marked, 0, 0);
    if (has_ports0) {
      in2out_instr0 |= FLOWROUTER_INSTR_SOURCE_PORT | FLOWROUTER_INSTR_TCP_CONN_TRACK;
      l4_c0 = l4_checksum_delta(in2out_instr0, c0, sport, x_marked, 0, 0);
    }

    clib_memcpy_fast(&i2o_fs0->k, in2out_key0, sizeof(*in2out_key0));
    i2o_fs0->instructions = in2out_instr0;
    i2o_fs0->fib_index = rx_fib_index0;
    i2o_fs0->post_sa = X_marked;
    i2o_fs0->post_da.as_u32 = 0;
    i2o_fs0->post_sp = x_marked;
    i2o_fs0->post_dp = 0;
    i2o_fs0->checksum = c0;
    i2o_fs0->l4_checksum = l4_c0;
    i2o_fs0->tcp_mss = 0;
    i2o_fs0->state = state0;

    out2in_instr0 = FLOWROUTER_INSTR_DESTINATION_ADDRESS;
    c0 = l3_checksum_delta(out2in_instr0, 0, 0, &X_marked, &ip0->src_address);
    if (has_ports0) {
      out2in_instr0 |= FLOWROUTER_INSTR_DESTINATION_PORT | FLOWROUTER_INSTR_TCP_CONN_TRACK;
      l4_c0 = l4_checksum_delta(out2in_instr0, c0, 0, 0, x_marked, sport);
    }

    clib_memcpy_fast(&o2i_fs0->k, out2in_key0, sizeof(*out2in_key0));
    o2i_fs0->instructions = out2in_instr0;
    o2i_fs0->fib_index = rx_fib_index0;
    o2i_fs0->post_sa.as_u32 = 0;
    clib_memcpy_fast(&o2i_fs0->post_da, &ip0->src_address, 4);
    o2i_fs0->post_sp = 0;
    o2i_fs0->post_dp = sport;
    o2i_fs0->checksum = c0;
    o2i_fs0->l4_checksum = l4_c0;
    o2i_fs0->tcp_mss = 0;
    o2i_fs0->state = FLOWROUTER_STATE_UNKNOWN;

    s0->timer = flowrouter_get_timer(ip0->protocol);
    s0->last_heard = now;
    s0->lru_head_index = flowrouter_get_lru_head_index(ip0->protocol, thread_index);

    i2o_kv0.value = ((u64)thread_index << 32) | pool_index0;
    o2i_kv0.value = ((u64)thread_index << 32) | pool_index0;

    if (clib_bihash_add_del_16_8 (&um->flowhash, &i2o_kv0, 1)) {
      pool_put(um->sessions_per_worker[thread_index], s0);
      next[0] = FLOWROUTER_NEXT_DROP;
      b[0]->error = node->errors[FLOWROUTER_SP_ERROR_CREATE_FAILED];
      goto trace0;
    }

    if (clib_bihash_add_del_16_8 (&um->flowhash, &o2i_kv0, 1)) {
      clib_warning("ADDING FAILED");
      clib_bihash_add_del_16_8 (&um->flowhash, &i2o_kv0, 0);
      pool_put(um->sessions_per_worker[thread_index], s0);
      next[0] = FLOWROUTER_NEXT_DROP;
      b[0]->error = node->errors[FLOWROUTER_SP_ERROR_CREATE_FAILED];
      goto trace0;
    }

    vnet_buffer(b[0])->flowrouter.pool_index = pool_index0;

    dlist_elt_t *lru_list_elt;
    pool_get (um->lru_pool[thread_index], lru_list_elt);
    lru_list_elt->value = pool_index0;
    s0->lru_index = lru_list_elt - um->lru_pool[thread_index];
    clib_dlist_addtail (um->lru_pool[thread_index], s0->lru_head_index, s0->lru_index);

    next[0] = FLOWROUTER_NEXT_FASTPATH_I2O;
    created += 1;
  trace0:
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
		       && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
      {
	flowrouter_trace_t *t =
	  vlib_add_trace (vm, node, b[0], sizeof (*t));
	t->ip = 0;
      }


    b += 1;
    next += 1;
    n_left_from -= 1;
  }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  if (conflicts > 0)
    vlib_increment_simple_counter (um->counters + FLOWROUTER_COUNTER_SLOWPATH_PORT_ALLOC_CONFLICT, thread_index, 0, conflicts);
  if (created > 0)
    vlib_increment_simple_counter (um->counters + FLOWROUTER_COUNTER_SLOWPATH_CREATED, thread_index, 0, created);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowrouter_sp_i2o_node) = {
  .name = "flowrouter-slowpath-i2o",
  .vector_size = sizeof (u32),
  .format_trace = format_flowrouter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (flowrouter_sp_error_strings),
  .error_strings = flowrouter_sp_error_strings,
  .sibling_of = "flowrouter-handoff",
};
/* *INDENT-ON* */


#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () =
{
.version = VPP_BUILD_VER,.description = "NAT slowpath"
};

/*
 * out2in logic:
 * No match in the session database.
 * If DA == pool address:
 *    3-tuple lookup: if match create entries (static binding)
 *    else If interface address overload mode:
 *        create entry + punt
 * else bypass entirely
 *
 * in2out logic:
 * If RX interface == inside => NAT
 * If SA == pool address => NAT
 * Bypass (install entry?)
 *
 */
VLIB_NODE_FN (flowrouter_sp_o2i_node) (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  flowrouter_main_t *um = &flowrouter_main;
  u32 n_left_from, *from, *to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left_from > 0) {
    u32 n_left_to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 sw_if_index0, rx_fib_index0;
      ip4_header_t *ip0;

      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index0);

      /*
       * Session is not created from the inside. Let the packet
       * in. Perhaps something will respond.
       */
      if (flowrouter_is_pool_address(&ip0->dst_address)) {
	/* Lookup static binding */
	ip4_address_t src = { 0 };
	u16 dport = vnet_buffer (b0)->ip.reass.l4_dst_port;
	clib_bihash_kv_16_8_t k;
	flowrouter_calc_key2(&src, &ip0->dst_address, ip0->protocol, rx_fib_index0, 0, dport, (flowrouter_key_t *)&k);
	clib_bihash_kv_16_8_t kv;
	clib_memcpy_fast (&kv.key, &k, 16);
	if (clib_bihash_search_inline_16_8 (&um->flowhash, &kv)) {
	  /* Not match */
	  if (um->pool_is_interface_address) {
	    /* Punt */
	    /* Create entry??? */
	    clib_warning("Packet forus, punt, should create entry");
	    vnet_feature_next(&next0, b0);
	  } else {
	    /* drop */
	    b0->error = node->errors[FLOWROUTER_SP_ERROR_NO_SESSION];
	    next0 = FLOWROUTER_NEXT_DROP;
	  }
	} else {
	   /*
	    * Match for static binding
	    * Create new 5/6-tuple session
	    */
	  clib_warning("Add code to create new 5-tuple session from 3-tuple");
	  //TODO
	  next0 = FLOWROUTER_NEXT_FASTPATH_O2I;
	}
      } else {
	/* Bypass - not destined to us */
	vnet_feature_next(&next0, b0);
      }

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                         && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	flowrouter_trace_t *t =
	  vlib_add_trace (vm, node, b0, sizeof (*t));
	t->ip = ip0;
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
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowrouter_sp_o2i_node) = {
  .name = "flowrouter-slowpath-o2i",
  .vector_size = sizeof (u32),
  .format_trace = format_flowrouter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (flowrouter_sp_error_strings),
  .error_strings = flowrouter_sp_error_strings,
  .sibling_of = "flowrouter-handoff",
};
/* *INDENT-ON* */




/*******************************/
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

/*
 * This module implement the HANAT session request protocol.  The slow
 * node receives data packets from the fast worker, and generates
 * sessions requests.  The input node receives session bindings from
 * the mapper and updates the session cache.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/gre/packet.h>
#ifndef HANAT_TEST
#include <vnet/fib/fib_types.h>
#include <vnet/fib/fib_table.h>
#endif
#include "hanat_worker_db.h"
#include "../protocol/hanat_protocol.h"

/*
 * hanat-worker-slow NEXT nodes
 */
#define foreach_hanat_worker_slow_next		\
  _(IP4_LOOKUP, "ip4-lookup")			\
  _(DROP, "error-drop")

typedef enum {
#define _(s, n) HANAT_WORKER_SLOW_NEXT_##s,
  foreach_hanat_worker_slow_next
#undef _
    HANAT_WORKER_SLOW_N_NEXT,
} hanat_worker_slow_next_t;


#define foreach_hanat_protocol_input_next	\
  _(DROP, "error-drop")				\
  _(WORKER, "hanat-worker")			\
  _(GRE4_INPUT, "hanat-gre4-input")

typedef enum {
#define _(s, n) HANAT_PROTOCOL_INPUT_NEXT_##s,
  foreach_hanat_protocol_input_next
#undef _
    HANAT_PROTOCOL_INPUT_N_NEXT,
} hanat_protocol_input_next_t;

/*
 * Counters
 */
#define foreach_hanat_worker_slow_counters	\
  /* Must be first. */				\
  _(MAPPER_REQUEST, "mapper request")		\
  _(NO_MAPPER, "no mapper found")		\
  _(QUEUED_DROPPED, "dropped queued packet")

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

#define foreach_hanat_protocol_input_counters	\
  /* Must be first. */				\
  _(MAPPER_BINDING, "mapper binding")		\
  _(NO_MAPPER, "no mapper found")		\
  _(HELD_PACKET, "forwarded held packet")	\
  _(DECLINE_PACKET, "dropped held packet")	\
  _(NOT_IMPLEMENTED_YET, "not implemented yet")

typedef enum
{
#define _(sym, str) HANAT_PROTOCOL_INPUT_##sym,
  foreach_hanat_protocol_input_counters
#undef _
    HANAT_PROTOCOL_INPUT_N_ERROR,
} hanat_protocol_input_counters_t;

static char *hanat_protocol_input_counter_strings[] = {
#define _(sym,string) string,
  foreach_hanat_protocol_input_counters
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
 * This function tries to figure out the interface mode of the packet's RX interface.
 */
u32
hanat_get_interface_mode(u32 sw_if_index)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 index = hm->interface_by_sw_if_index[sw_if_index];
  if (index == ~0) return ~0;
  hanat_interface_t *interface = pool_elt_at_index(hm->interfaces, index);
  return interface->mode;
}

/*
 * FIB index is only used for out2in traffic. The in2out buckets are shared across all VNIs
 */
static u32
find_mapper (u32 sw_if_index, u32 fib_index, ip4_header_t *ip, u32 mode)
{
  icmp46_header_t *icmp = (icmp46_header_t *) ip4_next_header (ip);
  hanat_worker_main_t *hm = &hanat_worker_main;
  ip4_address_t src, dst;
  u32 mid = ~0;

  if (ip->protocol == IP_PROTOCOL_ICMP && is_icmp_error_message (icmp))
    {
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      ip = (ip4_header_t *) (echo + 1);
      src = ip->dst_address;
      dst = ip->src_address;
    }
  else
    {
      src = ip->src_address;
      dst = ip->dst_address;
    }

  if (mode == HANAT_WORKER_IF_OUTSIDE ||
      mode == HANAT_WORKER_IF_DUAL) {
    mid = hanat_lpm_64_lookup (&hm->pool_db, fib_index, ntohl(dst.as_u32));
  }
  if (mode == HANAT_WORKER_IF_INSIDE ||
      mode == HANAT_WORKER_IF_DUAL) {
    if (mid == ~0) {
      if (vec_len(hm->pool_db.lb_buckets) == 0)
	return ~0;
      u32 i = htonl(src.as_u32) % hm->pool_db.n_buckets;
      mid = hm->pool_db.lb_buckets[i];
    }
  }
  return mid;
}

static u32
hanat_get_session_index(hanat_session_t *s)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  return s - hm->db.sessions;
}

static void
hanat_protocol_request(u32 vni, hanat_pool_entry_t *pe, hanat_session_t *session, u32 mode,
		       ip4_address_t gre, u32 *buffer_per_mapper, u32 *offset_per_mapper_buffer, u32 **to_node)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vlib_main_t *vm = vlib_get_main();
  u32 bi;
  hanat_ip_udp_hanat_header_t *h;
  u16 offset;
  vlib_buffer_t *b;

  if (buffer_per_mapper[session->mapper_id] == 0) {
    h = vlib_packet_template_get_packet (vm, &hm->hanat_protocol_template, &bi);
    if (!h) return;
    vec_add1(*to_node, bi);
    buffer_per_mapper[session->mapper_id] = bi;
    offset_per_mapper_buffer[session->mapper_id] = offset = sizeof(*h);
    memcpy(&h->ip.src_address.as_u32, &pe->src.ip4.as_u32, 4);
    memcpy(&h->ip.dst_address.as_u32, &pe->mapper.ip4.as_u32, 4);
    h->udp.src_port = htons(hm->udp_port);
    h->udp.dst_port = htons(pe->udp_port);
    h->hanat.core_id = 0;

    b = vlib_get_buffer(vm, bi);
    VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
    b->flags |= VLIB_BUFFER_IS_TRACED;
    offset = sizeof(*h);
  } else {
    clib_warning("Reusing existing buffer %d", buffer_per_mapper[session->mapper_id]);
    b = vlib_get_buffer(vm, buffer_per_mapper[session->mapper_id]);
    h = vlib_buffer_get_current(b);
    offset = offset_per_mapper_buffer[session->mapper_id];
  }

  hanat_option_session_request_t *req = (hanat_option_session_request_t *) ((u8 *)h + offset);
  int session_request_len = (gre.as_u32 > 0) ? sizeof(hanat_option_session_request_t) + 4 : sizeof(hanat_option_session_request_t);
  req->type = HANAT_SESSION_REQUEST;
  req->length = session_request_len;
  req->session_id = htonl(hanat_get_session_index(session));
  req->pool_id = htonl(pe->pool_id);

  req->desc.sa.as_u32 = session->key.sa.as_u32;
  req->desc.da.as_u32 = session->key.da.as_u32;
  req->desc.sp = session->key.sp;
  req->desc.dp = session->key.dp;
  req->desc.proto = session->key.proto;
  req->desc.vni = htonl(vni);
  req->desc.in2out = mode == (HANAT_WORKER_IF_INSIDE || HANAT_WORKER_IF_DUAL) ? true : false;
  if (gre.as_u32)
    memcpy(req->opaque_data, &gre.as_u32, 4);
  offset += session_request_len;

  h->ip.length = htons(offset);
  h->ip.checksum = ip4_header_checksum (&h->ip);
  h->udp.length = htons (offset - sizeof(ip4_header_t));
  h->udp.checksum = 0;

  b->current_length = offset;
  offset_per_mapper_buffer[session->mapper_id] = offset;

  if (offset > HANAT_PROTOCOL_MAX_SIZE) /* Limit packet size */
    buffer_per_mapper[session->mapper_id] = 0;
  clib_warning("Session request packet %U", format_ip4_header, &h->ip);
}

static void
hanat_worker_cache_update(hanat_session_t *s, f64 now, hanat_instructions_t instructions,
			  u32 fib_index, ip4_address_t *sa, ip4_address_t *da,
			  u16 sport, u16 dport, ip4_address_t gre, u16 tcp_mss_value)
{
  /* Update session entry */
  hanat_session_key_t *key = &s->key;
  hanat_session_entry_t *entry = &s->entry;
  entry->flags &= ~HANAT_SESSION_FLAG_INCOMPLETE;
  entry->instructions = instructions;
  entry->fib_index = fib_index;
  memcpy(&entry->post_sa, &sa->as_u32, 4);
  memcpy(&entry->post_da, &da->as_u32, 4);
  entry->post_sp = sport; /* Network byte order */
  entry->post_dp = dport; /* Network byte order */
  entry->tcp_mss_value = ntohs (tcp_mss_value);
  entry->tcp_mss_value_net = tcp_mss_value;

  if (gre.as_u32)
    entry->gre = gre;

  ip_csum_t c = l3_checksum_delta(instructions, key->sa, entry->post_sa, key->da, entry->post_da);
  if (key->proto == IP_PROTOCOL_ICMP) /* ICMP checksum does not include pseudoheader */
    entry->l4_checksum = l4_checksum_delta(entry->instructions, 0, key->sp, entry->post_sp, key->dp, entry->post_dp);
  else
    entry->l4_checksum = l4_checksum_delta(entry->instructions, c, key->sp, entry->post_sp, key->dp, entry->post_dp);
  entry->checksum = c;

  entry->last_heard = entry->last_refreshed = now;
}

static hanat_session_t *
hanat_worker_cache_add_incomplete(hanat_db_t *db, u32 fib_index, ip4_header_t *ip, u32 bi, u32 *rv)
{
  hanat_session_key_t key;
  hanat_session_t *s;

  // we don't care about return value
  hanat_key_from_ip(fib_index, ip, &key);
  /* Check if session already exists */
  s = hanat_session_find(db, &key);
  if (!s) {
    /* Add session to pool */
    pool_get_zero(db->sessions, s);
    s->key = key;
    clib_bihash_kv_16_8_t kv;
    kv.key[0] = key.as_u64[0];
    kv.key[1] = key.as_u64[1];
    kv.value = s - db->sessions;
    if (clib_bihash_add_or_overwrite_stale_16_8(&db->cache, &kv, hanat_session_stale_cb, &db))
      assert(0);
  } else {
    /* - If not incomplete, report error
     * - If existing buffer, send buffer to drop node, and enqueue current one
     */
    if (s->entry.buffer) {
      vlib_main_t *vm = vlib_get_main();
      vlib_buffer_free(vm, &s->entry.buffer, 1);
      *rv = HANAT_WORKER_SLOW_QUEUED_DROPPED;
    }
  }

  s->entry.buffer = bi;

  s->entry.flags |= HANAT_SESSION_FLAG_INCOMPLETE;

  /* Add to index */
  return s;
}

static inline uword
hanat_worker_slow_inline (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 n_left_from, *from, *to_next;
  u32 *buffer_per_mapper = 0, *offset_per_mapper_buffer = 0, *to_node = 0;

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
	  u32 next0, sw_if_index0, vni0;
	  ip4_header_t *ip0;
	  ip4_address_t gre0 = {0};

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  ip0 = (ip4_header_t *) vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  u32 mode0;
	    vni0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							sw_if_index0);
	    mode0 = hanat_get_interface_mode(sw_if_index0);
	    if (mode0 == ~0) { /* NAT not enabled on interface? */
	      goto drop0;
	    }
	  u32 mid0 = find_mapper(sw_if_index0, vni0, ip0, mode0);
	  if (mid0 == ~0) goto drop0;

	  hanat_pool_entry_t *pe = pool_elt_at_index(hm->pool_db.pools, mid0);
	  if (!pe) goto drop0;
	  u32 rv = 0;
	  hanat_session_t *s = hanat_worker_cache_add_incomplete(&hm->db, vni0, ip0, bi0, &rv);
	  s->mapper_id = mid0;
	  if (rv)
	    vlib_node_increment_counter (vm, node->node_index, rv, 1);

	  vec_validate_init_empty(buffer_per_mapper, mid0, 0);
	  vec_validate_init_empty(offset_per_mapper_buffer, mid0, 0);
	  hanat_protocol_request(vni0, pe, s, mode0, gre0, buffer_per_mapper, offset_per_mapper_buffer, &to_node);
	  vlib_node_increment_counter (vm, node->node_index, HANAT_WORKER_SLOW_MAPPER_REQUEST, 1);
	  n_left_to_next++;
	  to_next--;

	  b0->flags &= ~VLIB_BUFFER_IS_TRACED; /* Trace doesn't work for buffered packets */
	  continue;

	  /* Fall through to failure */
	drop0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	    hanat_worker_slow_trace_t *t =
	      vlib_add_trace (vm, node, b0, sizeof (*t));
	  }

	  b0->error = node->errors[HANAT_WORKER_SLOW_NO_MAPPER];
	  next0 = HANAT_WORKER_SLOW_NEXT_DROP;

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);

	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  hanat_send_to_node(vm, to_node, node, HANAT_WORKER_SLOW_NEXT_IP4_LOOKUP);
  vec_free(buffer_per_mapper);
  vec_free(offset_per_mapper_buffer);
  vec_free(to_node);

  return frame->n_vectors;
}

static uword
hanat_worker_slow_feature (vlib_main_t * vm,
			   vlib_node_runtime_t * node,
			   vlib_frame_t * frame)
{
  return hanat_worker_slow_inline(vm, node, frame, false /* input feature */);
}

/*
 * Receive instructions from mapper
 * Do hand-off to owning worker?
 * Single-thread at the moment?
 */
static uword
hanat_protocol_input (vlib_main_t * vm,
		      vlib_node_runtime_t * node,
		      vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  hanat_protocol_input_next_t next_index;
  hanat_worker_main_t *hm = &hanat_worker_main;

 f64 now = vlib_time_now (vm);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 *to_gre4_input = 0;
  u32 *to_hanat_worker = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = HANAT_PROTOCOL_INPUT_NEXT_DROP;
	  u32 error0 = 0;
	  udp_header_t *u0;
	  hanat_header_t *h0;
	  ip4_header_t *ip40 = 0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);
	  u0 = (udp_header_t *) ((u8 *) h0 - sizeof (*u0));

	  ip40 = (ip4_header_t *) (((u8 *) u0) - sizeof (ip4_header_t));
	  if (ip40->ip_version_and_header_length != 0x45) {
	    error0 = 0;
	    goto done0;
	  }

	  typedef struct {
	    u8 t;
	    u8 l;
	  } tl_t;


	  u16 offset = sizeof(udp_header_t) + sizeof(hanat_header_t);
	  u16 plen = ntohs(u0->length);

	  while (offset + 2 < plen) {
	    u8 *p = (u8 *) ((u8 *) u0 + offset);
	    tl_t *tl = (tl_t *)(p);
	    offset += tl->l;
	    switch(tl->t) {

	      /*
	       * Lookup based on session-id
	       * Add data to pool
	       * Ship cached packet
	       */
	    case HANAT_SESSION_BINDING:
	      {
		if (tl->l != sizeof(hanat_option_session_binding_t) &&
		    tl->l != sizeof(hanat_option_session_binding_t) +4) {
		  clib_warning("Invalid Session Binding TLV");
		  continue;
		}
		hanat_option_session_binding_t *sp = (hanat_option_session_binding_t *)(p);
		hanat_session_t *s = pool_elt_at_index(hm->db.sessions, ntohl(sp->session_id));
		if (!s) {
		  clib_warning("Could not find session %d", ntohl(sp->session_id));
		  continue;
		}
		ip4_address_t gre = {0};
		if (tl->l == sizeof(hanat_option_session_binding_t) + 4)
		  memcpy(&gre, sp->opaque_data, 4);
		hanat_worker_cache_update(s, now, ntohl(sp->instructions), ntohl(sp->fib_index),
					  &sp->sa, &sp->da, sp->sp, sp->dp, gre, sp->mss_value);

		/* Put cached packet back to fast worker node */
		if (s->entry.buffer) {
		  vlib_node_increment_counter (vm, node->node_index, HANAT_PROTOCOL_INPUT_HELD_PACKET, 1);
		  vec_add1(to_hanat_worker, s->entry.buffer);
		  s->entry.buffer = 0;
		}
	      }
	      break;
	    case HANAT_SESSION_DECLINE:
	      {
		if (tl->l != sizeof(hanat_option_session_decline_t)) {
		  clib_warning("Invalid Session Decline TLV");
		  continue;
		}
		hanat_option_session_decline_t *sp = (hanat_option_session_decline_t *)(p);
		hanat_session_t *s = pool_elt_at_index(hm->db.sessions, ntohl(sp->session_id));
		if (!s) {
		  clib_warning("Could not find session %d", ntohl(sp->session_id));
		  continue;
		}

		u32 bi = s->entry.buffer;
		hanat_session_delete(&hm->db, &s->key);

		/* Put cached packet back to fast worker node */
		if (s->entry.buffer) {
		  /* TODO: Consider sending ICMP error back */
		  vlib_node_increment_counter (vm, node->node_index, HANAT_PROTOCOL_INPUT_DECLINE_PACKET, 1);
		  give_to_frame(hm->error_node_index, bi);
		}
	      }
	      break;
	    default:
	      clib_warning("Unimplemented TLV");
	      error0 = HANAT_PROTOCOL_INPUT_NOT_IMPLEMENTED_YET;
	      break;
	    }
	  }

	done0:
	  b0->error = node->errors[error0];

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

  hanat_send_to_node(vm, to_hanat_worker, node, HANAT_PROTOCOL_INPUT_NEXT_WORKER);
  hanat_send_to_node(vm, to_gre4_input, node, HANAT_PROTOCOL_INPUT_NEXT_GRE4_INPUT);
  vec_free(to_hanat_worker);
  vec_free(to_gre4_input);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
/*
 * Node receiving packets from the input feature path fast node
 */
VLIB_REGISTER_NODE(hanat_worker_slow_feature_node, static) = {
    .function = hanat_worker_slow_feature,
    .name = "hanat-worker-slow-feature",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = HANAT_WORKER_SLOW_N_ERROR,
    .error_strings = hanat_worker_slow_counter_strings,
    .n_next_nodes = HANAT_WORKER_SLOW_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [HANAT_WORKER_SLOW_NEXT_##s] = n,
     foreach_hanat_worker_slow_next
#undef _
    },
    .format_trace = format_hanat_worker_slow_trace,
};

/*
 * Node receiving packets from a NAT fast node
 */
VLIB_REGISTER_NODE(hanat_protocol_input_node) = {
    .function = hanat_protocol_input,
    .name = "hanat-protocol-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = HANAT_PROTOCOL_INPUT_N_ERROR,
    .error_strings = hanat_protocol_input_counter_strings,
    .n_next_nodes = HANAT_PROTOCOL_INPUT_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [HANAT_PROTOCOL_INPUT_NEXT_##s] = n,
     foreach_hanat_protocol_input_next
#undef _
    },
    .format_trace = format_hanat_worker_slow_trace,
};
/* *INDENT-ON* */
#endif


VLIB_NODE_FN (flowrouter_slowpath_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  u32 n_left_from, *from;
  u16 *next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  vlib_get_buffers(vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0) {
    next[0] = FLOWROUTER_NEXT_DROP;
    b += 1;
    next += 1;
    n_left_from -= 1;
  }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (flowrouter_slowpath_node) = {
  .name = "flowrouter-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_flowrouter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (flowrouter_slowpath_error_strings),
  .error_strings = flowrouter_slowpath_error_strings,
  .sibling_of = "flowrouter-handoff",
};
/* *INDENT-ON* */
