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
#include "flowrouter_protocol.h"
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/buffer.h>

#include <arpa/inet.h>
#include <assert.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/fib/fib_types.h>

//#include "flowrouter_worker_db.h"
//#include "../protocol/flowrouter_protocol.h"

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

#endif

/*
 * flowrouter-worker-slow NEXT nodes
 */
#define foreach_flowrouter_worker_slow_next		\
  _(IP4_LOOKUP, "ip4-lookup")			\
  _(DROP, "error-drop")

typedef enum {
#define _(s, n) FLOWROUTER_WORKER_SLOW_NEXT_##s,
  foreach_flowrouter_worker_slow_next
#undef _
    FLOWROUTER_WORKER_SLOW_N_NEXT,
} flowrouter_worker_slow_next_t;


#define foreach_flowrouter_protocol_input_next	\
  _(DROP, "error-drop")				\
  _(WORKER, "flowrouter-fastpath")

typedef enum {
#define _(s, n) FLOWROUTER_PROTOCOL_INPUT_NEXT_##s,
  foreach_flowrouter_protocol_input_next
#undef _
    FLOWROUTER_PROTOCOL_INPUT_N_NEXT,
} flowrouter_protocol_input_next_t;

/*
 * Counters
 */
#define foreach_flowrouter_worker_slow_counters	\
  /* Must be first. */				\
  _(MAPPER_REQUEST, "mapper request")		\
  _(NO_MAPPER, "no mapper found")		\
  _(QUEUED_DROPPED, "dropped queued packet")

typedef enum
{
#define _(sym, str) FLOWROUTER_WORKER_SLOW_##sym,
  foreach_flowrouter_worker_slow_counters
#undef _
    FLOWROUTER_WORKER_SLOW_N_ERROR,
} flowrouter_worker_slow_counters_t;

#if 0
static char *flowrouter_worker_slow_counter_strings[] = {
#define _(sym,string) string,
  foreach_flowrouter_worker_slow_counters
#undef _
};
#endif

#define foreach_flowrouter_protocol_input_counters	\
  /* Must be first. */				\
  _(MAPPER_BINDING, "mapper binding")		\
  _(NO_MAPPER, "no mapper found")		\
  _(HELD_PACKET, "forwarded held packet")	\
  _(DECLINE_PACKET, "dropped held packet")	\
  _(NOT_IMPLEMENTED_YET, "not implemented yet")

typedef enum
{
#define _(sym, str) FLOWROUTER_PROTOCOL_INPUT_##sym,
  foreach_flowrouter_protocol_input_counters
#undef _
    FLOWROUTER_PROTOCOL_INPUT_N_ERROR,
} flowrouter_protocol_input_counters_t;

static char *flowrouter_protocol_input_counter_strings[] = {
#define _(sym,string) string,
  foreach_flowrouter_protocol_input_counters
#undef _
};

/*
 * Trace
 */
typedef struct {
  u32 sw_if_index;
} flowrouter_worker_slow_trace_t;

static u8 *
format_flowrouter_worker_slow_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  //flowrouter_worker_trace_t *t = va_arg (*args, flowrouter_worker_trace_t *);
  s = format (s, "FLOWROUTER SLOW WORKER");
  return s;
}

/*
 * This function tries to figure out the interface mode of the packet's RX interface.
 */
#if 0
u32
flowrouter_get_interface_mode(u32 sw_if_index)
{
  flowrouter_worker_main_t *hm = &flowrouter_worker_main;
  u32 index = hm->interface_by_sw_if_index[sw_if_index];
  if (index == ~0) return ~0;
  flowrouter_interface_t *interface = pool_elt_at_index(hm->interfaces, index);
  return interface->mode;
}

/*
 * FIB index is only used for out2in traffic. The in2out buckets are shared across all VNIs
 */
static u32
find_mapper (u32 sw_if_index, u32 fib_index, ip4_header_t *ip, u32 mode)
{
  icmp46_header_t *icmp = (icmp46_header_t *) ip4_next_header (ip);
  flowrouter_worker_main_t *hm = &flowrouter_worker_main;
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

  if (mode == FLOWROUTER_WORKER_IF_OUTSIDE ||
      mode == FLOWROUTER_WORKER_IF_DUAL) {
    mid = flowrouter_lpm_64_lookup (&hm->pool_db, fib_index, ntohl(dst.as_u32));
  }
  if (mode == FLOWROUTER_WORKER_IF_INSIDE ||
      mode == FLOWROUTER_WORKER_IF_DUAL) {
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
flowrouter_get_session_index (flowrouter_session_t *s)
{
  flowrouter_worker_main_t *hm = &flowrouter_worker_main;
  return s - hm->db.sessions;
}
#endif

static bool
flowrouter_protocol_request (u32 thread_index, flowrouter_session_t *session,
			     u32 *protocol_buffer, u32 *protocol_offset, bool is_trace)
{
  flowrouter_main_t *fm = &flowrouter_main;
  vlib_main_t *vm = vlib_get_main();
  u32 bi;
  flowrouter_ip_udp_flowrouter_header_t *h;
  u16 offset;
  vlib_buffer_t *b;
  bool rv = false;

  if (*protocol_buffer == 0) {
    h = vlib_packet_template_get_packet (vm, &fm->protocol_template, &bi);
    if (!h) assert(0);
    *protocol_buffer = bi;
    *protocol_offset = offset = sizeof(*h);
    memcpy(&h->ip.src_address.as_u32, &fm->src.as_u32, 4);
    memcpy(&h->ip.dst_address.as_u32, &fm->mapper.as_u32, 4);
    h->udp.src_port = htons(fm->udp_port);
    h->udp.dst_port = htons(fm->udp_port);
    h->fr.core_id = thread_index;

    b = vlib_get_buffer(vm, bi);
    VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
    if (is_trace) {
      b->flags |= VLIB_BUFFER_IS_TRACED;
    }
    offset = sizeof(*h);

    rv = true;
  } else {
    clib_warning("Reusing existing buffer %d", protocol_buffer);
    b = vlib_get_buffer(vm, *protocol_buffer);
    h = vlib_buffer_get_current(b);
    offset = *protocol_offset;
  }

  flowrouter_option_session_request_t *req = (flowrouter_option_session_request_t *) ((u8 *)h + offset);
  int session_request_len = sizeof(flowrouter_option_session_request_t);
  req->type = FLOWROUTER_SESSION_REQUEST;
  req->length = session_request_len;
  //  req->session_id = htonl(flowrouter_get_session_index(session));

  req->desc.sa.as_u32 = session->k.sa.as_u32;
  req->desc.da.as_u32 = session->k.da.as_u32;
  req->desc.sp = session->k.sp;
  req->desc.dp = session->k.dp;
  req->desc.proto = session->k.proto;
  req->desc.vni = htonl(session->k.fib_index);
  //  req->desc.in2out = mode == (FLOWROUTER_WORKER_IF_INSIDE || FLOWROUTER_WORKER_IF_DUAL) ? true : false;
  offset += session_request_len;

  h->ip.length = htons(offset);
  h->ip.checksum = ip4_header_checksum (&h->ip);
  h->udp.length = htons (offset - sizeof(ip4_header_t));
  h->udp.checksum = 0;

  b->current_length = offset;
  *protocol_offset = offset;

  if (offset > FLOWROUTER_PROTOCOL_MAX_SIZE) /* Limit packet size */
    *protocol_buffer = 0;
  //clib_warning("Session request packet %U", format_ip4_header, &h->ip);

  return rv;
}

static void
flowrouter_cache_update(flowrouter_session_t *s, f64 now, flowrouter_instructions_t instructions,
			u32 fib_index, ip4_address_t *sa, ip4_address_t *da,
			u16 sport, u16 dport, u16 tcp_mss)
{
  /* Update session entry */
  flowrouter_key_t *key = &s->k;

  s->flags &= ~FLOWROUTER_SESSION_FLAG_INCOMPLETE;
  s->instructions = instructions;
  s->fib_index = fib_index;
  memcpy(&s->post_sa, &sa->as_u32, 4);
  memcpy(&s->post_da, &da->as_u32, 4);
  s->post_sp = sport; /* Network byte order */
  s->post_dp = dport; /* Network byte order */
  s->tcp_mss = ntohs (tcp_mss);

  ip_csum_t c = l3_checksum_delta(instructions, &key->sa, &s->post_sa, &key->da, &s->post_da);
  if (key->proto == IP_PROTOCOL_ICMP) /* ICMP checksum does not include pseudoheader */
    s->l4_checksum = l4_checksum_delta(s->instructions, 0, key->sp, s->post_sp, key->dp, s->post_dp);
  else
    s->l4_checksum = l4_checksum_delta(s->instructions, c, key->sp, s->post_sp, key->dp, s->post_dp);
  s->checksum = c;

  //  s->last_heard = s->last_refreshed = now;
}

static flowrouter_session_t *
flowrouter_session_find (u32 thread_index, clib_bihash_kv_16_8_t *k)
{
  flowrouter_main_t *fm = &flowrouter_main;
  clib_bihash_kv_16_8_t value;

  if (clib_bihash_search_16_8 (&fm->flowhash, k, &value))
    return 0;
  if (pool_is_free_index (fm->sessions_per_worker[thread_index], value.value)) /* Is this check necessary? */
    return 0;
  return pool_elt_at_index (fm->sessions_per_worker[thread_index], value.value);
}

static flowrouter_session_t *
flowrouter_worker_cache_add_incomplete (u32 thread_index, clib_bihash_kv_16_8_t *kv, u32 bi)
{
  flowrouter_main_t *fm = &flowrouter_main;
  flowrouter_session_t *s;

  /* Check if session already exists */
  s = flowrouter_session_find(thread_index, kv);
  if (!s) {
    /* Add session to pool */
    pool_get(fm->sessions_per_worker[thread_index], s);
    clib_memcpy_fast(&s->k, &kv->key, sizeof(s->k));
    kv->value = s - fm->sessions_per_worker[thread_index];
    if (clib_bihash_add_del_16_8(&fm->flowhash, kv, 1))
      assert(0);
  } else {
    /* - If not incomplete, report error
     * - If existing buffer, send buffer to drop node, and enqueue current one
     */
    if (s->buffer) {
      vlib_main_t *vm = vlib_get_main();
      vlib_buffer_free(vm, &s->buffer, 1);
      //*rv = FLOWROUTER_WORKER_SLOW_QUEUED_DROPPED;
    }
  }

  s->buffer = bi;

  s->flags |= FLOWROUTER_SESSION_FLAG_INCOMPLETE;

  /* Add to index */
  return s;
}

VLIB_NODE_FN (flowrouter_slowpath_node) (vlib_main_t * vm,
					 vlib_node_runtime_t * node,
					 vlib_frame_t * frame)
{
  flowrouter_main_t *fm = &flowrouter_main;
  u16 *next;
  u32 n_left_from, *from;//, *to_next;
  u32 protocol_buffer = 0, protocol_offset = 0;
  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 to_bufs[VLIB_FRAME_SIZE], *to_b = to_bufs;
  flowrouter_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  u32 no_to_bufs = 0;
  u32 *bi;
  u32 thread_index = vm->thread_index;
  //  u32 no_cachemiss = 0, no_fastpath = 0;
  ip4_header_t *ip0;
  clib_bihash_kv_16_8_t kv;
  //f64 now = vlib_time_now (vm);
  //u32 out_fib_index0;

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

    flowrouter_session_t *s = flowrouter_worker_cache_add_incomplete(thread_index, &kv, *bi);

    bool is_trace = ((node->flags & VLIB_NODE_FLAG_TRACE) && (b[0]->flags & VLIB_BUFFER_IS_TRACED)) ? true : false;
    if (flowrouter_protocol_request(thread_index, s, &protocol_buffer, &protocol_offset, is_trace)) {
      to_b[0] = protocol_buffer;
      to_b++;
      next[0] = FLOWROUTER_NEXT_IP4_LOOKUP;
      next += 1;
      no_to_bufs += 1;
    }
    
    vlib_node_increment_counter (vm, node->node_index, FLOWROUTER_WORKER_SLOW_MAPPER_REQUEST, 1);

    b[0]->flags &= ~VLIB_BUFFER_IS_TRACED; /* Trace doesn't work for buffered packets */

#if 0      
    if (is_trace) {
      flowrouter_worker_slow_trace_t *t =
	vlib_add_trace (vm, node, b0, sizeof (*t));
    }
#endif

    n_left_from -= 1;
    k += 1;
    h += 1;
    b += 1;
    bi += 1;

  }

  vlib_buffer_enqueue_to_next (vm, node, to_bufs, nexts, no_to_bufs);

  return frame->n_vectors;
}

/*
 * Receive instructions from mapper
 * Do hand-off to owning worker?
 * Single-thread at the moment?
 */

VLIB_NODE_FN (flowrouter_protocol_input_node) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  flowrouter_main_t *fm = &flowrouter_main;
  //  u16 *next;
  u32 n_left_from, *from;//, *to_next;
  //u32 protocol_buffer = 0, protocol_offset = 0;
  //  u16 nexts[VLIB_FRAME_SIZE] = { 0 };
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  //  u32 to_bufs[VLIB_FRAME_SIZE], *to_b = to_bufs;
  //flowrouter_key_t keys[VLIB_FRAME_SIZE], *k = keys;
  //u64 hashes[VLIB_FRAME_SIZE], *h = hashes;
  //u32 no_to_bufs = 0;
  //u32 *bi;
  u32 thread_index = vm->thread_index;
  //  u32 no_cachemiss = 0, no_fastpath = 0;
  //  ip4_header_t *ip0;
  //clib_bihash_kv_16_8_t kv;
  f64 now = vlib_time_now (vm);
  //u32 out_fib_index0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, b, n_left_from);

  while (n_left_from > 0) {
    u32 error0 = 0;
    udp_header_t *u0;
    flowrouter_header_t *h0;
    ip4_header_t *ip40 = 0;

    h0 = vlib_buffer_get_current (b[0]);
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


    u16 offset = sizeof(udp_header_t) + sizeof(flowrouter_header_t);
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
      case FLOWROUTER_SESSION_BINDING:
	{
	  if (tl->l != sizeof(flowrouter_option_session_binding_t) &&
	      tl->l != sizeof(flowrouter_option_session_binding_t) +4) {
	    clib_warning("Invalid Session Binding TLV");
	    continue;
	  }
	  flowrouter_option_session_binding_t *sp = (flowrouter_option_session_binding_t *)(p);
	  flowrouter_session_t *s = pool_elt_at_index(fm->sessions_per_worker[thread_index], ntohl(sp->session_id));
	  if (!s) {
	    clib_warning("Could not find session %d", ntohl(sp->session_id));
	    continue;
	  }
	  flowrouter_cache_update(s, now, ntohl(sp->instructions), ntohl(sp->fib_index),
				  &sp->sa, &sp->da, sp->sp, sp->dp, sp->mss_value);

	  /* Put cached packet back to fast worker node */
	  if (s->buffer) {
	    vlib_node_increment_counter (vm, node->node_index, FLOWROUTER_PROTOCOL_INPUT_HELD_PACKET, 1);
	    //vec_add1(to_flowrouter_worker, s->buffer);
	    s->buffer = 0;
	  }
	}
	break;
#if 0
      case FLOWROUTER_SESSION_DECLINE:
	{
	  if (tl->l != sizeof(flowrouter_option_session_decline_t)) {
	    clib_warning("Invalid Session Decline TLV");
	    continue;
	  }
	  flowrouter_option_session_decline_t *sp = (flowrouter_option_session_decline_t *)(p);
	  flowrouter_session_t *s = pool_elt_at_index(fm->sessions_per_worker[thread_index], ntohl(sp->session_id));
	  if (!s) {
	    clib_warning("Could not find session %d", ntohl(sp->session_id));
	    continue;
	  }

	  u32 bi = s->buffer;
	  //flowrouter_session_delete(&s->k);

	  /* Put cached packet back to fast worker node */
	  if (s->buffer) {
	    /* TODO: Consider sending ICMP error back */
	    //vlib_node_increment_counter (vm, node->node_index, FLOWROUTER_PROTOCOL_INPUT_DECLINE_PACKET, 1);
	    //give_to_frame(hm->error_node_index, bi);
	  }
	}
	break;
#endif
      default:
	clib_warning("Unimplemented TLV");
	error0 = FLOWROUTER_PROTOCOL_INPUT_NOT_IMPLEMENTED_YET;
	break;
      }
    }

  done0:
    ;
    //b0->error = node->errors[error0];
#if 0
    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
		       && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
      flowrouter_worker_slow_trace_t *t =
	vlib_add_trace (vm, node, b0, sizeof (*t));
    }
#endif
  }
  return frame->n_vectors;
}

/*
 * Node receiving packets from a NAT fast node
 */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(flowrouter_protocol_input_node) = {
    .name = "flowrouter-protocol-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = FLOWROUTER_PROTOCOL_INPUT_N_ERROR,
    .error_strings = flowrouter_protocol_input_counter_strings,
    .n_next_nodes = FLOWROUTER_PROTOCOL_INPUT_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [FLOWROUTER_PROTOCOL_INPUT_NEXT_##s] = n,
     foreach_flowrouter_protocol_input_next
#undef _
    },
    .format_trace = format_flowrouter_worker_slow_trace,
};

VLIB_REGISTER_NODE (flowrouter_slowpath_node) = {
  .name = "flowrouter-slowpath",
  .vector_size = sizeof (u32),
  .format_trace = format_flowrouter_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (flowrouter_slowpath_error_strings),
  .error_strings = flowrouter_slowpath_error_strings,
  .sibling_of = "flowrouter-fastpath",
};
/* *INDENT-ON* */
