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
#include <vnet/gre/packet.h>
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
  _(SLOW_FEATURE, "hanat-worker-slow-feature")	\
  _(IP4_LOOKUP, "ip4-lookup")

typedef enum {
#define _(s, n) HANAT_WORKER_NEXT_##s,
  foreach_hanat_worker_next
#undef _
    HANAT_WORKER_N_NEXT,
} hanat_worker_next_t;

/*
 * hanat-gre4_input NEXT nodes
 */
#define foreach_hanat_gre4_input_next		\
  _(DROP, "error-drop")				\
  _(SLOW_TUNNEL, "hanat-worker-slow-tunnel")	\
  _(IP4_LOOKUP, "ip4-lookup")

typedef enum {
#define _(s, n) HANAT_GRE4_INPUT_NEXT_##s,
  foreach_hanat_gre4_input_next
#undef _
    HANAT_GRE4_INPUT_N_NEXT,
} hanat_gre4_input_next_t;

/*
 * hanat-worker counters
 */
#define foreach_hanat_worker_counters		\
  _(CACHE_HIT_PACKETS, "cache hit")		\
  _(CACHE_MISS_PACKETS, "cache miss")		\
  _(CACHE_REFRESH_SENT, "session refresh")

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
 * hanat-gre4_input counters
 */
#define foreach_hanat_gre4_input_counters		\
  _(CACHE_HIT_PACKETS, "cache hit")			\
  _(CACHE_MISS_PACKETS, "cache miss")			\
  _(CACHE_REFRESH_SENT, "session refresh")		\
  _(UNSUPPORTED_VERSION, "GRE unknown version")		\
  _(UNSUPPORTED_PROTOCOL, "GRE unsupported protocol")   \
  _(MISSING_KEY, "GRE missing key")

typedef enum
{
#define _(sym, str) HANAT_GRE4_INPUT_##sym,
  foreach_hanat_gre4_input_counters
#undef _
    HANAT_GRE4_INPUT_N_ERROR,
} hanat_gre4_input_counters_t;

static char *hanat_gre4_input_counter_strings[] = {
#define _(sym,string) string,
  foreach_hanat_gre4_input_counters
#undef _
};


/*
 * hanat-worker trace
 */
typedef struct {
  hanat_session_t session;
} hanat_worker_trace_t;

static u8 *
format_hanat_session_key (u8 *s, va_list *args)
{
  hanat_session_key_t *k = va_arg(*args, hanat_session_key_t *);
  return format (s, "%U: %U:%d -> %U:%d fib_index %d",
		 format_ip_protocol, k->proto,
		 format_ip4_address, &k->sa, k->sp,
		 format_ip4_address, &k->da, k->dp,
		 k->fib_index);
}

static u8 *
format_hanat_worker_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  hanat_worker_trace_t *t = va_arg (*args, hanat_worker_trace_t *);
  return format (s, "HANAT WORKER: %U", format_hanat_session_key, &t->session.key);
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
  } else if (ip->protocol == IP_PROTOCOL_ICMP) {
    icmp46_header_t *icmp = (icmp46_header_t *) ip4_next_header (ip);
    if (icmp->type == ICMP4_echo_request ||
	icmp->type == ICMP4_echo_reply) {
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      if (s->instructions & HANAT_INSTR_SOURCE_PORT)
	echo->identifier = s->post_sp;
      else if (s->instructions & HANAT_INSTR_DESTINATION_PORT)
	echo->identifier = s->post_dp;
      l4csum = icmp->checksum;
      l4csum = ip_csum_sub_even(l4csum, s->l4_checksum);
      icmp->checksum = ip_csum_fold(l4csum);
    } else {
      /* Not implemented */
      clib_warning("ICMP error not implemented");
    }
  }
  /* Falling through for other L4 protocols */
  return true;
}

/*
 * Add refresh TLV to per-mapper buffer
 */
static void
hanat_refresh_session (hanat_session_t *session, u32 *buffer_per_mapper, u32 *offset_per_mapper_buffer, u32 **to_node)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vlib_main_t *vm = vlib_get_main();
  u32 bi;
  hanat_pool_entry_t *pe = pool_elt_at_index(hm->pool_db.pools, session->mapper_id);
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

  hanat_option_session_refresh_t *ref = (hanat_option_session_refresh_t *) ((u8 *)h + offset);
  ref->type = HANAT_SESSION_REFRESH;
  ref->length = sizeof(hanat_option_session_refresh_t);
  ref->desc.sa.as_u32 = session->key.sa.as_u32;
  ref->desc.da.as_u32 = session->key.da.as_u32;
  ref->desc.sp = session->key.sp;
  ref->desc.dp = session->key.dp;
  ref->desc.proto = session->key.proto;
  ref->desc.vni = htonl(session->entry.fib_index);
  ref->desc.in2out = 0; // TODO: Move?
  ref->flags = 0;
  ref->packets = 0;
  ref->bytes = 0;

  offset += sizeof(hanat_option_session_refresh_t);
  h->ip.length = htons(offset);
  h->ip.checksum = ip4_header_checksum (&h->ip);
  h->udp.length = htons (offset - sizeof(ip4_header_t));
  h->udp.checksum = 0;

  b->current_length = offset;

  if (offset > HANAT_PROTOCOL_MAX_SIZE) /* Limit packet size */
    buffer_per_mapper[session->mapper_id] = 0;

  clib_warning("Session refresh packet %U", format_ip4_header, &h->ip);
  offset_per_mapper_buffer[session->mapper_id] = offset;
}

static bool
hanat_nat44_transform (hanat_db_t *db, u32 fib_index, ip4_header_t *ip, f64 now, u32 *out_fib_index, hanat_session_t **session)
{
  hanat_session_t *s;
  hanat_worker_main_t *hm = &hanat_worker_main;

  /* 6-tuple lookup */
  s = hanat_session_find_ip(db, fib_index, ip);
  if (!s || s->entry.flags & HANAT_SESSION_FLAG_INCOMPLETE)
    return false;
  if (now >= s->entry.last_heard + hm->cache_expiry_timer)
    return false;

  *out_fib_index = s->entry.fib_index;
  s->entry.last_heard = now;
  *session = s;
  return transform_packet(&s->entry, ip);
}

static void
add_gre_encap(vlib_buffer_t *b, ip4_header_t *org_ip, ip4_address_t dst, u32 vni)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  int header_len = sizeof(ip4_header_t) + sizeof(gre_header_t) + sizeof(u32);
  vlib_buffer_advance(b, -header_len);
  ip4_header_t *ip = vlib_buffer_get_current (b);
  clib_memcpy(ip, hm->gre_template, header_len);

  ip->dst_address = dst;
  ip->length = htons(ntohs(org_ip->length) + 28);
  ip->checksum = ip4_header_checksum(ip);
  gre_header_t *h = (gre_header_t *) (ip + 1);
  u32 *vnip = (u32 *) (h + 1);
  *vnip = htonl(vni);
}


#ifndef HANAT_TEST

/*
 * NAT node sitting as an interface  input feature
 */
static uword
hanat_worker (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 n_left_from, *from, *to_next;
  f64 now = vlib_time_now (vm);
  //u32 thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  u32 cache_hit = 0, cache_miss = 0;
  u32 *buffer_per_mapper = 0, *offset_per_mapper_buffer = 0, *to_node = 0;
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
	  vni0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
						      sw_if_index0);

	  /*
	   * Lookup and do transform in cache, if miss send to slow path node
	   */
	  u32 out_fib_index0;
	  hanat_session_t *session = 0;
	  if (hanat_nat44_transform(&hm->db, vni0, ip0, now, &out_fib_index0, &session)) {
	    vnet_feature_next(&next0, b0);
	    if (session->entry.gre.as_u32)
	      add_gre_encap(b0, ip0, session->entry.gre, out_fib_index0);

	    if (now >= session->entry.last_refreshed + hm->cache_refresh_interval) {
	      vec_validate_init_empty(buffer_per_mapper, session->mapper_id, 0);
	      vec_validate_init_empty(offset_per_mapper_buffer, session->mapper_id, 0);
	      hanat_refresh_session(session, buffer_per_mapper, offset_per_mapper_buffer, &to_node);
	      session->entry.last_refreshed = now;
	    }

	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0; //out_fib_index0;
	    cache_hit++;
	  } else {
	    next0 = HANAT_WORKER_NEXT_SLOW_FEATURE;
	    cache_miss++;
	  }

          if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                             && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	    hanat_worker_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
	    if (session)
	      clib_memcpy(&t->session, session, sizeof(hanat_session_t));
	  }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, HANAT_WORKER_CACHE_HIT_PACKETS, cache_hit);
  vlib_node_increment_counter (vm, node->node_index, HANAT_WORKER_CACHE_MISS_PACKETS, cache_miss);
  vlib_node_increment_counter (vm, node->node_index, HANAT_WORKER_CACHE_REFRESH_SENT, vec_len(to_node));
  hanat_send_to_node(vm, to_node, node, HANAT_WORKER_NEXT_IP4_LOOKUP);
  vec_free(buffer_per_mapper);
  vec_free(offset_per_mapper_buffer);
  vec_free(to_node);
  return frame->n_vectors;
}

/*
 * NAT node sitting at the end of a GRE4 tunnel (inside mode only)
 */
static uword
hanat_gre4_input (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  f64 now = vlib_time_now (vm);
  u32 n_left_from, *from, *to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  u32 cache_hit = 0, cache_miss = 0;
  u32 *buffer_per_mapper = 0, *offset_per_mapper_buffer = 0, *to_node = 0;
  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  gre_header_t *h0;
	  ip4_header_t *ip40;
	  u16 version0;
	  int verr0;
	  u32 next0, error0 = 0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip40 = vlib_buffer_get_current (b0);

	  vlib_buffer_advance (b0, sizeof (*ip40));
	  h0 = vlib_buffer_get_current (b0);

	  error0 = ntohs(h0->protocol) != GRE_PROTOCOL_ip4 ? HANAT_GRE4_INPUT_UNSUPPORTED_PROTOCOL : error0;
	  version0 = ntohs (h0->flags_and_version);
	  verr0 = version0 & GRE_VERSION_MASK;
	  error0 = verr0 ? HANAT_GRE4_INPUT_UNSUPPORTED_VERSION : error0;
	  error0 = !(ntohs (h0->flags_and_version) & GRE_FLAGS_KEY) ? HANAT_GRE4_INPUT_MISSING_KEY : error0; 
	  u32 vni0_n = *(u32 *) (h0 + 1);
	  vlib_buffer_advance (b0, sizeof (*h0) + sizeof (u32) /* key */);
	  u32 vni0 = ntohl(vni0_n);
	  if (error0) goto error0;

	  /*
	   * Lookup and do transform in cache, if miss send to slow path node
	   */
	  u32 out_fib_index0;
	  ip4_header_t *inner_ip0 = vlib_buffer_get_current (b0);
	  hanat_session_t *session = 0;
	  if (hanat_nat44_transform(&hm->db, vni0, inner_ip0, now, &out_fib_index0, &session)) {
	    next0 = HANAT_GRE4_INPUT_NEXT_IP4_LOOKUP;

	    if (now >= session->entry.last_refreshed + hm->cache_refresh_interval) {
	      vec_validate_init_empty(buffer_per_mapper, session->mapper_id, 0);
	      vec_validate_init_empty(offset_per_mapper_buffer, session->mapper_id, 0);
	      hanat_refresh_session(session, buffer_per_mapper, offset_per_mapper_buffer, &to_node);
	      session->entry.last_refreshed = now;
	    }

	    vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0; //out_fib_index0;
	    cache_hit++;
	  } else {
	    next0 = HANAT_GRE4_INPUT_NEXT_SLOW_TUNNEL;

	    /* Pass GRE information to slow path */
	    hanat_gre_data_t *metadata = (hanat_gre_data_t *)vnet_buffer2(b0);
	    metadata->src = ip40->src_address;
	    metadata->vni = vni0;
	    cache_miss++;
	  }

	error0:
	  if (error0) {
	    b0->error = node->errors[error0];
	    next0 = HANAT_GRE4_INPUT_NEXT_DROP;
	  }
          if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                             && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
	    hanat_worker_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
	    if (session)
	      clib_memcpy(&t->session, session, sizeof(hanat_session_t));

	  }
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, node->node_index, HANAT_GRE4_INPUT_CACHE_HIT_PACKETS, cache_hit);
  vlib_node_increment_counter (vm, node->node_index, HANAT_GRE4_INPUT_CACHE_MISS_PACKETS, cache_miss);
  vlib_node_increment_counter (vm, node->node_index, HANAT_GRE4_INPUT_CACHE_REFRESH_SENT, vec_len(to_node));
  hanat_send_to_node(vm, to_node, node, HANAT_WORKER_NEXT_IP4_LOOKUP);
  vec_free(buffer_per_mapper);
  vec_free(offset_per_mapper_buffer);
  vec_free(to_node);

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

VLIB_REGISTER_NODE(hanat_gre4_input_node) = {
    .function = hanat_gre4_input,
    .name = "hanat-gre4-input",
    /* Takes a vector of packets. */
    .vector_size = sizeof(u32),
    .n_errors = HANAT_GRE4_INPUT_N_ERROR,
    .error_strings = hanat_gre4_input_counter_strings,
    .n_next_nodes = HANAT_GRE4_INPUT_N_NEXT,
    .next_nodes =
    {
#define _(s, n) [HANAT_GRE4_INPUT_NEXT_##s] = n,
     foreach_hanat_gre4_input_next
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
