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
  hanat_worker_main_t *hm = &hanat_worker_main;
  u32 mid = ~0;

  if (mode == HANAT_WORKER_IF_OUTSIDE ||
      mode == HANAT_WORKER_IF_DUAL) {
    mid = hanat_lpm_64_lookup (&hm->pool_db, fib_index, ntohl(ip->dst_address.as_u32));
  }
  if (mode == HANAT_WORKER_IF_INSIDE ||
      mode == HANAT_WORKER_IF_DUAL) {
    if (mid == ~0) {
      if (vec_len(hm->pool_db.lb_buckets) == 0)
	  return ~0;
      u32 i = htonl(ip->src_address.as_u32) % hm->pool_db.n_buckets;
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
			  u16 sport, u16 dport, ip4_address_t gre)
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
hanat_worker_cache_add_incomplete(hanat_db_t *db, u32 fib_index, ip4_header_t *ip, u32 bi, bool tunnel, u32 *rv)
{
  hanat_session_key_t key;
  hanat_session_t *s;

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
  if (tunnel)
    s->entry.flags |= HANAT_SESSION_FLAG_TUNNEL;

  s->entry.flags |= HANAT_SESSION_FLAG_INCOMPLETE;

  /* Add to index */
  return s;
}

static inline uword
hanat_worker_slow_inline (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame, bool tunnel)
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
	  if (tunnel) {
	    hanat_gre_data_t *metadata = (hanat_gre_data_t *)vnet_buffer2(b0);
	    vni0 = metadata->vni;
	    gre0 = metadata->src;
	    mode0 = HANAT_WORKER_IF_INSIDE;
	    tunnel = true;
	  } else {
	    vni0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4,
							sw_if_index0);
	    mode0 = hanat_get_interface_mode(sw_if_index0);
	    if (mode0 == ~0) { /* NAT not enabled on interface? */
	      goto drop0;
	    }
	  }

	  u32 mid0 = find_mapper(sw_if_index0, vni0, ip0, mode0);
	  if (mid0 == ~0) goto drop0;

	  hanat_pool_entry_t *pe = pool_elt_at_index(hm->pool_db.pools, mid0);
	  if (!pe) goto drop0;
	  u32 rv = 0;
	  hanat_session_t *s = hanat_worker_cache_add_incomplete(&hm->db, vni0, ip0, bi0, tunnel, &rv);
	  s->mapper_id = mid0;
	  if (rv)
	    vlib_node_increment_counter (vm, node->node_index, rv, 1);

	  vec_validate_init_empty(buffer_per_mapper, mid0, 0);
	  vec_validate_init_empty(offset_per_mapper_buffer, mid0, 0);
	  hanat_protocol_request(vni0, pe, s, mode0, gre0, buffer_per_mapper, offset_per_mapper_buffer, &to_node);
	  if (tunnel) { /* Reset buffer to be able to play it back to hanat_gre4_input */
	    int header_len = sizeof(ip4_header_t) + sizeof(gre_header_t) + sizeof(u32);
	    vlib_buffer_advance(b0, -header_len);
	  }
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

static uword
hanat_worker_slow_tunnel (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
  return hanat_worker_slow_inline(vm, node, frame, true /* tunnel */);
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
					  &sp->sa, &sp->da, sp->sp, sp->dp, gre);

		/* Put cached packet back to fast worker node */
		if (s->entry.buffer) {
		  vlib_node_increment_counter (vm, node->node_index, HANAT_PROTOCOL_INPUT_HELD_PACKET, 1);
		  if (s->entry.flags & HANAT_SESSION_FLAG_TUNNEL)
		    vec_add1(to_gre4_input, s->entry.buffer);
		  else
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
 * Node receiving packets from a NAT inside tunnel fast node
 */
VLIB_REGISTER_NODE(hanat_worker_slow_tunnel_node, static) = {
    .function = hanat_worker_slow_tunnel,
    .name = "hanat-worker-slow-tunnel",
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
