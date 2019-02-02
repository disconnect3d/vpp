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
#define foreach_hanat_worker_slow_next	\
  _(IP4_LOOKUP, "ip4-lookup")		\
  _(DROP, "error-drop")

typedef enum {
#define _(s, n) HANAT_WORKER_SLOW_NEXT_##s,
  foreach_hanat_worker_slow_next
#undef _
    HANAT_WORKER_SLOW_N_NEXT,
} hanat_worker_slow_next_t;


#define foreach_hanat_protocol_input_next	\
  _(DROP, "error-drop")

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
  _(NO_MAPPER, "no mapper found")

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
  _(HELD_PACKET, "forwarded held packet")

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
      u32 i = ip->src_address.as_u32 % hm->pool_db.n_buckets;
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
give_to_frame(u32 node_index, u32 bi)
{
  vlib_main_t *vm = vlib_get_main();
  vlib_frame_t *f;
  u32 *to_next;
  f = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, f);
}

static int
send_hanat_protocol_request(vlib_main_t *vm, u32 vni, vlib_buffer_t *org_b,
			    hanat_pool_entry_t *pe, hanat_session_t *session, u32 mode,
			    ip4_address_t gre)
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
  len = sizeof(ip4_header_t);

  udp_header_t *udp = (udp_header_t *) (ip + 1);
  udp->src_port = htons(hm->udp_port);
  udp->dst_port = htons(pe->udp_port);
  len += sizeof (udp_header_t);

  hanat_header_t *hanat = (hanat_header_t *) (udp + 1);
  hanat->core_id = vlib_get_thread_index();
  len += sizeof (hanat_header_t);

  hanat_option_session_request_t *req = (hanat_option_session_request_t *) (hanat + 1);
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
  req->desc.vni = htonl(vni) >> 8;
  req->desc.in2out = mode == (HANAT_WORKER_IF_INSIDE || HANAT_WORKER_IF_DUAL) ? true : false;
  if (gre.as_u32)
    memcpy(req->opaque_data, &gre.as_u32, 4);
  len += session_request_len;

  ip->length = htons(len);
  ip->checksum = ip4_header_checksum (ip);
  udp->length = htons (len - sizeof(ip4_header_t));

  b->current_length = len;

  /* Add to frame */
  give_to_frame(hm->ip4_lookup_node_index, bi);
      
  return 0;
}

static inline uword
hanat_worker_slow_inline (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame, bool tunnel)
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
	  u32 next0, sw_if_index0, vni0;
	  ip4_header_t *ip0;
	  ip4_address_t gre0 = {0};

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];

	  from += 1;
	  n_left_from -= 1;

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

	  hanat_session_t *s = hanat_worker_cache_add_incomplete(&hm->db, vni0, ip0, bi0, tunnel);
	  send_hanat_protocol_request(vm, vni0, b0, pe, s, mode0, gre0);
	  if (tunnel) { /* Reset buffer to be able to play it back to hanat_gre4_input */
	    int header_len = sizeof(ip4_header_t) + sizeof(gre_header_t) + sizeof(u32);
	    vlib_buffer_advance(b0, -header_len);
	  }
	  vlib_node_increment_counter (vm, node->node_index, HANAT_WORKER_SLOW_MAPPER_REQUEST, 1);
	  continue;

	  /* Fall through to failure */
	drop0:
	  clib_warning("OLE DROPPING!!!!");
	  b0->error = node->errors[HANAT_WORKER_SLOW_NO_MAPPER];
	  next0 = HANAT_WORKER_SLOW_NEXT_DROP;
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
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  //send_protocol_requests();
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

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

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
	    error0 = 0; //DNS46_REQUEST_ERROR_IP_OPTIONS;
	    goto done0;
	  }

	  typedef struct {
	    u8 t;
	    u8 l;
	  } tl_t;

	  tl_t *tl = (tl_t *)(h0 + 1);

	  switch(tl->t) {
	  case HANAT_SESSION_BINDING:
	    {
	      hanat_option_session_binding_t *sp = (hanat_option_session_binding_t *)(h0 + 1);

	      /*
	       * Lookup based on session-id
	       * Add data to pool
	       * Ship cached packet
	       */
	      hanat_session_t *s = pool_elt_at_index(hm->db.sessions, ntohl(sp->session_id));
	      if (!s) {
		clib_warning("Could not find session %d", ntohl(sp->session_id));
		goto done0;
	      }
	      ip4_address_t gre = {0};
	      if (tl->l == sizeof(hanat_option_session_binding_t) + 4)
		memcpy(&gre, sp->opaque_data, 4);
		
	      hanat_worker_cache_update(s, ntohl(sp->instructions), ntohl(sp->fib_index),
					&sp->sa, &sp->da, sp->sp, sp->dp, gre);

	      vlib_node_increment_counter (vm, node->node_index, HANAT_PROTOCOL_INPUT_MAPPER_BINDING, 1);

	      /* Put cached packet back to fast worker node */
	      if (s->entry.buffer) {
		vlib_node_increment_counter (vm, node->node_index, HANAT_PROTOCOL_INPUT_HELD_PACKET, 1);
		if (s->entry.tunnel)
		  give_to_frame(hm->hanat_gre4_input_node_index, s->entry.buffer);
		else
		  give_to_frame(hm->hanat_worker_node_index, s->entry.buffer);
		s->entry.buffer = 0;
	      }
	    }
	    break;
	  case HANAT_SESSION_DECLINE:
	    break;
	  default:
	    // increase error counter
	    // move tl
	    break;
	  }

	done0:
	  b0->error = node->errors[error0];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
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
