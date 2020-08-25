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

#ifndef included_flowrouter_h
#define included_flowrouter_h

#include <vnet/ip/ip4_packet.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/dlist.h>

#include <flowrouter/flowrouter.api_types.h>
typedef vl_api_flowrouter_instructions_t flowrouter_instructions_t;
typedef vl_api_flowrouter_arc_t flowrouter_arc_t;
typedef vl_api_flowrouter_cache_miss_behaviour_t flowrouter_cache_miss_behaviour_t;
typedef vl_api_flowrouter_params_t flowrouter_params_t;

#define FLOWROUTER_DEFAULT_MAX_SESSIONS	1 << 20 /* Default 1M sessions */

#define FLOWROUTER_DEFAULT_TIMEOUT		200
#define FLOWROUTER_DEFAULT_TIMEOUT_ICMP		10
#define FLOWROUTER_DEFAULT_TIMEOUT_UDP		200
#define FLOWROUTER_DEFAULT_TIMEOUT_TCP_TRANSITORY	10
#define FLOWROUTER_DEFAULT_TIMEOUT_TCP_ESTABLISHED	30

typedef enum
{
  FLOWROUTER_NEXT_DROP,
  FLOWROUTER_NEXT_ICMP_ERROR,
  FLOWROUTER_NEXT_FASTPATH,
  FLOWROUTER_NEXT_SLOWPATH,
  FLOWROUTER_N_NEXT
} flowrouter_next_t;

enum flowrouter_session_state {
  FLOWROUTER_STATE_UNKNOWN = 0,
  FLOWROUTER_STATE_TCP_SYN_SEEN,
  FLOWROUTER_STATE_TCP_SYN_SENT,
  FLOWROUTER_STATE_TCP_ESTABLISHED,
  FLOWROUTER_STATE_TCP_FIN_WAIT,
  FLOWROUTER_STATE_TCP_CLOSE_WAIT,
  FLOWROUTER_STATE_TCP_CLOSED,
  FLOWROUTER_STATE_TCP_LAST_ACK,
};

/* Connection 6-tuple key. 16 octets */
typedef struct {
  union {
    struct {
      ip4_address_t sa;
      ip4_address_t da;
      u32 proto:8, fib_index:24;
      u16 sp;
      u16 dp;
    };
    u64 as_u64[2];
  };
} __clib_packed flowrouter_key_t;
STATIC_ASSERT_SIZEOF (flowrouter_key_t, 16);

/* Session cache entries */
typedef struct {
  flowrouter_key_t k;

  /* What to translate to */
  flowrouter_instructions_t instructions;
  u32 fib_index;
  /* NAT */
  /* Stored in network byte order */
  ip4_address_t post_sa;
  ip4_address_t post_da;
  u16 post_sp;
  u16 post_dp;
  ip_csum_t checksum;
  ip_csum_t l4_checksum;
  u16 tcp_mss;

  /* Writeable by fast-path */
  enum flowrouter_session_state state;
  //  vlib_combined_counter_t counter;

  u32 timer;
  f64 last_heard;
  u32 lru_head_index;
  u32 lru_index;
  f64 last_lru_update;
} flowrouter_session_t;

typedef enum
{
 FLOWROUTER_COUNTER_HANDOFF_SLOWPATH = 0,
 FLOWROUTER_COUNTER_HANDOFF_FP,
 FLOWROUTER_COUNTER_HANDOFF_DIFFERENT_WORKER_FP,
 FLOWROUTER_COUNTER_FASTPATH_FORWARDED,
 FLOWROUTER_COUNTER_SLOWPATH_FREED_ALREADY,
 FLOWROUTER_COUNTER_SLOWPATH_DELETED,
 FLOWROUTER_COUNTER_SLOWPATH_PORT_ALLOC_CONFLICT,
 FLOWROUTER_COUNTER_SLOWPATH_CREATED,
 FLOWROUTER_COUNTER_SLOWPATH_EXPIRE_VECTOR_MAX,
 FLOWROUTER_N_COUNTER
} flowrouter_counter_type_t;

#define foreach_flowrouter_counter_name					\
  _(HANDOFF_SLOWPATH, slowpath, flowrouter/handoff)				\
  _(HANDOFF_FP, fastpath, flowrouter/handoff)		\
  _(HANDOFF_DIFFERENT_WORKER_FP, different_worker_fp, flowrouter/handoff)     \
  _(FASTPATH_FORWARDED, forwarded, flowrouter/fastpath)			\
  _(SLOWPATH_FREED_ALREADY, freedalready, flowrouter/slowpath)		\
  _(SLOWPATH_DELETED, deleted, flowrouter/slowpath)                           \
  _(SLOWPATH_PORT_ALLOC_CONFLICT, portallocconflict, flowrouter/slowpath)     \
  _(SLOWPATH_CREATED, created, flowrouter/slowpath)                           \
  _(SLOWPATH_EXPIRE_VECTOR_MAX, expire_vector_max, flowrouter/slowpath)

#define foreach_flowrouter_timers			\
  _(icmp)					\
  _(udp)					\
  _(tcp_transitory)				\
  _(tcp_established)				\
  _(default)

typedef struct {
  u32 sw_if_index;
  flowrouter_arc_t arc;
  flowrouter_cache_miss_behaviour_t cache_miss;
} flowrouter_interface_t;

typedef struct {
  bool enabled;
  u32 no_threads;
  u32 *pool_per_thread;
  clib_bihash_16_8_t flowhash;	/* Bi-directional */

  /* Interface pool */
  flowrouter_interface_t *interfaces;
  u32 *interface_by_sw_if_index;

  //u32 fast_path_node_index;

  u32 max_sessions;

  /* Configuration */
  //char *handoff_node;

  /* per-thread data */
  flowrouter_session_t **sessions_per_worker;

  /* LRU session lists - head is stale, tail is fresh */
  dlist_elt_t **lru_pool;

#define _(n) \
  u32 *lru_head_index_##n; \
  u32 n##_timeout;
  foreach_flowrouter_timers
#undef _

  /* Counters */
  clib_spinlock_t counter_lock;
  vlib_simple_counter_main_t *counters;

  /* Configuration store indicies */
  //  u32 interfaces_index;
  //u32 parameters_index;

  u16 msg_id_base;

} flowrouter_main_t;
extern flowrouter_main_t flowrouter_main;

//void flowrouter_register_interface (u32 sw_if_index, u32 node_index, bool in2out);
u8 *format_flowrouter_state (u8 *s, va_list * args);
u8 *format_flowrouter_fp_session (u8 * s, va_list * args);
u8 *format_flowrouter_session (u8 * s, va_list * args);
u8 *format_flowrouter_key (u8 * s, va_list * args);
//clib_error_t *flowrouter_enable (vlib_main_t *vm);
void flowrouter_reset_tables (void);
flowrouter_interface_t *flowrouter_interface_by_sw_if_index (u32 sw_if_index);

#endif
