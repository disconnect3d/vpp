/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_hanat_worker_db_h
#define included_hanat_worker_db_h

#include <stdbool.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include "../protocol/hanat_protocol.h"

#define HANAT_CACHE_EXPIRY_TIMER	100 /* Seconds */
#define HANAT_CACHE_REFRESH_INTERVAL	 10 /* Seconds */

typedef unsigned int u32;

/* Move to vnet/ip? */
typedef struct {
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;


/* NAT 6-tuple key. 16 octets */
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
} hanat_session_key_t;


/* TODO:
 * Different type of session state caches
 * - Everything in value. 8 octets. instruction, address to translate to
 * - Separate session pool
 */

typedef struct {
  u32 vni;
  ip4_address_t src;
} hanat_gre_data_t;

typedef enum {
  HANAT_SESSION_FLAG_INCOMPLETE = 0x1,
  HANAT_SESSION_FLAG_TUNNEL     = 0x2,
} hanat_session_entry_flags_t;

/* Session cache entries */
typedef struct {
  /* What to translate to */
  hanat_instructions_t instructions;
  u32 fib_index;
  /* Stored in network byte order */
  ip4_address_t post_sa;
  ip4_address_t post_da;
  u16 post_sp;
  u16 post_dp;
  ip_csum_t checksum;
  ip_csum_t l4_checksum;
  u16 tcp_mss;
  u32 buffer;
  f64 last_heard;
  f64 last_refreshed;
  ip4_address_t gre;
  hanat_session_entry_flags_t flags;
} hanat_session_entry_t;

typedef struct {
  hanat_session_key_t key;
  hanat_session_entry_t entry;
  u32 mapper_id;
} hanat_session_t;

typedef struct {
  hanat_session_t *sessions;
  clib_bihash_16_8_t cache;	/* Session index */
} hanat_db_t;

typedef struct
{
  u32 sw_if_index;
  vl_api_hanat_worker_if_mode_t mode;
} hanat_interface_t;

typedef struct
{
  u32 fib_index;
  u32 pool_id;
  ip4_address_t prefix;
  u8 prefix_len;
  ip46_address_t src;
  ip46_address_t mapper;
  u16 udp_port;
} hanat_pool_entry_t;

typedef struct
{
  hanat_pool_entry_t *pools;

  /* Vector of stable hash buckets */
  u32 *lb_buckets;
  u32 n_buckets;

  /* LPM */
  BVT (clib_bihash) bihash;
  uword *prefix_lengths_bitmap;
  u32 prefix_length_refcount[65];
} hanat_pool_t;

typedef struct {
  ip4_header_t ip;
  udp_header_t udp;
  hanat_header_t hanat;
}  __attribute__((packed))hanat_ip_udp_hanat_header_t;

typedef struct {
  hanat_db_t db;
  hanat_pool_t pool_db;
  u16 udp_port;

  /* error node index */
  u32 error_node_index;

  /* Interface pool */
  hanat_interface_t *interfaces;
  u32 *interface_by_sw_if_index;

  u32 ip4_lookup_node_index;
  u32 hanat_worker_node_index;
  u32 hanat_gre4_input_node_index;

  /* API message ID base */
  u16 msg_id_base;

  void *gre_template;

  u32 cache_expiry_timer;	/* In seconds */
  u32 cache_refresh_interval;	/* In seconds */

  vlib_packet_template_t hanat_protocol_template;

} hanat_worker_main_t;

extern hanat_worker_main_t hanat_worker_main;

void hanat_db_init (hanat_db_t * db, u32 buckets, u32 memory_size);
void hanat_db_free (hanat_db_t * db);
hanat_session_t *hanat_session_add (hanat_db_t *db, hanat_session_key_t *key, hanat_session_entry_t *e);
void hanat_session_delete (hanat_db_t *db, hanat_session_key_t *key);
hanat_session_t *hanat_session_find (hanat_db_t *db, hanat_session_key_t *key);
hanat_session_t *hanat_session_find_ip (hanat_db_t *db, u32 fib_index, ip4_header_t *ip);

int hanat_worker_interface_add_del (u32 sw_if_index, bool is_add, vl_api_hanat_worker_if_mode_t mode);
clib_error_t *hanat_worker_api_init (vlib_main_t * vm, hanat_worker_main_t *hm);
int hanat_worker_cache_add (hanat_session_key_t *key, hanat_session_entry_t *entry);
int hanat_worker_cache_clear(void);
void hanat_key_from_ip (u32 fib_index, ip4_header_t *ip, hanat_session_key_t *key);
int l3_checksum_delta(hanat_instructions_t instructions,
		      ip4_address_t pre_sa, ip4_address_t post_sa,
		      ip4_address_t pre_da, ip4_address_t post_da);
int l4_checksum_delta (hanat_instructions_t instructions, ip_csum_t c,
		       u16 pre_sp, u16 post_sp, u16 pre_dp, u16 post_dp);

int hanat_worker_mapper_add_del(bool is_add, u32 pool_id, u32 fib_index, ip4_address_t *prefix, u8 prefix_len,
				ip46_address_t *src, ip46_address_t *mapper, u16 udp_port, u32 *mapper_index);
int hanat_worker_mapper_buckets(u32 n, u32 mapper_index[]);
int hanat_worker_enable(u16 udp_port, ip4_address_t *gre_src, u32 cache_expiry_timer, u32 cache_refresh_interval);
void hanat_mapper_table_init(hanat_pool_t *db);
void hanat_lpm_64_add (hanat_pool_t *lpm, u32 fib_index, u32 address, u8 pfxlen, u32 value);
void hanat_lpm_64_delete (hanat_pool_t *lpm, u32 fib_index, u32 address, u8 pfxlen);
u32 hanat_lpm_64_lookup (hanat_pool_t *lpm, u32 fib_index, u32 address);

u32 hanat_get_interface_mode(u32 sw_if_index);
int hanat_session_stale_cb(clib_bihash_kv_16_8_t *kv, void *arg);

static inline void
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

static inline void
hanat_send_to_node(vlib_main_t *vm, u32 *pi_vector,
		   vlib_node_runtime_t *node, /* vlib_error_t *error, */
		   u32 next)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = pi_vector;
  n_left_from = vec_len(pi_vector);
  next_index = node->cached_next_index;
  while (n_left_from > 0) {
    vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
    while (n_left_from > 0 && n_left_to_next > 0) {
      u32 pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;
      //vlib_buffer_t *p0 = vlib_get_buffer(vm, pi0);
      //p0->error = *error;
      vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next, n_left_to_next, pi0, next);
    }
    vlib_put_next_frame(vm, node, next_index, n_left_to_next);
  }
}


#endif
