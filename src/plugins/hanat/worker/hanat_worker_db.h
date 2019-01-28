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
#include <vppinfra/bihash_template.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include "../protocol/hanat_protocol.h"

typedef unsigned int u32;

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
  //  vlib_combined_counter_t counter;
  u32 *buffer_vec;
} hanat_session_entry_t;

typedef struct {
  hanat_session_key_t key; // USED?
  hanat_session_entry_t entry;
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

typedef struct {
  union {
    u32 as_u32[2];
    u64 as_u64;
  };
} hanat_pool_key_t;

typedef struct
{
  hanat_pool_entry_t *pools;

  /* Vector by VRF of stable hash buckets */
  u32 **lb_buckets;
  u32 n_buckets;

  /* LPM */
  BVT (clib_bihash) bihash;
  uword *prefix_lengths_bitmap;
  u32 prefix_length_refcount[65];
} hanat_pool_t;

typedef struct {
  hanat_db_t db;
  hanat_pool_t pool_db;
  u16 udp_port;

  /* Interface pool */
  hanat_interface_t *interfaces;
  u32 *interface_by_sw_if_index;

  u32 ip4_lookup_node_index;

  /* API message ID base */
  u16 msg_id_base;
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
hanat_session_t *hanat_worker_cache_add_incomplete(hanat_db_t *db, u32 fib_index, ip4_header_t *ip, u32 bi);
int hanat_worker_mapper_add_del(bool is_add, u32 pool_id, ip4_address_t *prefix, u8 prefix_len,
				ip46_address_t *mapper, ip46_address_t *src, u16 udp_port, u32 *mapper_index);
int hanat_worker_mapper_buckets(u32 fib_index, u32 n, u32 mapper_index[]);
int hanat_worker_enable(u16 udp_port);

void hanat_mapper_table_init(hanat_pool_t *db);
void hanat_lpm_64_add (hanat_pool_t *lpm, void *addr_v, u8 pfxlen, u32 value);
void hanat_lpm_64_delete (hanat_pool_t *lpm, void *addr_v, u8 pfxlen);
u32 hanat_lpm_64_lookup (hanat_pool_t *lpm, void *addr_v, u8 pfxlen);

#endif
