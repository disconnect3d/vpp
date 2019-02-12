/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#ifndef __included_hanat_mapper_db_h__
#define __included_hanat_mapper_db_h__

#include <vnet/ip/ip.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/dlist.h>

typedef struct
{
  ip4_address_t in_addr;
  u16 in_port;
  ip4_address_t out_addr;
  u16 out_port;
  u32 pool_id;
  u32 tenant_id;
  u32 nsessions;
  u8 proto;
  u8 is_static;
} hanat_mapper_mapping_t;

typedef struct
{
  ip4_address_t in_r_addr;
  u16 in_r_port;
  ip4_address_t out_r_addr;
  u16 out_r_port;
  u32 mapping_index;
  u8 proto;
  u32 user_index;
  u32 per_user_index;
  u32 per_user_list_head_index;
  u32 flags;
  f64 expire;
  u64 total_bytes;
  u64 total_pkts;
  u8 *opaque_data;
} hanat_mapper_session_t;

typedef struct
{
  ip4_address_t addr;
  u32 tenant_id;
  u32 sessions_per_user_list_head_index;
  u32 nsessions;
} hanat_mapper_user_t;

typedef struct
{
  clib_bihash_8_8_t user_hash;
  hanat_mapper_user_t *users;
  u32 max_translations_per_user;
  dlist_elt_t *list_pool;
  clib_bihash_8_8_t mapping_in2out;
  clib_bihash_8_8_t mapping_out2in;
  hanat_mapper_mapping_t *mappings;
  clib_bihash_16_8_t session_in2out;
  clib_bihash_16_8_t session_out2in;
  hanat_mapper_session_t *sessions;
  vlib_simple_counter_main_t total_users;
  vlib_simple_counter_main_t total_mappings;
  vlib_simple_counter_main_t total_sessions;
  vlib_simple_counter_main_t timeouted_sessions_deleted;
} hanat_mapper_db_t;

int hanat_mapper_db_init (hanat_mapper_db_t * hanat_mapper_db,
			  u32 max_translations_per_user);

hanat_mapper_mapping_t *hanat_mapper_mapping_get (hanat_mapper_db_t *
						  hanat_mapper_db,
						  ip4_address_t * addr,
						  u16 port, u8 proto,
						  u32 tenant_id,
						  u8 is_in2out);

hanat_mapper_mapping_t *hanat_mapper_mapping_create (hanat_mapper_db_t *
						     hanat_mapper_db,
						     ip4_address_t * in_addr,
						     u16 in_port,
						     ip4_address_t * out_addr,
						     u16 out_port, u8 proto,
						     u32 pool_id,
						     u32 tenant_id,
						     u8 is_static);

void hanat_mapper_mapping_free (hanat_mapper_db_t * hanat_mapper_db,
				hanat_mapper_mapping_t * mapping,
				u8 flush_static);

hanat_mapper_user_t *hanat_mapper_user_get (hanat_mapper_db_t *
					    hanat_mapper_db,
					    ip4_address_t * addr,
					    u32 tenant_id);

hanat_mapper_user_t *hanat_mapper_user_create (hanat_mapper_db_t *
					       hanat_mapper_db,
					       ip4_address_t * addr,
					       u32 tenant_id);

hanat_mapper_session_t *hanat_mapper_session_get (hanat_mapper_db_t *
						  hanat_mapper_db,
						  ip4_address_t * l_addr,
						  u16 l_port,
						  ip4_address_t * r_addr,
						  u16 r_port, u8 proto,
						  u32 tenant_id,
						  u8 is_in2out);

void hanat_mapper_session_free (hanat_mapper_db_t * hanat_mapper_db,
				hanat_mapper_session_t * session);

hanat_mapper_session_t *hanat_mapper_session_create (hanat_mapper_db_t *
						     hanat_mapper_db,
						     hanat_mapper_mapping_t *
						     mapping,
						     ip4_address_t *
						     in_r_addr, u16 in_r_port,
						     ip4_address_t *
						     out_r_addr,
						     u16 out_r_port,
						     hanat_mapper_user_t *
						     user, f64 now,
						     u8 * opaque_data,
						     u8 opaque_data_len);

typedef int (*hanat_mapper_session_walk_fn_t) (hanat_mapper_session_t *
					       session,
					       hanat_mapper_mapping_t *
					       mapping, void *ctx);
void hanat_mapper_session_walk (hanat_mapper_db_t * db,
				hanat_mapper_session_walk_fn_t fn, void *ctx);

void hanat_mapper_free_ext_addr_pool (hanat_mapper_db_t * db, u32 pool_id);

#endif /* __included_hanat_mapper_db_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
