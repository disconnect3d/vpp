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

#include <stdbool.h>
#include <arpa/inet.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/pool.h>
#include "hanat_worker_db.h"

hanat_worker_main_t hanat_worker_main;

static clib_error_t *
hanat_worker_init (vlib_main_t * vm)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vlib_node_t *ip4_lookup_node;
  clib_memset (hm, 0, sizeof (*hm));
  hanat_db_init(&hm->db, 1024, 2000000);

  ip4_lookup_node = vlib_get_node_by_name (vm, (u8 *) "ip4-lookup");
  hm->ip4_lookup_node_index = ip4_lookup_node->index;

  hanat_mapper_table_init(&hm->pool_db);
  hm->pool_db.n_buckets = 1024;

  hanat_worker_slow_init(vm);

  /* Init API */
  return hanat_worker_api_init(vm, hm);
}

int
hanat_worker_interface_add_del (u32 sw_if_index, bool is_add, vl_api_hanat_worker_if_mode_t mode)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  hanat_interface_t *interface = 0, *i;

  /* *INDENT-OFF* */
  pool_foreach (i, hm->interfaces, ({
	if (i->sw_if_index == sw_if_index) {
	  interface = i;
	  break;
	}
      }));
  /* *INDENT-ON* */

  if (is_add) {
    if (interface)
      return VNET_API_ERROR_VALUE_EXIST;

    pool_get (hm->interfaces, interface);
    interface->sw_if_index = sw_if_index;
    interface->mode = mode;
    u32 index = interface - hm->interfaces;
    vec_validate(hm->interface_by_sw_if_index, index);
    hm->interface_by_sw_if_index[sw_if_index] = index;
  } else {
    if (!interface)
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    pool_put (hm->interfaces, interface);
    hm->interface_by_sw_if_index[sw_if_index] = ~0;
  }

  return vnet_feature_enable_disable ("ip4-unicast", "hanat-worker",
				      sw_if_index, is_add, 0, 0);
}

int
hanat_worker_cache_add (hanat_session_key_t *key, hanat_session_entry_t *entry)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  ip_csum_t c = 0;

  /*
   * Checksum delta
   */
  if (entry->instructions & HANAT_INSTR_SOURCE_ADDRESS) {
    c = ip_csum_add_even(c, entry->post_sa.as_u32);
    c = ip_csum_sub_even(c, key->sa.as_u32);
  }
  if (entry->instructions & HANAT_INSTR_DESTINATION_ADDRESS) {
    c = ip_csum_sub_even(c, key->sa.as_u32);
    c = ip_csum_add_even(c, entry->post_sa.as_u32);
  }
  ip_csum_t l4_c = c;
  if (entry->instructions & HANAT_INSTR_SOURCE_PORT) {
    l4_c = ip_csum_add_even(l4_c, entry->post_sp);
    l4_c = ip_csum_sub_even(l4_c, key->sp);
  }
  if (entry->instructions & HANAT_INSTR_DESTINATION_PORT) {
    l4_c = ip_csum_add_even(l4_c, entry->post_dp);
    l4_c = ip_csum_sub_even(l4_c, key->dp);
  }
  entry->checksum = c;
  entry->l4_checksum = l4_c;

  hanat_session_t *s = hanat_session_add(&hm->db, key, entry);
  if (!s)
    return -1;
  return 0;
}

int
hanat_worker_mapper_add_del(bool is_add, u32 pool_id, ip4_address_t *prefix, u8 prefix_len,
			    ip46_address_t *mapper, ip46_address_t *src, u16 udp_port, u32 *mapper_index)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  hanat_pool_key_t key = { .as_u32[0] = pool_id,
			   .as_u32[1] = prefix->as_u32 };
  hanat_pool_entry_t *poolentry;
  u32 mi = hanat_lpm_64_lookup (&hm->pool_db, &key, prefix_len);

  if (is_add) {
    pool_get_zero (hm->pool_db.pools, poolentry);
    *mapper_index = poolentry - hm->pool_db.pools;

    poolentry->pool_id = pool_id;
    poolentry->prefix = *prefix;
    poolentry->prefix_len = prefix_len;
    poolentry->src = *src;
    poolentry->mapper = *mapper;
    poolentry->udp_port = udp_port;

    /* Add prefix to LPM for outside to in traffix */
    hanat_lpm_64_add(&hm->pool_db, &key, prefix_len, *mapper_index);
  } else {
    hanat_lpm_64_delete(&hm->pool_db, &key, prefix_len);
    pool_put_index(hm->pool_db.pools, mi);
  }
  return 0;
}

/*
 * Vector of VRFs of pointers to bucket vector
 */
int
hanat_worker_mapper_buckets(u32 fib_index, u32 n, u32 mapper_index[])
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  int i;
  u32 *b = 0;
  /* Replace stable hash */
  if (hm->pool_db.lb_buckets && vec_len(hm->pool_db.lb_buckets) >= fib_index &&
      hm->pool_db.lb_buckets[fib_index]) {
    vec_free(hm->pool_db.lb_buckets[fib_index]);
  }
  vec_validate_init_empty (hm->pool_db.lb_buckets, fib_index, 0);
  vec_validate(b, n);

  for (i = 0; i < n; i++) {
    b[i] = ntohl(mapper_index[i]);
  }

  hm->pool_db.lb_buckets[fib_index] = b;

  return 0;
}

VLIB_INIT_FUNCTION (hanat_worker_init);
