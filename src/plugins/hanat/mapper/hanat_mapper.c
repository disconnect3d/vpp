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

#include "hanat_mapper.h"
#include "hanat_state_sync.h"
#include <vnet/udp/udp.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

hanat_mapper_main_t hanat_mapper_main;

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "HA NAT mapper",
};
/* *INDENT-ON* */

static_always_inline u16
random_port (u16 min, u16 max)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;

  return min +
    random_u32 (&nm->random_seed) / (random_u32_max () / (max - min + 1) + 1);
}

static int
hanat_mapper_alloc_out_addr_and_port_default (u32 pool_id,
					      hanat_mapper_protocol_t proto,
					      ip4_address_t * addr,
					      u16 * port)
{
  hanat_mapper_addr_pool_t *pool;
  hanat_mapper_address_t *address;
  u16 port_num;
  int i;

  pool = get_pool_by_pool_id (pool_id);
  if (!pool)
    {
      clib_warning ("pool_id %d not found", pool_id);
      return 1;
    }

  for (i = 0; i < vec_len (pool->addresses); i++)
    {
      address = pool->addresses + i;

      switch (proto)
	{
#define _(N, id, n, s) \
        case HANAT_MAPPER_PROTOCOL_##N: \
          if (address->busy_##n##_ports < (65535 - 1024)) \
            { \
              while (1) \
                { \
                  port_num = random_port (1024, 65535); \
                  if (clib_bitmap_get_no_check (address->busy_##n##_port_bitmap, port_num)) \
                    continue; \
                  clib_bitmap_set_no_check (address->busy_##n##_port_bitmap, port_num, 1); \
                  address->busy_##n##_ports++; \
                  *port = clib_host_to_net_u16(port_num); \
                  addr->as_u32 = address->addr.as_u32; \
                  return 0; \
                } \
            } \
          break;
	  foreach_hanat_mapper_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return 1;
	}
    }

  clib_warning ("addresses exhausted pool-id %d", pool_id);
  return 1;
}

int
hanat_mapper_set_out_addr_and_port (u32 pool_id,
				    hanat_mapper_protocol_t proto,
				    ip4_address_t * addr, u16 port)
{
  hanat_mapper_addr_pool_t *pool;
  hanat_mapper_address_t *address;
  int i;
  u16 port_host_byte_order = clib_net_to_host_u16 (port);

  pool = get_pool_by_pool_id (pool_id);
  if (!pool)
    {
      clib_warning ("pool_id %d not found", pool_id);
      return VNET_API_ERROR_UNSPECIFIED;
    }

  for (i = 0; i < vec_len (pool->addresses); i++)
    {
      address = pool->addresses + i;
      if (addr->as_u32 != address->addr.as_u32)
	continue;

      switch (proto)
	{
#define _(N, id, n, s) \
            case HANAT_MAPPER_PROTOCOL_##N: \
              if (clib_bitmap_get_no_check (address->busy_##n##_port_bitmap, port_host_byte_order)) \
                return VNET_API_ERROR_INSTANCE_IN_USE; \
              clib_bitmap_set_no_check (address->busy_##n##_port_bitmap, port_host_byte_order, 1); \
              if (port_host_byte_order > 1024) \
                address->busy_##n##_ports++; \
              return 0;
	  foreach_hanat_mapper_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return VNET_API_ERROR_INVALID_VALUE;
	}
    }

  return 1;
}

void
hanat_mapper_free_out_addr_and_port (u32 pool_id,
				     hanat_mapper_protocol_t proto,
				     ip4_address_t * addr, u16 port)
{
  hanat_mapper_addr_pool_t *pool;
  hanat_mapper_address_t *address;
  u16 port_host_byte_order = clib_net_to_host_u16 (port);
  int i;

  pool = get_pool_by_pool_id (pool_id);
  if (!pool)
    {
      clib_warning ("pool_id %d not found", pool_id);
      return;
    }

  for (i = 0; i < vec_len (pool->addresses); i++)
    {
      address = pool->addresses + i;
      if (addr->as_u32 != address->addr.as_u32)
	continue;

      switch (proto)
	{
#define _(N, id, n, s) \
        case HANAT_MAPPER_PROTOCOL_##N: \
          ASSERT (clib_bitmap_get_no_check (address->busy_##n##_port_bitmap, \
            port_host_byte_order) == 1); \
          clib_bitmap_set_no_check (address->busy_##n##_port_bitmap, \
            port_host_byte_order, 0); \
          address->busy_##n##_ports--; \
          break;
	  foreach_hanat_mapper_protocol
#undef _
	default:
	  clib_warning ("unknown protocol");
	  return;
	}
    }
}

static clib_error_t *
hanat_mapper_init (vlib_main_t * vm)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  clib_error_t *error = 0;

  nm->port = 0;
  nm->udp_timeout = HANAT_MAPPER_UDP_TIMEOUT;
  nm->tcp_established_timeout = HANAT_MAPPER_TCP_ESTABLISHED_TIMEOUT;
  nm->tcp_transitory_timeout = HANAT_MAPPER_TCP_TRANSITORY_TIMEOUT;
  nm->icmp_timeout = HANAT_MAPPER_ICMP_TIMEOUT;
  nm->pool_index_by_pool_id = hash_create (0, sizeof (uword));
  nm->alloc_addr_and_port = hanat_mapper_alloc_out_addr_and_port_default;
  nm->random_seed = random_default_seed ();

  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main ();
  nm->api_main = &api_main;

  hanat_mapper_db_init (&nm->db, 100);
  hanat_state_sync_init (vm);

  error = hanat_mapper_api_init (vm, nm);

  return error;
}

VLIB_INIT_FUNCTION (hanat_mapper_init);

int
hanat_mapper_enable (u16 port)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;

  nm->port = port;
  udp_register_dst_port (nm->vlib_main, port, hanat_mapper_node.index, 1);

  return 0;
}

static inline void
increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = clib_net_to_host_u32 (a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32 (v);
}

int
hanat_mapper_add_del_ext_addr_pool (ip4_address_t * prefix, u8 prefix_len,
				    u32 pool_id, u8 is_add)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_addr_pool_t *pool;
  hanat_mapper_address_t *address;
  ip4_address_t start_addr, end_addr, this_addr;
  int i, count;

  pool = get_pool_by_pool_id (pool_id);

  if (is_add)
    {
      if (pool)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (nm->ext_addr_pool, pool);
      pool->pool_id = pool_id;
      pool->failover_index = ~0;
      hash_set (nm->pool_index_by_pool_id, pool_id, pool - nm->ext_addr_pool);
      start_addr.as_u32 = prefix->as_u32;
      ip4_address_normalize (&start_addr, prefix_len);
      ip4_prefix_max_address_host_order (&start_addr, prefix_len, &end_addr);
      count =
	(end_addr.as_u32 - clib_net_to_host_u32 (start_addr.as_u32)) + 1;
      this_addr = start_addr;
      for (i = 0; i < count; i++)
	{
	  vec_add2 (pool->addresses, address, 1);
	  address->addr.as_u32 = this_addr.as_u32;
	  increment_v4_address (&this_addr);
#define _(N, id, n, s) \
      clib_bitmap_alloc (address->busy_##n##_port_bitmap, 65535); \
      address->busy_##n##_ports = 0;
	  foreach_hanat_mapper_protocol
#undef _
	}
    }
  else
    {
      if (!pool)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      vec_foreach (address, pool->addresses)
      {
	//TODO: delete sessions using address
#define _(N, id, n, s) \
      clib_bitmap_free (address->busy_##n##_port_bitmap);
	foreach_hanat_mapper_protocol
#undef _
      }

      vec_free (pool->addresses);
      hash_unset (nm->pool_index_by_pool_id, pool->pool_id);
      pool_put (nm->ext_addr_pool, pool);
    }

  return 0;
}

int
hanat_mapper_set_pool_failover (u32 pool_id, u32 failover_index)
{
  hanat_mapper_addr_pool_t *pool;

  pool = get_pool_by_pool_id (pool_id);
  if (!pool)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool->failover_index = failover_index;

  return 0;
}

int
hanat_mapper_add_del_static_mapping (ip4_address_t * local_addr,
				     ip4_address_t * external_addr,
				     u16 local_port, u16 external_port,
				     u8 protocol, u32 tenant_id, u32 pool_id,
				     u8 is_add)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_mapping_t *mapping;
  int rv;

  mapping =
    hanat_mapper_mapping_get (&nm->db, local_addr, local_port, protocol,
			      tenant_id, 1);

  if (is_add)
    {
      if (mapping)
	return VNET_API_ERROR_VALUE_EXIST;

      rv =
	hanat_mapper_set_out_addr_and_port (pool_id, protocol, external_addr,
					    external_port);
      if (rv)
	return rv;

      mapping =
	hanat_mapper_mappig_create (&nm->db, local_addr, local_port,
				    external_addr, external_port, protocol,
				    pool_id, tenant_id, 1);
      if (!mapping)
	return VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      if (!mapping)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      hanat_mapper_mapping_free (&nm->db, mapping, 1);
    }

  return 0;
}

u8 *
format_hanat_mapper_protocol (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(N, j, n, str) case HANAT_MAPPER_PROTOCOL_##N: t = (u8 *) str; break;
      foreach_hanat_mapper_protocol
#undef _
    default:
      s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
