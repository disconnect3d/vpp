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
                { \
                  clib_warning ("port %d already in use addr %U pool-id %d", \
                                port_host_byte_order, format_ip4_address, addr, pool_id); \
                  return VNET_API_ERROR_INSTANCE_IN_USE; \
                } \
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

  clib_warning ("addr %U in pool-id %d not found", format_ip4_address, addr,
		pool_id);

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
  vlib_thread_main_t *tm = vlib_get_thread_main ();
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

  nm->mss_value = 0;

  nm->vlib_main = vm;
  nm->vnet_main = vnet_get_main ();
  nm->api_main = &api_main;

  hanat_mapper_db_init (&nm->db, 100);
  hanat_state_sync_init (vm);

  vec_validate_aligned (nm->request_buffers, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

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
  clib_warning ("mapper listening on port %d for HANAT proto", port);

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
	{
	  clib_warning ("add: pool-id %d already exists", pool_id);
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      pool_get (nm->ext_addr_pool, pool);
      pool->pool_id = pool_id;
      pool->failover_index = ~0;
      hash_set (nm->pool_index_by_pool_id, pool_id, pool - nm->ext_addr_pool);
      start_addr.as_u32 = prefix->as_u32;
      ip4_address_normalize (&start_addr, prefix_len);
      pool->prefix.as_u32 = start_addr.as_u32;
      pool->prefix_len = prefix_len;
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
	{
	  clib_warning ("del: pool-id %d not found", pool_id);
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

      vec_foreach (address, pool->addresses)
      {
	hanat_mapper_free_ext_addr_pool (&nm->db, pool_id);
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
    {
      clib_warning ("pool-id %d not found", pool_id);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  pool->failover_index = failover_index;
  clib_warning ("pool-id %d failover-index %d", pool_id, failover_index);

  return 0;
}

typedef struct
{
  u32 pool_id;
  u32 thread_index;
} session_resync_walk_ctx_t;

static int
session_resync_walk (hanat_mapper_session_t * session,
		     hanat_mapper_mapping_t * mapping, void *arg)
{
  session_resync_walk_ctx_t *ctx = arg;
  hanat_state_sync_event_t event;

  if (mapping->pool_id == ctx->pool_id)
    {
      clib_memset (&event, 0, sizeof (event));
      event.event_type = HANAT_STATE_SYNC_ADD;
      event.in_l_addr = mapping->in_addr.as_u32;
      event.in_r_addr = session->in_r_addr.as_u32;
      event.in_l_port = mapping->in_port;
      event.in_r_port = session->in_r_port;
      event.out_l_addr = mapping->out_addr.as_u32;
      event.out_r_addr = session->out_r_addr.as_u32;
      event.out_l_port = mapping->out_port;
      event.out_r_port = session->out_r_port;
      event.tenant_id = clib_host_to_net_u32 (mapping->tenant_id);
      event.pool_id = clib_host_to_net_u32 (mapping->pool_id);
      event.protocol = mapping->proto;
      event.opaque_len = (u8) vec_len (session->opaque_data);
      hanat_state_sync_event_add (&event, session->opaque_data, 0, 0,
				  ctx->thread_index);
    }

  return 0;
}

int
hanat_mapper_pool_resync (u32 pool_id, u32 client_index, u32 pid,
			  hanat_mapper_pool_resync_event_cb_t event_callback)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_addr_pool_t *pool;
  int rv;

  clib_warning ("resync pool-id %d", pool_id);
  pool = get_pool_by_pool_id (pool_id);
  if (!pool)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (pool->failover_index == ~0)
    return VNET_API_ERROR_UNKNOWN_DESTINATION;
  rv =
    hanat_state_sync_resync_init (pool->failover_index, client_index, pid,
				  event_callback);
  if (rv)
    return rv;

  session_resync_walk_ctx_t ctx = {
    .pool_id = pool_id,
    .thread_index = 0,
  };
  hanat_mapper_session_walk (&nm->db, session_resync_walk, &ctx);
  hanat_state_sync_event_add (0, 0, 1, 0, 0);
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
	{
	  clib_warning ("add: mapping already exists");
	  return VNET_API_ERROR_VALUE_EXIST;
	}

      rv =
	hanat_mapper_set_out_addr_and_port (pool_id, protocol, external_addr,
					    external_port);
      if (rv)
	return rv;

      mapping =
	hanat_mapper_mapping_create (&nm->db, local_addr, local_port,
				     external_addr, external_port, protocol,
				     pool_id, tenant_id, 1);
      if (!mapping)
	return VNET_API_ERROR_UNSPECIFIED;
    }
  else
    {
      if (!mapping)
	{
	  clib_warning ("del: mapping not found");
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

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
