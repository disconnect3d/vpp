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

#include <hanat_mapper/hanat_mapper.h>
#include <hanat_mapper/hanat_state_sync.h>
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

void
increment_v4_address (ip4_address_t * a)
{
  u32 v;

  v = clib_net_to_host_u32 (a->as_u32) + 1;
  a->as_u32 = clib_host_to_net_u32 (v);
}

int
hanat_mapper_add_del_address (ip4_address_t * addr, u32 tenant_id, u8 is_add)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_address_t *address = 0, *a;

  /* *INDENT-OFF* */
  pool_foreach (a, nm->addresses,
  ({
    if (a->addr.as_u32 == addr->as_u32)
      {
        address = a;
        break;
      }
  }));
  /* *INDENT-ON* */

  if (is_add)
    {
      if (address)
	return VNET_API_ERROR_VALUE_EXIST;

      pool_get (nm->addresses, address);

      address->tenant_id = tenant_id;

#define _(N, id, n, s) \
      clib_bitmap_alloc (address->busy_##n##_port_bitmap, 65535); \
      address->busy_##n##_ports = 0;
      foreach_hanat_mapper_protocol
#undef _
    }
  else
    {
      if (!address)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      //TODO: delete sessions using address
#define _(N, id, n, s) \
      clib_bitmap_free (address->busy_##n##_port_bitmap);
      foreach_hanat_mapper_protocol
#undef _
	pool_put (nm->addresses, address);
    }

  return 0;
}

int
hanat_mapper_add_del_static_mapping (ip4_address_t * local_addr,
				     ip4_address_t * external_addr,
				     u16 local_port, u16 external_port,
				     u8 protocol, u32 tenant_id, u8 is_add)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_mapping_t *mapping;

  mapping =
    hanat_mapper_mapping_get (&nm->db, local_addr, local_port, protocol,
			      tenant_id, 1);

  if (is_add)
    {
      if (mapping)
	return VNET_API_ERROR_VALUE_EXIST;

      mapping =
	hanat_mapper_mappig_create (&nm->db, local_addr, local_port,
				    external_addr, external_port, protocol,
				    tenant_id, 1);
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
