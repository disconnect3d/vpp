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

#ifndef __included_hanat_mapper_h__
#define __included_hanat_mapper_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include "hanat_mapper_db.h"

/* default session timeouts */
#define HANAT_MAPPER_UDP_TIMEOUT 300
#define HANAT_MAPPER_TCP_TRANSITORY_TIMEOUT 240
#define HANAT_MAPPER_TCP_ESTABLISHED_TIMEOUT 7440
#define HANAT_MAPPER_ICMP_TIMEOUT 60

/* supported L4 protocols */
#define foreach_hanat_mapper_protocol \
  _(UDP, 0, udp, "udp")               \
  _(TCP, 1, tcp, "tcp")               \
  _(ICMP, 2, icmp, "icmp")

typedef enum
{
#define _(N, i, n, s) HANAT_MAPPER_PROTOCOL_##N = i,
  foreach_hanat_mapper_protocol
#undef _
} hanat_mapper_protocol_t;

typedef struct
{
  ip4_address_t addr;
  u32 tenant_id;
#define _(N, i, n, s) \
  u16 busy_##n##_ports; \
  uword * busy_##n##_port_bitmap;
    foreach_hanat_mapper_protocol
#undef _
} hanat_mapper_address_t;

typedef struct hanat_mapper_main_s
{
  /* API message ID base */
  u16 msg_id_base;

  /* mapper settings */
  u16 port;

  /* external address pool */
  hanat_mapper_address_t *addresses;

  /* values of various timeouts */
  u32 udp_timeout;
  u32 tcp_established_timeout;
  u32 tcp_transitory_timeout;
  u32 icmp_timeout;

  hanat_mapper_db_t db;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip4_main_t *ip4_main;
  ip_lookup_main_t *ip4_lookup_main;
  api_main_t *api_main;
} hanat_mapper_main_t;

extern hanat_mapper_main_t hanat_mapper_main;

extern vlib_node_registration_t hanat_mapper_node;
extern vlib_node_registration_t hanat_state_sync_node;

clib_error_t *hanat_mapper_api_init (vlib_main_t * vm,
				     hanat_mapper_main_t * nm);

void increment_v4_address (ip4_address_t * a);

int hanat_mapper_enable (u16 port);

int hanat_mapper_add_del_address (ip4_address_t * addr, u32 tenant_id,
				  u8 is_add);

int hanat_mapper_add_del_static_mapping (ip4_address_t * local_addr,
					 ip4_address_t * external_addr,
					 u16 local_port, u16 external_port,
					 u8 protocol, u32 tenant_id,
					 u8 is_add);

format_function_t format_hanat_mapper_protocol;

always_inline u8
ip_proto_to_hanat_mapper_proto (u8 ip_proto)
{
  u8 proto = ~0;

  proto = (ip_proto == IP_PROTOCOL_UDP) ? HANAT_MAPPER_PROTOCOL_UDP : proto;
  proto = (ip_proto == IP_PROTOCOL_TCP) ? HANAT_MAPPER_PROTOCOL_TCP : proto;
  proto = (ip_proto == IP_PROTOCOL_ICMP) ? HANAT_MAPPER_PROTOCOL_ICMP : proto;

  return proto;
}

always_inline void
session_reset_timeout (hanat_mapper_main_t * nm,
		       hanat_mapper_session_t * session, f64 now)
{
  switch (session->proto)
    {
    case HANAT_MAPPER_PROTOCOL_UDP:
      session->expire = now + nm->udp_timeout;
      break;
    case HANAT_MAPPER_PROTOCOL_TCP:
      session->expire = now + nm->tcp_established_timeout;
      break;
    case HANAT_MAPPER_PROTOCOL_ICMP:
      session->expire = now + nm->icmp_timeout;
      break;
    default:
      break;
    }
}

#endif /* __included_hanat_mapper_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
