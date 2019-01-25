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
#ifndef __included_hanat_state_sync_h__
#define __included_hanat_state_sync_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#define HANAT_STATE_SYNC_VERSION 0x01

typedef struct
{
  u8 version;
  u8 rsvd;
  u16 count;
} hanat_state_sync_message_header_t;

typedef struct
{
  u8 event_type;
  u8 protocol;
  u16 flags;
  u32 in_l_addr;
  u32 in_r_addr;
  u16 in_l_port;
  u16 in_r_port;
  u32 out_l_addr;
  u32 out_r_addr;
  u16 out_l_port;
  u16 out_r_port;
  u32 pool_id;
  u32 tenant_id;
} hanat_state_sync_event_t;

typedef enum
{
  HANAT_STATE_SYNC_ADD = 1,
  HANAT_STATE_SYNC_DEL,
  HANAT_STATE_SYNC_KEEPALIVE,
} hanat_state_sync_event_type_t;

void hanat_state_sync_init (vlib_main_t * vm);
int hanat_state_sync_set (ip4_address_t * src_addr,
			  ip4_address_t * failover_addr, u16 src_port,
			  u16 failover_port, u32 path_mtu);

void hanat_state_sync_event_process (hanat_state_sync_event_t * event,
				     f64 now, u32 thread_index);

void hanat_state_sync_event_add (hanat_state_sync_event_t * event,
				 u8 do_flush, u32 thread_index);

#endif /* __included_hanat_state_sync_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
