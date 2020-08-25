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

#ifndef included_flowrouter_protocol_h
#define included_flowrouter_protocol_h

#include <vnet/udp/udp_packet.h>

/*
 * Worker - Mapper protocol.
 *
 * A worker missing a binding for a session, it sends a
 * SESSION_REQUEST to the mapper. The mapper responds with a
 * SESSION_REPLY containing the NAT instructions, and which addresses
 * / ports to translate to. The worker can pass in opaque data like
 * e.g. a tunnel end-point address in case of DS-lite style tunneling.
 *
 * The worker will periodically send SESSION_UPDATE messages,
 * indicating that the session is still active.  On detection of a
 * session completing, e.g. a TCP FIN flag, the worker will send a
 * SESSION_UPDATE message with the session_completing flag
 * set. Likewise the mapper can send this message to the workers to
 * indicate that it can clean up a session. A session will not be
 * cleaned up immediately, but flagged for reuse.
 *
 */

#define FLOWROUTER_PROTOCOL_MAX_SIZE		1400

/*
 * Message header
 */
typedef struct {
  u32 core_id;
} __attribute__((packed)) flowrouter_header_t;

typedef struct {
  ip4_header_t ip;
  udp_header_t udp;
  flowrouter_header_t fr;
}  __attribute__((packed))flowrouter_ip_udp_flowrouter_header_t;

/*
 * TLV Types
 */
#define FLOWROUTER_SESSION_REQUEST 0x00
#define FLOWROUTER_SESSION_BINDING 0x01
#define FLOWROUTER_SESSION_REFRESH 0x02
#define FLOWROUTER_SESSION_DECLINE 0x03

/*
 * Session descriptor
 */
typedef struct {
  ip4_address_t sa;
  ip4_address_t da;
  u8 proto;
  u32 vni;
  u16 sp;
  u16 dp;
} __attribute__((packed)) flowrouter_session_descriptor_t;

/*
 * Session request / binding
 */
typedef struct {
  u8 type;		/* Session request */
  u8 length;
  u32 session_id;
  flowrouter_session_descriptor_t desc;
  u8 opaque_data[0];
} __attribute__((packed)) flowrouter_option_session_request_t;

typedef struct {
  u8 type;		/* Session binding */
  u8 length;
  u32 session_id;
  flowrouter_instructions_t instructions;
  /* Translated data fields */
  u32 fib_index;
  ip4_address_t sa;
  ip4_address_t da;
  u16 sp;
  u16 dp;
  u16 mss_value;
  u8 opaque_data[0];
}  __attribute__((packed)) flowrouter_option_session_binding_t;

typedef struct {
  u8 type;		/* Session decline */
  u8 length;
  u32 session_id;
  u8 code;		/* Reason code */
}  __attribute__((packed)) flowrouter_option_session_decline_t;

/*
 * Session refresh
 */
typedef enum {
  FLOWROUTER_FLAGS_UPDATE     = 0x0,	      
  FLOWROUTER_FLAGS_COMPLETING = 0x1,
} flowrouter_flags_t;

typedef struct {
  u8 type;		/* Session keepalive */
  u8 length;
  flowrouter_session_descriptor_t desc;
  flowrouter_flags_t flags;
  u64 packets;
  u64 bytes;
}  __attribute__((packed)) flowrouter_option_session_refresh_t;

#endif
