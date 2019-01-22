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
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip_types_api.h>
#include <vpp/app/version.h>
#include "hanat_worker_db.h"
#include "hanat_worker_msg_enum.h"

/* define message structures */
#define vl_typedefs
#include <hanat-worker/hanat_worker_all_api_h.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <hanat-worker/hanat_worker_all_api_h.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <hanat-worker/hanat_worker_all_api_h.h>
#undef vl_printfun

#define REPLY_MSG_ID_BASE hm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <hanat-worker/hanat_worker_all_api_h.h>
#undef vl_api_version

static void
vl_api_hanat_worker_interface_add_del_t_handler(vl_api_hanat_worker_interface_add_del_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  vl_api_hanat_worker_interface_add_del_reply_t *rmp;

  VALIDATE_SW_IF_INDEX (mp);
  rv = hanat_worker_interface_add_del (sw_if_index, mp->is_add, ntohl(mp->mode));
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_HANAT_WORKER_INTERFACE_ADD_DEL_REPLY);
}

static void
vl_api_hanat_worker_interfaces_t_handler(vl_api_hanat_worker_interfaces_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_interfaces_reply_t *rmp;
  hanat_interface_t *interface;
  int i = 0, rv = 0;
  int len = pool_elts(hm->interfaces) * sizeof(*hm->interfaces);

  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_HANAT_WORKER_INTERFACES_REPLY, len,
  ({
    pool_foreach (interface, hm->interfaces, ({
	  rmp->sw_if_index[i++] = htonl(interface->sw_if_index);
    }));
    rmp->n_interfaces = htonl(i);
  }));
}

static void
vl_api_hanat_worker_mapper_add_del_t_handler(vl_api_hanat_worker_mapper_add_del_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_mapper_add_del_reply_t *rmp;
  int rv = 0;
  u32 mapper_index = 0;
  ip46_address_t mapper, src;

  ip_address_decode (&mp->src, &src);
  ip_address_decode (&mp->mapper, &mapper);
  rv = hanat_worker_mapper_add_del(mp->is_add,
				   ntohl(mp->fib_index),
				   (ip4_address_t *)&mp->pool.prefix, mp->pool.len,
				   &src, &mapper, ntohs(mp->udp_port), &mapper_index);

  /* *INDENT OFF* */
  REPLY_MACRO2 (VL_API_HANAT_WORKER_MAPPER_ADD_DEL_REPLY,
  ({
    rmp->mapper_index = htonl(mapper_index);
  }));
  /* *INDENT ON* */		  
}

static void
vl_api_hanat_worker_cache_add_t_handler(vl_api_hanat_worker_cache_add_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_cache_add_reply_t *rmp;
  int rv = 0;

  hanat_session_key_t key;
  memcpy(&key.sa, mp->key.sa, 4);
  memcpy(&key.da, mp->key.da, 4);
  key.proto = mp->key.proto;
  key.fib_index = ntohl(mp->key.fib_index);
  key.sp = mp->key.sp; /* Network byte order */
  key.dp = mp->key.dp; /* Network byte order */

  hanat_session_entry_t entry;
  entry.instructions = ntohl(mp->instructions);
  entry.fib_index = ntohl(mp->post_fib_index);
  memcpy(&entry.post_sa, mp->post_sa, 4);
  memcpy(&entry.post_da, mp->post_da, 4);
  entry.post_sp = mp->post_sp; /* Network byte order */
  entry.post_dp = mp->post_dp; /* Network byte order */

  rv = hanat_worker_cache_add(&key, &entry);

  REPLY_MACRO (VL_API_HANAT_WORKER_CACHE_ADD_REPLY);
}

static void
vl_api_hanat_worker_mapper_buckets_t_handler(vl_api_hanat_worker_mapper_buckets_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_mapper_buckets_reply_t *rmp;
  int rv = 0;

  rv = hanat_worker_mapper_buckets(ntohl(mp->fib_index), hm->pool_db.n_buckets, mp->mapper_index);
  REPLY_MACRO (VL_API_HANAT_WORKER_MAPPER_BUCKETS_REPLY);
}


/* List of message types that this plugin understands */
#define foreach_hanat_worker_plugin_api_msg				\
_(HANAT_WORKER_INTERFACE_ADD_DEL, hanat_worker_interface_add_del)	\
_(HANAT_WORKER_INTERFACES, hanat_worker_interfaces)			\
_(HANAT_WORKER_MAPPER_ADD_DEL, hanat_worker_mapper_add_del)		\
_(HANAT_WORKER_CACHE_ADD, hanat_worker_cache_add)			\
_(HANAT_WORKER_MAPPER_BUCKETS, hanat_worker_mapper_buckets)

/* Set up the API message handling tables */
static clib_error_t *
hanat_worker_plugin_api_hookup (vlib_main_t * vm)
{
  hanat_worker_main_t *hm __attribute__ ((unused)) = &hanat_worker_main;
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + hm->msg_id_base),     \
                           #n,					\
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_hanat_worker_plugin_api_msg;
#undef _

  return 0;
}

#define vl_msg_name_crc_list
#include <hanat-worker/hanat_worker_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (hanat_worker_main_t * hm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + hm->msg_id_base);
  foreach_vl_msg_name_crc_hanat_worker;
#undef _
}

clib_error_t *
hanat_worker_api_init (vlib_main_t * vm, hanat_worker_main_t *hm)
{
  u8 *name;
  clib_error_t *error = 0;

  name = format (0, "hanat_worker_%08x%c", api_version, 0);

  /* Ask for a correctly-sized block of API message decode slots */
  hm->msg_id_base =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_FIRST_AVAILABLE);

  error = hanat_worker_plugin_api_hookup (vm);

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (hm, &api_main);
  vec_free (name);

  return error;
}

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "High Availability NAT Worker Node",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
