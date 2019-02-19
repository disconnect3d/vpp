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
#include "hanat_worker_all_api_h.h"
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include "hanat_worker_all_api_h.h"
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include "hanat_worker_all_api_h.h"
#undef vl_printfun

#define REPLY_MSG_ID_BASE hm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include "hanat_worker_all_api_h.h"
#undef vl_api_version

static void
vl_api_hanat_worker_enable_t_handler (vl_api_hanat_worker_enable_t * mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_enable_reply_t *rmp;
  int rv = 0;

  rv = hanat_worker_enable(ntohs(mp->udp_port), (ip4_address_t *)&mp->gre_src, ntohl(mp->cache_expiry_timer),
			   ntohl(mp->cache_refresh_interval));
  REPLY_MACRO (VL_API_HANAT_WORKER_ENABLE_REPLY);
}

static void
  vl_api_hanat_worker_interface_add_del_t_handler
  (vl_api_hanat_worker_interface_add_del_t * mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;

  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;
  vl_api_hanat_worker_interface_add_del_reply_t *rmp;

  VALIDATE_SW_IF_INDEX (mp);
  rv =
    hanat_worker_interface_add_del (sw_if_index, mp->is_add,
				    ntohl (mp->mode));
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_HANAT_WORKER_INTERFACE_ADD_DEL_REPLY);
}

static void
vl_api_hanat_worker_interfaces_t_handler (vl_api_hanat_worker_interfaces_t *
					  mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_interfaces_reply_t *rmp;
  hanat_interface_t *interface;
  int i = 0, rv = 0;
  int len = pool_elts (hm->interfaces) * sizeof (*hm->interfaces);

  /* *INDENT-OFF* */
  REPLY_MACRO3(VL_API_HANAT_WORKER_INTERFACES_REPLY, len,
  ({
    pool_foreach (interface, hm->interfaces, ({
	  rmp->ifs[i].sw_if_index = htonl(interface->sw_if_index);
	  rmp->ifs[i].mode = htonl(interface->mode);
	  i++;
    }));
    rmp->n_interfaces = htonl(i);
  }));
  /* *INDENT-ON* */
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
				   ntohl(mp->pool_id),
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
send_hanat_worker_mapper_details (vl_api_registration_t * reg, u32 context, hanat_pool_entry_t *p)
{
  vl_api_hanat_worker_mapper_details_t *rmp;
  hanat_worker_main_t *hm = &hanat_worker_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_HANAT_WORKER_MAPPER_DETAILS + hm->msg_id_base);
  rmp->context = context;

  rmp->pool_id = htonl(p->pool_id);
  rmp->fib_index = htonl(p->fib_index);
  
  memcpy(&rmp->pool.prefix, &p->prefix, 4);
  rmp->pool.len = p->prefix_len;
  ip_address_encode (&p->src, IP46_TYPE_ANY, &rmp->src);
  ip_address_encode (&p->mapper, IP46_TYPE_ANY, &rmp->mapper);
  rmp->udp_port = htons(p->udp_port);    

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_hanat_worker_mapper_dump_t_handler(vl_api_hanat_worker_mapper_dump_t *mp)
{
  vl_api_registration_t *reg;
  hanat_worker_main_t *hm = &hanat_worker_main;
  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  hanat_pool_entry_t *p;
  pool_foreach (p, hm->pool_db.pools,
  ({
    send_hanat_worker_mapper_details(reg, mp->context, p);
  }));
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
vl_api_hanat_worker_cache_clear_t_handler(vl_api_hanat_worker_cache_clear_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_cache_clear_reply_t *rmp;
  int rv = 0;

  rv = hanat_worker_cache_clear();

  REPLY_MACRO (VL_API_HANAT_WORKER_CACHE_CLEAR_REPLY);
}

static void
vl_api_hanat_worker_mapper_buckets_t_handler(vl_api_hanat_worker_mapper_buckets_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_mapper_buckets_reply_t *rmp;
  int rv = 0;

  rv = hanat_worker_mapper_buckets(1024, mp->mapper_index);
  REPLY_MACRO (VL_API_HANAT_WORKER_MAPPER_BUCKETS_REPLY);
}

static void
vl_api_hanat_worker_mapper_get_buckets_t_handler(vl_api_hanat_worker_mapper_get_buckets_t *mp)
{
  hanat_worker_main_t *hm = &hanat_worker_main;
  vl_api_hanat_worker_mapper_get_buckets_reply_t *rmp;
  int rv = 0, i;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_HANAT_WORKER_MAPPER_GET_BUCKETS_REPLY,
  ({
   memset(&rmp->mapper_index, 0, sizeof(u32)*1024);
   for (i = 0; i < vec_len(hm->pool_db.lb_buckets) - 1; i++)
     rmp->mapper_index[i] = htonl(hm->pool_db.lb_buckets[i]);
  }));
  /* *INDENT-ON* */
}

static void
send_hanat_worker_cache_details (vl_api_registration_t * reg, u32 context, hanat_session_t *s)
{
  vl_api_hanat_worker_cache_details_t *rmp;
  hanat_worker_main_t *hm = &hanat_worker_main;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_HANAT_WORKER_CACHE_DETAILS + hm->msg_id_base);
  rmp->context = context;
  rmp->mapper_id = htonl(s->mapper_id);
  memcpy(&rmp->key.sa, &s->key.sa.as_u32, 4);
  memcpy(&rmp->key.da, &s->key.da.as_u32, 4);
  rmp->key.sp = s->key.sp;
  rmp->key.dp = s->key.dp;
  rmp->key.proto = s->key.proto;
  rmp->key.fib_index = htonl(s->key.fib_index);
  rmp->instructions = htonl(s->entry.instructions);
  rmp->post_fib_index = htonl(s->entry.fib_index);
  memcpy(&rmp->post_sa, &s->entry.post_sa, 4);
  memcpy(&rmp->post_da, &s->entry.post_da, 4);
  rmp->post_sp = s->entry.post_sp;
  rmp->post_dp = s->entry.post_dp;
  memcpy(&rmp->gre, &s->entry.gre, 4);
  rmp->tcp_mss = htons(s->entry.tcp_mss_value);
  rmp->cached_buffer = htonl(s->entry.buffer);
  rmp->flags = htonl(s->entry.flags);
  rmp->last_heard = (f64)clib_net_to_host_u64(s->entry.last_heard);
  rmp->last_refreshed = (f64)clib_net_to_host_u64(s->entry.last_refreshed);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_hanat_worker_cache_dump_t_handler (vl_api_hanat_worker_cache_dump_t *mp)
{
  vl_api_registration_t *reg;
  hanat_worker_main_t *hm = &hanat_worker_main;
  // TODO: Add support for multiple workers

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  hanat_session_t *s;
  pool_foreach (s, hm->db.sessions,
  ({
    send_hanat_worker_cache_details(reg, mp->context, s);
  }));
}

/* List of message types that this plugin understands */
#define foreach_hanat_worker_plugin_api_msg				\
_(HANAT_WORKER_ENABLE, hanat_worker_enable)				\
_(HANAT_WORKER_INTERFACE_ADD_DEL, hanat_worker_interface_add_del)	\
_(HANAT_WORKER_INTERFACES, hanat_worker_interfaces)			\
_(HANAT_WORKER_MAPPER_ADD_DEL, hanat_worker_mapper_add_del)		\
_(HANAT_WORKER_MAPPER_DUMP, hanat_worker_mapper_dump)			\
_(HANAT_WORKER_CACHE_ADD, hanat_worker_cache_add)			\
_(HANAT_WORKER_CACHE_DUMP, hanat_worker_cache_dump)			\
_(HANAT_WORKER_CACHE_CLEAR, hanat_worker_cache_clear)			\
_(HANAT_WORKER_MAPPER_BUCKETS, hanat_worker_mapper_buckets)		\
_(HANAT_WORKER_MAPPER_GET_BUCKETS, hanat_worker_mapper_get_buckets)

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
#include "hanat_worker_all_api_h.h"
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
  .description = "High Availability NAT Worker",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
