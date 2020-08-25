#include <stdbool.h>
#include "flowrouter.h"

#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/interface_funcs.h>

#include <flowrouter/flowrouter.api_enum.h>
#include <flowrouter/flowrouter.api_types.h>


#define REPLY_MSG_ID_BASE fm->msg_id_base
#include <vlibapi/api_helper_macros.h>

extern flowrouter_main_t flowrouter_main;

void flowrouter_api_enable (flowrouter_arc_t arc, u32 sw_if_index, flowrouter_dpo_t *dpo,
			    flowrouter_cache_miss_behaviour_t cache_miss);
static void
vl_api_flowrouter_enable_t_handler (vl_api_flowrouter_enable_t * mp)
{
  int rv = 0;
  flowrouter_main_t *fm = &flowrouter_main;

  clib_warning("Adding to feature arc: %u on %u", mp->arc, mp->sw_if_index);
  flowrouter_api_enable(mp->arc, mp->sw_if_index, &mp->dpo, mp->cache_miss);

  vl_api_flowrouter_enable_reply_t *rmp;
  REPLY_MACRO_END (VL_API_FLOWROUTER_ENABLE_REPLY);
}

void flowrouter_mapper_add (u32 fib_index, ip4_address_t src, ip4_address_t mapper, u16 udp_port);
static void
vl_api_flowrouter_mapper_add_t_handler (vl_api_flowrouter_mapper_add_t * mp)
{
  int rv = 0;
  flowrouter_main_t *fm = &flowrouter_main;
  ip4_address_t src, mapper;

  ip4_address_decode(mp->src, &src);
  ip4_address_decode(mp->mapper, &mapper);

  flowrouter_mapper_add(mp->fib_index, src, mapper, mp->udp_port);

  vl_api_flowrouter_mapper_add_reply_t *rmp;
  REPLY_MACRO_END (VL_API_FLOWROUTER_MAPPER_ADD_REPLY);
}

int flowrouter_session_add(u32 threadid, flowrouter_instructions_t instructions,
			   flowrouter_key_t *key, ip4_address_t post_sa,
			   ip4_address_t post_da, u16 post_sp, u16 post_dp, u16 tcp_mss, u32 fib_index,
			   u32 next_index, u64 *session_index);
static void
vl_api_flowrouter_session_add_t_handler (vl_api_flowrouter_session_add_t * mp)
{
  int rv = 0;
  flowrouter_main_t *fm = &flowrouter_main;
  flowrouter_key_t key;
  ip4_address_t post_sa, post_da;
  u64 session_index = 0;

  ip4_address_decode(mp->key.sa, &key.sa);
  ip4_address_decode(mp->key.da, &key.da);
  key.proto = mp->key.proto;
  key.fib_index = mp->key.fib_index;
  key.sp = htons(mp->key.sp);
  key.dp = htons(mp->key.dp);

  ip4_address_decode(mp->post_sa, &post_sa);
  ip4_address_decode(mp->post_da, &post_da);
  rv = flowrouter_session_add(mp->threadid, mp->instructions, &key,
			      post_sa, post_da, mp->post_sp, mp->post_dp, mp->tcp_mss, mp->fib_index, mp->next_index,
			      &session_index);

  vl_api_flowrouter_session_add_reply_t *rmp;
  REPLY_MACRO2_END (VL_API_FLOWROUTER_SESSION_ADD_REPLY,
		    ({
		      rmp->session_index = session_index;
		    }));
}

/* API definitions */
#include <vnet/format_fns.h>
#include <flowrouter/flowrouter.api.c>

/* Set up the API message handling tables */
clib_error_t *
flowrouter_plugin_api_hookup (vlib_main_t * vm)
{
  flowrouter_main_t *fm = &flowrouter_main;

  fm->msg_id_base = setup_message_id_table ();

  api_main_t *am = vlibapi_get_main ();
  am->is_autoendian[fm->msg_id_base + VL_API_FLOWROUTER_ENABLE] = 1;
  am->is_autoendian[fm->msg_id_base + VL_API_FLOWROUTER_SESSION_ADD] = 1;
  am->is_autoendian[fm->msg_id_base + VL_API_FLOWROUTER_MAPPER_ADD] = 1;
  return 0;
}
