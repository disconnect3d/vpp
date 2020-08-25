/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <assert.h>
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include "flowrouter.h"
#include "flowrouter_inlines.h"
#include <vnet/ip/format.h>
#include <arpa/inet.h>
#include <vnet/ip/ip4.h>
#include <math.h>
#include <vnet/fib/fib_table.h>

flowrouter_main_t flowrouter_main;

#if 0

extern vlib_node_registration_t flowrouter_fp_i2o_node;
extern vlib_node_registration_t flowrouter_fp_o2i_node;
extern vlib_node_registration_t flowrouter_sp_i2o_node;
extern vlib_node_registration_t flowrouter_sp_o2i_node;

static bool
flowrouter_validate_configuration (void)
{
  flowrouter_main_t *um = &flowrouter_main;
  u32 in2out = 0, out2in = 0;

  /* Validate pool */
  if (vec_len(um->pool_per_thread) == 0 || um->pool_per_thread[0] == ~0) {
    return false;
  }

  if (vec_len(um->sessions_per_worker) == 0) {
    return false;
  }

  /* Validate inside and outside interfaces */
  flowrouter_interface_t *interface;
  pool_foreach(interface, um->interfaces,
	       ({
		 if (interface->in2out) in2out++;
		 if (!interface->in2out) out2in++;
	       }));
  if (in2out == 0 || out2in == 0) return false;

  return true;
}

void
flowrouter_register_interface (u32 sw_if_index, u32 node_index, bool in2out)
{
  flowrouter_main_t *um = &flowrouter_main;
  flowrouter_interface_t *interface = flowrouter_interface_by_sw_if_index(sw_if_index);
  if (interface) {
    clib_warning("Interface already configured");
    return;
  }

  pool_get (um->interfaces, interface);
  interface->sw_if_index = sw_if_index;
  vec_validate_init_empty(um->interface_by_sw_if_index, sw_if_index, ~0);
  um->interface_by_sw_if_index[sw_if_index] = interface - um->interfaces;
  interface->in2out = in2out;
}

void
flowrouter_ip4_add_del_interface_address_cb (ip4_main_t * im,
					     uword opaque,
					     u32 sw_if_index,
					     ip4_address_t * address,
					     u32 address_length,
					     u32 if_address_index, u32 is_delete)
{
  flowrouter_main_t *um = &flowrouter_main;
  if (um->pool_sw_if_index != sw_if_index) {
    return;
  }

  /*
   * Delete pools belonging to that part of the configuration
   * Delete session table
   * Re-create sub-pools
   */

  /* Check if this is an address we are interested in */
  //cbb_lookup("/flowrouter/pool/interface/sw_if_index");
  cdb_notify_path("/flowrouter/pool/interface", CDB_NOTIFY_TYPE_MOD);
}

#include <vnet/interface_funcs.h>
static u32
interface_name_to_sw_if_index(char *name)
{
  unformat_input_t input = {0};
  input.buffer = (u8 *)name;
  u32 sw_if_index;
  return  unformat(&input, "%U", unformat_vnet_sw_interface, vnet_get_main(), &sw_if_index) ? sw_if_index : ~0;
}

void
flowrouter_cfg_params (cdb_inode_t *dir, flowrouter_cfg_params_t *cfg, cdb_notify_type_t t)
{
  flowrouter_main_t *um = &flowrouter_main;

  /* Only change if set / different from default */
  /* If max-sessions is changed, reset all tables */
  if (um->max_sessions != cfg->max_sessions) {
    um->max_sessions = cfg->max_sessions;
    flowrouter_reset_tables();
  }

  um->default_timeout = cfg->default_timeout;
  um->icmp_timeout = cfg->icmp_timeout;
  um->udp_timeout = cfg->udp_timeout;
  um->tcp_transitory_timeout = cfg->tcp_transitory_timeout;
  um->tcp_established_timeout = cfg->tcp_established_timeout;
}
#endif

u8 *
format_flowrouter_state (u8 *s, va_list * args)
{
  enum flowrouter_session_state state = va_arg (*args, enum flowrouter_session_state);

  switch (state) {
  case FLOWROUTER_STATE_TCP_SYN_SEEN:
    s = format (s, "syn seen");
    break;
  case FLOWROUTER_STATE_TCP_ESTABLISHED:
    s = format (s, "tcp established");
    break;
  case FLOWROUTER_STATE_TCP_FIN_WAIT:
    s = format (s, "tcp fin wait");
    break;
  case FLOWROUTER_STATE_TCP_CLOSE_WAIT:
    s = format (s, "tcp close wait");
    break;
  case FLOWROUTER_STATE_TCP_CLOSED:
    s = format (s, "tcp closed");
    break;
  case FLOWROUTER_STATE_TCP_LAST_ACK:
    s = format (s, "tcp last ack");
    break;
  case FLOWROUTER_STATE_UNKNOWN:
  default:
    s = format (s, "unknown");
  }
  return s;
}

u8 *
format_flowrouter_key (u8 * s, va_list * args)
{
  flowrouter_key_t *k = va_arg (*args, flowrouter_key_t *);

  s = format (s,
	      "%U%%%u:%u -> %U:%u protocol: %u",
	      format_ip4_address, &k->sa, k->fib_index, ntohs(k->sp),
	      format_ip4_address, &k->da, ntohs(k->dp),
	      k->proto);
  return s;
}

u8 *
format_flowrouter_fp_session (u8 * s, va_list * args)
{
  flowrouter_session_t *ses = va_arg (*args, flowrouter_session_t *);

  s = format (s, "Flow: %U", format_flowrouter_key, &ses->k);
  if (ses->instructions & (FLOWROUTER_INSTR_SOURCE_ADDRESS|FLOWROUTER_INSTR_SOURCE_PORT)) {
    s = format (s, "\n         Rewrite source: ->%U:%u",
		format_ip4_address, &ses->post_sa, ntohs(ses->post_sp));
  }
  if (ses->instructions & (FLOWROUTER_INSTR_DESTINATION_ADDRESS|FLOWROUTER_INSTR_DESTINATION_PORT)) {
    s = format (s, "\n         Rewrite destination: ->%U:%u",
		format_ip4_address, &ses->post_da, ntohs(ses->post_dp));
  }
  s = format (s, "\n");
  return s;
}

u8 *
format_flowrouter_session (u8 * s, va_list * args)
{
  vlib_main_t *vm = vlib_get_main ();
  f64 now = vlib_time_now (vm);
  u32 poolidx = va_arg (*args, u32);
  flowrouter_session_t *ses = va_arg (*args, flowrouter_session_t *);

  s = format(s, "[%-6u] %U", poolidx, format_flowrouter_fp_session, ses);
  s = format(s, "          last heard: %.2f", now - ses->last_heard);
  s = format (s, "\n");
  return s;
}

void
flowrouter_reset_tables (void)
{
  flowrouter_main_t *fm = &flowrouter_main;
  int i;
  vlib_main_t *vm = vlib_get_main();

  /* New */
  clib_bihash_16_8_t flowhash = { 0 };
  flowrouter_session_t **sessions_per_worker = 0;
  dlist_elt_t **lru_pool = 0;

  vec_validate (sessions_per_worker, fm->no_threads);
  vec_validate (lru_pool, fm->no_threads);
#define _(n)						\
  u32 *lru_head_index_##n = 0;				\
  vec_validate (lru_head_index_##n, fm->no_threads);
  foreach_flowrouter_timers
#undef _

  /* Old */
  clib_bihash_16_8_t old_flowhash;
  flowrouter_session_t **old_sessions_per_worker;
  dlist_elt_t **old_lru_pool;

  /* Create new tables */
  clib_bihash_init_16_8 (&flowhash, "flow hash", fm->max_sessions, fm->max_sessions * 250);

  /* per-worker */
  for (i = 0; i < fm->no_threads + 1; i++) {
    pool_init_fixed(sessions_per_worker[i], fm->max_sessions);
    pool_init_fixed (lru_pool[i], fm->max_sessions);

    dlist_elt_t *head;
#define _(n)						\
    pool_get (lru_pool[i], head);			\
    lru_head_index_##n[i] = head - lru_pool[i];		\
    clib_dlist_init (lru_pool[i], lru_head_index_##n[i]);
    foreach_flowrouter_timers
#undef _
  }

  /* Swap with old */
  vlib_worker_thread_barrier_sync(vm);

  old_flowhash = fm->flowhash;

  old_sessions_per_worker = fm->sessions_per_worker;
  old_lru_pool = fm->lru_pool;

  fm->flowhash = flowhash;

  fm->sessions_per_worker = sessions_per_worker;
  fm->lru_pool = lru_pool;

#define _(n)						\
  fm->lru_head_index_##n = lru_head_index_##n;
  foreach_flowrouter_timers
#undef _

  vlib_worker_thread_barrier_release(vm);

  /* Free old */
  if (old_sessions_per_worker) {
    clib_bihash_free_16_8(&old_flowhash);

    for (i = 0; i < fm->no_threads + 1; i++) {
      pool_free(old_sessions_per_worker[i]);
      pool_free (old_lru_pool[i]);
    }
    vec_free(old_sessions_per_worker);
    vec_free(old_lru_pool);
  }
}

/*
 * Will not enable NAT until all required configuration is in place.
 * XXX: If this funtion fails, it will leave the configuration in undefined state.
 */
static int
flowrouter_enable (void)
{
  flowrouter_main_t *fm = &flowrouter_main;

  if (fm->enabled) return 0;
  //if (!flowrouter_validate_configuration()) return 0;

  flowrouter_reset_tables ();

  /*
   * Register fast path handover
   */
  clib_spinlock_init(&fm->counter_lock);
  clib_spinlock_lock (&fm->counter_lock); /* should be no need */

  vec_validate (fm->counters, FLOWROUTER_N_COUNTER - 1);
#define _(E,n,p)                                                        \
  fm->counters[FLOWROUTER_COUNTER_##E].name = #n;				\
  fm->counters[FLOWROUTER_COUNTER_##E].stat_segment_name = "/" #p "/" #n;	\
  vlib_validate_simple_counter (&fm->counters[FLOWROUTER_COUNTER_##E], 0);	\
  vlib_zero_simple_counter (&fm->counters[FLOWROUTER_COUNTER_##E], 0);
  foreach_flowrouter_counter_name
#undef _
    clib_spinlock_unlock (&fm->counter_lock);

  fm->enabled = true;

  return 0;
}

flowrouter_interface_t *
flowrouter_interface_by_sw_if_index (u32 sw_if_index)
{
  flowrouter_main_t *fm = &flowrouter_main;

  if (sw_if_index > vec_len(fm->interface_by_sw_if_index)) return 0;
  u32 index = fm->interface_by_sw_if_index[sw_if_index];
  if (index == ~0) return 0;

  if (pool_is_free_index(fm->interfaces, index)) return 0;
  return pool_elt_at_index(fm->interfaces, index);
}

void
flowrouter_api_enable (flowrouter_arc_t arc, u32 sw_if_index, flowrouter_params_t *params)
{
  flowrouter_main_t *um = &flowrouter_main;
  flowrouter_interface_t *interface = flowrouter_interface_by_sw_if_index(sw_if_index);
  if (interface) {
    clib_warning("Interface already configured");
    return;
  }

  pool_get (um->interfaces, interface);
  interface->sw_if_index = sw_if_index;
  vec_validate_init_empty(um->interface_by_sw_if_index, sw_if_index, ~0);
  um->interface_by_sw_if_index[sw_if_index] = interface - um->interfaces;

  switch (params->cache_miss) {
  case FLOWROUTER_CACHE_MISS_FORWARD:
  case FLOWROUTER_CACHE_MISS_DROP:
  case FLOWROUTER_CACHE_MISS_PUNT:
  default:
    assert(0);
  }
  interface->cache_miss = params->cache_miss;
  //punt_node;
  //punt_port;

  clib_warning("Enabling reass for %u", sw_if_index);
  ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);

  flowrouter_enable();
  const char *arcname;

  switch (arc) {
  case FLOWROUTER_ARC_IP4_RX:
    arcname = "ip4-unicast";
    break;
  case FLOWROUTER_ARC_IP4_TX:
    arcname = "ip4-output";
    break;
  case FLOWROUTER_ARC_IP4_DPO:
    assert(0); // not implemented yet
    break;
  default:
    break;
  }
  interface->arc = arc;

  /* Validate and try to enable */
  if (vnet_feature_enable_disable (arcname, "flowrouter-handoff",
				   sw_if_index, 1, 0, 0) != 0)
    clib_warning("VNET feature enable failed on %u", interface->sw_if_index);

}

int
flowrouter_session_add (u32 thread_index, flowrouter_instructions_t instructions,
			flowrouter_key_t *key, ip4_address_t post_sa,
			ip4_address_t post_da, u16 post_sp, u16 post_dp, u16 tcp_mss, u32 fib_index,
			u32 next_index)
{
  flowrouter_main_t *fm = &flowrouter_main;
  flowrouter_session_t *s;

  clib_bihash_kv_16_8_t bkey, value;
  bkey.key[0] = key->as_u64[0];
  bkey.key[1] = key->as_u64[1];
  if (clib_bihash_search_16_8 (&fm->flowhash, &bkey, &value) == 0) {
    clib_warning("Bihash duplicate key");
    return -1;
  }

  pool_get(fm->sessions_per_worker[thread_index], s);

  clib_warning("Adding new session: %u %u", key->sp, key->dp);
  clib_memcpy_fast(&s->k, key, sizeof(*key));
  s->instructions = instructions;
  s->fib_index = fib_index;
  s->post_sa = post_sa;
  s->post_da = post_da;
  s->post_sp = htons(post_sp);
  s->post_dp = htons(post_dp);
  s->l4_checksum = 0;
  s->tcp_mss = 0;
  //s->state = state0;

  s->checksum = l3_checksum_delta(instructions,
				  &key->sa, &post_sa,
				  &key->da, &post_da);
  if (key->proto == IPPROTO_TCP ||
      key->proto == IPPROTO_UDP) {
    s->l4_checksum = l4_checksum_delta(instructions,
				       s->checksum,
				       key->sp, post_sp,
				       key->dp, post_dp);
  }

  u32 pool_index = s - fm->sessions_per_worker[thread_index];
  bkey.value = ((u64)thread_index << 32) | pool_index;

  if (clib_bihash_add_del_16_8 (&fm->flowhash, &bkey, 1)) {
    clib_warning("Bihash add failed");
    pool_put(fm->sessions_per_worker[thread_index], s);
    return -1;
  }
  return 0;
}

clib_error_t *flowrouter_plugin_api_hookup (vlib_main_t * vm);
clib_error_t *
flowrouter_init (vlib_main_t * vm)
{
  flowrouter_main_t *fm = &flowrouter_main;
  memset (fm, 0, sizeof(*fm));

  fm->max_sessions = FLOWROUTER_DEFAULT_MAX_SESSIONS;
  fm->default_timeout = FLOWROUTER_DEFAULT_TIMEOUT;
  fm->icmp_timeout = FLOWROUTER_DEFAULT_TIMEOUT_ICMP;
  fm->udp_timeout = FLOWROUTER_DEFAULT_TIMEOUT_UDP;
  fm->tcp_transitory_timeout = FLOWROUTER_DEFAULT_TIMEOUT_TCP_TRANSITORY;
  fm->tcp_established_timeout = FLOWROUTER_DEFAULT_TIMEOUT_TCP_ESTABLISHED;
  fm->no_threads = vlib_num_workers();
  vec_validate_init_empty(fm->pool_per_thread, fm->no_threads, ~0);

  return flowrouter_plugin_api_hookup (vm);
}

VLIB_INIT_FUNCTION (flowrouter_init);

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () =
{
 .version = VPP_BUILD_VER,
 .description = "Flowrouter"
};
