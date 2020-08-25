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
#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vppinfra/clib_error.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip.h>
#include "flowrouter.h"
#include <vnet/ip/ip4.h>

#if 0

static clib_error_t *
flowrouter_interface_command_fn (vlib_main_t * vm,
				   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u8 *name = 0;
  bool in2out = false;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "in %s", &name))
	in2out = true;
      else if (unformat (line_input, "out %s", &name))
	;
      else {
	error = clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, line_input);
	goto done;
      }
    }

  char *path = (char *)format(0, "/flowrouter/interfaces/%s%c", name, 0);
  cdb_set_inline(CDB_CANDIDATE_DATASTORE, path, in2out);
  vec_free(path);

 done:
  unformat_free(line_input);
  return error;
}

static clib_error_t *
flowrouter_params_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  flowrouter_main_t *um = &flowrouter_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  flowrouter_cfg_params_t cfg = { .max_sessions = FLOWROUTER_DEFAULT_MAX_SESSIONS,
			    .default_timeout = FLOWROUTER_DEFAULT_TIMEOUT,
			    .icmp_timeout = FLOWROUTER_DEFAULT_TIMEOUT_ICMP,
			    .udp_timeout = FLOWROUTER_DEFAULT_TIMEOUT_UDP,
			    .tcp_transitory_timeout = FLOWROUTER_DEFAULT_TIMEOUT_TCP_TRANSITORY,
			    .tcp_established_timeout = FLOWROUTER_DEFAULT_TIMEOUT_TCP_ESTABLISHED,
  };

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  /* Retrieve old value if set */
  cdb_get(CDB_CANDIDATE_DATASTORE, "/flowrouter/parameters", &cfg);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "max-sessions %u", &cfg.max_sessions))
	;
    else if (unformat (line_input, "timeout default %u", &cfg.default_timeout))
      ;
    else if (unformat (line_input, "timeout icmp %u", &cfg.icmp_timeout))
      ;
    else if (unformat (line_input, "timeout udp %u", &cfg.udp_timeout))
      ;
    else if (unformat (line_input, "timeout tcp-transitory %u", &cfg.tcp_transitory_timeout))
      ;
    else if (unformat (line_input, "timeout tcp-established %u", &cfg.tcp_established_timeout))
      ;
    else {
      error = clib_error_return (0, "unknown input '%U'",
				 format_unformat_error, line_input);
      goto done;
    }
  }

  /* Add or update */
  cdb_inode_t *d = cdb_lookup_index(CDB_CANDIDATE_DATASTORE, "/flowrouter/parameters");
  if (d->data)
    vec_free(d->data);
  flowrouter_cfg_params_t *cfgvec = 0;
  vec_add1(cfgvec, cfg);
  cdb_set_pointer(CDB_CANDIDATE_DATASTORE, um->parameters_index, "/flowrouter/parameters", cfgvec);

 done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND (set_interface_flowrouter_command, static) = {
  .path = "set flowrouter interface",
  .function = flowrouter_interface_command_fn,
  .short_help = "set flowrouter interface <in | out> <intfc>",
};

VLIB_CLI_COMMAND (set_flowrouter_params_command, static) = {
  .path = "set flowrouter",
  .function = flowrouter_params_command_fn,
  .short_help = "set flowrouter max-sessions <n> | "
                "timeout [udp <sec> | icmp <sec> "
                "tcp-transitory <sec> | tcp-established <sec> | "
                "default <sec>]",
};

#endif

static clib_error_t *
show_flowrouter_summary_command_fn (vlib_main_t * vm, unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  flowrouter_main_t *fm = &flowrouter_main;
  flowrouter_interface_t *interface;
  clib_error_t *error = 0;
  int i;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      /* *INDENT-OFF* */
      vlib_cli_output(vm, "Flowrouter state: %s", fm->enabled ? "enabled" : "disabled");
      vlib_cli_output(vm, "Max-sessions: %u", fm->max_sessions);
      pool_foreach(interface, fm->interfaces,
		   ({
		     vlib_cli_output(vm, "NAT: %U (%u) cache-miss: %u",
				     format_vnet_sw_if_index_name, vnet_get_main(), interface->sw_if_index,
				     interface->arc, interface->cache_miss);
		   }));
      /* *INDENT-ON* */
      vlib_cli_output (vm, "Timouts:");
      vlib_cli_output (vm, "  default: %u ICMP: %u UDP: %u", fm->default_timeout, fm->icmp_timeout,
		       fm->udp_timeout);
      vlib_cli_output (vm, "  TCP transitory: %u TCP established: %u", fm->tcp_transitory_timeout, fm->tcp_established_timeout);

      vlib_cli_output (vm, "flow hash: %U", format_bihash_16_8, &fm->flowhash, 0);
      for (i = 0; i < vec_len(fm->sessions_per_worker); i++) {
	vlib_cli_output(vm, "Sessions: [%u]: %u", i, pool_elts(fm->sessions_per_worker[i]));
	vlib_cli_output(vm, "LRU: [%u]: %u", i, pool_elts(fm->lru_pool[i]));
      }

      return 0;
    }
  unformat_free (line_input);

  return error;
}

static clib_error_t *
clear_flowrouter_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      flowrouter_reset_tables();
      return 0;
    }
  unformat_free (line_input);

  return error;
}

static clib_error_t *
show_flowrouter_sessions_command_fn (vlib_main_t * vm, unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  flowrouter_main_t *fm = &flowrouter_main;
  flowrouter_session_t *s;
  clib_error_t *error = 0;
  int i;

  if (!fm->enabled)
    return clib_error_return(0, "flowrouter not enabled");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      for (i = 0; i <= vlib_num_workers(); i++) {
	vlib_cli_output(vm, "Thread %u:", i);
	/* *INDENT-OFF* */
	pool_foreach(s, fm->sessions_per_worker[i],
		     ({vlib_cli_output(vm, "%U", format_flowrouter_session,
				       s - fm->sessions_per_worker[i], s);
		     }));
	/* *INDENT-ON* */
      }
      return 0;
    }
  unformat_free (line_input);

  return error;
}

static int
flowrouter_flowhash_print_cb (clib_bihash_kv_16_8_t *kv, void *ctx)
{
  vlib_main_t *vm = ctx;
  flowrouter_key_t *k = (flowrouter_key_t *)kv->key;
  vlib_cli_output(vm, "[%u/%u] %U", kv->value >> 32, kv->value & 0x00000000FFFFFFFF,
		  format_flowrouter_key, k);
  return BIHASH_WALK_CONTINUE;
}

static clib_error_t *
show_flowrouter_sessions_hash_command_fn (vlib_main_t * vm, unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  flowrouter_main_t *fm = &flowrouter_main;
  clib_error_t *error = 0;

  if (!fm->enabled)
    return clib_error_return(0, "flowrouter not enabled");

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    {
      clib_bihash_foreach_key_value_pair_16_8(&fm->flowhash, flowrouter_flowhash_print_cb, vm);
      return 0;
    }
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND(show_flowrouter_summary_command, static) = {
  .path = "show flowrouter summary",
  .short_help = "show flowrouter summary",
  .function = show_flowrouter_summary_command_fn,
  .is_mp_safe = 1,
};

VLIB_CLI_COMMAND(show_flowrouter_sessions_command, static) = {
  .path = "show flowrouter sessions",
  .short_help = "show flowrouter sessions",
  .function = show_flowrouter_sessions_command_fn,
};

VLIB_CLI_COMMAND(show_flowrouter_sessions_hash_command, static) = {
  .path = "show flowrouter sessions hash",
  .short_help = "show flowrouter sessions hash",
  .function = show_flowrouter_sessions_hash_command_fn,
};

VLIB_CLI_COMMAND(clear_flowrouter_sessions_command, static) = {
  .path = "clear flowrouter sessions",
  .short_help = "clear flowrouter sessions",
  .function = clear_flowrouter_sessions_command_fn,
};
