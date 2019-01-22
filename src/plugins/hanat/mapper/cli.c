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

static clib_error_t *
hanat_mapper_enable_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 port = 0;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "port %d", &port))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = hanat_mapper_enable ((u16) port);

  if (rv)
    {
      error = clib_error_return (0, "hanat-mapper enable failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
hanat_mapper_add_address_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t start_addr, end_addr, this_addr;
  u32 start_host_order, end_host_order;
  u32 tenant_id = ~0;
  int i, count;
  int is_add = 1;
  int rv = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U - %U",
		    unformat_ip4_address, &start_addr,
		    unformat_ip4_address, &end_addr))
	;
      else if (unformat (line_input, "tenant-id %u", &tenant_id))
	;
      else if (unformat (line_input, "%U", unformat_ip4_address, &start_addr))
	end_addr = start_addr;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  start_host_order = clib_host_to_net_u32 (start_addr.as_u32);
  end_host_order = clib_host_to_net_u32 (end_addr.as_u32);

  if (end_host_order < start_host_order)
    {
      error = clib_error_return (0, "end address less than start address");
      goto done;
    }

  count = (end_host_order - start_host_order) + 1;
  this_addr = start_addr;

  for (i = 0; i < count; i++)
    {
      rv = hanat_mapper_add_del_address (&this_addr, tenant_id, is_add);

      switch (rv)
	{
	case VNET_API_ERROR_VALUE_EXIST:
	  error = clib_error_return (0, "NAT address already in use.");
	  goto done;
	case VNET_API_ERROR_NO_SUCH_ENTRY:
	  error = clib_error_return (0, "NAT address not exist.");
	  goto done;
	default:
	  break;
	}

      increment_v4_address (&this_addr);
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
hanat_mapper_set_timeout_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "udp %u", &nm->udp_timeout))
	;
      else if (unformat (line_input, "tcp-established %u",
			 &nm->tcp_established_timeout))
	;
      else if (unformat (line_input, "tcp-transitory %u",
			 &nm->tcp_transitory_timeout))
	;
      else if (unformat (line_input, "icmp %u", &nm->icmp_timeout))
	;
      else if (unformat (line_input, "reset"))
	{
	  nm->udp_timeout = HANAT_MAPPER_UDP_TIMEOUT;
	  nm->tcp_established_timeout = HANAT_MAPPER_TCP_ESTABLISHED_TIMEOUT;
	  nm->tcp_transitory_timeout = HANAT_MAPPER_TCP_TRANSITORY_TIMEOUT;
	  nm->icmp_timeout = HANAT_MAPPER_ICMP_TIMEOUT;
	}
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

done:
  unformat_free (line_input);

  return error;
}

uword
unformat_hanat_mapper_protocol (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(N, i, n, s) else if (unformat (input, s)) *r = HANAT_MAPPER_PROTOCOL_##N;
  foreach_hanat_mapper_protocol
#undef _
    else
    return 0;
  return 1;
}

static clib_error_t *
hanat_mapper_add_static_mapping_command_fn (vlib_main_t * vm,
					    unformat_input_t * input,
					    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t l_addr, e_addr;
  u32 tenant_id = 0, l_port, e_port;
  int rv = 0;
  clib_error_t *error = 0;
  u8 is_add = 1;
  hanat_mapper_protocol_t proto = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "local %U:%u", unformat_ip4_address, &l_addr,
		    &l_port))
	;
      else if (unformat (line_input, "external %U:%u", unformat_ip4_address,
			 &e_addr, &e_port))
	;
      else if (unformat (line_input, "tenant-id %u", &tenant_id))
	;
      else
	if (unformat
	    (line_input, "%U", unformat_hanat_mapper_protocol, &proto))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv =
    hanat_mapper_add_del_static_mapping (&l_addr, &e_addr,
					 clib_host_to_net_u16 (l_port),
					 clib_host_to_net_u16 (e_port), proto,
					 tenant_id, is_add);

  if (rv)
    {
      error = clib_error_return (0, "hanat-mapper add static mapping failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
hanat_mapper_set_state_sync_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip4_address_t src_addr, failover_addr;
  u32 src_port, failover_port, path_mtu = 512;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "src %U:%u", unformat_ip4_address, &src_addr,
		    &src_port))
	;
      else if (unformat (line_input, "failover %U:%u", unformat_ip4_address,
			 &failover_addr, &failover_port))
	;
      else if (unformat (line_input, "path-mtu %d", &path_mtu))
	;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv =
    hanat_state_sync_set (&src_addr, &failover_addr, (u16) src_port,
			  (u16) failover_port, path_mtu);

  if (rv)
    {
      error = clib_error_return (0, "set hanat-mapper state sync failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

u8 *
format_session (u8 * s, va_list * args)
{
  hanat_mapper_db_t *db = va_arg (*args, hanat_mapper_db_t *);
  hanat_mapper_session_t *session = va_arg (*args, hanat_mapper_session_t *);
  hanat_mapper_mapping_t *mapping =
    pool_elt_at_index (db->mappings, session->mapping_index);
  u32 indent = format_get_indent (s);

  s = format (s, "%Uin %U:%u->%U:%u out %U:%u->%U:%u protocol %U\n",
	      format_white_space, indent + 2,
	      format_ip4_address, &mapping->in_addr,
	      clib_net_to_host_u16 (mapping->in_port),
	      format_ip4_address, &session->in_r_addr,
	      clib_net_to_host_u16 (session->in_r_port),
	      format_ip4_address, &mapping->out_addr,
	      clib_net_to_host_u16 (mapping->out_port),
	      format_ip4_address, &session->out_r_addr,
	      clib_net_to_host_u16 (session->out_r_port),
	      format_hanat_mapper_protocol, mapping->proto);

  return s;
}

u8 *
format_user (u8 * s, va_list * args)
{
  hanat_mapper_db_t *db = va_arg (*args, hanat_mapper_db_t *);
  hanat_mapper_user_t *u = va_arg (*args, hanat_mapper_user_t *);
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index;
  u32 session_index;
  hanat_mapper_session_t *session;

  s =
    format (s, "%U: %d sessions\n", format_ip4_address, &u->addr,
	    u->nsessions);

  head_index = u->sessions_per_user_list_head_index;
  head = pool_elt_at_index (db->list_pool, head_index);
  elt_index = head->next;
  elt = pool_elt_at_index (db->list_pool, elt_index);
  session_index = elt->value;

  while (session_index != ~0)
    {
      session = pool_elt_at_index (db->sessions, session_index);

      s = format (s, "%U\n", format_session, db, session);

      elt_index = elt->next;
      elt = pool_elt_at_index (db->list_pool, elt_index);
      session_index = elt->value;
    }

  return s;
}

static clib_error_t *
hanat_mapper_show_sessions_command_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
  hanat_mapper_main_t *nm = &hanat_mapper_main;
  hanat_mapper_user_t *u;

  vlib_cli_output (vm, "HA NAT mapper sessions:");

  /* *INDENT-OFF* */
  pool_foreach (u, nm->db.users,
  ({
    vlib_cli_output (vm, "%U", format_user, &nm->db, u);
  }));
  /* *INDENT-ON* */

  vlib_cli_output (vm, "%U", format_bihash_16_8, &nm->db.session_in2out, 1);
  vlib_cli_output (vm, "%U", format_bihash_16_8, &nm->db.session_out2in, 1);

  return 0;
}

static clib_error_t *
hanat_mapper_state_sync_flush_command_fn (vlib_main_t * vm,
					  unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
  hanat_state_sync_event_add (0, 1, vm->thread_index);

  return 0;
}

static clib_error_t *
hanat_mapper_add_session_command_fn (vlib_main_t * vm,
				     unformat_input_t * input,
				     vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t in_l_addr, in_r_addr, out_l_addr, out_r_addr;
  u32 tenant_id = 0, in_l_port, in_r_port, out_l_port, out_r_port;
  hanat_mapper_protocol_t proto = ~0;
  u8 is_add = 1;
  clib_error_t *error = 0;
  hanat_state_sync_event_t event;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "in-local %U:%u", unformat_ip4_address, &in_l_addr,
	   &in_l_port))
	;
      else
	if (unformat
	    (line_input, "in-remote %U:%u", unformat_ip4_address, &in_r_addr,
	     &in_r_port))
	;
      else
	if (unformat
	    (line_input, "out-local %U:%u", unformat_ip4_address, &out_l_addr,
	     &out_l_port))
	;
      else
	if (unformat
	    (line_input, "out-remote %U:%u", unformat_ip4_address,
	     &out_r_addr, &out_r_port))
	;
      else if (unformat (line_input, "tenant-id %u", &tenant_id))
	;
      else
	if (unformat
	    (line_input, "%U", unformat_hanat_mapper_protocol, &proto))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  event.in_l_addr = in_l_addr.as_u32;
  event.in_r_addr = in_r_addr.as_u32;
  event.in_l_port = clib_host_to_net_u16 (in_l_port);
  event.in_r_port = clib_host_to_net_u16 (in_r_port);
  event.out_l_addr = out_l_addr.as_u32;
  event.out_r_addr = out_r_addr.as_u32;
  event.out_l_port = clib_host_to_net_u16 (out_l_port);
  event.out_r_port = clib_host_to_net_u16 (out_r_port);
  event.tenant_id = clib_host_to_net_u32 (tenant_id);
  event.protocol = proto;
  event.flags = 0;
  event.event_type = is_add ? HANAT_STATE_SYNC_ADD : HANAT_STATE_SYNC_DEL;
  hanat_state_sync_event_add (&event, 0, vm->thread_index);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */

VLIB_CLI_COMMAND (hanat_mapper_enable_command, static) = {
  .path = "hanat-mapper enable",
  .short_help = "hanat-mapper enable port <port>",
  .function = hanat_mapper_enable_command_fn,
};

VLIB_CLI_COMMAND (hanat_mapper_add_address_command, static) = {
  .path = "hanat-mapper add address",
  .short_help = "hanat-mapper add address <ip4-range-start> "
                "[- <ip4-range-end>] [tenant-id <id>] [del]",
  .function = hanat_mapper_add_address_command_fn,
};

VLIB_CLI_COMMAND (hanat_mapper_set_timeout_command, static) = {
  .path = "set hanat-mapper timeout",
  .short_help =
    "set hanat-mapper timeout [udp <sec> | tcp-established <sec> "
    "tcp-transitory <sec> | icmp <sec> | reset]",
  .function = hanat_mapper_set_timeout_command_fn,
};

VLIB_CLI_COMMAND (hanat_mapper_add_static_mapping_command, static) = {
  .path = "hanat-mapper add static mapping",
  .short_help = "hanat-mapper add static mapping tcp|udp|icmp "
                "local <ip-addr>:<port> external <ip-addr>:<port> "
                "[tenant-id <id>] [del]",
  .function = hanat_mapper_add_static_mapping_command_fn,
};

VLIB_CLI_COMMAND (hanat_mapper_set_state_sync_command, static) = {
  .path = "set hanat-mapper state sync",
  .short_help = "set hanat-mapper state sync src <ip-addr>:<port> "
                "failover <ip-addr>:<port> [path-mtu <path-mtu>]",
  .function = hanat_mapper_set_state_sync_command_fn,
};

VLIB_CLI_COMMAND (hanat_mapper_show_sessions_command, static) = {
  .path = "show hanat-mapper sessions",
  .short_help = "show hanat-mapper sessions",
  .function = hanat_mapper_show_sessions_command_fn,
};

VLIB_CLI_COMMAND (hanat_mapper_state_sync_flush_command, static) = {
  .path = "hanat-mapper state sync flush",
  .short_help = "hanat-mapper state sync flush",
  .function = hanat_mapper_state_sync_flush_command_fn,
};

//TODO: for testing purpose (delete later?)
VLIB_CLI_COMMAND (hanat_mapper_add_session_command, static) = {
  .path = "hanat-mapper add session",
  .short_help = "hanat-mapper add session in-local <ip-addr>:<port> "
                "in-remote <ip-addr>:<port> out-local <ip-addr>:<port> "
                "out-remote<ip-addr>:<port> tcp|udp|icmp tenant-id <id> [del]",
  .function = hanat_mapper_add_session_command_fn,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
