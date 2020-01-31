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

#include "shmdb.h"
#include <vppinfra/pool.h>
#include <vlib/vlib.h> // for cli
#include <vpp/stats/stat_segment.h>


static clib_error_t *
show_data_store_command_fn (vlib_main_t * vm,
			    unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  stat_segment_main_t *sm = &stat_segment_main;
  shmdb_inode_t *d;
  shmdb_directory_t *fs = sm->shared_header->operational_ds;
  clib_warning("Entries: %d", pool_elts(fs->root));

  pool_foreach(d, fs->root,
	       ({vlib_cli_output(vm, "%s", d->name);}));


  return 0;
}

VLIB_CLI_COMMAND (show_stat_segment_command, static) =
{
  .path = "show data-store",
  .short_help = "show data-store",
  .function = show_data_store_command_fn,
};
