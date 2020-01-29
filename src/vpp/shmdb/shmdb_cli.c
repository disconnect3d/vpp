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
