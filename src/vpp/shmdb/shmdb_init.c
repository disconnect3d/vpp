#include <vlib/vlib.h>
#include "shmdb.h"
#include <vpp/stats/stat_segment.h>

static clib_error_t *
shmdb_init (vlib_main_t * vm)
{
  stat_segment_shared_header_t *shared_header = vlib_stat_segment_get_shared_header();

  shared_header->operational_ds = shmdb_createdb();

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (shmdb_init) =
{
  .runs_after = VLIB_INITS("statseg_init"),
};
/* *INDENT-ON* */
