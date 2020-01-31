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

#include <vlib/vlib.h>
#include "shmdb.h"
#include <vpp/stats/stat_segment.h>

static clib_error_t *
shmdb_init (vlib_main_t * vm)
{
  stat_segment_main_t *sm = &stat_segment_main;

  stat_segment_shared_header_t *shared_header = vlib_stat_segment_get_shared_header();

  shared_header->operational_ds = shmdb_createdb(sm->heap);

  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (shmdb_init) =
{
  .runs_after = VLIB_INITS("statseg_init"),
};
/* *INDENT-ON* */
