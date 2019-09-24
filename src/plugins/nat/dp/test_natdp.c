#include <assert.h>
#include "natdp_db.h"

static void
test_table_actions (void)
{
  printf("Adding to table\n");
  natdp_db_t db = {0};
  natdp_db_init(&db, 1024, 209715200);

  natdp_session_t *s;
  natdp_session_key_t key = {
     .sa.as_u64[0] = 0xaabbccdd,
     .da.as_u64[0] = 0xddccbbaa,
  };

  natdp_session_entry_t entry = {
     .instructions = NAT_INSTR_SOURCE_ADDRESS,
     .post_sa.as_u64[0] = 0xaaaaaaaa,
  };

  s = natdp_session_add(&db, &key, &entry);
  assert(s);
  assert(pool_elts(db.sessions) == 1);

  /* Verify that adding twice fails */
  s = natdp_session_add(&db, &key, &entry);
  assert(s == 0);
  assert(pool_elts(db.sessions) == 1);

  key.sa.as_u64[0] = 0xaabbccbb;
  key.da.as_u64[0] = 0xddccbbaa;
  s = natdp_session_add(&db, &key, &entry);
  assert(pool_elts(db.sessions) == 2);

  printf("Finding in table\n");
  s = natdp_session_find(&db, &key);
  assert(memcmp(&s->entry, &entry, sizeof(entry)) == 0);

  printf("Deleting from table\n");
  natdp_session_delete(&db, &key);
  assert(pool_elts(db.sessions) == 1);

  key.sa.as_u64[0] = 0xaabbccdd;
  key.da.as_u64[0] = 0xddccbbaa;
  natdp_session_delete(&db, &key);
  assert(pool_elts(db.sessions) == 0);

  /* Delete non-existant key */
  key.sa.as_u64[0] = 0xaabbccdd;
  key.da.as_u64[0] = 0xddccbbaa;
  natdp_session_delete(&db, &key);

  natdp_db_free(&db);

}

int main (int argc, char **argv)
{
  printf("Running tests...\n");
  printf("Init memory\n");
  clib_mem_init (0, 1 << 30);
  void * global_heap = clib_mem_get_per_cpu_heap ();

  clib_mem_set_per_cpu_heap (global_heap);

  test_table_actions();
  //test_table_actions_performance();

  /* Walk all entries of cache */
  /* Delete entrires from cache */

  /* Timers and expiry? */

  /* Locking? */
  /* Instrumentation */
  /* Running out of memory */


  /* Forwarding tests */
  //  test_nat44();
  //  test_transform();
}
