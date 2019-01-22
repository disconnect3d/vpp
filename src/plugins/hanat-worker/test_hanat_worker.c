#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "hanat_worker_db.h"
#define HANAT_TEST 1
#include "hanat_worker_node.c" /* To access static functions */

static ip_csum_t
incremental_checksum (ip_csum_t sum, void *_data, uword n_bytes)
{
  uword data = pointer_to_uword (_data);
  ip_csum_t sum0, sum1;

  sum0 = 0;
  sum1 = sum;

  /*
   * Align pointer to 64 bits. The ip checksum is a 16-bit
   * one's complememt sum. It's impractical to optimize
   * the calculation if the incoming address is odd.
   */
#define _(t)					\
do {						\
  if (n_bytes >= sizeof (t)			\
      && sizeof (t) < sizeof (ip_csum_t)	\
      && (data % (2 * sizeof (t))) != 0)	\
    {						\
      sum0 += * uword_to_pointer (data, t *);	\
      data += sizeof (t);			\
      n_bytes -= sizeof (t);			\
    }						\
} while (0)

  if (PREDICT_TRUE ((data & 1) == 0))
    {
      _(u16);
      if (BITS (ip_csum_t) > 32)
	_(u32);
    }
#undef _

  {
    ip_csum_t *d = uword_to_pointer (data, ip_csum_t *);

    while (n_bytes >= 2 * sizeof (d[0]))
      {
	sum0 = ip_csum_with_carry (sum0, d[0]);
	sum1 = ip_csum_with_carry (sum1, d[1]);
	d += 2;
	n_bytes -= 2 * sizeof (d[0]);
      }

    data = pointer_to_uword (d);
  }

#define _(t)								\
do {									\
  if (n_bytes >= sizeof (t) && sizeof (t) <= sizeof (ip_csum_t))	\
    {									\
      sum0 = ip_csum_with_carry (sum0, * uword_to_pointer (data, t *));	\
      data += sizeof (t);						\
      n_bytes -= sizeof (t);						\
    }									\
} while (0)

  if (BITS (ip_csum_t) > 32)
    _(u64);
  _(u32);
  _(u16);
  _(u8);

#undef _

  /* Combine even and odd sums. */
  sum0 = ip_csum_with_carry (sum0, sum1);

  return sum0;
}


always_inline u16
header_checksum (ip4_header_t * i)
{
  u16 save, csum;
  ip_csum_t sum;

  save = i->checksum;
  i->checksum = 0;
  sum = incremental_checksum (0, i, ip4_header_bytes (i));
  csum = ~ip_csum_fold (sum);

  i->checksum = save;

  /* Make checksum agree for special case where either
     0 or 0xffff would give same 1s complement sum. */
  if (csum == 0 && save == 0xffff)
    csum = save;

  return csum;
}

static inline uword
header_checksum_is_valid (ip4_header_t * i)
{
  return i->checksum == header_checksum (i);
}

#if 0
	    sum0 = ip_csum_update (sum0, ip0->dst_address.as_u32,
				   s0->ext_host_addr.as_u32, ip4_header_t,
				   dst_address);
#endif

static void
test_transform (void)
{
  printf("Running transform tests\n");
  hanat_session_entry_t s = {0};
  ip4_header_t ip = {0};

  ip.ip_version_and_header_length = 0x45;
  s.instructions = HANAT_INSTR_SOURCE_ADDRESS;
  s.post_sa.as_u32 = 0xaaaaaaab;

  int no_entries = 10000000;

  ip.src_address.as_u32 = 0xaabbccdd;
  ip.dst_address.as_u32 = 0xddccbbaa;
  ip.checksum = 0;
  u16 org_csum = htons(ip_csum(&ip, 20));
  transform_packet(&s, &ip);
  u16 new_csum = ip.checksum;

  clock_t begin = clock();
  for (int i = 0; i < no_entries; i++) {
    ip.src_address.as_u32 = 0xaabbccdd;
    ip.dst_address.as_u32 = 0xddccbbaa;
    ip.checksum = org_csum;
    transform_packet(&s, &ip);
    //assert(ip.checksum == new_csum);
    assert(ip.src_address.as_u32 == 0xaaaaaaab);
    assert(ip.dst_address.as_u32 == 0xddccbbaa);
  }
  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

  printf("Time spent NAT transform %f\n", time_spent);

  
  s.instructions = HANAT_INSTR_DESTINATION_ADDRESS;
  s.post_da.as_u32 = 0xbbbbbbbb;
  ip.src_address.as_u32 = 0xaabbccdd;
  ip.dst_address.as_u32 = 0xddccbbaa;
  transform_packet(&s, &ip);
  assert(ip.src_address.as_u32 == 0xaabbccdd);
  assert(ip.dst_address.as_u32 == 0xbbbbbbbb);

  s.instructions = HANAT_INSTR_SOURCE_ADDRESS | HANAT_INSTR_DESTINATION_ADDRESS;
  ip.src_address.as_u32 = 0xaabbccdd;
  ip.dst_address.as_u32 = 0xddccbbaa;
  transform_packet(&s, &ip);
  assert(ip.src_address.as_u32 == 0xaaaaaaab);
  assert(ip.dst_address.as_u32 == 0xbbbbbbbb);

}

static void
test_nat44 (void)
{
  printf("Running NAT44 tests\n");

  hanat_db_t db = {0};
  hanat_db_init(&db, 1024, 209715200);

  /* Add an entry in cache */
  hanat_session_t *s;
  hanat_session_key_t key = {
     .sa.as_u32 = 0xaabbccdd,
     .da.as_u32 = 0xddccbbaa,
  };

  hanat_session_entry_t entry = {
     .instructions = HANAT_INSTR_SOURCE_ADDRESS,
     .post_sa.as_u32 = 0xaaaaaaaa,
  };


  s = hanat_session_add(&db, &key, &entry);
  assert(pool_elts(db.sessions) == 1);

  ip4_header_t ip = {
		     .src_address.as_u32 = 0xaabbccdd,
		     .dst_address.as_u32 = 0xddccbbaa,
  };
  u32 out_fib_index;
  hanat_nat44_transform(&db, 0, &ip, &out_fib_index);
  assert(ip.src_address.as_u32 == 0xaaaaaaaa);
}

static void
test_table_actions (void)
{
  printf("Adding to table\n");
  hanat_db_t db = {0};
  hanat_db_init(&db, 1024, 209715200);

  hanat_session_t *s;
  hanat_session_key_t key = {
     .sa.as_u32 = 0xaabbccdd,
     .da.as_u32 = 0xddccbbaa,
  };

  hanat_session_entry_t entry = {
     .instructions = HANAT_INSTR_SOURCE_ADDRESS,
     .post_sa.as_u32 = 0xaaaaaaaa,
  };

  s = hanat_session_add(&db, &key, &entry);
  assert(pool_elts(db.sessions) == 1);

  /* Verify that adding twice fails */
  s = hanat_session_add(&db, &key, &entry);
  assert(s == 0);
  assert(pool_elts(db.sessions) == 1);

  key.sa.as_u32 = 0xaabbccbb;
  key.da.as_u32 = 0xddccbbaa;
  s = hanat_session_add(&db, &key, &entry);
  assert(pool_elts(db.sessions) == 2);

  printf("Finding in table\n");
  s = hanat_session_find(&db, &key);
  assert(memcmp(&s->entry, &entry, sizeof(entry)) == 0);

  printf("Deleting from table\n");
  hanat_session_delete(&db, &key);
  assert(pool_elts(db.sessions) == 1);

  key.sa.as_u32 = 0xaabbccdd;
  key.da.as_u32 = 0xddccbbaa;
  hanat_session_delete(&db, &key);
  assert(pool_elts(db.sessions) == 0);

  /* Delete non-existant key */
  key.sa.as_u32 = 0xaabbccdd;
  key.da.as_u32 = 0xddccbbaa;
  hanat_session_delete(&db, &key);

  hanat_db_free(&db);
}

static void
test_table_actions_performance (void)
{
  hanat_db_t db = {0};

  hanat_db_init(&db, 1024, 209715200);
  hanat_session_t *s;
  hanat_session_key_t key;
  int no_entries = 1000000;
  hanat_session_entry_t entry = {
     .instructions = HANAT_INSTR_SOURCE_ADDRESS,
     .post_sa.as_u32 = 0xaaaaaaaa,
  };
  fformat (stdout, "%U", BV (format_bihash), &db.cache, 0);

  clock_t begin = clock();
  for (int i = 0; i < no_entries; i++) {
    key.sa.as_u32 = i;
    key.da.as_u32 = i;
    s = hanat_session_add(&db, &key, &entry);
    assert(pool_elts(db.sessions) == i+1);
  }
  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;

  printf("Time spent adding %f\n", time_spent);


  begin = clock();
  int not_found = 0, found = 0;
  for (int i = 0; i < no_entries; i++) {
    int r = rand() % no_entries;
    key.sa.as_u32 = r;
    key.da.as_u32 = r;
    s = hanat_session_find(&db, &key);
    if (s == 0)
      not_found++;
    else
      found++;
  }
  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("Time spent lookup %f %d/%d\n", time_spent, found, not_found);

  fformat (stdout, "%U", BV (format_bihash), &db.cache, 0);

  begin = clock();
  for (int i = no_entries; i >= 0; i--) {
    key.sa.as_u32 = i;
    key.da.as_u32 = i;
    hanat_session_delete(&db, &key);
    assert(pool_elts(db.sessions) == i);
  }
  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("Time spent deleting %f\n", time_spent);

  assert(pool_elts(db.sessions) == 0);

  fformat (stdout, "%U", BV (format_bihash), &db.cache, 0);
  printf("USED: %ld / %ld\n", alloc_arena_next(&db.cache), alloc_arena_size(&db.cache));

  hanat_db_free(&db);
  assert(alloc_arena_size(&db.cache) == 0);
}

int main (int argc, char **argv)
{
  printf("Running tests...\n");
  printf("Init memory\n");
  clib_mem_init (0, 1 << 30);
  void * global_heap = clib_mem_get_per_cpu_heap ();

  clib_mem_set_per_cpu_heap (global_heap);

  test_table_actions();
  test_table_actions_performance();

  /* Walk all entries of cache */
  /* Delete entrires from cache */

  /* Timers and expiry? */

  /* Locking? */
  /* Instrumentation */
  /* Running out of memory */


  /* Forwarding tests */
  test_nat44();
  test_transform();
}
