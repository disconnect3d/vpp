#include <assert.h>
#include "natdp_db.h"
#include <vppinfra/bihash_template.c>

void
natdp_db_init (natdp_db_t * db, u32 buckets, u32 memory_size)
{
  clib_bihash_init_40_8 (&db->cache, "hanat-worker-cache", buckets, memory_size);
}

void
natdp_db_free (natdp_db_t * db)
{
  clib_bihash_free_40_8 (&db->cache);
}

static inline void
bihash_keycpy(clib_bihash_kv_40_8_t *dst, natdp_session_key_t *src) {
  /* Add to index */
  dst->key[0] = src->as_u64[0];
  dst->key[1] = src->as_u64[1];
  dst->key[2] = src->as_u64[2];
  dst->key[3] = src->as_u64[3];
  dst->key[4] = src->as_u64[4];
}
static inline void
keycpy(natdp_session_key_t *dst, natdp_session_key_t *src) {
  /* Add to index */
  dst->as_u64[0] = src->as_u64[0];
  dst->as_u64[1] = src->as_u64[1];
  dst->as_u64[2] = src->as_u64[2];
  dst->as_u64[3] = src->as_u64[3];
  dst->as_u64[4] = src->as_u64[4];
}

natdp_session_t *
natdp_session_find (natdp_db_t *db, natdp_session_key_t *key)
{
  clib_bihash_kv_40_8_t kv, value;

  /* Add to index */
  bihash_keycpy(&kv, key);

  if (clib_bihash_search_40_8 (&db->cache, &kv, &value))
    return 0;
  if (pool_is_free_index (db->sessions, value.value)) /* Is this check necessary? */
    return 0;
  return pool_elt_at_index (db->sessions, value.value);
}

int
nat_session_stale_cb(clib_bihash_kv_40_8_t *kv, void *arg)
{
  return 0;
}

natdp_session_t *
natdp_session_add (natdp_db_t *db, natdp_session_key_t *key, natdp_session_entry_t *e)
{
  natdp_session_t *s;
  clib_bihash_kv_40_8_t kv;

  /* Check if session already exists */
  if (natdp_session_find(db, key))
    return 0;

  /* Add session to pool */
  pool_get_zero(db->sessions, s);
  s->key = *key;
  s->entry = *e;

  /* Add to index */
  bihash_keycpy(&kv, key);
  kv.value = s - db->sessions;
  if (clib_bihash_add_or_overwrite_stale_40_8(&db->cache, &kv, nat_session_stale_cb, &db))
    assert(0);
  return s;
}

void
natdp_session_delete (natdp_db_t *db, natdp_session_key_t *key)
{
  clib_bihash_kv_40_8_t kv, value;

  /* Just search with the session key??? */
  bihash_keycpy(&kv, key);
  if (clib_bihash_search_40_8 (&db->cache, &kv, &value)) {
    printf("Find failed\n");
    return;
  }

  /* Remove from pool */
  if (pool_is_free_index (db->sessions, value.value))
    printf("Delete failed 2");

  pool_put_index(db->sessions, value.value);

  /* Remove from index */
  if (clib_bihash_add_del_40_8 (&db->cache, &kv, 0))
    printf("Delete failed");
}
