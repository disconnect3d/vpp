#include <assert.h>
#include "hanat_worker_db.h"
#include <vnet/udp/udp_packet.h>
#include <vppinfra/bihash_template.c>
#include <vppinfra/vec.h>

/*
 * Functions:
 * Instrumentation:
 * Total number of entries / memory usage
 * Bihash collisions
 * Searches per second
 * New entries per second
 * Delete entries per second
 *
 * Create time
 * Last used time
 *
 * Bytes / Packets forwarded against entry
 *
 * How to update the mapper?
 *  - pure idle timeout
 *  - tcp flags
 *  - worker signals just like ipfix to mapper
 *    (even for local create a buffer)
 *  - 
 */

void
hanat_db_init (hanat_db_t * db, u32 buckets, u32 memory_size)
{
  clib_bihash_init_16_8 (&db->cache, "hanat-worker-cache", buckets, memory_size);
}

void
hanat_db_free (hanat_db_t * db)
{
  clib_bihash_free_16_8 (&db->cache);
}

static void
hanat_key_from_ip (u32 fib_index, ip4_header_t *ip, hanat_session_key_t *key)
{
  u16 sport = 0, dport = 0;
  if (ip->protocol == IP_PROTOCOL_TCP ||
      ip->protocol == IP_PROTOCOL_UDP) {
    udp_header_t *udp = ip4_next_header (ip);
    sport = udp->src_port;
    dport = udp->dst_port;
  }

  key->sa = ip->src_address;
  key->da = ip->dst_address;
  key->proto = ip->protocol;
  key->fib_index = fib_index;
  key->sp = sport;
  key->dp = dport;
}

hanat_session_t *
hanat_session_find (hanat_db_t *db, hanat_session_key_t *key)
{
  clib_bihash_kv_16_8_t kv, value;

  /* Add to index */
  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];

  if (clib_bihash_search_16_8 (&db->cache, &kv, &value))
    return 0;
  if (pool_is_free_index (db->sessions, value.value)) /* Is this check necessary? */
    return 0;
  return pool_elt_at_index (db->sessions, value.value);
}

hanat_session_t *
hanat_session_find_ip (hanat_db_t *db, u32 fib_index, ip4_header_t *ip)
{
  hanat_session_key_t key;
  hanat_key_from_ip(fib_index, ip, &key);
  return hanat_session_find(db, &key);
}

static int
hanat_session_stale_cb(clib_bihash_kv_16_8_t *kv, void *arg)
{
  return 0;
}


hanat_session_t *
hanat_session_add (hanat_db_t *db, hanat_session_key_t *key, hanat_session_entry_t *e)
{
  hanat_session_t *s;
  clib_bihash_kv_16_8_t kv;

  /* Check if session already exists */
  if (hanat_session_find(db, key))
    return 0;
    
  /* Add session to pool */
  pool_get_zero(db->sessions, s);
  s->key = *key;
  s->entry = *e;

  /* Add to index */
  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];
  kv.value = s - db->sessions;
#if 0  
  if (clib_bihash_add_del_16_8 (&db->cache, &kv, 1)) {
    assert(0);
    return 0;
  }
#endif
  if (clib_bihash_add_or_overwrite_stale_16_8(&db->cache, &kv, hanat_session_stale_cb, 0))
    assert(0);
  return s;
}

hanat_session_t *
hanat_worker_cache_add_incomplete(hanat_db_t *db, u32 fib_index, ip4_header_t *ip, u32 bi)
{
  hanat_session_key_t key;
  hanat_session_t *s;

  hanat_key_from_ip(fib_index, ip, &key);
  /* Check if session already exists */
  s = hanat_session_find(db, &key);
  if (s) {
    /* Just buffer packet */
    // TODO: Only buffer a maximum of n packets
    clib_warning("Buffer exists");
    //vec_add1(*s->entry.buffer_vec, bi);
    s->entry.buffer = bi;
    return s;
  }

  /* Add session to pool */
  pool_get_zero(db->sessions, s);
  s->key = key;
  //vec_add1(*s->entry.buffer_vec, bi);
  s->entry.buffer = bi;

  /* Add to index */
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = key.as_u64[0];
  kv.key[1] = key.as_u64[1];
  kv.value = s - db->sessions;
  if (clib_bihash_add_or_overwrite_stale_16_8(&db->cache, &kv, hanat_session_stale_cb, 0))
    assert(0);
  return s;
}

void
hanat_session_delete (hanat_db_t *db, hanat_session_key_t *key)
{
  clib_bihash_kv_16_8_t kv, value;

  kv.key[0] = key->as_u64[0];
  kv.key[1] = key->as_u64[1];

  if (clib_bihash_search_16_8 (&db->cache, &kv, &value)) {
    printf("Find failed\n");
    return;
  }

  /* Remove from pool */
  if (pool_is_free_index (db->sessions, value.value))
    printf("Delete failed 2");

  pool_put_index(db->sessions, value.value);

  /* Remove from index */
  if (clib_bihash_add_del_16_8 (&db->cache, &kv, 0))
    printf("Delete failed");
}

// Shared table. Needs locking.
// n^2 buckets -> mapper ids
// mapper ids -> endpoints (pool)
// on failure replace mapper id to endpoint mapping
// worker uses mapper-id to endpoint mapping on keepalive/status updates

// LPM
/* Worker to mapper table */
/*
 * Vector of mapper id's.
 * Separate pool of mapper id to IP address
 */

static uint64_t
masked_address64 (uint64_t addr, uint8_t len)
{
  return len == 64 ? addr : addr & ~(~0ull >> len);
}

static int
lpm_64_lookup_core (hanat_pool_t *lpm, u64 *addr, u8 pfxlen, u32 *value)
{
  BVT(clib_bihash_kv) kv, v;
  int rv;
  kv.key[0] = masked_address64(*addr, pfxlen);
  kv.key[1] = pfxlen;
  rv = BV(clib_bihash_search_inline_2)(&lpm->bihash, &kv, &v);
  if (rv != 0)
    return -1;
  *value = v.value;
  return 0;
}

u32
hanat_lpm_64_lookup (hanat_pool_t *lpm, void *addr_v, u8 pfxlen)
{
  u64 *addr = addr_v;
  int i = 0, rv;
  u32 value;
  clib_bitmap_foreach (i, lpm->prefix_lengths_bitmap,
    ({
      rv = lpm_64_lookup_core(lpm, addr, i, &value);
      if (rv == 0)
	return value;
    }));
  return ~0;
}

void
hanat_lpm_64_add (hanat_pool_t *lpm, void *addr_v, u8 pfxlen, u32 value)
{
  BVT(clib_bihash_kv) kv;
  u64 *addr = addr_v;

  kv.key[0] = masked_address64(*addr, pfxlen);
  kv.key[1] = pfxlen;
  kv.value = value;
  BV(clib_bihash_add_del)(&lpm->bihash, &kv, 1);
  lpm->prefix_length_refcount[pfxlen]++;
  lpm->prefix_lengths_bitmap = clib_bitmap_set (lpm->prefix_lengths_bitmap, 64 - pfxlen, 1);
}

void
hanat_lpm_64_delete (hanat_pool_t *lpm, void *addr_v, u8 pfxlen)
{
  u64 *addr = addr_v;
  BVT(clib_bihash_kv) kv;
  kv.key[0] = masked_address64(*addr, pfxlen);
  kv.key[1] = pfxlen;
  BV(clib_bihash_add_del)(&lpm->bihash, &kv, 0);

  /* refcount accounting */
  ASSERT (lpm->prefix_length_refcount[pfxlen] > 0);
  if (--lpm->prefix_length_refcount[pfxlen] == 0) {
    lpm->prefix_lengths_bitmap = clib_bitmap_set (lpm->prefix_lengths_bitmap, 
						  64 - pfxlen, 0);
  }
}


void
hanat_mapper_table_init(hanat_pool_t *db)
{
  
  /* Make bihash sizes configurable */
  BV (clib_bihash_init) (&(db->bihash),
			 "LPM 64", 64*1024, 32<<20);
 
}

#if 0

//hanat_hash_XXX
/*
 * Map IP4 destination address to mapping id.
 * Used by out2in.
 */
u32
hanat_lpm_lookup (u32 vrfid, ip4_address_t *da)
{
  //  lpm_lookup();
  return 0;
}
#endif
