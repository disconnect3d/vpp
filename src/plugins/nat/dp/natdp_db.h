#ifndef included_natdp_db_h
#define included_natdp_db_h

#include <stdbool.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>
#include <vnet/ip/ip6_packet.h>

/*
 * Data-plane session database
 */

/* NAT dataplane cache 6-tuple key. 40 octets */
typedef struct {
  union {
    struct {
      ip6_address_t sa;
      ip6_address_t da;
      u32 proto:8, fib_index:24;
      u16 sp;
      u16 dp;
    };
    u64 as_u64[5];
  };
} natdp_session_key_t;

typedef enum {
  NAT_INSTR_SOURCE_ADDRESS         = 0x01,
  NAT_INSTR_SOURCE_PORT            = 0x02,
  NAT_INSTR_DESTINATION_ADDRESS    = 0x04,
  NAT_INSTR_DESTINATION_PORT       = 0x08,
  NAT_INSTR_TCP_MSS                = 0x10,
} nat_instructions_t;


/* Session cache entries */
typedef struct {
  /* What to translate to */
  nat_instructions_t instructions;
  u32 fib_index;
  /* Stored in network byte order */
  ip6_address_t post_sa;
  ip6_address_t post_da;
  u16 post_sp;
  u16 post_dp;
  ip_csum_t l4_checksum;
  u16 tcp_mss_value;
  f64 last_heard;
  f64 last_refreshed;
} natdp_session_entry_t;

typedef struct {
  natdp_session_key_t key;
  natdp_session_entry_t entry;
  u32 mapper_id;
} natdp_session_t;

typedef struct {
  natdp_session_t *sessions;
  clib_bihash_40_8_t cache;     /* Session index */
} natdp_db_t;

void natdp_db_init (natdp_db_t * db, u32 buckets, u32 memory_size);
void natdp_db_free (natdp_db_t * db);
natdp_session_t *natdp_session_add (natdp_db_t *db, natdp_session_key_t *key, natdp_session_entry_t *e);
natdp_session_t *natdp_session_find (natdp_db_t *db, natdp_session_key_t *key);
void natdp_session_delete (natdp_db_t *db, natdp_session_key_t *key);

#endif
