static inline void
flowrouter_calc_key (ip4_header_t *ip, u32 fib_index, u16 sport, u16 dport, flowrouter_key_t * k)
{
  clib_memcpy_fast(&k->sa, &ip->src_address, 4);
  clib_memcpy_fast(&k->da, &ip->dst_address, 4);
  //k->as_u64[1] = (u64)ip->protocol << 56 | (u64)fib_index << 32 | (u64)sport << 16 | dport;
  k->proto = ip->protocol;
  k->fib_index = fib_index;
  k->sp = sport;
  k->dp = dport;
}

static inline int
l3_checksum_delta (flowrouter_instructions_t instructions,
                   ip4_address_t *pre_sa, ip4_address_t *post_sa,
		   ip4_address_t *pre_da, ip4_address_t *post_da)
{
  ip_csum_t c = 0;
  if (instructions & FLOWROUTER_INSTR_SOURCE_ADDRESS) {
    c = ip_csum_add_even(c, post_sa->as_u32);
    c = ip_csum_sub_even(c, pre_sa->as_u32);
  }
  if (instructions & FLOWROUTER_INSTR_DESTINATION_ADDRESS) {
    c = ip_csum_sub_even(c, pre_da->as_u32);
    c = ip_csum_add_even(c, post_da->as_u32);
  }
  return c;
}

/*
 * L4 checksum delta (UDP/TCP)
 */
static inline int
l4_checksum_delta (flowrouter_instructions_t instructions, ip_csum_t c,
                   u16 pre_sp, u16 post_sp, u16 pre_dp, u16 post_dp)
{
  if (instructions & FLOWROUTER_INSTR_SOURCE_PORT) {
    c = ip_csum_add_even(c, post_sp);
    c = ip_csum_sub_even(c, pre_sp);
  }
  if (instructions & FLOWROUTER_INSTR_DESTINATION_PORT) {
    c = ip_csum_add_even(c, post_dp);
    c = ip_csum_sub_even(c, pre_dp);
  }
  return c;
}

