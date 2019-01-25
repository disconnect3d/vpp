/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "hanat_mapper_db.h"
#include "hanat_mapper.h"

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u16 protocol:3, tenant_id:13;
    };
    u64 as_u64;
  };
} mapping_key_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t l_addr;
      ip4_address_t r_addr;
      u32 proto:3, tenant_id:29;
      u16 l_port;
      u16 r_port;
    };
    u64 as_u64[2];
  };
} session_key_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u32 tenant_id;
    };
    u64 as_u64;
  };
} user_key_t;

u8 *
format_session_kvp (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);
  session_key_t k;

  k.as_u64[0] = v->key[0];
  k.as_u64[1] = v->key[1];

  s =
    format (s,
	    "local %U:%d remote %U:%d proto %U tenant-id %d session-index %llu",
	    format_ip4_address, &k.l_addr, clib_net_to_host_u16 (k.l_port),
	    format_ip4_address, &k.r_addr, clib_net_to_host_u16 (k.r_port),
	    format_hanat_mapper_protocol, k.proto, k.tenant_id, v->value);

  return s;
}

int
hanat_mapper_db_init (hanat_mapper_db_t * hanat_mapper_db,
		      u32 max_translations_per_user)
{
  u32 user_buckets = 128;
  u32 user_memory_size = 64 << 20;
  u32 mapping_buckets = 1024;
  u32 mapping_memory_size = 128 << 20;
  u32 session_buckets = 2048;
  u32 session_memory_size = 256 << 20;

  hanat_mapper_db->max_translations_per_user = max_translations_per_user;

  clib_bihash_init_8_8 (&hanat_mapper_db->user_hash, "users", user_buckets,
			user_memory_size);
  clib_bihash_init_8_8 (&hanat_mapper_db->mapping_in2out, "mapping-in2out",
			mapping_buckets, mapping_memory_size);
  clib_bihash_init_8_8 (&hanat_mapper_db->mapping_out2in, "mapping-out2in",
			mapping_buckets, mapping_memory_size);
  clib_bihash_init_16_8 (&hanat_mapper_db->session_in2out, "session-in2out",
			 session_buckets, session_memory_size);
  clib_bihash_set_kvp_format_fn_16_8 (&hanat_mapper_db->session_in2out,
				      format_session_kvp);
  clib_bihash_init_16_8 (&hanat_mapper_db->session_out2in, "session-out2in",
			 session_buckets, session_memory_size);
  clib_bihash_set_kvp_format_fn_16_8 (&hanat_mapper_db->session_out2in,
				      format_session_kvp);

  return 0;
}

hanat_mapper_user_t *
hanat_mapper_user_get (hanat_mapper_db_t * db, ip4_address_t * addr,
		       u32 tenant_id)
{
  hanat_mapper_user_t *user = 0;
  user_key_t user_key;
  clib_bihash_kv_8_8_t kv, value;

  user_key.addr.as_u32 = addr->as_u32;
  user_key.tenant_id = tenant_id;
  kv.key = user_key.as_u64;

  if (!clib_bihash_search_8_8 (&db->user_hash, &kv, &value))
    user = pool_elt_at_index (db->users, value.value);

  return user;
}

hanat_mapper_user_t *
hanat_mapper_user_create (hanat_mapper_db_t * db, ip4_address_t * addr,
			  u32 tenant_id)
{
  hanat_mapper_user_t *user;
  user_key_t user_key;
  clib_bihash_kv_8_8_t kv;
  dlist_elt_t *per_user_list_head_elt;

  pool_get (db->users, user);
  clib_memset (user, 0, sizeof (*user));
  user->addr.as_u32 = addr->as_u32;
  user->tenant_id = tenant_id;
  pool_get (db->list_pool, per_user_list_head_elt);
  user->sessions_per_user_list_head_index =
    per_user_list_head_elt - db->list_pool;
  clib_dlist_init (db->list_pool, user->sessions_per_user_list_head_index);
  user_key.addr.as_u32 = addr->as_u32;
  user_key.tenant_id = tenant_id;
  kv.key = user_key.as_u64;
  kv.value = user - db->users;
  clib_bihash_add_del_8_8 (&db->user_hash, &kv, 1);

  return user;
}

void
hanat_mapper_user_free (hanat_mapper_db_t * db, hanat_mapper_user_t * user)
{
  user_key_t user_key;
  clib_bihash_kv_8_8_t kv;

  user_key.addr.as_u32 = user->addr.as_u32;
  user_key.tenant_id = user->tenant_id;
  kv.key = user_key.as_u64;
  kv.value = user - db->users;
  clib_bihash_add_del_8_8 (&db->user_hash, &kv, 0);

  pool_put_index (db->list_pool, user->sessions_per_user_list_head_index);
  pool_put (db->users, user);

}

hanat_mapper_mapping_t *
hanat_mapper_mapping_get (hanat_mapper_db_t * db, ip4_address_t * addr,
			  u16 port, u8 proto, u32 tenant_id, u8 is_in2out)
{
  hanat_mapper_mapping_t *mapping = 0;
  mapping_key_t mapping_key;
  clib_bihash_kv_8_8_t kv, value;
  clib_bihash_8_8_t *h;

  h = is_in2out ? &db->mapping_in2out : &db->mapping_out2in;
  mapping_key.addr.as_u32 = addr->as_u32;
  mapping_key.port = port;
  mapping_key.protocol = proto;
  mapping_key.tenant_id = tenant_id;
  kv.key = mapping_key.as_u64;

  if (!clib_bihash_search_8_8 (h, &kv, &value))
    mapping = pool_elt_at_index (db->mappings, value.value);

  return mapping;
}

hanat_mapper_mapping_t *
hanat_mapper_mappig_create (hanat_mapper_db_t * db, ip4_address_t * in_addr,
			    u16 in_port, ip4_address_t * out_addr,
			    u16 out_port, u8 proto, u32 pool_id,
			    u32 tenant_id, u8 is_static)
{
  hanat_mapper_mapping_t *mapping;
  mapping_key_t mapping_key;
  clib_bihash_kv_8_8_t kv;

  pool_get (db->mappings, mapping);
  clib_memset (mapping, 0, sizeof (*mapping));
  mapping->in_addr.as_u32 = in_addr->as_u32;
  mapping->in_port = in_port;
  mapping->out_addr.as_u32 = out_addr->as_u32;
  mapping->out_port = out_port;
  mapping->proto = proto;
  mapping->pool_id = pool_id;
  mapping->tenant_id = tenant_id;
  mapping->is_static = is_static;

  mapping_key.addr.as_u32 = in_addr->as_u32;
  mapping_key.port = in_port;
  mapping_key.protocol = proto;
  mapping_key.tenant_id = tenant_id;
  kv.key = mapping_key.as_u64;
  kv.value = mapping - db->mappings;
  clib_bihash_add_del_8_8 (&db->mapping_in2out, &kv, 1);

  mapping_key.addr.as_u32 = out_addr->as_u32;
  mapping_key.port = out_port;
  mapping_key.tenant_id = 0;
  kv.key = mapping_key.as_u64;
  clib_bihash_add_del_8_8 (&db->mapping_out2in, &kv, 1);

  return mapping;
}

void
hanat_mapper_mapping_free (hanat_mapper_db_t * db,
			   hanat_mapper_mapping_t * mapping, u8 flush_static)
{
  mapping_key_t mapping_key;
  clib_bihash_kv_8_8_t kv;
  hanat_mapper_user_t *user;
  dlist_elt_t *head, *elt;
  u32 elt_index, head_index, session_index, mapping_index, nsessions = 0;
  hanat_mapper_session_t *session;
  session_key_t session_key;
  clib_bihash_kv_16_8_t s_kv;

  mapping_key.addr.as_u32 = mapping->in_addr.as_u32;
  mapping_key.port = mapping->in_port;
  mapping_key.protocol = mapping->proto;
  mapping_key.tenant_id = mapping->tenant_id;
  kv.key = mapping_key.as_u64;
  clib_bihash_add_del_8_8 (&db->mapping_in2out, &kv, 0);

  mapping_key.addr.as_u32 = mapping->out_addr.as_u32;
  mapping_key.port = mapping->out_port;
  mapping_key.tenant_id = 0;
  kv.key = mapping_key.as_u64;
  clib_bihash_add_del_8_8 (&db->mapping_out2in, &kv, 0);

  if (flush_static && mapping->is_static)
    {
      mapping_index = mapping - db->mappings;
      user =
	hanat_mapper_user_get (db, &mapping->in_addr, mapping->tenant_id);
      if (user)
	{
	  head_index = user->sessions_per_user_list_head_index;
	  head = pool_elt_at_index (db->list_pool, head_index);
	  elt_index = head->next;
	  elt = pool_elt_at_index (db->list_pool, elt_index);
	  session_index = elt->value;
	  while (session_index != ~0)
	    {
	      session = pool_elt_at_index (db->sessions, session_index);
	      elt = pool_elt_at_index (db->list_pool, elt->next);
	      session_index = elt->value;
	      if (session->mapping_index == mapping_index)
		{
		  session_key.l_addr.as_u32 = mapping->in_addr.as_u32;
		  session_key.l_port = mapping->in_port;
		  session_key.r_addr.as_u32 = session->in_r_addr.as_u32;
		  session_key.r_port = session->in_r_port;
		  session_key.proto = session->proto;
		  session_key.tenant_id = mapping->tenant_id;
		  s_kv.key[0] = session_key.as_u64[0];
		  s_kv.key[1] = session_key.as_u64[1];
		  clib_bihash_add_del_16_8 (&db->session_in2out, &s_kv, 0);

		  session_key.l_addr.as_u32 = mapping->out_addr.as_u32;
		  session_key.l_port = mapping->out_port;
		  session_key.r_addr.as_u32 = session->out_r_addr.as_u32;
		  session_key.r_port = session->out_r_port;
		  session_key.tenant_id = 0;
		  s_kv.key[0] = session_key.as_u64[0];
		  s_kv.key[1] = session_key.as_u64[1];
		  clib_bihash_add_del_16_8 (&db->session_out2in, &s_kv, 0);

		  pool_put (db->sessions, session);

		  nsessions++;
		}
	    }
	  user->nsessions -= nsessions;
	  if (!user->nsessions)
	    hanat_mapper_user_free (db, user);
	}
    }

  pool_put (db->mappings, mapping);
}

hanat_mapper_session_t *
hanat_mapper_session_get (hanat_mapper_db_t * db, ip4_address_t * l_addr,
			  u16 l_port, ip4_address_t * r_addr, u16 r_port,
			  u8 proto, u32 tenant_id, u8 is_in2out)
{
  hanat_mapper_session_t *session = 0;
  session_key_t session_key;
  clib_bihash_kv_16_8_t kv, value;
  clib_bihash_16_8_t *h;

  h = is_in2out ? &db->session_in2out : &db->session_out2in;
  session_key.l_addr.as_u32 = l_addr->as_u32;
  session_key.l_port = l_port;
  session_key.r_addr.as_u32 = r_addr->as_u32;
  session_key.r_port = r_port;
  session_key.proto = proto;
  session_key.tenant_id = tenant_id;
  kv.key[0] = session_key.as_u64[0];
  kv.key[1] = session_key.as_u64[1];

  if (!clib_bihash_search_16_8 (h, &kv, &value))
    session = pool_elt_at_index (db->sessions, value.value);

  return session;
}

void
hanat_mapper_session_free (hanat_mapper_db_t * db,
			   hanat_mapper_session_t * session)
{
  session_key_t session_key;
  clib_bihash_kv_16_8_t kv;
  hanat_mapper_mapping_t *mapping;
  hanat_mapper_user_t *user;

  mapping = pool_elt_at_index (db->mappings, session->mapping_index);

  session_key.l_addr.as_u32 = mapping->in_addr.as_u32;
  session_key.l_port = mapping->in_port;
  session_key.r_addr.as_u32 = session->in_r_addr.as_u32;
  session_key.r_port = session->in_r_port;
  session_key.proto = session->proto;
  session_key.tenant_id = mapping->tenant_id;
  kv.key[0] = session_key.as_u64[0];
  kv.key[1] = session_key.as_u64[1];
  clib_bihash_add_del_16_8 (&db->session_in2out, &kv, 0);

  session_key.l_addr.as_u32 = mapping->out_addr.as_u32;
  session_key.l_port = mapping->out_port;
  session_key.r_addr.as_u32 = session->out_r_addr.as_u32;
  session_key.r_port = session->out_r_port;
  session_key.tenant_id = 0;
  kv.key[0] = session_key.as_u64[0];
  kv.key[1] = session_key.as_u64[1];
  clib_bihash_add_del_16_8 (&db->session_out2in, &kv, 0);

  mapping->nsessions--;

  clib_dlist_remove (db->list_pool, session->per_user_index);
  pool_put_index (db->list_pool, session->per_user_index);
  user = pool_elt_at_index (db->users, session->user_index);
  user->nsessions--;

  pool_put (db->sessions, session);

  if (!mapping->is_static && !mapping->nsessions)
    hanat_mapper_mapping_free (db, mapping, 0);
  if (!user->nsessions)
    hanat_mapper_user_free (db, user);
}

typedef struct
{
  hanat_mapper_db_t *db;
  f64 now;
  u32 mapping_index;
  u32 user_index;
} is_idle_session_ctx_t;

static_always_inline int
is_session_idle (clib_bihash_kv_16_8_t * kv, void *arg, u8 in2out)
{
  is_idle_session_ctx_t *ctx = arg;
  hanat_mapper_db_t *db = ctx->db;
  hanat_mapper_session_t *session;
  session_key_t session_key;
  clib_bihash_kv_16_8_t d_kv;
  hanat_mapper_mapping_t *mapping;
  hanat_mapper_user_t *user;

  session = pool_elt_at_index (db->sessions, kv->value);
  if (ctx->now >= session->expire)
    {
      mapping = pool_elt_at_index (db->mappings, session->mapping_index);

      session_key.proto = session->proto;
      if (in2out)
	{
	  session_key.l_addr.as_u32 = mapping->out_addr.as_u32;
	  session_key.l_port = mapping->out_port;
	  session_key.r_addr.as_u32 = session->out_r_addr.as_u32;
	  session_key.r_port = session->out_r_port;
	  session_key.tenant_id = 0;
	}
      else
	{
	  session_key.l_addr.as_u32 = mapping->in_addr.as_u32;
	  session_key.l_port = mapping->in_port;
	  session_key.r_addr.as_u32 = session->in_r_addr.as_u32;
	  session_key.r_port = session->in_r_port;
	  session_key.tenant_id = mapping->tenant_id;
	}
      d_kv.key[0] = session_key.as_u64[0];
      d_kv.key[1] = session_key.as_u64[1];
      clib_bihash_add_del_16_8 (in2out ? &db->
				session_out2in : &db->session_in2out, &d_kv,
				0);

      mapping->nsessions--;
      if ((session->mapping_index != ctx->mapping_index)
	  && !mapping->nsessions)
	hanat_mapper_mapping_free (db, mapping, 0);

      clib_dlist_remove (db->list_pool, session->per_user_index);
      pool_put_index (db->list_pool, session->per_user_index);
      user = pool_elt_at_index (db->users, session->user_index);
      user->nsessions--;
      if ((session->user_index != ctx->user_index) && !user->nsessions)
	hanat_mapper_user_free (db, user);

      pool_put (db->sessions, session);

      return 1;
    }

  return 0;
}

int
is_session_idle_in2out (clib_bihash_kv_16_8_t * kv, void *arg)
{
  return is_session_idle (kv, arg, 1);
}

int
is_session_idle_out2in (clib_bihash_kv_16_8_t * kv, void *arg)
{
  return is_session_idle (kv, arg, 0);
}

hanat_mapper_session_t *
hanat_mapper_session_create (hanat_mapper_db_t * db,
			     hanat_mapper_mapping_t * mapping,
			     ip4_address_t * in_r_addr, u16 in_r_port,
			     ip4_address_t * out_r_addr, u16 out_r_port,
			     hanat_mapper_user_t * user, f64 now,
			     u8 * opaque_data, u8 opaque_data_len)
{
  hanat_mapper_session_t *session = 0;
  dlist_elt_t *per_user_elt, *oldest_elt;
  u32 oldest_index;
  session_key_t session_key;
  clib_bihash_kv_16_8_t kv;
  hanat_mapper_mapping_t *m;
  is_idle_session_ctx_t ctx;

  if (user->nsessions >= db->max_translations_per_user)
    {
      oldest_index =
	clib_dlist_remove_head (db->list_pool,
				user->sessions_per_user_list_head_index);
      oldest_elt = pool_elt_at_index (db->list_pool, oldest_index);
      session = pool_elt_at_index (db->sessions, oldest_elt->value);
      if (now >= session->expire)
	{
	  clib_dlist_addtail (db->list_pool,
			      user->sessions_per_user_list_head_index,
			      oldest_index);
	  m = pool_elt_at_index (db->mappings, session->mapping_index);
	  session_key.l_addr.as_u32 = m->in_addr.as_u32;
	  session_key.l_port = m->in_port;
	  session_key.r_addr.as_u32 = session->in_r_addr.as_u32;
	  session_key.r_port = session->in_r_port;
	  session_key.proto = session->proto;
	  session_key.tenant_id = m->tenant_id;
	  kv.key[0] = session_key.as_u64[0];
	  kv.key[1] = session_key.as_u64[1];
	  clib_bihash_add_del_16_8 (&db->session_in2out, &kv, 0);

	  session_key.l_addr.as_u32 = m->out_addr.as_u32;
	  session_key.l_port = m->out_port;
	  session_key.r_addr.as_u32 = session->out_r_addr.as_u32;
	  session_key.r_port = session->out_r_port;
	  session_key.tenant_id = 0;
	  kv.key[0] = session_key.as_u64[0];
	  kv.key[1] = session_key.as_u64[1];
	  clib_bihash_add_del_16_8 (&db->session_out2in, &kv, 0);
	  m->nsessions--;
	  if ((m != mapping) && !m->nsessions)
	    hanat_mapper_mapping_free (db, m, 0);

	  session->flags = 0;
	  session->total_bytes = 0;
	  session->total_pkts = 0;
	  vec_free (session->opaque_data);
	}
      else
	{
	  clib_dlist_addhead (db->list_pool,
			      user->sessions_per_user_list_head_index,
			      oldest_index);
	  return 0;
	}
    }
  else
    {
      pool_get (db->sessions, session);
      clib_memset (session, 0, sizeof (*session));
      pool_get (db->list_pool, per_user_elt);
      session->per_user_index = per_user_elt - db->list_pool;
      session->per_user_list_head_index =
	user->sessions_per_user_list_head_index;
      clib_dlist_init (db->list_pool, session->per_user_index);
      per_user_elt->value = session - db->sessions;
      clib_dlist_addtail (db->list_pool, session->per_user_list_head_index,
			  session->per_user_index);
      session->user_index = user - db->users;
      user->nsessions++;
    }

  session->in_r_addr.as_u32 = in_r_addr->as_u32;
  session->in_r_port = in_r_port;
  session->out_r_addr.as_u32 = out_r_addr->as_u32;
  session->out_r_port = out_r_port;
  session->proto = mapping->proto;
  session->mapping_index = mapping - db->mappings;
  if (opaque_data_len)
    {
      session->opaque_data = vec_new (u8, opaque_data_len);
      clib_memcpy (session->opaque_data, opaque_data, opaque_data_len);
    }

  mapping->nsessions++;

  ctx.now = now;
  ctx.db = db;
  ctx.mapping_index = session->mapping_index;
  ctx.user_index = session->user_index;

  session_key.l_addr.as_u32 = mapping->in_addr.as_u32;
  session_key.l_port = mapping->in_port;
  session_key.r_addr.as_u32 = session->in_r_addr.as_u32;
  session_key.r_port = session->in_r_port;
  session_key.proto = session->proto;
  session_key.tenant_id = mapping->tenant_id;
  kv.key[0] = session_key.as_u64[0];
  kv.key[1] = session_key.as_u64[1];
  kv.value = session - db->sessions;
  clib_bihash_add_or_overwrite_stale_16_8 (&db->session_in2out, &kv,
					   is_session_idle_in2out, &ctx);

  session_key.l_addr.as_u32 = mapping->out_addr.as_u32;
  session_key.l_port = mapping->out_port;
  session_key.r_addr.as_u32 = session->out_r_addr.as_u32;
  session_key.r_port = session->out_r_port;
  session_key.tenant_id = 0;
  kv.key[0] = session_key.as_u64[0];
  kv.key[1] = session_key.as_u64[1];
  clib_bihash_add_or_overwrite_stale_16_8 (&db->session_out2in, &kv,
					   is_session_idle_out2in, &ctx);

  return session;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
