#ifndef included_shmdb_inlines_h
#define included_shmdb_inlines_h

#include <assert.h>

/*
 * Split a path string into a vector of path elements
 */
static inline char **
split_path(const char *pathname)
{
  assert(pathname);
  char **result = 0;
  const char *p = pathname;
  size_t s;
  const char *end = rindex(pathname, '\0');
  while (p < end) {
    s = strcspn(p, "/");
    if (s > 0) {
      char *slice = 0;
      vec_add(slice, p, s);
      vec_add1(result, slice);
    }
    p  = p + s + 1;
  }
  return result;
}

static inline void
split_path_free(char **paths)
{
  assert(*paths);
  char **p;
  vec_foreach(p, paths) {
    vec_free(*p);
  }
  vec_free(paths);
}

/* Wrappers for vppinfra that allocates from our heap */
#define shmdb_pool_get_aligned(DS,I,P,E,A)			\
do {								\
  shmdb_lock(DS);						\
  shmdb_inode_t *inode = pool_elt_at_index(DS->root, I);	\
  void *oldheap = clib_mem_set_heap(DS->heap);			\
  pool_get_aligned(P,E,A);					\
  inode->data = P;						\
  shmdb_unlock(DS);						\
  clib_mem_set_heap(oldheap);					\
} while(0)

#define shmdb_pool_put(DS,I,P,E)				\
do {								\
  shmdb_lock(DS);						\
  shmdb_inode_t *inode = pool_elt_at_index(DS->root, I);	\
  void *oldheap = clib_mem_set_heap(DS->heap);			\
  pool_put(P,E);						\
  inode->data = P;						\
  shmdb_unlock(DS);						\
  clib_mem_set_heap(oldheap);					\
} while(0)

#endif
