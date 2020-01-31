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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "shmdb.h"
#include "shmdb_inlines.h"

/*
 *  Used only by VPP writers
 */
void shmdb_lock (shmdb_directory_t *d)
{
  assert (d);
  clib_spinlock_lock (&d->lockp);
  d->in_progress = 1;
}

void shmdb_unlock (shmdb_directory_t *d)
{
  assert (d);
  d->epoch++;
  d->in_progress = 0;
  clib_spinlock_unlock (&d->lockp);
}

/*
 * Create the directory nodes for a path vector
 */
int
shmdb_mkdir_vector (shmdb_directory_t *fs, char **pathvector)
{
  int rv = 0;
  char **p;
  hash_pair_t *hp;
  shmdb_inode_t *dir = fs->root;
  shmdb_lock (fs);
  void* oldheap = clib_mem_set_heap(fs->heap);
  vec_foreach (p, pathvector)
  {
    hp = hash_get_pair (dir->dir_vec_by_name, *p);
    if (!hp)
      {
        if (!dir->dir_vec_by_name)
          {
            dir->dir_vec_by_name =
                hash_create_string (0, sizeof (uword));
          }

        shmdb_inode_t *d;
	u32 parentidx = dir - fs->root;
        pool_get_zero (fs->root, d);

	/* parent might have moved */
	dir = pool_elt_at_index(fs->root, parentidx);
        u32 index = d - fs->root;
        char *n = (char *)format (0, "%s%c", *p, 0);
        hash_set (dir->dir_vec_by_name, n, index);
	vec_add1(dir->dir_vec, index);
        d->name = n;
        dir = d;
      }
    else
      {
        dir = &fs->root[hp->value[0]];
        if (dir->type != SHMDB_INODE_TYPE_DIR)
          {
            rv = -1;
            break;
          }
      }
  }
  shmdb_unlock (fs);
  clib_mem_set_heap(oldheap);
  return rv;
}

/*
 * Create directory nodes for a path
 */
int
shmdb_mkdir (shmdb_directory_t *fs, char *pathname)
{
  int rv;
  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  assert(paths);

  rv = shmdb_mkdir_vector(fs, paths);

  split_path_free (paths);
  return rv;
}

u32
shmdb_lookup_index_vector (shmdb_directory_t *fs, char **paths)
{
  hash_pair_t *hp;
  int i;
  u32 index = -1;
  shmdb_lock (fs);
  shmdb_inode_t *dir = fs->root;
  vec_foreach_index (i, paths)
  {
    hp = hash_get_pair (dir->dir_vec_by_name, paths[i]);
    if (!hp) {
      index = -1;
      break;
    }
    index = hp->value[0];
    dir = pool_elt_at_index(fs->root, index);
  }
  shmdb_unlock (fs);
  return index;
}

u32
shmdb_lookup_index (shmdb_directory_t *fs, char *pathname)
{
  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  assert(paths);

  u32 index = shmdb_lookup_index_vector(fs, paths);

  split_path_free (paths);
  return index;
}

u32
shmdb_lookup_dir_index (shmdb_directory_t *fs, u32 directory_index, const char *filename)
{
  assert (fs);
  assert (filename);
  hash_pair_t *hp;
  shmdb_inode_t *dir = pool_elt_at_index(fs->root, directory_index);
  assert(dir);
  hp = hash_get_pair (dir->dir_vec_by_name, filename);
  if (!hp) return -1;
  return hp->value[0];
}

shmdb_inode_t *
shmdb_lookup_vector (shmdb_directory_t *fs, char **paths)
{
  u32 index = shmdb_lookup_index_vector(fs, paths);
  if (index == ~0) return 0;
  shmdb_inode_t *dir = pool_elt_at_index(fs->root, index);
  return dir;
}

/*
 * Look up a path in the directory hierarchy
 */
shmdb_inode_t *
shmdb_lookup (shmdb_directory_t *fs, char *pathname)
{
  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  assert(paths);

  shmdb_inode_t *dir = shmdb_lookup_vector(fs, paths);

  split_path_free (paths);
  return dir;
}

static void
shmdb_attach(shmdb_directory_t *fs, u32 dirindex, char *filename, shmdb_inode_t *d, u32 index)
{
  shmdb_inode_t *dir = pool_elt_at_index(fs->root, dirindex);
  assert(dir);

  /* Copy name */
  char *n = (char *)format (0, "%s%c", filename, 0);

  /* Add filename to directory */
  if (!dir->dir_vec_by_name)
    {
      dir->dir_vec_by_name =
	hash_create_string (0, sizeof (uword));
    }

  hash_set (dir->dir_vec_by_name, n, index);
  vec_add1(dir->dir_vec, index);
  d->name = n;
}

/*
 * Create a pointer leaf
 * pathname is the full path, the directory must exist.
 */
u32
shmdb_create_pointer (shmdb_directory_t *fs, char *directory, char *filename, void *data)
{
  u32 dirindex = shmdb_lookup_index(fs, directory);
  if (dirindex == ~0) return -1;

  /* Validate that filename does not exist */
  u32 fileindex = shmdb_lookup_dir_index (fs, dirindex, filename);
  if (fileindex != ~0) return -1;

  void* oldheap = clib_mem_set_heap(fs->heap);
  shmdb_inode_t *d;
  pool_get_zero (fs->root, d);
  u32 index = d - fs->root;
  d->type = SHMDB_INODE_TYPE_POINTER;
  d->data = data;

  shmdb_attach(fs, dirindex, filename, d, index);
  clib_mem_set_heap(oldheap);
  return index;
}

/*
 * Create an inline leaf
 * pathname is the full path, the directory must exist.
 */
u32
shmdb_create_inline (shmdb_directory_t *fs, char *directory, char *filename, u64 value)
{
  u32 dirindex = shmdb_lookup_index(fs, directory);
  if (dirindex == ~0) return -1;

  /* Validate that filename does not exist */
  u32 fileindex = shmdb_lookup_dir_index (fs, dirindex, filename);
  if (fileindex != ~0) return -1;

  void* oldheap = clib_mem_set_heap(fs->heap);
  shmdb_inode_t *d;
  pool_get_zero (fs->root, d);
  u32 index = d - fs->root;
  d->type = SHMDB_INODE_TYPE_INLINE;
  d->value = value;

  shmdb_attach(fs, dirindex, filename, d, index);
  clib_mem_set_heap(oldheap);
  return index;
}

/*
 * Create a symlink to another leaf
 */
u32
shmdb_create_symlink (shmdb_directory_t *fs, char *directory, char *filename, u32 inode_index, u32 inode_data_index)
{
  u32 dirindex = shmdb_lookup_index(fs, directory);
  if (dirindex == ~0) return -1;

  /* Validate that filename does not exist */
  u32 fileindex = shmdb_lookup_dir_index (fs, dirindex, filename);
  if (fileindex != ~0) return -1;

  void* oldheap = clib_mem_set_heap(fs->heap);
  shmdb_inode_t *d;
  pool_get_zero (fs->root, d);
  u32 index = d - fs->root;
  d->type = SHMDB_INODE_TYPE_SYMLINK;
  d->inode_index = inode_index;
  d->inode_data_index = inode_data_index;

  shmdb_attach(fs, dirindex, filename, d, index);
  clib_mem_set_heap(oldheap);
  return index;
}

/*
 * Create a new datastore
 */
shmdb_directory_t *
shmdb_createdb (void* heap)
{
  void* oldheap = clib_mem_set_heap(heap);
  shmdb_directory_t *fs = clib_mem_alloc (sizeof (*fs));
  clib_memset(fs, 0, sizeof(*fs));
  clib_spinlock_init (&fs->lockp);
  fs->epoch = 0;
  fs->in_progress = 0;
  fs->root = 0;
  fs->heap = heap;
  shmdb_inode_t *d;
  pool_get_zero (fs->root, d);
  char *n = (char *)format (0, "/%c", 0);
  d->name = n;
  clib_mem_set_heap(oldheap);
  return fs;
}

/*
 * Destroy datastore
 */
void
shmdb_destroydb (shmdb_directory_t *root)
{
  clib_warning("Not implemented yet");
}
