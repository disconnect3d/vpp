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
 * Create a new directory node
 */
int
shmdb_mkdir_vector (shmdb_directory_t *fs, char **pathvector)
{
  int rv = 0;
  char **p;
  hash_pair_t *hp;
  shmdb_inode_t *dir = fs->root;
  shmdb_lock (fs);
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

  return rv;
}

int
shmdb_mkdir (shmdb_directory_t *fs, const char *pathname)
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

/*
 * Look up a path in the directory hierarchy
 */
shmdb_inode_t *shmdb_lookup (shmdb_directory_t *fs, const char *pathname)
{
  hash_pair_t *hp;
  int i;

  assert (fs);
  assert (pathname);

  /* Split path into individual elements */
  char **paths = split_path (pathname);
  shmdb_lock (fs);
  shmdb_inode_t *dir = fs->root;
  vec_foreach_index (i, paths)
  {
    hp = hash_get_pair (dir->dir_vec_by_name, paths[i]);
    if (!hp)
      {
        dir = 0;
        break;
      }
    dir = &fs->root[hp->value[0]];
    if (dir->type != SHMDB_INODE_TYPE_DIR)
      {
        if (i != vec_len (paths) - 1)
          {
            dir = 0;
          }
        break;
      }
  }
  shmdb_unlock (fs);
  split_path_free (paths);
  return dir;
}

/*
 * Create a leaf
 *
 * Input: 1) Name of directory
 *        2) Index of directory
 *        3) Pointer to directory structure
 *
 *        1) Filename
 *        2) Full pathname
 *
 *        Pointer to data object.
 */
// Expect directory to exist?
//
u32
shmdb_create_parent(char *path, void *data)
{
  return 0;
}

#if 0
shmdb_inode_t *
shmdb_create (shmdb_inode_t *dir, char *filename)
{
  assert (dir);
  assert (filename);

  shmdb_inode_t *d;
  pool_get_zero (dir->dir_vec, d);
  assert (d);

  u32 index = d - dir->dir_vec;
  char *n = (char *)format (0, "%s%c", filename, 0);
  assert (n);

  if (!dir->dir_vec_by_name)
    {
      dir->dir_vec_by_name = hash_create_string (0, sizeof (uword));
      assert (dir->dir_vec_by_name);
    }
  hash_set (dir->dir_vec_by_name, n, index);
  d->name = n;
  d->type = type;

  return d;
}
#endif

/*
 * Create a new datastore
 */
shmdb_directory_t *
shmdb_createdb (void)
{
  shmdb_directory_t *fs = clib_mem_alloc (sizeof (*fs));
  clib_memset(fs, 0, sizeof(*fs));
  clib_spinlock_init (&fs->lockp);
  fs->epoch = 0;
  fs->in_progress = 0;
  fs->root = 0;
  shmdb_inode_t *d;
  pool_get_zero (fs->root, d);
  char *n = (char *)format (0, "/%c", 0);
  d->name = n;
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
