#ifndef included_shmdb_h
#define included_shmdb_h

#include <stdint.h>
#include <vppinfra/vec.h>
#include <vppinfra/pool.h>
#include <vppinfra/lock.h>
#include <vppinfra/hash.h>
#include <vpp/stats/stat_segment.h>

/*
 * SHMDB - A shared memory hierarchical KV store.
 *
 * shmdb supports multiple data-stores. A data-store consists of a
 * shmdb_directory_t structure with a pointer to a single pool of
 * inodes containing all the inodes in the database.
 *
 * An inode has a name and a type.
 *
 * A directory inode has a vector of the indicies into the inode
 * pool. The indicies are used to access the elements of the
 * directory. Either content nodes (files), symlinks or
 * sub-directories. A directory inode also has a pointer to a hash
 * that can be used to do a string lookup for names in the directory.
 * E.g. doing a lookup on the path "/sys/nodes/ip4-lookup", means
 * first doing a hash lookup on "sys" in the root inode, then on
 * "nodes" in the "sys" inode and finally on "ip4-lookup" in the
 * "nodes" inode.
 *
 * There are three types of content (file) inodes. "Inline"
 * (SHMDB_INODE_TYPE_INLINE), where a single 64-bit value is stored
 * directly in the inode itself, "Pointer" (SHMDB_INODE_TYPE_POINTER)
 * where the data field points to an arbitrary data structure in
 * shared memory or "symlink" (SHMDB_INODE_TYPE_SYMLINK), where the
 * inode provides an alternative name for an existing node or an index
 * into a vector in another inode.
 *
 * The filesystem meta data uses the VPP pool, vector and string hash
 * data structures. Pools and multi-dimensional vectors are supports
 * as data structures for content (files).
 *
 * The shared memory segment is mapped to different memory address for
 * the server and client. To simplify VPP implementation, VPP uses
 * pointers directly in it's own address space. Clients following
 * pointers in the shared memory segment must calculate the offset
 * between VPP's shared memory segment base address and the client's.
 *
 * Locking: There is a single optimistic lock per filesystem. The lock
 * is implemented by having two atomic variables, one epoch and an
 * in_progress flag. The client must check the in_progress flag and
 * wait until 0, then copy the epoch on start, copy out the data it is
 * interested in, and check the in_progress flag and the epoch. If the
 * in_progress is set or the epoch has increased the operation must be
 * retried. It is the clients responsibility to ensure that adjusted
 * pointers are dealt with in a safe way. I.e. not allowed to point
 * outside of the shared memory segment.
 */

typedef enum {
  SHMDB_INODE_TYPE_DIR = 0,
  SHMDB_INODE_TYPE_INLINE,
  SHMDB_INODE_TYPE_POINTER,
  SHMDB_INODE_TYPE_SYMLINK,
} shmdb_inode_type_t;

typedef struct shmdb_inode shmdb_inode_t;
struct shmdb_inode
{
  shmdb_inode_type_t type;
  union {
    struct {
      u32 *dir_vec; 	/* Vector of indicies into the inode pool */
      uword *dir_vec_by_name;
    };
    u64 value;	/* Inline data */
    void *data;
  };
  char *name;
};

typedef struct shmdb_directory_t
{
  clib_spinlock_t lockp;		/* Used by VPP to ensure single writer */
  volatile uint64_t epoch;		/* Increased when VPP is done writing */
  volatile uint64_t in_progress;	/* VPP sets this when it's writing */
  shmdb_inode_t *root;			/* Pool of all the filesystem's inodes */
} shmdb_directory_t;


/*
 * Shared header first in the shared memory segment.
 */
typedef struct
{
  uint64_t version;
  intptr_t base;
  shmdb_directory_t fs;
} shmdb_segment_shared_header_t;

int shmdb_mkdir(shmdb_directory_t *fs, const char *pathname);
shmdb_inode_t *shmdb_lookup(shmdb_directory_t *fs, const char *pathname);
u32 shmdb_create_pointer (char *path, void *data);

/* Shared memory segment */
void shmdb_lock (shmdb_directory_t *d);
void shmdb_unlock (shmdb_directory_t *d);


shmdb_directory_t *shmdb_createdb (void);

/* Wrappers for vppinfra that allocates from our heap */
#define shmdb_pool_get_aligned(I, P,E,A)			\
do {								\
  shmdb_directory_t *fs = vlib_stat_segment_get_shared_header()->operational_ds;\
  shmdb_lock(fs);\
  shmdb_inode_t *inode = pool_elt_at_index(fs->root, I);	\
  clib_warning("POOL GET ALIGNED CALLED");			\
  pool_get_aligned(P,E,A);					\
  inode->data = P;						\
  shmdb_unlock(fs);\
} while(0)

#endif
