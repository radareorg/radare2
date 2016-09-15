/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * mksquashfs.c
 */

#if 0
#define _GNU_SOURCE 1

#define FALSE 0
#define TRUE 1

#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>
#include <math.h>
#include <regex.h>
#include <fnmatch.h>
#include <sys/wait.h>

#ifndef linux
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#include <sys/sysctl.h>
#else
#include <endian.h>
#include <sys/sysinfo.h>
#endif

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			if(progress_enabled) \
				printf("\n"); \
			printf("mksquashfs: "s, ## args); \
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define INFO(s, args...) \
		do {\
			 if(!silent)\
				printf("mksquashfs: "s, ## args);\
		} while(0)

#define ERROR(s, args...) \
		do {\
			pthread_mutex_lock(&progress_mutex); \
			if(progress_enabled) \
				fprintf(stderr, "\n"); \
			fprintf(stderr, s, ## args);\
			pthread_mutex_unlock(&progress_mutex); \
		} while(0)

#define EXIT_MKSQUASHFS() \
		do {\
			if(restore)\
				restorefs();\
			if(delete && destination_file && !block_device)\
				unlink(destination_file);\
			exit(1);\
		} while(0)

#define BAD_ERROR(s, args...) \
		do {\
			pthread_mutex_lock(&progress_mutex); \
			if(progress_enabled) \
				fprintf(stderr, "\n"); \
			fprintf(stderr, "FATAL ERROR:" s, ##args);\
			pthread_mutex_unlock(&progress_mutex); \
			EXIT_MKSQUASHFS();\
		} while(0)

#include "squashfs_fs.h"
#include "squashfs_swap.h"
#include "mksquashfs.h"
#include "sort.h"
#include "pseudo.h"
#include "compressor.h"
#include "xattr.h"
#include "action.h"

int delete = FALSE;
int fd;
int cur_uncompressed = 0, estimated_uncompressed = 0;
int columns;

/* filesystem flags for building */
int comp_opts = FALSE;
int no_xattrs = XATTR_DEF, noX = 0;
int duplicate_checking = 1, noF = 0, no_fragments = 0, always_use_fragments = 0;
int noI = 0, noD = 0;
int silent = TRUE;
long long global_uid = -1, global_gid = -1;
int exportable = TRUE;
int progress = TRUE;
int progress_enabled = FALSE;
int sparse_files = TRUE;
int old_exclude = TRUE;
int use_regex = FALSE;
int first_freelist = TRUE;

/* superblock attributes */
int block_size = SQUASHFS_FILE_SIZE, block_log;
unsigned int id_count = 0;
int file_count = 0, sym_count = 0, dev_count = 0, dir_count = 0, fifo_count = 0,
	sock_count = 0;

/* write position within data section */
long long bytes = 0, total_bytes = 0;

/* in memory directory table - possibly compressed */
char *directory_table = NULL;
unsigned int directory_bytes = 0, directory_size = 0, total_directory_bytes = 0;

/* cached directory table */
char *directory_data_cache = NULL;
unsigned int directory_cache_bytes = 0, directory_cache_size = 0;

/* in memory inode table - possibly compressed */
char *inode_table = NULL;
unsigned int inode_bytes = 0, inode_size = 0, total_inode_bytes = 0;

/* cached inode table */
char *data_cache = NULL;
unsigned int cache_bytes = 0, cache_size = 0, inode_count = 0;

/* inode lookup table */
squashfs_inode *inode_lookup_table = NULL;

/* in memory directory data */
#define I_COUNT_SIZE		128
#define DIR_ENTRIES		32
#define INODE_HASH_SIZE		65536
#define INODE_HASH_MASK		(INODE_HASH_SIZE - 1)
#define INODE_HASH(dev, ino)	(ino & INODE_HASH_MASK)

struct cached_dir_index {
	struct squashfs_dir_index	index;
	char				*name;
};

struct directory {
	unsigned int		start_block;
	unsigned int		size;
	unsigned char		*buff;
	unsigned char		*p;
	unsigned int		entry_count;
	unsigned char		*entry_count_p;
	unsigned int		i_count;
	unsigned int		i_size;
	struct cached_dir_index	*index;
	unsigned char		*index_count_p;
	unsigned int		inode_number;
};

struct inode_info *inode_info[INODE_HASH_SIZE];

/* hash tables used to do fast duplicate searches in duplicate check */
struct file_info *dupl[65536];
int dup_files = 0;

/* exclude file handling */
/* list of exclude dirs/files */
struct exclude_info {
	dev_t			st_dev;
	ino_t			st_ino;
};

#define EXCLUDE_SIZE 8192
int exclude = 0;
struct exclude_info *exclude_paths = NULL;
int old_excluded(char *filename, struct stat *buf);

struct path_entry {
	char *name;
	regex_t *preg;
	struct pathname *paths;
};

struct pathname {
	int names;
	struct path_entry *name;
};

struct pathnames {
	int count;
	struct pathname *path[0];
};
#define PATHS_ALLOC_SIZE 10

struct pathnames *paths = NULL;
struct pathname *path = NULL;
struct pathname *stickypath = NULL;
int excluded(struct pathnames *paths, char *name, struct pathnames **new);

/* fragment block data structures */
int fragments = 0;

struct fragment {
	unsigned int		index;
	int			offset;
	int			size;
};

#define FRAG_SIZE 32768
#define FRAG_INDEX (1LL << 32)

struct squashfs_fragment_entry *fragment_table = NULL;
int fragments_outstanding = 0;

/* current inode number for directories and non directories */
unsigned int dir_inode_no = 1;
unsigned int inode_no = 0;
unsigned int root_inode_number = 0;

/* list of source dirs/files */
int source = 0;
char **source_path;

/* list of root directory entries read from original filesystem */
int old_root_entries = 0;
struct old_root_entry_info {
	char			*name;
	struct inode_info	inode;
};
struct old_root_entry_info *old_root_entry;

/* in memory file info */
struct file_info {
	long long		file_size;
	long long		bytes;
	unsigned short		checksum;
	unsigned short		fragment_checksum;
	long long		start;
	unsigned int		*block_list;
	struct file_info	*next;
	struct fragment		*fragment;
	char			checksum_flag;
};

/* count of how many times SIGINT or SIGQUIT has been sent */
int interrupted = 0;

/* flag if we're restoring existing filesystem */
int restoring = 0;

/* restore orignal filesystem state if appending to existing filesystem is
 * cancelled */
jmp_buf env;
char *sdata_cache, *sdirectory_data_cache, *sdirectory_compressed;

long long sbytes, stotal_bytes;

unsigned int sinode_bytes, scache_bytes, sdirectory_bytes,
	sdirectory_cache_bytes, sdirectory_compressed_bytes,
	stotal_inode_bytes, stotal_directory_bytes,
	sinode_count = 0, sfile_count, ssym_count, sdev_count,
	sdir_count, sfifo_count, ssock_count, sdup_files;
int sfragments;
int restore = 0;
int threads;

/* flag whether destination file is a block device */
int block_device = 0;

/* flag indicating whether files are sorted using sort list(s) */
int sorted = 0;

/* save destination file name for deleting on error */
char *destination_file = NULL;

/* recovery file for abnormal exit on appending */
char recovery_file[1024] = "";
int recover = TRUE;

/* struct describing a cache entry passed between threads */
struct file_buffer {
	struct cache *cache;
	struct file_buffer *hash_next;
	struct file_buffer *hash_prev;
	struct file_buffer *free_next;
	struct file_buffer *free_prev;
	struct file_buffer *next;
	long long file_size;
	long long index;
	long long block;
	long long sequence;
	int size;
	int c_byte;
	char keep;
	char used;
	char fragment;
	char error;
	char noD;
	char data[0];
};


/* struct describing queues used to pass data between threads */
struct queue {
	int			size;
	int			readp;
	int			writep;
	pthread_mutex_t		mutex;
	pthread_cond_t		empty;
	pthread_cond_t		full;
	void			**data;
};


/* in memory uid tables */
#define ID_ENTRIES 256
#define ID_HASH(id) (id & (ID_ENTRIES - 1))
#define ISA_UID 1
#define ISA_GID 2
struct id {
	unsigned int id;
	int	index;
	char	flags;
	struct id *next;
};
struct id *id_hash_table[ID_ENTRIES];
struct id *id_table[SQUASHFS_IDS], *sid_table[SQUASHFS_IDS];
unsigned int uid_count = 0, guid_count = 0;
unsigned int sid_count = 0, suid_count = 0, sguid_count = 0;

struct cache *reader_buffer, *writer_buffer, *fragment_buffer;
struct queue *to_reader, *from_reader, *to_writer, *from_writer, *from_deflate,
	*to_frag;
pthread_t *thread, *deflator_thread, *frag_deflator_thread, progress_thread;
pthread_mutex_t	fragment_mutex;
pthread_cond_t fragment_waiting;
pthread_mutex_t	pos_mutex;
pthread_mutex_t progress_mutex;
pthread_cond_t progress_wait;
int rotate = 0;
struct pseudo *pseudo = NULL;

/* user options that control parallelisation */
int processors = -1;
/* default size of output buffer in Mbytes */
#define WRITER_BUFFER_DEFAULT 512
/* default size of input buffer in Mbytes */
#define READER_BUFFER_DEFAULT 64
/* default size of fragment buffer in Mbytes */
#define FRAGMENT_BUFFER_DEFAULT 64
int writer_buffer_size;

/* compression operations */
static struct compressor *comp;
int compressor_opts_parsed = 0;
void *stream = NULL;

/* xattr stats */
unsigned int xattr_bytes = 0, total_xattr_bytes = 0;

char *read_from_disk(long long start, unsigned int avail_bytes);
void add_old_root_entry(char *name, squashfs_inode inode, int inode_number,
	int type);
extern struct compressor  *read_super(int fd, struct squashfs_super_block *sBlk,
	char *source);
extern long long read_filesystem(char *root_name, int fd,
	struct squashfs_super_block *sBlk, char **cinode_table, char **data_cache,
	char **cdirectory_table, char **directory_data_cache,
	unsigned int *last_directory_block, unsigned int *inode_dir_offset,
	unsigned int *inode_dir_file_size, unsigned int *root_inode_size,
	unsigned int *inode_dir_start_block, int *file_count, int *sym_count,
	int *dev_count, int *dir_count, int *fifo_count, int *sock_count,
	long long *uncompressed_file, unsigned int *uncompressed_inode,
	unsigned int *uncompressed_directory,
	unsigned int *inode_dir_inode_number,
	unsigned int *inode_dir_parent_inode,
	void (push_directory_entry)(char *, squashfs_inode, int, int),
	struct squashfs_fragment_entry **fragment_table,
	squashfs_inode **inode_lookup_table);
extern int read_sort_file(char *filename, int source, char *source_path[]);
extern void sort_files_and_write(struct dir_info *dir);
struct file_info *duplicate(long long file_size, long long bytes,
	unsigned int **block_list, long long *start, struct fragment **fragment,
	struct file_buffer *file_buffer, int blocks, unsigned short checksum,
	unsigned short fragment_checksum, int checksum_flag);
struct dir_info *dir_scan1(char *, struct pathnames *, int (_readdir)(char *,
	char *, struct dir_info *), int);
struct dir_info *dir_scan2(struct dir_info *dir, struct pseudo *pseudo, int);
void dir_scan3(squashfs_inode *inode, struct dir_info *dir_info);
struct file_info *add_non_dup(long long file_size, long long bytes,
	unsigned int *block_list, long long start, struct fragment *fragment,
	unsigned short checksum, unsigned short fragment_checksum,
	int checksum_flag);
extern int generate_file_priorities(struct dir_info *dir, int priority,
	struct stat *buf);
extern struct priority_entry *priority_list[65536];
void progress_bar(long long current, long long max, int columns);
long long generic_write_table(int, void *, int, void *, int);
void restorefs();


struct queue *queue_init(int size)
{
	struct queue *queue = malloc(sizeof(struct queue));

	if(queue == NULL)
		goto failed;

	queue->data = malloc(sizeof(void *) * (size + 1));
	if(queue->data == NULL) {
		free(queue);
		goto failed;
	}

	queue->size = size + 1;
	queue->readp = queue->writep = 0;
	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->empty, NULL);
	pthread_cond_init(&queue->full, NULL);

	return queue;

failed:
	BAD_ERROR("Out of memory in queue_init\n");
}


void queue_put(struct queue *queue, void *data)
{
	int nextp;

	pthread_mutex_lock(&queue->mutex);

	while((nextp = (queue->writep + 1) % queue->size) == queue->readp)
		pthread_cond_wait(&queue->full, &queue->mutex);

	queue->data[queue->writep] = data;
	queue->writep = nextp;
	pthread_cond_signal(&queue->empty);
	pthread_mutex_unlock(&queue->mutex);
}


void *queue_get(struct queue *queue)
{
	void *data;
	pthread_mutex_lock(&queue->mutex);

	while(queue->readp == queue->writep)
		pthread_cond_wait(&queue->empty, &queue->mutex);

	data = queue->data[queue->readp];
	queue->readp = (queue->readp + 1) % queue->size;
	pthread_cond_signal(&queue->full);
	pthread_mutex_unlock(&queue->mutex);

	return data;
}


/* Cache status struct.  Caches are used to keep
  track of memory buffers passed between different threads */
struct cache {
	int	max_buffers;
	int	count;
	int	buffer_size;
	pthread_mutex_t	mutex;
	pthread_cond_t wait_for_free;
	struct file_buffer *free_list;
	struct file_buffer *hash_table[65536];
};


#define INSERT_LIST(NAME, TYPE) \
void insert_##NAME##_list(TYPE **list, TYPE *entry) { \
	if(*list) { \
		entry->NAME##_next = *list; \
		entry->NAME##_prev = (*list)->NAME##_prev; \
		(*list)->NAME##_prev->NAME##_next = entry; \
		(*list)->NAME##_prev = entry; \
	} else { \
		*list = entry; \
		entry->NAME##_prev = entry->NAME##_next = entry; \
	} \
}


#define REMOVE_LIST(NAME, TYPE) \
void remove_##NAME##_list(TYPE **list, TYPE *entry) { \
	if(entry->NAME##_prev == entry && entry->NAME##_next == entry) { \
		/* only this entry in the list */ \
		*list = NULL; \
	} else if(entry->NAME##_prev != NULL && entry->NAME##_next != NULL) { \
		/* more than one entry in the list */ \
		entry->NAME##_next->NAME##_prev = entry->NAME##_prev; \
		entry->NAME##_prev->NAME##_next = entry->NAME##_next; \
		if(*list == entry) \
			*list = entry->NAME##_next; \
	} \
	entry->NAME##_prev = entry->NAME##_next = NULL; \
}


#define CALCULATE_HASH(start)	(start & 0xffff) \


/* Called with the cache mutex held */
void insert_hash_table(struct cache *cache, struct file_buffer *entry)
{
	int hash = CALCULATE_HASH(entry->index);

	entry->hash_next = cache->hash_table[hash];
	cache->hash_table[hash] = entry;
	entry->hash_prev = NULL;
	if(entry->hash_next)
		entry->hash_next->hash_prev = entry;
}


/* Called with the cache mutex held */
void remove_hash_table(struct cache *cache, struct file_buffer *entry)
{
	if(entry->hash_prev)
		entry->hash_prev->hash_next = entry->hash_next;
	else
		cache->hash_table[CALCULATE_HASH(entry->index)] =
			entry->hash_next;
	if(entry->hash_next)
		entry->hash_next->hash_prev = entry->hash_prev;

	entry->hash_prev = entry->hash_next = NULL;
}


/* Called with the cache mutex held */
INSERT_LIST(free, struct file_buffer)

/* Called with the cache mutex held */
REMOVE_LIST(free, struct file_buffer)


struct cache *cache_init(int buffer_size, int max_buffers)
{
	struct cache *cache = malloc(sizeof(struct cache));

	if(cache == NULL)
		BAD_ERROR("Out of memory in cache_init\n");

	cache->max_buffers = max_buffers;
	cache->buffer_size = buffer_size;
	cache->count = 0;
	cache->free_list = NULL;
	memset(cache->hash_table, 0, sizeof(struct file_buffer *) * 65536);
	pthread_mutex_init(&cache->mutex, NULL);
	pthread_cond_init(&cache->wait_for_free, NULL);

	return cache;
}


struct file_buffer *cache_lookup(struct cache *cache, long long index)
{
	/* Lookup block in the cache, if found return with usage count
 	 * incremented, if not found return NULL */
	int hash = CALCULATE_HASH(index);
	struct file_buffer *entry;

	pthread_mutex_lock(&cache->mutex);

	for(entry = cache->hash_table[hash]; entry; entry = entry->hash_next)
		if(entry->index == index)
			break;

	if(entry) {
		/* found the block in the cache, increment used count and
 		 * if necessary remove from free list so it won't disappear
 		 */
		entry->used ++;
		remove_free_list(&cache->free_list, entry);
	}

	pthread_mutex_unlock(&cache->mutex);

	return entry;
}


struct file_buffer *cache_get(struct cache *cache, long long index, int keep)
{
	/* Get a free block out of the cache indexed on index. */
	struct file_buffer *entry;

	pthread_mutex_lock(&cache->mutex);

	while(1) {
		/* first try to get a block from the free list */
		if(first_freelist && cache->free_list) {
			/* a block on the free_list is a "keep" block */
			entry = cache->free_list;
			remove_free_list(&cache->free_list, entry);
			remove_hash_table(cache, entry);
			break;
		} else if(cache->count < cache->max_buffers) {
			/* next try to allocate new block */
			entry = malloc(sizeof(struct file_buffer) +
				cache->buffer_size);
			if(entry == NULL)
				goto failed;
			entry->cache = cache;
			entry->free_prev = entry->free_next = NULL;
			cache->count ++;
			break;
		} else if(!first_freelist && cache->free_list) {
			/* a block on the free_list is a "keep" block */
			entry = cache->free_list;
			remove_free_list(&cache->free_list, entry);
			remove_hash_table(cache, entry);
			break;
		} else
			/* wait for a block */
			pthread_cond_wait(&cache->wait_for_free, &cache->mutex);
	}

	/* initialise block and if a keep block insert into the hash table */
	entry->used = 1;
	entry->error = FALSE;
	entry->keep = keep;
	if(keep) {
		entry->index = index;
		insert_hash_table(cache, entry);
	}
	pthread_mutex_unlock(&cache->mutex);

	return entry;

failed:
	pthread_mutex_unlock(&cache->mutex);
	BAD_ERROR("Out of memory in cache_get\n");
}


void cache_rehash(struct file_buffer *entry, long long index)
{
	struct cache *cache = entry->cache;

	pthread_mutex_lock(&cache->mutex);
	if(entry->keep)
		remove_hash_table(cache, entry);
	entry->keep = TRUE;
	entry->index = index;
	insert_hash_table(cache, entry);
	pthread_mutex_unlock(&cache->mutex);
}


void cache_block_put(struct file_buffer *entry)
{
	struct cache *cache;

	/* finished with this cache entry, once the usage count reaches zero it
 	 * can be reused and if a keep block put onto the free list.  As keep
 	 * blocks remain accessible via the hash table they can be found
 	 * getting a new lease of life before they are reused. */

	if(entry == NULL)
		return;

	cache = entry->cache;

	pthread_mutex_lock(&cache->mutex);

	entry->used --;
	if(entry->used == 0) {
		if(entry->keep)
			insert_free_list(&cache->free_list, entry);
		else {
			free(entry);
			cache->count --;
		}

		/* One or more threads may be waiting on this block */
		pthread_cond_signal(&cache->wait_for_free);
	}

	pthread_mutex_unlock(&cache->mutex);
}


#define MKINODE(A)	((squashfs_inode)(((squashfs_inode) inode_bytes << 16) \
			+ (((char *)A) - data_cache)))


inline void inc_progress_bar()
{
	cur_uncompressed ++;
}


inline void update_progress_bar()
{
	pthread_mutex_lock(&progress_mutex);
	pthread_cond_signal(&progress_wait);
	pthread_mutex_unlock(&progress_mutex);
}


inline void waitforthread(int i)
{
	TRACE("Waiting for thread %d\n", i);
	while(thread[i] != 0)
		sched_yield();
}


void restorefs()
{
	int i;

	if(thread == NULL || thread[0] == 0)
		return;

	if(restoring++)
		/*
		 * Recursive failure when trying to restore filesystem!
		 * Nothing to do except to exit, otherwise we'll just appear
		 * to hang.  The user should be able to restore from the
		 * recovery file (which is why it was added, in case of
		 * catastrophic failure in Mksquashfs)
		 */
		exit(1);

	ERROR("Exiting - restoring original filesystem!\n\n");

	for(i = 0; i < 2 + processors * 2; i++)
		if(thread[i])
			pthread_kill(thread[i], SIGUSR1);
	for(i = 0; i < 2 + processors * 2; i++)
		waitforthread(i);
	TRACE("All threads in signal handler\n");
	bytes = sbytes;
	memcpy(data_cache, sdata_cache, cache_bytes = scache_bytes);
	memcpy(directory_data_cache, sdirectory_data_cache,
		sdirectory_cache_bytes);
	directory_cache_bytes = sdirectory_cache_bytes;
	inode_bytes = sinode_bytes;
	directory_bytes = sdirectory_bytes;
 	memcpy(directory_table + directory_bytes, sdirectory_compressed,
		sdirectory_compressed_bytes);
 	directory_bytes += sdirectory_compressed_bytes;
	total_bytes = stotal_bytes;
	total_inode_bytes = stotal_inode_bytes;
	total_directory_bytes = stotal_directory_bytes;
	inode_count = sinode_count;
	file_count = sfile_count;
	sym_count = ssym_count;
	dev_count = sdev_count;
	dir_count = sdir_count;
	fifo_count = sfifo_count;
	sock_count = ssock_count;
	dup_files = sdup_files;
	fragments = sfragments;
	id_count = sid_count;
	restore_xattrs();
	longjmp(env, 1);
}


void sighandler()
{
	if(++interrupted > 2)
		return;
	if(interrupted == 2)
		restorefs();
	else {
		ERROR("Interrupting will restore original filesystem!\n");
		ERROR("Interrupt again to quit\n");
	}
}


void sighandler2()
{
	EXIT_MKSQUASHFS();
}


void sigusr1_handler()
{
	int i;
	sigset_t sigmask;
	pthread_t thread_id = pthread_self();

	for(i = 0; i < (2 + processors * 2) && thread[i] != thread_id; i++);
	thread[i] = (pthread_t) 0;

	TRACE("Thread %d(%p) in sigusr1_handler\n", i, &thread_id);

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGQUIT);
	sigaddset(&sigmask, SIGUSR1);
	while(1) {
		sigsuspend(&sigmask);
		TRACE("After wait in sigusr1_handler :(\n");
	}
}


void sigwinch_handler()
{
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			printf("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
}


void sigalrm_handler()
{
	rotate = (rotate + 1) % 4;
}


int mangle2(void *strm, char *d, char *s, int size,
	int block_size, int uncompressed, int data_block)
{
	int error, c_byte = 0;

	if(!uncompressed) {
		c_byte = compressor_compress(comp, strm, d, s, size, block_size,
			 &error);
		if(c_byte == -1)
			BAD_ERROR("mangle2:: %s compress failed with error "
				"code %d\n", comp->name, error);
	}

	if(c_byte == 0 || c_byte >= size) {
		memcpy(d, s, size);
		return size | (data_block ? SQUASHFS_COMPRESSED_BIT_BLOCK :
			SQUASHFS_COMPRESSED_BIT);
	}

	return c_byte;
}


int mangle(char *d, char *s, int size, int block_size,
	int uncompressed, int data_block)
{
	return mangle2(stream, d, s, size, block_size, uncompressed,
		data_block);
}


void *get_inode(int req_size)
{
	int data_space;
	unsigned short c_byte;

	while(cache_bytes >= SQUASHFS_METADATA_SIZE) {
		if((inode_size - inode_bytes) <
				((SQUASHFS_METADATA_SIZE << 1)) + 2) {
			void *it = realloc(inode_table, inode_size +
				(SQUASHFS_METADATA_SIZE << 1) + 2);
			if(it == NULL) {
				goto failed;
			}
			inode_table = it;
			inode_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
		}

		c_byte = mangle(inode_table + inode_bytes + BLOCK_OFFSET,
			data_cache, SQUASHFS_METADATA_SIZE,
			SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Inode block @ 0x%x, size %d\n", inode_bytes, c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte, inode_table + inode_bytes, 1);
		inode_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) + BLOCK_OFFSET;
		total_inode_bytes += SQUASHFS_METADATA_SIZE + BLOCK_OFFSET;
		memmove(data_cache, data_cache + SQUASHFS_METADATA_SIZE,
			cache_bytes - SQUASHFS_METADATA_SIZE);
		cache_bytes -= SQUASHFS_METADATA_SIZE;
	}

	data_space = (cache_size - cache_bytes);
	if(data_space < req_size) {
			int realloc_size = cache_size == 0 ?
				((req_size + SQUASHFS_METADATA_SIZE) &
				~(SQUASHFS_METADATA_SIZE - 1)) : req_size -
				data_space;

			void *dc = realloc(data_cache, cache_size +
				realloc_size);
			if(dc == NULL) {
				goto failed;
			}
			cache_size += realloc_size;
			data_cache = dc;
	}

	cache_bytes += req_size;

	return data_cache + cache_bytes - req_size;

failed:
	BAD_ERROR("Out of memory in inode table reallocation!\n");
}


int read_bytes(int fd, void *buff, int bytes)
{
	int res, count;

	for(count = 0; count < bytes; count += res) {
		res = read(fd, buff + count, bytes - count);
		if(res < 1) {
			if(res == 0)
				goto bytes_read;
			else if(errno != EINTR) {
				ERROR("Read failed because %s\n",
						strerror(errno));
				return -1;
			} else
				res = 0;
		}
	}

bytes_read:
	return count;
}


int read_fs_bytes(int fd, long long byte, int bytes, void *buff)
{
	off_t off = byte;

	TRACE("read_fs_bytes: reading from position 0x%llx, bytes %d\n",
		byte, bytes);

	pthread_mutex_lock(&pos_mutex);
	if(lseek(fd, off, SEEK_SET) == -1) {
		ERROR("Lseek on destination failed because %s\n",
			strerror(errno));
		goto failed;
	}

	if(read_bytes(fd, buff, bytes) < bytes) {
		ERROR("Read on destination failed\n");
		goto failed;
	}

	pthread_mutex_unlock(&pos_mutex);
	return 1;

failed:
	pthread_mutex_unlock(&pos_mutex);
	return 0;
}


int write_bytes(int fd, void *buff, int bytes)
{
	int res, count;

	for(count = 0; count < bytes; count += res) {
		res = write(fd, buff + count, bytes - count);
		if(res == -1) {
			if(errno != EINTR) {
				ERROR("Write failed because %s\n",
						strerror(errno));
				return -1;
			}
			res = 0;
		}
	}

	return 0;
}


void write_destination(int fd, long long byte, int bytes, void *buff)
{
	off_t off = byte;

	if(!restoring)
		pthread_mutex_lock(&pos_mutex);

	if(lseek(fd, off, SEEK_SET) == -1)
		BAD_ERROR("Lseek on destination failed because %s\n",
			strerror(errno));

	if(write_bytes(fd, buff, bytes) == -1)
		BAD_ERROR("Write on destination failed\n");
	
	if(!restoring)
		pthread_mutex_unlock(&pos_mutex);
}


long long write_inodes()
{
	unsigned short c_byte;
	int avail_bytes;
	char *datap = data_cache;
	long long start_bytes = bytes;

	while(cache_bytes) {
		if(inode_size - inode_bytes <
				((SQUASHFS_METADATA_SIZE << 1) + 2)) {
			void *it = realloc(inode_table, inode_size +
				((SQUASHFS_METADATA_SIZE << 1) + 2));
			if(it == NULL) {
				BAD_ERROR("Out of memory in inode table "
					"reallocation!\n");
			}
			inode_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
			inode_table = it;
		}
		avail_bytes = cache_bytes > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : cache_bytes;
		c_byte = mangle(inode_table + inode_bytes + BLOCK_OFFSET, datap,
			avail_bytes, SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Inode block @ 0x%x, size %d\n", inode_bytes, c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte, inode_table + inode_bytes, 1); 
		inode_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) + BLOCK_OFFSET;
		total_inode_bytes += avail_bytes + BLOCK_OFFSET;
		datap += avail_bytes;
		cache_bytes -= avail_bytes;
	}

	write_destination(fd, bytes, inode_bytes,  inode_table);
	bytes += inode_bytes;

	return start_bytes;
}


long long write_directories()
{
	unsigned short c_byte;
	int avail_bytes;
	char *directoryp = directory_data_cache;
	long long start_bytes = bytes;

	while(directory_cache_bytes) {
		if(directory_size - directory_bytes <
				((SQUASHFS_METADATA_SIZE << 1) + 2)) {
			void *dt = realloc(directory_table,
				directory_size + ((SQUASHFS_METADATA_SIZE << 1)
				+ 2));
			if(dt == NULL) {
				BAD_ERROR("Out of memory in directory table "
					"reallocation!\n");
			}
			directory_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
			directory_table = dt;
		}
		avail_bytes = directory_cache_bytes > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : directory_cache_bytes;
		c_byte = mangle(directory_table + directory_bytes +
			BLOCK_OFFSET, directoryp, avail_bytes,
			SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Directory block @ 0x%x, size %d\n", directory_bytes,
			c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte,
			directory_table + directory_bytes, 1);
		directory_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) +
			BLOCK_OFFSET;
		total_directory_bytes += avail_bytes + BLOCK_OFFSET;
		directoryp += avail_bytes;
		directory_cache_bytes -= avail_bytes;
	}
	write_destination(fd, bytes, directory_bytes, directory_table);
	bytes += directory_bytes;

	return start_bytes;
}


long long write_id_table()
{
	unsigned int id_bytes = SQUASHFS_ID_BYTES(id_count);
	unsigned int p[id_count];
	int i;

	TRACE("write_id_table: ids %d, id_bytes %d\n", id_count, id_bytes);
	for(i = 0; i < id_count; i++) {
		TRACE("write_id_table: id index %d, id %d", i, id_table[i]->id);
		SQUASHFS_SWAP_INTS(&id_table[i]->id, p + i, 1);
	}

	return generic_write_table(id_bytes, p, 0, NULL, noI);
}


struct id *get_id(unsigned int id)
{
	int hash = ID_HASH(id);
	struct id *entry = id_hash_table[hash];

	for(; entry; entry = entry->next)
		if(entry->id == id)
			break;

	return entry;
}


struct id *create_id(unsigned int id)
{
	int hash = ID_HASH(id);
	struct id *entry = malloc(sizeof(struct id));
	if(entry == NULL)
		BAD_ERROR("Out of memory in create_id\n");
	entry->id = id;
	entry->index = id_count ++;
	entry->flags = 0;
	entry->next = id_hash_table[hash];
	id_hash_table[hash] = entry;
	id_table[entry->index] = entry;
	return entry;
}


unsigned int get_uid(unsigned int uid)
{
	struct id *entry = get_id(uid);

	if(entry == NULL) {
		if(id_count == SQUASHFS_IDS)
			BAD_ERROR("Out of uids!\n");
		entry = create_id(uid);
	}

	if((entry->flags & ISA_UID) == 0) {
		entry->flags |= ISA_UID;
		uid_count ++;
	}

	return entry->index;
}


unsigned int get_guid(unsigned int guid)
{
	struct id *entry = get_id(guid);

	if(entry == NULL) {
		if(id_count == SQUASHFS_IDS)
			BAD_ERROR("Out of gids!\n");
		entry = create_id(guid);
	}

	if((entry->flags & ISA_GID) == 0) {
		entry->flags |= ISA_GID;
		guid_count ++;
	}

	return entry->index;
}


int create_inode(squashfs_inode *i_no, struct dir_info *dir_info,
	struct dir_ent *dir_ent, int type, long long byte_size,
	long long start_block, unsigned int offset, unsigned int *block_list,
	struct fragment *fragment, struct directory *dir_in, long long sparse)
{
	struct stat *buf = &dir_ent->inode->buf;
	union squashfs_inode_header inode_header;
	struct squashfs_base_inode_header *base = &inode_header.base;
	void *inode;
	char *filename = dir_ent->pathname;
	int nlink = dir_ent->inode->nlink;
	int inode_number = type == SQUASHFS_DIR_TYPE ?
		dir_ent->inode->inode_number :
		dir_ent->inode->inode_number + dir_inode_no;
	int xattr = read_xattrs(dir_ent);

	switch(type) {
	case SQUASHFS_FILE_TYPE:
		if(dir_ent->inode->nlink > 1 ||
				byte_size >= (1LL << 32) ||
				start_block >= (1LL << 32) ||
				sparse || IS_XATTR(xattr))
			type = SQUASHFS_LREG_TYPE;
		break;
	case SQUASHFS_DIR_TYPE:
		if(dir_info->dir_is_ldir || IS_XATTR(xattr))
			type = SQUASHFS_LDIR_TYPE;
		break;
	case SQUASHFS_SYMLINK_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LSYMLINK_TYPE;
		break;
	case SQUASHFS_BLKDEV_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LBLKDEV_TYPE;
		break;
	case SQUASHFS_CHRDEV_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LCHRDEV_TYPE;
		break;
	case SQUASHFS_FIFO_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LFIFO_TYPE;
		break;
	case SQUASHFS_SOCKET_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LSOCKET_TYPE;
		break;
	}
			
	base->mode = SQUASHFS_MODE(buf->st_mode);
	base->uid = get_uid((unsigned int) global_uid == -1 ?
		buf->st_uid : global_uid);
	base->inode_type = type;
	base->guid = get_guid((unsigned int) global_gid == -1 ?
		buf->st_gid : global_gid);
	base->mtime = buf->st_mtime;
	base->inode_number = inode_number;

	if(type == SQUASHFS_FILE_TYPE) {
		int i;
		struct squashfs_reg_inode_header *reg = &inode_header.reg;
		size_t off = offsetof(struct squashfs_reg_inode_header, block_list);

		inode = get_inode(sizeof(*reg) + offset * sizeof(unsigned int));
		reg->file_size = byte_size;
		reg->start_block = start_block;
		reg->fragment = fragment->index;
		reg->offset = fragment->offset;
		SQUASHFS_SWAP_REG_INODE_HEADER(reg, inode);
		SQUASHFS_SWAP_INTS(block_list, inode + off, offset);
		TRACE("File inode, file_size %lld, start_block 0x%llx, blocks "
			"%d, fragment %d, offset %d, size %d\n", byte_size,
			start_block, offset, fragment->index, fragment->offset,
			fragment->size);
		for(i = 0; i < offset; i++)
			TRACE("Block %d, size %d\n", i, block_list[i]);
	}
	else if(type == SQUASHFS_LREG_TYPE) {
		int i;
		struct squashfs_lreg_inode_header *reg = &inode_header.lreg;
		size_t off = offsetof(struct squashfs_lreg_inode_header, block_list);

		inode = get_inode(sizeof(*reg) + offset * sizeof(unsigned int));
		reg->nlink = nlink;
		reg->file_size = byte_size;
		reg->start_block = start_block;
		reg->fragment = fragment->index;
		reg->offset = fragment->offset;
		if(sparse && sparse >= byte_size)
			sparse = byte_size - 1;
		reg->sparse = sparse;
		reg->xattr = xattr;
		SQUASHFS_SWAP_LREG_INODE_HEADER(reg, inode);
		SQUASHFS_SWAP_INTS(block_list, inode + off, offset);
		TRACE("Long file inode, file_size %lld, start_block 0x%llx, "
			"blocks %d, fragment %d, offset %d, size %d, nlink %d"
			"\n", byte_size, start_block, offset, fragment->index,
			fragment->offset, fragment->size, nlink);
		for(i = 0; i < offset; i++)
			TRACE("Block %d, size %d\n", i, block_list[i]);
	}
	else if(type == SQUASHFS_LDIR_TYPE) {
		int i;
		unsigned char *p;
		struct squashfs_ldir_inode_header *dir = &inode_header.ldir;
		struct cached_dir_index *index = dir_in->index;
		unsigned int i_count = dir_in->i_count;
		unsigned int i_size = dir_in->i_size;

		if(byte_size >= 1 << 27)
			BAD_ERROR("directory greater than 2^27-1 bytes!\n");

		inode = get_inode(sizeof(*dir) + i_size);
		dir->inode_type = SQUASHFS_LDIR_TYPE;
		dir->nlink = dir_ent->dir->directory_count + 2;
		dir->file_size = byte_size;
		dir->offset = offset;
		dir->start_block = start_block;
		dir->i_count = i_count;
		dir->parent_inode = dir_ent->our_dir ?
			dir_ent->our_dir->dir_ent->inode->inode_number :
			dir_inode_no + inode_no;
		dir->xattr = xattr;

		SQUASHFS_SWAP_LDIR_INODE_HEADER(dir, inode);
		p = inode + offsetof(struct squashfs_ldir_inode_header, index);
		for(i = 0; i < i_count; i++) {
			SQUASHFS_SWAP_DIR_INDEX(&index[i].index, p);
			p += offsetof(struct squashfs_dir_index, name);
			memcpy(p, index[i].name, index[i].index.size + 1);
			p += index[i].index.size + 1;
		}
		TRACE("Long directory inode, file_size %lld, start_block "
			"0x%llx, offset 0x%x, nlink %d\n", byte_size,
			start_block, offset, dir_ent->dir->directory_count + 2);
	}
	else if(type == SQUASHFS_DIR_TYPE) {
		struct squashfs_dir_inode_header *dir = &inode_header.dir;

		inode = get_inode(sizeof(*dir));
		dir->nlink = dir_ent->dir->directory_count + 2;
		dir->file_size = byte_size;
		dir->offset = offset;
		dir->start_block = start_block;
		dir->parent_inode = dir_ent->our_dir ?
			dir_ent->our_dir->dir_ent->inode->inode_number :
			dir_inode_no + inode_no;
		SQUASHFS_SWAP_DIR_INODE_HEADER(dir, inode);
		TRACE("Directory inode, file_size %lld, start_block 0x%llx, "
			"offset 0x%x, nlink %d\n", byte_size, start_block,
			offset, dir_ent->dir->directory_count + 2);
	}
	else if(type == SQUASHFS_CHRDEV_TYPE || type == SQUASHFS_BLKDEV_TYPE) {
		struct squashfs_dev_inode_header *dev = &inode_header.dev;
		unsigned int major = major(buf->st_rdev);
		unsigned int minor = minor(buf->st_rdev);

		if(major > 0xfff) {
			ERROR("Major %d out of range in device node %s, "
				"truncating to %d\n", major, filename,
				major & 0xfff);
			major &= 0xfff;
		}
		if(minor > 0xfffff) {
			ERROR("Minor %d out of range in device node %s, "
				"truncating to %d\n", minor, filename,
				minor & 0xfffff);
			minor &= 0xfffff;
		}
		inode = get_inode(sizeof(*dev));
		dev->nlink = nlink;
		dev->rdev = (major << 8) | (minor & 0xff) |
				((minor & ~0xff) << 12);
		SQUASHFS_SWAP_DEV_INODE_HEADER(dev, inode);
		TRACE("Device inode, rdev 0x%x, nlink %d\n", dev->rdev, nlink);
	}
	else if(type == SQUASHFS_LCHRDEV_TYPE || type == SQUASHFS_LBLKDEV_TYPE) {
		struct squashfs_ldev_inode_header *dev = &inode_header.ldev;
		unsigned int major = major(buf->st_rdev);
		unsigned int minor = minor(buf->st_rdev);

		if(major > 0xfff) {
			ERROR("Major %d out of range in device node %s, "
				"truncating to %d\n", major, filename,
				major & 0xfff);
			major &= 0xfff;
		}
		if(minor > 0xfffff) {
			ERROR("Minor %d out of range in device node %s, "
				"truncating to %d\n", minor, filename,
				minor & 0xfffff);
			minor &= 0xfffff;
		}
		inode = get_inode(sizeof(*dev));
		dev->nlink = nlink;
		dev->rdev = (major << 8) | (minor & 0xff) |
				((minor & ~0xff) << 12);
		dev->xattr = xattr;
		SQUASHFS_SWAP_LDEV_INODE_HEADER(dev, inode);
		TRACE("Device inode, rdev 0x%x, nlink %d\n", dev->rdev, nlink);
	}
	else if(type == SQUASHFS_SYMLINK_TYPE) {
		struct squashfs_symlink_inode_header *symlink = &inode_header.symlink;
		int byte;
		char buff[65536];
		size_t off = offsetof(struct squashfs_symlink_inode_header, symlink);

		byte = readlink(filename, buff, 65536);
		if(byte == -1) {
			ERROR("Failed to read symlink %s, creating empty "
				"symlink\n", filename);
			byte = 0;
		}

		if(byte == 65536) {
			ERROR("Symlink %s is greater than 65536 bytes! "
				"Creating empty symlink\n", filename);
			byte = 0;
		}

		inode = get_inode(sizeof(*symlink) + byte);
		symlink->nlink = nlink;
		symlink->symlink_size = byte;
		SQUASHFS_SWAP_SYMLINK_INODE_HEADER(symlink, inode);
		strncpy(inode + off, buff, byte);
		TRACE("Symbolic link inode, symlink_size %d, nlink %d\n", byte,
			nlink);
	}
	else if(type == SQUASHFS_LSYMLINK_TYPE) {
		struct squashfs_symlink_inode_header *symlink = &inode_header.symlink;
		int byte;
		char buff[65536];
		size_t off = offsetof(struct squashfs_symlink_inode_header, symlink);

		byte = readlink(filename, buff, 65536);
		if(byte == -1) {
			ERROR("Failed to read symlink %s, creating empty "
				"symlink\n", filename);
			byte = 0;
		}

		if(byte == 65536) {
			ERROR("Symlink %s is greater than 65536 bytes! "
				"Creating empty symlink\n", filename);
			byte = 0;
		}

		inode = get_inode(sizeof(*symlink) + byte +
						sizeof(unsigned int));
		symlink->nlink = nlink;
		symlink->symlink_size = byte;
		SQUASHFS_SWAP_SYMLINK_INODE_HEADER(symlink, inode);
		strncpy(inode + off, buff, byte);
		SQUASHFS_SWAP_INTS(&xattr, inode + off + byte, 1);
		TRACE("Symbolic link inode, symlink_size %d, nlink %d\n", byte,
			nlink);
	}
	else if(type == SQUASHFS_FIFO_TYPE || type == SQUASHFS_SOCKET_TYPE) {
		struct squashfs_ipc_inode_header *ipc = &inode_header.ipc;

		inode = get_inode(sizeof(*ipc));
		ipc->nlink = nlink;
		SQUASHFS_SWAP_IPC_INODE_HEADER(ipc, inode);
		TRACE("ipc inode, type %s, nlink %d\n", type ==
			SQUASHFS_FIFO_TYPE ? "fifo" : "socket", nlink);
	}
	else if(type == SQUASHFS_LFIFO_TYPE || type == SQUASHFS_LSOCKET_TYPE) {
		struct squashfs_lipc_inode_header *ipc = &inode_header.lipc;

		inode = get_inode(sizeof(*ipc));
		ipc->nlink = nlink;
		ipc->xattr = xattr;
		SQUASHFS_SWAP_LIPC_INODE_HEADER(ipc, inode);
		TRACE("ipc inode, type %s, nlink %d\n", type ==
			SQUASHFS_FIFO_TYPE ? "fifo" : "socket", nlink);
	} else
		BAD_ERROR("Unrecognised inode %d in create_inode\n", type);

	*i_no = MKINODE(inode);
	inode_count ++;

	TRACE("Created inode 0x%llx, type %d, uid %d, guid %d\n", *i_no, type,
		base->uid, base->guid);

	return TRUE;
}


void scan3_init_dir(struct directory *dir)
{
	dir->buff = malloc(SQUASHFS_METADATA_SIZE);
	if(dir->buff == NULL) {
		BAD_ERROR("Out of memory allocating directory buffer\n");
	}

	dir->size = SQUASHFS_METADATA_SIZE;
	dir->p = dir->index_count_p = dir->buff;
	dir->entry_count = 256;
	dir->entry_count_p = NULL;
	dir->index = NULL;
	dir->i_count = dir->i_size = 0;
}


void add_dir(squashfs_inode inode, unsigned int inode_number, char *name,
	int type, struct directory *dir)
{
	unsigned char *buff;
	struct squashfs_dir_entry idir;
	unsigned int start_block = inode >> 16;
	unsigned int offset = inode & 0xffff;
	unsigned int size = strlen(name);
	size_t name_off = offsetof(struct squashfs_dir_entry, name);

	if(size > SQUASHFS_NAME_LEN) {
		size = SQUASHFS_NAME_LEN;
		ERROR("Filename is greater than %d characters, truncating! ..."
			"\n", SQUASHFS_NAME_LEN);
	}

	if(dir->p + sizeof(struct squashfs_dir_entry) + size +
			sizeof(struct squashfs_dir_header)
			>= dir->buff + dir->size) {
		buff = realloc(dir->buff, dir->size += SQUASHFS_METADATA_SIZE);
		if(buff == NULL)  {
			BAD_ERROR("Out of memory reallocating directory buffer"
				"\n");
		}

		dir->p = (dir->p - dir->buff) + buff;
		if(dir->entry_count_p) 
			dir->entry_count_p = (dir->entry_count_p - dir->buff +
			buff);
		dir->index_count_p = dir->index_count_p - dir->buff + buff;
		dir->buff = buff;
	}

	if(dir->entry_count == 256 || start_block != dir->start_block ||
			((dir->entry_count_p != NULL) &&
			((dir->p + sizeof(struct squashfs_dir_entry) + size -
			dir->index_count_p) > SQUASHFS_METADATA_SIZE)) ||
			((long long) inode_number - dir->inode_number) > 32767
			|| ((long long) inode_number - dir->inode_number)
			< -32768) {
		if(dir->entry_count_p) {
			struct squashfs_dir_header dir_header;

			if((dir->p + sizeof(struct squashfs_dir_entry) + size -
					dir->index_count_p) >
					SQUASHFS_METADATA_SIZE) {
				if(dir->i_count % I_COUNT_SIZE == 0) {
					dir->index = realloc(dir->index,
						(dir->i_count + I_COUNT_SIZE) *
						sizeof(struct cached_dir_index));
					if(dir->index == NULL)
						BAD_ERROR("Out of memory in "
							"directory index table "
							"reallocation!\n");
				}
				dir->index[dir->i_count].index.index =
					dir->p - dir->buff;
				dir->index[dir->i_count].index.size = size - 1;
				dir->index[dir->i_count++].name = name;
				dir->i_size += sizeof(struct squashfs_dir_index)
					+ size;
				dir->index_count_p = dir->p;
			}

			dir_header.count = dir->entry_count - 1;
			dir_header.start_block = dir->start_block;
			dir_header.inode_number = dir->inode_number;
			SQUASHFS_SWAP_DIR_HEADER(&dir_header,
				dir->entry_count_p);

		}


		dir->entry_count_p = dir->p;
		dir->start_block = start_block;
		dir->entry_count = 0;
		dir->inode_number = inode_number;
		dir->p += sizeof(struct squashfs_dir_header);
	}

	idir.offset = offset;
	idir.type = type;
	idir.size = size - 1;
	idir.inode_number = ((long long) inode_number - dir->inode_number);
	SQUASHFS_SWAP_DIR_ENTRY(&idir, dir->p);
	strncpy((char *) dir->p + name_off, name, size);
	dir->p += sizeof(struct squashfs_dir_entry) + size;
	dir->entry_count ++;
}


void write_dir(squashfs_inode *inode, struct dir_info *dir_info,
	struct directory *dir)
{
	unsigned int dir_size = dir->p - dir->buff;
	int data_space = directory_cache_size - directory_cache_bytes;
	unsigned int directory_block, directory_offset, i_count, index;
	unsigned short c_byte;

	if(data_space < dir_size) {
		int realloc_size = directory_cache_size == 0 ?
			((dir_size + SQUASHFS_METADATA_SIZE) &
			~(SQUASHFS_METADATA_SIZE - 1)) : dir_size - data_space;

		void *dc = realloc(directory_data_cache,
			directory_cache_size + realloc_size);
		if(dc == NULL) {
			goto failed;
		}
		directory_cache_size += realloc_size;
		directory_data_cache = dc;
	}

	if(dir_size) {
		struct squashfs_dir_header dir_header;

		dir_header.count = dir->entry_count - 1;
		dir_header.start_block = dir->start_block;
		dir_header.inode_number = dir->inode_number;
		SQUASHFS_SWAP_DIR_HEADER(&dir_header, dir->entry_count_p);
		memcpy(directory_data_cache + directory_cache_bytes, dir->buff,
			dir_size);
	}
	directory_offset = directory_cache_bytes;
	directory_block = directory_bytes;
	directory_cache_bytes += dir_size;
	i_count = 0;
	index = SQUASHFS_METADATA_SIZE - directory_offset;

	while(1) {
		while(i_count < dir->i_count &&
				dir->index[i_count].index.index < index)
			dir->index[i_count++].index.start_block =
				directory_bytes;
		index += SQUASHFS_METADATA_SIZE;

		if(directory_cache_bytes < SQUASHFS_METADATA_SIZE)
			break;

		if((directory_size - directory_bytes) <
					((SQUASHFS_METADATA_SIZE << 1) + 2)) {
			void *dt = realloc(directory_table,
				directory_size + (SQUASHFS_METADATA_SIZE << 1)
				+ 2);
			if(dt == NULL) {
				goto failed;
			}
			directory_size += SQUASHFS_METADATA_SIZE << 1;
			directory_table = dt;
		}

		c_byte = mangle(directory_table + directory_bytes +
				BLOCK_OFFSET, directory_data_cache,
				SQUASHFS_METADATA_SIZE, SQUASHFS_METADATA_SIZE,
				noI, 0);
		TRACE("Directory block @ 0x%x, size %d\n", directory_bytes,
			c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte,
			directory_table + directory_bytes, 1);
		directory_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) +
			BLOCK_OFFSET;
		total_directory_bytes += SQUASHFS_METADATA_SIZE + BLOCK_OFFSET;
		memmove(directory_data_cache, directory_data_cache +
			SQUASHFS_METADATA_SIZE, directory_cache_bytes -
			SQUASHFS_METADATA_SIZE);
		directory_cache_bytes -= SQUASHFS_METADATA_SIZE;
	}

	create_inode(inode, dir_info, dir_info->dir_ent, SQUASHFS_DIR_TYPE,
		dir_size + 3, directory_block, directory_offset, NULL, NULL,
		dir, 0);

#ifdef SQUASHFS_TRACE
	{
		unsigned char *dirp;
		int count;

		TRACE("Directory contents of inode 0x%llx\n", *inode);
		dirp = dir->buff;
		while(dirp < dir->p) {
			char buffer[SQUASHFS_NAME_LEN + 1];
			struct squashfs_dir_entry idir, *idirp;
			struct squashfs_dir_header dirh;
			SQUASHFS_SWAP_DIR_HEADER((struct squashfs_dir_header *) dirp,
				&dirh);
			count = dirh.count + 1;
			dirp += sizeof(struct squashfs_dir_header);

			TRACE("\tStart block 0x%x, count %d\n",
				dirh.start_block, count);

			while(count--) {
				idirp = (struct squashfs_dir_entry *) dirp;
				SQUASHFS_SWAP_DIR_ENTRY(idirp, &idir);
				strncpy(buffer, idirp->name, idir.size + 1);
				buffer[idir.size + 1] = '\0';
				TRACE("\t\tname %s, inode offset 0x%x, type "
					"%d\n", buffer, idir.offset, idir.type);
				dirp += sizeof(struct squashfs_dir_entry) + idir.size +
					1;
			}
		}
	}
#endif
	dir_count ++;

	return;

failed:
	BAD_ERROR("Out of memory in directory table reallocation!\n");
}


struct file_buffer *get_fragment(struct fragment *fragment)
{
	struct squashfs_fragment_entry *disk_fragment;
	int res, size;
	long long start_block;
	struct file_buffer *buffer, *compressed_buffer;

	if(fragment->index == SQUASHFS_INVALID_FRAG)
		return NULL;

	buffer = cache_lookup(fragment_buffer, fragment->index);
	if(buffer)
		return buffer;

	compressed_buffer = cache_lookup(writer_buffer, fragment->index +
		FRAG_INDEX);

	buffer = cache_get(fragment_buffer, fragment->index, 1);

	pthread_mutex_lock(&fragment_mutex);
	disk_fragment = &fragment_table[fragment->index];
	size = SQUASHFS_COMPRESSED_SIZE_BLOCK(disk_fragment->size);
	start_block = disk_fragment->start_block;
	pthread_mutex_unlock(&fragment_mutex);

	if(SQUASHFS_COMPRESSED_BLOCK(disk_fragment->size)) {
		int error;
		char *data;

		if(compressed_buffer)
			data = compressed_buffer->data;
		else
			data = read_from_disk(start_block, size);

		res = compressor_uncompress(comp, buffer->data, data, size,
			block_size, &error);
		if(res == -1)
			BAD_ERROR("%s uncompress failed with error code %d\n",
				comp->name, error);
	} else if(compressed_buffer)
		memcpy(buffer->data, compressed_buffer->data, size);
	else {
		res = read_fs_bytes(fd, start_block, size, buffer->data);
		if(res == 0)
			EXIT_MKSQUASHFS();
	}

	cache_block_put(compressed_buffer);

	return buffer;
}


struct frag_locked {
	struct file_buffer *buffer;
	int c_byte;
	int fragment;
	struct frag_locked *fragment_prev;
	struct frag_locked *fragment_next;
};

int fragments_locked = FALSE;
struct frag_locked *frag_locked_list = NULL;

INSERT_LIST(fragment, struct frag_locked)
REMOVE_LIST(fragment, struct frag_locked)

int lock_fragments()
{
	int count;
	pthread_mutex_lock(&fragment_mutex);
	fragments_locked = TRUE;
	count = fragments_outstanding;
	pthread_mutex_unlock(&fragment_mutex);
	return count;
}


void unlock_fragments()
{
	struct frag_locked *entry;
	int compressed_size;

	pthread_mutex_lock(&fragment_mutex);
	while(frag_locked_list) {
		entry = frag_locked_list;
		remove_fragment_list(&frag_locked_list, entry);
		compressed_size = SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->c_byte);
		fragment_table[entry->fragment].size = entry->c_byte;
		fragment_table[entry->fragment].start_block = bytes;
		entry->buffer->block = bytes;
		bytes += compressed_size;
		fragments_outstanding --;
		queue_put(to_writer, entry->buffer);
		TRACE("fragment_locked writing fragment %d, compressed size %d"
			"\n", entry->fragment, compressed_size);
		free(entry);
	}
	fragments_locked = FALSE;
	pthread_mutex_unlock(&fragment_mutex);
}


void add_pending_fragment(struct file_buffer *write_buffer, int c_byte,
	int fragment)
{
	struct frag_locked *entry = malloc(sizeof(struct frag_locked));
	if(entry == NULL)
		BAD_ERROR("Out of memory in add_pending fragment\n");
	entry->buffer = write_buffer;
	entry->c_byte = c_byte;
	entry->fragment = fragment;
	entry->fragment_prev = entry->fragment_next = NULL;
	pthread_mutex_lock(&fragment_mutex);
	insert_fragment_list(&frag_locked_list, entry);
	pthread_mutex_unlock(&fragment_mutex);
}


void write_fragment(struct file_buffer *fragment)
{
	if(fragment == NULL)
		return;

	pthread_mutex_lock(&fragment_mutex);
	fragment_table[fragment->block].unused = 0;
	fragments_outstanding ++;
	queue_put(to_frag, fragment);
	pthread_mutex_unlock(&fragment_mutex);
}


struct file_buffer *allocate_fragment()
{
	struct file_buffer *fragment = cache_get(fragment_buffer, fragments, 1);

	pthread_mutex_lock(&fragment_mutex);

	if(fragments % FRAG_SIZE == 0) {
		void *ft = realloc(fragment_table, (fragments +
			FRAG_SIZE) * sizeof(struct squashfs_fragment_entry));
		if(ft == NULL) {
			pthread_mutex_unlock(&fragment_mutex);
			BAD_ERROR("Out of memory in fragment table\n");
		}
		fragment_table = ft;
	}

	fragment->size = 0;
	fragment->block = fragments ++;

	pthread_mutex_unlock(&fragment_mutex);

	return fragment;
}


static struct fragment empty_fragment = {SQUASHFS_INVALID_FRAG, 0, 0};
struct fragment *get_and_fill_fragment(struct file_buffer *file_buffer,
	struct dir_ent *dir_ent)
{
	struct fragment *ffrg;
	struct file_buffer **fragment;

	if(file_buffer == NULL || file_buffer->size == 0)
		return &empty_fragment;

	fragment = eval_frag_actions(dir_ent);

	if((*fragment) && (*fragment)->size + file_buffer->size > block_size) {
		write_fragment(*fragment);
		*fragment = NULL;
	}

	ffrg = malloc(sizeof(struct fragment));
	if(ffrg == NULL)
		BAD_ERROR("Out of memory in fragment block allocation!\n");

	if(*fragment == NULL)
		*fragment = allocate_fragment();

	ffrg->index = (*fragment)->block;
	ffrg->offset = (*fragment)->size;
	ffrg->size = file_buffer->size;
	memcpy((*fragment)->data + (*fragment)->size, file_buffer->data,
		file_buffer->size);
	(*fragment)->size += file_buffer->size;

	return ffrg;
}


long long generic_write_table(int length, void *buffer, int length2,
	void *buffer2, int uncompressed)
{
	int meta_blocks = (length + SQUASHFS_METADATA_SIZE - 1) /
		SQUASHFS_METADATA_SIZE;
	long long list[meta_blocks], start_bytes;
	int compressed_size, i;
	unsigned short c_byte;
	char cbuffer[(SQUASHFS_METADATA_SIZE << 2) + 2];
	
#ifdef SQUASHFS_TRACE
	long long obytes = bytes;
	int olength = length;
#endif

	for(i = 0; i < meta_blocks; i++) {
		int avail_bytes = length > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : length;
		c_byte = mangle(cbuffer + BLOCK_OFFSET, buffer + i *
			SQUASHFS_METADATA_SIZE , avail_bytes,
			SQUASHFS_METADATA_SIZE, uncompressed, 0);
		SQUASHFS_SWAP_SHORTS(&c_byte, cbuffer, 1);
		list[i] = bytes;
		compressed_size = SQUASHFS_COMPRESSED_SIZE(c_byte) +
			BLOCK_OFFSET;
		TRACE("block %d @ 0x%llx, compressed size %d\n", i, bytes,
			compressed_size);
		write_destination(fd, bytes, compressed_size, cbuffer);
		bytes += compressed_size;
		total_bytes += avail_bytes;
		length -= avail_bytes;
	}

	start_bytes = bytes;
	if(length2) {
		write_destination(fd, bytes, length2, buffer2);
		bytes += length2;
		total_bytes += length2;
	}
		
	SQUASHFS_INSWAP_LONG_LONGS(list, meta_blocks);
	write_destination(fd, bytes, sizeof(list), list);
	bytes += sizeof(list);
	total_bytes += sizeof(list);

	TRACE("generic_write_table: total uncompressed %d compressed %lld\n",
		olength, bytes - obytes);

	return start_bytes;
}


long long write_fragment_table()
{
	unsigned int frag_bytes = SQUASHFS_FRAGMENT_BYTES(fragments);
	struct squashfs_fragment_entry p[fragments];
	int i;

	TRACE("write_fragment_table: fragments %d, frag_bytes %d\n", fragments,
		frag_bytes);
	for(i = 0; i < fragments; i++) {
		TRACE("write_fragment_table: fragment %d, start_block 0x%llx, "
			"size %d\n", i, fragment_table[i].start_block,
			fragment_table[i].size);
		SQUASHFS_SWAP_FRAGMENT_ENTRY(&fragment_table[i], p + i);
	}

	return generic_write_table(frag_bytes, p, 0, NULL, noF);
}


char read_from_file_buffer[SQUASHFS_FILE_MAX_SIZE];
char *read_from_disk(long long start, unsigned int avail_bytes)
{
	int res;

	res = read_fs_bytes(fd, start, avail_bytes, read_from_file_buffer);
	if(res == 0)
		EXIT_MKSQUASHFS();

	return read_from_file_buffer;
}


char read_from_file_buffer2[SQUASHFS_FILE_MAX_SIZE];
char *read_from_disk2(long long start, unsigned int avail_bytes)
{
	int res;

	res = read_fs_bytes(fd, start, avail_bytes, read_from_file_buffer2);
	if(res == 0)
		EXIT_MKSQUASHFS();

	return read_from_file_buffer2;
}


/*
 * Compute 16 bit BSD checksum over the data
 */
unsigned short get_checksum(char *buff, int bytes, unsigned short chksum)
{
	unsigned char *b = (unsigned char *) buff;

	while(bytes --) {
		chksum = (chksum & 1) ? (chksum >> 1) | 0x8000 : chksum >> 1;
		chksum += *b++;
	}

	return chksum;
}


unsigned short get_checksum_disk(long long start, long long l,
	unsigned int *blocks)
{
	unsigned short chksum = 0;
	unsigned int bytes;
	struct file_buffer *write_buffer;
	int i;

	for(i = 0; l; i++)  {
		bytes = SQUASHFS_COMPRESSED_SIZE_BLOCK(blocks[i]);
		if(bytes == 0) /* sparse block */
			continue;
		write_buffer = cache_lookup(writer_buffer, start);
		if(write_buffer) {
			chksum = get_checksum(write_buffer->data, bytes,
				chksum);
			cache_block_put(write_buffer);
		} else
			chksum = get_checksum(read_from_disk(start, bytes),
				bytes, chksum);
		l -= bytes;
		start += bytes;
	}

	return chksum;
}


unsigned short get_checksum_mem(char *buff, int bytes)
{
	return get_checksum(buff, bytes, 0);
}


unsigned short get_checksum_mem_buffer(struct file_buffer *file_buffer)
{
	if(file_buffer == NULL)
		return 0;
	else
		return get_checksum(file_buffer->data, file_buffer->size, 0);
}


#define DUP_HASH(a) (a & 0xffff)
void add_file(long long start, long long file_size, long long file_bytes,
	unsigned int *block_listp, int blocks, unsigned int fragment,
	int offset, int bytes)
{
	struct fragment *frg;
	unsigned int *block_list = block_listp;
	struct file_info *dupl_ptr = dupl[DUP_HASH(file_size)];

	if(!duplicate_checking || file_size == 0)
		return;

	for(; dupl_ptr; dupl_ptr = dupl_ptr->next) {
		if(file_size != dupl_ptr->file_size)
			continue;
		if(blocks != 0 && start != dupl_ptr->start)
			continue;
		if(fragment != dupl_ptr->fragment->index)
			continue;
		if(fragment != SQUASHFS_INVALID_FRAG && (offset !=
				dupl_ptr->fragment->offset || bytes !=
				dupl_ptr->fragment->size))
			continue;
		return;
	}

	frg = malloc(sizeof(struct fragment));
	if(frg == NULL)
		BAD_ERROR("Out of memory in fragment block allocation!\n");

	frg->index = fragment;
	frg->offset = offset;
	frg->size = bytes;

	add_non_dup(file_size, file_bytes, block_list, start, frg, 0, 0, FALSE);
}


int pre_duplicate(long long file_size)
{
	struct file_info *dupl_ptr = dupl[DUP_HASH(file_size)];

	for(; dupl_ptr; dupl_ptr = dupl_ptr->next)
		if(dupl_ptr->file_size == file_size)
			return TRUE;

	return FALSE;
}


int pre_duplicate_frag(long long file_size, unsigned short checksum)
{
	struct file_info *dupl_ptr = dupl[DUP_HASH(file_size)];

	for(; dupl_ptr; dupl_ptr = dupl_ptr->next)
		if(file_size == dupl_ptr->file_size && file_size ==
				dupl_ptr->fragment->size) {
			if(dupl_ptr->checksum_flag == FALSE) {
				struct file_buffer *frag_buffer =
					get_fragment(dupl_ptr->fragment);
				dupl_ptr->checksum =
					get_checksum_disk(dupl_ptr->start,
					dupl_ptr->bytes, dupl_ptr->block_list);
				dupl_ptr->fragment_checksum =
					get_checksum_mem(frag_buffer->data +
					dupl_ptr->fragment->offset, file_size);
				cache_block_put(frag_buffer);
				dupl_ptr->checksum_flag = TRUE;
			}
			if(dupl_ptr->fragment_checksum == checksum)
				return TRUE;
		}

	return FALSE;
}


struct file_info *add_non_dup(long long file_size, long long bytes,
	unsigned int *block_list, long long start, struct fragment *fragment,
	unsigned short checksum, unsigned short fragment_checksum,
	int checksum_flag)
{
	struct file_info *dupl_ptr = malloc(sizeof(struct file_info));

	if(dupl_ptr == NULL) {
		BAD_ERROR("Out of memory in dup_files allocation!\n");
	}

	dupl_ptr->file_size = file_size;
	dupl_ptr->bytes = bytes;
	dupl_ptr->block_list = block_list;
	dupl_ptr->start = start;
	dupl_ptr->fragment = fragment;
	dupl_ptr->checksum = checksum;
	dupl_ptr->fragment_checksum = fragment_checksum;
	dupl_ptr->checksum_flag = checksum_flag;
	dupl_ptr->next = dupl[DUP_HASH(file_size)];
	dupl[DUP_HASH(file_size)] = dupl_ptr;
	dup_files ++;

	return dupl_ptr;
}


struct file_info *duplicate(long long file_size, long long bytes,
	unsigned int **block_list, long long *start, struct fragment **fragment,
	struct file_buffer *file_buffer, int blocks, unsigned short checksum,
	unsigned short fragment_checksum, int checksum_flag)
{
	struct file_info *dupl_ptr = dupl[DUP_HASH(file_size)];
	int frag_bytes = file_buffer ? file_buffer->size : 0;

	for(; dupl_ptr; dupl_ptr = dupl_ptr->next)
		if(file_size == dupl_ptr->file_size && bytes == dupl_ptr->bytes
				 && frag_bytes == dupl_ptr->fragment->size) {
			long long target_start, dup_start = dupl_ptr->start;
			int block;

			if(memcmp(*block_list, dupl_ptr->block_list, blocks *
					sizeof(unsigned int)) != 0)
				continue;

			if(checksum_flag == FALSE) {
				checksum = get_checksum_disk(*start, bytes,
					*block_list);
				fragment_checksum =
					get_checksum_mem_buffer(file_buffer);
				checksum_flag = TRUE;
			}

			if(dupl_ptr->checksum_flag == FALSE) {
				struct file_buffer *frag_buffer =
					get_fragment(dupl_ptr->fragment);
				dupl_ptr->checksum =
					get_checksum_disk(dupl_ptr->start,
					dupl_ptr->bytes, dupl_ptr->block_list);
				dupl_ptr->fragment_checksum =
					get_checksum_mem(frag_buffer->data +
					dupl_ptr->fragment->offset, frag_bytes);
				cache_block_put(frag_buffer);
				dupl_ptr->checksum_flag = TRUE;
			}

			if(checksum != dupl_ptr->checksum ||
					fragment_checksum !=
					dupl_ptr->fragment_checksum)
				continue;

			target_start = *start;
			for(block = 0; block < blocks; block ++) {
				int size = SQUASHFS_COMPRESSED_SIZE_BLOCK
					((*block_list)[block]);
				struct file_buffer *target_buffer = NULL;
				struct file_buffer *dup_buffer = NULL;
				char *target_data, *dup_data;
				int res;

				if(size == 0)
					continue;
				target_buffer = cache_lookup(writer_buffer,
					target_start);
				if(target_buffer)
					target_data = target_buffer->data;
				else
					target_data =
						read_from_disk(target_start,
						size);

				dup_buffer = cache_lookup(writer_buffer,
					dup_start);
				if(dup_buffer)
					dup_data = dup_buffer->data;
				else
					dup_data = read_from_disk2(dup_start,
						size);

				res = memcmp(target_data, dup_data, size);
				cache_block_put(target_buffer);
				cache_block_put(dup_buffer);
				if(res != 0)
					break;
				target_start += size;
				dup_start += size;
			}
			if(block == blocks) {
				struct file_buffer *frag_buffer =
					get_fragment(dupl_ptr->fragment);

				if(frag_bytes == 0 ||
						memcmp(file_buffer->data,
						frag_buffer->data +
						dupl_ptr->fragment->offset,
						frag_bytes) == 0) {
					TRACE("Found duplicate file, start "
						"0x%llx, size %lld, checksum "
						"0x%x, fragment %d, size %d, "
						"offset %d, checksum 0x%x\n",
						dupl_ptr->start,
						dupl_ptr->bytes,
						dupl_ptr->checksum,
						dupl_ptr->fragment->index,
						frag_bytes,
						dupl_ptr->fragment->offset,
						fragment_checksum);
					*block_list = dupl_ptr->block_list;
					*start = dupl_ptr->start;
					*fragment = dupl_ptr->fragment;
					cache_block_put(frag_buffer);
					return 0;
				}
				cache_block_put(frag_buffer);
			}
		}


	return add_non_dup(file_size, bytes, *block_list, *start, *fragment,
		checksum, fragment_checksum, checksum_flag);
}


inline int is_fragment(struct inode_info *inode)
{
	int file_size = inode->buf.st_size;

	/*
	 * If this block is to be compressed differently to the
	 * fragment compression then it cannot be a fragment
	 */
	if(inode->noF != noF)
		return FALSE;

	return !inode->no_fragments && (file_size < block_size ||
		(inode->always_use_fragments && file_size & (block_size - 1)));
}


static int seq = 0;
void reader_read_process(struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;
	struct file_buffer *prev_buffer = NULL, *file_buffer;
	int status, res, byte, count = 0;
	int file = get_pseudo_file(inode->pseudo_id)->fd;
	int child = get_pseudo_file(inode->pseudo_id)->child;
	long long bytes = 0;

	while(1) {
		file_buffer = cache_get(reader_buffer, 0, 0);
		file_buffer->sequence = seq ++;
		file_buffer->noD = inode->noD;

		byte = read_bytes(file, file_buffer->data, block_size);
		if(byte == -1)
			goto read_err;

		file_buffer->size = byte;
		file_buffer->file_size = -1;
		file_buffer->block = count ++;
		file_buffer->error = FALSE;
		file_buffer->fragment = FALSE;
		bytes += byte;

		if(byte == 0)
			break;

		/*
		 * Update estimated_uncompressed block count.  This is done
		 * on every block rather than waiting for all blocks to be
		 * read incase write_file_process() is running in parallel
		 * with this.  Otherwise cur uncompressed block count may
		 * get ahead of the total uncompressed block count.
		 */ 
		estimated_uncompressed ++;

		if(prev_buffer)
			queue_put(from_reader, prev_buffer);
		prev_buffer = file_buffer;
	}

	/*
 	 * Update inode file size now that the size of the dynamic pseudo file
	 * is known.  This is needed for the -info option.
	 */
	inode->buf.st_size = bytes;

	res = waitpid(child, &status, 0);
	if(res == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		goto read_err;

	if(prev_buffer == NULL)
		prev_buffer = file_buffer;
	else {
		cache_block_put(file_buffer);
		seq --;
	}
	prev_buffer->file_size = bytes;
	prev_buffer->fragment = is_fragment(inode);
	queue_put(from_reader, prev_buffer);

	return;

read_err:
	if(prev_buffer) {
		cache_block_put(file_buffer);
		seq --;
		file_buffer = prev_buffer;
	}
	file_buffer->error = TRUE;
	queue_put(from_deflate, file_buffer);
}


void reader_read_file(struct dir_ent *dir_ent)
{
	struct stat *buf = &dir_ent->inode->buf, buf2;
	struct file_buffer *file_buffer;
	int blocks, byte, count, expected, file;
	long long bytes, read_size;
	struct inode_info *inode = dir_ent->inode;

	if(inode->read)
		return;

	inode->read = TRUE;
again:
	bytes = 0;
	count = 0;
	file_buffer = NULL;
	read_size = buf->st_size;
	blocks = (read_size + block_size - 1) >> block_log;

	file = open(dir_ent->pathname, O_RDONLY);
	if(file == -1) {
		file_buffer = cache_get(reader_buffer, 0, 0);
		file_buffer->sequence = seq ++;
		goto read_err;
	}

	do {
		expected = read_size - ((long long) count * block_size) >
			block_size ? block_size :
			read_size - ((long long) count * block_size);

		if(file_buffer)
			queue_put(from_reader, file_buffer);
		file_buffer = cache_get(reader_buffer, 0, 0);
		file_buffer->sequence = seq ++;
		file_buffer->noD = inode->noD;

		/*
		 * Always try to read block_size bytes from the file rather
		 * than expected bytes (which will be less than the block_size
		 * at the file tail) to check that the file hasn't grown
		 * since being stated.  If it is longer (or shorter) than
		 * expected, then restat, and try again.  Note the special
		 * case where the file is an exact multiple of the block_size
		 * is dealt with later.
		 */
		byte = file_buffer->size = read_bytes(file, file_buffer->data,
			block_size);

		file_buffer->file_size = read_size;

		if(byte == -1)
			goto read_err;

		if(byte != expected)
			goto restat;

		file_buffer->block = count;
		file_buffer->error = FALSE;
		file_buffer->fragment = FALSE;

		bytes += byte;
		count ++;
	} while(count < blocks);

	if(read_size != bytes)
		goto restat;

	if(expected == block_size) {
		/*
		 * Special case where we've not tried to read past the end of
		 * the file.  We expect to get EOF, i.e. the file isn't larger
		 * than we expect.
		 */
		char buffer;
		int res;

		res = read_bytes(file, &buffer, 1);
		if(res == -1)
			goto read_err;

		if(res != 0)
			goto restat;
	}

	file_buffer->fragment = is_fragment(inode);
	queue_put(from_reader, file_buffer);

	close(file);

	return;

restat:
	fstat(file, &buf2);
	close(file);
	if(read_size != buf2.st_size) {
		memcpy(buf, &buf2, sizeof(struct stat));
		file_buffer->error = 2;
		queue_put(from_deflate, file_buffer);
		goto again;
	}
read_err:
	file_buffer->error = TRUE;
	queue_put(from_deflate, file_buffer);
}


void reader_scan(struct dir_info *dir) {
	int i;

	for(i = 0; i < dir->count; i++) {
		struct dir_ent *dir_ent = dir->list[i];
		struct stat *buf = &dir_ent->inode->buf;
		if(dir_ent->inode->root_entry)
			continue;

		if(IS_PSEUDO_PROCESS(dir_ent->inode)) {
			reader_read_process(dir_ent);
			continue;
		}

		switch(buf->st_mode & S_IFMT) {
			case S_IFREG:
				reader_read_file(dir_ent);
				break;
			case S_IFDIR:
				reader_scan(dir_ent->dir);
				break;
		}
	}
}


void *reader(void *arg)
{
	int oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate);

	if(!sorted)
		reader_scan(queue_get(to_reader));
	else {
		int i;
		struct priority_entry *entry;

		queue_get(to_reader);
		for(i = 65535; i >= 0; i--)
			for(entry = priority_list[i]; entry;
							entry = entry->next)
				reader_read_file(entry->dir);
	}

	thread[0] = 0;

	pthread_exit(NULL);
}


void *writer(void *arg)
{
	int write_error = FALSE;
	int oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate);

	while(1) {
		struct file_buffer *file_buffer = queue_get(to_writer);
		off_t off;

		if(file_buffer == NULL) {
			queue_put(from_writer,
				write_error ? &write_error : NULL);
			continue;
		}

		off = file_buffer->block;

		pthread_mutex_lock(&pos_mutex);

		if(!write_error && lseek(fd, off, SEEK_SET) == -1) {
			ERROR("Lseek on destination failed because %s\n",
				strerror(errno));
			write_error = TRUE;
		}

		if(!write_error && write_bytes(fd, file_buffer->data,
				file_buffer->size) == -1) {
			ERROR("Write on destination failed because %s\n",
				strerror(errno));
			write_error = TRUE;
		}
		pthread_mutex_unlock(&pos_mutex);

		cache_block_put(file_buffer);
	}
}


int all_zero(struct file_buffer *file_buffer)
{
	int i;
	long entries = file_buffer->size / sizeof(long);
	long *p = (long *) file_buffer->data;

	for(i = 0; i < entries && p[i] == 0; i++);

	if(i == entries) {
		for(i = file_buffer->size & ~(sizeof(long) - 1);
			i < file_buffer->size && file_buffer->data[i] == 0;
			i++);

		return i == file_buffer->size;
	}

	return 0;
}


void *deflator(void *arg)
{
	void *stream = NULL;
	int res, oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate);

	res = compressor_init(comp, &stream, block_size, 1);
	if(res)
		BAD_ERROR("deflator:: compressor_init failed\n");

	while(1) {
		struct file_buffer *file_buffer = queue_get(from_reader);
		struct file_buffer *write_buffer;

		if(file_buffer->file_size == 0) {
			file_buffer->c_byte = 0;
			queue_put(from_deflate, file_buffer);
		} else if(sparse_files && all_zero(file_buffer)) { 
			file_buffer->c_byte = 0;
			queue_put(from_deflate, file_buffer);
		} else if(file_buffer->fragment) {
			file_buffer->c_byte = file_buffer->size;
			queue_put(from_deflate, file_buffer);
		} else {
			write_buffer = cache_get(writer_buffer, 0, 0);
			write_buffer->c_byte = mangle2(stream,
				write_buffer->data, file_buffer->data,
				file_buffer->size, block_size,
				file_buffer->noD, 1);
			write_buffer->sequence = file_buffer->sequence;
			write_buffer->file_size = file_buffer->file_size;
			write_buffer->block = file_buffer->block;
			write_buffer->size = SQUASHFS_COMPRESSED_SIZE_BLOCK
				(write_buffer->c_byte);
			write_buffer->fragment = FALSE;
			write_buffer->error = FALSE;
			cache_block_put(file_buffer);
			queue_put(from_deflate, write_buffer);
		}
	}
}


void *frag_deflator(void *arg)
{
	void *stream = NULL;
	int res, oldstate;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldstate);

	res = compressor_init(comp, &stream, block_size, 1);
	if(res)
		BAD_ERROR("frag_deflator:: compressor_init failed\n");

	while(1) {
		int c_byte, compressed_size;
		struct file_buffer *file_buffer = queue_get(to_frag);
		struct file_buffer *write_buffer =
			cache_get(writer_buffer, file_buffer->block +
			FRAG_INDEX, 1);

		c_byte = mangle2(stream, write_buffer->data, file_buffer->data,
			file_buffer->size, block_size, noF, 1);
		compressed_size = SQUASHFS_COMPRESSED_SIZE_BLOCK(c_byte);
		write_buffer->size = compressed_size;
		pthread_mutex_lock(&fragment_mutex);
		if(fragments_locked == FALSE) {
			fragment_table[file_buffer->block].size = c_byte;
			fragment_table[file_buffer->block].start_block = bytes;
			write_buffer->block = bytes;
			bytes += compressed_size;
			fragments_outstanding --;
			queue_put(to_writer, write_buffer);
			pthread_mutex_unlock(&fragment_mutex);
			TRACE("Writing fragment %lld, uncompressed size %d, "
				"compressed size %d\n", file_buffer->block,
				file_buffer->size, compressed_size);
		} else {
				pthread_mutex_unlock(&fragment_mutex);
				add_pending_fragment(write_buffer, c_byte,
					file_buffer->block);
		}
		cache_block_put(file_buffer);
	}
}


#define HASH_ENTRIES		256
#define BLOCK_HASH(a)		(a % HASH_ENTRIES)
struct file_buffer		*block_hash[HASH_ENTRIES];

void push_buffer(struct file_buffer *file_buffer)
{
	int hash = BLOCK_HASH(file_buffer->sequence);

	file_buffer->next = block_hash[hash];
	block_hash[hash] = file_buffer;
}


struct file_buffer *get_file_buffer(struct queue *queue)
{
	static unsigned int sequence = 0;
	int hash = BLOCK_HASH(sequence);
	struct file_buffer *file_buffer = block_hash[hash], *prev = NULL;

	for(;file_buffer; prev = file_buffer, file_buffer = file_buffer->next)
		if(file_buffer->sequence == sequence)
			break;

	if(file_buffer) {
		if(prev)
			prev->next = file_buffer->next;
		else
			block_hash[hash] = file_buffer->next;
	} else {
		while(1) {
			file_buffer = queue_get(queue);
			if(file_buffer->sequence == sequence)
				break;
			push_buffer(file_buffer);
		}
	}

	sequence ++;

	return file_buffer;
}


void *progress_thrd(void *arg)
{
	struct timeval timeval;
	struct timespec timespec;
	struct itimerval itimerval;
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			printf("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
	signal(SIGWINCH, sigwinch_handler);
	signal(SIGALRM, sigalrm_handler);

	itimerval.it_value.tv_sec = 0;
	itimerval.it_value.tv_usec = 250000;
	itimerval.it_interval.tv_sec = 0;
	itimerval.it_interval.tv_usec = 250000;
	setitimer(ITIMER_REAL, &itimerval, NULL);

	pthread_cond_init(&progress_wait, NULL);

	pthread_mutex_lock(&progress_mutex);

	while(1) {
		gettimeofday(&timeval, NULL);
		timespec.tv_sec = timeval.tv_sec;
		if(timeval.tv_usec + 250000 > 999999)
			timespec.tv_sec++;
		timespec.tv_nsec = ((timeval.tv_usec + 250000) % 1000000) *
			1000;
		pthread_cond_timedwait(&progress_wait, &progress_mutex,
			&timespec);
		if(progress_enabled && estimated_uncompressed)
			progress_bar(cur_uncompressed, estimated_uncompressed,
				columns);
	}
}


void enable_progress_bar()
{
	pthread_mutex_lock(&progress_mutex);
	progress_enabled = TRUE;
	pthread_mutex_unlock(&progress_mutex);
}


void disable_progress_bar()
{
	pthread_mutex_lock(&progress_mutex);
	progress_enabled = FALSE;
	pthread_mutex_unlock(&progress_mutex);
}


void progress_bar(long long current, long long max, int columns)
{
	char rotate_list[] = { '|', '/', '-', '\\' };
	int max_digits, used, hashes, spaces;
	static int tty = -1;

	if(max == 0)
		return;

	max_digits = floor(log10(max)) + 1;
	used = max_digits * 2 + 11;
	hashes = (current * (columns - used)) / max;
	spaces = columns - used - hashes;

	if((current > max) || (columns - used < 0))
		return;

	if(tty == -1)
		tty = isatty(STDOUT_FILENO);
	if(!tty) {
		static long long previous = -1;

		/* Updating much more frequently than this results in huge
		 * log files. */
		if((current % 100) != 0 && current != max)
			return;
		/* Don't update just to rotate the spinner. */
		if(current == previous)
			return;
		previous = current;
	}

	printf("\r[");

	while (hashes --)
		putchar('=');

	putchar(rotate_list[rotate]);

	while(spaces --)
		putchar(' ');

	printf("] %*lld/%*lld", max_digits, current, max_digits, max);
	printf(" %3lld%%", current * 100 / max);
	fflush(stdout);
}


void write_file_empty(squashfs_inode *inode, struct dir_ent *dir_ent,
	int *duplicate_file)
{
	file_count ++;
	*duplicate_file = FALSE;
	create_inode(inode, NULL, dir_ent, SQUASHFS_FILE_TYPE, 0, 0, 0,
		 NULL, &empty_fragment, NULL, 0);
}


void write_file_frag_dup(squashfs_inode *inode, struct dir_ent *dir_ent,
	int size, int *duplicate_file, struct file_buffer *file_buffer,
	unsigned short checksum)
{
	struct file_info *dupl_ptr;
	struct fragment *fragment;
	unsigned int *block_listp = NULL;
	long long start = 0;

	dupl_ptr = duplicate(size, 0, &block_listp, &start, &fragment,
		file_buffer, 0, 0, checksum, TRUE);

	if(dupl_ptr) {
		*duplicate_file = FALSE;
		fragment = get_and_fill_fragment(file_buffer, dir_ent);
		dupl_ptr->fragment = fragment;
	} else
		*duplicate_file = TRUE;

	cache_block_put(file_buffer);

	total_bytes += size;
	file_count ++;

	inc_progress_bar();

	create_inode(inode, NULL, dir_ent, SQUASHFS_FILE_TYPE, size, 0,
			0, NULL, fragment, NULL, 0);
}


void write_file_frag(squashfs_inode *inode, struct dir_ent *dir_ent, int size,
	struct file_buffer *file_buffer, int *duplicate_file)
{
	struct fragment *fragment;
	unsigned short checksum;

	checksum = get_checksum_mem_buffer(file_buffer);

	if(pre_duplicate_frag(size, checksum)) {
		write_file_frag_dup(inode, dir_ent, size, duplicate_file,
			file_buffer, checksum);
		return;
	}
		
	fragment = get_and_fill_fragment(file_buffer, dir_ent);

	cache_block_put(file_buffer);

	if(duplicate_checking)
		add_non_dup(size, 0, NULL, 0, fragment, 0, checksum, TRUE);

	total_bytes += size;
	file_count ++;

	*duplicate_file = FALSE;

	inc_progress_bar();

	create_inode(inode, NULL, dir_ent, SQUASHFS_FILE_TYPE, size, 0,
			0, NULL, fragment, NULL, 0);

	return;
}


int write_file_process(squashfs_inode *inode, struct dir_ent *dir_ent,
	struct file_buffer *read_buffer, int *duplicate_file)
{
	long long read_size, file_bytes, start;
	struct fragment *fragment;
	unsigned int *block_list = NULL;
	int block = 0, status;
	long long sparse = 0;
	struct file_buffer *fragment_buffer = NULL;

	*duplicate_file = FALSE;

	lock_fragments();

	file_bytes = 0;
	start = bytes;
	while (1) {
		read_size = read_buffer->file_size;
		if(read_buffer->fragment && read_buffer->c_byte)
			fragment_buffer = read_buffer;
		else {
			block_list = realloc(block_list, (block + 1) *
				sizeof(unsigned int));
			if(block_list == NULL)
				BAD_ERROR("Out of memory allocating block_list"
					"\n");
			block_list[block ++] = read_buffer->c_byte;
			if(read_buffer->c_byte) {
				read_buffer->block = bytes;
				bytes += read_buffer->size;
				cache_rehash(read_buffer, read_buffer->block);
				file_bytes += read_buffer->size;
				queue_put(to_writer, read_buffer);
			} else {
				sparse += read_buffer->size;
				cache_block_put(read_buffer);
			}
		}
		inc_progress_bar();

		if(read_size != -1)
			break;

		read_buffer = get_file_buffer(from_deflate);
		if(read_buffer->error)
			goto read_err;
	}

	unlock_fragments();
	fragment = get_and_fill_fragment(fragment_buffer, dir_ent);
	cache_block_put(fragment_buffer);

	if(duplicate_checking)
		add_non_dup(read_size, file_bytes, block_list, start, fragment,
			0, 0, FALSE);
	file_count ++;
	total_bytes += read_size;

	create_inode(inode, NULL, dir_ent, SQUASHFS_FILE_TYPE, read_size, start,
		 block, block_list, fragment, NULL, sparse);

	if(duplicate_checking == FALSE)
		free(block_list);

	return 0;

read_err:
	cur_uncompressed -= block;
	status = read_buffer->error;
	bytes = start;
	if(!block_device) {
		int res;

		queue_put(to_writer, NULL);
		if(queue_get(from_writer) != 0)
			EXIT_MKSQUASHFS();
		res = ftruncate(fd, bytes);
		if(res != 0)
			BAD_ERROR("Failed to truncate dest file because %s\n",
				strerror(errno));
	}
	unlock_fragments();
	free(block_list);
	cache_block_put(read_buffer);
	return status;
}


int write_file_blocks(squashfs_inode *inode, struct dir_ent *dir_ent,
	long long read_size, struct file_buffer *read_buffer,
	int *duplicate_file)
{
	long long file_bytes, start;
	struct fragment *fragment;
	unsigned int *block_list;
	int block, status;
	int blocks = (read_size + block_size - 1) >> block_log;
	long long sparse = 0;
	struct file_buffer *fragment_buffer = NULL;

	*duplicate_file = FALSE;

	block_list = malloc(blocks * sizeof(unsigned int));
	if(block_list == NULL)
		BAD_ERROR("Out of memory allocating block_list\n");

	lock_fragments();

	file_bytes = 0;
	start = bytes;
	for(block = 0; block < blocks;) {
		if(read_buffer->fragment && read_buffer->c_byte) {
			fragment_buffer = read_buffer;
			blocks = read_size >> block_log;
		} else {
			block_list[block] = read_buffer->c_byte;
			if(read_buffer->c_byte) {
				read_buffer->block = bytes;
				bytes += read_buffer->size;
				cache_rehash(read_buffer, read_buffer->block);
				file_bytes += read_buffer->size;
				queue_put(to_writer, read_buffer);
			} else {
				sparse += read_buffer->size;
				cache_block_put(read_buffer);
			}
		}
		inc_progress_bar();

		if(++block < blocks) {
			read_buffer = get_file_buffer(from_deflate);
			if(read_buffer->error)
				goto read_err;
		}
	}

	unlock_fragments();
	fragment = get_and_fill_fragment(fragment_buffer, dir_ent);
	cache_block_put(fragment_buffer);

	if(duplicate_checking)
		add_non_dup(read_size, file_bytes, block_list, start, fragment,
			0, 0, FALSE);
	file_count ++;
	total_bytes += read_size;

	/*
	 * sparse count is needed to ensure squashfs correctly reports a
 	 * a smaller block count on stat calls to sparse files.  This is
 	 * to ensure intelligent applications like cp correctly handle the
 	 * file as a sparse file.  If the file in the original filesystem isn't
 	 * stored as a sparse file then still store it sparsely in squashfs, but
 	 * report it as non-sparse on stat calls to preserve semantics
 	 */
	if(sparse && (dir_ent->inode->buf.st_blocks << 9) >= read_size)
		sparse = 0;

	create_inode(inode, NULL, dir_ent, SQUASHFS_FILE_TYPE, read_size, start,
		 blocks, block_list, fragment, NULL, sparse);

	if(duplicate_checking == FALSE)
		free(block_list);

	return 0;

read_err:
	cur_uncompressed -= block;
	status = read_buffer->error;
	bytes = start;
	if(!block_device) {
		int res;

		queue_put(to_writer, NULL);
		if(queue_get(from_writer) != 0)
			EXIT_MKSQUASHFS();
		res = ftruncate(fd, bytes);
		if(res != 0)
			BAD_ERROR("Failed to truncate dest file because %s\n",
				strerror(errno));
	}
	unlock_fragments();
	free(block_list);
	cache_block_put(read_buffer);
	return status;
}


int write_file_blocks_dup(squashfs_inode *inode, struct dir_ent *dir_ent,
	long long read_size, struct file_buffer *read_buffer,
	int *duplicate_file)
{
	int block, thresh;
	long long file_bytes, dup_start, start;
	struct fragment *fragment;
	struct file_info *dupl_ptr;
	int blocks = (read_size + block_size - 1) >> block_log;
	unsigned int *block_list, *block_listp;
	struct file_buffer **buffer_list;
	int status, num_locked_fragments;
	long long sparse = 0;
	struct file_buffer *fragment_buffer = NULL;

	block_list = malloc(blocks * sizeof(unsigned int));
	if(block_list == NULL)
		BAD_ERROR("Out of memory allocating block_list\n");
	block_listp = block_list;

	buffer_list = malloc(blocks * sizeof(struct file_buffer *));
	if(buffer_list == NULL)
		BAD_ERROR("Out of memory allocating file block list\n");

	num_locked_fragments = lock_fragments();

	file_bytes = 0;
	start = dup_start = bytes;
	thresh = blocks > (writer_buffer_size - num_locked_fragments) ?
		blocks - (writer_buffer_size - num_locked_fragments): 0;

	for(block = 0; block < blocks;) {
		if(read_buffer->fragment && read_buffer->c_byte) {
			fragment_buffer = read_buffer;
			blocks = read_size >> block_log;
		} else {
			block_list[block] = read_buffer->c_byte;

			if(read_buffer->c_byte) {
				read_buffer->block = bytes;
				bytes += read_buffer->size;
				file_bytes += read_buffer->size;
				cache_rehash(read_buffer, read_buffer->block);
				if(block < thresh) {
					buffer_list[block] = NULL;
					queue_put(to_writer, read_buffer);
				} else
					buffer_list[block] = read_buffer;
			} else {
				buffer_list[block] = NULL;
				sparse += read_buffer->size;
				cache_block_put(read_buffer);
			}
		}
		inc_progress_bar();

		if(++block < blocks) {
			read_buffer = get_file_buffer(from_deflate);
			if(read_buffer->error)
				goto read_err;
		}
	}

	dupl_ptr = duplicate(read_size, file_bytes, &block_listp, &dup_start,
		&fragment, fragment_buffer, blocks, 0, 0, FALSE);

	if(dupl_ptr) {
		*duplicate_file = FALSE;
		for(block = thresh; block < blocks; block ++)
			if(buffer_list[block])
				queue_put(to_writer, buffer_list[block]);
		fragment = get_and_fill_fragment(fragment_buffer, dir_ent);
		dupl_ptr->fragment = fragment;
	} else {
		*duplicate_file = TRUE;
		for(block = thresh; block < blocks; block ++)
			cache_block_put(buffer_list[block]);
		bytes = start;
		if(thresh && !block_device) {
			int res;

			queue_put(to_writer, NULL);
			if(queue_get(from_writer) != 0)
				EXIT_MKSQUASHFS();
			res = ftruncate(fd, bytes);
			if(res != 0)
				BAD_ERROR("Failed to truncate dest file because"
					"  %s\n", strerror(errno));
		}
	}

	unlock_fragments();
	cache_block_put(fragment_buffer);
	free(buffer_list);
	file_count ++;
	total_bytes += read_size;

	/*
	 * sparse count is needed to ensure squashfs correctly reports a
 	 * a smaller block count on stat calls to sparse files.  This is
 	 * to ensure intelligent applications like cp correctly handle the
 	 * file as a sparse file.  If the file in the original filesystem isn't
 	 * stored as a sparse file then still store it sparsely in squashfs, but
 	 * report it as non-sparse on stat calls to preserve semantics
 	 */
	if(sparse && (dir_ent->inode->buf.st_blocks << 9) >= read_size)
		sparse = 0;

	create_inode(inode, NULL, dir_ent, SQUASHFS_FILE_TYPE, read_size,
		dup_start, blocks, block_listp, fragment, NULL, sparse);

	if(*duplicate_file == TRUE)
		free(block_list);

	return 0;

read_err:
	cur_uncompressed -= block;
	status = read_buffer->error;
	bytes = start;
	if(thresh && !block_device) {
		int res;

		queue_put(to_writer, NULL);
		if(queue_get(from_writer) != 0)
			EXIT_MKSQUASHFS();
		res = ftruncate(fd, bytes);
		if(res != 0)
			BAD_ERROR("Failed to truncate dest file because %s\n",
				strerror(errno));
	}
	unlock_fragments();
	for(blocks = thresh; blocks < block; blocks ++)
		cache_block_put(buffer_list[blocks]);
	free(buffer_list);
	free(block_list);
	cache_block_put(read_buffer);
	return status;
}


void write_file(squashfs_inode *inode, struct dir_ent *dir_ent,
	int *duplicate_file)
{
	int status;
	struct file_buffer *read_buffer;
	long long read_size;

again:
	read_buffer = get_file_buffer(from_deflate);

	status = read_buffer->error;
	if(status) {
		cache_block_put(read_buffer);
		goto file_err;
	}
	
	read_size = read_buffer->file_size;

	if(read_size == -1)
		status = write_file_process(inode, dir_ent, read_buffer,
			duplicate_file);
	else if(read_size == 0) {
		write_file_empty(inode, dir_ent, duplicate_file);
		cache_block_put(read_buffer);
	} else if(read_buffer->fragment && read_buffer->c_byte)
		write_file_frag(inode, dir_ent, read_size, read_buffer,
			duplicate_file);
	else if(pre_duplicate(read_size))
		status = write_file_blocks_dup(inode, dir_ent, read_size,
			read_buffer, duplicate_file);
	else
		status = write_file_blocks(inode, dir_ent, read_size,
			read_buffer, duplicate_file);

file_err:
	if(status == 2) {
		ERROR("File %s changed size while reading filesystem, "
			"attempting to re-read\n", dir_ent->pathname);
		goto again;
	} else if(status == 1) {
		ERROR("Failed to read file %s, creating empty file\n",
			dir_ent->pathname);
		write_file_empty(inode, dir_ent, duplicate_file);
	}
}


#define BUFF_SIZE 8192
char b_buffer[BUFF_SIZE];
char *name;
char *basename_r();

char *getbase(char *pathname)
{
	char *result;

	if(*pathname != '/') {
		result = getcwd(b_buffer, BUFF_SIZE);
		if(result == NULL)
			return NULL;
		strcat(strcat(b_buffer, "/"), pathname);
	} else
		strcpy(b_buffer, pathname);
	name = b_buffer;
	if(((result = basename_r()) == NULL) || (strcmp(result, "..") == 0))
		return NULL;
	else
		return result;
}


char *basename_r()
{
	char *s;
	char *p;
	int n = 1;

	for(;;) {
		s = name;
		if(*name == '\0')
			return NULL;
		if(*name != '/') {
			while(*name != '\0' && *name != '/') name++;
			n = name - s;
		}
		while(*name == '/') name++;
		if(strncmp(s, ".", n) == 0)
			continue;
		if((*name == '\0') || (strncmp(s, "..", n) == 0) ||
				((p = basename_r()) == NULL)) {
			s[n] = '\0';
			return s;
		}
		if(strcmp(p, "..") == 0)
			continue;
		return p;
	}
}


struct inode_info *lookup_inode(struct stat *buf)
{
	int inode_hash = INODE_HASH(buf->st_dev, buf->st_ino);
	struct inode_info *inode = inode_info[inode_hash];

	while(inode != NULL) {
		if(memcmp(buf, &inode->buf, sizeof(struct stat)) == 0) {
			inode->nlink ++;
			return inode;
		}
		inode = inode->next;
	}

	inode = malloc(sizeof(struct inode_info));
	if(inode == NULL)
		BAD_ERROR("Out of memory in inode hash table entry allocation"
			"\n");

	memcpy(&inode->buf, buf, sizeof(struct stat));
	inode->read = FALSE;
	inode->root_entry = FALSE;
	inode->pseudo_file = FALSE;
	inode->inode = SQUASHFS_INVALID_BLK;
	inode->nlink = 1;

	/*
	 * Copy filesystem wide defaults into inode, these filesystem
	 * wide defaults may be altered on an individual inode basis by
	 * user specified actions
	 *
	*/
	inode->no_fragments = no_fragments;
	inode->always_use_fragments = always_use_fragments;
	inode->noD = noD;
	inode->noF = noF;

	if((buf->st_mode & S_IFMT) == S_IFREG)
		estimated_uncompressed += (buf->st_size + block_size - 1) >>
			block_log;

	if((buf->st_mode & S_IFMT) == S_IFDIR)
		inode->inode_number = dir_inode_no ++;
	else
		inode->inode_number = inode_no ++;

	inode->next = inode_info[inode_hash];
	inode_info[inode_hash] = inode;

	return inode;
}


void add_dir_entry(char *name, char *pathname, struct dir_info *sub_dir,
	struct inode_info *inode_info, struct dir_info *dir)
{
	if((dir->count % DIR_ENTRIES) == 0) {
		dir->list = realloc(dir->list, (dir->count + DIR_ENTRIES) *
				sizeof(struct dir_ent *));
		if(dir->list == NULL)
			BAD_ERROR("Out of memory in add_dir_entry\n");
	}

	dir->list[dir->count] = malloc(sizeof(struct dir_ent));
	if(dir->list[dir->count] == NULL)
		BAD_ERROR("Out of memory in linux_opendir\n");

	if(sub_dir)
		sub_dir->dir_ent = dir->list[dir->count];
	dir->list[dir->count]->name = strdup(name);
	dir->list[dir->count]->pathname = pathname != NULL ? strdup(pathname) :
		NULL;
	dir->list[dir->count]->inode = inode_info;
	dir->list[dir->count]->dir = sub_dir;
	dir->list[dir->count++]->our_dir = dir;
	dir->byte_count += strlen(name) + sizeof(struct squashfs_dir_entry);
}


inline void add_excluded(struct dir_info *dir)
{
	dir->excluded ++;
}


int compare_name(const void *ent1_ptr, const void *ent2_ptr)
{
	struct dir_ent *ent1 = *((struct dir_ent **) ent1_ptr);
	struct dir_ent *ent2 = *((struct dir_ent **) ent2_ptr);

	return strcmp(ent1->name, ent2->name);
}


void sort_directory(struct dir_info *dir)
{
	qsort(dir->list, dir->count, sizeof(struct dir_ent *), compare_name);

	if((dir->count < 257 && dir->byte_count < SQUASHFS_METADATA_SIZE))
		dir->dir_is_ldir = FALSE;
}


struct dir_info *scan1_opendir(char *pathname, int depth)
{
	struct dir_info *dir;

	dir = malloc(sizeof(struct dir_info));
	if(dir == NULL)
		BAD_ERROR("Out of memory in scan1_opendir\n");

	if(pathname[0] != '\0' && (dir->linuxdir = opendir(pathname)) == NULL) {
		free(dir);
		return NULL;
	}
	dir->pathname = strdup(pathname);
	dir->count = 0;
	dir->directory_count = 0;
	dir->current_count = 0;
	dir->byte_count = 0;
	dir->dir_is_ldir = TRUE;
	dir->list = NULL;
	dir->depth = depth;
	dir->excluded = 0;

	return dir;
}


int scan1_encomp_readdir(char *pathname, char *dir_name, struct dir_info *dir)
{
	static int index = 0;

	if(dir->count < old_root_entries) {
		int i;

		for(i = 0; i < old_root_entries; i++) {
			if(old_root_entry[i].inode.type == SQUASHFS_DIR_TYPE)
				dir->directory_count ++;
			add_dir_entry(old_root_entry[i].name, "", NULL,
				&old_root_entry[i].inode, dir);
		}
	}

	while(index < source) {
		char *basename = getbase(source_path[index]);
		int n, pass = 1;

		if(basename == NULL) {
			ERROR("Bad source directory %s - skipping ...\n",
				source_path[index]);
			index ++;
			continue;
		}
		strcpy(dir_name, basename);
		for(;;) {
			for(n = 0; n < dir->count &&
				strcmp(dir->list[n]->name, dir_name) != 0; n++);
			if(n == dir->count)
				break;
			ERROR("Source directory entry %s already used! - trying"
				" ", dir_name);
			sprintf(dir_name, "%s_%d", basename, pass++);
			ERROR("%s\n", dir_name);
		}
		strcpy(pathname, source_path[index ++]);
		return 1;
	}
	return 0;
}


int scan1_single_readdir(char *pathname, char *dir_name, struct dir_info *dir)
{
	struct dirent *d_name;
	int i;

	if(dir->count < old_root_entries) {
		for(i = 0; i < old_root_entries; i++) {
			if(old_root_entry[i].inode.type == SQUASHFS_DIR_TYPE)
				dir->directory_count ++;
			add_dir_entry(old_root_entry[i].name, "", NULL,
				&old_root_entry[i].inode, dir);
		}
	}

	if((d_name = readdir(dir->linuxdir)) != NULL) {
		int pass = 1;

		strcpy(dir_name, d_name->d_name);
		for(;;) {
			for(i = 0; i < dir->count &&
				strcmp(dir->list[i]->name, dir_name) != 0; i++);
			if(i == dir->count)
				break;
			ERROR("Source directory entry %s already used! - trying"
				" ", dir_name);
			sprintf(dir_name, "%s_%d", d_name->d_name, pass++);
			ERROR("%s\n", dir_name);
		}
		strcat(strcat(strcpy(pathname, dir->pathname), "/"),
			d_name->d_name);
		return 1;
	}

	return 0;
}


int scan1_readdir(char *pathname, char *dir_name, struct dir_info *dir)
{
	struct dirent *d_name = readdir(dir->linuxdir);

	if(d_name != NULL) {
		strcpy(dir_name, d_name->d_name);
		strcat(strcat(strcpy(pathname, dir->pathname), "/"),
			d_name->d_name);
		return 1;
	}

	return 0;
}


struct dir_ent *scan2_readdir(struct dir_info *dir_info)
{
	int current_count;

	while((current_count = dir_info->current_count++) < dir_info->count)
		if(dir_info->list[current_count]->inode->root_entry)
			continue;
		else 
			return dir_info->list[current_count];
	return NULL;	
}


struct dir_ent *scan2_lookup(struct dir_info *dir, char *name)
{
	int i;

	for(i = 0; i < dir->count; i++)
		if(strcmp(dir->list[i]->name, name) == 0)
			return dir->list[i];

	return NULL;
}


struct dir_ent *scan3_readdir(struct directory *dir, struct dir_info *dir_info)
{
	int current_count;

	while((current_count = dir_info->current_count++) < dir_info->count)
		if(dir_info->list[current_count]->inode->root_entry)
			add_dir(dir_info->list[current_count]->inode->inode,
				dir_info->list[current_count]->inode->inode_number,
				dir_info->list[current_count]->name,
				dir_info->list[current_count]->inode->type, dir);
		else 
			return dir_info->list[current_count];
	return NULL;	
}


void scan1_freedir(struct dir_info *dir)
{
	if(dir->pathname[0] != '\0')
		closedir(dir->linuxdir);
	free(dir->pathname);
	dir->pathname = NULL;
}


void scan2_freedir(struct dir_info *dir)
{
	dir->current_count = 0;
	if(dir->pathname) {
		free(dir->pathname);
		dir->pathname = NULL;
	}
}


void scan3_freedir(struct directory *dir)
{
	if(dir->index)
		free(dir->index);
	free(dir->buff);
}


void dir_scan(squashfs_inode *inode, char *pathname,
	int (_readdir)(char *, char *, struct dir_info *))
{
	struct stat buf;
	struct dir_info *dir_info = dir_scan1(pathname, paths, _readdir, 1);
	struct dir_ent *dir_ent;
	
	if(dir_info == NULL)
		return;

	dir_scan2(dir_info, pseudo, 1);

	dir_ent = malloc(sizeof(struct dir_ent));
	if(dir_ent == NULL)
		BAD_ERROR("Out of memory in dir_scan\n");

	if(pathname[0] == '\0') {
		/*
 		 * dummy top level directory, if multiple sources specified on
		 * command line
		 */
		memset(&buf, 0, sizeof(buf));
		buf.st_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFDIR;
		buf.st_uid = getuid();
		buf.st_gid = getgid();
		buf.st_mtime = time(NULL);
		buf.st_dev = 0;
		buf.st_ino = 0;
		dir_ent->inode = lookup_inode(&buf);
		dir_ent->inode->pseudo_file = PSEUDO_FILE_OTHER;
	} else {
		if(lstat(pathname, &buf) == -1) {
			ERROR("Cannot stat dir/file %s because %s, ignoring",
				pathname, strerror(errno));
			return;
		}
		dir_ent->inode = lookup_inode(&buf);
	}

	if(root_inode_number) {
		dir_ent->inode->inode_number = root_inode_number;
		dir_inode_no --;
	}
	dir_ent->name = dir_ent->pathname = strdup(pathname);
	dir_ent->dir = dir_info;
	dir_ent->our_dir = NULL;
	dir_info->dir_ent = dir_ent;

	if(sorted) {
		int res = generate_file_priorities(dir_info, 0,
			&dir_info->dir_ent->inode->buf);

		if(res == FALSE)
			BAD_ERROR("generate_file_priorities failed\n");
	}
	queue_put(to_reader, dir_info);
	if(sorted)
		sort_files_and_write(dir_info);
	if(progress)
		enable_progress_bar();
	dir_scan3(inode, dir_info);
	dir_ent->inode->inode = *inode;
	dir_ent->inode->type = SQUASHFS_DIR_TYPE;
}


struct dir_info *dir_scan1(char *pathname, struct pathnames *paths,
	int (_readdir)(char *, char *, struct dir_info *), int depth)
{
	char filename[8192], dir_name[8192];
	struct dir_info *dir = scan1_opendir(pathname, depth);

	if(dir == NULL) {
		ERROR("Could not open %s, skipping...\n", pathname);
		goto error;
	}

	while(_readdir(filename, dir_name, dir) != FALSE) {
		struct dir_info *sub_dir;
		struct stat buf;
		struct pathnames *new;

		if(strcmp(dir_name, ".") == 0 || strcmp(dir_name, "..") == 0)
			continue;

		if(lstat(filename, &buf) == -1) {
			ERROR("Cannot stat dir/file %s because %s, ignoring",
				filename, strerror(errno));
			continue;
		}

		if((buf.st_mode & S_IFMT) != S_IFREG &&
			(buf.st_mode & S_IFMT) != S_IFDIR &&
			(buf.st_mode & S_IFMT) != S_IFLNK &&
			(buf.st_mode & S_IFMT) != S_IFCHR &&
			(buf.st_mode & S_IFMT) != S_IFBLK &&
			(buf.st_mode & S_IFMT) != S_IFIFO &&
			(buf.st_mode & S_IFMT) != S_IFSOCK) {
			ERROR("File %s has unrecognised filetype %d, ignoring"
				"\n", filename, buf.st_mode & S_IFMT);
			continue;
		}

		if((old_exclude && old_excluded(filename, &buf)) ||
				excluded(paths, dir_name, &new) ||
				eval_exclude_actions(dir_name, filename, &buf,
							depth)) {
			add_excluded(dir);
			continue;
		}

		if((buf.st_mode & S_IFMT) == S_IFDIR) {
			sub_dir = dir_scan1(filename, new, scan1_readdir,
							depth + 1);
			if(sub_dir == NULL)
				continue;

			if(eval_empty_actions(dir_name, filename, &buf, depth,
						sub_dir)) {
				add_excluded(dir);
				continue;
			}

			dir->directory_count ++;
		} else
			sub_dir = NULL;

		add_dir_entry(dir_name, filename, sub_dir, lookup_inode(&buf),
			dir);
	}

	scan1_freedir(dir);

error:
	return dir;
}


struct dir_info *dir_scan2(struct dir_info *dir, struct pseudo *pseudo, int depth)
{
	struct dir_info *sub_dir;
	struct dir_ent *dir_ent;
	struct pseudo_entry *pseudo_ent;
	struct stat buf;
	static int pseudo_ino = 1;
	
	if(dir == NULL && (dir = scan1_opendir("", depth)) == NULL)
		return NULL;
	
	while((dir_ent = scan2_readdir(dir)) != NULL) {
		struct inode_info *inode_info = dir_ent->inode;
		struct stat *buf = &inode_info->buf;
		char *name = dir_ent->name;

		eval_actions(dir_ent);

		if((buf->st_mode & S_IFMT) == S_IFDIR)
			dir_scan2(dir_ent->dir, pseudo_subdir(name, pseudo),
								depth + 1);
	}

	while((pseudo_ent = pseudo_readdir(pseudo)) != NULL) {
		dir_ent = scan2_lookup(dir, pseudo_ent->name);
		if(pseudo_ent->dev->type == 'm') {
			struct stat *buf;
			if(dir_ent == NULL) {
				ERROR("Pseudo modify file \"%s\" does not exist "
					"in source filesystem.  Ignoring.\n",
					pseudo_ent->pathname);
				continue;
			}
			if(dir_ent->inode->root_entry) {
				ERROR("Pseudo modify file \"%s\" is a pre-existing"
					" file in the filesystem being appended"
					"  to.  It cannot be modified. "
					"Ignoring.\n", pseudo_ent->pathname);
				continue;
			}
			buf = &dir_ent->inode->buf;
			buf->st_mode = (buf->st_mode & S_IFMT) |
				pseudo_ent->dev->mode;
			buf->st_uid = pseudo_ent->dev->uid;
			buf->st_gid = pseudo_ent->dev->gid;
			continue;
		}

		if(dir_ent) {
			if(dir_ent->inode->root_entry)
				ERROR("Pseudo file \"%s\" is a pre-existing"
					" file in the filesystem being appended"
					"  to.  Ignoring.\n",
					pseudo_ent->pathname);
			else
				ERROR("Pseudo file \"%s\" exists in source "
					"filesystem \"%s\".\nIgnoring, "
					"exclude it (-e/-ef) to override.\n",
					pseudo_ent->pathname,
					dir_ent->pathname);
			continue;
		}

		if(pseudo_ent->dev->type == 'd') {
			sub_dir = dir_scan2(NULL, pseudo_ent->pseudo, depth + 1);
			if(sub_dir == NULL) {
				ERROR("Could not create pseudo directory \"%s\""
					", skipping...\n",
					pseudo_ent->pathname);
				continue;
			}
			dir->directory_count ++;
		} else
			sub_dir = NULL;

		memset(&buf, 0, sizeof(buf));
		buf.st_mode = pseudo_ent->dev->mode;
		buf.st_uid = pseudo_ent->dev->uid;
		buf.st_gid = pseudo_ent->dev->gid;
		buf.st_rdev = makedev(pseudo_ent->dev->major,
			pseudo_ent->dev->minor);
		buf.st_mtime = time(NULL);
		buf.st_ino = pseudo_ino ++;

		if(pseudo_ent->dev->type == 'f') {
#ifdef USE_TMP_FILE
			struct stat buf2;
			int res = stat(pseudo_ent->dev->filename, &buf2);
			struct inode_info *inode;
			if(res == -1) {
				ERROR("Stat on pseudo file \"%s\" failed, "
					"skipping...", pseudo_ent->pathname);
				continue;
			}
			buf.st_size = buf2.st_size;
			inode = lookup_inode(&buf);
			inode->pseudo_file = PSEUDO_FILE_OTHER;		
			add_dir_entry(pseudo_ent->name,
				pseudo_ent->dev->filename, sub_dir, inode,
				dir);
#else
			struct inode_info *inode = lookup_inode(&buf);
			inode->pseudo_id = pseudo_ent->dev->pseudo_id;
			inode->pseudo_file = PSEUDO_FILE_PROCESS;		
			add_dir_entry(pseudo_ent->name, pseudo_ent->pathname,
				sub_dir, inode, dir);
#endif
		} else {
			struct inode_info *inode = lookup_inode(&buf);
			inode->pseudo_file = PSEUDO_FILE_OTHER;		
			add_dir_entry(pseudo_ent->name, pseudo_ent->pathname,
				sub_dir, inode, dir);
		}
	}

	scan2_freedir(dir);
	sort_directory(dir);

	return dir;
}


void dir_scan3(squashfs_inode *inode, struct dir_info *dir_info)
{
	int squashfs_type;
	int duplicate_file;
	char *pathname = dir_info->dir_ent->pathname;
	struct directory dir;
	struct dir_ent *dir_ent;
	
	scan3_init_dir(&dir);
	
	while((dir_ent = scan3_readdir(&dir, dir_info)) != NULL) {
		struct inode_info *inode_info = dir_ent->inode;
		struct stat *buf = &inode_info->buf;
		char *filename = dir_ent->pathname;
		char *dir_name = dir_ent->name;
		unsigned int inode_number = ((buf->st_mode & S_IFMT) == S_IFDIR)
			?  dir_ent->inode->inode_number :
			dir_ent->inode->inode_number + dir_inode_no;

		if(dir_ent->inode->inode == SQUASHFS_INVALID_BLK) {
			switch(buf->st_mode & S_IFMT) {
				case S_IFREG:
					squashfs_type = SQUASHFS_FILE_TYPE;
					write_file(inode, dir_ent,
						&duplicate_file);
					INFO("file %s, uncompressed size %lld "
						"bytes %s\n", filename,
						(long long) buf->st_size,
						duplicate_file ?  "DUPLICATE" :
						 "");
					break;

				case S_IFDIR:
					squashfs_type = SQUASHFS_DIR_TYPE;
					dir_scan3(inode, dir_ent->dir);
					break;

				case S_IFLNK:
					squashfs_type = SQUASHFS_SYMLINK_TYPE;
					create_inode(inode, NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("symbolic link %s inode 0x%llx\n",
						dir_name, *inode);
					sym_count ++;
					break;

				case S_IFCHR:
					squashfs_type = SQUASHFS_CHRDEV_TYPE;
					create_inode(inode, NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("character device %s inode 0x%llx"
						"\n", dir_name, *inode);
					dev_count ++;
					break;

				case S_IFBLK:
					squashfs_type = SQUASHFS_BLKDEV_TYPE;
					create_inode(inode, NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("block device %s inode 0x%llx\n",
						dir_name, *inode);
					dev_count ++;
					break;

				case S_IFIFO:
					squashfs_type = SQUASHFS_FIFO_TYPE;
					create_inode(inode, NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("fifo %s inode 0x%llx\n",dir_name,
						*inode);
					fifo_count ++;
					break;

				case S_IFSOCK:
					squashfs_type = SQUASHFS_SOCKET_TYPE;
					create_inode(inode, NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("unix domain socket %s inode "
						"0x%llx\n", dir_name, *inode);
					sock_count ++;
					break;

				default:
					BAD_ERROR("%s unrecognised file type, "
						"mode is %x\n", filename,
						buf->st_mode);
			}
			dir_ent->inode->inode = *inode;
			dir_ent->inode->type = squashfs_type;
		 } else {
			*inode = dir_ent->inode->inode;
			squashfs_type = dir_ent->inode->type;
			switch(squashfs_type) {
				case SQUASHFS_FILE_TYPE:
					if(!sorted)
						INFO("file %s, uncompressed "
							"size %lld bytes LINK"
							"\n", filename,
							(long long)
							buf->st_size);
					break;
				case SQUASHFS_SYMLINK_TYPE:
					INFO("symbolic link %s inode 0x%llx "
						"LINK\n", dir_name, *inode);
					break;
				case SQUASHFS_CHRDEV_TYPE:
					INFO("character device %s inode 0x%llx "
						"LINK\n", dir_name, *inode);
					break;
				case SQUASHFS_BLKDEV_TYPE:
					INFO("block device %s inode 0x%llx "
						"LINK\n", dir_name, *inode);
					break;
				case SQUASHFS_FIFO_TYPE:
					INFO("fifo %s inode 0x%llx LINK\n",
						dir_name, *inode);
					break;
				case SQUASHFS_SOCKET_TYPE:
					INFO("unix domain socket %s inode "
						"0x%llx LINK\n", dir_name,
						*inode);
					break;
			}
		}
		
		add_dir(*inode, inode_number, dir_name, squashfs_type, &dir);
		update_progress_bar();
	}

	write_dir(inode, dir_info, &dir);
	INFO("directory %s inode 0x%llx\n", pathname, *inode);

	scan3_freedir(&dir);
}


unsigned int slog(unsigned int block)
{
	int i;

	for(i = 12; i <= 20; i++)
		if(block == (1 << i))
			return i;
	return 0;
}


int old_excluded(char *filename, struct stat *buf)
{
	int i;

	for(i = 0; i < exclude; i++)
		if((exclude_paths[i].st_dev == buf->st_dev) &&
				(exclude_paths[i].st_ino == buf->st_ino))
			return TRUE;
	return FALSE;
}


#define ADD_ENTRY(buf) \
	if(exclude % EXCLUDE_SIZE == 0) { \
		exclude_paths = realloc(exclude_paths, (exclude + EXCLUDE_SIZE) \
			* sizeof(struct exclude_info)); \
		if(exclude_paths == NULL) \
			BAD_ERROR("Out of memory in exclude dir/file table\n"); \
	} \
	exclude_paths[exclude].st_dev = buf.st_dev; \
	exclude_paths[exclude++].st_ino = buf.st_ino;
int old_add_exclude(char *path)
{
	int i;
	char filename[4096];
	struct stat buf;

	if(path[0] == '/' || strncmp(path, "./", 2) == 0 ||
			strncmp(path, "../", 3) == 0) {
		if(lstat(path, &buf) == -1) {
			ERROR("Cannot stat exclude dir/file %s because %s, "
				"ignoring", path, strerror(errno));
			return TRUE;
		}
		ADD_ENTRY(buf);
		return TRUE;
	}

	for(i = 0; i < source; i++) {
		strcat(strcat(strcpy(filename, source_path[i]), "/"), path);
		if(lstat(filename, &buf) == -1) {
			if(!(errno == ENOENT || errno == ENOTDIR))
				ERROR("Cannot stat exclude dir/file %s because "
					"%s, ignoring", filename,
					strerror(errno));
			continue;
		}
		ADD_ENTRY(buf);
	}
	return TRUE;
}


void add_old_root_entry(char *name, squashfs_inode inode, int inode_number,
	int type)
{
	old_root_entry = realloc(old_root_entry,
		sizeof(struct old_root_entry_info) * (old_root_entries + 1));
	if(old_root_entry == NULL)
		BAD_ERROR("Out of memory in old root directory entries "
			"reallocation\n");

	old_root_entry[old_root_entries].name = strdup(name);
	old_root_entry[old_root_entries].inode.inode = inode;
	old_root_entry[old_root_entries].inode.inode_number = inode_number;
	old_root_entry[old_root_entries].inode.type = type;
	old_root_entry[old_root_entries++].inode.root_entry = TRUE;
}


void initialise_threads(int readb_mbytes, int writeb_mbytes,
	int fragmentb_mbytes)
{
	int i;
	sigset_t sigmask, old_mask;
	int reader_buffer_size = readb_mbytes << (20 - block_log);
	int fragment_buffer_size = fragmentb_mbytes << (20 - block_log);

	/*
	 * writer_buffer_size is global because it is needed in
	 * write_file_blocks_dup()
	 */
	writer_buffer_size = writeb_mbytes << (20 - block_log);

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGQUIT);
	if(sigprocmask(SIG_BLOCK, &sigmask, &old_mask) == -1)
		BAD_ERROR("Failed to set signal mask in intialise_threads\n");

	signal(SIGUSR1, sigusr1_handler);

	if(processors == -1) {
#ifndef linux
		int mib[2];
		size_t len = sizeof(processors);

		mib[0] = CTL_HW;
#ifdef HW_AVAILCPU
		mib[1] = HW_AVAILCPU;
#else
		mib[1] = HW_NCPU;
#endif

		if(sysctl(mib, 2, &processors, &len, NULL, 0) == -1) {
			ERROR("Failed to get number of available processors.  "
				"Defaulting to 1\n");
			processors = 1;
		}
#else
		processors = sysconf(_SC_NPROCESSORS_ONLN);
#endif
	}

	thread = malloc((2 + processors * 2) * sizeof(pthread_t));
	if(thread == NULL)
		BAD_ERROR("Out of memory allocating thread descriptors\n");
	deflator_thread = &thread[2];
	frag_deflator_thread = &deflator_thread[processors];

	to_reader = queue_init(1);
	from_reader = queue_init(reader_buffer_size);
	to_writer = queue_init(writer_buffer_size);
	from_writer = queue_init(1);
	from_deflate = queue_init(reader_buffer_size);
	to_frag = queue_init(fragment_buffer_size);
	reader_buffer = cache_init(block_size, reader_buffer_size);
	writer_buffer = cache_init(block_size, writer_buffer_size);
	fragment_buffer = cache_init(block_size, fragment_buffer_size);
	pthread_create(&thread[0], NULL, reader, NULL);
	pthread_create(&thread[1], NULL, writer, NULL);
	pthread_create(&progress_thread, NULL, progress_thrd, NULL);
	pthread_mutex_init(&fragment_mutex, NULL);
	pthread_cond_init(&fragment_waiting, NULL);

	for(i = 0; i < processors; i++) {
		if(pthread_create(&deflator_thread[i], NULL, deflator, NULL) !=
				 0)
			BAD_ERROR("Failed to create thread\n");
		if(pthread_create(&frag_deflator_thread[i], NULL, frag_deflator,
				NULL) != 0)
			BAD_ERROR("Failed to create thread\n");
	}

	printf("Parallel mksquashfs: Using %d processor%s\n", processors,
			processors == 1 ? "" : "s");

	if(sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
		BAD_ERROR("Failed to set signal mask in intialise_threads\n");
}


long long write_inode_lookup_table()
{
	int i, inode_number, lookup_bytes = SQUASHFS_LOOKUP_BYTES(inode_count);
	void *it;

	if(inode_count == sinode_count)
		goto skip_inode_hash_table;

	it = realloc(inode_lookup_table, lookup_bytes);
	if(it == NULL)
		BAD_ERROR("Out of memory in write_inode_table\n");
	inode_lookup_table = it;

	for(i = 0; i < INODE_HASH_SIZE; i ++) {
		struct inode_info *inode = inode_info[i];

		for(inode = inode_info[i]; inode; inode = inode->next) {

			inode_number = inode->type == SQUASHFS_DIR_TYPE ?
				inode->inode_number : inode->inode_number +
				dir_inode_no;

			SQUASHFS_SWAP_LONG_LONGS(&inode->inode,
				&inode_lookup_table[inode_number - 1], 1);

		}
	}

skip_inode_hash_table:
	return generic_write_table(lookup_bytes, inode_lookup_table, 0, NULL,
		noI);
}


char *get_component(char *target, char *targname)
{
	while(*target == '/')
		target ++;

	while(*target != '/' && *target!= '\0')
		*targname ++ = *target ++;

	*targname = '\0';

	return target;
}


void free_path(struct pathname *paths)
{
	int i;

	for(i = 0; i < paths->names; i++) {
		if(paths->name[i].paths)
			free_path(paths->name[i].paths);
		free(paths->name[i].name);
		if(paths->name[i].preg) {
			regfree(paths->name[i].preg);
			free(paths->name[i].preg);
		}
	}

	free(paths);
}


struct pathname *add_path(struct pathname *paths, char *target, char *alltarget)
{
	char targname[1024];
	int i, error;

	target = get_component(target, targname);

	if(paths == NULL) {
		paths = malloc(sizeof(struct pathname));
		if(paths == NULL)
			BAD_ERROR("failed to allocate paths\n");

		paths->names = 0;
		paths->name = NULL;
	}

	for(i = 0; i < paths->names; i++)
		if(strcmp(paths->name[i].name, targname) == 0)
			break;

	if(i == paths->names) {
		/* allocate new name entry */
		paths->names ++;
		paths->name = realloc(paths->name, (i + 1) *
			sizeof(struct path_entry));
		if(paths->name == NULL)
			BAD_ERROR("Out of memory in add path\n");
		paths->name[i].name = strdup(targname);
		paths->name[i].paths = NULL;
		if(use_regex) {
			paths->name[i].preg = malloc(sizeof(regex_t));
			if(paths->name[i].preg == NULL)
				BAD_ERROR("Out of memory in add_path\n");
			error = regcomp(paths->name[i].preg, targname,
				REG_EXTENDED|REG_NOSUB);
			if(error) {
				char str[1024];

				regerror(error, paths->name[i].preg, str, 1024);
				BAD_ERROR("invalid regex %s in export %s, "
					"because %s\n", targname, alltarget,
					str);
			}
		} else
			paths->name[i].preg = NULL;

		if(target[0] == '\0')
			/* at leaf pathname component */
			paths->name[i].paths = NULL;
		else
			/* recurse adding child components */
			paths->name[i].paths = add_path(NULL, target,
				alltarget);
	} else {
		/* existing matching entry */
		if(paths->name[i].paths == NULL) {
			/* No sub-directory which means this is the leaf
			 * component of a pre-existing exclude which subsumes
			 * the exclude currently being added, in which case stop
			 * adding components */
		} else if(target[0] == '\0') {
			/* at leaf pathname component and child components exist
			 * from more specific excludes, delete as they're
			 * subsumed by this exclude */
			free_path(paths->name[i].paths);
			paths->name[i].paths = NULL;
		} else
			/* recurse adding child components */
			add_path(paths->name[i].paths, target, alltarget);
	}

	return paths;
}


void add_exclude(char *target)
{

	if(target[0] == '/' || strncmp(target, "./", 2) == 0 ||
			strncmp(target, "../", 3) == 0)
		BAD_ERROR("/, ./ and ../ prefixed excludes not supported with "
			"-wildcards or -regex options\n");	
	else if(strncmp(target, "... ", 4) == 0)
		stickypath = add_path(stickypath, target + 4, target + 4);
	else	
		path = add_path(path, target, target);
}


void display_path(int depth, struct pathname *paths)
{
	int i, n;

	if(paths == NULL)
		return;

	for(i = 0; i < paths->names; i++) {
		for(n = 0; n < depth; n++)
			printf("\t");
		printf("%d: %s\n", depth, paths->name[i].name);
		display_path(depth + 1, paths->name[i].paths);
	}
}


void display_path2(struct pathname *paths, char *string)
{
	int i;
	char path[1024];

	if(paths == NULL) {
		printf("%s\n", string);
		return;
	}

	for(i = 0; i < paths->names; i++) {
		strcat(strcat(strcpy(path, string), "/"), paths->name[i].name);
		display_path2(paths->name[i].paths, path);
	}
}


struct pathnames *init_subdir()
{
	struct pathnames *new = malloc(sizeof(struct pathnames));
	if(new == NULL)
		BAD_ERROR("Out of memory in init_subdir\n");
	new->count = 0;
	return new;
}


struct pathnames *add_subdir(struct pathnames *paths, struct pathname *path)
{
	if(paths->count % PATHS_ALLOC_SIZE == 0) {
		paths = realloc(paths, sizeof(struct pathnames *) +
			(paths->count + PATHS_ALLOC_SIZE) *
			sizeof(struct pathname *));
		if(paths == NULL)
			BAD_ERROR("Out of memory in add_subdir\n");
	}

	paths->path[paths->count++] = path;
	return paths;
}


void free_subdir(struct pathnames *paths)
{
	free(paths);
}


int excluded(struct pathnames *paths, char *name, struct pathnames **new)
{
	int i, n, res;
		
	if(paths == NULL) {
		*new = NULL;
		return FALSE;
	}


	*new = init_subdir();
	if(stickypath)
		*new = add_subdir(*new, stickypath);

	for(n = 0; n < paths->count; n++) {
		struct pathname *path = paths->path[n];

		for(i = 0; i < path->names; i++) {
			int match = use_regex ?
				regexec(path->name[i].preg, name, (size_t) 0,
					NULL, 0) == 0 :
				fnmatch(path->name[i].name, name,
					FNM_PATHNAME|FNM_PERIOD) == //|FNM_EXTMATCH) ==
					 0;

			if(match && path->name[i].paths == NULL) {
				/* match on a leaf component, any subdirectories
				 * in the filesystem should be excluded */
				res = TRUE;
				goto empty_set;
			}

			if(match)
				/* match on a non-leaf component, add any
				 * subdirectories to the new set of
				 * subdirectories to scan for this name */
				*new = add_subdir(*new, path->name[i].paths);
		}
	}

	if((*new)->count == 0) {
			/* no matching names found, return empty new search set
			 */
			res = FALSE;
			goto empty_set;
	}

	/* one or more matches with sub-directories found (no leaf matches).
	 * Return new set */
	return FALSE;

empty_set:
	free_subdir(*new);
	*new = NULL;
	return res;
}


#define RECOVER_ID "Squashfs recovery file v1.0\n"
#define RECOVER_ID_SIZE 28

void write_recovery_data(struct squashfs_super_block *sBlk)
{
	int res, recoverfd, bytes = sBlk->bytes_used - sBlk->inode_table_start;
	pid_t pid = getpid();
	char *metadata;
	char header[] = RECOVER_ID;

	if(recover == FALSE) {
		printf("No recovery data option specified.\n");
		printf("Skipping saving recovery file.\n\n");
		return;
	}

	metadata = malloc(bytes);
	if(metadata == NULL)
		BAD_ERROR("Failed to alloc metadata buffer in "
			"write_recovery_data\n");

	res = read_fs_bytes(fd, sBlk->inode_table_start, bytes, metadata);
	if(res == 0)
		EXIT_MKSQUASHFS();

	sprintf(recovery_file, "squashfs_recovery_%s_%d",
		getbase(destination_file), pid);
	recoverfd = open(recovery_file, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
	if(recoverfd == -1)
		BAD_ERROR("Failed to create recovery file, because %s.  "
			"Aborting\n", strerror(errno));
		
	if(write_bytes(recoverfd, header, RECOVER_ID_SIZE) == -1)
		BAD_ERROR("Failed to write recovery file, because %s\n",
			strerror(errno));

	if(write_bytes(recoverfd, sBlk, sizeof(struct squashfs_super_block)) == -1)
		BAD_ERROR("Failed to write recovery file, because %s\n",
			strerror(errno));

	if(write_bytes(recoverfd, metadata, bytes) == -1)
		BAD_ERROR("Failed to write recovery file, because %s\n",
			strerror(errno));

	close(recoverfd);
	free(metadata);
	
	printf("Recovery file \"%s\" written\n", recovery_file);
	printf("If Mksquashfs aborts abnormally (i.e. power failure), run\n");
	printf("mksquashfs dummy %s -recover %s\n", destination_file,
		recovery_file);
	printf("to restore filesystem\n\n");
}


void read_recovery_data(char *recovery_file, char *destination_file)
{
	int fd, recoverfd, bytes;
	struct squashfs_super_block orig_sBlk, sBlk;
	char *metadata;
	int res;
	struct stat buf;
	char header[] = RECOVER_ID;
	char header2[RECOVER_ID_SIZE];

	recoverfd = open(recovery_file, O_RDONLY);
	if(recoverfd == -1)
		BAD_ERROR("Failed to open recovery file because %s\n",
			strerror(errno));

	if(stat(destination_file, &buf) == -1)
		BAD_ERROR("Failed to stat destination file, because %s\n",
			strerror(errno));

	fd = open(destination_file, O_RDWR);
	if(fd == -1)
		BAD_ERROR("Failed to open destination file because %s\n",
			strerror(errno));

	res = read_bytes(recoverfd, header2, RECOVER_ID_SIZE);
	if(res == -1)
		BAD_ERROR("Failed to read recovery file, because %s\n",
			strerror(errno));
	if(res < RECOVER_ID_SIZE)
		BAD_ERROR("Recovery file appears to be truncated\n");
	if(strncmp(header, header2, RECOVER_ID_SIZE) !=0 )
		BAD_ERROR("Not a recovery file\n");

	res = read_bytes(recoverfd, &sBlk, sizeof(struct squashfs_super_block));
	if(res == -1)
		BAD_ERROR("Failed to read recovery file, because %s\n",
			strerror(errno));
	if(res < sizeof(struct squashfs_super_block))
		BAD_ERROR("Recovery file appears to be truncated\n");

	res = read_fs_bytes(fd, 0, sizeof(struct squashfs_super_block), &orig_sBlk);
	if(res == 0)
		EXIT_MKSQUASHFS();

	if(memcmp(((char *) &sBlk) + 4, ((char *) &orig_sBlk) + 4,
			sizeof(struct squashfs_super_block) - 4) != 0)
		BAD_ERROR("Recovery file and destination file do not seem to "
			"match\n");

	bytes = sBlk.bytes_used - sBlk.inode_table_start;

	metadata = malloc(bytes);
	if(metadata == NULL)
		BAD_ERROR("Failed to alloc metadata buffer in "
			"read_recovery_data\n");

	res = read_bytes(recoverfd, metadata, bytes);
	if(res == -1)
		BAD_ERROR("Failed to read recovery file, because %s\n",
			strerror(errno));
	if(res < bytes)
		BAD_ERROR("Recovery file appears to be truncated\n");

	write_destination(fd, 0, sizeof(struct squashfs_super_block), &sBlk);

	write_destination(fd, sBlk.inode_table_start, bytes, metadata);

	close(recoverfd);
	close(fd);

	printf("Successfully wrote recovery file \"%s\".  Exiting\n",
		recovery_file);
	
	exit(0);
}


#define VERSION() \
	printf("mksquashfs version 4.2-CVS (2011/12/31)\n");\
	printf("copyright (C) 2011 Phillip Lougher "\
		"<phillip@lougher.demon.co.uk>\n\n"); \
	printf("This program is free software; you can redistribute it and/or"\
		"\n");\
	printf("modify it under the terms of the GNU General Public License"\
		"\n");\
	printf("as published by the Free Software Foundation; either version "\
		"2,\n");\
	printf("or (at your option) any later version.\n\n");\
	printf("This program is distributed in the hope that it will be "\
		"useful,\n");\
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty "\
		"of\n");\
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"\
		"\n");\
	printf("GNU General Public License for more details.\n");
int main(int argc, char *argv[])
{
	struct stat buf, source_buf;
	int res, i;
	struct squashfs_super_block sBlk;
	char *b, *root_name = NULL;
	int nopad = FALSE, keep_as_directory = FALSE;
	squashfs_inode inode;
	int readb_mbytes = READER_BUFFER_DEFAULT,
		writeb_mbytes = WRITER_BUFFER_DEFAULT,
		fragmentb_mbytes = FRAGMENT_BUFFER_DEFAULT;

	pthread_mutex_init(&progress_mutex, NULL);
	block_log = slog(block_size);
	if(argc > 1 && strcmp(argv[1], "-version") == 0) {
		VERSION();
		exit(0);
	}
        for(i = 1; i < argc && argv[i][0] != '-'; i++);
	if(i < 3)
		goto printOptions;
	source_path = argv + 1;
	source = i - 2;
	/*
	 * lookup default compressor.  Note the Makefile ensures the default
	 * compressor has been built, and so we don't need to to check
	 * for failure here
	 */
	comp = lookup_compressor(COMP_DEFAULT);
	for(; i < argc; i++) {
		if(strcmp(argv[i], "-action") == 0) {
			if(++i == argc) {
				ERROR("%s: -action missing action\n",
					argv[0]);
				exit(1);
			}
			res = parse_action(argv[i]);
			if(res == 0)
				exit(1);

		} else if(strcmp(argv[i], "-comp") == 0) {
			if(compressor_opts_parsed) {
				ERROR("%s: -comp must appear before -X options"
					"\n", argv[0]);
				exit(1);
			}
			if(++i == argc) {
				ERROR("%s: -comp missing compression type\n",
					argv[0]);
				exit(1);
			}
			comp = lookup_compressor(argv[i]);
			if(!comp->supported) {
				ERROR("%s: Compressor \"%s\" is not supported!"
					"\n", argv[0], argv[i]);
				ERROR("%s: Compressors available:\n", argv[0]);
				display_compressors("", COMP_DEFAULT);
				exit(1);
			}

		} else if(strncmp(argv[i], "-X", 2) == 0) {
			int args = compressor_options(comp, argv + i, argc - i);
			if(args < 0) {
				if(args == -1) {
					ERROR("%s: Unrecognised compressor"
						" option %s\n", argv[0],
						argv[i]);
					ERROR("%s: Did you forget to specify"
						" -comp, or specify it after"
						" the compressor specific"
						" option?\n", argv[0]);
					}
				exit(1);
			}
			i += args;
			compressor_opts_parsed = 1;

		} else if(strcmp(argv[i], "-pf") == 0) {
			if(++i == argc) {
				ERROR("%s: -pf missing filename\n", argv[0]);
				exit(1);
			}
			if(read_pseudo_file(&pseudo, argv[i]) == FALSE)
				exit(1);
		} else if(strcmp(argv[i], "-p") == 0) {
			if(++i == argc) {
				ERROR("%s: -p missing pseudo file definition\n",
					argv[0]);
				exit(1);
			}
			if(read_pseudo_def(&pseudo, argv[i]) == FALSE)
				exit(1);
		} else if(strcmp(argv[i], "-recover") == 0) {
			if(++i == argc) {
				ERROR("%s: -recover missing recovery file\n",
					argv[0]);
				exit(1);
			}
			read_recovery_data(argv[i], argv[source + 1]);
		} else if(strcmp(argv[i], "-no-recovery") == 0)
			recover = FALSE;
		else if(strcmp(argv[i], "-wildcards") == 0) {
			old_exclude = FALSE;
			use_regex = FALSE;
		} else if(strcmp(argv[i], "-regex") == 0) {
			old_exclude = FALSE;
			use_regex = TRUE;
		} else if(strcmp(argv[i], "-no-sparse") == 0)
			sparse_files = FALSE;
		else if(strcmp(argv[i], "-no-progress") == 0)
			progress = FALSE;
		else if(strcmp(argv[i], "-no-exports") == 0)
			exportable = FALSE;
		else if(strcmp(argv[i], "-processors") == 0) {
			if((++i == argc) || (processors =
					strtol(argv[i], &b, 10), *b != '\0')) {
				ERROR("%s: -processors missing or invalid "
					"processor number\n", argv[0]);
				exit(1);
			}
			if(processors < 1) {
				ERROR("%s: -processors should be 1 or larger\n",
					argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-read-queue") == 0) {
			if((++i == argc) || (readb_mbytes =
					strtol(argv[i], &b, 10), *b != '\0')) {
				ERROR("%s: -read-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(readb_mbytes < 1) {
				ERROR("%s: -read-queue should be 1 megabyte or "
					"larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-write-queue") == 0) {
			if((++i == argc) || (writeb_mbytes =
					strtol(argv[i], &b, 10), *b != '\0')) {
				ERROR("%s: -write-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(writeb_mbytes < 1) {
				ERROR("%s: -write-queue should be 1 megabyte "
					"or larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-fragment-queue") == 0) {
			if((++i == argc) ||
					(fragmentb_mbytes =
					strtol(argv[i], &b, 10), *b != '\0')) {
				ERROR("%s: -fragment-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(fragmentb_mbytes < 1) {
				ERROR("%s: -fragment-queue should be 1 "
					"megabyte or larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-b") == 0) {
			if(++i == argc) {
				ERROR("%s: -b missing block size\n", argv[0]);
				exit(1);
			}
			block_size = strtol(argv[i], &b, 10);
			if(*b == 'm' || *b == 'M')
				block_size *= 1048576;
			else if(*b == 'k' || *b == 'K')
				block_size *= 1024;
			else if(*b != '\0') {
				ERROR("%s: -b invalid block size\n", argv[0]);
				exit(1);
			}
			if((block_log = slog(block_size)) == 0) {
				ERROR("%s: -b block size not power of two or "
					"not between 4096 and 1Mbyte\n",
					argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-ef") == 0) {
			if(++i == argc) {
				ERROR("%s: -ef missing filename\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-no-duplicates") == 0)
			duplicate_checking = FALSE;

		else if(strcmp(argv[i], "-no-fragments") == 0)
			no_fragments = TRUE;

		 else if(strcmp(argv[i], "-always-use-fragments") == 0)
			always_use_fragments = TRUE;

		 else if(strcmp(argv[i], "-sort") == 0) {
			if(++i == argc) {
				ERROR("%s: -sort missing filename\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-all-root") == 0 ||
				strcmp(argv[i], "-root-owned") == 0)
			global_uid = global_gid = 0;

		else if(strcmp(argv[i], "-force-uid") == 0) {
			if(++i == argc) {
				ERROR("%s: -force-uid missing uid or user\n",
					argv[0]);
				exit(1);
			}
			if((global_uid = strtoll(argv[i], &b, 10)), *b =='\0') {
				if(global_uid < 0 || global_uid >
						(((long long) 1 << 32) - 1)) {
					ERROR("%s: -force-uid uid out of range"
						"\n", argv[0]);
					exit(1);
				}
			} else {
				struct passwd *uid = getpwnam(argv[i]);
				if(uid)
					global_uid = uid->pw_uid;
				else {
					ERROR("%s: -force-uid invalid uid or "
						"unknown user\n", argv[0]);
					exit(1);
				}
			}
		} else if(strcmp(argv[i], "-force-gid") == 0) {
			if(++i == argc) {
				ERROR("%s: -force-gid missing gid or group\n",
					argv[0]);
				exit(1);
			}
			if((global_gid = strtoll(argv[i], &b, 10)), *b =='\0') {
				if(global_gid < 0 || global_gid >
						(((long long) 1 << 32) - 1)) {
					ERROR("%s: -force-gid gid out of range"
						"\n", argv[0]);
					exit(1);
				}
			} else {
				struct group *gid = getgrnam(argv[i]);
				if(gid)
					global_gid = gid->gr_gid;
				else {
					ERROR("%s: -force-gid invalid gid or "
						"unknown group\n", argv[0]);
					exit(1);
				}
			}
		} else if(strcmp(argv[i], "-noI") == 0 ||
				strcmp(argv[i], "-noInodeCompression") == 0)
			noI = TRUE;

		else if(strcmp(argv[i], "-noD") == 0 ||
				strcmp(argv[i], "-noDataCompression") == 0)
			noD = TRUE;

		else if(strcmp(argv[i], "-noF") == 0 ||
				strcmp(argv[i], "-noFragmentCompression") == 0)
			noF = TRUE;

		else if(strcmp(argv[i], "-noX") == 0 ||
				strcmp(argv[i], "-noXattrCompression") == 0)
			noX = TRUE;

		else if(strcmp(argv[i], "-no-xattrs") == 0)
			no_xattrs = TRUE;

		else if(strcmp(argv[i], "-xattrs") == 0)
			no_xattrs = FALSE;

		else if(strcmp(argv[i], "-nopad") == 0)
			nopad = TRUE;

		else if(strcmp(argv[i], "-info") == 0) {
			silent = FALSE;
			progress = FALSE;
		}

		else if(strcmp(argv[i], "-e") == 0)
			break;

		else if(strcmp(argv[i], "-noappend") == 0)
			delete = TRUE;

		else if(strcmp(argv[i], "-keep-as-directory") == 0)
			keep_as_directory = TRUE;

		else if(strcmp(argv[i], "-root-becomes") == 0) {
			if(++i == argc) {
				ERROR("%s: -root-becomes: missing name\n",
					argv[0]);
				exit(1);
			}	
			root_name = argv[i];
		} else if(strcmp(argv[i], "-version") == 0) {
			VERSION();
		} else {
			ERROR("%s: invalid option\n\n", argv[0]);
printOptions:
			ERROR("SYNTAX:%s source1 source2 ...  dest [options] "
				"[-e list of exclude\ndirs/files]\n", argv[0]);
			ERROR("\nFilesystem build options:\n");
			ERROR("-comp <comp>\t\tselect <comp> compression\n");
			ERROR("\t\t\tCompressors available:\n");
			display_compressors("\t\t\t", COMP_DEFAULT);
			ERROR("-b <block_size>\t\tset data block to "
				"<block_size>.  Default %d bytes\n",
				SQUASHFS_FILE_SIZE);
			ERROR("-no-exports\t\tdon't make the filesystem "
				"exportable via NFS\n");
			ERROR("-no-sparse\t\tdon't detect sparse files\n");
			ERROR("-no-xattrs\t\tdon't store extended attributes"
				NOXOPT_STR "\n");
			ERROR("-xattrs\t\t\tstore extended attributes" XOPT_STR
				"\n");
			ERROR("-noI\t\t\tdo not compress inode table\n");
			ERROR("-noD\t\t\tdo not compress data blocks\n");
			ERROR("-noF\t\t\tdo not compress fragment blocks\n");
			ERROR("-noX\t\t\tdo not compress extended "
				"attributes\n");
			ERROR("-no-fragments\t\tdo not use fragments\n");
			ERROR("-always-use-fragments\tuse fragment blocks for "
				"files larger than block size\n");
			ERROR("-no-duplicates\t\tdo not perform duplicate "
				"checking\n");
			ERROR("-all-root\t\tmake all files owned by root\n");
			ERROR("-force-uid uid\t\tset all file uids to uid\n");
			ERROR("-force-gid gid\t\tset all file gids to gid\n");
			ERROR("-nopad\t\t\tdo not pad filesystem to a multiple "
				"of 4K\n");
			ERROR("-keep-as-directory\tif one source directory is "
				"specified, create a root\n");
			ERROR("\t\t\tdirectory containing that directory, "
				"rather than the\n");
			ERROR("\t\t\tcontents of the directory\n");
			ERROR("\nFilesystem filter options:\n");
			ERROR("-p <pseudo-definition>\tAdd pseudo file "
				"definition\n");
			ERROR("-pf <pseudo-file>\tAdd list of pseudo file "
				"definitions\n");
			ERROR("-sort <sort_file>\tsort files according to "
				"priorities in <sort_file>.  One\n");
			ERROR("\t\t\tfile or dir with priority per line.  "
				"Priority -32768 to\n");
			ERROR("\t\t\t32767, default priority 0\n");
			ERROR("-ef <exclude_file>\tlist of exclude dirs/files."
				"  One per line\n");
			ERROR("-wildcards\t\tAllow extended shell wildcards "
				"(globbing) to be used in\n\t\t\texclude "
				"dirs/files\n");
			ERROR("-regex\t\t\tAllow POSIX regular expressions to "
				"be used in exclude\n\t\t\tdirs/files\n");
			ERROR("\nFilesystem append options:\n");
			ERROR("-noappend\t\tdo not append to existing "
				"filesystem\n");
			ERROR("-root-becomes <name>\twhen appending source "
				"files/directories, make the\n");
			ERROR("\t\t\toriginal root become a subdirectory in "
				"the new root\n");
			ERROR("\t\t\tcalled <name>, rather than adding the new "
				"source items\n");
			ERROR("\t\t\tto the original root\n");
			ERROR("\nMksquashfs runtime options:\n");
			ERROR("-version\t\tprint version, licence and "
				"copyright message\n");
			ERROR("-recover <name>\t\trecover filesystem data "
				"using recovery file <name>\n");
			ERROR("-no-recovery\t\tdon't generate a recovery "
				"file\n");
			ERROR("-info\t\t\tprint files written to filesystem\n");
			ERROR("-no-progress\t\tdon't display the progress "
				"bar\n");
			ERROR("-processors <number>\tUse <number> processors."
				"  By default will use number of\n");
			ERROR("\t\t\tprocessors available\n");
			ERROR("-read-queue <size>\tSet input queue to <size> "
				"Mbytes.  Default %d Mbytes\n",
				READER_BUFFER_DEFAULT);
			ERROR("-write-queue <size>\tSet output queue to <size> "
				"Mbytes.  Default %d Mbytes\n",
				WRITER_BUFFER_DEFAULT);
			ERROR("-fragment-queue <size>\tSet fragment queue to "
				"<size> Mbytes.  Default %d Mbytes\n",
				FRAGMENT_BUFFER_DEFAULT);
			ERROR("\nMiscellaneous options:\n");
			ERROR("-root-owned\t\talternative name for -all-root"
				"\n");
			ERROR("-noInodeCompression\talternative name for -noI"
				"\n");
			ERROR("-noDataCompression\talternative name for -noD"
				"\n");
			ERROR("-noFragmentCompression\talternative name for "
				"-noF\n");
			ERROR("-noXattrCompression\talternative name for "
				"-noX\n");
			ERROR("\nCompressors available and compressor specific "
				"options:\n");
			display_compressor_usage(COMP_DEFAULT);
			exit(1);
		}
	}

	/*
	 * Some compressors may need the options to be checked for validity
	 * once all the options have been processed
	 */
	res = compressor_options_post(comp, block_size);
	if(res)
		EXIT_MKSQUASHFS();

	for(i = 0; i < source; i++)
		if(lstat(source_path[i], &source_buf) == -1) {
			fprintf(stderr, "Cannot stat source directory \"%s\" "
				"because %s\n", source_path[i],
				strerror(errno));
			EXIT_MKSQUASHFS();
		}

	destination_file = argv[source + 1];
	if(stat(argv[source + 1], &buf) == -1) {
		if(errno == ENOENT) { /* Does not exist */
			fd = open(argv[source + 1], O_CREAT | O_TRUNC | O_RDWR,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if(fd == -1) {
				perror("Could not create destination file");
				exit(1);
			}
			delete = TRUE;
		} else {
			perror("Could not stat destination file");
			exit(1);
		}

	} else {
		if(S_ISBLK(buf.st_mode)) {
			if((fd = open(argv[source + 1], O_RDWR)) == -1) {
				perror("Could not open block device as "
					"destination");
				exit(1);
			}
			block_device = 1;

		} else if(S_ISREG(buf.st_mode))	 {
			fd = open(argv[source + 1], (delete ? O_TRUNC : 0) |
				O_RDWR);
			if(fd == -1) {
				perror("Could not open regular file for "
					"writing as destination");
				exit(1);
			}
		}
		else {
			ERROR("Destination not block device or regular file\n");
			exit(1);
		}

	}

	signal(SIGTERM, sighandler2);
	signal(SIGINT, sighandler2);

	/*
	 * process the exclude files - must be done afer destination file has
	 * been possibly created
	 */
	for(i = source + 2; i < argc; i++)
		if(strcmp(argv[i], "-ef") == 0) {
			FILE *fd;
			char filename[16385];
			if((fd = fopen(argv[++i], "r")) == NULL) {
				perror("Could not open exclude file...");
				EXIT_MKSQUASHFS();
			}
			while(fscanf(fd, "%16384[^\n]\n", filename) != EOF)
					if(old_exclude)
						old_add_exclude(filename);
					else
						add_exclude(filename);
			fclose(fd);
		} else if(strcmp(argv[i], "-e") == 0)
			break;
		else if(strcmp(argv[i], "-root-becomes") == 0 ||
				strcmp(argv[i], "-sort") == 0 ||
				strcmp(argv[i], "-pf") == 0 ||
				strcmp(argv[i], "-comp") == 0)
			i++;

	if(i != argc) {
		if(++i == argc) {
			ERROR("%s: -e missing arguments\n", argv[0]);
			EXIT_MKSQUASHFS();
		}
		while(i < argc)
			if(old_exclude)
				old_add_exclude(argv[i++]);
			else
				add_exclude(argv[i++]);
	}

	/* process the sort files - must be done afer the exclude files  */
	for(i = source + 2; i < argc; i++)
		if(strcmp(argv[i], "-sort") == 0) {
			int res = read_sort_file(argv[++i], source,
								source_path);
			if(res == FALSE)
				BAD_ERROR("Failed to read sort file\n");
			sorted ++;
		} else if(strcmp(argv[i], "-e") == 0)
			break;
		else if(strcmp(argv[i], "-root-becomes") == 0 ||
				strcmp(argv[i], "-ef") == 0 ||
				strcmp(argv[i], "-pf") == 0 ||
				strcmp(argv[i], "-comp") == 0)
			i++;

#ifdef SQUASHFS_TRACE
	progress = FALSE;
#endif

	if(!delete) {
	        comp = read_super(fd, &sBlk, argv[source + 1]);
	        if(comp == NULL) {
			ERROR("Failed to read existing filesystem - will not "
				"overwrite - ABORTING!\n");
			ERROR("To force Mksquashfs to write to this block "
				"device or file use -noappend\n");
			EXIT_MKSQUASHFS();
		}

		block_log = slog(block_size = sBlk.block_size);
		noI = SQUASHFS_UNCOMPRESSED_INODES(sBlk.flags);
		noD = SQUASHFS_UNCOMPRESSED_DATA(sBlk.flags);
		noF = SQUASHFS_UNCOMPRESSED_FRAGMENTS(sBlk.flags);
		noX = SQUASHFS_UNCOMPRESSED_XATTRS(sBlk.flags);
		no_fragments = SQUASHFS_NO_FRAGMENTS(sBlk.flags);
		always_use_fragments = SQUASHFS_ALWAYS_FRAGMENTS(sBlk.flags);
		duplicate_checking = SQUASHFS_DUPLICATES(sBlk.flags);
		exportable = SQUASHFS_EXPORTABLE(sBlk.flags);
		no_xattrs = SQUASHFS_NO_XATTRS(sBlk.flags);
		comp_opts = SQUASHFS_COMP_OPTS(sBlk.flags);
	}

	initialise_threads(readb_mbytes, writeb_mbytes, fragmentb_mbytes);

	res = compressor_init(comp, &stream, SQUASHFS_METADATA_SIZE, 0);
	if(res)
		BAD_ERROR("compressor_init failed\n");

	if(delete) {
		int size;
		void *comp_data = compressor_dump_options(comp, block_size,
			&size);

		printf("Creating %d.%d filesystem on %s, block size %d.\n",
			SQUASHFS_MAJOR, SQUASHFS_MINOR, argv[source + 1], block_size);

		/*
		 * store any compressor specific options after the superblock,
		 * and set the COMP_OPT flag to show that the filesystem has
		 * compressor specfic options
		 */
		if(comp_data) {
			unsigned short c_byte = size | SQUASHFS_COMPRESSED_BIT;
	
			SQUASHFS_INSWAP_SHORTS(&c_byte, 1);
			write_destination(fd, sizeof(struct squashfs_super_block),
				sizeof(c_byte), &c_byte);
			write_destination(fd, sizeof(struct squashfs_super_block) +
				sizeof(c_byte), size, comp_data);
			bytes = sizeof(struct squashfs_super_block) + sizeof(c_byte)
				+ size;
			comp_opts = TRUE;
		} else			
			bytes = sizeof(struct squashfs_super_block);
	} else {
		unsigned int last_directory_block, inode_dir_offset,
			inode_dir_file_size, root_inode_size,
			inode_dir_start_block, uncompressed_data,
			compressed_data, inode_dir_inode_number,
			inode_dir_parent_inode;
		unsigned int root_inode_start =
			SQUASHFS_INODE_BLK(sBlk.root_inode),
			root_inode_offset =
			SQUASHFS_INODE_OFFSET(sBlk.root_inode);

		if((bytes = read_filesystem(root_name, fd, &sBlk, &inode_table,
				&data_cache, &directory_table,
				&directory_data_cache, &last_directory_block,
				&inode_dir_offset, &inode_dir_file_size,
				&root_inode_size, &inode_dir_start_block,
				&file_count, &sym_count, &dev_count, &dir_count,
				&fifo_count, &sock_count, &total_bytes,
				&total_inode_bytes, &total_directory_bytes,
				&inode_dir_inode_number,
				&inode_dir_parent_inode, add_old_root_entry,
				&fragment_table, &inode_lookup_table)) == 0) {
			ERROR("Failed to read existing filesystem - will not "
				"overwrite - ABORTING!\n");
			ERROR("To force Mksquashfs to write to this block "
				"device or file use -noappend\n");
			EXIT_MKSQUASHFS();
		}
		if((fragments = sBlk.fragments)) {
			fragment_table = realloc((char *) fragment_table,
				((fragments + FRAG_SIZE - 1) & ~(FRAG_SIZE - 1))
				 * sizeof(struct squashfs_fragment_entry)); 
			if(fragment_table == NULL)
				BAD_ERROR("Out of memory in save filesystem state\n");
		}

		printf("Appending to existing %d.%d filesystem on %s, block "
			"size %d\n", SQUASHFS_MAJOR, SQUASHFS_MINOR, argv[source + 1],
			block_size);
		printf("All -b, -noI, -noD, -noF, -noX, no-duplicates, no-fragments, "
			"-always-use-fragments,\n-exportable and -comp options "
			"ignored\n");
		printf("\nIf appending is not wanted, please re-run with "
			"-noappend specified!\n\n");

		compressed_data = (inode_dir_offset + inode_dir_file_size) &
			~(SQUASHFS_METADATA_SIZE - 1);
		uncompressed_data = (inode_dir_offset + inode_dir_file_size) &
			(SQUASHFS_METADATA_SIZE - 1);
		
		/* save original filesystem state for restoring ... */
		sfragments = fragments;
		sbytes = bytes;
		sinode_count = sBlk.inodes;
		scache_bytes = root_inode_offset + root_inode_size;
		sdirectory_cache_bytes = uncompressed_data;
		sdata_cache = malloc(scache_bytes);
		if(sdata_cache == NULL)
			BAD_ERROR("Out of memory in save filesystem state\n");
		sdirectory_data_cache = malloc(sdirectory_cache_bytes);
		if(sdirectory_data_cache == NULL)
			BAD_ERROR("Out of memory in save filesystem state\n");
		memcpy(sdata_cache, data_cache, scache_bytes);
		memcpy(sdirectory_data_cache, directory_data_cache +
			compressed_data, sdirectory_cache_bytes);
		sinode_bytes = root_inode_start;
		stotal_bytes = total_bytes;
		stotal_inode_bytes = total_inode_bytes;
		stotal_directory_bytes = total_directory_bytes +
			compressed_data;
		sfile_count = file_count;
		ssym_count = sym_count;
		sdev_count = dev_count;
		sdir_count = dir_count + 1;
		sfifo_count = fifo_count;
		ssock_count = sock_count;
		sdup_files = dup_files;
		sid_count = id_count;
		write_recovery_data(&sBlk);
		if(save_xattrs() == FALSE)
			BAD_ERROR("Failed to save xattrs from existing "
				"filesystem\n");
		restore = TRUE;
		if(setjmp(env))
			goto restore_filesystem;
		signal(SIGTERM, sighandler);
		signal(SIGINT, sighandler);
		write_destination(fd, SQUASHFS_START, 4, "\0\0\0\0");

		/*
		 * set the filesystem state up to be able to append to the
		 * original filesystem.  The filesystem state differs depending
		 * on whether we're appending to the original root directory, or
		 * if the original root directory becomes a sub-directory
		 * (root-becomes specified on command line, here root_name !=
		 * NULL)
		 */
		inode_bytes = inode_size = root_inode_start;
		directory_size = last_directory_block;
		cache_size = root_inode_offset + root_inode_size;
		directory_cache_size = inode_dir_offset + inode_dir_file_size;
		if(root_name) {
			sdirectory_bytes = last_directory_block;
			sdirectory_compressed_bytes = 0;
			root_inode_number = inode_dir_parent_inode;
			dir_inode_no = sBlk.inodes + 2;
			directory_bytes = last_directory_block;
			directory_cache_bytes = uncompressed_data;
			memmove(directory_data_cache, directory_data_cache +
				compressed_data, uncompressed_data);
			cache_bytes = root_inode_offset + root_inode_size;
			add_old_root_entry(root_name, sBlk.root_inode,
				inode_dir_inode_number, SQUASHFS_DIR_TYPE);
			total_directory_bytes += compressed_data;
			dir_count ++;
		} else {
			sdirectory_compressed_bytes = last_directory_block -
				inode_dir_start_block;
			sdirectory_compressed =
				malloc(sdirectory_compressed_bytes);
			if(sdirectory_compressed == NULL)
				BAD_ERROR("Out of memory in save filesystem "
					"state\n");
			memcpy(sdirectory_compressed, directory_table +
				inode_dir_start_block,
				sdirectory_compressed_bytes); 
			sdirectory_bytes = inode_dir_start_block;
			root_inode_number = inode_dir_inode_number;
			dir_inode_no = sBlk.inodes + 1;
			directory_bytes = inode_dir_start_block;
			directory_cache_bytes = inode_dir_offset;
			cache_bytes = root_inode_offset;
		}

		inode_count = file_count + dir_count + sym_count + dev_count +
			fifo_count + sock_count;

		/*
		 * The default use freelist before growing cache policy behaves
		 * poorly with appending - with many deplicates the caches
		 * do not grow due to the fact that large queues of outstanding
		 * fragments/writer blocks do not occur, leading to small caches
		 * and un-uncessary performance loss to frequent cache
		 * replacement in the small caches.  Therefore with appending
		 * change the policy to grow the caches before reusing blocks
		 * from the freelist
		 */
		first_freelist = FALSE;
	}

	if(path || stickypath) {
		paths = init_subdir();
		if(path)
			paths = add_subdir(paths, path);
		if(stickypath)
			paths = add_subdir(paths, stickypath);
	}

	dump_actions(); 

	if(delete && !keep_as_directory && source == 1 &&
			S_ISDIR(source_buf.st_mode))
		dir_scan(&inode, source_path[0], scan1_readdir);
	else if(!keep_as_directory && source == 1 &&
			S_ISDIR(source_buf.st_mode))
		dir_scan(&inode, source_path[0], scan1_single_readdir);
	else
		dir_scan(&inode, "", scan1_encomp_readdir);
	sBlk.root_inode = inode;
	sBlk.inodes = inode_count;
	sBlk.s_magic = SQUASHFS_MAGIC;
	sBlk.s_major = SQUASHFS_MAJOR;
	sBlk.s_minor = SQUASHFS_MINOR;
	sBlk.block_size = block_size;
	sBlk.block_log = block_log;
	sBlk.flags = SQUASHFS_MKFLAGS(noI, noD, noF, noX, no_fragments,
		always_use_fragments, duplicate_checking, exportable,
		no_xattrs, comp_opts);
	sBlk.mkfs_time = time(NULL);

restore_filesystem:
	if(progress && estimated_uncompressed) {
		disable_progress_bar();
		progress_bar(cur_uncompressed, estimated_uncompressed, columns);
	}

	sBlk.fragments = fragments;
	if(!restoring) {
		struct file_buffer **fragment = NULL;
		while((fragment = get_frag_action(fragment)))
			write_fragment(*fragment);
		unlock_fragments();
		pthread_mutex_lock(&fragment_mutex);
		while(fragments_outstanding) {
			pthread_mutex_unlock(&fragment_mutex);
			sched_yield();
			pthread_mutex_lock(&fragment_mutex);
		}
		queue_put(to_writer, NULL);
		if(queue_get(from_writer) != 0)
			EXIT_MKSQUASHFS();
	}

	sBlk.no_ids = id_count;
	sBlk.inode_table_start = write_inodes();
	sBlk.directory_table_start = write_directories();
	sBlk.fragment_table_start = write_fragment_table();
	sBlk.lookup_table_start = exportable ? write_inode_lookup_table() :
		SQUASHFS_INVALID_BLK;
	sBlk.id_table_start = write_id_table();
	sBlk.xattr_id_table_start = write_xattrs();

	TRACE("sBlk->inode_table_start 0x%llx\n", sBlk.inode_table_start);
	TRACE("sBlk->directory_table_start 0x%llx\n",
		sBlk.directory_table_start);
	TRACE("sBlk->fragment_table_start 0x%llx\n", sBlk.fragment_table_start);
	if(exportable)
		TRACE("sBlk->lookup_table_start 0x%llx\n",
			sBlk.lookup_table_start);

	sBlk.bytes_used = bytes;

	sBlk.compression = comp->id;

	SQUASHFS_INSWAP_SUPER_BLOCK(&sBlk); 
	write_destination(fd, SQUASHFS_START, sizeof(sBlk), &sBlk);

	if(!nopad && (i = bytes & (4096 - 1))) {
		char temp[4096] = {0};
		write_destination(fd, bytes, 4096 - i, temp);
	}

	close(fd);

	delete_pseudo_files();

	if(recovery_file[0] != '\0')
		unlink(recovery_file);

	total_bytes += total_inode_bytes + total_directory_bytes +
		sizeof(struct squashfs_super_block) + total_xattr_bytes;

	printf("\n%sSquashfs %d.%d filesystem, %s compressed, data block size"
		" %d\n", exportable ? "Exportable " : "", SQUASHFS_MAJOR,
		SQUASHFS_MINOR, comp->name, block_size);
	printf("\t%s data, %s metadata, %s fragments, %s xattrs\n",
		noD ? "uncompressed" : "compressed", noI ?  "uncompressed" :
		"compressed", no_fragments ? "no" : noF ? "uncompressed" :
		"compressed", no_xattrs ? "no" : noX ? "uncompressed" :
		"compressed");
	printf("\tduplicates are %sremoved\n", duplicate_checking ? "" :
		"not ");
	printf("Filesystem size %.2f Kbytes (%.2f Mbytes)\n", bytes / 1024.0,
		bytes / (1024.0 * 1024.0));
	printf("\t%.2f%% of uncompressed filesystem size (%.2f Kbytes)\n",
		((float) bytes / total_bytes) * 100.0, total_bytes / 1024.0);
	printf("Inode table size %d bytes (%.2f Kbytes)\n",
		inode_bytes, inode_bytes / 1024.0);
	printf("\t%.2f%% of uncompressed inode table size (%d bytes)\n",
		((float) inode_bytes / total_inode_bytes) * 100.0,
		total_inode_bytes);
	printf("Directory table size %d bytes (%.2f Kbytes)\n",
		directory_bytes, directory_bytes / 1024.0);
	printf("\t%.2f%% of uncompressed directory table size (%d bytes)\n",
		((float) directory_bytes / total_directory_bytes) * 100.0,
		total_directory_bytes);
	if(total_xattr_bytes) {
		printf("Xattr table size %d bytes (%.2f Kbytes)\n",
			xattr_bytes, xattr_bytes / 1024.0);
		printf("\t%.2f%% of uncompressed xattr table size (%d bytes)\n",
			((float) xattr_bytes / total_xattr_bytes) * 100.0,
			total_xattr_bytes);
	}
	if(duplicate_checking)
		printf("Number of duplicate files found %d\n", file_count -
			dup_files);
	else
		printf("No duplicate files removed\n");
	printf("Number of inodes %d\n", inode_count);
	printf("Number of files %d\n", file_count);
	if(!no_fragments)
		printf("Number of fragments %d\n", fragments);
	printf("Number of symbolic links  %d\n", sym_count);
	printf("Number of device nodes %d\n", dev_count);
	printf("Number of fifo nodes %d\n", fifo_count);
	printf("Number of socket nodes %d\n", sock_count);
	printf("Number of directories %d\n", dir_count);
	printf("Number of ids (unique uids + gids) %d\n", id_count);
	printf("Number of uids %d\n", uid_count);

	for(i = 0; i < id_count; i++) {
		if(id_table[i]->flags & ISA_UID) {
			struct passwd *user = getpwuid(id_table[i]->id);
			printf("\t%s (%d)\n", user == NULL ? "unknown" :
				user->pw_name, id_table[i]->id);
		}
	}

	printf("Number of gids %d\n", guid_count);

	for(i = 0; i < id_count; i++) {
		if(id_table[i]->flags & ISA_GID) {
			struct group *group = getgrgid(id_table[i]->id);
			printf("\t%s (%d)\n", group == NULL ? "unknown" :
				group->gr_name, id_table[i]->id);
		}
	}

	return 0;
}
#endif
