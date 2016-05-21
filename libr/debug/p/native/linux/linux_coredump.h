/* coredump api */

#include "elf_specs.h"
#include <sys/procfs.h>

#define SIZE_PR_FNAME	16

#define ELF_HDR_SIZE	sizeof(Elf64_Ehdr)

#define R_DEBUG_REG_T	struct user_regs_struct

#define SIZE_NT_FILE_DESCSZ	sizeof(unsigned long) * 3   /* start_address * end_address * offset_address */
/* 
NT_FILE layout:
	[number of mappings]
	[page size]
	[foreach(mapping)
		[start_address]
		[end_address]
		[offset_address]
	[filenames]
*/

#define	DEFAULT_NOTE	6

static int n_notes = DEFAULT_NOTE;

#define	X_MEM	0x1
#define	W_MEM	0x2
#define	R_MEM	0x4
#define	P_MEM	0x8
#define	S_MEM	0x10
#define	WRG_PERM	0x20

#define	MAP_ANON_PRIV	0x1
#define	MAP_ANON_SHR	0x2
#define	MAP_FILE_PRIV	0x4
#define	MAP_FILE_SHR	0x8
#define	MAP_ELF_HDR	0x10
#define	MAP_HUG_PRIV	0x20
#define	MAP_HUG_SHR	0x40

#define	SH_FLAG	0x1
#define	IO_FLAG	0x2
#define	DD_FLAG	0x4
#define	HT_FLAG	0x8
#define	PV_FLAG	0x10 /* just for us */

typedef struct proc_stat_content {
	int pid;
	int ppid;
	int pgrp;
	int sid;
	char s_name;
	ut32 flag;
	ut64 utime;
	ut64 stime;
	long int cutime;
	long int cstime;
	long int nice;
	long int num_threads;
	ut64 sigpend;
	ut64 sighold;
	ut32 uid;
	ut32 gid;
	unsigned char coredump_filter;
} proc_stat_content_t;

typedef struct map_file {
	ut32 count;
	ut32 size;
} map_file_t;

typedef struct auxv_buff {
	void *data;
	size_t size;
} auxv_buff_t;

typedef struct linux_map_entry {
	ut64 start_addr;
	ut64 end_addr;
	ut64 offset;
	ut64 inode;
	ut8 perms;
	bool anonymous;
	bool dumpeable;
	bool kernel_mapping;
	bool file_backed;
	char *name;
	struct linux_map_entry *n;
} linux_map_entry_t;

#define ADD_MAP_NODE(p)	{ if (me_head) { p->n = NULL; me_tail->n = p; me_tail = p; } else { me_head = p; me_tail = p; } }

typedef struct linux_elf_note {
	prpsinfo_t *prpsinfo;
	prstatus_t *prstatus;
	siginfo_t *siginfo;
	auxv_buff_t *auxv;
	elf_fpregset_t *fp_regset;
	linux_map_entry_t *maps;
} linux_elf_note_t;

typedef enum {
	ADDR,
	PERM,
	OFFSET,
	DEV,
	INODE,
	NAME
} MAPS_FIELD;

extern ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov,
	unsigned long liovcnt, const struct iovec *remote_iov,
	unsigned long riovcnt, unsigned long flags);

bool linux_generate_corefile (RDebug *dbg, RBuffer *dest);
int linux_reg_read (RDebug *dbg, int type, ut8 *buf, int size);
