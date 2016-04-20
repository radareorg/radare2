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

static prpsinfo_t *linux_get_prpsinfo(RDebug *dbg, proc_stat_content_t *proc_data);
static prstatus_t *linux_get_prstatus(RDebug *dbg, proc_stat_content_t *proc_data, short int signr);
static elf_fpregset_t *linux_get_fp_regset(RDebug *dbg);
static siginfo_t *linux_get_siginfo(RDebug *dbg);
static void get_map_address_space(char *pstr, ut64 *start_addr, ut64 *end_addr);
static void get_map_perms(char *pstr, ut8 *fl_perms);
static void get_map_offset(char *pstr, ut64 *offset);
static char *get_map_name(char *pstr);
static bool get_anonymous_value(char *keyw);
static bool has_map_deleted_part(char *name);
static bool dump_this_map(char *buff_smaps, ut64 start_addr, ut64 end_addr, bool file_backed, bool anonymous, ut8 perms, ut8 filter_flags);
static bool has_map_anonymous_content(char *buff_smaps, ut64 start_addr, ut64 end_addr);
static bool is_a_kernel_mapping(char *map_name);
//static char *read_alloc_from_file(FILE *f);
static linux_map_entry_t *linux_get_mapped_files(RDebug *dbg, ut8 filter_flags);
static auxv_buff_t *linux_get_auxv(RDebug *dbg);
static Elf64_Ehdr *build_elf_hdr(int n_segments);
static int get_n_mappings(linux_map_entry_t *me_head);
static bool dump_elf_header(RBuffer *dest, Elf64_Ehdr *hdr);
static void *get_nt_data(linux_map_entry_t *head, size_t *nt_file_size);
static const ut8 *build_note_section(linux_elf_note_t *sec_note, size_t *size_note_section);
static bool dump_elf_pheaders(RBuffer *dest, linux_elf_note_t *sec_note, st64 *offset);
static void show_maps(linux_map_entry_t *head);	/* test purposes */
static bool dump_elf_map_content(RBuffer *dest, linux_map_entry_t *head, pid_t pid);
static void clean_maps(linux_map_entry_t *h);
static void may_clean_all(linux_elf_note_t *sec_note, proc_stat_content_t *proc_data, Elf64_Ehdr *elf_hdr);
static bool dump_elf_sheader_pxnum(RBuffer *dest, Elf64_Shdr *shdr);
static Elf64_Shdr *get_extra_sectionhdr(Elf64_Ehdr *elf_hdr, st64 offset, int n_segments);
bool linux_generate_corefile (RDebug *dbg, RBuffer *dest);
