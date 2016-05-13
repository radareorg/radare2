/*  __
 -=(o '.
    \.-.\
    /|  \\
    '|  ||
     _\_):,_
*/

#include <limits.h>
#include <sys/ptrace.h>

struct user_regs_struct_x86_64 {
  ut64 r15; ut64 r14; ut64 r13; ut64 r12; ut64 rbp; ut64 rbx; ut64 r11;
  ut64 r10; ut64 r9; ut64 r8; ut64 rax; ut64 rcx; ut64 rdx; ut64 rsi;
  ut64 rdi; ut64 orig_rax; ut64 rip; ut64 cs; ut64 eflags; ut64 rsp;
  ut64 ss; ut64 fs_base; ut64 gs_base; ut64 ds; ut64 es; ut64 fs; ut64 gs;
};

struct user_regs_struct_x86_32 {
  ut32 ebx; ut32 ecx; ut32 edx; ut32 esi; ut32 edi; ut32 ebp; ut32 eax;
  ut32 xds; ut32 xes; ut32 xfs; ut32 xgs; ut32 orig_eax; ut32 eip;
  ut32 xcs; ut32 eflags; ut32 esp; ut32 xss;
};

#if __ANDROID__

#if __arm64__ || __aarch64__
#define R_DEBUG_REG_T struct user_pt_regs

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

#else
#define R_DEBUG_REG_T struct pt_regs
#endif

#else

#include <sys/user.h>
#if __i386__ || __x86_64__
#define R_DEBUG_REG_T struct user_regs_struct
#elif __arm64__ || __aarch64__
#define R_DEBUG_REG_T struct user_pt_regs
#elif __arm__
#define R_DEBUG_REG_T struct user_regs
#elif __mips__

#include <sys/ucontext.h>
typedef ut64 mips64_regs_t [274];
#define R_DEBUG_REG_T mips64_regs_t
#endif
#endif


//API
int linux_step (RDebug *dbg);
int linux_attach (RDebug *dbg, int pid);
RDebugInfo *linux_info (RDebug *dbg, const char *arg);
RList *linux_thread_list (int pid, RList *list);
int linux_reg_read (RDebug *dbg, int type, ut8 *buf, int size);
int linux_reg_write (RDebug *dbg, int type, const ut8 *buf, int size);
RList *linux_desc_list (int pid);
int linux_handle_signals (RDebug *dbg);
const char *linux_reg_profile (RDebug *dbg);
/* coredump api */

//#include "elf/elf.h"
#include <elf.h>
#include <sys/procfs.h>

#define ELF_HDR_SIZE sizeof(Elf64_Ehdr)

#define R_DEBUG_REG_T struct user_regs_struct

#define SIZE_NT_FILE_DESCSZ sizeof(unsigned long) * 3   /* start_address * end_address * offset_address */
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
#define DEFAULT_NOTE    6

#define X_MEM 0x1
#define W_MEM 0x2
#define R_MEM 0x4
#define P_MEM 0x8
#define S_MEM 0x10
#define WRG_PERM 0x20

#define MAP_ANON_PRIV	0x1
#define MAP_ANON_SHR	0x2
#define MAP_FILE_PRIV	0x4
#define MAP_FILE_SHR	0x8
#define MAP_ELF_HDR	0x10
#define MAP_HUG_PRIV	0x20
#define MAP_HUG_SHR	0x40

#define SH_FLAG         0x1
#define IO_FLAG         0x2
#define DD_FLAG         0x4
#define HT_FLAG         0x8
#define PV_FLAG         0x10 /* just for us */

static unsigned int n_notes = DEFAULT_NOTE;

typedef struct proc_stat_content {
        int pid;
        int ppid;
        int pgrp;
        int sid;
        char s_name;
        unsigned long int flag;
	unsigned long int utime;
	unsigned long int stime;
	unsigned long int cutime;
	unsigned long int cstime;
        unsigned long int nice;
        unsigned int num_threads;
        unsigned long int sigpend;
        unsigned long int sighold;
        unsigned int uid;
        unsigned int gid;
	unsigned char coredump_filter;
}proc_stat_content_t;

typedef struct map_file {
        unsigned int count;
        unsigned int size;
}map_file_t;

typedef struct auxv_buff {
        void *data;
        size_t size;
} auxv_buff_t;

typedef struct linux_map_entry {
        unsigned long long start_addr;
        unsigned long long end_addr;
        unsigned long long offset;
        unsigned long long inode;
        unsigned long int perms;
        bool anonymous;
	bool dumpeable;
	bool kernel_mapping;
	bool file_backed;
        unsigned int s_name;
        char *name;
        struct linux_map_entry *n;
}linux_map_entry_t;

#define ADD_MAP_NODE(p)         do {                                                    \
                                        if(me_head == NULL) {                           \
                                                me_head = p;                            \
                                                me_tail = p;                            \
                                        } else {                                        \
                                                p->n = NULL;                            \
                                                me_tail->n = p;                         \
                                                me_tail = p;                            \
                                        }                                               \
                                } while(0)


typedef struct linux_elf_note {
        prpsinfo_t *prpsinfo;
        prstatus_t *prstatus;
        siginfo_t *siginfo;
        auxv_buff_t *auxv;
        elf_fpregset_t *fp_regset;
        linux_map_entry_t *maps;
}linux_elf_note_t;

typedef enum {
        ADDR,
        PERM,
        OFFSET,
        DEV,
        INODE,
        NAME
}MAPS_FIELD;

static prpsinfo_t *linux_get_prpsinfo(RDebug *dbg, proc_stat_content_t *proc_data);
static prstatus_t *linux_get_prstatus(RDebug *dbg, proc_stat_content_t *proc_data, short int signr);
static elf_fpregset_t *linux_get_fp_regset(RDebug *dbg);
static siginfo_t *linux_get_siginfo(RDebug *dbg);
static void get_map_address_space(char *pstr, unsigned long long *start_addr, unsigned long long *end_addr);
static void get_map_perms(char *pstr, unsigned long int *fl_perms);
static void get_map_offset(char *pstr, unsigned long long *offset);
static void get_map_name(char *pstr, char **name);
static bool get_anonymous_value(char *keyw);
static bool has_map_deleted_part(char *name);
static bool has_map_anonymous_content(FILE *f, unsigned long long start_addr, unsigned long long end_addr);
static bool is_a_kernel_mapping(char *map_name);
static linux_map_entry_t *linux_get_mapped_files(RDebug *dbg, unsigned long int filter_flags);
static auxv_buff_t *linux_get_auxv(RDebug *dbg);
static Elf64_Ehdr *build_elf_hdr(unsigned int n_segments);
static int get_n_mappings(linux_map_entry_t *me_head);
static bool dump_elf_header(RBuffer *dest, Elf64_Ehdr *hdr);
static void *get_nt_data(linux_map_entry_t *head, size_t *nt_file_size);
static const ut8 *build_note_section(linux_elf_note_t *sec_note, size_t *size_note_section);
static bool dump_elf_pheaders(RBuffer *dest, linux_elf_note_t *sec_note, unsigned long offset_to_note);
static void show_maps(linux_map_entry_t *head);	/* test purposes */
static bool dump_elf_map_content(RBuffer *dest, linux_map_entry_t *head, pid_t pid);
static void may_clean_all(linux_elf_note_t *sec_note, proc_stat_content_t *proc_data, Elf64_Ehdr *elf_hdr);
bool linux_generate_corefile (RDebug *dbg, RBuffer *dest);
