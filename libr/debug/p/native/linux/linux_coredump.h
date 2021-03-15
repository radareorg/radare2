/* coredump api */

#ifndef LINUX_COREDUMP_H
#define LINUX_COREDUMP_H

#include "elf_specs.h"
#include <sys/procfs.h>

#if __i386__ || __x86_64__
/*Macros for XSAVE/XRESTORE*/
/*
        From: http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developers-manual.pdf
        Bit 00: x87 state.
        Bit 01: SSE state.
        Bit 02: AVX state.
        Bits 04 - 03: MPX state. (https://software.intel.com/sites/default/files/managed/9d/f6/Intel_MPX_EnablingGuide.pdf)
        Bits 07 - 05: AVX-512 state.
        Bit 08: Used for IA32_XSS.
        Bit 09: PKRU state
*/
#define X87_BIT                 (1ULL << 0)
#define SSE_BIT                 (1ULL << 1)
#define AVX_BIT                 (1ULL << 2)
#define BNDREGS_BIT             (1ULL << 3)
#define BNDCSR_BIT              (1ULL << 4)
/* From Intel MPX: "The OS should set both bits to ONE to enable Intel MPX; otherwise the processor would interpret Intel MPX instructions as NOPs" */
#define MPX_BIT			(BNDREGS_BIT | BNDCSR_BIT)
/* https://software.intel.com/sites/default/files/managed/b4/3a/319433-024.pdf - Page 66
"Execute XGETBV and verify that XCR0[7:5] = ‘111b’ (OPMASK state, upper 256-bit of ZMM0-ZMM15 and ZMM16-ZMM31 state are enabled by OS) and that XCR0[2:1] = ‘11b’ (XMM state and YMM state are enabled by OS)" */
#define AVX512_k_BIT            (1ULL << 5)
#define AVX512_ZMM0_15_BIT      (1ULL << 6)
#define AVX512_ZMM16_31_BIT     (1ULL << 7)
#define AVX512_FULL_BIT         (AVX512_k_BIT|AVX512_ZMM0_15_BIT|AVX512_ZMM16_31_BIT)
#define IA32_XSS_BIT    	(1ULL << 8)     /* ?? */
#define PKRU_BIT        	(1ULL << 9)     /* ?? */

#define NO_STATE_BIT            X87_BIT
#define XSTATE_SSE_SIZE         576
#define XSTATE_AVX_SIZE         832
/*#define XSTATE_BNDCGR ?? */
#define XSTATE_MPX_SIZE         1088
#define XSTATE_AVX512_k_SIZE    1152
#define XSTATE_AVX512_ZMM0_7    1408
#define XSTATE_AVX512_ZMM8_15   1664
#define XSTATE_AVX512_ZMM16_31  2688
#define XSTATE_FULL_SIZE        XSTATE_AVX512_ZMM16_31

#define XSTATE_HDR_SIZE         XSTATE_SSE_SIZE
#define XCR0_OFFSET             464

#define XSTATE_SSE_MASK         (X87_BIT|SSE_BIT)
#define XSTATE_AVX_MASK         (XSTATE_SSE_MASK|AVX_BIT)
#define XSTATE_MPX_MASK         (MPX_BIT|XSTATE_AVX_MASK|XSTATE_SSE_MASK)
#define XSTATE_AVX512_MASK      (XSTATE_AVX_MASK|AVX512_FULL_BIT)
/*********************************/
#endif

#define SIZE_PR_FNAME	16

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

typedef struct proc_per_process {
	int pid;
	char s_name;
	ut32 uid;
	ut32 gid;
	int ppid;
	int pgrp;
	int sid;
	ut32 flag;
	long int nice;
	long int num_threads;
	unsigned char coredump_filter;
} proc_per_process_t;

typedef struct proc_per_thread {
	int tid;
	ut64 sigpend;
	ut64 sighold;
	ut64 utime;
	ut64 stime;
	long int cutime;
	long int cstime;
	struct proc_per_thread *n;
} proc_per_thread_t;

typedef struct proc_content {
	proc_per_thread_t *per_thread;
	proc_per_process_t *per_process;
} proc_content_t;

typedef struct map_file {
	ut32 count;
	ut32 size;
} map_file_t;

typedef struct linux_map_entry {
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long offset;
	ut8 perms;
	bool anonymous;
	bool dumpeable;
	bool kernel_mapping;
	bool file_backed;
	bool shared;
	char *name;
	struct linux_map_entry *n;
} linux_map_entry_t;

#define ADD_MAP_NODE(p)	{ if (me_head) { p->n = NULL; me_tail->n = p; me_tail = p; } else { me_head = p; me_tail = p; } }

typedef struct auxv_buff {
        void *data;
        size_t size;
} auxv_buff_t;

/*NT_* thread-wide*/
typedef struct thread_elf_note {
	prstatus_t *prstatus;
	elf_fpregset_t *fp_regset;
#if __i386__
	elf_fpxregset_t	*fpx_regset;
#endif
	siginfo_t *siginfo;
#if __i386__ || __x86_64__
	void *xsave_data;
#elif __arm__ || __arm64__
	void *arm_vfp_data;
#endif
	struct thread_elf_note *n;
} thread_elf_note_t;

/*NT_* process-wide*/
typedef struct proc_elf_note {
	prpsinfo_t *prpsinfo;
	auxv_buff_t *auxv;
	linux_map_entry_t *maps;
	thread_elf_note_t *thread_note;
	int n_threads;
} elf_proc_note_t;

typedef enum {
	NT_PRPSINFO_T = 0,
	NT_AUXV_T,
	NT_FILE_T,
	NT_PRSTATUS_T,
	NT_SIGINFO_T,
	NT_FPREGSET_T,
#if __i386__
	NT_PRXFPREG_T,
#endif
#if __i386__ || __x86_64__
	NT_X86_XSTATE_T,
#elif __arm__ || __arm64__
	NT_ARM_VFP_T,
#endif
	NT_LENGHT_T
} note_type_t;

typedef struct elf_note_types {
	int size;
	int size_roundedup;
	int size_name;
	char name[8];
} note_info_t;

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

#endif
