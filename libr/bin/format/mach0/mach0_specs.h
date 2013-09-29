
#ifndef _INCLUDE_R_BIN_MACH0_SPECS_H_
#define _INCLUDE_R_BIN_MACH0_SPECS_H_

typedef int integer_t;

// NOTE(eddyb) the following have been slightly modified to work under radare.

#include "mach/machine.h"
#include "mach/vm_prot.h"
#include "mach-o/loader.h"
#include "mach-o/nlist.h"
#include "mach-o/fat.h"

// HACK(eddyb) everything below is from the old mach0_specs.h, should replace
// with proper original definitions.

#undef MACH0_

#if R_BIN_MACH064
#define MACH0_(name) name##_64
#else
#define MACH0_(name) name
#endif

#define R_BIN_MACH0_SYMBOL_TYPE_EXT 0
#define R_BIN_MACH0_SYMBOL_TYPE_LOCAL 1

struct x86_thread_state32 {
	ut32	eax;
	ut32	ebx;
	ut32	ecx;
	ut32	edx;
	ut32	edi;
	ut32	esi;
	ut32	ebp;
	ut32	esp;
	ut32	ss;
	ut32	eflags;
	ut32	eip;
	ut32	cs;
	ut32	ds;
	ut32	es;
	ut32	fs;
	ut32	gs;
};

struct x86_thread_state64 {
	ut64	rax;
	ut64	rbx;
	ut64	rcx;
	ut64	rdx;
	ut64	rdi;
	ut64	rsi;
	ut64	rbp;
	ut64	rsp;
	ut64	r8;
	ut64	r9;
	ut64	r10;
	ut64	r11;
	ut64	r12;
	ut64	r13;
	ut64	r14;
	ut64	r15;
	ut64	rip;
	ut64	rflags;
	ut64	cs;
	ut64	fs;
	ut64	gs;
};

#define X86_THREAD_STATE32	1
#define X86_THREAD_STATE64	4

struct ppc_thread_state32 {
	ut32 srr0;  /* Instruction address register (PC) */
	ut32 srr1;	/* Machine state register (supervisor) */
	ut32 r0;
	ut32 r1;
	ut32 r2;
	ut32 r3;
	ut32 r4;
	ut32 r5;
	ut32 r6;
	ut32 r7;
	ut32 r8;
	ut32 r9;
	ut32 r10;
	ut32 r11;
	ut32 r12;
	ut32 r13;
	ut32 r14;
	ut32 r15;
	ut32 r16;
	ut32 r17;
	ut32 r18;
	ut32 r19;
	ut32 r20;
	ut32 r21;
	ut32 r22;
	ut32 r23;
	ut32 r24;
	ut32 r25;
	ut32 r26;
	ut32 r27;
	ut32 r28;
	ut32 r29;
	ut32 r30;
	ut32 r31;

	ut32 cr;    /* Condition register */
	ut32 xer;	/* User's integer exception register */
	ut32 lr;	/* Link register */
	ut32 ctr;	/* Count register */
	ut32 mq;	/* MQ register (601 only) */

	ut32 vrsave;	/* Vector Save Register */
};

struct ppc_thread_state64 {
	ut64 srr0;  /* Instruction address register (PC) */
	ut64 srr1;  /* Machine state register (supervisor) */
	ut64 r0;
	ut64 r1;
	ut64 r2;
	ut64 r3;
	ut64 r4;
	ut64 r5;
	ut64 r6;
	ut64 r7;
	ut64 r8;
	ut64 r9;
	ut64 r10;
	ut64 r11;
	ut64 r12;
	ut64 r13;
	ut64 r14;
	ut64 r15;
	ut64 r16;
	ut64 r17;
	ut64 r18;
	ut64 r19;
	ut64 r20;
	ut64 r21;
	ut64 r22;
	ut64 r23;
	ut64 r24;
	ut64 r25;
	ut64 r26;
	ut64 r27;
	ut64 r28;
	ut64 r29;
	ut64 r30;
	ut64 r31;

	ut32 cr;			/* Condition register */
	ut64 xer;		/* User's integer exception register */
	ut64 lr;		/* Link register */
	ut64 ctr;		/* Count register */

	ut32 vrsave;		/* Vector Save Register */
};

struct arm_thread_state32 {
	ut32 r0;
	ut32 r1;
	ut32 r2;
	ut32 r3;
	ut32 r4;
	ut32 r5;
	ut32 r6;
	ut32 r7;
	ut32 r8;
	ut32 r9;
	ut32 r10;
	ut32 r11;
	ut32 r12;
	ut32 r13;
	ut32 r14;
	ut32 r15;
	ut32 r16;   /* Apple's thread_state has this 17th reg, bug?? */
};

struct arm_thread_state64 {
	ut64 x[29];
	ut64 fp;
	ut64 lr;
	ut64 sp;
	ut64 pc;
	ut32 cpsr;
};

/* Cache header */

struct cache_header {
	char version[16];
	ut32 baseaddroff;
	ut32 unk2;
	ut32 startaddr;
	ut32 numlibs;

	ut64 dyldaddr;
	//ut64 codesignoff;
};

#endif
