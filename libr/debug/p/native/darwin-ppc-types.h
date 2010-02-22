/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef	_MACH_PPC__TYPES_H_
#define	_MACH_PPC__TYPES_H_

/*
 * ppc_thread_state is the structure that is exported to user threads for 
 * use in status/mutate calls.  This structure should never change.
 *
 */

#ifndef _POSIX_C_SOURCE
struct ppc_thread_state
#else /* _POSIX_C_SOURCE */
struct __darwin_ppc_thread_state
#endif /* _POSIX_C_SOURCE */
{
	unsigned int srr0;      /* Instruction address register (PC) */
	unsigned int srr1;	/* Machine state register (supervisor) */
	unsigned int r0;
	unsigned int r1;
	unsigned int r2;
	unsigned int r3;
	unsigned int r4;
	unsigned int r5;
	unsigned int r6;
	unsigned int r7;
	unsigned int r8;
	unsigned int r9;
	unsigned int r10;
	unsigned int r11;
	unsigned int r12;
	unsigned int r13;
	unsigned int r14;
	unsigned int r15;
	unsigned int r16;
	unsigned int r17;
	unsigned int r18;
	unsigned int r19;
	unsigned int r20;
	unsigned int r21;
	unsigned int r22;
	unsigned int r23;
	unsigned int r24;
	unsigned int r25;
	unsigned int r26;
	unsigned int r27;
	unsigned int r28;
	unsigned int r29;
	unsigned int r30;
	unsigned int r31;

	unsigned int cr;        /* Condition register */
	unsigned int xer;	/* User's integer exception register */
	unsigned int lr;	/* Link register */
	unsigned int ctr;	/* Count register */
	unsigned int mq;	/* MQ register (601 only) */

	unsigned int vrsave;	/* Vector Save Register */
};

#ifndef _POSIX_C_SOURCE
#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct ppc_thread_state64 {
	unsigned long long srr0;	/* Instruction address register (PC) */
	unsigned long long srr1;	/* Machine state register (supervisor) */
	unsigned long long r0;
	unsigned long long r1;
	unsigned long long r2;
	unsigned long long r3;
	unsigned long long r4;
	unsigned long long r5;
	unsigned long long r6;
	unsigned long long r7;
	unsigned long long r8;
	unsigned long long r9;
	unsigned long long r10;
	unsigned long long r11;
	unsigned long long r12;
	unsigned long long r13;
	unsigned long long r14;
	unsigned long long r15;
	unsigned long long r16;
	unsigned long long r17;
	unsigned long long r18;
	unsigned long long r19;
	unsigned long long r20;
	unsigned long long r21;
	unsigned long long r22;
	unsigned long long r23;
	unsigned long long r24;
	unsigned long long r25;
	unsigned long long r26;
	unsigned long long r27;
	unsigned long long r28;
	unsigned long long r29;
	unsigned long long r30;
	unsigned long long r31;

	unsigned int cr;			/* Condition register */
	unsigned long long xer;		/* User's integer exception register */
	unsigned long long lr;		/* Link register */
	unsigned long long ctr;		/* Count register */

	unsigned int vrsave;		/* Vector Save Register */
};

#pragma pack()
#endif /* _POSIX_C_SOURCE */

/* This structure should be double-word aligned for performance */

#ifndef _POSIX_C_SOURCE
struct ppc_float_state
#else /* _POSIX_C_SOURCE */
struct __darwin_ppc_float_state
#endif /* _POSIX_C_SOURCE */
{
	double  fpregs[32];

	unsigned int fpscr_pad; /* fpscr is 64 bits, 32 bits of rubbish */
	unsigned int fpscr;	/* floating point status register */
};

#pragma pack(4)		/* Make sure the structure stays as we defined it */

#ifndef _POSIX_C_SOURCE
struct ppc_vector_state
#else /* _POSIX_C_SOURCE */
struct __darwin_ppc_vector_state
#endif /* _POSIX_C_SOURCE */
{
#if defined(__LP64__)
	unsigned int	save_vr[32][4];
	unsigned int	save_vscr[4];
#else
	unsigned long	save_vr[32][4];
	unsigned long	save_vscr[4];
#endif
	unsigned int	save_pad5[4];
	unsigned int	save_vrvalid;			/* VRs that have been saved */
	unsigned int	save_pad6[7];
};
#pragma pack()

/*
 * ppc_exception_state
 *
 * This structure corresponds to some additional state of the user
 * registers as saved in the PCB upon kernel entry. They are only
 * available if an exception is passed out of the kernel, and even
 * then not all are guaranteed to be updated.
 *
 * Some padding is included in this structure which allows space for
 * servers to store temporary values if need be, to maintain binary
 * compatiblity.
 */

/* Exception state for 32-bit thread (on 32-bit processor) */
/* Still available on 64-bit processors, but may fall short */
/* of covering the full potential state (hi half available). */

#pragma pack(4)	/* Make sure the structure stays as we defined it */

#ifndef _POSIX_C_SOURCE
struct ppc_exception_state
#else /* _POSIX_C_SOURCE */
struct __darwin_ppc_exception_state
#endif /* _POSIX_C_SOURCE */
{
#if defined(__LP64__)
	unsigned int dar;			/* Fault registers for coredump */
	unsigned int dsisr;
	unsigned int exception;	/* number of powerpc exception taken */
	unsigned int pad0;			/* align to 16 bytes */
	unsigned int pad1[4];		/* space in PCB "just in case" */
#else
	unsigned long dar;			/* Fault registers for coredump */
	unsigned long dsisr;
	unsigned long exception;	/* number of powerpc exception taken */
	unsigned long pad0;			/* align to 16 bytes */
	unsigned long pad1[4];		/* space in PCB "just in case" */
#endif
};

#ifndef _POSIX_C_SOURCE
struct ppc_exception_state64 {
	unsigned long long dar;		/* Fault registers for coredump */
#if defined(__LP64__)
	unsigned int  dsisr;
	unsigned int  exception;	/* number of powerpc exception taken */
	unsigned int  pad1[4];		/* space in PCB "just in case" */
#else
	unsigned long dsisr;
	unsigned long exception;	/* number of powerpc exception taken */
	unsigned long pad1[4];		/* space in PCB "just in case" */
#endif
};
#endif /* _POSIX_C_SOURCE */

#pragma pack()

#endif /* _MACH_PPC__TYPES_H_ */
