//ssed on the registers rdi, rsi, rdx, r10, r8 and r9
/*
 * sfsyscall.h --- SFLib syscall macros for OpenBSD/i386 
 * see http://www.secdev.org/projects/shellforge.html for more informations
 *
 * Copyright (C) 2004  Philippe Biondi <phil@secdev.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */


#ifndef SFSYSCALL_H
#define SFSYSCALL_H


#ifdef SF_USE_ERRNO
/* Remove errno stuff */
int errno;
#error "SF_USER_ERRNO not supported yet"
#else
#define __sfsyscall_return(type, res) \
do { \
	return (type) (res); \
} while (0)
#endif


/* syscall macros */

#define _sfsyscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("syscall" \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name)); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("mov %2, %%rdi\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name),"g" ((long)(arg1))); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("mov %2, %%rdi\n\t"     \
		  "mov %3, %%rsi\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name),"g" ((long)(arg1)),"g" ((long)(arg2)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall3ipi(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("mov %4, %%rdx\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name), \
		"D" (arg1),\
		"S" (arg2), \
		"g" ((long)(arg3)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("mov %2, %%rdi\n\t"     \
		  "mov %3, %%rsi\n\t"     \
		  "mov %4, %%rdx\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name),"g" ((long)(arg1)),"g" ((long)(arg2)), \
		  "g" ((long)(arg3)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("mov %2, %%rdi\n\t"     \
		  "mov %3, %%rsi\n\t"     \
		  "mov %4, %%rdx\n\t"     \
		  "mov %5, %%r10\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)) ); \
__sfsyscall_return(type,__res); \
} 

#define _sfsyscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("mov %2, %%rdi\n\t"     \
		  "mov %3, %%rsi\n\t"     \
		  "mov %4, %%rdx\n\t"     \
		  "mov %5, %%r10\n\t"     \
		  "mov %6, %%r8\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name),"g" ((long)(arg1)),"g" ((long)(arg2)), \
	  "g" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5))); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
long __res; \
__asm__ volatile ("mov %2, %%rdi\n\t"     \
		  "mov %3, %%rsi\n\t"     \
		  "mov %4, %%rdx\n\t"     \
		  "mov %5, %%r10\n\t"     \
		  "mov %6, %%r8\n\t"     \
		  "mov %7, %%r9\n\t"     \
		  "syscall\n\t"  \
	: "=a" (__res) \
	: "0" (0x2000000 | __NR_##name),"g" ((long)(arg1)),"g" ((long)(arg2)), \
	  "g" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5)), \
	  "g" ((long)(arg6))); \
__sfsyscall_return(type,__res); \
}


#endif /* SFSYSCALL_H */
