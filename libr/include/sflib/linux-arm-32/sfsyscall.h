/* sfsyscall.h --- SFLib syscall macros for Linux/arm64 - pancake */

#ifndef SFSYSCALL_H
#define SFSYSCALL_H

/* $Id$ */

#ifdef SF_USE_ERRNO

static int errno = 1234;

#define __sfsyscall_return(type, res) \
do { \
        if ((unsigned long)(res) >= (unsigned long)(-125)) { \
                errno = -(res); \
                res = -1; \
        } \
        return (type) (res); \
} while (0)

#else /* SF_USE_ERRNO */

#define __sfsyscall_return(type, res) \
do { \
	return (type) (res); \
} while (0)

#endif /* SF_USE_ERRNO */


/* syscall macros */

#define _sfsyscall0(type, name) 						\
type name(void) {					\
	long __res;						\
	__asm__ volatile("###> " #name " <###\n\t"						\
		"svc 0"					\
		: "=a" (__res)					\
		: "0" (__NR_##name)				\
		: "memory", "cc"\
	);							\
	__sfsyscall_return(type,__res);						\
}

#define _sfsyscall1(type, name, type1, arg1) 					\
type name(type1 arg1) {						\
	long __res;						\
	register type1 r1 asm("r0");				\
	r1 = arg1;						\
	asm volatile ("###> " #name "(%2) <###\n\t"						\
		"mov r7, %0\n\t"					\
		"svc 0"					\
		: "=g" (__res) \
		: "0" (__NR_##name), "r"(r1) \
	);							\
	__sfsyscall_return(type,__res);						\
}

#define _sfsyscall2(type, name, type1, arg1, type2, arg2) 				\
	type name(type1 arg1, type2 arg2) {				\
		long __res;						\
		register type1 r1 asm("r1");				\
		register type2 r2 asm("r2");				\
		r1 = arg1;						\
		r2 = arg2;						\
		__asm__ volatile("###> " #name "(%2, %3) <###\n\t" 						\
				"svc 0"					\
				: "=g" (__res)					\
				: "0" (__NR_##name),				\
				"r" (r1),					\
				"r" (r2)					\
				);							\
		__sfsyscall_return(type, __res);						\
}

#define _sfsyscall3(type, name, type1, arg1, type2, arg2, type3, arg3) 			\
	type name(type1 arg1, type2 arg2, type3 arg3) {			\
		long __res;						\
		register type1 r0 asm("r0");				\
		register type2 r1 asm("r1");				\
		register type3 r2 asm("r2");				\
		r0 = arg1;						\
		r1 = arg2;						\
		r2 = arg3;						\
		__asm__ __volatile__ ("###> " #name "(%2, %3, %4) <###\n\t"	\
				"mov r7, %1\n\t"			\
				"svc 0"					\
				: "=g" (__res)				\
				: "0" (__NR_##name),			\
				"r" (r0),				\
				"r" (r1),				\
				"r" (r2)				\
				: "memory", "cc"\
				);					\
		__sfsyscall_return(type, __res);			\
	}

#define _sfsyscall4(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) 		\
	type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {	\
		long __res;						\
		register type1 r1 asm("r1"); ;				\
		register type2 r2 asm("r2");				\
		register type3 r3 asm("r3");				\
		register type4 r4 asm("r4");				\
		r1 = arg1;						\
		r2 = arg2;						\
		r3 = arg3;						\
		r4 = arg4;						\
		asm volatile("###> " #name "(%2, %3, %4, %5) <###\n\t"						\
				"svc 0"					\
				: "=g" (__res)					\
				: "0" (__NR_##name),				\
				"r" (r1),					\
				"r" (r2),					\
				"r" (r3),					\
				"r" (r4)					\
				: "memory", "cc"			\
				);							\
		__sfsyscall_return(type, __res);						\
	}

#define _sfsyscall5(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) 	\
	type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,	\
			type5 arg5) {						\
		long __res;						\
		register type1 r1 asm("r1");				\
		register type2 r2 asm("r2");				\
		register type3 r3 asm("r3");				\
		register type4 r4 asm("r4");				\
		register type5 r5 asm("r5");				\
		r1 = arg1;						\
		r2 = arg2;						\
		r3 = arg3;						\
		r4 = arg4;						\
		r5 = arg5;						\
		asm volatile("###> " #name "(%2, %3, %4, %5, %6) <###\n\t"						\
				"svc 0"					\
				: "=g" (__res)					\
				: "0" (__NR_##name),				\
				"r" (r1),					\
				"r" (r2),					\
				"r" (r3),					\
				"r" (r4),					\
				"r" (r5)					\
				: "memory", "cc"			\
				);							\
		__sfsyscall_return(type, __res);						\
	}

#define _sfsyscall6(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6)\
	type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,	\
			type5 arg5, type6 arg6) {				\
		long __res;						\
		register type1 r1 asm("r1");				\
		register type2 r2 asm("r2");				\
		register type3 r3 asm("r3");				\
		register type4 r4 asm("r4");				\
		register type5 r5 asm("r5");				\
		register type6 r6 asm("r6");				\
		r1 = arg1;						\
		r2 = arg2;						\
		r3 = arg3;						\
		r4 = arg4;						\
		r5 = arg5;						\
		r6 = arg6;						\
		asm volatile("###> " #name "(%2, %3, %4, %5, %6, %7) <###\n\t"						\
				"svc 0"					\
				: "=a" (__res)					\
				: "0" (__NR_##name),				\
				"r" (r1),					\
				"r" (r2),					\
				"r" (r3),					\
				"r" (r4),					\
				"r" (r5),					\
				"r" (r6)					\
				: "memory", "cc"			\
				);							\
		__sfsyscall_return(type, __res);						\
	}

#endif /* SFSYSCALL_H */
