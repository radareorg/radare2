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
	register type1 x1 asm("x0");				\
	x1 = arg1;						\
	asm volatile ("###> " #name "(%2) <###\n\t"						\
		"mov x8, %0\n\t"					\
		"svc 0"					\
		: "=g" (__res) \
		: "0" (__NR_##name), "r"(x1) \
	);							\
	__sfsyscall_return(type,__res);						\
}

#define _sfsyscall2(type, name, type1, arg1, type2, arg2) 				\
	type name(type1 arg1, type2 arg2) {				\
		long __res;						\
		register type1 x1 asm("x1");				\
		register type2 x2 asm("x2");				\
		x1 = arg1;						\
		x2 = arg2;						\
		__asm__ volatile("###> " #name "(%2, %3) <###\n\t" 						\
				"svc 0"					\
				: "=g" (__res)					\
				: "0" (__NR_##name),				\
				"r" (x1),					\
				"r" (x2)					\
				);							\
		__sfsyscall_return(type, __res);						\
}

#define _sfsyscall3(type, name, type1, arg1, type2, arg2, type3, arg3) 			\
	type name(type1 arg1, type2 arg2, type3 arg3) {			\
		long __res;						\
		register type1 x0 asm("x0");				\
		register type2 x1 asm("x1");				\
		register type3 x2 asm("x2");				\
		x0 = arg1;						\
		x1 = arg2;						\
		x2 = arg3;						\
		__asm__ __volatile__ ("###> " #name "(%2, %3, %4) <###\n\t"	\
				"mov x8, %1\n\t"			\
				"svc 0"					\
				: "=g" (__res)				\
				: "0" (__NR_##name),			\
				"r" (x0),				\
				"r" (x1),				\
				"r" (x2)				\
				: "memory", "cc"\
				);					\
		__sfsyscall_return(type, __res);			\
	}

#define _sfsyscall4(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) 		\
	type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {	\
		long __res;						\
		register type1 x1 asm("x1"); ;				\
		register type2 x2 asm("x2");				\
		register type3 x3 asm("x3");				\
		register type4 x4 asm("x4");				\
		x1 = arg1;						\
		x2 = arg2;						\
		x3 = arg3;						\
		x4 = arg4;						\
		asm volatile("###> " #name "(%2, %3, %4, %5) <###\n\t"						\
				"svc 0"					\
				: "=g" (__res)					\
				: "0" (__NR_##name),				\
				"r" (x1),					\
				"r" (x2),					\
				"r" (x3),					\
				"r" (x4)					\
				: "memory", "cc"			\
				);							\
		__sfsyscall_return(type, __res);						\
	}

#define _sfsyscall5(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) 	\
	type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,	\
			type5 arg5) {						\
		long __res;						\
		register type1 x1 asm("x1");				\
		register type2 x2 asm("x2");				\
		register type3 x3 asm("x3");				\
		register type4 x4 asm("x4");				\
		register type5 x5 asm("x5");				\
		x1 = arg1;						\
		x2 = arg2;						\
		x3 = arg3;						\
		x4 = arg4;						\
		x5 = arg5;						\
		asm volatile("###> " #name "(%2, %3, %4, %5, %6) <###\n\t"						\
				"svc 0"					\
				: "=g" (__res)					\
				: "0" (__NR_##name),				\
				"r" (x1),					\
				"r" (x2),					\
				"r" (x3),					\
				"r" (x4),					\
				"r" (x5)					\
				: "memory", "cc"			\
				);							\
		__sfsyscall_return(type, __res);						\
	}

#define _sfsyscall6(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6)\
	type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4,	\
			type5 arg5, type6 arg6) {				\
		long __res;						\
		register type1 x1 asm("x1");				\
		register type2 x2 asm("x2");				\
		register type3 x3 asm("x3");				\
		register type4 x4 asm("x4");				\
		register type5 x5 asm("x5");				\
		register type6 x6 asm("x6");				\
		x1 = arg1;						\
		x2 = arg2;						\
		x3 = arg3;						\
		x4 = arg4;						\
		x5 = arg5;						\
		x6 = arg6;						\
		asm volatile("###> " #name "(%2, %3, %4, %5, %6, %7) <###\n\t"						\
				"svc 0"					\
				: "=a" (__res)					\
				: "0" (__NR_##name),				\
				"r" (x1),					\
				"r" (x2),					\
				"r" (x3),					\
				"r" (x4),					\
				"r" (x5),					\
				"r" (x6)					\
				: "memory", "cc"			\
				);							\
		__sfsyscall_return(type, __res);						\
	}

#endif /* SFSYSCALL_H */
