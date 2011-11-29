
/* $Id$ */

#ifdef SF_USE_ERRNO

static int errno=1234;

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

#define _sfsyscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("###> " #name "() <###\n\t" \
		   "int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name)); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("###> " #name "(%2) <###\n\t"    \
		  "pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1))); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("###> " #name "(%2, %3) <###\n\t"    \
		  "pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("###> " #name "(%2, %3, %4) <###\n\t"    \
		  "pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
		  "d" ((long)(arg3)) ); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("###> " #name "(%2, %3, %4, %5) <###\n\t"    \
		  "pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)) ); \
__sfsyscall_return(type,__res); \
} 

#define _sfsyscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("###> " #name "(%2, %3, %4, %5, %6) <###\n\t"    \
		  "pushl %%ebx\n\t"     \
                  "mov %2,%%ebx\n\t"    \
		  "int $0x80\n\t"       \
                  "popl %%ebx"          \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5))); \
__sfsyscall_return(type,__res); \
}

#define _sfsyscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
	  type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
long __res; \
__asm__ volatile ("##> " #name "(%2, %3, %4, %5, %6, %7) <###\n\t"    \
		  "pushl %%ebx\n\t"  \
		  "pushl %%ebp\n\t"  \
                  "movl %2,%%ebx\n\t" \
                  "movl %7,%%ebp\n\t" \
		  "int $0x80\n\t"    \
		  "popl %%ebp\n\t"   \
                  "popl %%ebx"       \
	: "=a" (__res) \
	: "0" (__NR_##name),"g" ((long)(arg1)),"c" ((long)(arg2)), \
	  "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)), \
	  "g" ((long)(arg6))); \
__sfsyscall_return(type,__res); \
}


#define _sfoldsyscall6(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
          type5,arg5,type6,arg6) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5, type6 arg6) \
{ \
long __res; \
__asm__ volatile ("pushl %%ebx\n\t"  \
                  "pushl %7\n\t" \
                  "pushl %6\n\t" \
                  "pushl %5\n\t" \
                  "pushl %4\n\t" \
                  "pushl %3\n\t" \
                  "pushl %2\n\t" \
                  "movl %%esp, %%ebx\n\t" \
                  "int $0x80\n\t"    \
                  "add $0x18,%%esp\n\t"  \
                  "popl %%ebx"   \
        : "=a" (__res) \
        : "0" (__NR_##name),"g" ((long)(arg1)),"g" ((long)(arg2)), \
          "g" ((long)(arg3)),"g" ((long)(arg4)),"g" ((long)(arg5)), \
          "g" ((long)(arg6))); \
__sfsyscall_return(type,__res); \
}

