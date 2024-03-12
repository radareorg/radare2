#ifndef R2_TYPES_H
#define R2_TYPES_H

#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64

// defines like IS_DIGIT, etc'
#include <r_types_base.h>
#include "r_util/r_str_util.h"
#include <r_userconf.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h> // required for uint64_t
#include <inttypes.h> // required for PRIx64

// TODO: fix this to make it crosscompile-friendly: R_SYS_OSTYPE ?
/* operating system */
#undef R2__BSD__
#undef __KFBSD__
#undef R2__UNIX__
#undef R2__WINDOWS__

#define R_MODE_PRINT 0x000
#define R_MODE_RADARE 0x001
#define R_MODE_SET 0x002
#define R_MODE_SIMPLE 0x004
#define R_MODE_JSON 0x008
#define R_MODE_ARRAY 0x010
#define R_MODE_SIMPLEST 0x020
#define R_MODE_CLASSDUMP 0x040 /* deprecate maybe */
#define R_MODE_EQUAL 0x080
#define R_MODE_KV 0x100

#define R_IN /* do not use, implicit */
#define R_OUT /* parameter is written, not read */
#define R_INOUT /* parameter is read and written */
#define R_OWN /* pointer ownership is transferred */
#define R_BORROW /* pointer ownership is not transferred, it must not be freed by the caller */
#define R_NONNULL /* pointer can not be null */
#define R_NULLABLE /* pointer can be null */

/* should not be used in new code and should/will be removed in the future */
#ifdef __GNUC__
#  define R_DEPRECATE
#  define R_DEPRECATED __attribute__((deprecated))
#else
#  define R_DEPRECATE
#  define R_DEPRECATED
#endif

#ifdef __GNUC__
#  define R_WIP __attribute__((deprecated))
// ("this function is considered as work-in-progress", "use it at your own risk")))
// warning doesnt work on llvm/clang, its a gcc specific thing,
// __attribute__((warning("Don't use this function yet. its too new")))
#else
#  define R_WIP /* should not be used in new code and should/will be removed in the future */
#endif
#define R_IFNULL(x) /* default value for the pointer when null */

#ifdef R_NEW
#undef R_NEW
#endif

#ifdef R_NEW0
#undef R_NEW0
#endif

#ifdef R_FREE
#undef R_FREE
#endif

#ifdef R_NEWCOPY
#undef R_NEWCOPY
#endif

// used in debug, io, bin, anal, ...
#define R_PERM_R	4
#define R_PERM_W	2
#define R_PERM_X	1
#define R_PERM_RW	(R_PERM_R|R_PERM_W)
#define R_PERM_RX	(R_PERM_R|R_PERM_X)
#define R_PERM_RWX	(R_PERM_R|R_PERM_W|R_PERM_X)
#define R_PERM_WX	(R_PERM_W|R_PERM_X)
#define R_PERM_S	8
#define R_PERM_SHAR	8 /* just S_PERM, instead of _SHAR -- R2_590 */
#define R_PERM_PRIV	16
#define R_PERM_ACCESS	32
#define R_PERM_CREAT	64


// HACK to fix capstone-android-mips build
#undef mips
#define mips mips

#if defined(__powerpc) || defined(__powerpc__)
#undef __POWERPC__
#define __POWERPC__ 1
#endif

#ifndef TARGET_OS_IPHONE
#if defined(__APPLE__) && (__arm__ || __arm64__ || __aarch64__ || __arm64e__)
#define TARGET_OS_IPHONE 1
#else
#define TARGET_OS_IPHONE 0
#endif
#endif

#undef LIBC_HAVE_SYSTEM
#undef HAVE_SYSTEM
#if __IPHONE_8_0 && TARGET_OS_IPHONE && !defined(MAC_OS_VERSION_11_0)
#define LIBC_HAVE_SYSTEM 0
#define HAVE_SYSTEM 0
#elif __wasi__
#define LIBC_HAVE_SYSTEM 0
#define HAVE_SYSTEM 0
#else
#define LIBC_HAVE_SYSTEM 1
#define HAVE_SYSTEM 1
#endif

#if APPLE_SDK_IPHONEOS || APPLE_SDK_APPLETVOS || APPLE_SDK_WATCHOS || APPLE_SDK_APPLETVSIMULATOR || APPLE_SDK_WATCHSIMULATOR
#define LIBC_HAVE_PTRACE 0
#else
#define LIBC_HAVE_PTRACE 1
#endif

#if HAVE_FORK
#define LIBC_HAVE_FORK 1
#else
#define LIBC_HAVE_FORK 0
#endif

#if defined(__OpenBSD__)
#include <sys/param.h>
#undef MAXCOMLEN	/* redefined in zipint.h */
#endif

/* release >= 5.9 */
#if __OpenBSD__ && OpenBSD >= 201605
#define LIBC_HAVE_PLEDGE 1
#else
#define LIBC_HAVE_PLEDGE 0
#endif

#if __sun
#define LIBC_HAVE_PRIV_SET 1
#else
#define LIBC_HAVE_PRIV_SET 0
#endif

#ifdef __GNUC__
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x
#else
#  define UNUSED_FUNCTION(x) UNUSED_ ## x
#endif

#define R_UNUSED_RESULT(x) if ((x)) {}

#if defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
#define __KFBSD__ 1
#else
#define __KFBSD__ 0
#endif

#ifdef _MSC_VER
  #define restrict
  #define strcasecmp stricmp
  #define strncasecmp strnicmp
  #define R2__WINDOWS__ 1

  #include <time.h>
  static inline struct tm *gmtime_r(const time_t *t, struct tm *r) { return (gmtime_s(r, t))? NULL : r; }
#endif

#ifdef __HAIKU__
# define R2__UNIX__ 1
#endif

#undef HAVE_PTY
#if EMSCRIPTEN || __wasi__ || defined(__serenity__)
#define HAVE_PTY 0
#else
#define HAVE_PTY R2__UNIX__ && LIBC_HAVE_FORK && !__sun
#endif

#if defined(EMSCRIPTEN) || defined(__wasi__) || defined(__linux__) || defined(__APPLE__) || defined(__GNU__) || defined(__ANDROID__) || defined(__QNX__) || defined(__sun) || defined(__HAIKU__) || defined(__serenity__) || defined(__vinix__) || defined(_AIX)
  #define R2__BSD__ 0
  #define R2__UNIX__ 1
#endif
#if __KFBSD__ || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
  #define R2__BSD__ 1
  #define R2__UNIX__ 1
#endif
#if R2__WINDOWS__ || _WIN32
  #ifdef _MSC_VER
  /* Must be included before windows.h */
#ifndef WINSOCK_INCLUDED
#define WINSOCK_INCLUDED 1
  #include <winsock2.h>
  #include <ws2tcpip.h>
#endif
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #endif
  typedef int socklen_t;
  #undef USE_SOCKETS
  #define R2__WINDOWS__ 1
  #undef R2__UNIX__
  #undef R2__BSD__
#endif
#if R2__WINDOWS__ || _WIN32
  #define __addr_t_defined
  #include <windows.h>
#endif

#ifdef __GNUC__
  #define FUNC_ATTR_MALLOC __attribute__((malloc))
  #define FUNC_ATTR_ALLOC_SIZE(x) __attribute__((alloc_size(x)))
  #define FUNC_ATTR_ALLOC_SIZE_PROD(x,y) __attribute__((alloc_size(x,y)))
  #define FUNC_ATTR_ALLOC_ALIGN(x) __attribute__((alloc_align(x)))
  #define FUNC_ATTR_PURE __attribute__ ((pure))
  #define FUNC_ATTR_CONST __attribute__((const))
  #define FUNC_ATTR_USED __attribute__((used))
  #define FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
  #define FUNC_ATTR_ALWAYS_INLINE __attribute__((always_inline))

  #ifdef __clang__
    // clang only
  #elif defined(__INTEL_COMPILER)
    // intel only
  #else
    // gcc only
  #endif
#else
  #define FUNC_ATTR_MALLOC
  #define FUNC_ATTR_ALLOC_SIZE(x)
  #define FUNC_ATTR_ALLOC_SIZE_PROD(x,y)
  #define FUNC_ATTR_ALLOC_ALIGN(x)
  #define FUNC_ATTR_PURE
  #define FUNC_ATTR_CONST
  #define FUNC_ATTR_USED
  #define FUNC_ATTR_WARN_UNUSED_RESULT
  #define FUNC_ATTR_ALWAYS_INLINE
#endif

/* printf format check attributes */
#if defined(__clang__) || defined(__GNUC__)
#define R_PRINTF_CHECK(fmt, dots) __attribute__ ((format (printf, fmt, dots)))
#else
#define R_PRINTF_CHECK(fmt, dots)
#endif

#undef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h> /* for O_RDONLY */
#include <r_endian.h> /* needs size_t */

#ifdef __cplusplus
extern "C" {
#endif

#define TODO(x) eprintf(__func__"  " x)

// TODO: FS or R_SYS_DIR ??
#undef FS
#if R2__WINDOWS__
#define FS '\\'
#define R_SYS_DIR "\\"
#define R_SYS_ENVSEP ";"
#define R_SYS_HOME "USERPROFILE"
#define R_SYS_TMP "TEMP"
#else
#define FS "/"
#define R_SYS_DIR "/"
#define R_SYS_ENVSEP ":"
#define R_SYS_HOME "HOME"
#define R_SYS_TMP "TMPDIR"
#endif

#define R_JOIN_2_PATHS(p1, p2) p1 R_SYS_DIR p2
#define R_JOIN_3_PATHS(p1, p2, p3) p1 R_SYS_DIR p2 R_SYS_DIR p3
#define R_JOIN_4_PATHS(p1, p2, p3, p4) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4
#define R_JOIN_5_PATHS(p1, p2, p3, p4, p5) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4 R_SYS_DIR p5

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

typedef int (*PrintfCallback)(const char *str, ...) R_PRINTF_CHECK(1, 2);

/* compile-time introspection helpers */
#define CTO(y,z) ((size_t) &((y*)0)->z)
#define CTA(x,y,z) (x+CTO(y,z))
#define CTI(x,y,z) (*((size_t*)(CTA(x,y,z))))
#define CTS(x,y,z,t,v) {t* _=(t*)CTA(x,y,z);*_=v;}

#define R_HIDDEN __attribute__((visibility("hidden")))

#define R_LIB_VERSION_HEADER(x) \
R_API const char *x##_version(void)
#define R_LIB_VERSION(x) \
R_API const char *x##_version(void) { return "" R2_GITTAP; }

#define BITS2BYTES(x) (((x)/8)+(((x)%8)?1:0))
#define ZERO_FILL(x) memset (&x, 0, sizeof (x))
#define R_NEWS0(x,y) (x*)calloc(y,sizeof (x))
#define R_NEWS(x,y) (x*)malloc(sizeof (x)*(y))
#define R_NEW0(x) (x*)calloc(1,sizeof (x))
#define R_NEW(x) (x*)malloc(sizeof (x))
#define R_NEWCOPY(x,y) (x*)r_new_copy(sizeof (x), y)

static inline void *r_new_copy(int size, void *data) {
	void *a = malloc(size);
	if (a) {
		memcpy (a, data, size);
	}
	return a;
}
// TODO: Make R_NEW_COPY be 1 arg, not two
#define R_NEW_COPY(x,y) x=(void*)malloc(sizeof (y));memcpy(x,y,sizeof (y))
#define R_MEM_ALIGN(x) ((void *)(size_t)(((ut64)(size_t)x) & 0xfffffffffffff000LL))
#define R_ARRAY_SIZE(x) (sizeof (x) / sizeof ((x)[0]))
#define R_PTR_MOVE(d,s) d=s;s=NULL;

#define R_PTR_ALIGN(v,t) \
	((char *)(((size_t)(v) ) \
	& ~(t - 1)))
#define R_PTR_ALIGN_NEXT(v,t) \
	((char *)(((size_t)(v) + (t - 1)) \
	& ~(t - 1)))

#define R_BIT_SET(x,y) (((ut8*)x)[(y)>>4] |= (1<<((y)&0xf)))
#define R_BIT_UNSET(x,y) (((ut8*)x)[(y)>>4] &= ~(1<<((y)&0xf)))
#define R_BIT_TOGGLE(x, y) ( R_BIT_CHK (x, y) ? \
		R_BIT_UNSET (x, y): R_BIT_SET (x, y))

//#define R_BIT_CHK(x,y) ((((const ut8*)x)[y>>4] & (1<<(y&0xf))))
#define R_BIT_CHK(x,y) (*(x) & (1<<(y)))

/* try for C99, but provide backwards compatibility */
#if defined(_MSC_VER) && (_MSC_VER <= 1800)
#define __func__ __FUNCTION__
#endif

#define PERROR_WITH_FILELINE 0

#if PERROR_WITH_FILELINE
/* make error messages useful by prepending file, line, and function name */
#define _perror(str,file,line,func) \
  { \
	  char buf[256]; \
	  snprintf(buf,sizeof (buf),"[%s:%d %s] %s",file,line,func,str); \
	  r_sys_perror_str(buf); \
  }
#define perror(x) _perror(x,__FILE__,__LINE__,__func__)
#define r_sys_perror(x) _perror(x,__FILE__,__LINE__,__func__)
#else
#define r_sys_perror(x) r_sys_perror_str(x);
#endif

#if R2__UNIX__
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/time.h>
#ifdef __HAIKU__
// Original macro cast it to clockid_t
#undef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 0
#endif
#endif

#ifndef typeof
#define typeof(arg) __typeof__(arg)
#endif

#if 1
#define r_offsetof(type, member) offsetof(type, member)
#else
#if __SDB_WINDOWS__
#define r_offsetof(type, member) ((unsigned long) (ut64)&((type*)0)->member)
#else
#define r_offsetof(type, member) ((unsigned long) &((type*)0)->member)
#endif
#endif


#define R_FREE(x) { free((void *)x); x = NULL; }

#if R2__WINDOWS__
#define HAVE_REGEXP 0
#else
#define HAVE_REGEXP 1
#endif

#if R2__WINDOWS__
#define PFMT64x "I64x"
#define PFMT64d "I64d"
#define PFMT64u "I64u"
#define PFMT64o "I64o"
#define PFMTSZx "Ix"
#define PFMTSZd "Id"
#define PFMTSZu "Iu"
#define PFMTSZo "Io"
#define LDBLFMT "f"
#define HHXFMT  "x"
#else
#define PFMT64x PRIx64
#define PFMT64d PRId64
#define PFMT64u PRIu64
#define PFMT64o PRIo64
#define PFMTSZx "zx"
#define PFMTSZd "zd"
#define PFMTSZu "zu"
#define PFMTSZo "zo"
#define LDBLFMT "Lf"
#define HHXFMT  "hhx"
#endif

#define PFMTDPTR "td"

#define PFMT32x "x"
#define PFMT32d "d"
#define PFMT32u "u"
#define PFMT32o "o"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef eprintf
#define eprintf(...) fprintf (stderr, __VA_ARGS__)
#endif

#ifndef R2_DEBUG_EPRINT
#define R2_DEBUG_EPRINT 0
#endif
#if !R2_DEBUG_EPRINT
#define EPRINT_STR
#define EPRINT_CHAR
#define EPRINT_INT
#define EPRINT_BOOL
#define EPRINT_PTR

#define EPRINT_UT64
#define EPRINT_ST64
#define EPRINT_UT32
#define EPRINT_ST32
#define EPRINT_UT16
#define EPRINT_ST16
#define EPRINT_UT8
#define EPRINT_ST8
#else
/* Pass R2_NO_EPRINT_MACROS=1 as an environment variable to disable these
 * macros at runtime. Used by r2r to prevent interference with tests. */
#define EPRINT_VAR_WRAPPER(name, fmt, ...) {				\
	char *eprint_env = r_sys_getenv ("R2_NO_EPRINT_MACROS");	\
	if (!eprint_env || strcmp (eprint_env, "1")) {			\
		eprintf (#name ": " fmt "\n", __VA_ARGS__);		\
	}								\
	free (eprint_env);						\
}

#define EPRINT_STR(x) EPRINT_VAR_WRAPPER (x, "\"%s\"", x)
#define EPRINT_CHAR(x) EPRINT_VAR_WRAPPER (x, "'%c' (0x%x)", x, x)
#define EPRINT_INT(x) EPRINT_VAR_WRAPPER (x, "%d (0x%x)", x, x)
#define EPRINT_BOOL(x) EPRINT_VAR_WRAPPER (x, "%s", x? "true": "false")
#define EPRINT_PTR(x) EPRINT_VAR_WRAPPER (x, "%p", x)

#define EPRINT_UT64(x) EPRINT_VAR_WRAPPER (x, "%" PFMT64u " (0x%" PFMT64x ")", x, x)
#define EPRINT_ST64(x) EPRINT_VAR_WRAPPER (x, "%" PFMT64d " (0x%" PFMT64x ")", x, x)
#define EPRINT_UT32(x) EPRINT_VAR_WRAPPER (x, "%" PFMT32u " (0x%" PFMT32x ")", x, x)
#define EPRINT_ST32(x) EPRINT_VAR_WRAPPER (x, "%" PFMT32d " (0x%" PFMT32x ")", x, x)
#define EPRINT_UT16(x) EPRINT_VAR_WRAPPER (x, "%hu (0x%hx)", x, x)
#define EPRINT_ST16(x) EPRINT_VAR_WRAPPER (x, "%hd (0x%hx)", x, x)
#define EPRINT_UT8(x) EPRINT_VAR_WRAPPER (x, "%hhu (0x%hhx)", x, x)
#define EPRINT_ST8(x) EPRINT_VAR_WRAPPER (x, "%hhd (0x%hhx)", x, x)
#endif

#if __APPLE__
# if __i386__
# define R_SYS_BASE ((ut64)0x1000)
# elif __x86_64__
# define R_SYS_BASE ((ut64)0x100000000)
# else
# define R_SYS_BASE ((ut64)0x1000)
# endif
#elif R2__WINDOWS__
# define R_SYS_BASE ((ut64)0x01001000)
#else // linux, bsd, ...
# if __arm__ || __arm64__ || __arm64e__
# define R_SYS_BASE ((ut64)0x4000)
# else
# define R_SYS_BASE ((ut64)0x8048000)
# endif
#endif

/* arch */
#if __i386__
#define R_SYS_ARCH "x86"
#define R_SYS_BITS R_SYS_BITS_32
#define R_SYS_ENDIAN 0
#elif __EMSCRIPTEN__ || __wasi__
#define R_SYS_ARCH "wasm"
#define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_ENDIAN 0
#elif __x86_64__
#define R_SYS_ARCH "x86"
#define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_ENDIAN 0
#elif __POWERPC__
# define R_SYS_ARCH "ppc"
# ifdef __powerpc64__
#  define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
# else
#  define R_SYS_BITS R_SYS_BITS_32
# endif
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define R_SYS_ENDIAN 0
# else
#  define R_SYS_ENDIAN 1
# endif
#elif __arm__
#define R_SYS_ARCH "arm"
#define R_SYS_BITS R_SYS_BITS_32
#define R_SYS_ENDIAN 0
#elif __arm64__ || __aarch64__ || __arm64e__
#define R_SYS_ARCH "arm"
#define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_ENDIAN 0
#elif __arc__
#define R_SYS_ARCH "arc"
#define R_SYS_BITS R_SYS_BITS_32
#define R_SYS_ENDIAN 0
#elif __s390x__
#define R_SYS_ARCH "s390x"
#define R_SYS_BITS R_SYS_BITS_64
#define R_SYS_ENDIAN 1
#elif __sparc__
#define R_SYS_ARCH "sparc"
#define R_SYS_BITS R_SYS_BITS_32
#define R_SYS_ENDIAN 1
#elif __mips__
#define R_SYS_ARCH "mips"
#define R_SYS_BITS R_SYS_BITS_32
#define R_SYS_ENDIAN 1
#elif __loongarch__
#define R_SYS_ARCH "loongarch"
#define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_ENDIAN 1
#elif __EMSCRIPTEN__
/* we should default to wasm when ready */
#define R_SYS_ARCH "x86"
#define R_SYS_BITS R_SYS_BITS_32
#elif __riscv__ || __riscv
# define R_SYS_ARCH "riscv"
# define R_SYS_ENDIAN 0
# if __riscv_xlen == 32
#  define R_SYS_BITS R_SYS_BITS_32
# else
#  define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
# endif
#else
#ifdef _MSC_VER
#if defined(_M_ARM64)
#define R_SYS_ARCH "arm"
#define R_SYS_BITS R_SYS_BITS_64
#define R_SYS_ENDIAN 0
#elif defined(_WIN64)
#define R_SYS_ARCH "x86"
#define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_ENDIAN 0
#define __x86_64__ 1
#else
#define R_SYS_ARCH "x86"
#define R_SYS_BITS (R_SYS_BITS_32)
#define __i386__ 1
#define R_SYS_ENDIAN 0
#endif
#else
#define R_SYS_ARCH "unknown"
#define R_SYS_BITS R_SYS_BITS_32
#define R_SYS_ENDIAN 0
#endif
#endif

#define R_SYS_ENDIAN_NONE 0
#define R_SYS_ENDIAN_LITTLE 1
#define R_SYS_ENDIAN_BIG 2
#define R_SYS_ENDIAN_BI 3

typedef enum {
	R_SYS_ARCH_NONE = 0,
	R_SYS_ARCH_X86,
	R_SYS_ARCH_ARM,
	R_SYS_ARCH_PPC,
	R_SYS_ARCH_M68K,
	R_SYS_ARCH_JAVA,
	R_SYS_ARCH_MIPS,
	R_SYS_ARCH_SPARC,
	R_SYS_ARCH_XAP,
	R_SYS_ARCH_MSIL,
	R_SYS_ARCH_OBJD,
	R_SYS_ARCH_BF,
	R_SYS_ARCH_SH,
	R_SYS_ARCH_AVR,
	R_SYS_ARCH_DALVIK,
	R_SYS_ARCH_Z80,
	R_SYS_ARCH_ARC,
	R_SYS_ARCH_I8080,
	R_SYS_ARCH_RAR,
	R_SYS_ARCH_8051,
	R_SYS_ARCH_TMS320,
	R_SYS_ARCH_EBC,
	R_SYS_ARCH_H8300,
	R_SYS_ARCH_CR16,
	R_SYS_ARCH_V850,
	R_SYS_ARCH_S390,
	R_SYS_ARCH_XCORE,
	R_SYS_ARCH_PROPELLER,
	R_SYS_ARCH_MSP430,
	R_SYS_ARCH_CRIS,
	R_SYS_ARCH_HPPA,
	R_SYS_ARCH_V810,
	R_SYS_ARCH_LM32,
	R_SYS_ARCH_RISCV,
	R_SYS_ARCH_ESIL,
	R_SYS_ARCH_BPF,
} RSysArch;

#define MONOTONIC_LINUX (__linux__ && _POSIX_C_SOURCE >= 199309L)
#define MONOTONIC_FREEBSD (__FreeBSD__ && __FreeBSD_version >= 1101000)
#define MONOTONIC_NETBSD (__NetBSD__ && __NetBSD_Version__ >= 700000000)
#define MONOTONIC_APPLE (__APPLE__ && CLOCK_MONOTONIC_RAW)
#define MONOTONIC_UNIX (MONOTONIC_APPLE || MONOTONIC_LINUX || MONOTONIC_FREEBSD || MONOTONIC_NETBSD)


#define HAS_CLOCK_NANOSLEEP 0
#if defined(__wasi__) || defined(_AIX)
# define HAS_CLOCK_MONOTONIC 0
#elif CLOCK_MONOTONIC && MONOTONIC_UNIX
# define HAS_CLOCK_MONOTONIC 1
# if HAVE_CLOCK_NANOSLEEP
#  undef HAS_CLOCK_NANOSLEEP
#  define HAS_CLOCK_NANOSLEEP 1
# endif
#else
# define HAS_CLOCK_MONOTONIC 0
#endif

/* os */
#if defined (__QNX__)
#define R_SYS_OS "qnx"
//#elif TARGET_OS_IPHONE
//#define R_SYS_OS "ios"
#elif defined (__wasi__)
#define R_SYS_OS "wasi"
#elif defined (__APPLE__)
#define R_SYS_OS "darwin"
#elif defined (__linux__)
#define R_SYS_OS "linux"
#elif defined (R2__WINDOWS__)
#define R_SYS_OS "windows"
#elif defined (__NetBSD__ )
#define R_SYS_OS "netbsd"
#elif defined (__OpenBSD__)
#define R_SYS_OS "openbsd"
#elif defined (__FreeBSD__) || defined (__FreeBSD_kernel__)
#define R_SYS_OS "freebsd"
#elif defined (__HAIKU__)
#define R_SYS_OS "haiku"
#elif defined (_AIX)
#define R_SYS_OS "aix"
#else
#define R_SYS_OS "unknown"
#endif

#ifdef __cplusplus
}
#endif

static inline void r_run_call1(void *fcn, void *arg1) {
	((void (*)(void *))(fcn))(arg1);
}

static inline void r_run_call2(void *fcn, void *arg1, void *arg2) {
	((void (*)(void *, void *))(fcn))(arg1, arg2);
}

static inline void r_run_call3(void *fcn, void *arg1, void *arg2, void *arg3) {
	((void (*)(void *, void *, void *))(fcn))(arg1, arg2, arg3);
}

static inline void r_run_call4(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4) {
	((void (*)(void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4);
}

static inline void r_run_call5(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5) {
	((void (*)(void *, void *, void *, void *, void *))(fcn))(arg1, arg2, arg3, arg4, arg5);
}

static inline void r_run_call6(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6) {
	((void (*)(void *, void *, void *, void *, void *, void *))(fcn))
		(arg1, arg2, arg3, arg4, arg5, arg6);
}

static inline void r_run_call7(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *))(fcn))
		(arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}

static inline void r_run_call8(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7, void *arg8) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *, void *))(fcn))
		(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}

static inline void r_run_call9(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7, void *arg8, void *arg9) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *, void *, void *))(fcn))
		(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9);
}

static inline void r_run_call10(void *fcn, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5,
	void *arg6, void *arg7, void *arg8, void *arg9, void *arg10) {
	((void (*)(void *, void *, void *, void *, void *, void *, void *, void *, void *, void *))(fcn))
		(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

#ifndef container_of
#define container_of(ptr, type, member) (ptr? ((type *)((char *)(ptr) - r_offsetof(type, member))): NULL)
#endif

#endif // R2_TYPES_H
