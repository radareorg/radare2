/* include/jemalloc/internal/jemalloc_internal_defs.h.  Generated from jemalloc_internal_defs.h.in by configure.  */
#ifndef JEMALLOC_INTERNAL_DEFS_H_
#define	JEMALLOC_INTERNAL_DEFS_H_
/*
 * If JEMALLOC_PREFIX is defined via --with-jemalloc-prefix, it will cause all
 * public APIs to be prefixed.  This makes it possible, with some care, to use
 * multiple allocators simultaneously.
 */
/* #undef JEMALLOC_PREFIX */
/* #undef JEMALLOC_CPREFIX */

/*
 * JEMALLOC_PRIVATE_NAMESPACE is used as a prefix for all library-private APIs.
 * For shared libraries, symbol visibility mechanisms prevent these symbols
 * from being exported, but for static libraries, naming collisions are a real
 * possibility.
 */
#define JEMALLOC_PRIVATE_NAMESPACE je_

/*
 * Hyper-threaded CPUs may need a special instruction inside spin loops in
 * order to yield to another virtual CPU.
 */
#define CPU_SPINWAIT __asm__ volatile("pause")

/* Defined if C11 atomics are available. */
#define JEMALLOC_C11ATOMICS 1

/* Defined if the equivalent of FreeBSD's atomic(9) functions are available. */
/* #undef JEMALLOC_ATOMIC9 */

/*
 * Defined if OSAtomic*() functions are available, as provided by Darwin, and
 * documented in the atomic(3) manual page.
 */
/* #undef JEMALLOC_OSATOMIC */

/*
 * Defined if __sync_add_and_fetch(uint32_t *, uint32_t) and
 * __sync_sub_and_fetch(uint32_t *, uint32_t) are available, despite
 * __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4 not being defined (which means the
 * functions are defined in libgcc instead of being inlines).
 */
/* #undef JE_FORCE_SYNC_COMPARE_AND_SWAP_4 */

/*
 * Defined if __sync_add_and_fetch(uint64_t *, uint64_t) and
 * __sync_sub_and_fetch(uint64_t *, uint64_t) are available, despite
 * __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8 not being defined (which means the
 * functions are defined in libgcc instead of being inlines).
 */
/* #undef JE_FORCE_SYNC_COMPARE_AND_SWAP_8 */

/*
 * Defined if __builtin_clz() and __builtin_clzl() are available.
 */
#define JEMALLOC_HAVE_BUILTIN_CLZ

/*
 * Defined if os_unfair_lock_*() functions are available, as provided by Darwin.
 */
/* #undef JEMALLOC_OS_UNFAIR_LOCK */

/*
 * Defined if OSSpin*() functions are available, as provided by Darwin, and
 * documented in the spinlock(3) manual page.
 */
/* #undef JEMALLOC_OSSPIN */

/* Defined if syscall(2) is usable. */
#define JEMALLOC_USE_SYSCALL

/*
 * Defined if secure_getenv(3) is available.
 */
#define JEMALLOC_HAVE_SECURE_GETENV

/*
 * Defined if issetugid(2) is available.
 */
/* #undef JEMALLOC_HAVE_ISSETUGID */

/* Defined if pthread_atfork(3) is available. */
#define JEMALLOC_HAVE_PTHREAD_ATFORK

/*
 * Defined if clock_gettime(CLOCK_MONOTONIC_COARSE, ...) is available.
 */
#define JEMALLOC_HAVE_CLOCK_MONOTONIC_COARSE 1

/*
 * Defined if clock_gettime(CLOCK_MONOTONIC, ...) is available.
 */
#define JEMALLOC_HAVE_CLOCK_MONOTONIC 1

/*
 * Defined if mach_absolute_time() is available.
 */
/* #undef JEMALLOC_HAVE_MACH_ABSOLUTE_TIME */

/*
 * Defined if _malloc_thread_cleanup() exists.  At least in the case of
 * FreeBSD, pthread_key_create() allocates, which if used during malloc
 * bootstrapping will cause recursion into the pthreads library.  Therefore, if
 * _malloc_thread_cleanup() exists, use it as the basis for thread cleanup in
 * malloc_tsd.
 */
/* #undef JEMALLOC_MALLOC_THREAD_CLEANUP */

/*
 * Defined if threaded initialization is known to be safe on this platform.
 * Among other things, it must be possible to initialize a mutex without
 * triggering allocation in order for threaded allocation to be safe.
 */
#define JEMALLOC_THREADED_INIT

/*
 * Defined if the pthreads implementation defines
 * _pthread_mutex_init_calloc_cb(), in which case the function is used in order
 * to avoid recursive allocation during mutex initialization.
 */
/* #undef JEMALLOC_MUTEX_INIT_CB */

/* Non-empty if the tls_model attribute is supported. */
#define JEMALLOC_TLS_MODEL __attribute__((tls_model("initial-exec")))

/* JEMALLOC_CC_SILENCE enables code that silences unuseful compiler warnings. */
#define JEMALLOC_CC_SILENCE

/* JEMALLOC_CODE_COVERAGE enables test code coverage analysis. */
/* #undef JEMALLOC_CODE_COVERAGE */

/*
 * JEMALLOC_DEBUG enables assertions and other sanity checks, and disables
 * inline functions.
 */
/* #undef JEMALLOC_DEBUG */

/* JEMALLOC_STATS enables statistics calculation. */
#define JEMALLOC_STATS

/* JEMALLOC_PROF enables allocation profiling. */
/* #undef JEMALLOC_PROF */

/* Use libunwind for profile backtracing if defined. */
/* #undef JEMALLOC_PROF_LIBUNWIND */

/* Use libgcc for profile backtracing if defined. */
/* #undef JEMALLOC_PROF_LIBGCC */

/* Use gcc intrinsics for profile backtracing if defined. */
/* #undef JEMALLOC_PROF_GCC */

/*
 * JEMALLOC_TCACHE enables a thread-specific caching layer for small objects.
 * This makes it possible to allocate/deallocate objects without any locking
 * when the cache is in the steady state.
 */
#define JEMALLOC_TCACHE

/*
 * JEMALLOC_DSS enables use of sbrk(2) to allocate chunks from the data storage
 * segment (DSS).
 */
#define JEMALLOC_DSS

/* Support memory filling (junk/zero/quarantine/redzone). */
#define JEMALLOC_FILL

/* Support utrace(2)-based tracing. */
/* #undef JEMALLOC_UTRACE */

/* Support Valgrind. */
/* #undef JEMALLOC_VALGRIND */

/* Support optional abort() on OOM. */
/* #undef JEMALLOC_XMALLOC */

/* Support lazy locking (avoid locking unless a second thread is launched). */
/* #undef JEMALLOC_LAZY_LOCK */

/* Minimum size class to support is 2^LG_TINY_MIN bytes. */
#define LG_TINY_MIN 3

/*
 * Minimum allocation alignment is 2^LG_QUANTUM bytes (ignoring tiny size
 * classes).
 */
/* #undef LG_QUANTUM */

/* One page is 2^LG_PAGE bytes. */
#define LG_PAGE 12

/*
 * If defined, adjacent virtual memory mappings with identical attributes
 * automatically coalesce, and they fragment when changes are made to subranges.
 * This is the normal order of things for mmap()/munmap(), but on Windows
 * VirtualAlloc()/VirtualFree() operations must be precisely matched, i.e.
 * mappings do *not* coalesce/fragment.
 */
#define JEMALLOC_MAPS_COALESCE

/*
 * If defined, use munmap() to unmap freed chunks, rather than storing them for
 * later reuse.  This is disabled by default on Linux because common sequences
 * of mmap()/munmap() calls will cause virtual memory map holes.
 */
/* #undef JEMALLOC_MUNMAP */

/* TLS is used to map arenas and magazine caches to threads. */
#ifndef _WIN32
#define JEMALLOC_TLS
#endif

/*
 * Used to mark unreachable code to quiet "end of non-void" compiler warnings.
 * Don't use this directly; instead use unreachable() from util.h
 */
#define JEMALLOC_INTERNAL_UNREACHABLE __builtin_unreachable

/*
 * ffs*() functions to use for bitmapping.  Don't use these directly; instead,
 * use ffs_*() from util.h.
 */
#define JEMALLOC_INTERNAL_FFSLL __builtin_ffsll
#define JEMALLOC_INTERNAL_FFSL __builtin_ffsl
#define JEMALLOC_INTERNAL_FFS __builtin_ffs

/*
 * JEMALLOC_IVSALLOC enables ivsalloc(), which verifies that pointers reside
 * within jemalloc-owned chunks before dereferencing them.
 */
/* #undef JEMALLOC_IVSALLOC */

/*
 * If defined, explicitly attempt to more uniformly distribute large allocation
 * pointer alignments across all cache indices.
 */
#define JEMALLOC_CACHE_OBLIVIOUS

/*
 * Darwin (OS X) uses zones to work around Mach-O symbol override shortcomings.
 */
/* #undef JEMALLOC_ZONE */

/*
 * Methods for determining whether the OS overcommits.
 * JEMALLOC_PROC_SYS_VM_OVERCOMMIT_MEMORY: Linux's
 *                                         /proc/sys/vm.overcommit_memory file.
 * JEMALLOC_SYSCTL_VM_OVERCOMMIT: FreeBSD's vm.overcommit sysctl.
 */
/* #undef JEMALLOC_SYSCTL_VM_OVERCOMMIT */
#define JEMALLOC_PROC_SYS_VM_OVERCOMMIT_MEMORY

/* Defined if madvise(2) is available. */
#define JEMALLOC_HAVE_MADVISE

/*
 * Defined if transparent huge pages are supported via the MADV_[NO]HUGEPAGE
 * arguments to madvise(2).
 */
#define JEMALLOC_HAVE_MADVISE_HUGE

/*
 * Methods for purging unused pages differ between operating systems.
 *
 *   madvise(..., MADV_FREE) : This marks pages as being unused, such that they
 *                             will be discarded rather than swapped out.
 *   madvise(..., MADV_DONTNEED) : This immediately discards pages, such that
 *                                 new pages will be demand-zeroed if the
 *                                 address region is later touched.
 */
/* #undef JEMALLOC_PURGE_MADVISE_FREE */
#define JEMALLOC_PURGE_MADVISE_DONTNEED

/* Defined if transparent huge page support is enabled. */
#define JEMALLOC_THP

/* Define if operating system has alloca.h header. */
#define JEMALLOC_HAS_ALLOCA_H 1

/* C99 restrict keyword supported. */
#define JEMALLOC_HAS_RESTRICT 1

/* For use by hash code. */
/* #undef JEMALLOC_BIG_ENDIAN */

/* sizeof (int) == 2^LG_SIZEOF_INT. */
#define LG_SIZEOF_INT 2

/* sizeof (long) == 2^LG_SIZEOF_LONG. */
#define LG_SIZEOF_LONG 3

/* sizeof (long long) == 2^LG_SIZEOF_LONG_LONG. */
#define LG_SIZEOF_LONG_LONG 3

/* sizeof (intmax_t) == 2^LG_SIZEOF_INTMAX_T. */
#define LG_SIZEOF_INTMAX_T 3

/* glibc malloc hooks (__malloc_hook, __realloc_hook, __free_hook). */
#define JEMALLOC_GLIBC_MALLOC_HOOK

/* glibc memalign hook. */
#define JEMALLOC_GLIBC_MEMALIGN_HOOK

/* Adaptive mutex support in pthreads. */
#define JEMALLOC_HAVE_PTHREAD_MUTEX_ADAPTIVE_NP

/*
 * If defined, jemalloc symbols are not exported (doesn't work when
 * JEMALLOC_PREFIX is not defined).
 */
/* #undef JEMALLOC_EXPORT */

/* config.malloc_conf options string. */
#define JEMALLOC_CONFIG_MALLOC_CONF ""

#endif /* JEMALLOC_INTERNAL_DEFS_H_ */
