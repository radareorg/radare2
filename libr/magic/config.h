/*
 * Hand-made config.h file for OpenBSD, so we don't have to run
 * the dratted configure script every time we build this puppy,
 * but can still carefully import stuff from Christos' version.
 *
 * This file is in the public domain. Original Author Ian F. Darwin.
 * $OpenBSD: config.h,v 1.7 2011/07/25 16:21:22 martynas Exp $
 */

/* header file issues. */
#define HAVE_UNISTD_H 1
#define HAVE_FCNTL_H 1
#define HAVE_LOCALE_H 1
#define HAVE_SYS_STAT_H 1
#define	HAVE_INTTYPES_H 1
#define HAVE_GETOPT_H 1
#define HAVE_LIMITS_H 1

// fail on w32?
#define HAVE_UNISTD_H 1
#define HAVE_WCHAR_H 1

// TODO: add dependency for zlib?
/* #define	HAVE_ZLIB_H	1	DO NOT ENABLE YET -- chl */
/* #define	HAVE_LIBZ	1	DO NOT ENABLE YET -- ian */

#define HAVE_VSNPRINTF
#define HAVE_SNPRINTF
#define HAVE_STRTOF

/* Compiler issues */
#define SIZEOF_LONG_LONG sizeof (long long)

/* Library issues */
#define HAVE_GETOPT_LONG 0	/* in-tree as of 3.2 */
#define HAVE_ST_RDEV 1

/* ELF support */
#define BUILTIN_ELF 0
#define ELFCORE 0
