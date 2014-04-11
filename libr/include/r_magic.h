/* radare - LGPL - Copyright 2011-2014 - pancake */

#ifndef R2_MAGIC_H
#define R2_MAGIC_H

#include <r_types.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_magic);

#ifndef MAGICFILE
#define MAGICFILE "/etc/magic"
#endif

#define R_MAGIC_PATH R2_LIBDIR "/radare2/" R2_VERSION "/magic"

#if USE_LIB_MAGIC

#include <magic.h>

#ifdef R_API
#define RMagic struct magic_set

#define r_magic_new(x)              magic_open(x)
#define r_magic_free(x)             { if (x) { magic_close(x); }}
#define r_magic_file(x,y)           magic_file(x,y)
#define r_magic_buffer(x,y,z)       magic_buffer(x,y,z)
#define r_magic_descriptor(x,y)     magic_descriptor(x,y)
#define r_magic_error(x)            magic_error(x)
#define r_magic_setflags(x,y)       magic_setflags(x,y)
#define r_magic_load(x,y)           magic_load(x,y)
#define r_magic_compile(x,y)        magic_compile(x,y)
#define r_magic_check(x,y)          magic_check(x,y)
#define r_magic_errno(x)            magic_errno(x)
#endif

#else
#ifdef R_API

#ifdef __EMX__
#define PATHSEP	';'
#else
#define PATHSEP	':'
#endif

/* limits */
#ifndef HOWMANY
# define HOWMANY    (256 * 1024)    /* how much of the file to look at */
#endif
#define MAXDESC     64
#define MAXMAGIS    8192            /* max entries in any one magic file or directory */
#define MAXstring   32              /* max leng of "string" types */

/* define this outside to fix build for g++ */
union VALUETYPE {
	ut8 b;
	ut16 h;
	ut32 l;
	ut64 q;
	ut8 hs[2];	/* 2 bytes of a fixed-endian "short" */
	ut8 hl[4];	/* 4 bytes of a fixed-endian "long" */
	ut8 hq[8];	/* 8 bytes of a fixed-endian "quad" */
	char s[MAXstring];	/* the search string or regex pattern */
	float f;
	double d;
};		/* either number or string */

/* constants */
#define MAGICNO         0xF11E041C
#define VERSIONNO       5
#define FILE_MAGICSIZE  (32 * 6)

#define	FILE_LOAD       0
#define FILE_CHECK      1
#define FILE_COMPILE    2

struct r_magic {
	/* Word 1 */
	ut16 cont_level;	/* level of ">" */
	ut8 flag;

#define INDIR           0x01 /* if '(...)' appears */
#define OFFADD          0x02 /* if '>&' or '>...(&' appears */
#define INDIROFFADD     0x04 /* if '>&(' appears */
#define UNSIGNED        0x08 /* comparison is unsigned */
#define NOSPACE         0x10 /* suppress space character before output */
#define BINTEST         0x20 /* test is for a binary type (set only
                                for top-level tests) */
#define TEXTTEST        0    /* for passing to file_softmagic */

	ut8 dummy1;

	/* Word 2 */
	ut8 reln;		/* relation (0=eq, '>'=gt, etc) */
	ut8 vallen;		/* length of string value, if any */
	ut8 type;		/* comparison type (FILE_*) */
	ut8 in_type;	/* type of indirection */
#define FILE_INVALID        0
#define FILE_BYTE           1
#define FILE_SHORT          2
#define FILE_DEFAULT        3
#define FILE_LONG           4
#define FILE_STRING         5
#define FILE_DATE           6
#define FILE_BESHORT        7
#define FILE_BELONG         8
#define FILE_BEDATE         9
#define FILE_LESHORT        10
#define FILE_LELONG         11
#define FILE_LEDATE         12
#define FILE_PSTRING        13
#define FILE_LDATE          14
#define FILE_BELDATE        15
#define FILE_LELDATE        16
#define FILE_REGEX          17
#define FILE_BESTRING16     18
#define FILE_LESTRING16     19
#define FILE_SEARCH         20
#define FILE_MEDATE         21
#define FILE_MELDATE        22
#define FILE_MELONG         23
#define FILE_QUAD           24
#define FILE_LEQUAD         25
#define FILE_BEQUAD         26
#define FILE_QDATE          27
#define FILE_LEQDATE        28
#define FILE_BEQDATE        29
#define FILE_QLDATE         30
#define FILE_LEQLDATE       31
#define FILE_BEQLDATE       32
#define FILE_FLOAT          33
#define FILE_BEFLOAT        34
#define FILE_LEFLOAT        35
#define FILE_DOUBLE         36
#define FILE_BEDOUBLE       37
#define FILE_LEDOUBLE       38
#define FILE_NAMES_SIZE     39	/* size of array to contain all names */

#define MAGIC_IS_STRING(t) \
	((t) == FILE_STRING || \
	 (t) == FILE_PSTRING || \
	 (t) == FILE_BESTRING16 || \
	 (t) == FILE_LESTRING16 || \
	 (t) == FILE_REGEX || \
	 (t) == FILE_SEARCH || \
	 (t) == FILE_DEFAULT)

#define FILE_FMT_NONE       0
#define FILE_FMT_NUM        1 /* "cduxXi" */
#define FILE_FMT_STR        2 /* "s" */
#define FILE_FMT_QUAD       3 /* "ll" */
#define FILE_FMT_FLOAT      4 /* "eEfFgG" */
#define FILE_FMT_DOUBLE     5 /* "eEfFgG" */

	/* Word 3 */
	ut8 in_op;		/* operator for indirection */
	ut8 mask_op;	/* operator for mask */
	ut8 cond;		/* conditional type */
	ut8 dummy2;

#define FILE_OPS            "&|^+-*/%"
#define FILE_OPAND          0
#define FILE_OPOR           1
#define FILE_OPXOR          2
#define FILE_OPADD          3
#define FILE_OPMINUS        4
#define FILE_OPMULTIPLY     5
#define FILE_OPDIVIDE       6
#define FILE_OPMODULO       7
#define FILE_OPS_MASK       0x07 /* mask for above ops */
#define FILE_UNUSED_1       0x08
#define FILE_UNUSED_2       0x10
#define FILE_UNUSED_3       0x20
#define FILE_OPINVERSE      0x40
#define FILE_OPINDIRECT     0x80

#define COND_NONE   0
#define COND_IF     1
#define COND_ELIF   2
#define COND_ELSE   3

	/* Word 4 */
	ut32 offset;	/* offset to magic number */
	/* Word 5 */
	ut32 in_offset;	/* offset from indirection */
	/* Word 6 */
	ut32 lineno;	/* line number in magic file */
	/* Word 7,8 */
	union {
		ut64 _mask;	/* for use with numeric and date types */
		struct {
			ut32 _count;	/* repeat/line count */
			ut32 _flags;	/* modifier flags */
		} _s;		/* for use with string types */
	} _u;

#define num_mask _u._mask
#define str_range _u._s._count
#define str_flags _u._s._flags

	/* Words 9-16 */
	union VALUETYPE value;
	/* Words 17..31 */
	char desc[MAXDESC];	/* description */
	/* Words 32..47 */
	char mimetype[MAXDESC]; /* MIME type */
};

#define BIT(A)                          (1 << (A))
#define STRING_COMPACT_BLANK            BIT(0)
#define STRING_COMPACT_OPTIONAL_BLANK   BIT(1)
#define STRING_IGNORE_LOWERCASE         BIT(2)
#define STRING_IGNORE_UPPERCASE         BIT(3)
#define REGEX_OFFSET_START              BIT(4)
#define CHAR_COMPACT_BLANK              'B'
#define CHAR_COMPACT_OPTIONAL_BLANK     'b'
#define CHAR_IGNORE_LOWERCASE           'c'
#define CHAR_IGNORE_UPPERCASE           'C'
#define CHAR_REGEX_OFFSET_START         's'
#define STRING_IGNORE_CASE              (STRING_IGNORE_LOWERCASE|STRING_IGNORE_UPPERCASE)
#define STRING_DEFAULT_RANGE            100

/* list of magic entries */
struct mlist {
	struct r_magic *magic;		/* array of magic entries */
	ut32 nmagic;			/* number of entries in array */
	int mapped;  /* allocation type: 0 => apprentice_file
		      *                  1 => apprentice_map + malloc
		      *                  2 => apprentice_map + mmap */
	struct mlist *next, *prev;
};

#define R_MAGIC_NONE                0x000000 /* No flags */
#define R_MAGIC_DEBUG               0x000001 /* Turn on debugging */
#define R_MAGIC_SYMLINK             0x000002 /* Follow symlinks */
#define R_MAGIC_COMPRESS            0x000004 /* Check inside compressed files */
#define R_MAGIC_DEVICES             0x000008 /* Look at the contents of devices */
#define R_MAGIC_MIME_TYPE           0x000010 /* Return only the MIME type */
#define R_MAGIC_CONTINUE            0x000020 /* Return all matches */
#define R_MAGIC_CHECK               0x000040 /* Print warnings to stderr */
#define R_MAGIC_PRESERVE_ATIME      0x000080 /* Restore access time on exit */
#define R_MAGIC_RAW                 0x000100 /* Don't translate unprint chars */
#define R_MAGIC_ERROR               0x000200 /* Handle ENOENT etc as real errors */
#define R_MAGIC_MIME_ENCODING       0x000400 /* Return only the MIME encoding */
#define R_MAGIC_MIME                (R_MAGIC_MIME_TYPE|R_MAGIC_MIME_ENCODING)
#define R_MAGIC_NO_CHECK_COMPRESS   0x001000 /* Don't check for compressed files */
#define R_MAGIC_NO_CHECK_TAR        0x002000 /* Don't check for tar files */
#define R_MAGIC_NO_CHECK_SOFT       0x004000 /* Don't check magic entries */
#define R_MAGIC_NO_CHECK_APPTYPE    0x008000 /* Don't check application type */
#define R_MAGIC_NO_CHECK_ELF        0x010000 /* Don't check for elf details */
#define R_MAGIC_NO_CHECK_ASCII      0x020000 /* Don't check for ascii files */
#define R_MAGIC_NO_CHECK_TOKENS     0x100000 /* Don't check ascii/tokens */

/* Defined for backwards compatibility; do nothing */
#define MAGIC_NO_CHECK_FORTRAN      0x000000 /* Don't check ascii/fortran */
#define MAGIC_NO_CHECK_TROFF        0x000000 /* Don't check ascii/troff */

struct r_magic_set {
	struct mlist *mlist;
	struct cont {
		size_t len;
		struct level_info {
			st32 off;
			int got_match;
			int last_match;
			int last_cond;	/* used for error checking by parse() */
		} *li;
	} c;
	struct out {
		char *buf;		/* Accumulation buffer */
		char *pbuf;		/* Printable buffer */
	} o;
	ut32 offset;
	int error;
	int flags;
	int haderr;
	const char *file;
	size_t line;			/* current magic line number */

	/* data for searches */
	struct {
		const char *s;		/* start of search in original source */
		size_t s_len;		/* length of search region */
		size_t offset;		/* starting offset in source: XXX - should this be off_t? */
		size_t rm_len;		/* match length */
	} search;

	/* FIXME: Make the string dynamically allocated so that e.g.
	   strings matched in files can be longer than MAXstring */
	union VALUETYPE ms_value;	/* either number or string */
};

typedef struct r_magic_set RMagic;

#ifdef R_API
R_API RMagic* r_magic_new(int flags);
R_API void r_magic_free(RMagic*);

R_API const char *r_magic_file(RMagic*, const char *);
R_API const char *r_magic_descriptor(RMagic*, int);
R_API const char *r_magic_buffer(RMagic*, const void *, size_t);

R_API const char *r_magic_error(RMagic*);
R_API void r_magic_setflags(RMagic*, int);

R_API int r_magic_load(RMagic*, const char *);
R_API int r_magic_compile(RMagic*, const char *);
R_API int r_magic_check(RMagic*, const char *);
R_API int r_magic_errno(RMagic*);
#endif


#endif
#endif // USE_LIB_MAGIC

#ifdef __cplusplus
}
#endif

#endif /* _MAGIC_H */
