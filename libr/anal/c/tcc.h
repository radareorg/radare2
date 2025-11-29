/* LGPLv2 - Tiny C Compiler - 2001-2004 fbellard, 2009-2024 pancake */

#ifndef _TCC_H
#define _TCC_H

#include <r_types.h>
#include <r_util/r_str.h>
#include <r_th.h>
#include <r_vec.h>
#include "tcc_config.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#ifndef __wasi__
#include <setjmp.h>
#endif
#include <time.h>

#ifdef CONFIG_TCCASSERT
#include <assert.h>
#define TCC_ASSERT(ex) assert(ex)
#else
#define TCC_ASSERT(ex)
#endif

#ifndef R2__WINDOWS__
# include <unistd.h>
# include <sys/time.h>
# ifndef __HAIKU__
# endif
# include <sys/mman.h>
#else
# include <windows.h>
# include <sys/timeb.h>
# include <io.h> /* open, close etc. */
# include <direct.h> /* getcwd */
# ifdef __GNUC__
#  include <stdint.h>
# else
typedef UINT_PTR uintptr_t;
# endif
# define inline __inline
# define inp next_inp
#endif

#ifndef O_BINARY
# define O_BINARY 0
#endif

#include "libtcc.h"
#include <inttypes.h>

// TODO: Make it dependable from the r2 asm/anal settings
#define LDOUBLE_SIZE 12
#define LDOUBLE_ALIGN 4
#define MAX_ALIGN 8
#define PTR_SIZE 4

#define ST_FUNC static
#define ST_DATA static

// TODO: Read this from the configuration variables in r2

#define STACK_NEW0(type, arg) \
	type arg; \
	ZERO_FILL(arg)

#define INCLUDE_STACK_SIZE  32
#define IFDEF_STACK_SIZE    64
#define VSTACK_SIZE         1024
#define STRING_MAX_SIZE     1024
#define PACK_STACK_SIZE     8

#define TOK_HASH_SIZE       8192 /* must be a power of two */
#define TOK_ALLOC_INCR      512  /* must be a power of two */
#define TOK_MAX_SIZE        4 /* token max size in int unit when stored in string */

/* token symbol management */
typedef struct TokenSym {
	struct TokenSym *hash_next;
	struct Sym *sym_define; /* direct pointer to define */
	struct Sym *sym_label; /* direct pointer to label */
	struct Sym *sym_struct; /* direct pointer to structure */
	struct Sym *sym_identifier; /* direct pointer to identifier */
	int tok; /* token number */
	int len;
	char str[1];
} TokenSym;

typedef int nwchar_t;

typedef struct CString {
	int size; /* size in bytes */
	char *data; /* either 'char *' or 'nwchar_t *' */
	int size_allocated;
	char *data_allocated; /* if non NULL, data has been malloced */
} CString;

R_VEC_FORWARD_DECLARE (RVecCharPtr);

/* type definition */
typedef struct CType {
	int t;
	struct Sym *ref;
} CType;

/* constant value */
typedef union CValue {
	long double ld;
	double d;
	float f;
	int i;
	unsigned int ui; // endian issues because we use 32bit with 64bit mixed types instead of casting
	unsigned int ul; /* address (should be unsigned long on 64 bit cpu) */
	long long ll;
	unsigned long long ull;
	struct CString *cstr;
	void *ptr;
	int tab[LDOUBLE_SIZE/4];
} CValue;

/* value on stack */
typedef struct SValue {
	CType type;      /* type */
	unsigned short r;      /* register + flags */
	unsigned short r2;     /* second register, used for 'long long'
				  type. If not used, set to VT_CONST */
	CValue c;              /* constant, if VT_CONST */
	struct Sym *sym;       /* symbol, if (VT_SYM | VT_CONST) */
} SValue;

/* symbol management */
typedef struct Sym {
	int v;    /* symbol token */
	char *asm_label;    /* associated asm label */
	unsigned int r;    /* associated register */
	union {
		long long c;    /* associated number */
		int *d;   /* define token stream */
	};
	CType type;    /* associated type */
	union {
		struct Sym *next; /* next related symbol */
		long jnext; /* next jump label */
	};
	struct Sym *prev; /* prev symbol in stack */
	struct Sym *prev_tok; /* previous symbol for this token */
} Sym;

/* GNUC attribute definition */
typedef struct AttributeDef {
	unsigned int
		func_call     : 3, /* calling convention (0..5), see below */
			      aligned       : 5, /* alignement (0..16) */
			      packed        : 1,
			      func_export   : 1,
			      func_import   : 1,
			      func_args     : 5,
			      mode          : 4,
			      weak          : 1,
			      fill          : 11;
	int alias_target;    /* token */
} AttributeDef;

/* gr: wrappers for casting sym->r for other purposes */
#define FUNC_CALL(r) (((AttributeDef*)&(r))->func_call)
#define FUNC_EXPORT(r) (((AttributeDef*)&(r))->func_export)
#define FUNC_IMPORT(r) (((AttributeDef*)&(r))->func_import)
#define FUNC_ARGS(r) (((AttributeDef*)&(r))->func_args)
#define FUNC_ALIGN(r) (((AttributeDef*)&(r))->aligned)
#define FUNC_PACKED(r) (((AttributeDef*)&(r))->packed)
#define ATTR_MODE(r)  (((AttributeDef*)&(r))->mode)
#define INT_ATTR(ad) (*(int*)(ad))

/* -------------------------------------------------- */

#define SYM_STRUCT     0x40000000 /* struct/union/enum symbol space */
#define SYM_FIELD      0x20000000 /* struct/union field symbol space */
#define SYM_FIRST_ANOM 0x10000000 /* first anonymous sym */

#define VLA_SP_LOC_SET     1 /* Location of SP on stack has been allocated */
#define VLA_SP_SAVED       2 /* SP has been saved to slot already */
#define VLA_NEED_NEW_FRAME 4 /* Needs new frame for next VLA */
#define VLA_IN_SCOPE       8 /* One or more VLAs are in scope */
/* Flags which are saved and restored upon entering and exiting a block */
#define VLA_SCOPE_FLAGS    (VLA_SP_SAVED | VLA_NEED_NEW_FRAME | VLA_IN_SCOPE)

/* stored in 'Sym.c' field */
#define FUNC_NEW       1 /* ansi function prototype */
#define FUNC_OLD       2 /* old function prototype */
#define FUNC_ELLIPSIS  3 /* ansi function prototype with ... */

/* stored in 'Sym.r' field */
#define FUNC_CDECL     0 /* standard c call */
#define FUNC_STDCALL   1 /* pascal c call */
#define FUNC_FASTCALL1 2 /* first param in %eax */
#define FUNC_FASTCALL2 3 /* first parameters in %eax, %edx */
#define FUNC_FASTCALL3 4 /* first parameter in %eax, %edx, %ecx */
#define FUNC_FASTCALLW 5 /* first parameter in %ecx, %edx */

/* field 'Sym.t' for macros */
#define MACRO_OBJ      0 /* object like macro */
#define MACRO_FUNC     1 /* function like macro */

/* field 'Sym.r' for C labels */
#define LABEL_DEFINED  0 /* label is defined */
#define LABEL_FORWARD  1 /* label is forward defined */
#define LABEL_DECLARED 2 /* label is declared but never used */

/* type_decl() types */
#define TYPE_ABSTRACT  1 /* type without variable */
#define TYPE_DIRECT    2 /* type with variable */

#define IO_BUF_SIZE 8192

typedef struct BufferedFile {
	uint8_t *buf_ptr;
	uint8_t *buf_end;
	int fd;
	struct BufferedFile *prev;
	int line_num;    /* current line number - here to simplify code */
	int ifndef_macro;  /* #ifndef macro / #endif search */
	int ifndef_macro_saved; /* saved ifndef_macro */
	int *ifdef_stack_ptr; /* ifdef_stack value at the start of the file */
	char filename[1024];    /* filename */
	unsigned char buffer[IO_BUF_SIZE + 1]; /* extra size for CH_EOB char */
} BufferedFile;


#define CH_EOB   '\\'       /* end of buffer or '\0' char in file */
#define CH_EOF   (-1)   /* end of file */

/* parsing state (used to save parser state to reparse part of the
   source several times) */
typedef struct ParseState {
	const int *macro_ptr;
	int line_num;
	int tok;
	CValue tokc;
} ParseState;

/* used to record tokens */
typedef struct TokenString {
	int *str;
	int len;
	int allocated_len;
	int last_line_num;
} TokenString;

/* inline functions */
typedef struct InlineFunc {
	int *token_str;
	Sym *sym;
	char filename[1];
} InlineFunc;

/* include file cache, used to find files faster and also to eliminate
   inclusion if the include file is protected by #ifndef ... #endif */
typedef struct CachedInclude {
	int ifndef_macro;
	int hash_next; /* -1 if none */
	char filename[1]; /* path specified in #include */
} CachedInclude;

#define CACHED_INCLUDES_HASH_SIZE 512

struct TCCState {
	int verbose; /* if > 0, display some information during compilation */

	char *tcc_lib_path; /* CONFIG_TCCDIR or -B option */

	/* output type, see TCC_OUTPUT_XXX */
	int output_type;
	/* output format, see TCC_OUTPUT_FORMAT_xxx */

	/* Target system */
	char *arch;
	int bits;
	char *os;

	/* warning switches */
	int warn_write_strings;
	int warn_unsupported;
	int warn_error;
	int warn_none;
	int warn_implicit_function_declaration;

	/* include paths */
	char **include_paths;
	int nb_include_paths;

	char **sysinclude_paths;
	int nb_sysinclude_paths;

	/* error handling */
	void *error_opaque;
	void (*error_func)(void *opaque, const char *msg);
	bool error_set_jmp_enabled;
#ifndef __wasi__
	jmp_buf error_jmp_buf;
#endif
	int nb_errors;

	/* output file for preprocessing (-E) */
	FILE *ppfp;

	/* for -MD/-MF: collected dependencies for this compilation */
	char **target_deps;
	int nb_target_deps;

	/* compilation */
	BufferedFile *include_stack[INCLUDE_STACK_SIZE];
	BufferedFile **include_stack_ptr;

	int ifdef_stack[IFDEF_STACK_SIZE];
	int *ifdef_stack_ptr;

	/* included files enclosed with #ifndef MACRO */
	int cached_includes_hash[CACHED_INCLUDES_HASH_SIZE];
	CachedInclude **cached_includes;
	int nb_cached_includes;

	/* #pragma pack stack */
	int pack_stack[PACK_STACK_SIZE];
	int *pack_stack_ptr;

	/* inline functions are stored as token lists and compiled last
	   only if referenced */
	struct InlineFunc **inline_fns;
	int nb_inline_fns;

	struct sym_attr *sym_attrs;
	int nb_sym_attrs;
	/* give the correspondance from symtab indexes to dynsym indexes */
	int *symtab_to_dynsym;

	/* tiny assembler state */
	Sym *asm_labels;

	/* used by main and tcc_parse_args only */
	char *deps_outfile; /* option -MF */
	// previously globals
	bool const_wanted;	/* true if constant wanted */
	bool global_expr;	/* true if compound literals must be allocated globally (used during initializers parsing */
	size_t arraysize;

	/* loc : local variable index
         * ind : output code index
         * rsym: return symbol
         * anon_sym: anonymous symbol index
	 */
	int anon_sym; // = SYM_FIRST_ANOM;
	int loc;
	int ch, tok;
	CValue tokc;
	const int *macro_ptr;
	CString tokcstr; /* current parsed string, if any */

	/* display benchmark infos */
	int total_lines;
	int total_bytes;
	int tok_ident;
	TokenSym **table_ident;
	//
	const char *global_type;
	const char *global_symname;

	RVecCharPtr *typedefs;

	// callback for appendf
	void (*cb)(const char *, char **);
	char **cb_user_data;

	char decl_kind[1024];

	// used to store current token information in the preprocessor
	char tok_buf[STRING_MAX_SIZE + 1];
	CString tok_cstr_buf;

	Sym *global_stack;
	Sym *local_stack;
	Sym *define_stack;

	bool nocode_wanted;
	// XXX?
	BufferedFile *file;
	char *funcname;
	int tok_flags;
	int parse_flags;
	void **sym_pools;
	int nb_sym_pools;
	Sym *sym_free_first;
	char *dir_name;

#define SYM_POOL_NB (8192 / sizeof (Sym))
	CType char_pointer_type, func_old_type;
	CType int8_type, int16_type, int32_type, int64_type, size_type;
	SValue vstack[1+/*to make bcheck happy*/ VSTACK_SIZE];
// #define vstack  (s1->__vstack + 1)
	SValue *vtop;
	// more
	int *macro_ptr_allocated;
	const int *unget_saved_macro_ptr;
	int unget_saved_buffer[TOK_MAX_SIZE + 1];
	bool unget_buffer_enabled;
	TokenSym *hash_ident[TOK_HASH_SIZE];
	char token_buf[STRING_MAX_SIZE + 1];
	/* true if isid(c) || isnum(c) || isdot(c) */
	unsigned char isidnum_table[256 - CH_EOF];
};

static const bool gnu_ext = true; // move into tcc_state

/* The current value can be: */
#define VT_VALMASK   0x003f  /* mask for value location, register or: */
#define VT_CONST     0x0030  /* constant in vc (must be first non register value) */
#define VT_LLOCAL    0x0031  /* lvalue, offset on stack */
#define VT_LOCAL     0x0032  /* offset on stack */
#define VT_CMP       0x0033  /* the value is stored in processor flags (in vc) */
#define VT_JMP       0x0034  /* value is the consequence of jmp true (even) */
#define VT_JMPI      0x0035  /* value is the consequence of jmp false (odd) */
#define VT_REF       0x0040  /* value is pointer to structure rather than address */
#define VT_LVAL      0x0100  /* var is an lvalue */
#define VT_SYM       0x0200  /* a symbol value is added */
#define VT_MUSTCAST  0x0400  /* value must be casted to be correct (used for
				char/short stored in integer registers) */
#define VT_MUSTBOUND 0x0800  /* bound checking must be done before
				dereferencing value */
#define VT_BOUNDED   0x8000  /* value is bounded. The address of the
				bounding function call point is in vc */
#define VT_LVAL_BYTE     0x1000  /* lvalue is a byte */
#define VT_LVAL_SHORT    0x2000  /* lvalue is a short */
#define VT_LVAL_UNSIGNED 0x4000  /* lvalue is unsigned */
#define VT_LVAL_TYPE     (VT_LVAL_BYTE | VT_LVAL_SHORT | VT_LVAL_UNSIGNED)

/* types */
#define VT_BTYPE       0x000f  /* mask for basic type */
#define VT_INT32            0  /* int32_t integer type */
#define VT_INT16            1  /* int16_t short type */
#define VT_INT8             2  /* int8_t signed byte type */
#define VT_VOID             3  /* void type */
#define VT_PTR              4  /* pointer */
#define VT_ENUM             5  /* enum definition */
#define VT_FUNC             6  /* function type */
#define VT_STRUCT           7  /* struct definition */
#define VT_UNION            8  /* union definition */
#define VT_FLOAT            9  /* IEEE float */
#define VT_DOUBLE          10  /* IEEE double */
#define VT_LDOUBLE         11  /* IEEE long double */
#define VT_BOOL            12  /* ISOC99 boolean type */
#define VT_INT64	   13  /* int64_t */
#define VT_LONG            14  /* long integer (NEVER USED as type, only
				  during parsing) */
#define VT_QLONG           15  /* 128-bit integer. Only used for x86-64 ABI */
#define VT_QFLOAT      0x0010  /* 128-bit float. Only used for x86-64 ABI */
#define VT_UNSIGNED    0x0020  /* unsigned type */
#define VT_ARRAY       0x0040  /* array type (also has VT_PTR) */
#define VT_BITFIELD    0x0800  /* bitfield modifier */
#define VT_CONSTANT    0x1000  /* const modifier */
#define VT_VOLATILE    0x2000  /* volatile modifier */
#define VT_SIGNED      0x4000  /* signed type */
#define VT_CHAR	   0x00040000  /* character type - for strings */
#define VT_VLA     0x00080000  /* VLA type (also has VT_PTR and VT_ARRAY) */

/* storage */
#define VT_EXTERN  0x00000080  /* extern definition */
#define VT_STATIC  0x00000100  /* static variable */
#define VT_TYPEDEF 0x00000200  /* typedef definition */
#define VT_INLINE  0x00000400  /* inline definition */
#define VT_IMPORT  0x00008000  /* win32: extern data imported from dll */
#define VT_EXPORT  0x00010000  /* win32: data exported from dll */
#define VT_WEAK    0x00020000  /* weak symbol */

#define VT_STRUCT_SHIFT 18     /* shift for bitfield shift values (max: 32 - 2*6) */

/* type mask (except storage) */
#define VT_STORAGE (VT_EXTERN | VT_STATIC | VT_TYPEDEF | VT_INLINE | VT_IMPORT | VT_EXPORT | VT_WEAK)
#define VT_TYPE (~(VT_STORAGE))

/* token values */

/* warning: the following compare tokens depend on i386 asm code */
#define TOK_ULT 0x92
#define TOK_UGE 0x93
#define TOK_EQ  0x94
#define TOK_NE  0x95
#define TOK_ULE 0x96
#define TOK_UGT 0x97
#define TOK_Nset 0x98
#define TOK_Nclear 0x99
#define TOK_LT  0x9c
#define TOK_GE  0x9d
#define TOK_LE  0x9e
#define TOK_GT  0x9f

#define TOK_LAND  0xa0
#define TOK_LOR   0xa1

#define TOK_DEC   0xa2
#define TOK_MID   0xa3 /* inc/dec, to void constant */
#define TOK_INC   0xa4
#define TOK_UDIV  0xb0 /* unsigned division */
#define TOK_UMOD  0xb1 /* unsigned modulo */
#define TOK_PDIV  0xb2 /* fast division with undefined rounding for pointers */
#define TOK_CINT   0xb3 /* number in tokc */
#define TOK_CCHAR 0xb4 /* char constant in tokc */
#define TOK_STR   0xb5 /* pointer to string in tokc */
#define TOK_TWOSHARPS 0xb6 /* ## preprocessing token */
#define TOK_LCHAR    0xb7
#define TOK_LSTR     0xb8
#define TOK_CFLOAT   0xb9 /* float constant */
#define TOK_LINENUM  0xba /* line number info */
#define TOK_CDOUBLE  0xc0 /* double constant */
#define TOK_CLDOUBLE 0xc1 /* long double constant */
#define TOK_UMULL    0xc2 /* unsigned 32x32 -> 64 mul */
#define TOK_ADDC1    0xc3 /* add with carry generation */
#define TOK_ADDC2    0xc4 /* add with carry use */
#define TOK_SUBC1    0xc5 /* add with carry generation */
#define TOK_SUBC2    0xc6 /* add with carry use */
#define TOK_CUINT    0xc8 /* unsigned int constant */
#define TOK_CLLONG   0xc9 /* long long constant */
#define TOK_CULLONG  0xca /* unsigned long long constant */
#define TOK_ARROW    0xcb
#define TOK_DOTS     0xcc /* three dots */
#define TOK_SHR      0xcd /* unsigned shift right */
#define TOK_PPNUM    0xce /* preprocessor number */
#define TOK_NOSUBST  0xcf /* means following token has already been pp'd */

#define TOK_SHL   0x01 /* shift left */
#define TOK_SAR   0x02 /* signed shift right */

/* assignement operators : normal operator or 0x80 */
#define TOK_A_MOD 0xa5
#define TOK_A_AND 0xa6
#define TOK_A_MUL 0xaa
#define TOK_A_ADD 0xab
#define TOK_A_SUB 0xad
#define TOK_A_DIV 0xaf
#define TOK_A_XOR 0xde
#define TOK_A_OR  0xfc
#define TOK_A_SHL 0x81
#define TOK_A_SAR 0x82

#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
#endif

#ifndef countof
#define countof(tab) (sizeof (tab) / sizeof ((tab)[0]))
#endif

#define TOK_EOF       (-1)  /* end of file */
#define TOK_LINEFEED  10    /* line feed */

/* all identificators and strings have token above that */
#define TOK_IDENT 256

#define DEF_ASM(x) DEF(TOK_ASM_ ## x, #x)
#define TOK_ASM_int TOK_INT
#define TOK_ASM_weak TOK_WEAK1

#if defined TCC_TARGET_I386 || defined TCC_TARGET_X86_64
/* only used for i386 asm opcodes definitions */
#define DEF_BWL(x) \
	DEF(TOK_ASM_ ## x ## b, #x "b") \
	DEF(TOK_ASM_ ## x ## w, #x "w") \
	DEF(TOK_ASM_ ## x ## l, #x "l") \
	DEF(TOK_ASM_ ## x, #x)
#define DEF_WL(x) \
	DEF(TOK_ASM_ ## x ## w, #x "w") \
	DEF(TOK_ASM_ ## x ## l, #x "l") \
	DEF(TOK_ASM_ ## x, #x)
#ifdef TCC_TARGET_X86_64
# define DEF_BWLQ(x) \
	DEF(TOK_ASM_ ## x ## b, #x "b") \
	DEF(TOK_ASM_ ## x ## w, #x "w") \
	DEF(TOK_ASM_ ## x ## l, #x "l") \
	DEF(TOK_ASM_ ## x ## q, #x "q") \
	DEF(TOK_ASM_ ## x, #x)
# define DEF_WLQ(x) \
	DEF(TOK_ASM_ ## x ## w, #x "w") \
	DEF(TOK_ASM_ ## x ## l, #x "l") \
	DEF(TOK_ASM_ ## x ## q, #x "q") \
	DEF(TOK_ASM_ ## x, #x)
# define DEF_BWLX DEF_BWLQ
# define DEF_WLX DEF_WLQ
/* number of sizes + 1 */
# define NBWLX 5
#else
# define DEF_BWLX DEF_BWL
# define DEF_WLX DEF_WL
/* number of sizes + 1 */
# define NBWLX 4
#endif

#define DEF_FP1(x) \
	DEF(TOK_ASM_ ## f ## x ## s, "f" #x "s") \
	DEF(TOK_ASM_ ## fi ## x ## l, "fi" #x "l") \
	DEF(TOK_ASM_ ## f ## x ## l, "f" #x "l") \
	DEF(TOK_ASM_ ## fi ## x ## s, "fi" #x "s")

#define DEF_FP(x) \
	DEF(TOK_ASM_ ## f ## x, "f" #x ) \
	DEF(TOK_ASM_ ## f ## x ## p, "f" #x "p") \
	DEF_FP1(x)

#define DEF_ASMTEST(x) \
	DEF_ASM(x ## o) \
	DEF_ASM(x ## no) \
	DEF_ASM(x ## b) \
	DEF_ASM(x ## c) \
	DEF_ASM(x ## nae) \
	DEF_ASM(x ## nb) \
	DEF_ASM(x ## nc) \
	DEF_ASM(x ## ae) \
	DEF_ASM(x ## e) \
	DEF_ASM(x ## z) \
	DEF_ASM(x ## ne) \
	DEF_ASM(x ## nz) \
	DEF_ASM(x ## be) \
	DEF_ASM(x ## na) \
	DEF_ASM(x ## nbe) \
	DEF_ASM(x ## a) \
	DEF_ASM(x ## s) \
	DEF_ASM(x ## ns) \
	DEF_ASM(x ## p) \
	DEF_ASM(x ## pe) \
	DEF_ASM(x ## np) \
	DEF_ASM(x ## po) \
	DEF_ASM(x ## l) \
	DEF_ASM(x ## nge) \
	DEF_ASM(x ## nl) \
	DEF_ASM(x ## ge) \
	DEF_ASM(x ## le) \
	DEF_ASM(x ## ng) \
	DEF_ASM(x ## nle) \
	DEF_ASM(x ## g)

#endif /* defined TCC_TARGET_I386 || defined TCC_TARGET_X86_64 */

enum tcc_token {
	TOK_LAST = TOK_IDENT - 1,
#define DEF(id, str) id,
#include "tokens.h"
#undef DEF
};

#define TOK_UIDENT TOK_DEFINE

#ifdef R2__WINDOWS__
#define IS_DIRSEP(c) (c == '/' || c == '\\')
#define IS_ABSPATH(p) (IS_DIRSEP(p[0]) || (p[0] && p[1] == ':' && IS_DIRSEP(p[2])))
#define PATHCMP stricmp
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#ifndef __GNUC__
# define strtold (long double)strtod
# define strtof (float)strtod
# define strtoll _strtoi64
# define strtoull _strtoui64
#endif
#else // ifdef R2__WINDOWS__
#define IS_DIRSEP(c) (c == '/')
#define IS_ABSPATH(p) IS_DIRSEP(p[0])
#define PATHCMP strcmp
#endif

/* space excluding newline */
static inline bool is_space(int ch) {
	return ch == ' ' || ch == '\t' || ch == '\v' || ch == '\f' || ch == '\r';
}

static inline bool isid(int c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

// TODO: deprecate. we have isdigit()
static inline bool isnum(int c) {
	return c >= '0' && c <= '9';
}

static inline bool isdot(int c) {
	return c == '.';
}

static inline bool isoct(int c) {
	return c >= '0' && c <= '7';
}

// TODO: deprecate, we have toupper()
static inline int toup(int c) {
	return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}

static inline int tcc_nerr(TCCState *s1) {
	return s1->nb_errors;
}

#define AFF_PRINT_ERROR     0x0001 /* print error if file not found */
#define AFF_REFERENCED_DLL  0x0002 /* load a referenced dll from another dll */
#define AFF_PREPROCESS      0x0004 /* preprocess file */

/* public functions currently used by the tcc main function */
R_API char *strcat2(char *buf, int buf_size, const char *s);
R_API char *tcc_basename(const char *name);
R_API char *tcc_fileextension(const char *name);
R_API void tcc_error_noabort(const char *fmt, ...);
R_API void tcc_error(TCCState *s1, const char *fmt, ...);
R_API void tcc_warning(TCCState *s1, const char *fmt, ...);
R_API void strcat_printf(char *buf, int buf_size, const char *fmt, ...);

/* other utilities */
ST_FUNC void dynarray_add(void ***ptab, int *nb_ptr, void *data);
ST_FUNC void dynarray_reset(void *pp, int *n);
ST_FUNC void cstr_ccat(CString *cstr, int ch);
ST_FUNC void cstr_cat(CString *cstr, const char *str);
ST_FUNC void cstr_wccat(CString *cstr, int ch);
ST_FUNC void cstr_new(CString *cstr);
ST_FUNC void cstr_free(CString *cstr);
ST_FUNC void cstr_reset(CString *cstr);

static inline void sym_free(TCCState *s1, Sym *sym);
ST_FUNC Sym *sym_push2(TCCState *s1, Sym **ps, int v, int t, long long c);
ST_FUNC Sym *sym_push(TCCState *s1, int v, CType *type, int r, long long c);
ST_FUNC void sym_pop(TCCState *s1, Sym **ptop, Sym *b);
static inline Sym *sym_find(TCCState *s1, int v);
ST_FUNC Sym *global_identifier_push(TCCState *s1, int v, int t, long long c);

ST_FUNC bool tcc_open_bf(TCCState *s1, const char *filename, int initlen);
ST_FUNC int tcc_open(TCCState *s1, const char *filename);
ST_FUNC void tcc_close(TCCState *s1);
ST_FUNC int tcc_add_file_internal(TCCState *s1, const char *filename, int flags);
R_API int tcc_parse_args(TCCState *s, int argc, char **argv);
R_API int tcc_decl0(TCCState *s1, int l, int is_for_loop_init);

/* ------------ tccpp.c ------------ */

#define TOK_FLAG_BOL   0x0001 /* beginning of line before */
#define TOK_FLAG_BOF   0x0002 /* beginning of file before */
#define TOK_FLAG_ENDIF 0x0004 /* a endif was found matching starting #ifdef */
#define TOK_FLAG_EOF   0x0008 /* end of file */

#define PARSE_FLAG_PREPROCESS 0x0001 /* activate preprocessing */
#define PARSE_FLAG_TOK_NUM    0x0002 /* return numbers instead of TOK_PPNUM */
#define PARSE_FLAG_LINEFEED   0x0004 /* line feed is returned as a
					token. line feed is also
					returned at eof */
#define PARSE_FLAG_ASM_COMMENTS 0x0008 /* '#' can be used for line comment */
#define PARSE_FLAG_SPACES     0x0010 /* next() returns space tokens (for -E) */

ST_FUNC TokenSym *tok_alloc(TCCState *s1, const char *str, int len);
ST_FUNC char *get_tok_str(TCCState *s1, int v, CValue *cv);
ST_FUNC void save_parse_state(TCCState *s1, ParseState *s);
static inline void tok_str_init(TokenString *s);
ST_FUNC void tok_str_free(int *str);
ST_FUNC void tok_str_add(TCCState *s1, TokenString *s, int t);
ST_FUNC void tok_str_add_tok(TCCState *s1, TokenString *s);
static inline void define_push(TCCState *s1, int v, int macro_type, int *str, Sym *first_arg);
ST_FUNC void define_undef(TCCState *s1, Sym *s);
static inline Sym *define_find(TCCState *s1, int v);
ST_FUNC void free_defines(TCCState *s1, Sym *b);
R_API void tcc_parse_define(TCCState *s1);
ST_FUNC void preprocess(TCCState *s1, bool is_bof);
ST_FUNC void next_nomacro(TCCState *s1);
static inline void unget_tok(TCCState *s1, int last_tok);
ST_FUNC void preprocess_init(TCCState *s1);
ST_FUNC void preprocess_new(TCCState *s1);
ST_FUNC int tcc_preprocess(TCCState *s1);
ST_FUNC void next(TCCState *s1);
ST_FUNC void skip(TCCState *s1, int c);
ST_FUNC void expect(TCCState *s1, const char *msg);

/* ------------ tccgen.c ------------ */

#define RC_INT 0x0001 /* generic integer register */
#define RC_FLOAT 0x0002 /* generic float register */
#define RC_IRET 0x0004
#define RC_LRET 0x0020
#define RC_FRET 0x0008
#define REG_IRET 0
#define REG_LRET 2
#define REG_FRET 3

static inline bool is_structured(CType *t);
static inline bool is_struct(CType *t);
static inline bool is_union(CType *t);
static inline bool is_float(int t);
static inline bool not_structured(CType *t);

ST_FUNC int type_size(TCCState *s1, CType *type, int *a);
ST_FUNC void mk_pointer(TCCState *s1, CType *type);
ST_FUNC long long expr_const(TCCState *s1);

/********************************************************/
#undef ST_DATA
#ifdef ONE_SOURCE
#define ST_DATA static
#else
#define ST_DATA
#endif
/********************************************************/
R_API void tcc_appendf(TCCState *s, const char *fmt, ...);
R_API void tcc_typedef_appendf(TCCState *s, const char *fmt, ...);
R_API void tcc_typedef_alias_fields(TCCState *s, const char *alias);

extern void (*tcc_cb)(const char *, char **);

#endif /* _TCC_H */
