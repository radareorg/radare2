#ifndef R2_EGG_H
#define R2_EGG_H

#include <r_asm.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_egg);

#define R_EGG_INCDIR_ENV "EGG_INCDIR"
#define R_EGG_INCDIR_PATH "/lib/radare2/" R2_VERSION "/egg"

// rename to REggShellcode
#define R_EGG_PLUGIN_SHELLCODE 0
#define R_EGG_PLUGIN_ENCODER 1

typedef struct r_egg_plugin_t {
	const char *name;
	const char *desc;
	int type;
	RBuffer* (*build) (void *egg);
} REggPlugin;

typedef struct r_egg_lang_t {
	int pushargs;
	int nalias;
	int nsyscalls;
	char *conditionstr;
	char *syscallbody;
	char *includefile;
	char *setenviron;
	char *mathline;
	// used for confusing mathop
	int commentmode;
	int varsize;
	int varxs;
	int lastctxdelta;
	int nargs;
	int docall;
	int nfunctions;
	int nbrackets;
	int slurpin;
	int slurp;
	int line;
	char elem[1024];
	int attsyntax;
	int elem_n;
	char *callname;
	char *endframe;
	char *ctxpush[32];
	char *file;
	char *dstvar;
	char *dstval;
	char *includedir;
	char *ifelse_table[32][32];
	// used to solve if-else problem in a not so ugly way
	int ndstval;
	int skipline;// BOOL
	int quoteline;
	int quotelinevar;
	int stackframe;
	int stackfixed;
	int oc;
	int mode;
 	int inlinectr;
	struct {
		char *name;
		char *body;
		// int fastcall; /* TODO: NOT YET USED */
	} inlines[256];
	int ninlines;
	struct {
		char *name;
		char *arg;
	} syscalls[256];
	struct {
		char *name;
		char *content;
	} aliases[256];
	char *nested[32];
	char *nested_callname[32];
	// char *nestede[32] = {0};
	// seems nestede are not used any more
	// (only one place that gives nestede[] value, where could be replaced)
	int nestedi[32];
} REggLang;

typedef struct r_egg_t {
	RBuffer *src; // input source code
	RBuffer *buf; // output compiled bytes
	RBuffer *bin; // input binary data
	RList *list;
	RAsm *rasm;
	RAnal *anal;/// XXX this is temporary hack until asm can use arch
	RSyscall *syscall;
	REggLang lang;
	Sdb *db;
	RList *plugins;
	RList *patches; // <RBuffer>
	struct r_egg_emit_t *remit;
	int arch;
	int endian;
	int bits;
	ut32 os;
	int context;
} REgg;

/* XXX: this may fail in different arches */
#if 0
// XXX should be a ph subcommand to hash strings. ?h must be removed
r2 -q - <<EOF
?e #define R_EGG_OS_LINUX \`?h linux\`
?e #define R_EGG_OS_OSX \`?h osx\`
?e #define R_EGG_OS_DARWIN \`?h darwin\`
?e #define R_EGG_OS_MACOS \`?h macos\`
?e #define R_EGG_OS_W32 \`?h w32\`
?e #define R_EGG_OS_WINDOWS \`?h windows\`
?e #define R_EGG_OS_BEOS \`?h beos\`
?e #define R_EGG_OS_FREEBSD \`?h freebsd\`
EOF
#endif

#define R_EGG_OS_LINUX 0x5ca62a43
#define R_EGG_OS_OSX 0x0ad593a1
#define R_EGG_OS_DARWIN 0xd86d1ae2
#define R_EGG_OS_WATCHOS 0x14945c70
#define R_EGG_OS_IOS 0x0ad58830
#define R_EGG_OS_MACOS 0x5cb23c16
#define R_EGG_OS_W32 0x0ad5fbb3
#define R_EGG_OS_WINDOWS 0x05b7de9a
#define R_EGG_OS_BEOS 0x506108be
#define R_EGG_OS_FREEBSD 0x73a72944

#if __APPLE__
#define R_EGG_OS_DEFAULT R_EGG_OS_OSX
#define R_EGG_OS_NAME "darwin"
#define R_EGG_FORMAT_DEFAULT "mach0"
#elif R2__WINDOWS__
#define R_EGG_OS_DEFAULT R_EGG_OS_W32
#define R_EGG_OS_NAME "windows"
#define R_EGG_FORMAT_DEFAULT "pe"
#else
#define R_EGG_OS_DEFAULT R_EGG_OS_LINUX
#define R_EGG_OS_NAME "linux"
#define R_EGG_FORMAT_DEFAULT "elf"
#endif

typedef struct r_egg_emit_t {
	const char *arch;
	int size; /* in bytes.. 32bit arch is 4, 64bit is 8 .. */
	const char *retvar;
	//const char *syscall_body;
	const char* (*regs)(REgg *egg, int idx);
	void (*init)(REgg *egg);
	void (*call)(REgg *egg, const char *addr, int ptr);
	void (*jmp)(REgg *egg, const char *addr, int ptr);
	//void (*sc)(int num);
	void (*frame)(REgg *egg, int sz);
	char *(*syscall)(REgg *egg, int num);
	void (*trap)(REgg *egg);
	void (*frame_end)(REgg *egg, int sz, int ctx);
	void (*comment)(REgg *egg, const char *fmt, ...);
	void (*push_arg)(REgg *egg, int xs, int num, const char *str);
	void (*set_string)(REgg *egg, const char *dstvar, const char *str, int j);
	void (*equ)(REgg *egg, const char *key, const char *value);
	void (*get_result)(REgg *egg, const char *ocn);
	void (*restore_stack)(REgg *egg, int size);
	void (*syscall_args)(REgg *egg, int nargs);
	void (*get_var)(REgg *egg, int type, char *out, int idx);
	void (*get_ar)(REgg *egg, char *out, int idx);
	void (*while_end)(REgg *egg, const char *label);
	void (*load)(REgg *egg, const char *str, int sz);
	void (*load_ptr)(REgg *egg, const char *str);
	void (*branch)(REgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst);
	void (*mathop)(REgg *egg, int ch, int sz, int type, const char *eq, const char *p);
	void (*get_while_end)(REgg *egg, char *out, const char *ctxpush, const char *label);
} REggEmit;

#ifdef R_API
R_API REgg *r_egg_new(void);
R_API void r_egg_lang_init(REgg *egg);
R_API void r_egg_lang_free(REgg *egg);
R_API char *r_egg_tostring(REgg *egg);
R_API void r_egg_free(REgg *egg);
R_API bool r_egg_plugin_add(REgg *a, REggPlugin *plugin);
R_API bool r_egg_plugin_remove(REgg *a, REggPlugin *plugin);
R_API void r_egg_reset(REgg *egg);
R_API bool r_egg_setup(REgg *egg, const char *arch, int bits, int endian, const char *os);
R_API bool r_egg_include(REgg *egg, const char *file, int format);
R_API bool r_egg_include_str(REgg *egg, const char *arg);
R_API void r_egg_load(REgg *egg, const char *code, int format);
R_API void r_egg_syscall(REgg *egg, const char *arg, ...) R_PRINTF_CHECK(2, 3);
R_API void r_egg_alloc(REgg *egg, int n);
R_API void r_egg_label(REgg *egg, const char *name);
R_API bool r_egg_raw(REgg *egg, const ut8 *b, int len);
R_API bool r_egg_encode(REgg *egg, const char *name);
R_API bool r_egg_shellcode(REgg *egg, const char *name);
#define r_egg_get_shellcodes(x) x->plugins
R_API void r_egg_option_set(REgg *egg, const char *k, const char *v);
R_API char *r_egg_option_get(REgg *egg, const char *k);
R_API void r_egg_if(REgg *egg, const char *reg, char cmp, int v);
R_API void r_egg_printf(REgg *egg, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API bool r_egg_compile(REgg *egg);
R_API bool r_egg_padding(REgg *egg, const char *pad);
R_API bool r_egg_assemble(REgg *egg);
R_API bool r_egg_assemble_asm(REgg *egg, char **asm_list);
R_API void r_egg_pattern(REgg *egg, int size);
R_API RBuffer *r_egg_get_bin(REgg *egg);
//R_API int r_egg_dump (REgg *egg, const char *file) { }
R_API char *r_egg_get_source(REgg *egg);
R_API RBuffer *r_egg_get_bin(REgg *egg);
R_API char *r_egg_get_assembly(REgg *egg);
R_API void r_egg_append(REgg *egg, const char *src);
R_API int r_egg_run(REgg *egg);
R_API int r_egg_run_rop(REgg *egg);
R_API bool r_egg_patch(REgg *egg, int off, const ut8 *b, int l);
R_API void r_egg_finalize(REgg *egg);

/* r_egg_cfile.c */
R_API char* r_egg_cfile_parser(const char *file, const char *arch, const char *os, int bits);

/* lang.c */
R_API char *r_egg_mkvar(REgg *egg, char *out, const char *_str, int delta);
R_API int r_egg_lang_parsechar(REgg *egg, char c);
R_API void r_egg_lang_include_path(REgg *egg, const char *path);
R_API void r_egg_lang_include_init(REgg *egg);

/* plugin pointers */
extern REggPlugin r_egg_plugin_xor;
extern REggPlugin r_egg_plugin_shya;
extern REggPlugin r_egg_plugin_exec;
#endif

#ifdef __cplusplus
}
#endif

#endif
