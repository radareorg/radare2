#ifndef R2_LIB_H
#define R2_LIB_H

#include <r_types.h>
#include <r_list.h>
#include <r_lib.h>
#include <sdb/ht_pp.h>

#if R2__UNIX__ && WANT_DYLINK
#include <dlfcn.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_lib);

// rename to '.' ??
#define R_LIB_SEPARATOR "."
#define R_LIB_SYMNAME "radare_plugin"
#define R_LIB_SYMFUNC "radare_plugin_function"

#define R2_ABIVERSION 9
#define R2_VERSION_ABI R2_ABIVERSION

#define R_LIB_ENV "R2_LIBR_PLUGINS"

/* TODO: This must depend on HOST_OS, and maybe move into r_types */
#if R2__WINDOWS__
#include <windows.h>
#define R_LIB_EXT "dll"
#elif __APPLE__
#define R_LIB_EXT "dylib"
#else
#define R_LIB_EXT "so"
#endif

// R2_610 rename to RLibPluginStatus ?
typedef enum r_plugin_status_t {
	R_PLUGIN_STATUS_BROKEN = 0,
	R_PLUGIN_STATUS_INCOMPLETE = 1,
	R_PLUGIN_STATUS_BASIC = 2,
	R_PLUGIN_STATUS_OK = 3,
	R_PLUGIN_STATUS_GOOD = 4,
	R_PLUGIN_STATUS_COMPLETE = 5,
} RPluginStatus;

// R2_610 rename to RLibPluginMeta ?
typedef struct r_plugin_meta_t {
	char *name;
	char *desc;
	char *author;
	char *version;
	char *license;
	char *contact; // email/mastodon/addr
	char *copyright; // 2024-2025 ..?
	RPluginStatus status;
} RPluginMeta;

/* store list of loaded plugins */
typedef struct r_lib_plugin_t {
	int type;
	char *file;
	void *data; /* user pointer */
	struct r_lib_handler_t *handler;
	void *dl_handler; // DL HANDLER
	void (*free)(void *data);
	char *name; // From the RPluginMeta's name // type + name imho
} RLibPlugin;

typedef bool (*RLibCallback)(RLibPlugin *, void *user, void *data);

/* store list of initialized plugin handlers */
typedef struct r_lib_handler_t {
	int type;
	char desc[128]; // TODO: use char *
	void *user; /* user pointer */
	RLibCallback constructor;
	RLibCallback destructor;
} RLibHandler;

/* this structure should be pointed by the 'radare_plugin' symbol
   found in the loaded .so */
typedef struct r_lib_struct_t {
	int type;
	void *data; /* pointer to data handled by plugin handler */
	const char *version; /* r2 version */
	void (*free)(void *data);
	const char *pkgname; /* pkgname associated to this plugin */
	ut32 abiversion; /* ABI version to prevent loading incompatible plugins */
} RLibStruct;

typedef RLibStruct* (*RLibStructFunc) (void);

// order matters because of libr/util/lib.c
enum {
	R_LIB_TYPE_IO,      /* io layer */
	R_LIB_TYPE_DBG,     /* debugger */
	R_LIB_TYPE_LANG,    /* language */
	R_LIB_TYPE_ASM,     /* assembler */
	R_LIB_TYPE_ANAL,    /* analysis */
	R_LIB_TYPE_BIN,     /* bin headers */
	R_LIB_TYPE_BIN_XTR, /* bin extractors */
	R_LIB_TYPE_BIN_LDR, /* bin loaders */
	R_LIB_TYPE_BP,      /* breakpoint */
	R_LIB_TYPE_SYSCALL, /* syscall */
	R_LIB_TYPE_FASTCALL,/* fastcall */
	R_LIB_TYPE_CRYPTO,  /* cryptography -- deprecate */
	R_LIB_TYPE_CORE,    /* RCore commands */
	R_LIB_TYPE_EGG,     /* r_egg plugin */
	R_LIB_TYPE_FS,      /* r_fs plugin */
	R_LIB_TYPE_ESIL,    /* r_anal.esil plugin */
	R_LIB_TYPE_ARCH,    /* arch plugins */
	R_LIB_TYPE_MUTA,    /* mutator */
	R_LIB_TYPE_LAST
};


typedef struct r_lib_t {
	char *symname;
	char *symnamefunc;
	RList /*RLibPlugin*/ *plugins;
	RList /*RLibHandler*/ *handlers;
	RLibHandler *handlers_bytype[R_LIB_TYPE_LAST];
	bool ignore_version;
	bool ignore_abiversion;
	bool safe_loading; /* true to enable 2-step loading process */
	// hashtable plugname = &plugin
	HtPP *plugins_ht;
	ut32 abiversion; /* Current ABI version */
} RLib;

#ifdef R_API

/* low level api */
R_API void *r_lib_dl_open(const char *libname, bool safe_mode);
R_API void *r_lib_dl_sym(void *handler, const char *name);
R_API bool r_lib_dl_close(void *handler);

/* high level api */
R_API RLib *r_lib_new(const char *symname, const char *symnamefunc);
R_API void r_lib_free(RLib *lib);
R_API bool r_lib_run_handler(RLib *lib, RLibPlugin *plugin, RLibStruct *symbol);
R_API RLibHandler *r_lib_get_handler(RLib *lib, int type);
R_API bool r_lib_open(RLib *lib, const char *file);
R_API bool r_lib_opendir(RLib *lib, const char *path);
R_API bool r_lib_open_ptr(RLib *lib, const char *file, void *handler, RLibStruct *stru);
R_API bool r_lib_validate_plugin(RLib *lib, const char *file, RLibStruct *stru);
R_API RList *r_lib_get_loaded_plugins(RLib *lib);
R_API char *r_lib_path(const char *libname);
R_API void r_lib_list(RLib *lib);
R_API bool r_lib_add_handler(RLib *lib, int type, const char *desc, RLibCallback ct, RLibCallback dt, void *user);
R_API bool r_lib_del_handler(RLib *lib, int type);
R_API bool r_lib_close(RLib *lib, const char *file);

#include <r_util/pj.h>
R_API void r_lib_meta_pj(PJ *pj, const RPluginMeta *meta);
#endif

#ifdef __cplusplus
}
#endif

#endif
