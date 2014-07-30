#ifndef R2_LIB_H
#define R2_LIB_H

// TODO: rename type from int to 4 byte string
// TODO: use 4 chars to idnetify plugin type

#include "r_types.h"
#include "r_list.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER (r_lib);
// rename to '.' ??
#define R_LIB_SEPARATOR "."

#define R_LIB_ENV "LIBR_PLUGINS"

/* XXX : This must depend on HOST_OS */
#if __WINDOWS__
#define R_LIB_EXT "dll"
#elif __APPLE__
#define R_LIB_EXT "dylib"
#else
#define R_LIB_EXT "so"
#endif

/* store list of loaded plugins */
typedef struct r_lib_plugin_t {
	int type;
	char *file;
	void *data; /* user pointer */
	struct r_lib_handler_t *handler;
	void *dl_handler; // DL HANDLER
} RLibPlugin;

/* store list of initialized plugin handlers */
typedef struct r_lib_handler_t {
	int type;
	char desc[128];
	void *user; /* user pointer */
	int (*constructor)(RLibPlugin *, void *user, void *data);
	int (*destructor)(RLibPlugin *, void *user, void *data);
} RLibHandler;

/* this structure should be pointed by the 'radare_plugin' symbol
   found in the loaded .so */
typedef struct r_lib_struct_t {
	int type;
	void *data; /* pointer to data handled by plugin handler */
} RLibStruct;

// order matters because of libr/util/lib.c
enum {
	R_LIB_TYPE_IO,      /* io layer */
	R_LIB_TYPE_DBG,     /* debugger */
	R_LIB_TYPE_LANG,    /* language */
	R_LIB_TYPE_ASM,     /* assembler */
	R_LIB_TYPE_ANAL,    /* analysis */
	R_LIB_TYPE_PARSE,   /* parsers */
	R_LIB_TYPE_BIN,     /* bins */
	R_LIB_TYPE_BIN_XTR, /* bin extractors */
	R_LIB_TYPE_BP,      /* breakpoint */
	R_LIB_TYPE_SYSCALL, /* syscall */
	R_LIB_TYPE_FASTCALL,/* fastcall */
	R_LIB_TYPE_CRYPTO,  /* cryptography */
	R_LIB_TYPE_CORE,    /* RCore commands */
	R_LIB_TYPE_EGG,     /* r_egg plugin */
	R_LIB_TYPE_LAST
};

typedef struct r_lib_t {
	/* linked list with all the plugin handler */
	/* only one handler per handler-id allowed */
	/* this is checked in add_handler function */
	char symname[32];
	RList /*RLibPlugin*/ *plugins;
	RList /*RLibHandler*/ *handlers;
} RLib;

#ifdef R_API
/* low level api */
R_API void *r_lib_dl_open(const char *libname);
R_API void *r_lib_dl_sym(void *handler, const char *name);
R_API int r_lib_dl_close(void *handler);
R_API int r_lib_dl_check_filename(const char *file);

/* high level api */
R_API RLib *r_lib_new(const char *symname);
R_API RLib *r_lib_free(RLib *lib);
R_API int r_lib_run_handler(RLib *lib, RLibPlugin *plugin, RLibStruct *symbol);
R_API RLibHandler *r_lib_get_handler(RLib *lib, int type);
R_API int r_lib_open(RLib *lib, const char *file);
R_API int r_lib_opendir(RLib *lib, const char *path);
R_API int r_lib_open_ptr (RLib *lib, const char *file, void *handler, RLibStruct *stru);
R_API char *r_lib_path(const char *libname);
R_API void r_lib_list(RLib *lib);
R_API int r_lib_add_handler(RLib *lib, int type, const char *desc,
	int (*cb)(RLibPlugin *, void *, void *),
	int (*dt)(RLibPlugin *, void *, void *),
	void *user );
R_API int r_lib_del_handler(RLib *lib, int type);
R_API int r_lib_close(RLib *lib, const char *file);

R_API const char *r_lib_types_get(int idx);
R_API int r_lib_types_get_i(const char *str);
#endif

#ifdef __cplusplus
}
#endif

#endif
