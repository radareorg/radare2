#ifndef _LIB_R_LIB_H_
#define _LIB_R_LIB_H_

// TODO: rename type from int to 4 byte string
// TODO: use 4 chars to idnetify plugin type

#include "r_types.h"
#include "list.h"

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
	struct list_head list;
} RLibraryPlugin;

/* store list of initialized plugin handlers */
typedef struct r_lib_handler_t {
	int type;
	char desc[128];
	void *user; /* user pointer */
	int (*constructor)(struct r_lib_plugin_t *, void *user, void *data);
	int (*destructor)(struct r_lib_plugin_t *, void *user, void *data);
	struct list_head list;
} RLibraryHandler;

/* this structure should be pointed by the 'radare_plugin' symbol 
   found in the loaded .so */
typedef struct r_lib_struct_t {
	int type;
	void *data; /* pointer to data handled by plugin handler */
} RLibraryStruct;

enum {
	R_LIB_TYPE_IO,      /* io layer */
	R_LIB_TYPE_DBG,     /* debugger */
	R_LIB_TYPE_LANG,    /* language */
	R_LIB_TYPE_ASM,     /* assembler */
	R_LIB_TYPE_ANAL,    /* analysis */
	R_LIB_TYPE_PARSE,   /* parsers */
	R_LIB_TYPE_BIN,     /* bins */
	R_LIB_TYPE_BININFO, /* bin info */
	R_LIB_TYPE_BP,      /* breakpoint */
	R_LIB_TYPE_SYSCALL, /* syscall */
	R_LIB_TYPE_FASTCALL,/* fastcall */
	R_LIB_TYPE_CRYPTO,  /* cryptography */
	R_LIB_TYPE_CMD,     /* commands */
	R_LIB_TYPE_LAST
};

typedef struct r_lib_t {
	/* linked list with all the plugin handler */
	/* only one handler per handler-id allowed */
	/* this is checked in add_handler function */
	char symname[32];
	struct list_head plugins;
	struct list_head handlers;
} RLibrary;

#ifdef R_API

/* low level api */
R_API void *r_lib_dl_open(const char *libname);
R_API void *r_lib_dl_sym(void *handle, const char *name);
R_API int r_lib_dl_close(void *handle);
R_API int r_lib_dl_check_filename(const char *file);

/* high level api */
R_API struct r_lib_t *r_lib_new(const char *symname);
R_API struct r_lib_t *r_lib_init(struct r_lib_t *lib, const char *symname);
R_API struct r_lib_t *r_lib_free(struct r_lib_t *lib);
R_API int r_lib_run_handler(struct r_lib_t *lib, struct r_lib_plugin_t *plugin, struct r_lib_struct_t *symbol);
R_API struct r_lib_handler_t *r_lib_get_handler(struct r_lib_t *lib, int type);
R_API int r_lib_open(struct r_lib_t *lib, const char *file);
R_API int r_lib_opendir(struct r_lib_t *lib, const char *path);
R_API void r_lib_list(struct r_lib_t *lib);
R_API int r_lib_add_handler(struct r_lib_t *lib, int type, const char *desc, int (*cb)(struct r_lib_plugin_t *,void *, void *), int (*dt)(struct r_lib_plugin_t *, void *, void *), void *user );
R_API int r_lib_del_handler(struct r_lib_t *lib, int type);
R_API int r_lib_close(struct r_lib_t *lib, const char *file);
#endif

#endif
