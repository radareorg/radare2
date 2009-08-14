#ifndef _LIB_R_LIB_H_
#define _LIB_R_LIB_H_

// TODO: rename type from int to 4 byte string
// TODO: use 4 chars to idnetify plugin type

#include "r_types.h"
#include "list.h"

/* store list of loaded plugins */
struct r_lib_plugin_t {
	int type;
	char *file;
	void *data; /* user pointer */
	struct r_lib_handler_t *handler;
	void *dl_handler; // DL HANDLER
	struct list_head list;
};

/* store list of initialized plugin handlers */
struct r_lib_handler_t {
	int type;
	char desc[128];
	void *user; /* user pointer */
	int (*constructor)(struct r_lib_plugin_t *, void *user, void *data);
	int (*destructor)(struct r_lib_plugin_t *, void *user, void *data);
	struct list_head list;
};


/* this structure should be pointed by the 'radare_plugin' symbol 
   found in the loaded .so */
struct r_lib_struct_t {
	int type;
	void *data; /* pointer to data handled by plugin handler */
};

extern const char *r_lib_types[];

enum {
	R_LIB_TYPE_IO,      /* io layer */
	R_LIB_TYPE_DBG,     /* debugger */
	R_LIB_TYPE_LANG,    /* language */
	R_LIB_TYPE_ASM,     /* assembler */
	R_LIB_TYPE_ANAL,    /* analysis */
	R_LIB_TYPE_PARSE,   /* parsers */
	R_LIB_TYPE_BIN,     /* bins */
	R_LIB_TYPE_BININFO, /* bin info */
	R_LIB_TYPE_BP,      /* breakpoint info */
	R_LIB_TYPE_SYSCALL, /* breakpoint info */
	R_LIB_TYPE_FASTCALL, /* breakpoint info */
	R_LIB_TYPE_LAST
};

struct r_lib_t {
	/* linked list with all the plugin handler */
	/* only one handler per handler-id allowed */
	/* this is checked in add_handler function */
	char symname[32];
	struct list_head plugins;
	struct list_head handlers;
};

int r_lib_init(struct r_lib_t *lib, const char *symname);

/* low level api */
void *r_lib_dl_open(const char *libname);
void *r_lib_dl_sym(void *handle, const char *name);
int r_lib_dl_close(void *handle);
int r_lib_dl_check_filename(const char *file);

/* high level api */
struct r_lib_t *r_lib_new(const char *symname);
int r_lib_free(struct r_lib_t *lib);
int r_lib_run_handler(struct r_lib_t *lib, struct r_lib_plugin_t *plugin, struct r_lib_struct_t *symbol);
int r_lib_open(struct r_lib_t *lib, const char *file);
int r_lib_opendir(struct r_lib_t *lib, const char *path);
int r_lib_list(struct r_lib_t *lib);
int r_lib_add_handler(struct r_lib_t *lib, int type, const char *desc, int (*cb)(struct r_lib_plugin_t *,void *, void *), int (*dt)(struct r_lib_plugin_t *, void *, void *), void *user );
int r_lib_close(struct r_lib_t *lib, const char *file);

#endif
