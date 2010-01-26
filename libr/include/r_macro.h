#ifndef _INCLUDE_R_MACRO_H_
#define _INCLUDE_R_MACRO_H_

#include "r_types.h"
#include "r_util.h"
#include "list.h"

#define MACRO_LIMIT 4096
#define MACRO_LABELS 20

typedef struct r_macro_label_t {
	char name[80];
	char *ptr;
} RMacrolabel;

typedef struct r_macro_item_t {
	char *name;
	char *args;
	char *code;
	int nargs;
	struct list_head list;
} RMacroItem;

typedef struct r_macro_t {
	int counter;
	ut64 *brk_value;
	ut64 _brk_value;
	int brk;
	int (*cmd)(void *user, const char *cmd);
	int (*printf)(const char str, ...);
	void *user;
	struct r_num_t *num;
	int labels_n;
	struct r_macro_label_t labels[MACRO_LABELS];
	struct list_head macros;
} RMacro;

#ifdef R_API
R_API void r_macro_init(struct r_macro_t *mac);
R_API int r_macro_add(struct r_macro_t *mac, const char *name);
R_API int r_macro_rm(struct r_macro_t *mac, const char *_name);
R_API int r_macro_list(struct r_macro_t *mac);
R_API int r_macro_call(struct r_macro_t *mac, const char *name);
R_API int r_macro_break(struct r_macro_t *mac, const char *value);
#endif

#endif
