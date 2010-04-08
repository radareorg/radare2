#ifndef _INCLUDE_R_SIGN_H_
#define _INCLUDE_R_SIGN_H_

#include <r_types.h>
#include <r_util.h>
#include "list.h"

enum {
	R_SIGN_BYTES = 'b',
	R_SIGN_FUNC= 'f',
	R_SIGN_ANAL = 'a',
};

/* signature struct */
typedef struct r_sign_item_t {
	int type;
	char name[32];
	int size;
	ut8 *bytes;
	ut8 *mask;
	struct list_head list;
} RSignItem;

typedef struct r_sign_t {
	int s_byte;
	int s_anal;
	char prefix[32];
	FunctionPrintf printf;
	struct list_head items;
} RSign;

typedef int (*RSignCallback)(RSignItem *si, void *user);

#ifdef R_API
R_API RSign *r_sign_init(RSign *sig);
R_API int r_sign_add(RSign *sig, int type, const char *name, const char *arg);
R_API RSign *r_sign_free(RSign *sig);
R_API void r_sign_prefix(RSign *sig, const char *str);
R_API void r_sign_list(RSign *sig, int rad);
R_API void r_sign_reset(RSign *sig);

// old api
R_API int r_sign_generate(RSign *sig, const char *file, FILE *fd);
R_API RSignItem *r_sign_check(RSign *sig, const ut8 *buf, int len);
R_API int r_sign_load_file(RSign *sig, const char *file);
R_API int r_sign_option(RSign *sig, const char *option);
R_API int r_sign_item_set(RSignItem *sig, const char *key, const char *value);
#endif

#endif
