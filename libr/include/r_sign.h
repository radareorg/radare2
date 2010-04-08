#ifndef _INCLUDE_R_SIGN_H_
#define _INCLUDE_R_SIGN_H_

#include <r_types.h>
#include "list.h"

enum {
	R_SIGN_BYTES,
	R_SIGN_GRAPH,
};

/* signature struct */
typedef struct r_sign_item_t {
	char name[32];
	ut32 size;
	ut8 *bytes;
	ut32 csum;
	struct list_head list;
} RSignItem;

typedef struct r_sign_t {
	int s_byte;
	int s_anal;
	struct list_head items;
} RSign;

typedef int (*RSignCallback)(RSignItem *si, void *user);

#ifdef R_API
R_API RSign *r_sign_init(RSign *sig);
R_API int r_sign_add(RSign *sig, int type, const char *name, const char *arg);
R_API RSign *r_sign_free(RSign *sig);

// old api
R_API int r_sign_generate(RSign *sig, const char *file, FILE *fd);
R_API int r_sign_check(RSign *sig, const char *binfile);
R_API int r_sign_info(RSign *sig);
R_API int r_sign_load_file(RSign *sig, const char *file);
R_API int r_sign_option(RSign *sig, const char *option);
R_API int r_sign_item_set(RSignItem *sig, const char *key, const char *value);
#endif

#endif
