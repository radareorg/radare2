#ifndef _INCLUDE_R_SIGN_H_
#define _INCLUDE_R_SIGN_H_

#include <r_types.h>
#include "list.h"

/* signature struct */
typedef struct r_sign_item_t {
	char name[32];
	ut32 size;
	ut8 *bytes;
	ut32 csum;
	struct list_head list;
} rSignItem;

typedef struct r_sign_t {
	int count;
	struct list_head items;
} rSign;

#ifdef R_API
R_API int r_sign_generate(struct r_sign_t *sig, const char *file, FILE *fd);
R_API int r_sign_check(struct r_sign_t *sig, const char *binfile);
R_API struct r_sign_t *r_sign_free(struct r_sign_t *sig);
R_API int r_sign_info(struct r_sign_t *sig);
R_API int r_sign_load_file(struct r_sign_t *sig, const char *file);
R_API struct r_sign_item_t *r_sign_add(struct r_sign_t *sig);
R_API int r_sign_option(struct r_sign_t *sig, const char *option);
R_API int r_sign_set(struct r_sign_item_t *sig, const char *key, const char *value);
R_API int r_sign_init(struct r_sign_t *sig);
#endif

#endif
