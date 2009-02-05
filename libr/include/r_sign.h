#ifndef _INCLUDE_R_SIGN_H_
#define _INCLUDE_R_SIGN_H_

#include <r_types.h>
#include "list.h"

/* signature struct */
struct r_sign_item_t {
	char name[32];
	u32 size;
	u8 *bytes;
	u32 csum;
	struct list_head list;
};

struct r_sign_t {
	int count;
	struct list_head items;
};

int r_sign_generate(struct r_sign_t *sig, const char *file, FILE *fd);
int r_sign_check(struct r_sign_t *sig, const char *binfile);
struct r_sign_t *r_sign_free(struct r_sign_t *sig);
int r_sign_info(struct r_sign_t *sig);
int r_sign_load_file(struct r_sign_t *sig, const char *file);
struct r_sign_item_t *r_sign_add(struct r_sign_t *sig);
int r_sign_option(struct r_sign_t *sig, const char *option);
int r_sign_set(struct r_sign_item_t *sig, const char *key, const char *value);
int r_sign_init(struct r_sign_t *sig);

#endif
