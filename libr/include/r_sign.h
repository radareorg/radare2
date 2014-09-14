#ifndef R2_SIGN_H
#define R2_SIGN_H

#include <r_types.h>
#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_sign);

enum {
	R_SIGN_BYTE = 'b',
	R_SIGN_FUNC = 'f',
	R_SIGN_HEAD = 'h',
	R_SIGN_ANAL = 'a',
};

/* signature struct */
typedef struct r_sign_item_t {
	int type;
	char name[32];
	int size;
	ut64 addr;
	ut8 *bytes;
	ut8 *mask;
} RSignItem;

typedef struct r_sign_t {
	int s_anal;
	int s_byte;
	int s_head;
	int s_func; // TODO: this must be an array count[N]
	char ns[32]; // namespace
	PrintfCallback printf;
	RList *items;
} RSign;

typedef int (*RSignCallback)(RSignItem *si, void *user);

#ifdef R_API
R_API RSign *r_sign_new();
R_API int r_sign_add(RSign *sig, RAnal *anal, int type,
		const char *name, const char *arg);
R_API RSign *r_sign_free(RSign *sig);
R_API void r_sign_ns(RSign *sig, const char *str);
R_API void r_sign_list(RSign *sig, int rad);
R_API void r_sign_reset(RSign *sig);
R_API void r_sign_item_free(void *_item);
R_API int r_sign_remove_ns(RSign* sig, const char* ns);
R_API int r_sign_is_flirt (RBuffer *buf);
R_API void r_sign_flirt_dump (const RAnal *anal, const char *flirt_file);
R_API void r_sign_flirt_scan (const RAnal *anal, const char *flirt_file);

// old api
R_API int r_sign_generate(RSign *sig, const char *file, FILE *fd);
R_API RSignItem *r_sign_check(RSign *sig, const ut8 *buf, int len);
R_API int r_sign_load_file(RSign *sig, const char *file);
R_API int r_sign_option(RSign *sig, const char *option);
R_API int r_sign_item_set(RSignItem *sig, const char *key, const char *value);
#endif

#ifdef __cplusplus
}
#endif

#endif
