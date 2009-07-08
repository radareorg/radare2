#ifndef _INCLUDE_R_VAR_H_
#define _INCLUDE_R_VAR_H_

#include "r_types.h"
#include "list.h"

#define R_VAR_ANAL_MAX 256

enum {
	R_VAR_TYPE_NONE = 0,
	R_VAR_TYPE_GLOBAL,
	R_VAR_TYPE_LOCAL,
	R_VAR_TYPE_ARG,
	R_VAR_TYPE_ARGREG
};

struct r_var_anal_t {
	int type;
	int delta;
	int count;
}; 

struct r_var_type_t {
        char name[128];
        char fmt[128];
        unsigned int size;
        struct list_head list;
};

struct r_var_t {
	int anal_size;
	struct r_var_anal_t anal[R_VAR_ANAL_MAX];
	struct list_head vartypes;
	struct list_head vars;
};

struct r_var_access_t {
	ut64 addr;
	int set;
	struct list_head list;
};

struct r_var_item_t {
	int type;         /* global, local... */
	ut64 addr;         /* address where it is used */
	ut64 eaddr;        /* address where it is used */
	int delta;        /* */
	int arraysize;    /* size of array var in bytes , 0 is no-array */
	char name[128];
	char vartype[128];
	struct list_head access; /* list of accesses for this var */
	struct list_head list;
};

/* api */
R_API struct r_var_t *r_var_new();
R_API void r_var_free(struct r_var_t *var);
R_API int r_var_init(struct r_var_t *var);
R_API int r_var_type_add(struct r_var_t *var, const char *typename, int size, const char *fmt);
R_API int r_var_type_del(struct r_var_t *var, const char *typename);
R_API int r_var_type_list(struct r_var_t *var);
R_API struct r_var_type_t *r_var_type_get(struct r_var_t *var, const char *datatype);
R_API const char *r_var_type_to_string(int type);

/* food */
R_API int r_var_item_print(struct r_var_t *var, struct r_var_item_t * v);
R_API int r_var_list_show(struct r_var_t *var, ut64 addr);
R_API int r_var_list(struct r_var_t *var, ut64 addr, int delta);

/* analyze */
R_API int r_var_anal_get(struct r_var_t *var, int type);
R_API void r_var_anal_reset(struct r_var_t *var);
R_API int r_var_anal_add(struct r_var_t *var, int type, int delta);

#endif
