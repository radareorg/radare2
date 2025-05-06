#ifndef R_TYPE_H
#define R_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sdb/sdb.h>

typedef struct r_type_enum {
	char *name;
	char *val;
} RTypeEnum;

typedef enum {
	R_TYPE_INVALID = -1,
	R_TYPE_BASIC = 0,
	R_TYPE_ENUM = 1,
	R_TYPE_STRUCT = 2,
	R_TYPE_UNION = 3,
	R_TYPE_TYPEDEF = 4,
	R_TYPE_CLASS = 5
} RTypeKind;

R_API bool r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val);
R_API void r_type_del(Sdb *TDB, const char *name);
R_API RTypeKind r_type_kind(Sdb *TDB, const char *name);
R_API char *r_type_enum_member(Sdb *TDB, const char *name, const char *member, ut64 val);
R_API char *r_type_enum_getbitfield(Sdb *TDB, const char *name, ut64 val);
R_API RList *r_type_get_enum(Sdb *TDB, const char *name);
R_API void r_type_enum_free(RTypeEnum *member);
R_API ut64 r_type_get_bitsize(Sdb *TDB, const char *type);
R_API RList *r_type_get_by_offset(Sdb *TDB, ut64 offset);
R_API char *r_type_get_struct_memb(Sdb *TDB, const char *type, int offset);
R_API char *r_type_link_at(Sdb *TDB, ut64 addr);
R_API int r_type_set_link(Sdb *TDB, const char *val, ut64 addr);
R_API int r_type_unlink(Sdb *TDB, ut64 addr);
R_API int r_type_link_offset(Sdb *TDB, const char *val, ut64 addr);
R_API char *r_type_format(Sdb *TDB, const char *t);

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name);
R_API const char *r_type_func_cc(Sdb *TDB, const char *func_name);
R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name);
R_API int r_type_func_args_count(Sdb *TDB, const char * R_NONNULL func_name);
R_API R_OWN char *r_type_func_args_type(Sdb *TDB, const char * R_NONNULL func_name, int i);
R_API const char *r_type_func_args_name(Sdb *TDB, const char * R_NONNULL func_name, int i);
R_API R_OWN char *r_type_func_guess(Sdb *TDB, char * R_NONNULL func_name);
R_API R_OWN char *r_type_func_name(Sdb *types, const char *fname);

#ifdef __cplusplus
}
#endif

#endif //  R_TYPE_H

