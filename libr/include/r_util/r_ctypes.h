#ifndef R_CTYPES_H
#define R_CTYPES_H

#ifdef __cplusplus
extern "C" {
#endif

R_API int r_type_set(Sdb *TDB, ut64 at, const char *field, ut64 val);
R_API void r_type_del(Sdb *TDB, const char *name);
R_API int r_type_get_bitsize (Sdb *TDB, const char *type);
R_API RList* r_type_get_by_offset(Sdb *TDB, ut64 offset);
R_API int r_type_link (Sdb *TDB, const char *val, ut64 addr);
R_API int r_type_unlink(Sdb *TDB, ut64 addr);
R_API int r_type_link_offset (Sdb *TDB, const char *val, ut64 addr);
R_API char *r_type_format(Sdb *TDB, const char *t);

// Function prototypes api
R_API int r_type_func_exist(Sdb *TDB, const char *func_name);
R_API const char *r_type_func_cc(Sdb *TDB, const char *func_name);
R_API const char *r_type_func_ret(Sdb *TDB, const char *func_name);
R_API int r_type_func_args_count(Sdb *TDB, const char *func_name);
R_API char *r_type_func_args_type(Sdb *TDB, const char *func_name, int i);
R_API char *r_type_func_args_name(Sdb *TDB, const char *func_name, int i);
R_API char *r_type_func_guess(Sdb *TDB, char *func_name);

#ifdef __cplusplus
}
#endif

#endif //  R_CTYPES_H

