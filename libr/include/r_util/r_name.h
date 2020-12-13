#ifndef R_NAME_H
#define R_NAME_H

#ifdef __cplusplus
extern "C" {
#endif

R_API bool r_name_check(const char *name);
R_API bool r_name_filter(char *name, int len);
R_API const char *r_name_filter_ro(const char *a);
R_API int r_name_validate_special(const char ch);
R_API char *r_name_filter2(const char *name);
R_API bool r_name_validate_char(const char ch);

#ifdef __cplusplus
}
#endif

#endif //  R_NAME_H
