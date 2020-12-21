#ifndef R_NAME_H
#define R_NAME_H

#ifdef __cplusplus
extern "C" {
#endif

R_API bool r_name_validate_print(const char ch);
R_API bool r_name_validate_char(const char ch);
R_API bool r_name_validate_first(const char ch);
R_API bool r_name_check(const char *s);
R_API const char *r_name_filter_ro(const char *a);
R_API bool r_name_filter_flag(char *s);
R_API bool r_name_filter_print(char *s);
R_API bool r_name_filter(char *name, int maxlen);
R_API char *r_name_filter2(const char *name);

#ifdef __cplusplus
}
#endif

#endif //  R_NAME_H
