#ifndef R_LOG_H
#define R_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

R_API void r_log_msg(const char *str);
R_API void r_log_error(const char *str);
R_API void r_log_file(const char *str);
R_API void r_log_progress(const char *str, int percent);

#ifdef __cplusplus
}
#endif

#endif //  R_LOG_H
