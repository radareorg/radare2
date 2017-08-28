#ifndef R_SIGNAL_H
#define R_SIGNAL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Returns atoi(str) if signal with `str` name not found. */
R_API int r_signal_from_string (const char *str);

/* Return NULL if signal with `code` not found. */
R_API const char* r_signal_to_string (int code);

#ifdef __cplusplus
}
#endif

#endif //  R_SIGNAL_H
