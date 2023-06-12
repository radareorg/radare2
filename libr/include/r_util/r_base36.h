#ifndef R2_BASE36_H
#define R2_BASE36_H

#ifdef __cplusplus
extern "C" {
#endif

R_API void b36_fromnum(char *s, ut64 n);
R_API ut64 b36_tonum(const char *s);

#ifdef __cplusplus
}
#endif

#endif
