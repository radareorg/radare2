#ifndef R2_NAKED_H
#define R2_NAKED_H

#ifdef __cplusplus
extern "C" {
#endif

void *r_core_new(void);
char *r_core_cmd_str(void *p, const char *cmd);
void r_core_free(void* core);
void free(void*);

#ifdef __cplusplus
}
#endif

#endif
