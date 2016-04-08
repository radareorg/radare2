#ifndef R2_NAKED_H
#define R2_NAKED_H

void *r_core_new();
char *r_core_cmd_str(void *p, const char *cmd);
void r_core_free(void* core);
void free(void*);

#endif
