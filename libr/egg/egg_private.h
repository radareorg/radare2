#ifndef R_EGG_PRIVATE_H
#define R_EGG_PRIVATE_H

#include <r_egg.h>

extern REggEmit emit_llvm;

bool egg_llvm_begin(REgg *egg);
bool egg_llvm_finish(REgg *egg);
bool egg_llvm_function(REgg *egg, const char *name, bool exported);
bool egg_llvm_extern(REgg *egg, const char *name, char *signature);
bool egg_llvm_syscall(REgg *egg, const char *name, const char *number);
bool egg_llvm_assembly_line(REgg *egg, const char *line);
bool egg_llvm_flush_assembly(REgg *egg);
void egg_llvm_end_function(REgg *egg);

#endif
