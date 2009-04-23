#ifndef _INCLUDE_VMAS_H_
#define _INCLUDE_VMAS_H_ 1

int psosvm_disasm(const u8 *bytes, char *output);
int psosvmasm_init();
int psosvm_assemble(unsigned char *bytes, char *string);

#endif
