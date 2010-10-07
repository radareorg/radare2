#ifndef _INCLUDE_ARMTHUMB_H_
#define _INCLUDE_ARMTHUMB_H_

int armthumb_length(unsigned int ins);
int armthumb_disassemble(char *buf, unsigned long pc, unsigned int ins);
int armass_assemble(const char *str, unsigned long off, int thumb);

#endif
