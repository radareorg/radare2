#ifndef _INCLUDE_R_JAVA_H_
#define _INCLUDE_R_JAVA_H_

#include <r_types.h>
#include "class.h"

struct cp_item {
	int tag;
	char name[255];
	char *value;
	unsigned char bytes[5];
	ut64 off;
};

struct java_op {
	char *name;
	unsigned char byte;
	int size;
};

extern struct java_op java_ops[];

int java_print_opcode(int idx, const ut8 *bytes, char *output);
//int r_java_disasm(const ut8 *bytes, char *output, int len);
unsigned short read_short(FILE *fd);
void javasm_init ();
int java_classdump(const char *file, int verbose);

R_API int r_java_disasm(const ut8 *bytes, char *output, int len);
R_API int r_java_assemble(ut8 *bytes, const char *string);

#endif
