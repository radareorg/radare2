#ifndef _INCLUDE_R_JAVA_H_
#define _INCLUDE_R_JAVA_H_

#include <r_types.h>
#include "class.h"

struct java_op {
	char *name;
	unsigned char byte;
	int size;
};

extern struct java_op java_ops[];

static char * java_resolve(int idx);
int java_print_opcode(ut64 addr, int idx, const ut8 *bytes, char *output, int outlen);
//int r_java_disasm(const ut8 *bytes, char *output, int len);
unsigned short read_short(FILE *fd);

int java_classdump(const char *file, int verbose);

R_API int r_java_disasm(ut64 addr, const ut8 *bytes, char *output, int len);
R_API int r_java_assemble(ut8 *bytes, const char *string);
R_API void r_java_set_obj(RBinJavaObj *obj);

#endif
