#ifndef _INCLUDE_R_JAVA_H_
#define _INCLUDE_R_JAVA_H_

#include <r_types.h>
#include "class.h"

typedef struct java_op {
	const char *name;
	unsigned char byte;
	int size;
	ut64 op_type;
} JavaOp;

extern struct java_op JAVA_OPS[];

int java_print_opcode(RBinJavaObj *obj, ut64 addr, int idx, const ut8 *bytes, char *output, int outlen);
unsigned short read_short(FILE *fd);

int java_classdump(const char *file, int verbose);

R_API int r_java_disasm(RBinJavaObj *obj, ut64 addr, const ut8 *bytes, char *output, int len);
R_API int r_java_assemble(ut8 *bytes, const char *string);
//R_API void r_java_set_obj(RBinJavaObj *obj);
R_API void r_java_new_method ();

#endif
