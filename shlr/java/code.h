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

#define JAVA_OPS_COUNT 297
extern struct java_op JAVA_OPS[JAVA_OPS_COUNT];
R_API int java_print_opcode(RBinJavaObj *obj, ut64 addr, int idx, const ut8 *bytes, int len, char *output, int outlen);
R_API int r_java_disasm(RBinJavaObj *obj, ut64 addr, const ut8 *bytes, int len, char *output, int outlen);
R_API int r_java_assemble(ut64 addr, ut8 *bytes, const char *string);
R_API bool r_java_assemblerz(const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written);
//R_API void r_java_set_obj(RBinJavaObj *obj);
R_API void r_java_new_method(void);

#endif
