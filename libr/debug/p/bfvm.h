#ifndef _R_BFVM_INCLUDE_
#define _R_BFVM_INCLUDE_

#include <r_io.h>
#include <r_util.h>

#define BFVM_SCREEN_ADDR 0x50000
#define BFVM_SCREEN_SIZE 4096
#define BFVM_INPUT_ADDR 0x10000
#define BFVM_INPUT_SIZE 4096
#define BFVM_DATA_ADDR 0xd00000
#define BFVM_DATA_SIZE 4096
#define BFVM_CODE_ADDR 0
#define BFVM_CODE_SIZE 4096 /* XXX */

typedef struct bfvm_cpu_t {
	ut64 eip;
	ut64 esp;
	int ptr;
	int trace;
	int breaked;
	ut64 base;
	ut8 *mem;
	ut32 size;
	ut64 screen;
	int screen_idx;
	int screen_size;
	ut8 *screen_buf;
	ut64 input;
	int input_idx;
	int input_size;
	ut8 *input_buf;
	int circular; /* circular memory */
	RIOBind iob;
} BfvmCPU;

#ifdef R_API
R_API BfvmCPU *bfvm_new(RIOBind *iob);
R_API BfvmCPU *bfvm_free(BfvmCPU *c);
R_API int bfvm_step(BfvmCPU *c, int over);
#endif

#endif
