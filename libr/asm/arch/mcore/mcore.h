#ifndef MCORE_H
#define MCORE_H

#include <stdint.h>
#include <r_types.h>

#ifdef __cplusplus
	extern "C" {
#endif

#define ARGS_SIZE 5

#define MCORE_CPU_DFLT 0
#define MCORE_CPU_510E 1
#define MCORE_CPU_610E 2
#define MCORE_CPU_620  3

#define TYPE_NONE 0
#define TYPE_REG  1 // Register
#define TYPE_IMM  2 // Immediate
#define TYPE_MEM  3 // Memory
#define TYPE_JMP  4 // Jump
#define TYPE_JMPI 5 // Indirect Jump
#define TYPE_CTRL 6 // Control Registers

typedef struct {
	const ut8* end;
	const ut8* pos;
	ut16 inc;
} mcore_handle;

typedef struct {
	ut32 value;
	ut16 type;
} mcore_field_t;

typedef struct {
	const char* name;
	mcore_field_t args[ARGS_SIZE];
	ut64 type;
	ut16 n_args;
	ut16 bytes;
	ut16 size;
} mcore_t;

int mcore_init(mcore_handle* handle, const ut8* buffer, const ut32 size);
mcore_t* mcore_next(mcore_handle* handle);
void mcore_free(mcore_t* instr);
void mcore_snprint(char* str, int size, ut64 addr, mcore_t* instr);

#ifdef __cplusplus
}
#endif

#endif
