#ifndef LIB_PPCVLE
#define LIB_PPCVLE
#include <r_types.h>

#define VLE_DEFAULTS     0
#define VLE_INTERNAL_PPC 1

#define TYPE_NONE 0
#define TYPE_REG  1
#define TYPE_IMM  2
#define TYPE_MEM  3
#define TYPE_JMP  4
#define TYPE_CR   5

typedef struct {
	const ut8* end;
	const ut8* pos;
	ut16 inc;
        ut32 options;
} vle_handle;

typedef struct {
	ut32 value;
	ut16 type;
} vle_field_t;

typedef struct {
	const char* name;
	vle_field_t fields[10];
	ut16 n;
	ut16 size;
	ut32 anal_op;
	int cond;
} vle_t;

int vle_init(vle_handle* handle, const ut8* buffer, const ut32 size);
vle_t* vle_next(vle_handle* handle);
int vle_option(vle_handle* handle, ut32 option);
void vle_free(vle_t* instr);
void vle_snprint(char* str, int size, ut32 addr, vle_t* instr);

#endif
