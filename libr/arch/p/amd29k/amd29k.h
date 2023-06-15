#ifndef ASM_AMD_29K_H
#define ASM_AMD_29K_H

#include <stdint.h>
#include <r_types.h>

#ifdef __cplusplus
	extern "C" {
#endif

#define CPU_29000 "29000"
#define CPU_29050 "29050"

typedef struct amd29k_instr_s {
	const char* mnemonic;
	ut64        op_type;
	ut32        operands[6];
	char        type[6];
} amd29k_instr_t;

bool amd29k_instr_decode(const ut8* buffer, const ut32 buffer_size, amd29k_instr_t* instruction, const char* cpu);
void amd29k_instr_print(char* string, int string_size, ut64 address, amd29k_instr_t* instruction);

bool amd29k_instr_is_ret(amd29k_instr_t* instruction);
ut64 amd29k_instr_jump(ut64 address, amd29k_instr_t* instruction);

#ifdef __cplusplus
}
#endif

#endif /* ASM_AMD_29K_H */