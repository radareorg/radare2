#ifndef _INCLUDE_WINEDBG_BE_ARM_H_
#define _INCLUDE_WINEDBG_BE_ARM_H_

struct arm_insn {
	ut64 pc;
	const ut8 *buf;
	int thumb;
	char *str_asm;
	char *str_hex;
};

int arm_disasm_one_insn(struct arm_insn *arminsn);
void arm_set_pc(struct arm_insn *arminsn, ut64 pc);
void arm_set_input_buffer(struct arm_insn *arminsn, const ut8 *buf);
void arm_set_thumb(struct arm_insn *arminsn, int thumb);
char* arm_insn_asm(struct arm_insn *arminsn);
char* arm_insn_hex(struct arm_insn *arminsn);
void* arm_free(struct arm_insn *arminsn);
struct arm_insn* arm_new();

#endif
