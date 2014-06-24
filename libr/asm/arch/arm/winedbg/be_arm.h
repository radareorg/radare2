#ifndef _INCLUDE_WINEDBG_BE_ARM_H_
#define _INCLUDE_WINEDBG_BE_ARM_H_

struct winedbg_arm_insn {
	ut64 pc;
	const ut8 *buf;
	int thumb;
	char *str_asm;
	char *str_hex;
	ut64 jmp, fail;
};

int arm_disasm_one_insn(struct winedbg_arm_insn *arminsn);
void arm_set_pc(struct winedbg_arm_insn *arminsn, ut64 pc);
void arm_set_input_buffer(struct winedbg_arm_insn *arminsn, const ut8 *buf);
void arm_set_thumb(struct winedbg_arm_insn *arminsn, int thumb);
char* winedbg_arm_insn_asm(struct winedbg_arm_insn *arminsn);
char* winedbg_arm_insn_hex(struct winedbg_arm_insn *arminsn);
void* arm_free(struct winedbg_arm_insn *arminsn);
struct winedbg_arm_insn* arm_new();

#endif
