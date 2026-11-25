/* radare - LGPL - Copyright 2026 - pancake */

#define X86_GETPC_THUNK_SIZE 6

// "mov r32, [esp]" followed by "ret", "repz ret" or "ret 0"; returns the r32 index or -1
static int x86_getpc_thunk_reg(const ut8 *b) {
	if (b[0] != 0x8b || (b[1] & 0xc7) != 4 || (b[2] & 0x3f) != 0x24) {
		return -1;
	}
	const ut8 *ret = b + 3;
	if (ret[0] == 0xc3 || (ret[0] == 0xf3 && ret[1] == 0xc3) || (ret[0] == 0xc2 && !ret[1] && !ret[2])) {
		return (b[1] >> 3) & 7;
	}
	return -1;
}
