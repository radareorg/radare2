/* radare2 - LGPL - Copyright 2014-2026 - pancake */

#ifndef R_CORE_VISUAL_MODES_H
#define R_CORE_VISUAL_MODES_H

#include <r_core.h>

#define PRINT_HEX_FORMATS 14

static inline int visual_op_size(RCore *core, ut64 addr, int size) {
	const int codealign = core->anal->config->codealign;
	if (size < 1) {
		if (codealign > 1 && addr % codealign) {
			return codealign - (addr % codealign);
		}
		size = R_MAX (1, r_arch_info (core->anal->arch, R_ARCH_INFO_MINOP_SIZE));
	}
	if (codealign > 1) {
		const int remainder = (addr % codealign + (ut64)size) % codealign;
		if (remainder) {
			const int padding = codealign - remainder;
			size = size <= INT_MAX - padding? size + padding: codealign - (addr % codealign);
		}
	}
	return size;
}

static inline void applyHexMode(RCore *core) {
	int hexMode = core->visual.hexMode;
	core->visual.currentFormat = R_ABS (hexMode) % PRINT_HEX_FORMATS;
	bool compact = false;
	bool comments = false;
	switch (core->visual.currentFormat) {
	case 0: /* px */
	case 1: /* pxa */
	case 3: /* prx */
	case 6: /* pxw */
	case 10: /* pxr */
		comments = true;
		break;
	case 4: /* pxb */
	case 7: /* pxq */
		compact = true;
		comments = true;
		break;
	}
	r_config_set_b (core->config, "hex.compact", compact);
	r_config_set_b (core->config, "hex.comments", comments);
}

static inline void applyDisMode(RCore *core) {
	switch (core->visual.disMode) {
	case 0:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.esil", false);
		break;
	case 1:
		r_config_set_b (core->config, "asm.pseudo", true);
		r_config_set_b (core->config, "asm.esil", false);
		break;
	case 2:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.esil", true);
		break;
	}
}

#endif
