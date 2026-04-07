/* radare - LGPL - Copyright 2026 - pancake */

#include <r_anal.h>

// Scan executable sections for ARM/Thumb mode switches by looking at BL/BLX
// immediate instructions. Creates ahb hints at mode-switch targets.
static int thumb_scan(RAnal *anal) {
	if (!anal->iob.read_at || !anal->binb.get_sections) {
		return 0;
	}
	const int bits = anal->config->bits;
	const int bsz = 4096;
	ut8 *buf = R_NEWS (ut8, bsz);
	int hints_added = 0;
	RList *sections = anal->binb.get_sections (anal->binb.bin);
	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (! (section->perm & R_PERM_X)) {
			continue;
		}
		ut64 addr = section->vaddr;
		ut64 end = addr + section->vsize;
		if (end - addr > 32 * 1024 * 1024) {
			continue;
		}
		int cur_bits = bits;
		while (addr < end) {
			int toread = R_MIN (end - addr, bsz);
			if (!anal->iob.read_at (anal->iob.io, addr, buf, toread)) {
				break;
			}
			RAnalHint *hint = r_anal_hint_get (anal, addr);
			if (hint && hint->bits) {
				cur_bits = hint->bits;
			}
			r_anal_hint_free (hint);
			int i = 0;
			while (i < toread - 3) {
				int insn_size;
				if (cur_bits == 32) {
					// ARM32 mode: 4-byte aligned instructions
					if ((addr + i) & 3) {
						i++;
						continue;
					}
					if (i + 4 > toread) {
						break;
					}
					ut32 insn = r_read_le32 (buf + i);
					insn_size = 4;
					// ARM BLX immediate: 1111 101H xxxx xxxx xxxx xxxx xxxx xxxx
					// This always switches to Thumb mode
					if ((insn & 0xfe000000) == 0xfa000000) {
						st32 offset = (st32) ((insn & 0x00ffffff) << 2);
						if (offset & 0x02000000) {
							offset |= (st32)0xfc000000;
						}
						int H = (insn >> 24) & 1;
						offset += H * 2;
						ut64 target = (addr + i) + 8 + offset;
						r_anal_hint_set_bits (anal, target, 16);
						hints_added++;
					}
				} else {
					// Thumb mode: 2-byte or 4-byte instructions
					if ((addr + i) & 1) {
						i++;
						continue;
					}
					if (i + 2 > toread) {
						break;
					}
					ut16 hw0 = r_read_le16 (buf + i);
					insn_size = 2;
					// Check for 32-bit Thumb BLX (switches to ARM)
					if ((hw0 & 0xf800) == 0xf000 && i + 4 <= toread) {
						ut16 hw1 = r_read_le16 (buf + i + 2);
						insn_size = 4;
						if ((hw1 & 0xd000) == 0xc000) {
							// BLX from Thumb to ARM
							st32 S = (hw0 >> 10) & 1;
							st32 imm10 = hw0 & 0x3ff;
							st32 J1 = (hw1 >> 13) & 1;
							st32 J2 = (hw1 >> 11) & 1;
							st32 imm11 = hw1 & 0x7ff;
							st32 I1 = ! (J1 ^ S);
							st32 I2 = ! (J2 ^ S);
							st32 offset = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1);
							if (S) {
								offset |= (st32)0xfe000000;
							}
							ut64 target = ((addr + i) + 4 + offset) & ~3ULL;
							r_anal_hint_set_bits (anal, target, 32);
							hints_added++;
						}
					}
				}
				i += insn_size;
				if ((i & 0xff) == 0) {
					RAnalHint *h = r_anal_hint_get (anal, addr + i);
					if (h && h->bits) {
						cur_bits = h->bits;
					}
					r_anal_hint_free (h);
				}
			}
			addr += toread;
		}
	}
	free (buf);
	return hints_added;
}

static char *thumbcmd(RAnal *anal, const char *cmd) {
	if (!r_str_startswith (cmd, "thumb")) {
		return NULL;
	}
	if (cmd[5] == '?') {
		return strdup (
			"| a:thumb    scan for ARM/Thumb mode switches and create ahb hints\n");
	}
	int n = thumb_scan (anal);
	if (n > 0) {
		return r_str_newf ("ARM thumb scan: %d mode switch hints added\n", n);
	}
	return strdup ("");
}

static int thumb_eligible(RAnal *anal) {
	const char *arch = anal->config->arch;
	if (!arch || !r_str_startswith (arch, "arm")) {
		return -1;
	}
	int bits = anal->config->bits;
	if (bits != 16 && bits != 32) {
		return -1;
	}
	return 0;
}

RAnalPlugin r_anal_plugin_thumb = {
	.meta = {
		.name = "thumb",
		.desc = "ARM Thumb/ARM32 mode switch detection",
		.author = "pancake",
		.license = "LGPL3",
	},
	.cmd = thumbcmd,
	.eligible = thumb_eligible,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_thumb,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
