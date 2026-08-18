/* radare - LGPL - Copyright 2021-2026 - Siguza, pancake, hot3eed */

// Context: https://raw.githubusercontent.com/Siguza/misc/master/xref.c

#include <r_anal.h>
#include <r_core.h>

#define SIX_CMD "six"
#define SIX_CHUNK_SIZE 0x10000
#define SIX_LOOKAHEAD_SIZE 0x1000
#define SIX_ARM64_NOP 0xd503201f

static void addref(RAnal *anal, ut64 from, ut64 to, RAnalRefType type) {
	r_anal_xrefs_set (anal, from, to, type);
}

static void add_code_ref_hint(RAnal *anal, ut64 from, ut64 to) {
	addref (anal, from, to, R_ANAL_REF_TYPE_CODE);
	r_anal_hint_set_type (anal, from, R_ANAL_OP_TYPE_JMP);
	r_anal_hint_set_jump (anal, from, to);
}

static bool is_br_reg(ut32 insn, ut32 reg) {
	return (insn & 0xfffffc1f) == 0xd61f0000 && ((insn >> 5) & 0x1f) == reg;
}

static const ut8 *skip_nops(const ut8 *p, const ut8 *e) {
	while (p < e && r_read_le32 (p) == SIX_ARM64_NOP) {
		p += 4;
	}
	return p;
}

static bool parse_add_imm(ut32 insn, ut32 src_reg, ut64 base, ut32 *dst_reg, ut64 *target, ut32 *off) {
	if ((insn & 0xff8003e0) != (0x91000000 | (src_reg << 5))) {
		return false;
	}
	ut32 aoff = (insn >> 10) & 0xfff;
	if (insn & 0x400000) {
		aoff <<= 12;
	}
	*dst_reg = insn & 0x1f;
	*target = base + aoff;
	*off = aoff;
	return true;
}

static bool parse_movz(ut32 insn, ut32 *dst_reg, ut64 *value) {
	if ((insn & 0xff800000) != 0xd2800000) {
		return false;
	}
	ut64 imm = (insn >> 5) & 0xffff;
	ut32 hw = (insn >> 21) & 0x3;
	*dst_reg = insn & 0x1f;
	*value = imm << (hw * 16);
	return true;
}

static bool parse_add_shift(ut32 insn, ut32 base_reg, ut32 add_reg, ut64 base, ut64 add, ut32 *dst_reg, ut64 *target, ut32 *shift) {
	if ((insn & 0xffc00000) != 0x8b000000) {
		return false;
	}
	ut32 rd = insn & 0x1f;
	ut32 rn = (insn >> 5) & 0x1f;
	ut32 rm = (insn >> 16) & 0x1f;
	ut32 sh = (insn >> 10) & 0x3f;
	if (rn != base_reg || rm != add_reg || sh >= 64) {
		return false;
	}
	*dst_reg = rd;
	*target = base + (add << sh);
	*shift = sh;
	return true;
}

static bool handle_stub_island(RAnal *anal, RStrBuf *sb, bool register_refs, ut64 search, const ut8 *p, const ut8 *e, ut64 addr, bool is_adrp, ut32 reg, ut64 base) {
	const ut8 *q = skip_nops (p + 4, e);
	if (q >= e) {
		return false;
	}
	ut32 insn = r_read_le32 (q);
	ut32 dst_reg = reg;
	ut64 target = base;
	if (is_br_reg (insn, dst_reg)) {
		ut64 br_addr = addr + (ut64)(q - p);
		if (register_refs) {
			add_code_ref_hint (anal, br_addr, target);
			return true;
		}
		if (target == search) {
			r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; br x%u\n", addr, is_adrp? "adrp": "adr", reg, base, dst_reg);
			return true;
		}
		return false;
	}

	ut32 aoff = 0;
	if (parse_add_imm (insn, reg, base, &dst_reg, &target, &aoff)) {
		const ut8 *brp = skip_nops (q + 4, e);
		if (brp < e && is_br_reg (r_read_le32 (brp), dst_reg)) {
			ut64 br_addr = addr + (ut64)(brp - p);
			if (register_refs) {
				add_code_ref_hint (anal, br_addr, target);
				return true;
			}
			if (target == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; add x%u, x%u, %#x; br x%u\n",
					addr, is_adrp? "adrp": "adr", reg, base, dst_reg, reg, aoff, dst_reg);
				return true;
			}
		}
		return false;
	}

	ut32 add_reg = 0;
	ut64 add = 0;
	if (parse_movz (insn, &add_reg, &add)) {
		const ut8 *addp = skip_nops (q + 4, e);
		ut32 shift = 0;
		if (addp < e && parse_add_shift (r_read_le32 (addp), reg, add_reg, base, add, &dst_reg, &target, &shift)) {
			const ut8 *brp = skip_nops (addp + 4, e);
			if (brp < e && is_br_reg (r_read_le32 (brp), dst_reg)) {
				ut64 br_addr = addr + (ut64)(brp - p);
				if (register_refs) {
					add_code_ref_hint (anal, br_addr, target);
					return true;
				}
				if (target == search) {
					r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; mov x%u, %#" PFMT64x "; add x%u, x%u, x%u, lsl %u; br x%u\n",
						addr, is_adrp? "adrp": "adr", reg, base, add_reg, add, dst_reg, reg, add_reg, shift, dst_reg);
					return true;
				}
			}
		}
	}
	return false;
}

static const char *lookup_inst_name(uint32_t opc_size) {
	static const char *inst_names[] = {
		[0x00] = "strb",
		[0x01] = "strh",
		[0x02] = "str",
		[0x03] = "str",
		[0x10] = "ldrb",
		[0x11] = "ldrh",
		[0x12] = "ldr",
		[0x13] = "ldr",
		[0x20] = "ldrsb",
		[0x21] = "ldrsh",
		[0x22] = "ldrsw",
		[0x30] = "ldrsb",
		[0x31] = "ldrsh",
	};
	return (opc_size < R_ARRAY_SIZE (inst_names))? inst_names[opc_size]: NULL;
}

static const char *lookup_unscaled_inst_name(uint32_t opc_size) {
	static const char *inst_names[] = {
		[0x00] = "sturb",
		[0x01] = "sturh",
		[0x02] = "stur",
		[0x03] = "stur",
		[0x10] = "ldurb",
		[0x11] = "ldurh",
		[0x12] = "ldur",
		[0x13] = "ldur",
		[0x20] = "ldursb",
		[0x21] = "ldursh",
		[0x22] = "ldursw",
		[0x30] = "ldursb",
		[0x31] = "ldursh",
	};
	return (opc_size < R_ARRAY_SIZE (inst_names))? inst_names[opc_size]: NULL;
}

static const char *lookup_unprivileged_inst_name(uint32_t opc_size) {
	static const char *inst_names[] = {
		[0x00] = "sttrb",
		[0x01] = "sttrh",
		[0x02] = "sttr",
		[0x03] = "sttr",
		[0x10] = "ldtrb",
		[0x11] = "ldtrh",
		[0x12] = "ldtr",
		[0x13] = "ldtr",
		[0x20] = "ldtrsb",
		[0x21] = "ldtrsh",
		[0x22] = "ldtrsw",
		[0x30] = "ldtrsb",
		[0x31] = "ldtrsh",
	};
	return (opc_size < R_ARRAY_SIZE (inst_names))? inst_names[opc_size]: NULL;
}

// Helper to append memory instruction with optional add prefix
static void append_mem_instr(RStrBuf *sb, ut64 addr, bool is_adrp, ut32 reg, ut64 target, ut32 reg2, ut32 aoff, const char *inst, const char *rs, ut32 dest_reg, ut64 offset, const char *suffix) {
	if (aoff) {
		r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; add x%u, x%u, %#x; %s %s%u, [x%u, %#" PFMT64x "%s\n", addr, is_adrp? "adrp": "adr", reg, target, reg2, reg, aoff, inst, rs, dest_reg, reg2, offset, suffix);
	} else {
		r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; %s %s%u, [x%u, %#" PFMT64x "%s\n", addr, is_adrp? "adrp": "adr", reg, target, inst, rs, dest_reg, reg2, offset, suffix);
	}
}

// Helper to append signed offset memory instruction
static void append_signed_mem_instr(RStrBuf *sb, ut64 addr, bool is_adrp, ut32 reg, ut64 target, ut32 reg2, ut32 aoff, const char *inst, const char *rs, ut32 dest_reg, int64_t soff, const char *suffix) {
	const char *sign = soff < 0? "-": "";
	if (aoff) {
		r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; add x%u, x%u, %#x; %s %s%u, [x%u, %s%" PFMT64d "%s\n", addr, is_adrp? "adrp": "adr", reg, target, reg2, reg, aoff, inst, rs, dest_reg, reg2, sign, (st64)soff, suffix);
	} else {
		r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; %s %s%u, [x%u, %s%" PFMT64d "%s\n", addr, is_adrp? "adrp": "adr", reg, target, inst, rs, dest_reg, reg2, sign, (st64)soff, suffix);
	}
}

static void siguza_xrefs_chunked(RAnal *anal, RStrBuf *sb, bool register_refs, ut64 search, const ut8 *mem, ut64 addr, int process_len, int mem_len) {
	const ut8 *p = mem;
	const ut8 *e = mem + (mem_len & ~3);
	const ut8 *pe = mem + (process_len & ~3);

	for (; p < pe; p += 4, addr += 4) {
		ut32 v = r_read_le32 (p);
		if ((v & 0x1f000000) == 0x10000000) // adr and adrp
		{
			ut32 reg = v & 0x1f;
			bool is_adrp = (v & 0x80000000) != 0;
			int64_t base = is_adrp? (addr & 0xfffffffffffff000): addr;
			int64_t off = (int64_t) ((uint64_t) ((((v >> 5) & 0x7ffff) << 2) | ((v >> 29) & 0x3)) << 43) >> (is_adrp? 31: 43);
			ut64 target = base + off;
			bool found_stub = handle_stub_island (anal, sb, register_refs, search, p, e, addr, is_adrp, reg, target);
			if (register_refs) {
				addref (anal, addr, target, R_ANAL_REF_TYPE_DATA);
			} else if (found_stub) {
				continue;
			} else if (target == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "\n", addr, is_adrp? "adrp": "adr", reg, target);
			} else {
				// More complicated cases - up to 3 instr
				const ut8 *q = p + 4;
				while (q < e && r_read_le32 (q) == 0xd503201f) { // nop
					q += 4;
				}
				if (q < e) {
					v = r_read_le32 (q);
					ut32 reg2 = reg;
					ut32 aoff = 0;
					bool found = false;
					if ((v & 0xff8003e0) == (0x91000000 | (reg << 5))) { // 64bit add, match reg
						reg2 = v & 0x1f;
						aoff = (v >> 10) & 0xfff;
						if (v & 0x400000) {
							aoff <<= 12;
						}
						if (target + aoff == search) {
							r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; add x%u, x%u, %#x\n", addr, is_adrp? "adrp": "adr", reg, target, reg2, reg, aoff);
							found = true;
						} else {
							do {
								q += 4;
							} while (q < e && r_read_le32 (q) == 0xd503201f); // nop
						}
					}
					if (!found && q < e) {
						v = r_read_le32 (q);
						if ((v & 0xff8003e0) == (0x91000000 | (reg2 << 5))) { // 64bit add, match reg
							ut32 xoff = (v >> 10) & 0xfff;
							if (v & 0x400000) {
								xoff <<= 12;
							}
							if (target + aoff + xoff == search) {
								// If we get here, we know the previous add matched
								r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "; add x%u, x%u, %#x; add x%u, x%u, %#x\n", addr, is_adrp? "adrp": "adr", reg, target, reg2, reg, aoff, v & 0x1f, reg2, xoff);
							}
						} else if ((v & 0x3e0003e0) == (0x38000000 | (reg2 << 5))) { // all of str[hb]/ldr[hb], match reg
							uint8_t size = (v >> 30) & 0x3;
							uint8_t opc = (v >> 22) & 0x3;
							uint32_t opc_size = (opc << 4) | size;
							const char *inst = lookup_inst_name (opc_size);

							if (inst) {
								uint8_t regsize = opc == 2 && size < 2? 3: size;
								const char *rs = regsize == 3? "x": "w";
								if ((v & 0x1000000) != 0) { // unsigned offset
									ut64 uoff = ((v >> 10) & 0xfff) << size;
									if (target + aoff + uoff == search) {
										append_mem_instr (sb, addr, is_adrp, reg, target, reg2, aoff, inst, rs, v & 0x1f, uoff, "]");
									}
								} else if ((v & 0x00200000) == 0) {
									int64_t soff = (int64_t) ((uint64_t) ((v >> 12) & 0x1ff) << 55) >> 55;
									if (target + aoff + soff == search) {
										if ((v & 0x400) == 0) {
											if ((v & 0x800) == 0) { // unscaled
												inst = lookup_unscaled_inst_name (opc_size);
											} else { // unprivileged
												inst = lookup_unprivileged_inst_name (opc_size);
											}
											if (inst) {
												if ((v & 0x400) != 0) { // pre/post-index
													const char *suffix = (v & 0x800) != 0? "]!": "]";
													append_signed_mem_instr (sb, addr, is_adrp, reg, target, reg2, aoff, inst, rs, v & 0x1f, soff, suffix);
												} else { // unscaled/unprivileged
													append_signed_mem_instr (sb, addr, is_adrp, reg, target, reg2, aoff, inst, rs, v & 0x1f, soff, "]");
												}
											}
										}
									}
								}
							}
						}
						// TODO: pairs, SIMD ldr/str, atomics
					}
				}
			}
		} else if ((v & 0xbf000000) == 0x18000000 || (v & 0xff000000) == 0x98000000) { // ldr and ldrsw literal
			int64_t off = (int64_t) ((uint64_t) ((v >> 5) & 0x7ffff) << 45) >> 43;
			if (register_refs) {
				addref (anal, addr, addr + off, R_ANAL_REF_TYPE_DATA);
			} else if (addr + off == search) {
				ut32 reg = v & 0x1f;
				bool is_ldrsw = (v & 0xff000000) == 0x98000000;
				bool is_64bit = (v & 0x40000000) != 0 && !is_ldrsw;
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %s%u, %#" PFMT64x "\n", addr, is_ldrsw? "ldrsw": "ldr", is_64bit? "x": "w", reg, search);
			}
		} else if ((v & 0x7c000000) == 0x14000000) { // b and bl
			int64_t off = (int64_t) ((uint64_t) (v & 0x3ffffff) << 38) >> 36;
			bool is_bl = (v & 0x80000000) != 0;
			if (register_refs) {
				addref (anal, addr, addr + off, is_bl? R_ANAL_REF_TYPE_CODE: R_ANAL_REF_TYPE_CALL);
			} else if (addr + off == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %#" PFMT64x "\n", addr, is_bl? "bl": "b", search);
			}
		} else if ((v & 0xff000010) == 0x54000000) { // b.cond
			int64_t off = (int64_t) ((uint64_t) ((v >> 5) & 0x7ffff) << 45) >> 43;
			if (register_refs) {
				addref (anal, addr, addr + off, R_ANAL_REF_TYPE_CODE);
			} else if (addr + off == search) {
				static const char *cond_names[] = {
					"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
				};
				const char *cond = cond_names[v & 0xf];
				r_strbuf_appendf (sb, "%#" PFMT64x ": b.%s %#" PFMT64x "\n", addr, cond, search);
			}
		} else if ((v & 0x7e000000) == 0x34000000) { // cbz and cbnz
			int64_t off = (int64_t) ((uint64_t) ((v >> 5) & 0x7ffff) << 45) >> 43;
			if (register_refs) {
				addref (anal, addr, addr + off, R_ANAL_REF_TYPE_CODE);
			} else if (addr + off == search) {
				ut32 reg = v & 0x1f;
				bool is_64bit = (v & 0x80000000) != 0;
				bool is_nz = (v & 0x01000000) != 0;
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %s%u, %#" PFMT64x "\n", addr, is_nz? "cbnz": "cbz", is_64bit? "x": "w", reg, search);
			}
		} else if ((v & 0x7e000000) == 0x36000000) { // tbz and tbnz
			int64_t off = ((int64_t) ((v >> 5) & 0x3fff) << 50) >> 48;
			if (register_refs) {
				addref (anal, addr, addr + off, R_ANAL_REF_TYPE_CODE);
			} else if (addr + off == search) {
				ut32 reg = v & 0x1f;
				ut32 bit = ((v >> 19) & 0x1f) | ((v >> 26) & 0x20);
				bool is_64bit = bit > 31;
				bool is_nz = (v & 0x01000000) != 0;
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %s%u, %u, %#" PFMT64x "\n", addr, is_nz? "tbnz": "tbz", is_64bit? "x": "w", reg, bit, search);
			}
		}
	}
}

/**
 * @param register_refs Register every discovered xref instead of listing matches.
 * @param search Address to find xrefs to when register_refs is false.
 * @param start Address at which to start looking for xrefs.
 * @param lenbytes Reach of the search for xrefs, in bytes.
 */
static void siguza_xrefs(RAnal *anal, RStrBuf *sb, bool register_refs, ut64 search, ut64 start, ut64 lenbytes) {
	ut8 *buf = malloc (SIX_CHUNK_SIZE + SIX_LOOKAHEAD_SIZE);
	if (!buf) {
		R_LOG_ERROR ("Failed to allocate buffer");
		return;
	}

	ut64 pos = 0;
	while (pos < lenbytes) {
		int process_len = (int)R_MIN (lenbytes - pos, SIX_CHUNK_SIZE);
		ut64 lookahead_rem = lenbytes - pos - process_len;
		int to_read = process_len + (int)R_MIN (lookahead_rem, SIX_LOOKAHEAD_SIZE);
		if (anal->iob.read_at (anal->iob.io, start + pos, buf, to_read) < 1) {
			break;
		}
		if (process_len < 4) {
			break;
		}
		siguza_xrefs_chunked (anal, sb, register_refs, search, buf, start + pos, process_len, to_read);
		pos += process_len;
	}
	free (buf);
}

static bool siguza_xrefs_current_map(RAnal *anal, RStrBuf *sb, bool register_refs, ut64 search, ut64 offset, ut64 len, bool has_len) {
	RIOMap *map = anal->iob.map_get_at? anal->iob.map_get_at (anal->iob.io, offset): NULL;
	if (!map || ! (map->perm & R_PERM_X)) {
		return false;
	}
	ut64 start = has_len? offset: r_io_map_begin (map);
	ut64 end = r_io_map_end (map);
	if (end <= start) {
		return false;
	}
	ut64 max_len = end - start;
	if (!has_len || len > max_len) {
		len = max_len;
	}
	siguza_xrefs (anal, sb, register_refs, search, start, len);
	return true;
}

static bool is_arm64(RAnal *anal) {
	const char *arch = anal->coreb.cfgGet (anal->coreb.core, "asm.arch");
	const int bits = anal->coreb.cfgGetI (anal->coreb.core, "asm.bits");
	return arch && strstr (arch, "arm") && bits == 64;
}

static char *six_help(void) {
	return strdup (
		"| a:six              find and register all xrefs in arm64 executable sections or current map\n"
		"| a:six <target>     list xrefs to target address in arm64 executable sections\n"
		"| a:six <target> <len> list xrefs to target address from $$ in current executable section\n");
}

static bool parse_num(RAnal *anal, RCore *core, const char *arg, const char *name, ut64 *out) {
	const char *err = NULL;
	if (anal->coreb.numGet) {
		if (core && core->num) {
			core->num->nc.errors = 0;
			core->num->nc.calc_err = NULL;
		}
		*out = anal->coreb.numGet (anal->coreb.core, arg);
		if (core && core->num) {
			err = core->num->nc.calc_err;
		}
	} else {
		*out = r_num_math_err (core? core->num: NULL, arg, &err);
	}
	if (err) {
		R_LOG_ERROR ("Invalid %s '%s': %s", name, arg, err);
		return false;
	}
	return true;
}

static char *r_cmdsix_call(RAnal *anal, const char *input) {
	if (!r_str_startswith (input, SIX_CMD)) {
		return NULL;
	}
	char ch = input[strlen (SIX_CMD)];
	if (ch && ch != '?' && ch != ' ') {
		R_LOG_ERROR ("Invalid command 'a:%s'. See 'a:six?' for help", input);
		return strdup ("");
	}
	input = input + strlen (SIX_CMD);
	if (*input == '?' || *r_str_trim_head_ro (input) == '?') {
		return six_help ();
	}

	if (!is_arm64 (anal)) {
		R_LOG_ERROR ("This command only works on arm64. Please check your asm.{arch,bits}");
		return strdup ("");
	}

	ut64 search = 0;
	ut64 len = 0;
	bool has_len = false;
	RCore *core = (RCore *)anal->coreb.core;
	input = r_str_trim_head_ro (input);
	bool register_refs = R_STR_ISEMPTY (input);
	if (!register_refs) {
		int argc = 0;
		char **argv = r_str_argv (input, &argc);
		if (!argv) {
			return strdup ("");
		}
		if (argc < 1 || argc > 2) {
			R_LOG_ERROR ("Usage: a:six [target] [len]");
			r_str_argv_free (argv);
			return strdup ("");
		}
		if (!parse_num (anal, core, argv[0], "target", &search)) {
			r_str_argv_free (argv);
			return strdup ("");
		}
		if (argc == 2) {
			if (!parse_num (anal, core, argv[1], "length", &len)) {
				r_str_argv_free (argv);
				return strdup ("");
			}
			if (!len) {
				R_LOG_ERROR ("Length must be greater than zero");
				r_str_argv_free (argv);
				return strdup ("");
			}
			has_len = true;
		}
		r_str_argv_free (argv);
	}

	RStrBuf *sb = register_refs? NULL: r_strbuf_new (NULL);
	if (!register_refs && !sb) {
		return strdup ("");
	}

	if (!has_len) {
		bool scanned = false;
		if (anal->binb.get_sections_vec) {
			RVecRBinSection *sections = anal->binb.get_sections_vec (anal->binb.bin);
			if (sections) {
				RBinSection *s;

				R_VEC_FOREACH (sections, s) {
					if (s->is_segment || ! (s->perm & R_PERM_X)) {
						continue;
					}
					siguza_xrefs (anal, sb, register_refs, search, s->vaddr, s->vsize);
					scanned = true;
				}
			}
		}
		if (!scanned) {
			ut64 offset = anal->coreb.numGet (anal->coreb.core, "$$");
			if (!siguza_xrefs_current_map (anal, sb, register_refs, search, offset, 0, false)) {
				R_LOG_ERROR ("No executable sections found");
				r_strbuf_free (sb);
				return strdup ("");
			}
		}
	} else {
		ut64 offset = anal->coreb.numGet (anal->coreb.core, "$$");
		if (offset & 3) {
			offset -= offset % 4;
			R_LOG_INFO ("Current offset is not 4-byte aligned, using 0x%" PFMT64x " instead", offset);
		}

		RBinSection *s = anal->binb.get_vsect_at? anal->binb.get_vsect_at (anal->binb.bin, offset): NULL;
		if (!s) {
			if (!siguza_xrefs_current_map (anal, sb, register_refs, search, offset, len, true)) {
				R_LOG_WARN ("Current section is not executable");
				r_strbuf_free (sb);
				return strdup ("");
			}
		} else {
			if (! (s->perm & R_PERM_X)) {
				R_LOG_WARN ("Current section is not executable");
				r_strbuf_free (sb);
				return strdup ("");
			}

			ut64 sect_end = s->vaddr + s->vsize;
			if (sect_end < s->vaddr || offset >= sect_end) {
				R_LOG_WARN ("Current section has invalid boundaries");
				r_strbuf_free (sb);
				return strdup ("");
			}
			ut64 max_len = sect_end - offset;
			if (len > max_len) {
				len = max_len;
				R_LOG_WARN ("Length is not within range for this section, using 0x%" PFMT64x " instead", len);
			}

			siguza_xrefs (anal, sb, register_refs, search, offset, len);
		}
	}

	if (register_refs) {
		return strdup ("");
	}
	char *result = r_strbuf_drain (sb);
	if (!result) {
		return strdup ("");
	}
	r_str_trim (result);
	return result;
}

static int six_eligible(RAnal *anal) {
	const char *arch = anal->config? anal->config->arch: NULL;
	if (!arch || !strstr (arch, "arm") || anal->config->bits != 64) {
		return -1;
	}
	return 0;
}

static bool six_pre_analysis(RAnal *anal) {
	if (six_eligible (anal) < 0) {
		return false;
	}
	bool scanned = false;
	if (anal->binb.get_sections_vec) {
		RVecRBinSection *sections = anal->binb.get_sections_vec (anal->binb.bin);
		if (sections) {
			RBinSection *s;

			R_VEC_FOREACH (sections, s) {
				if (s->is_segment || ! (s->perm & R_PERM_X)) {
					continue;
				}
				siguza_xrefs (anal, NULL, true, 0, s->vaddr, s->vsize);
				scanned = true;
			}
		}
	}
	if (!scanned && anal->coreb.numGet) {
		ut64 offset = anal->coreb.numGet (anal->coreb.core, "$$");
		scanned = siguza_xrefs_current_map (anal, NULL, true, 0, offset, 0, false);
	}
	return scanned;
}

RAnalPlugin r_anal_plugin_six = {
	.meta = {
		.name = "six",
		.desc = "quickly find xrefs in arm64 buffer (siguza's x-ref)",
		.author = "Siguza",
		.license = "MIT",
	},
	.cmd = r_cmdsix_call,
	.eligible = six_eligible,
	.pre_analysis = six_pre_analysis,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_six,
	.version = R2_VERSION
};
#endif
