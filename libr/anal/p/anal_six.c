/* radare - LGPL - Copyright 2021-2026 - Siguza, pancake, hot3eed */

// Context: https://raw.githubusercontent.com/Siguza/misc/master/xref.c

#include <r_anal.h>
#include <r_core.h>

static void addref(RAnal *anal, ut64 from, ut64 to, RAnalRefType type) {
	r_anal_xrefs_set (anal, from, to, type);
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

static void siguza_xrefs_chunked(RAnal *anal, RStrBuf *sb, ut64 search, const ut8 *mem, ut64 addr, int lenbytes) {
	ut32 *p = (ut32 *) ((uint8_t *)mem);
	ut32 *e = (ut32 *) (p + (lenbytes / 4));

	for (; p < e; p++, addr += 4) {
		ut32 v = *p;
		if ((v & 0x1f000000) == 0x10000000) // adr and adrp
		{
			ut32 reg = v & 0x1f;
			bool is_adrp = (v & 0x80000000) != 0;
			int64_t base = is_adrp? (addr & 0xfffffffffffff000): addr;
			int64_t off = (int64_t) ((uint64_t) ((((v >> 5) & 0x7ffff) << 2) | ((v >> 29) & 0x3)) << 43) >> (is_adrp? 31: 43);
			ut64 target = base + off;
			if (search == 0) {
				addref (anal, addr, target, R_ANAL_REF_TYPE_DATA);
			} else if (target == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "\n", addr, is_adrp? "adrp": "adr", reg, target);
			} else {
				// More complicated cases - up to 3 instr
				ut32 *q = p + 1;
				while (q < e && *q == 0xd503201f) { // nop
					q++;
				}
				if (q < e) {
					v = *q;
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
								q++;
							} while (q < e && *q == 0xd503201f); // nop
						}
					}
					if (!found && q < e) {
						v = *q;
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
			if (!search) {
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
			if (!search) {
				addref (anal, addr, addr + off, is_bl? R_ANAL_REF_TYPE_CODE: R_ANAL_REF_TYPE_CALL);
			} else if (addr + off == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %#" PFMT64x "\n", addr, is_bl? "bl": "b", search);
			}
		} else if ((v & 0xff000010) == 0x54000000) { // b.cond
			int64_t off = (int64_t) ((uint64_t) ((v >> 5) & 0x7ffff) << 45) >> 43;
			if (!search) {
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
			if (!search) {
				addref (anal, addr, addr + off, R_ANAL_REF_TYPE_CODE);
			} else if (addr + off == search) {
				ut32 reg = v & 0x1f;
				bool is_64bit = (v & 0x80000000) != 0;
				bool is_nz = (v & 0x01000000) != 0;
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %s%u, %#" PFMT64x "\n", addr, is_nz? "cbnz": "cbz", is_64bit? "x": "w", reg, search);
			}
		} else if ((v & 0x7e000000) == 0x36000000) { // tbz and tbnz
			int64_t off = ((int64_t) ((v >> 5) & 0x3fff) << 50) >> 48;
			if (!search) {
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
 * @param search Address to find xrefs to. If 0, all xrefs will be emitted.
 * @param start Address at which to start looking for xrefs.
 * @param lenbytes Reach of the search for xrefs, in bytes.
 */
static void siguza_xrefs(RAnal *anal, RStrBuf *sb, ut64 search, ut64 start, int lenbytes) {
	ut64 cursor = start;
	int lenbytes_rem = lenbytes;
	ut8 *big_buf = malloc (lenbytes);
	if (!big_buf) {
		R_LOG_ERROR ("Failed to allocate buffer");
		return;
	}

	int total_read = 0;
	while (lenbytes_rem > 0 && total_read < lenbytes) {
		int to_read = R_MIN (lenbytes_rem, 0x1000);
		int read_len = anal->iob.read_at (anal->iob.io, cursor, big_buf + total_read, to_read);
		if (read_len <= 0) {
			break;
		}
		total_read += read_len;
		lenbytes_rem -= read_len;
		cursor += read_len;
	}

	if (total_read > 0) {
		siguza_xrefs_chunked (anal, sb, search, big_buf, start, total_read);
	}
	free (big_buf);
}

static bool is_arm64(RAnal *anal) {
	const char *arch = anal->coreb.cfgGet (anal->coreb.core, "asm.arch");
	const int bits = anal->coreb.cfgGetI (anal->coreb.core, "asm.bits");
	return strstr (arch, "arm") && bits == 64;
}

static char *r_cmdsix_call(RAnal *anal, const char *input) {
	if (!r_str_startswith (input, "six")) {
		return NULL;
	}
	input = r_str_trim_head_ro (input + strlen ("six"));

	if (*input == '?') {
		const char *help = "Usage: a:six [addr] [len] - Find xrefs in arm64 executable sections\n"
				"       a:six - find all xrefs\n"
				"       a:six <addr> [len] - find xrefs to specific address\n";
		return strdup (help);
	}

	if (!is_arm64 (anal)) {
		R_LOG_ERROR ("This command only works on arm64. Please check your asm.{arch,bits}");
		return strdup ("");
	}

	RStrBuf *sb = r_strbuf_new (NULL);
	if (!sb) {
		return strdup ("");
	}

	ut64 search = 0;
	int len = 0;
	void *core = anal->coreb.core;

	char *args = strdup (input);
	char *space = strchr (args, ' ');
	if (space) {
		*space++ = 0;
		len = anal->coreb.numGet (core, space);
	}
	search = anal->coreb.numGet (core, args);
	free (args);

	if (len == 0) {
		if (!anal->binb.get_sections) {
			R_LOG_ERROR ("No get_sections callback available");
			r_strbuf_free (sb);
			return strdup ("");
		}
		RList *sections = anal->binb.get_sections (anal->binb.bin);
		if (!sections) {
			R_LOG_ERROR ("No executable sections found");
			r_strbuf_free (sb);
			return strdup ("");
		}

		RBinSection *s;
		RListIter *iter;

		r_list_foreach (sections, iter, s) {
			if (s->is_segment || ! (s->perm & R_PERM_X)) {
				continue;
			}
			siguza_xrefs (anal, sb, search, s->vaddr, s->vsize);
		}
	} else {
		ut64 offset = anal->coreb.numGet (core, "$$");
		if (offset & 3) {
			offset -= offset % 4;
			R_LOG_INFO ("Current offset is not 4-byte aligned, using 0x%" PFMT64x " instaed", offset);
		}

		RBinSection *s = anal->binb.get_vsect_at? anal->binb.get_vsect_at (anal->binb.bin, offset): NULL;
		if (!s || ! (s->perm & R_PERM_X)) {
			R_LOG_WARN ("Current section is not executable");
			r_strbuf_free (sb);
			return strdup ("");
		}

		ut64 sect_end = s->vaddr + s->vsize;
		if (offset + len > sect_end || offset + len < s->vaddr) {
			len = sect_end - offset;
			R_LOG_WARN ("Length is not within range for this section, using %u instead", len);
		}

		siguza_xrefs (anal, sb, search, offset, len);
	}

	char *result = r_strbuf_drain (sb);
	if (!result) {
		return strdup ("");
	}
	r_str_trim (result);
	return result;
}

RAnalPlugin r_anal_plugin_six = {
	.meta = {
		.name = "six",
		.desc = "quickly find xrefs in arm64 buffer (siguza's x-ref)",
		.author = "Siguza",
		.license = "MIT",
	},
	.cmd = r_cmdsix_call,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_six,
	.version = R2_VERSION
};
#endif
