/* radare - LGPL - Copyright 2021-2026 - Siguza, pancake, hot3eed */

// Context: https://raw.githubusercontent.com/Siguza/misc/master/xref.c

#include <r_anal.h>
#include <r_core.h>
#include "../refsearch.h"

#define SIX_CMD "six"
#define SIX_CHUNK_SIZE 0x10000
// call mode decodes single instructions: no lookahead, and bigger reads since each
// read has a fixed cost on targets with many maps (dyld caches)
#define SIX_CALLS_CHUNK_SIZE 0x100000
#define SIX_LOOKAHEAD_SIZE 0x1000
#define SIX_ARM64_NOP 0xd503201f

static const ut8 *skip_nops(const ut8 *p, const ut8 *end) {
	while (end - p >= 4 && r_read_le32 (p) == SIX_ARM64_NOP) {
		p += 4;
	}
	return p;
}

static const ut8 *resolve_stub(const ut8 *p, const ut8 *end, ut32 reg, ut64 *target) {
	p = skip_nops (p, end);
	if (reg == 31 || end - p < 4) {
		return NULL;
	}
	ut32 insn = r_read_le32 (p);
	if ((insn & 0xff8003e0) == (0x91000000 | (reg << 5))) { // ADD immediate
		*target += (ut64)((insn >> 10) & 0xfff) << ((insn & 0x400000)? 12: 0);
		reg = insn & 31;
		p = skip_nops (p + 4, end);
	} else if ((insn & 0xff800000) == 0xd2800000) { // MOVZ + ADD shifted register
		ut32 add_reg = insn & 31;
		if (add_reg == reg || add_reg == 31) {
			return NULL;
		}
		ut64 add = (ut64)((insn >> 5) & 0xffff) << (((insn >> 21) & 3) * 16);
		p = skip_nops (p + 4, end);
		if (end - p < 4) {
			return NULL;
		}
		insn = r_read_le32 (p);
		if ((insn & 0xffff03e0) != (0x8b000000 | (add_reg << 16) | (reg << 5))) {
			return NULL;
		}
		*target += add << ((insn >> 10) & 63);
		reg = insn & 31;
		p = skip_nops (p + 4, end);
	}
	return reg != 31 && !(*target & 3) && end - p >= 4 && r_read_le32 (p) == (0xd61f0000 | (reg << 5))? p: NULL;
}

typedef struct {
	RAnal *anal;
	RStrBuf *sb;
	RefSearch *refs;
	const RBreakBind *brk;
	ut64 search;
	bool register_refs;
	bool islands;
	bool calls;
} SixScan;

static inline void six_ref(const SixScan *ss, ut64 from, ut64 to, RAnalRefType type) {
	if (ss->register_refs) {
		r_anal_xrefs_set (ss->anal, from, to, type);
	} else {
		refsearch_emit (ss->refs, from, to, type);
	}
}

static inline bool six_is_branch(ut32 v, ut64 addr, ut64 *dst, bool *is_call) {
	if ((v & 0x7c000000) != 0x14000000) {
		return false;
	}
	*dst = refsearch_arm64_branch_target (v, addr);
	*is_call = (v & 0x80000000) != 0;
	return true;
}

static inline void six_call_ref(const SixScan *ss, ut32 v, ut64 addr) {
	ut64 dst;
	bool is_call;
	if (!six_is_branch (v, addr, &dst, &is_call)) {
		return;
	}
	// tail calls only count against explicit targets, otherwise every jump would be a ref
	if (!is_call && RVecRefSearchRange_empty (&ss->refs->ranges)) {
		return;
	}
	if (ss->register_refs && !refsearch_matches (ss->refs, dst)) {
		return;
	}
	// a b to a target is a tail call: JUMP, as core analysis records tail calls
	six_ref (ss, addr, dst, is_call? R_ANAL_REF_TYPE_CALL: R_ANAL_REF_TYPE_JUMP);
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

// address built by adr/adrp plus up to two add and a load/store immediate, the page when none follow
static ut64 adrp_resolve(const ut8 *p, const ut8 *e, ut32 reg, ut64 target, ut64 *adds) {
	int i;
	for (i = 0; i < 2; i++) {
		p = skip_nops (p, e);
		if (e - p < 4) {
			return target;
		}
		const ut32 v = r_read_le32 (p);
		if ((v & 0xff8003e0) != (0x91000000 | (reg << 5))) { // 64bit add, match reg
			break;
		}
		target += (ut64)((v >> 10) & 0xfff) << ((v & 0x400000)? 12: 0);
		if (adds) {
			adds[i] = target;
		}
		reg = v & 0x1f;
		p += 4;
	}
	p = skip_nops (p, e);
	if (e - p < 4) {
		return target;
	}
	const ut32 v = r_read_le32 (p);
	if ((v & 0x3e0003e0) != (0x38000000 | (reg << 5))) { // all of str[hb]/ldr[hb], match reg
		return target;
	}
	const ut32 size = (v >> 30) & 0x3;
	if (!lookup_inst_name ((((v >> 22) & 0x3) << 4) | size)) {
		return target;
	}
	if (v & 0x1000000) { // unsigned offset
		return target + (((v >> 10) & 0xfff) << size);
	}
	if (!(v & 0x00200000) && !(v & 0x400)) { // unscaled/unprivileged
		return target + ((st64)((ut64)((v >> 12) & 0x1ff) << 55) >> 55);
	}
	return target;
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

static void siguza_xrefs_chunked(const SixScan *ss, const ut8 *mem, ut64 addr, int process_len, int mem_len) {
	RAnal *anal = ss->anal;
	RStrBuf *sb = ss->sb;
	const bool register_refs = ss->register_refs;
	const bool emit_refs = register_refs || ss->refs;
	const bool list_intermediates = !register_refs && ss->refs && !RVecRefSearchRange_empty (&ss->refs->ranges);
	const bool islands = ss->islands;
	const ut64 search = ss->search;
	const ut8 *p = mem;
	const ut8 *e = mem + (mem_len & ~3);
	const ut8 *pe = mem + (process_len & ~3);
	ut64 dst;
	bool is_call;

	for (; p < pe; p += 4, addr += 4) {
		ut32 v = r_read_le32 (p);
		if (ss->calls) {
			six_call_ref (ss, v, addr);
			continue;
		}
		if ((v & 0x1f000000) == 0x10000000) // adr and adrp
		{
			ut32 reg = v & 0x1f;
			bool is_adrp = (v & 0x80000000) != 0;
			int64_t base = is_adrp? (addr & 0xfffffffffffff000): addr;
			int64_t off = (int64_t) ((uint64_t) ((((v >> 5) & 0x7ffff) << 2) | ((v >> 29) & 0x3)) << 43) >> (is_adrp? 31: 43);
			ut64 target = base + off;
			ut64 jump = target;
			const ut8 *branch = islands? resolve_stub (p + 4, e, reg, &jump): NULL;
			if (branch) {
				ut64 branch_addr = addr + (branch - p);
				if (register_refs) {
					six_ref (ss, branch_addr, jump, R_ANAL_REF_TYPE_CODE);
					r_anal_hint_set_type (anal, branch_addr, R_ANAL_OP_TYPE_JMP);
					r_anal_hint_set_jump (anal, branch_addr, jump);
				} else if (jump == search) {
					r_strbuf_appendf (sb, "%#" PFMT64x ": br x%u; %#" PFMT64x "\n", branch_addr, (r_read_le32 (branch) >> 5) & 31, jump);
				}
			}
			if (emit_refs) {
				ut64 candidates[] = { target, UT64_MAX, UT64_MAX };
				const ut64 resolved = adrp_resolve (p + 4, e, reg, target, list_intermediates? candidates + 1: NULL);
				if (list_intermediates) {
					ut64 previous = UT64_MAX;
					size_t i;
					for (i = 0; i < R_ARRAY_SIZE (candidates); i++) {
						const ut64 candidate = candidates[i];
						if (candidate != previous && candidate != resolved) {
							six_ref (ss, addr, candidate, R_ANAL_REF_TYPE_DATA);
						}
						previous = candidate;
					}
				}
				six_ref (ss, addr, resolved, R_ANAL_REF_TYPE_DATA);
			} else if (target == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s x%u, %#" PFMT64x "\n", addr, is_adrp? "adrp": "adr", reg, target);
			} else {
				// More complicated cases - up to 3 instr
				const ut8 *q = skip_nops (p + 4, e);
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
							q = skip_nops (q + 4, e);
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
			if (emit_refs) {
				six_ref (ss, addr, addr + off, R_ANAL_REF_TYPE_DATA);
			} else if (addr + off == search) {
				ut32 reg = v & 0x1f;
				bool is_ldrsw = (v & 0xff000000) == 0x98000000;
				bool is_64bit = (v & 0x40000000) != 0 && !is_ldrsw;
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %s%u, %#" PFMT64x "\n", addr, is_ldrsw? "ldrsw": "ldr", is_64bit? "x": "w", reg, search);
			}
		} else if (six_is_branch (v, addr, &dst, &is_call)) { // b and bl
			if (emit_refs) {
				// a plain b is a code ref, like the conditional branches below
				six_ref (ss, addr, dst, is_call? R_ANAL_REF_TYPE_CALL: R_ANAL_REF_TYPE_CODE);
			} else if (dst == search) {
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %#" PFMT64x "\n", addr, is_call? "bl": "b", search);
			}
		} else if ((v & 0xff000010) == 0x54000000) { // b.cond
			int64_t off = (int64_t) ((uint64_t) ((v >> 5) & 0x7ffff) << 45) >> 43;
			if (emit_refs) {
				six_ref (ss, addr, addr + off, R_ANAL_REF_TYPE_CODE);
			} else if (addr + off == search) {
				static const char *cond_names[] = {
					"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
				};
				const char *cond = cond_names[v & 0xf];
				r_strbuf_appendf (sb, "%#" PFMT64x ": b.%s %#" PFMT64x "\n", addr, cond, search);
			}
		} else if ((v & 0x7e000000) == 0x34000000) { // cbz and cbnz
			int64_t off = (int64_t) ((uint64_t) ((v >> 5) & 0x7ffff) << 45) >> 43;
			if (emit_refs) {
				six_ref (ss, addr, addr + off, R_ANAL_REF_TYPE_CODE);
			} else if (addr + off == search) {
				ut32 reg = v & 0x1f;
				bool is_64bit = (v & 0x80000000) != 0;
				bool is_nz = (v & 0x01000000) != 0;
				r_strbuf_appendf (sb, "%#" PFMT64x ": %s %s%u, %#" PFMT64x "\n", addr, is_nz? "cbnz": "cbz", is_64bit? "x": "w", reg, search);
			}
		} else if ((v & 0x7e000000) == 0x36000000) { // tbz and tbnz
			int64_t off = ((int64_t) ((v >> 5) & 0x3fff) << 50) >> 48;
			if (emit_refs) {
				six_ref (ss, addr, addr + off, R_ANAL_REF_TYPE_CODE);
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
static bool six_stopped(const SixScan *ss) {
	return ss->brk && (refsearch_stopped (ss->refs) || r_break_check (ss->brk));
}

static void siguza_xrefs(const SixScan *ss, ut64 start, ut64 lenbytes) {
	RAnal *anal = ss->anal;
	if (six_stopped (ss)) {
		return;
	}
	const int chunk = ss->calls? SIX_CALLS_CHUNK_SIZE: SIX_CHUNK_SIZE;
	const int lookahead = ss->calls? 0: SIX_LOOKAHEAD_SIZE;
	ut8 *buf = malloc (chunk + lookahead);
	if (!buf) {
		R_LOG_ERROR ("Failed to allocate buffer");
		if (ss->refs) {
			ss->refs->failed = true;
		}
		return;
	}

	ut64 pos = (ss->islands || ss->calls || ss->brk)? (4 - (start & 3)) & 3: 0;
	while (pos < lenbytes && !six_stopped (ss)) {
		int process_len = (int)R_MIN (lenbytes - pos, chunk);
		ut64 lookahead_rem = lenbytes - pos - process_len;
		int to_read = process_len + (int)R_MIN (lookahead_rem, lookahead);
		int got = anal->iob.read_at (anal->iob.io, start + pos, buf, to_read);
		if (got < 0) {
			got = 0;
		}
		// a short read (end of file, unmapped gap) still scans the complete
		// instructions it returned, with lookahead bounded by the bytes read
		const bool short_read = got < to_read;
		if (short_read) {
			to_read = got;
			process_len = R_MIN (process_len, got);
		}
		if (process_len < 4) {
			break;
		}
		siguza_xrefs_chunked (ss, buf, start + pos, process_len, to_read);
		if (short_read && process_len == got) {
			break;
		}
		pos += process_len;
	}
	free (buf);
}

static bool is_arm64(RAnal *anal) {
	const char *arch = anal->coreb.cfgGet (anal->coreb.core, "asm.arch");
	const int bits = anal->coreb.cfgGetI (anal->coreb.core, "asm.bits");
	return arch && strstr (arch, "arm") && bits == 64;
}

static char *six_help(void) {
	return strdup (
		"| a:six                 register xrefs in arm64 executable sections or current map\n"
		"| a:sixi                also resolve stub islands and install jump hints (opt-in)\n"
		"| a:six[i] <target>     list xrefs to target address without changing xrefs or hints\n"
		"| a:six[i] <target> <len> list xrefs to target from $$ in current executable section or map\n"
		"| a:sixc <from> <to> [targets...] register call xrefs (bl, and b when targets are given) in [from, to)\n"
		"| a:sixl[j] [targets...] list code and data xrefs in executable I/O bank regions\n"
		"| a:sixcl[j] <from> <to> [targets...] list call xrefs, or unique bl destinations with no targets\n"
		"| Listing targets accept address expressions, inclusive A..B ranges and names from sym.imp. or reloc. flags\n");
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

static void six_scan_range(const SixScan *ss, RIO *io, ut64 from, ut64 to, int perm) {
	// Keep instructions that straddle adjacent maps.
	RInterval itv = { from, to - from };
	RVecRIORegion *regions = (io && io->va)? r_io_bank_get_regions (io, io->bank, itv): NULL;
	if (regions) {
		ut64 run_lo = 0, run_hi = 0;
		RIORegion *r;
		R_VEC_FOREACH (regions, r) {
			const ut64 end = r_itv_end (r->itv);
			const ut64 lo = R_MAX (r->itv.addr, from);
			const ut64 hi = (end < r->itv.addr)? to: R_MIN (end, to);
			if (hi <= lo || (r->perm & perm) != perm) {
				continue;
			}
			if (run_hi > run_lo && lo == run_hi) {
				run_hi = hi;
				continue;
			}
			if (run_hi > run_lo) {
				siguza_xrefs (ss, run_lo, run_hi - run_lo);
			}
			run_lo = lo;
			run_hi = hi;
		}
		if (run_hi > run_lo) {
			siguza_xrefs (ss, run_lo, run_hi - run_lo);
		}
		RVecRIORegion_free (regions);
	} else if (perm == R_PERM_R || !io->va) {
		siguza_xrefs (ss, from, to - from);
	}
}

static bool six_parse_targets(RAnal *anal, RCore *core, RefSearch *search, char **words, int count, bool listing) {
	static const char *const prefixes[] = { "sym.imp.", "reloc." };
	int i;
	for (i = 0; i < count; i++) {
		char *word = words[i];
		if (!listing) {
			ut64 addr;
			if (!parse_num (anal, core, word, "target", &addr)
					|| !refsearch_add_range (&search->ranges, (RefSearchRange){addr, addr})) {
				return false;
			}
			continue;
		}
		const char *name = word;
		size_t j;
		for (j = 0; j < R_ARRAY_SIZE (prefixes); j++) {
			if (r_str_startswith (name, prefixes[j])) {
				name += strlen (prefixes[j]);
				break;
			}
		}
		RefSearchRange range;
		const bool bounds = strstr (word, "..") != NULL;
		if ((name == word || bounds) && refsearch_parse_range (core->num, word, &range)) {
			if (!refsearch_add_range (&search->ranges, range)) {
				return false;
			}
			continue;
		}
		bool found = false;
		if (*name && !bounds) {
			for (j = 0; j < R_ARRAY_SIZE (prefixes); j++) {
				char *key = r_str_newf ("%s%s", prefixes[j], name);
				RFlagItem *flag = r_flag_get (core->flags, key);
				free (key);
				if (flag) {
					found = true;
					if (!refsearch_add_range (&search->ranges, (RefSearchRange){flag->addr, flag->addr})) {
						return false;
					}
				}
			}
		}
		if (!found) {
			R_LOG_ERROR ("Invalid target '%s'", word);
			return false;
		}
	}
	return true;
}

static char *six_scan_cmd(RAnal *anal, const char *args, bool calls, bool listing) {
	const bool json = listing && *args == 'j';
	args += json;
	if (*args && *args != '?' && (listing? !isspace ((ut8)*args): *args != ' ')) {
		R_LOG_ERROR ("Invalid command 'a:six%s%s%s'. See 'a:six?' for help",
			calls? "c": "", listing? "l": "", args - json);
		return strdup (json? "[]": "");
	}
	args = r_str_trim_head_ro (args);
	if (*args == '?') {
		return six_help ();
	}
	RCore *core = anal->coreb.core;
	if (!is_arm64 (anal) || (listing && !core)) {
		if (!listing) {
			return NULL;
		}
		R_LOG_ERROR ("This command only works on arm64. Please check your asm.{arch,bits}");
		return strdup (json? "[]": "");
	}
	RIO *io = core? core->io: NULL;
	int argc = 0;
	char **argv = *args? r_str_argv (args, &argc): NULL;
	const int first = calls? 2: 0;
	ut64 from = 0;
	ut64 to = !calls && !io->va? r_io_size (io): UT64_MAX;
	bool ok = (!*args || argv) && argc >= first;
	if (!ok && calls) {
		R_LOG_ERROR ("Usage: %s", listing? "a:sixcl[j] <from> <to> [targets...]": "a:sixc <from> <to> [target ..]");
	}
	if (ok && calls) {
		ok = parse_num (anal, core, argv[0], "from", &from)
			&& parse_num (anal, core, argv[1], "to", &to);
		if (ok && listing && to <= from) {
			R_LOG_ERROR ("The scan end must be greater than the start");
		}
	}
	RStrBuf text = {0};
	RefSearch search = { .text = &text };
	if (ok && argc > first) {
		ok = six_parse_targets (anal, core, &search, argv + first, argc - first, listing);
	}
	r_str_argv_free (argv);
	if (json) {
		search.json = anal->coreb.pjWithEncoding? anal->coreb.pjWithEncoding (core): pj_new ();
		pj_a (search.json);
	}
	if (ok && listing && calls && argc == first) {
		search.seen = ht_uu_new0 ();
		ok = search.seen != NULL;
	}
	const RBreakBind brk = listing? r_cons_break_bind (core->cons): (RBreakBind){0};
	if (ok && to > from && r_break_begin (&brk)) {
		refsearch_ranges_sort (&search.ranges);
		const SixScan ss = {
			.anal = anal, .refs = &search, .brk = listing? &brk: NULL, .calls = calls, .register_refs = !listing,
		};
		six_scan_range (&ss, io, from, to, calls? R_PERM_R: R_PERM_RX);
		r_break_end (&brk);
	}
	refsearch_finish (&search);
	if (json) {
		return pj_drain (search.json);
	}
	char *result = r_strbuf_drain_nofree (&text);
	r_str_trim (result);
	return result;
}

static char *r_cmdsix_call(RAnal *anal, const char *input) {
	if (!r_str_startswith (input, SIX_CMD)) {
		return NULL;
	}
	size_t cmd_len = strlen (SIX_CMD);
	if (input[cmd_len] == 'l') {
		return six_scan_cmd (anal, input + cmd_len + 1, false, true);
	}
	if (input[cmd_len] == 'c') {
		const bool listing = input[cmd_len + 1] == 'l';
		return six_scan_cmd (anal, input + cmd_len + 1 + listing, true, listing);
	}
	bool islands = input[cmd_len] == 'i';
	if (islands) {
		cmd_len++;
	}
	char ch = input[cmd_len];
	if (ch && ch != '?' && ch != ' ') {
		R_LOG_ERROR ("Invalid command 'a:%s'. See 'a:six?' for help", input);
		return strdup ("");
	}
	input += cmd_len;
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
			R_LOG_ERROR ("Usage: a:six%s [target] [len]", islands? "i": "");
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
	const SixScan ss = {
		.anal = anal,
		.sb = sb,
		.register_refs = register_refs,
		.islands = islands,
		.search = search,
	};

	bool scanned = false;
	RVecRBinSection *sections = anal->binb.get_sections_vec? anal->binb.get_sections_vec (anal->binb.bin): NULL;
	if (!has_len && sections) {
		RBinSection *s;
		R_VEC_FOREACH (sections, s) {
			if (!s->is_segment && (s->perm & R_PERM_X)) {
				siguza_xrefs (&ss, s->vaddr, s->vsize);
				scanned = true;
			}
		}
	}
	if (!scanned) {
		ut64 offset = anal->coreb.numGet (anal->coreb.core, "$$");
		if (has_len && (offset & 3)) {
			offset &= ~3ULL;
			R_LOG_INFO ("Current offset is not 4-byte aligned, using 0x%" PFMT64x " instead", offset);
		}
		RBinSection *s = has_len && anal->binb.get_vsect_at? anal->binb.get_vsect_at (anal->binb.bin, offset): NULL;
		RIOMap *map = !s && anal->iob.map_get_at? anal->iob.map_get_at (anal->iob.io, offset): NULL;
		ut64 start = s? s->vaddr: map? r_io_map_begin (map): offset;
		ut64 end = s? s->vaddr + s->vsize: map? r_io_map_end (map): offset;
		int perm = s? s->perm: map? map->perm: 0;
		if (!(perm & R_PERM_X) || end <= start || offset < start || offset >= end) {
			R_LOG_WARN ("Current section or map is not executable or has invalid boundaries");
			r_strbuf_free (sb);
			return strdup ("");
		}
		if (!has_len) {
			offset = start;
			len = end - start;
		} else if (len > end - offset) {
			len = end - offset;
			R_LOG_WARN ("Length is not within range for this section, using 0x%" PFMT64x " instead", len);
		}
		siguza_xrefs (&ss, offset, len);
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
