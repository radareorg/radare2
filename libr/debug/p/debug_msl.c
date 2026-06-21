/* radare - LGPL - Copyright 2026 - memslicer */

// Debug backend for Memory Slice (.msl) process memory dumps.
//
// A .msl is a static snapshot, so "execution" is driven by emulation: this
// backend wires the standard debugger commands (ds / dso / dc / dr) onto
// radare2's ESIL engine. On attach it initializes the ESIL VM and seeds the
// full register file from the Current thread's Thread Context block (0x0011),
// so stepping resumes from the real captured CPU state.
//
// Usage:  r2 -d msl://dump.msl      (or:  r2 dump.msl; e dbg.backend=msl; ood)
//
// Memory comes from the maps created by the bin/io plugins; this backend only
// provides registers + stepping. MVP scope: uncompressed, unencrypted slices.

#include <r_core.h>
#include <r_debug.h>

#define MSL_FILE_MAGIC "MEMSLICE"
#define MSL_BLOCK_MAGIC "MSLC"
#define MSL_HDR_FLAG_ENCRYPTED 0x4
#define MSL_BT_THREAD_CONTEXT 0x0011
#define MSL_BT_END_OF_CAPTURE 0x0FFF
#define MSL_BLOCK_HEADER_SIZE 80
#define MSL_THREAD_FLAG_CURRENT 0x1

static inline ut64 msl_pad8(ut64 n) {
	return (n + 7) & ~(ut64)7;
}

static const char *msl_arch_str(ut16 arch, int *bits) {
	switch (arch) {
	case 0: *bits = 32; return "x86";
	case 1: *bits = 64; return "x86";
	case 2: *bits = 64; return "arm";
	case 3: *bits = 32; return "arm";
	case 4: *bits = 32; return "mips";
	case 5: *bits = 64; return "mips";
	case 8: *bits = 32; return "ppc";
	case 9: *bits = 64; return "ppc";
	default: *bits = 64; return "x86";
	}
}

// Seed core->anal->reg from the Thread Context register file of the open
// buffer. Prefers the Current thread; falls back to the first thread context.
static void msl_seed_regs(RCore *core, RBuffer *b) {
	RReg *reg = core->anal->reg;
	ut8 h[16];
	if (r_buf_read_at (b, 0, h, sizeof (h)) != sizeof (h)) {
		return;
	}
	ut64 fsize = r_buf_size (b);
	ut64 off = h[9];
	while (off + MSL_BLOCK_HEADER_SIZE <= fsize) {
		ut8 bh[MSL_BLOCK_HEADER_SIZE];
		if (r_buf_read_at (b, off, bh, sizeof (bh)) != sizeof (bh) || memcmp (bh, MSL_BLOCK_MAGIC, 4)) {
			break;
		}
		ut16 btype = r_read_le16 (bh + 4);
		ut32 blen = r_read_le32 (bh + 8);
		if (blen < MSL_BLOCK_HEADER_SIZE) {
			break;
		}
		if (btype == MSL_BT_THREAD_CONTEXT) {
			ut8 th[32];
			if (r_buf_read_at (b, off + MSL_BLOCK_HEADER_SIZE, th, sizeof (th)) == sizeof (th)) {
				ut16 tflags = r_read_le16 (th + 16);
				ut32 regcount = r_read_le32 (th + 20);
				ut16 namelen = r_read_le16 (th + 24);
				ut64 ro = off + MSL_BLOCK_HEADER_SIZE + 32 + msl_pad8 (namelen);
				ut32 i;
				for (i = 0; i < regcount; i++) {
					ut8 e[8];
					if (r_buf_read_at (b, ro, e, sizeof (e)) != sizeof (e)) {
						break;
					}
					ut8 rnamelen = e[0];
					ut8 width = e[1];
					char name[64] = {0};
					if (rnamelen > 0 && rnamelen < sizeof (name)) {
						r_buf_read_at (b, ro + 8, (ut8 *)name, rnamelen);
						name[sizeof (name) - 1] = 0;
					}
					ut8 v[8] = {0};
					int n = (width > 8)? 8: width;
					r_buf_read_at (b, ro + 8 + msl_pad8 (rnamelen), v, n);
					if (*name) {
						RRegItem *ri = r_reg_get (reg, name, -1);
						if (ri) {
							r_reg_set_value (reg, ri, r_read_le64 (v));
						}
					}
					ro += 8 + msl_pad8 (rnamelen) + msl_pad8 (width);
				}
				if (tflags & MSL_THREAD_FLAG_CURRENT) {
					break; // Current thread wins; stop here
				}
			}
		} else if (btype == MSL_BT_END_OF_CAPTURE) {
			break;
		}
		off += blen;
	}
	r_unref (b);
}

// One-time-per-core initialization: set up the ESIL VM, seed the register
// file from the Thread Context, and seek to the captured PC. Tracked by core
// pointer so reopening a different slice re-initializes.
static void *g_inited_core = NULL;

static void msl_ensure(RDebug *dbg) {
	RCore *core = dbg->coreb.core;
	if (!core || g_inited_core == core) {
		return;
	}
	g_inited_core = core;
	dbg->pid = 1;
	dbg->tid = 1;
	// Force hard stepping: r_debug_step must call our plugin->step (which
	// drives ESIL), not the software-breakpoint step_soft path which assumes
	// a real process. Set the struct field directly so it takes effect before
	// the first `ds` (the cached config value would apply too late).
	dbg->options.swstep = false;
	const char *path = (core->io && core->io->desc)? core->io->desc->name: NULL;
	if (!path) {
		return;
	}
	if (r_str_startswith (path, "msl://")) {
		path += strlen ("msl://");
	}
	RBuffer *b = r_buf_new_mmap (path, R_PERM_R);
	if (!b) {
		return;
	}
	ut8 h[16];
	if (r_buf_read_at (b, 0, h, sizeof (h)) != sizeof (h) || memcmp (h, MSL_FILE_MAGIC, 8)
			|| (r_read_le32 (h + 12) & MSL_HDR_FLAG_ENCRYPTED)) {
		r_unref (b);
		return;
	}
	// Set the architecture from the file header BEFORE initializing ESIL, so
	// the register profile matches (over msl:// there is no bin to do this).
	ut8 ab[4];
	if (r_buf_read_at (b, 0x30, ab, sizeof (ab)) == sizeof (ab) && dbg->coreb.cmdf) {
		int bits = 64;
		const char *arch = msl_arch_str (r_read_le16 (ab + 2), &bits);
		dbg->coreb.cmdf (core, "e asm.arch=%s", arch);
		dbg->coreb.cmdf (core, "e asm.bits=%d", bits);
	}
	// Capture ESIL writes into the io cache (the dump itself is read-only)
	// and step via the plugin (hard step) rather than software breakpoints.
	dbg->coreb.cmd (core, "e io.cache=true");
	dbg->coreb.cmd (core, "e dbg.swstep=false");
	// Safety net: a snapshot has no program exit, and unmapped fetches read
	// back as the fill byte (which decodes as instructions), so `dc`/`aec`
	// without a breakpoint would run forever. Bound it; override with
	// `e esil.maxsteps=0` for unlimited.
	dbg->coreb.cmd (core, "e esil.maxsteps=1000000");
	// Enable ESIL step-back recording (reverse/time-travel debugging via
	// dsb/aesb). The config callback only applies once esil.reg exists, i.e.
	// after aei, so (re)set it here.
	dbg->coreb.cmd (core, "e esil.maxbacksteps=256");
	// Follow the PC after each step (the default 32-byte threshold leaves the
	// seek behind for small instructions).
	dbg->coreb.cmd (core, "e dbg.follow=1");
	// The emulator is the source of truth for registers; r2's debug trace
	// would re-read PC at sync points and fight the ESIL state.
	if (dbg->trace) {
		dbg->trace->enabled = false;
	}
	dbg->coreb.cmd (core, "aei");
	// The debugger register arena was built with the host arch at startup;
	// rebuild it with the (now arch-correct) anal/ESIL profile so that
	// dr / trace_pc read the right register slots.
	char *prof = r_anal_get_reg_profile (core->anal);
	if (prof) {
		r_reg_set_profile_string (dbg->reg, prof);
		free (prof);
	}
	msl_seed_regs (core, b);
	r_unref (b);
	// Seek to the captured program counter.
	const char *pcname = r_reg_alias_getname (core->anal->reg, R_REG_ALIAS_PC);
	if (pcname && dbg->coreb.cmdf) {
		RRegItem *pc = r_reg_get (core->anal->reg, pcname, -1);
		if (pc) {
			dbg->coreb.cmdf (core, "s 0x%"PFMT64x, r_reg_get_value (core->anal->reg, pc));
		}
	}
	// Pull the seeded ESIL/anal register state into the debugger arena so the
	// r_debug step machinery (PC, trace) sees the captured values.
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, false);
	// Route ds/dso/dc to the ESIL stepper: with cfg.debug set, those commands
	// go through r_debug_step (arena swap + trace + recoil) which assumes a
	// live ptrace process and breaks on a static, emulated snapshot. With it
	// cleared, the debug command handlers dispatch to ESIL (aes/aec) instead.
	dbg->coreb.cmd (core, "e cfg.debug=false");
}

static bool __msl_attach(RDebug *dbg, int pid) {
	RCore *core = dbg->coreb.core;
	if (!core) {
		return false;
	}
	g_inited_core = NULL; // force re-init on explicit attach
	msl_ensure (dbg);
	return true;
}

static bool __msl_detach(RDebug *dbg, int pid) {
	return true;
}

static bool __msl_step(RDebug *dbg) {
	RCore *core = dbg->coreb.core;
	if (!core) {
		return false;
	}
	msl_ensure (dbg);
	// r2 re-enables these when entering debug mode (after attach); keep them
	// off at step time so ESIL stepping isn't fought by trace/software-step.
	if (dbg->trace) {
		dbg->trace->enabled = false;
	}
	dbg->options.swstep = false;
	dbg->coreb.cmd (core, "aes");
	return true;
}

static bool __msl_step_over(RDebug *dbg) {
	RCore *core = dbg->coreb.core;
	if (!core) {
		return false;
	}
	msl_ensure (dbg);
	dbg->coreb.cmd (core, "aeso");
	return true;
}

static bool __msl_continue(RDebug *dbg, int pid, int tid, int sig) {
	RCore *core = dbg->coreb.core;
	if (!core) {
		return false;
	}
	msl_ensure (dbg);
	// ESIL continue: runs until a breakpoint, trap or invalid instruction.
	dbg->coreb.cmd (core, "aec");
	return true;
}

static RDebugReasonType __msl_wait(RDebug *dbg, int pid) {
	return R_DEBUG_REASON_NONE;
}

static char *__msl_reg_profile(RDebug *dbg) {
	return r_anal_get_reg_profile (dbg->anal);
}

// Expose the captured memory regions as debug maps (so dm/om work and `dgm`
// can re-dump). Uncompressed regions only.
static RList *__msl_map_get(RDebug *dbg) {
	RCore *core = dbg->coreb.core;
	const char *path = (core && core->io && core->io->desc)? core->io->desc->name: NULL;
	if (!path) {
		return NULL;
	}
	if (r_str_startswith (path, "msl://")) {
		path += strlen ("msl://");
	}
	RBuffer *b = r_buf_new_mmap (path, R_PERM_R);
	if (!b) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_debug_map_free);
	ut8 h[16];
	if (r_buf_read_at (b, 0, h, sizeof (h)) != sizeof (h) || memcmp (h, MSL_FILE_MAGIC, 8)
			|| (r_read_le32 (h + 12) & MSL_HDR_FLAG_ENCRYPTED)) {
		r_unref (b);
		return list;
	}
	ut64 fsize = r_buf_size (b);
	ut64 off = h[9];
	while (off + MSL_BLOCK_HEADER_SIZE <= fsize) {
		ut8 bh[MSL_BLOCK_HEADER_SIZE];
		if (r_buf_read_at (b, off, bh, sizeof (bh)) != sizeof (bh) || memcmp (bh, MSL_BLOCK_MAGIC, 4)) {
			break;
		}
		ut16 btype = r_read_le16 (bh + 4);
		ut16 bflags = r_read_le16 (bh + 6);
		ut32 blen = r_read_le32 (bh + 8);
		if (blen < MSL_BLOCK_HEADER_SIZE) {
			break;
		}
		if (btype == 0x0001 && !(bflags & 1)) {  // uncompressed Memory Region
			ut8 p[32];
			if (r_buf_read_at (b, off + MSL_BLOCK_HEADER_SIZE, p, sizeof (p)) == sizeof (p)) {
				ut64 base = r_read_le64 (p);
				ut64 size = r_read_le64 (p + 8);
				ut8 prot = p[16];
				int perm = ((prot & 1)? R_PERM_R: 0) | ((prot & 2)? R_PERM_W: 0)
					| ((prot & 4)? R_PERM_X: 0);
				char *nm = strdup ("msl");
				RDebugMap *m = r_debug_map_new (nm, base, base + size, perm, 0);
				free (nm);
				if (m) {
					r_list_append (list, m);
				}
			}
		}
		if (btype == 0x0FFF) {
			break;
		}
		off += blen;
	}
	r_unref (b);
	return list;
}

// Mirror the ESIL/anal register arena so `dr` reflects emulation progress.
static bool __msl_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	RCore *core = dbg->coreb.core;
	msl_ensure (dbg);
	RReg *reg = (core && core->anal)? core->anal->reg: dbg->reg;
	int sz = 0;
	ut8 *bytes = r_reg_get_bytes (reg, type, &sz);
	if (!bytes) {
		return false;
	}
	memcpy (buf, bytes, R_MIN (size, sz));
	free (bytes);
	return true;
}

static bool __msl_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	RCore *core = dbg->coreb.core;
	RReg *reg = (core && core->anal)? core->anal->reg: dbg->reg;
	return r_reg_set_bytes (reg, type, buf, size);
}

RDebugPlugin r_debug_plugin_msl = {
	.meta = {
		.name = "msl",
		.author = "memslicer",
		.desc = "Memory Slice (.msl) emulated debug backend (ESIL)",
		.license = "LGPL-3.0-only",
	},
	.arch = "any",
	.bits = R_SYS_BITS_PACK2 (32, 64),
	.canstep = 1,
	.attach = &__msl_attach,
	.detach = &__msl_detach,
	.step = &__msl_step,
	.step_over = &__msl_step_over,
	.cont = &__msl_continue,
	.wait = &__msl_wait,
	.reg_profile = &__msl_reg_profile,
	.reg_read = &__msl_reg_read,
	.reg_write = &__msl_reg_write,
	.map_get = &__msl_map_get,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_msl,
	.version = R2_VERSION
};
#endif
