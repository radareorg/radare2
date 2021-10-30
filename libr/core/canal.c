/* radare - LGPL - Copyright 2009-2021 - pancake, nibble */

#include <r_types.h>
#include <r_list.h>
#include <r_flag.h>
#include <r_core.h>
#include <r_bin.h>
#include <ht_uu.h>
#include <r_util/r_graph_drawable.h>

#include <string.h>

HEAPTYPE (ut64);

// used to speedup strcmp with rconfig.get in loops
enum {
	R2_ARCH_THUMB,
	R2_ARCH_ARM32,
	R2_ARCH_ARM64,
	R2_ARCH_MIPS
};
// 128M
#define MAX_SCAN_SIZE 0x7ffffff

static void loganal(ut64 from, ut64 to, int depth) {
	r_cons_clear_line (1);
	eprintf ("0x%08"PFMT64x" > 0x%08"PFMT64x" %d\r", from, to, depth);
}

static int cmpsize(const void *a, const void *b) {
	ut64 as = r_anal_function_linear_size ((RAnalFunction *) a);
	ut64 bs = r_anal_function_linear_size ((RAnalFunction *) b);
	return (as> bs)? 1: (as< bs)? -1: 0;
}

static int cmpfcncc(const void *_a, const void *_b) {
	RAnalFunction *a = (RAnalFunction *)_a;
	RAnalFunction *b = (RAnalFunction *)_b;
	ut64 as = r_anal_function_complexity (a);
	ut64 bs = r_anal_function_complexity (b);
	return (as > bs)? 1: (as < bs)? -1: 0;
}

static int cmpedges(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int as, bs;
	r_anal_function_count_edges (a, &as);
	r_anal_function_count_edges (b, &bs);
	return (as > bs)? 1: (as < bs)? -1: 0;
}

static int cmpframe(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int as = a->maxstack;
	int bs = b->maxstack;
	return (as > bs)? 1: (as < bs)? -1: 0;
}

static int cmpxrefs(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int as = a->meta.numrefs;
	int bs = b->meta.numrefs;
	return (as > bs)? 1: (as < bs)? -1: 0;
}

static int cmpname(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int as = strcmp (a->name, b->name);
	int bs = strcmp (b->name, a->name);
	return (as > bs)? 1: (as < bs)? -1: 0;
}

static int cmpcalls(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	int as = a->meta.numcallrefs;
	int bs = b->meta.numcallrefs;
	return (as > bs)? 1: (as < bs)? -1: 0;
}

static int cmpnbbs(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	ut64 as = r_list_length (a->bbs);
	ut64 bs = r_list_length (b->bbs);
	return (as> bs)? 1: (as< bs)? -1: 0;
}

static int cmpaddr(const void *_a, const void *_b) {
	const RAnalFunction *a = _a, *b = _b;
	return (a->addr > b->addr)? 1: (a->addr < b->addr)? -1: 0;
}

static char *get_function_name(RCore *core, ut64 addr) {
	RBinFile *bf = r_bin_cur (core->bin);
	if (bf && bf->o) {
		RBinSymbol *sym = ht_up_find (bf->o->addr2klassmethod, addr, NULL);
		if (sym && sym->classname && sym->name) {
			return r_str_newf ("method.%s.%s", sym->classname, sym->name);
		}
	}
	RFlagItem *flag = r_core_flag_get_by_spaces (core->flags, addr);
	return (flag && flag->name) ? strdup (flag->name) : NULL;
}

static RCore *mycore = NULL;

// XXX: copypaste from anal/data.c
#define MINLEN 1
static int is_string(const ut8 *buf, int size, int *len) {
	int i, fakeLen = 0;
	if (size < 1) {
		return 0;
	}
	if (!len) {
		len = &fakeLen;
	}
	if (size > 3 && buf[0] && !buf[1] && buf[2] && !buf[3]) {
		*len = 1; // XXX: TODO: Measure wide string length
		return 2; // is wide
	}
	for (i = 0; i < size; i++) {
		if (!buf[i] && i > MINLEN) {
			*len = i;
			return 1;
		}
		if (buf[i] == 10 || buf[i] == 13 || buf[i] == 9) {
			continue;
		}
		if (buf[i] < 32 || buf[i] > 127) {
			// not ascii text
			return 0;
		}
		if (!IS_PRINTABLE (buf[i])) {
			*len = i;
			return 0;
		}
	}
	*len = i;
	return 1;
}

static char *is_string_at(RCore *core, ut64 addr, int *olen) {
	ut8 rstr[128] = {0};
	int ret = 0, len = 0;
	ut8 *str = calloc (256, 1);
	if (!str) {
		if (olen) {
			*olen = 0;
		}
		return NULL;
	}
	r_io_read_at (core->io, addr, str, 255);

	str[255] = 0;
	if (is_string (str, 256, &len)) {
		if (olen) {
			*olen = len;
		}
		return (char*) str;
	}

	ut64 *cstr = (ut64*)str;
	ut64 lowptr = cstr[0];
	if (lowptr >> 32) { // must be pa mode only
		lowptr &= UT32_MAX;
	}
	// cstring
	if (cstr[0] == 0 && cstr[1] < 0x1000) {
		ut64 ptr = cstr[2];
		if (ptr >> 32) { // must be pa mode only
			ptr &= UT32_MAX;
		}
		if (ptr) {
			r_io_read_at (core->io, ptr, rstr, sizeof (rstr));
			rstr[127] = 0;
			ret = is_string (rstr, 128, &len);
			if (ret) {
				strcpy ((char*) str, (char*) rstr);
				if (olen) {
					*olen = len;
				}
				return (char*) str;
			}
		}
	} else {
		// pstring
		r_io_read_at (core->io, lowptr, rstr, sizeof (rstr));
		rstr[127] = 0;
		ret = is_string (rstr, sizeof (rstr), &len);
		if (ret) {
			strcpy ((char*) str, (char*) rstr);
			if (olen) {
				*olen = len;
			}
			return (char*) str;
		}
	}
	// check if current section have no exec bit
	if (len < 1) {
		ret = 0;
		free (str);
		len = -1;
	} else if (olen) {
		*olen = len;
	}
	// NOTE: coverity says that ret is always 0 here, so str is dead code
	return ret? (char *)str: NULL;
}

/* returns the R_ANAL_ADDR_TYPE_* of the address 'addr' */
R_API ut64 r_core_anal_address(RCore *core, ut64 addr) {
	ut64 types = 0;
	RRegSet *rs = NULL;
	if (!core) {
		return 0;
	}
	if (core->dbg && core->dbg->reg) {
		rs = r_reg_regset_get (core->dbg->reg, R_REG_TYPE_GPR);
	}
	if (rs) {
		RRegItem *r;
		RListIter *iter;
		r_list_foreach (rs->regs, iter, r) {
			if (r->type == R_REG_TYPE_GPR) {
				ut64 val = r_reg_getv(core->dbg->reg, r->name);
				if (addr == val) {
					types |= R_ANAL_ADDR_TYPE_REG;
					break;
				}
			}
		}
	}
	if (r_flag_get_i (core->flags, addr)) {
		types |= R_ANAL_ADDR_TYPE_FLAG;
	}
	if (r_anal_get_fcn_in (core->anal, addr, 0)) {
		types |= R_ANAL_ADDR_TYPE_FUNC;
	}
	// check registers
	if (core->bin && core->dbg && r_config_get_b (core->config, "cfg.debug")) {
		RDebugMap *map;
		RListIter *iter;
		// use 'dm'
		// XXX: this line makes r2 debugging MUCH slower
		// r_debug_map_sync (core->dbg);
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				if (map->name && map->name[0] == '/') {
					if (core->io && core->io->desc &&
						core->io->desc->name &&
						!strcmp (map->name,
							 core->io->desc->name)) {
						types |= R_ANAL_ADDR_TYPE_PROGRAM;
					} else {
						types |= R_ANAL_ADDR_TYPE_LIBRARY;
					}
				}
				if (map->perm & R_PERM_X) {
					types |= R_ANAL_ADDR_TYPE_EXEC;
				}
				if (map->perm & R_PERM_R) {
					types |= R_ANAL_ADDR_TYPE_READ;
				}
				if (map->perm & R_PERM_W) {
					types |= R_ANAL_ADDR_TYPE_WRITE;
				}
				// find function
				if (map->name && strstr (map->name, "heap")) {
					types |= R_ANAL_ADDR_TYPE_HEAP;
				}
				if (map->name && strstr (map->name, "stack")) {
					types |= R_ANAL_ADDR_TYPE_STACK;
				}
				break;
			}
		}
	} else {
		int _perm = -1;
		if (core->io) {
			// sections
			RIOBank *bank = r_io_bank_get (core->io, core->io->bank);
			if (bank) {
				RIOMapRef *mapref;
				RListIter *iter;
				r_list_foreach (bank->maprefs, iter, mapref) {
					RIOMap *s = r_io_map_get (core->io, mapref->id);
					if (addr >= s->itv.addr && addr < (s->itv.addr + s->itv.size)) {
						// sections overlap, so we want to get the one with lower perms
						_perm = (_perm != -1) ? R_MIN (_perm, s->perm) : s->perm;
						// TODO: we should identify which maps come from the program or other
						//types |= R_ANAL_ADDR_TYPE_PROGRAM;
						// find function those sections should be created by hand or esil init
						if (s->name && strstr (s->name, "heap")) {
							types |= R_ANAL_ADDR_TYPE_HEAP;
						}
						if (s->name && strstr (s->name, "stack")) {
							types |= R_ANAL_ADDR_TYPE_STACK;
						}
					}
				}
			}
		}
		if (_perm != -1) {
			if (_perm & R_PERM_X) {
				types |= R_ANAL_ADDR_TYPE_EXEC;
			}
			if (_perm & R_PERM_R) {
				types |= R_ANAL_ADDR_TYPE_READ;
			}
			if (_perm & R_PERM_W) {
				types |= R_ANAL_ADDR_TYPE_WRITE;
			}
		}
	}

	// check if it's ascii
	if (addr != 0) {
		int not_ascii = 0;
		int i, failed_sequence, dir, on;
		for (i = 0; i < 8; i++) {
			ut8 n = (addr >> (i * 8)) & 0xff;
			if (n && !IS_PRINTABLE (n)) {
				not_ascii = 1;
			}
		}
		if (!not_ascii) {
			types |= R_ANAL_ADDR_TYPE_ASCII;
		}
		failed_sequence = 0;
		dir = on = -1;
		for (i = 0; i < 8; i++) {
			ut8 n = (addr >> (i * 8)) & 0xff;
			if (on != -1) {
				if (dir == -1) {
					dir = (n > on)? 1: -1;
				}
				if (n == on + dir) {
					// ok
				} else {
					failed_sequence = 1;
					break;
				}
			}
			on = n;
		}
		if (!failed_sequence) {
			types |= R_ANAL_ADDR_TYPE_SEQUENCE;
		}
	}
	return types;
}

static bool blacklisted_word(char* name) {
	const char * list[] = {
		"__stack_chk_guard",
		"__stderrp",
		"__stdinp",
		"__stdoutp",
		"_DefaultRuneLocale"
	};
	int i;
	for (i = 0; i < sizeof (list) / sizeof (list[0]); i++) {
		if (strstr (name, list[i])) { return true; }
	}
	return false;
}

static char *anal_fcn_autoname(RCore *core, RAnalFunction *fcn, int dump, int mode) {
	int use_getopt = 0;
	int use_isatty = 0;
	PJ *pj = NULL;
	char *do_call = NULL;
	RAnalRef *ref;
	RListIter *iter;
	RList *refs = r_anal_function_get_refs (fcn);
	if (mode == 'j') {
		// start a new JSON object
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	if (refs) {
		r_list_foreach (refs, iter, ref) {
			RFlagItem *f = r_flag_get_i (core->flags, ref->addr);
			if (f) {
				// If dump is true, print all strings referenced by the function
				if (dump) {
					// take only strings flags
					if (!strncmp (f->name, "str.", 4)) {
						if (mode == 'j') {
							// add new json item
							pj_o (pj);
							pj_kn (pj, "addr", ref->at);
							pj_kn (pj, "ref", ref->addr);
							pj_ks (pj, "flag", f->name);
							pj_end (pj);
						} else {
							r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %s\n", ref->at, ref->addr, f->name);
						}
					}
				} else if (do_call) { // break if a proper autoname found and not in dump mode
					break;
				}
				// enter only if a candidate name hasn't found yet
				if (!do_call) {
					if (blacklisted_word (f->name)) {
						continue;
					}
					if (strstr (f->name, ".isatty")) {
						use_isatty = 1;
					}
					if (strstr (f->name, ".getopt")) {
						use_getopt = 1;
					}
					if (!strncmp (f->name, "method.", 7)) {
						free (do_call);
						do_call = strdup (f->name + 7);
						continue;
					}
					if (!strncmp (f->name, "str.", 4)) {
						free (do_call);
						do_call = strdup (f->name + 4);
						continue;
					}
					if (!strncmp (f->name, "dbg.", 4)) {
						free (do_call);
						do_call = strdup (f->name + 4);
						continue;
					}
					if (!strncmp (f->name, "sym.imp.", 8)) {
						free (do_call);
						do_call = strdup (f->name + 8);
						continue;
					}
					if (!strncmp (f->name, "reloc.", 6)) {
						free (do_call);
						do_call = strdup (f->name + 6);
						continue;
					}
				}
			}
		}
		r_list_free (refs);
	}
	if (mode ==  'j') {
		pj_end (pj);
	}
	if (pj) {
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	// TODO: append counter if name already exists
	if (use_getopt) {
		RFlagItem *item = r_flag_get (core->flags, "main");
		free (do_call);
		// if referenced from entrypoint. this should be main
		if (item && item->offset == fcn->addr) {
			return strdup ("main"); // main?
		}
		return strdup ("parse_args"); // main?
	}
	if (use_isatty) {
		char *ret = r_str_newf ("sub.setup_tty_%s_%"PFMT64x, do_call, fcn->addr);
		free (do_call);
		return ret;
	}
	if (do_call) {
		char *ret = r_str_newf ("sub.%s_%"PFMT64x, do_call, fcn->addr);
		free (do_call);
		return ret;
	}
	return NULL;
}

/*this only autoname those function that start with fcn.* or sym.func.* */
R_API void r_core_anal_autoname_all_fcns(RCore *core) {
	RListIter *it;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, it, fcn) {
		if (!strncmp (fcn->name, "fcn.", 4) || !strncmp (fcn->name, "sym.func.", 9)) {
			RFlagItem *item = r_flag_get (core->flags, fcn->name);
			if (item) {
				char *name = anal_fcn_autoname (core, fcn, 0, 0);
				if (name) {
					r_flag_rename (core->flags, item, name);
					free (fcn->name);
					fcn->name = name;
				}
			} else {
				// there should always be a flag for a function
				r_warn_if_reached ();
			}
		}
	}
}

/* reads .gopclntab section in go binaries to recover function names
   and adds them as sym.go.* flags */
R_API void r_core_anal_autoname_all_golang_fcns(RCore *core) {
	RList* section_list = r_bin_get_sections (core->bin);
	RListIter *iter;
	const char* oldstr = NULL;
	RBinSection *section;
	ut64 gopclntab = 0;
	r_list_foreach (section_list, iter, section) {
		if (strstr (section->name, ".gopclntab")) {
			gopclntab = section->vaddr;
			break;
		}
	}
	if (!gopclntab) {
		oldstr = r_print_rowlog (core->print, "Could not find .gopclntab section");
		r_print_rowlog_done (core->print, oldstr);
		return;
	}
	int ptr_size = core->anal->bits / 8;
	ut64 offset = gopclntab + 2 * ptr_size;
	ut64 size_offset = gopclntab + 3 * ptr_size ;
	ut8 temp_size[4] = {0};
	if (!r_io_nread_at (core->io, size_offset, temp_size, 4)) {
		return;
	}
	ut32 size = r_read_le32 (temp_size);
	int num_syms = 0;
	//r_cons_print ("[x] Reading .gopclntab...\n");
	r_flag_space_push (core->flags, R_FLAGS_FS_SYMBOLS);
	while (offset < gopclntab + size) {
		ut8 temp_delta[4] = {0};
		ut8 temp_func_addr[4] = {0};
		ut8 temp_func_name[4] = {0};
		if (!r_io_nread_at (core->io, offset + ptr_size, temp_delta, 4)) {
			break;
		}
		ut32 delta = r_read_le32 (temp_delta);
		ut64 func_offset = gopclntab + delta;
		if (!r_io_nread_at (core->io, func_offset, temp_func_addr, 4) ||
			!r_io_nread_at (core->io, func_offset + ptr_size, temp_func_name, 4)) {
			break;
		}
		ut32 func_addr = r_read_le32 (temp_func_addr);
		ut32 func_name_offset = r_read_le32 (temp_func_name);
		ut8 func_name[64] = {0};
		r_io_read_at (core->io, gopclntab + func_name_offset, func_name, 63);
		if (func_name[0] == 0xff) {
			break;
		}
		r_name_filter ((char *)func_name, 0);
		//r_cons_printf ("[x] Found symbol %s at 0x%x\n", func_name, func_addr);
		r_flag_set (core->flags, sdb_fmt ("sym.go.%s", func_name), func_addr, 1);
		offset += 2 * ptr_size;
		num_syms++;
	}
	r_flag_space_pop (core->flags);
	if (num_syms) {
		oldstr = r_print_rowlog (core->print, sdb_fmt ("Found %d symbols and saved them at sym.go.*", num_syms));
		r_print_rowlog_done (core->print, oldstr);
	} else {
		oldstr = r_print_rowlog (core->print, "Found no symbols.");
		r_print_rowlog_done (core->print, oldstr);
	}
}

/* suggest a name for the function at the address 'addr'.
 * If dump is true, every strings associated with the function is printed */
R_API char *r_core_anal_fcn_autoname(RCore *core, ut64 addr, int dump, int mode) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (fcn) {
		return anal_fcn_autoname (core, fcn, dump, mode);
	}
	return NULL;
}

static ut64 *next_append(ut64 *next, int *nexti, ut64 v) {
	ut64 *tmp_next = realloc (next, sizeof (ut64) * (1 + *nexti));
	if (!tmp_next) {
		return NULL;
	}
	next = tmp_next;
	next[*nexti] = v;
	(*nexti)++;
	return next;
}

static void r_anal_set_stringrefs(RCore *core, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalRef *ref;
	RList *refs = r_anal_function_get_refs (fcn);
	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_DATA &&
			r_bin_is_string (core->bin, ref->addr)) {
			r_anal_xrefs_set (core->anal, ref->at, ref->addr, R_ANAL_REF_TYPE_STRING);
		}
	}
	r_list_free (refs);
}

static bool r_anal_try_get_fcn(RCore *core, RAnalRef *ref, int fcndepth, int refdepth) {
	if (!refdepth) {
		return false;
	}
	RIOMap *map = r_io_map_get_at (core->io, ref->addr);
	if (!map) {
		return false;
	}

	if (map->perm & R_PERM_X) {
		ut8 buf[64];
		r_io_read_at (core->io, ref->addr, buf, sizeof (buf));
		bool looksLikeAFunction = r_anal_check_fcn (core->anal, buf, sizeof (buf), ref->addr, r_io_map_begin (map),
				r_io_map_end (map));
		if (looksLikeAFunction) {
			if (core->anal->limit) {
				if (ref->addr < core->anal->limit->from ||
						ref->addr > core->anal->limit->to) {
					return 1;
				}
			}
			r_core_anal_fcn (core, ref->addr, ref->at, ref->type, fcndepth - 1);
		}
	} else {
		ut64 offs = 0;
		ut64 sz = core->anal->bits >> 3;
		RAnalRef ref1;
		ref1.type = R_ANAL_REF_TYPE_DATA;
		ref1.at = ref->addr;
		ref1.addr = 0;
		ut32 i32;
		ut16 i16;
		ut8 i8;
		ut64 offe = offs + 1024;
		for (offs = 0; offs < offe; offs += sz, ref1.at += sz) {
			ut8 bo[8];
			r_io_read_at (core->io, ref->addr + offs, bo, R_MIN (sizeof (bo), sz));
			bool be = core->anal->big_endian;
			switch (sz) {
			case 1:
				i8 = r_read_ble8 (bo);
				ref1.addr = (ut64)i8;
				break;
			case 2:
				i16 = r_read_ble16 (bo, be);
				ref1.addr = (ut64)i16;
				break;
			case 4:
				i32 = r_read_ble32 (bo, be);
				ref1.addr = (ut64)i32;
				break;
			case 8:
				ref1.addr = r_read_ble64 (bo, be);
				break;
			}
			r_anal_try_get_fcn (core, &ref1, fcndepth, refdepth - 1);
		}
	}
	return 1;
}

static int r_anal_analyze_fcn_refs(RCore *core, RAnalFunction *fcn, int depth) {
	RListIter *iter;
	RAnalRef *ref;
	RList *refs = r_anal_function_get_refs (fcn);

	r_list_foreach (refs, iter, ref) {
		if (ref->addr == UT64_MAX) {
			continue;
		}
		switch (ref->type) {
		case R_ANAL_REF_TYPE_DATA:
			if (core->anal->opt.followdatarefs) {
				r_anal_try_get_fcn (core, ref, depth, 2);
			}
			break;
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_CALL:
			r_core_anal_fcn (core, ref->addr, ref->at, ref->type, depth - 1);
			break;
		default:
			break;
		}
		// TODO: fix memleak here, fcn not freed even though it is
		// added in core->anal->fcns which is freed in r_anal_free()
	}
	r_list_free (refs);
	return 1;
}

static void function_rename(RFlag *flags, RAnalFunction *fcn) {
	const char *locname = "loc.";
	const size_t locsize = strlen (locname);
	char *fcnname = fcn->name;

	if (strncmp (fcn->name, locname, locsize) == 0) {
		const char *fcnpfx, *restofname;
		RFlagItem *f;

		fcn->type = R_ANAL_FCN_TYPE_FCN;
		fcnpfx = r_anal_fcntype_tostring (fcn->type);
		restofname = fcn->name + locsize;
		fcn->name = r_str_newf ("%s.%s", fcnpfx, restofname);

		f = r_flag_get_i (flags, fcn->addr);
		r_flag_rename (flags, f, fcn->name);

		free (fcnname);
	}
}

static void autoname_imp_trampoline(RCore *core, RAnalFunction *fcn) {
	if (r_list_length (fcn->bbs) == 1 && ((RAnalBlock *) r_list_first (fcn->bbs))->ninstr == 1) {
		RList *refs = r_anal_function_get_refs (fcn);
		if (refs && r_list_length (refs) == 1) {
			RAnalRef *ref = r_list_first (refs);
			if (ref->type != R_ANAL_REF_TYPE_CALL) { /* Some fcns don't return */
				RFlagItem *flg = r_flag_get_i (core->flags, ref->addr);
				if (flg && r_str_startswith (flg->name, "sym.imp.")) {
					R_FREE (fcn->name);
					fcn->name = r_str_newf ("sub.%s", flg->name + 8);
				}
			}
		}
		r_list_free (refs);
	}
}

static void set_fcn_name_from_flag(RAnalFunction *fcn, RFlagItem *f, const char *fcnpfx) {
	bool nameChanged = false;
	if (f && f->name) {
		if (!strncmp (fcn->name, "loc.", 4) || !strncmp (fcn->name, "fcn.", 4)) {
			r_anal_function_rename (fcn, f->name);
			nameChanged = true;
		} else if (strncmp (f->name, "sect", 4)) {
			r_anal_function_rename (fcn, f->name);
			nameChanged = true;
		}
	}
	if (!nameChanged) {
		r_anal_function_rename (fcn, sdb_fmt ("%s.%08" PFMT64x, fcnpfx, fcn->addr));
	}
}

static bool is_entry_flag(RFlagItem *f) {
	return f->space && !strcmp (f->space->name, R_FLAGS_FS_SYMBOLS) && r_str_startswith (f->name, "entry.");
}

static bool __core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	if (depth < 0) {
//		printf ("Too deep for 0x%08"PFMT64x"\n", at);
//		r_sys_backtrace ();
		return false;
	}
	int has_next = r_config_get_i (core->config, "anal.hasnext");
	RAnalHint *hint = NULL;
	int i, nexti = 0;
	ut64 *next = NULL;
	int fcnlen;
	RAnalFunction *fcn = r_anal_function_new (core->anal);
	r_warn_if_fail (fcn);
	const char *fcnpfx = r_config_get (core->config, "anal.fcnprefix");
	if (!fcnpfx) {
		fcnpfx = "fcn";
	}
	const char *cc = r_anal_cc_default (core->anal);
	if (!cc) {
		if (r_anal_cc_once (core->anal)) {
			eprintf ("Warning: set your favourite calling convention in `e anal.cc=?`\n");
		}
		cc = "reg";
	}
	fcn->cc = r_str_constpool_get (&core->anal->constpool, cc);
	r_warn_if_fail (fcn->cc);
	hint = r_anal_hint_get (core->anal, at);
	if (hint && hint->bits == 16) {
		// expand 16bit for function
		fcn->bits = 16;
	} else {
		fcn->bits = core->anal->bits;
	}
	fcn->addr = at;
	fcn->name = get_function_name (core, at);

	if (!fcn->name) {
		fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnpfx, at);
	}
	r_anal_fcn_invalidate_read_ahead_cache ();
	do {
		RFlagItem *f;
		ut64 delta = r_anal_function_linear_size (fcn);
		if (!r_io_is_valid_offset (core->io, at + delta, !core->anal->opt.noncode)) {
			goto error;
		}
		if (r_cons_is_breaked ()) {
			break;
		}
		fcnlen = r_anal_function(core->anal, fcn, at + delta, core->anal->opt.bb_max_size, reftype);
		if (core->anal->opt.searchstringrefs) {
			r_anal_set_stringrefs (core, fcn);
		}
		if (fcnlen == 0) {
			if (core->anal->verbose) {
				eprintf ("Analyzed function size is 0 at 0x%08"PFMT64x"\n", at + delta);
			}
			goto error;
		}
		if (fcnlen < 0) {
			switch (fcnlen) {
			case R_ANAL_RET_ERROR:
			case R_ANAL_RET_NEW:
			case R_ANAL_RET_DUP:
			case R_ANAL_RET_END:
				break;
			default:
				eprintf ("Oops. Negative fcnsize at 0x%08"PFMT64x" (%d)\n", at, fcnlen);
				continue;
			}
		}
		f = r_core_flag_get_by_spaces (core->flags, fcn->addr);
		set_fcn_name_from_flag (fcn, f, fcnpfx);

		if (fcnlen == R_ANAL_RET_ERROR ||
			(fcnlen == R_ANAL_RET_END && !r_anal_function_realsize (fcn))) { /* Error analyzing function */
			if (core->anal->opt.followbrokenfcnsrefs) {
				r_anal_analyze_fcn_refs (core, fcn, depth);
			}
			goto error;
		} else if (fcnlen == R_ANAL_RET_END) { /* Function analysis complete */
			f = r_core_flag_get_by_spaces (core->flags, fcn->addr);
			if (f && f->name && strncmp (f->name, "sect", 4)) { /* Check if it's already flagged */
				char *new_name = strdup (f->name);
				if (is_entry_flag (f)) {
					RListIter *iter;
					RBinSymbol *sym;
					const RList *syms = r_bin_get_symbols (core->bin);
					ut64 baddr = r_config_get_i (core->config, "bin.baddr");
					r_list_foreach (syms, iter, sym) {
						if (sym->type && (sym->paddr + baddr) == fcn->addr && !strcmp (sym->type, R_BIN_TYPE_FUNC_STR)) {
							free (new_name);
							new_name = r_str_newf ("sym.%s", sym->name);
							break;
						}
					}
				}
				free (fcn->name);
				fcn->name = new_name;
			} else {
				R_FREE (fcn->name);
				const char *fcnpfx = r_anal_fcntype_tostring (fcn->type);
				if (!fcnpfx || !*fcnpfx || !strcmp (fcnpfx, "fcn")) {
					fcnpfx = r_config_get (core->config, "anal.fcnprefix");
				}
				fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnpfx, fcn->addr);
				autoname_imp_trampoline (core, fcn);
				/* Add flag */
				r_flag_space_push (core->flags, R_FLAGS_FS_FUNCTIONS);
				r_flag_set (core->flags, fcn->name, fcn->addr, r_anal_function_linear_size (fcn));
				r_flag_space_pop (core->flags);
			}

			/* New function: Add initial xref */
			if (from != UT64_MAX) {
				r_anal_xrefs_set (core->anal, from, fcn->addr, reftype);
			}
			// XXX: this is wrong. See CID 1134565
			r_anal_add_function (core->anal, fcn);
			if (has_next) {
				ut64 addr = r_anal_function_max_addr (fcn);
				RIOMap *map = r_io_map_get_at (core->io, addr);
				// only get next if found on an executable section
				if (!map || (map && map->perm & R_PERM_X)) {
					for (i = 0; i < nexti; i++) {
						if (next[i] == addr) {
							break;
						}
					}
					if (i == nexti) {
						ut64 at = r_anal_function_max_addr (fcn);
						while (true) {
							ut64 size;
							RAnalMetaItem *mi = r_meta_get_at (core->anal, at, R_META_TYPE_ANY, &size);
							if (!mi) {
								break;
							}
							at += size;
						}
						// TODO: ensure next address is function after padding (nop or trap or wat)
						// XXX noisy for test cases because we want to clear the stderr
						r_cons_clear_line (1);
						loganal (fcn->addr, at, 10000 - depth);
						next = next_append (next, &nexti, at);
					}
				}
			}
			if (!r_anal_analyze_fcn_refs (core, fcn, depth)) {
				goto error;
			}
		}
	} while (fcnlen != R_ANAL_RET_END);
	r_list_free (core->anal->leaddrs);
	core->anal->leaddrs = NULL;
	if (has_next) {
		for (i = 0; i < nexti; i++) {
			if (!next[i] || r_anal_get_fcn_in (core->anal, next[i], 0)) {
				continue;
			}
			r_core_anal_fcn (core, next[i], from, 0, depth - 1);
		}
		free (next);
	}
	if (core->anal->cur && core->anal->cur->arch && !strcmp (core->anal->cur->arch, "x86")) {
		r_anal_function_check_bp_use (fcn);
		if (fcn && !fcn->bp_frame) {
			r_anal_function_delete_vars_by_kind (fcn, R_ANAL_VAR_KIND_BPV);
		}
	}
	r_anal_hint_free (hint);
	return true;

error:
	r_list_free (core->anal->leaddrs);
	core->anal->leaddrs = NULL;
	// ugly hack to free fcn
	if (fcn) {
		if (!r_anal_function_realsize (fcn) || fcn->addr == UT64_MAX) {
			r_anal_function_free (fcn);
			fcn = NULL;
		} else {
			// TODO: mark this function as not properly analyzed
			if (!fcn->name) {
				// XXX dupped code.
				fcn->name = r_str_newf (
					"%s.%08" PFMT64x,
					r_anal_fcntype_tostring (fcn->type),
					at);
				/* Add flag */
				r_flag_space_push (core->flags, R_FLAGS_FS_FUNCTIONS);
				r_flag_set (core->flags, fcn->name, at, r_anal_function_linear_size (fcn));
				r_flag_space_pop (core->flags);
			}
			r_anal_add_function (core->anal, fcn);
		}
		if (fcn && has_next) {
			ut64 newaddr = r_anal_function_max_addr (fcn);
			RIOMap *map = r_io_map_get_at (core->io, newaddr);
			if (!map || (map && (map->perm & R_PERM_X))) {
				next = next_append (next, &nexti, newaddr);
				for (i = 0; i < nexti; i++) {
					if (!next[i]) {
						continue;
					}
					r_core_anal_fcn (core, next[i], next[i], 0, depth - 1);
				}
				free (next);
			}
		}
	}
	if (fcn && core->anal->cur && core->anal->cur->arch && !strcmp (core->anal->cur->arch, "x86")) {
		r_anal_function_check_bp_use (fcn);
		if (!fcn->bp_frame) {
			r_anal_function_delete_vars_by_kind (fcn, R_ANAL_VAR_KIND_BPV);
		}
	}
	r_anal_hint_free (hint);
	return false;
}

static char *get_title(ut64 addr) {
	return r_str_newf ("0x%"PFMT64x, addr);
}

/* decode and return the RAnalOp at the address addr */
R_API RAnalOp* r_core_anal_op(RCore *core, ut64 addr, int mask) {
	int len;
	ut8 buf[32];
	ut8 *ptr;

	r_return_val_if_fail (core, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	RAnalOp *op = R_NEW0 (RAnalOp);
	if (!op) {
		return NULL;
	}
	int delta = (addr - core->offset);
	int minopsz = 8;
	if (delta > 0 && delta + minopsz < core->blocksize && addr >= core->offset && addr + 16 < core->offset + core->blocksize) {
		ptr = core->block + delta;
		len = core->blocksize - delta;
		if (len < 1) {
			goto err_op;
		}
	} else {
		if (!r_io_read_at (core->io, addr, buf, sizeof (buf))) {
			goto err_op;
		}
		ptr = buf;
		len = sizeof (buf);
	}
	if (r_anal_op (core->anal, op, addr, ptr, len, mask) < 1) {
		goto err_op;
	}
	// TODO This code block must be deleted when all the anal plugs support disasm
	if (!op->mnemonic && mask & R_ANAL_OP_MASK_DISASM) {
		RAsmOp asmop;
		if (core->anal->verbose) {
			eprintf ("Warning: Implement RAnalOp.MASK_DISASM for current anal.arch. Using the sluggish RAsmOp fallback for now.\n");
		}
		r_asm_set_pc (core->rasm, addr);
		r_asm_op_init (&asmop);
		if (r_asm_disassemble (core->rasm, &asmop, ptr, len) > 0) {
			op->mnemonic = strdup (r_strbuf_get (&asmop.buf_asm));
		}
		r_asm_op_fini (&asmop);
	}
	return op;
err_op:
	free (op);
	return NULL;
}

// Node for tree-sorting anal hints or collecting hint records at a single addr
typedef struct {
	RBNode rb;
	ut64 addr;
	enum {
		HINT_NODE_ADDR,
		HINT_NODE_ARCH,
		HINT_NODE_BITS
	} type;
	union {
		const RVector/*<const RAnalAddrHintRecord>*/ *addr_hints;
		const char *arch;
		int bits;
	};
} HintNode;

static void print_hint_h_format(HintNode *node) {
	switch (node->type) {
	case HINT_NODE_ADDR: {
		const RAnalAddrHintRecord *record;
		r_vector_foreach (node->addr_hints, record) {
			switch (record->type) {
			case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
				r_cons_printf (" immbase=%d", record->immbase);
				break;
			case R_ANAL_ADDR_HINT_TYPE_JUMP:
				r_cons_printf (" jump=0x%08"PFMT64x, record->jump);
				break;
			case R_ANAL_ADDR_HINT_TYPE_FAIL:
				r_cons_printf (" fail=0x%08"PFMT64x, record->fail);
				break;
			case R_ANAL_ADDR_HINT_TYPE_STACKFRAME:
				r_cons_printf (" stackframe=0x%"PFMT64x, record->stackframe);
				break;
			case R_ANAL_ADDR_HINT_TYPE_PTR:
				r_cons_printf (" ptr=0x%"PFMT64x, record->ptr);
				break;
			case R_ANAL_ADDR_HINT_TYPE_NWORD:
				r_cons_printf (" nword=%d", record->nword);
				break;
			case R_ANAL_ADDR_HINT_TYPE_RET:
				r_cons_printf (" ret=0x%08"PFMT64x, record->retval);
				break;
			case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
				r_cons_printf (" newbits=%d", record->newbits);
				break;
			case R_ANAL_ADDR_HINT_TYPE_SIZE:
				r_cons_printf (" size=%"PFMT64u, record->size);
				break;
			case R_ANAL_ADDR_HINT_TYPE_SYNTAX:
				r_cons_printf (" syntax='%s'", record->syntax);
				break;
			case R_ANAL_ADDR_HINT_TYPE_OPTYPE: {
				const char *type = r_anal_optype_to_string (record->optype);
				if (type) {
					r_cons_printf (" type='%s'", type);
				}
				break;
			}
			case R_ANAL_ADDR_HINT_TYPE_OPCODE:
				r_cons_printf (" opcode='%s'", record->opcode);
				break;
			case R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET:
				r_cons_printf (" offset='%s'", record->type_offset);
				break;
			case R_ANAL_ADDR_HINT_TYPE_ESIL:
				r_cons_printf (" esil='%s'", record->esil);
				break;
			case R_ANAL_ADDR_HINT_TYPE_HIGH:
				r_cons_printf (" high=true");
				break;
			case R_ANAL_ADDR_HINT_TYPE_VAL:
				r_cons_printf (" val=0x%08"PFMT64x, record->val);
				break;
			}
		}
		break;
	}
	case HINT_NODE_ARCH:
		if (node->arch) {
			r_cons_printf (" arch='%s'", node->arch);
		} else {
			r_cons_print (" arch=RESET");
		}
		break;
	case HINT_NODE_BITS:
		if (node->bits) {
			r_cons_printf (" bits=%d", node->bits);
		} else {
			r_cons_print (" bits=RESET");
		}
		break;
	}
}

// if mode == 'j', pj must be an existing PJ!
static void hint_node_print(HintNode *node, int mode, PJ *pj) {
	switch (mode) {
	case '*':
#define HINTCMD_ADDR(hint,fmt,x) r_cons_printf (fmt" @ 0x%"PFMT64x"\n", x, (hint)->addr)
		switch (node->type) {
		case HINT_NODE_ADDR: {
			const RAnalAddrHintRecord *record;
			r_vector_foreach (node->addr_hints, record) {
				switch (record->type) {
				case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
					HINTCMD_ADDR (node, "ahi %d", record->immbase);
					break;
				case R_ANAL_ADDR_HINT_TYPE_JUMP:
					HINTCMD_ADDR (node, "ahc 0x%"PFMT64x, record->jump);
					break;
				case R_ANAL_ADDR_HINT_TYPE_FAIL:
					HINTCMD_ADDR (node, "ahf 0x%"PFMT64x, record->fail);
					break;
				case R_ANAL_ADDR_HINT_TYPE_STACKFRAME:
					HINTCMD_ADDR (node, "ahF 0x%"PFMT64x, record->stackframe);
					break;
				case R_ANAL_ADDR_HINT_TYPE_PTR:
					HINTCMD_ADDR (node, "ahp 0x%"PFMT64x, record->ptr);
					break;
				case R_ANAL_ADDR_HINT_TYPE_NWORD:
					// no command for this
					break;
				case R_ANAL_ADDR_HINT_TYPE_RET:
					HINTCMD_ADDR (node, "ahr 0x%"PFMT64x, record->retval);
					break;
				case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
					// no command for this
					break;
				case R_ANAL_ADDR_HINT_TYPE_SIZE:
					HINTCMD_ADDR (node, "ahs 0x%"PFMT64x, record->size);
					break;
				case R_ANAL_ADDR_HINT_TYPE_SYNTAX:
					HINTCMD_ADDR (node, "ahS %s", record->syntax); // TODO: escape for newcmd
					break;
				case R_ANAL_ADDR_HINT_TYPE_OPTYPE: {
					const char *type = r_anal_optype_to_string (record->optype);
					if (type) {
						HINTCMD_ADDR (node, "aho %s", type); // TODO: escape for newcmd
					}
					break;
				}
				case R_ANAL_ADDR_HINT_TYPE_OPCODE:
					HINTCMD_ADDR (node, "ahd %s", record->opcode);
					break;
				case R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET:
					HINTCMD_ADDR (node, "aht %s", record->type_offset); // TODO: escape for newcmd
					break;
				case R_ANAL_ADDR_HINT_TYPE_ESIL:
					HINTCMD_ADDR (node, "ahe %s", record->esil); // TODO: escape for newcmd
					break;
				case R_ANAL_ADDR_HINT_TYPE_HIGH:
					r_cons_printf ("ahh @ 0x%"PFMT64x"\n", node->addr);
					break;
				case R_ANAL_ADDR_HINT_TYPE_VAL:
					// no command for this
					break;
				}
			}
			break;
		}
		case HINT_NODE_ARCH:
			HINTCMD_ADDR (node, "aha %s", r_str_get_fail (node->arch, "0"));
			break;
		case HINT_NODE_BITS:
			HINTCMD_ADDR (node, "ahb %d", node->bits);
			break;
		}
#undef HINTCMD_ADDR
		break;
	case 'j':
		switch (node->type) {
		case HINT_NODE_ADDR: {
			const RAnalAddrHintRecord *record;
			r_vector_foreach (node->addr_hints, record) {
				switch (record->type) {
				case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
					pj_ki (pj, "immbase", record->immbase);
					break;
				case R_ANAL_ADDR_HINT_TYPE_JUMP:
					pj_kn (pj, "jump", record->jump);
					break;
				case R_ANAL_ADDR_HINT_TYPE_FAIL:
					pj_kn (pj, "fail", record->fail);
					break;
				case R_ANAL_ADDR_HINT_TYPE_STACKFRAME:
					pj_kn (pj, "stackframe", record->stackframe);
					break;
				case R_ANAL_ADDR_HINT_TYPE_PTR:
					pj_kn (pj, "ptr", record->ptr);
					break;
				case R_ANAL_ADDR_HINT_TYPE_NWORD:
					pj_ki (pj, "nword", record->nword);
					break;
				case R_ANAL_ADDR_HINT_TYPE_RET:
					pj_kn (pj, "ret", record->retval);
					break;
				case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
					pj_ki (pj, "newbits", record->newbits);
					break;
				case R_ANAL_ADDR_HINT_TYPE_SIZE:
					pj_kn (pj, "size", record->size);
					break;
				case R_ANAL_ADDR_HINT_TYPE_SYNTAX:
					pj_ks (pj, "syntax", record->syntax);
					break;
				case R_ANAL_ADDR_HINT_TYPE_OPTYPE: {
					const char *type = r_anal_optype_to_string (record->optype);
					if (type) {
						pj_ks (pj, "type", type);
					}
					break;
				}
				case R_ANAL_ADDR_HINT_TYPE_OPCODE:
					pj_ks (pj, "opcode", record->opcode);
					break;
				case R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET:
					pj_ks (pj, "offset", record->type_offset);
					break;
				case R_ANAL_ADDR_HINT_TYPE_ESIL:
					pj_ks (pj, "esil", record->esil);
					break;
				case R_ANAL_ADDR_HINT_TYPE_HIGH:
					pj_kb (pj, "high", true);
					break;
				case R_ANAL_ADDR_HINT_TYPE_VAL:
					pj_kn (pj, "val", record->val);
					break;
				}
			}
			break;
		}
		case HINT_NODE_ARCH:
			if (node->arch) {
				pj_ks (pj, "arch", node->arch);
			} else {
				pj_knull (pj, "arch");
			}
			break;
		case HINT_NODE_BITS:
			pj_ki (pj, "bits", node->bits);
			break;
		}
		break;
	default:
		print_hint_h_format (node);
		break;
	}
}

void hint_node_free(RBNode *node, void *user) {
	free (container_of (node, HintNode, rb));
}

int hint_node_cmp(const void *incoming, const RBNode *in_tree, void *user) {
	ut64 ia = *(ut64 *)incoming;
	ut64 ta = container_of (in_tree, const HintNode, rb)->addr;
	if (ia < ta) {
		return -1;
	} else if (ia > ta) {
		return 1;
	}
	return 0;
}

bool print_addr_hint_cb(ut64 addr, const RVector/*<const RAnalAddrHintRecord>*/ *records, void *user) {
	HintNode *node = R_NEW0 (HintNode);
	if (!node) {
		return false;
	}
	node->addr = addr;
	node->type = HINT_NODE_ADDR;
	node->addr_hints = records;
	r_rbtree_insert (user, &addr, &node->rb, hint_node_cmp, NULL);
	return true;
}

bool print_arch_hint_cb(ut64 addr, R_NULLABLE const char *arch, void *user) {
	HintNode *node = R_NEW0 (HintNode);
	if (!node) {
		return false;
	}
	node->addr = addr;
	node->type = HINT_NODE_ARCH;
	node->arch = arch;
	r_rbtree_insert (user, &addr, &node->rb, hint_node_cmp, NULL);
	return true;
}

bool print_bits_hint_cb(ut64 addr, int bits, void *user) {
	HintNode *node = R_NEW0 (HintNode);
	if (!node) {
		return false;
	}
	node->addr = addr;
	node->type = HINT_NODE_BITS;
	node->bits = bits;
	r_rbtree_insert (user, &addr, &node->rb, hint_node_cmp, NULL);
	return true;
}

static void print_hint_tree(RBTree tree, int mode) {
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new ();
		pj_a (pj);
	}
#define END_ADDR \
		if (pj) { \
			pj_end (pj); \
		} else if (mode != '*') { \
			r_cons_newline (); \
		}
	RBIter it;
	HintNode *node;
	ut64 last_addr = 0;
	bool in_addr = false;
	r_rbtree_foreach (tree, it, node, HintNode, rb) {
		if (!in_addr || last_addr != node->addr) {
			if (in_addr) {
				END_ADDR
			}
			in_addr = true;
			last_addr = node->addr;
			if (pj) {
				pj_o (pj);
				pj_kn (pj, "addr", node->addr);
			} else if (mode != '*') {
				r_cons_printf (" 0x%08"PFMT64x" =>", node->addr);
			}
		}
		hint_node_print (node, mode, pj);
	}
	if (in_addr) {
		END_ADDR
	}
#undef BEGIN_ADDR
#undef END_ADDR
	if (pj) {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

R_API void r_core_anal_hint_list(RAnal *a, int mode) {
	RBTree tree = NULL;
	// Collect all hints in the tree to sort them
	r_anal_arch_hints_foreach (a, print_arch_hint_cb, &tree);
	r_anal_bits_hints_foreach (a, print_bits_hint_cb, &tree);
	r_anal_addr_hints_foreach (a, print_addr_hint_cb, &tree);
	print_hint_tree (tree, mode);
	r_rbtree_free (tree, hint_node_free, NULL);
}

R_API void r_core_anal_hint_print(RAnal* a, ut64 addr, int mode) {
	RBTree tree = NULL;
	ut64 hint_addr = UT64_MAX;
	const char *arch = r_anal_hint_arch_at(a, addr, &hint_addr);
	if (hint_addr != UT64_MAX) {
		print_arch_hint_cb (hint_addr, arch, &tree);
	}
	int bits = r_anal_hint_bits_at (a, addr, &hint_addr);
	if (hint_addr != UT64_MAX) {
		print_bits_hint_cb (hint_addr, bits, &tree);
	}
	const RVector *addr_hints = r_anal_addr_hints_at (a, addr);
	if (addr_hints) {
		print_addr_hint_cb (addr, addr_hints, &tree);
	}
	print_hint_tree (tree, mode);
	r_rbtree_free (tree, hint_node_free, NULL);
}

static char *core_anal_graph_label(RCore *core, RAnalBlock *bb, int opts) {
	int is_html = r_cons_context ()->is_html;
	int is_json = opts & R_CORE_ANAL_JSON;
	char cmd[1024], file[1024], *cmdstr = NULL, *filestr = NULL, *str = NULL;
	int line = 0, oline = 0, idx = 0;
	ut64 at;

	if (opts & R_CORE_ANAL_GRAPHLINES) {
		for (at = bb->addr; at < bb->addr + bb->size; at += 2) {
			r_bin_addr2line (core->bin, at, file, sizeof (file) - 1, &line);
			if (line != 0 && line != oline && strcmp (file, "??")) {
				filestr = r_file_slurp_line (file, line, 0);
				if (filestr) {
					int flen = strlen (filestr);
					cmdstr = realloc (cmdstr, idx + flen + 8);
					memcpy (cmdstr + idx, filestr, flen);
					idx += flen;
					if (is_json) {
						strcpy (cmdstr + idx, "\\n");
						idx += 2;
					} else if (is_html) {
						strcpy (cmdstr + idx, "<br />");
						idx += 6;
					} else {
						strcpy (cmdstr + idx, "\\l");
						idx += 2;
					}
					free (filestr);
				}
			}
			oline = line;
		}
	} else if (opts & R_CORE_ANAL_STAR) {
		snprintf (cmd, sizeof (cmd), "pdb %"PFMT64u" @ 0x%08" PFMT64x, bb->size, bb->addr);
		str = r_core_cmd_str (core, cmd);
	} else if (opts & R_CORE_ANAL_GRAPHBODY) {
		const bool scrColor = r_config_get (core->config, "scr.color");
		const bool scrUtf8 = r_config_get (core->config, "scr.utf8");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
		r_config_set (core->config, "scr.utf8", "false");
		snprintf (cmd, sizeof (cmd), "pD %"PFMT64u" @ 0x%08" PFMT64x, bb->size, bb->addr);
		cmdstr = r_core_cmd_str (core, cmd);
		r_config_set_i (core->config, "scr.color", scrColor);
		r_config_set_i (core->config, "scr.utf8", scrUtf8);
	}
	if (cmdstr) {
		str = r_str_escape_dot (cmdstr);
		free (cmdstr);
	}
	return str;
}

static char *palColorFor(const char *k) {
	if (!r_cons_singleton ()) {
		return NULL;
	}
	RColor rcolor = r_cons_pal_get (k);
	return r_cons_rgb_tostring (rcolor.r, rcolor.g, rcolor.b);
}

static void core_anal_color_curr_node(RCore *core, RAnalBlock *bbi) {
	bool color_current = r_config_get_i (core->config, "graph.gv.current");
	char *pal_curr = palColorFor ("graph.current");
	bool current = r_anal_block_contains (bbi, core->offset);

	if (current && color_current) {
		r_cons_printf ("\t\"0x%08"PFMT64x"\" ", bbi->addr);
		r_cons_printf ("\t[fillcolor=%s style=filled shape=box];\n", pal_curr);
	}
	free (pal_curr);
}

static int core_anal_graph_construct_edges(RCore *core, RAnalFunction *fcn, int opts, PJ *pj, Sdb *DB) {
	RAnalBlock *bbi;
	RListIter *iter;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	int is_star = opts & R_CORE_ANAL_STAR;
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_html = r_cons_context ()->is_html;
	char *pal_jump = palColorFor ("graph.true");
	char *pal_fail = palColorFor ("graph.false");
	char *pal_trfa = palColorFor ("graph.trufae");
	int nodes = 0;
	r_list_foreach (fcn->bbs, iter, bbi) {
		if (bbi->jump != UT64_MAX) {
			nodes++;
			if (is_keva) {
				char key[128];
				char val[128];
				snprintf (key, sizeof (key), "bb.0x%08"PFMT64x".to", bbi->addr);
				if (bbi->fail != UT64_MAX) {
					snprintf (val, sizeof (val), "0x%08"PFMT64x, bbi->jump);
				} else {
					snprintf (val, sizeof (val), "0x%08"PFMT64x ",0x%08"PFMT64x,
							bbi->jump, bbi->fail);
				}
				// bb.<addr>.to=<jump>,<fail>
				sdb_set (DB, key, val, 0);
			} else if (is_html) {
				r_cons_printf ("<div class=\"connector _0x%08"PFMT64x" _0x%08"PFMT64x"\">\n"
						"  <img class=\"connector-end\" src=\"img/arrow.gif\" /></div>\n",
						bbi->addr, bbi->jump);
			} else if (!is_json && !is_keva) {
				if (is_star) {
					char *from = get_title (bbi->addr);
					char *to = get_title (bbi->jump);
					r_cons_printf ("age %s %s\n", from, to);
					free (from);
					free (to);
				} else {
					const char* edge_color = bbi->fail != -1 ? pal_jump : pal_trfa;
					if (sdb_const_get (core->sdb, sdb_fmt ("agraph.edge.0x%"PFMT64x"_0x%"PFMT64x".highlight", bbi->addr, bbi->jump), 0)) {
						edge_color = "cyan";
					}
					r_cons_printf ("        \"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
							"[color=\"%s\"];\n", bbi->addr, bbi->jump, edge_color);
					core_anal_color_curr_node (core, bbi);
				}
			}
		}
		if (bbi->fail != -1) {
			nodes++;
			if (is_html) {
				r_cons_printf ("<div class=\"connector _0x%08"PFMT64x" _0x%08"PFMT64x"\">\n"
						"  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
						bbi->addr, bbi->fail);
			} else if (!is_keva && !is_json) {
				if (is_star) {
					char *from = get_title (bbi->addr);
					char *to = get_title (bbi->fail);
					r_cons_printf ("age %s %s\n", from, to);
					free(from);
					free(to);
				} else {
					r_cons_printf ("        \"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
									"[color=\"%s\"];\n", bbi->addr, bbi->fail, pal_fail);
					core_anal_color_curr_node (core, bbi);
				}
			}
		}
		if (bbi->switch_op) {
			RAnalCaseOp *caseop;
			RListIter *iter;

			if (bbi->fail != UT64_MAX) {
				if (is_html) {
					r_cons_printf ("<div class=\"connector _0x%08"PFMT64x" _0x%08"PFMT64x"\">\n"
							"  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
							bbi->addr, bbi->fail);
				} else if (!is_keva && !is_json) {
					if (is_star) {
						char *from = get_title (bbi->addr);
						char *to = get_title (bbi->fail);
						r_cons_printf ("age %s %s\n", from, to);
						free(from);
						free(to);
					} else {
						r_cons_printf ("        \"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
								"[color=\"%s\"];\n", bbi->addr, bbi->fail, pal_fail);
						core_anal_color_curr_node (core, bbi);
					}
				}
			}
			r_list_foreach (bbi->switch_op->cases, iter, caseop) {
				nodes++;
				if (is_keva) {
					char key[128];
					snprintf (key, sizeof (key),
							"bb.0x%08"PFMT64x".switch.%"PFMT64d,
							bbi->addr, caseop->value);
					sdb_num_set (DB, key, caseop->jump, 0);
					snprintf (key, sizeof (key),
							"bb.0x%08"PFMT64x".switch", bbi->addr);
							sdb_array_add_num (DB, key, caseop->value, 0);
				} else if (is_html) {
					r_cons_printf ("<div class=\"connector _0x%08" PFMT64x " _0x%08" PFMT64x "\">\n"
							"  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
							bbi->addr, caseop->addr);
				} else if (!is_json && !is_keva) {
					if (is_star) {
						char *from = get_title (bbi->addr);
						char *to = get_title (caseop->addr);
						r_cons_printf ("age %s %s\n", from ,to);
						free (from);
						free (to);
					} else {
						r_cons_printf ("        \"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x "\" "
								"[color=\"%s\"];\n",
								bbi->addr, caseop->addr, pal_trfa);
						core_anal_color_curr_node (core, bbi);
					}
				}
			}
		}
	}
	free(pal_jump);
	free(pal_fail);
	free(pal_trfa);
	return nodes;
}

static int core_anal_graph_construct_nodes(RCore *core, RAnalFunction *fcn, int opts, PJ *pj, Sdb *DB) {
	RAnalBlock *bbi;
	RListIter *iter;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	int is_star = opts & R_CORE_ANAL_STAR;
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_html = r_cons_context ()->is_html;
	int left = 300;
	int top = 0;

	int is_json_format_disasm = opts & R_CORE_ANAL_JSON_FORMAT_DISASM;
	char *pal_curr = palColorFor ("graph.current");
	char *pal_traced = palColorFor ("graph.traced");
	char *pal_box4 = palColorFor ("graph.box4");
	const char *font = r_config_get (core->config, "graph.font");
	bool color_current = r_config_get_i (core->config, "graph.gv.current");
	char *str;
	int nodes = 0;
	r_list_foreach (fcn->bbs, iter, bbi) {
		if (is_keva) {
			char key[128];
			sdb_array_push_num (DB, "bbs", bbi->addr, 0);
			snprintf (key, sizeof (key), "bb.0x%08"PFMT64x".size", bbi->addr);
			sdb_num_set (DB, key, bbi->size, 0); // bb.<addr>.size=<num>
		} else if (is_json) {
			RDebugTracepoint *t = r_debug_trace_get (core->dbg, bbi->addr);
			pj_o (pj);
			pj_kn (pj, "offset", bbi->addr);
			pj_kn (pj, "size", bbi->size);
			if (bbi->jump != UT64_MAX) {
				pj_kn (pj, "jump", bbi->jump);
			}
			if (bbi->fail != -1) {
				pj_kn (pj, "fail", bbi->fail);
			}
			if (bbi->switch_op) {
				RAnalSwitchOp *op = bbi->switch_op;
				pj_k (pj, "switchop");
				pj_o (pj);
				pj_kn (pj, "offset", op->addr);
				pj_kn (pj, "defval", op->def_val);
				pj_kn (pj, "maxval", op->max_val);
				pj_kn (pj, "minval", op->min_val);
				pj_k (pj, "cases");
				pj_a (pj);
				RAnalCaseOp *case_op;
				RListIter *case_iter;
				r_list_foreach (op->cases, case_iter, case_op) {
					pj_o (pj);
					pj_kn (pj, "offset", case_op->addr);
					pj_kn (pj, "value", case_op->value);
					pj_kn (pj, "jump", case_op->jump);
					pj_end (pj);
				}
				pj_end (pj);
				pj_end (pj);
			}
			if (t) {
				pj_k (pj, "trace");
				pj_o (pj);
				pj_ki (pj, "count", t->count);
				pj_ki (pj, "times", t->times);
				pj_end (pj);
			}
			if (bbi->color.r || bbi->color.g || bbi->color.b) {
				char *s = r_cons_rgb_tostring (bbi->color.r, bbi->color.g, bbi->color.b);
				pj_ks (pj, "color", s);
				free (s);
			}
			pj_k (pj, "ops");
			pj_a (pj);
			ut8 *buf = malloc (bbi->size);
			if (buf) {
				r_io_read_at (core->io, bbi->addr, buf, bbi->size);
				if (is_json_format_disasm) {
					r_core_print_disasm (core, bbi->addr, buf, bbi->size, bbi->size, true, false, true, pj, NULL);
				} else {
					r_core_print_disasm_json (core, bbi->addr, buf, bbi->size, 0, pj);
				}
				free (buf);
			} else {
				eprintf ("cannot allocate %"PFMT64u" byte(s)\n", bbi->size);
			}
			pj_end (pj);
			pj_end (pj);
			continue;
		}
		if ((str = core_anal_graph_label (core, bbi, opts))) {
			if (opts & R_CORE_ANAL_GRAPHDIFF) {
				const char *difftype = bbi->diff? (\
				bbi->diff->type==R_ANAL_DIFF_TYPE_MATCH? "lightgray":
				bbi->diff->type==R_ANAL_DIFF_TYPE_UNMATCH? "yellow": "red"): "orange";
				const char *diffname = bbi->diff? (\
				bbi->diff->type==R_ANAL_DIFF_TYPE_MATCH? "match":
				bbi->diff->type==R_ANAL_DIFF_TYPE_UNMATCH? "unmatch": "new"): "unk";
				if (is_keva) {
					sdb_set (DB, "diff", diffname, 0);
					sdb_set (DB, "label", str, 0);
				} else if (!is_json) {
					nodes++;
					RConfigHold *hc = r_config_hold_new (core->config);
					r_config_hold (hc, "scr.color", "scr.utf8", "asm.offset", "asm.lines",
							"asm.cmt.right", "asm.lines.fcn", "asm.bytes", NULL);
					RDiff *d = r_diff_new ();
					r_config_set_i (core->config, "scr.utf8", 0);
					r_config_set_i (core->config, "asm.offset", 0);
					r_config_set_i (core->config, "asm.lines", 0);
					r_config_set_i (core->config, "asm.cmt.right", 0);
					r_config_set_i (core->config, "asm.lines.fcn", 0);
					r_config_set_i (core->config, "asm.bytes", 0);
					if (!is_star) {
						r_config_set_i (core->config, "scr.color", 0);	// disable color for dot
					}

					if (bbi->diff && bbi->diff->type != R_ANAL_DIFF_TYPE_MATCH && core->c2) {
						RCore *c = core->c2;
						RConfig *oc = c->config;
						char *str = r_core_cmd_strf (core, "pdb @ 0x%08"PFMT64x, bbi->addr);
						c->config = core->config;
						// XXX. the bbi->addr doesnt needs to be in the same address in core2
						char *str2 = r_core_cmd_strf (c, "pdb @ 0x%08"PFMT64x, bbi->diff->addr);
						char *diffstr = r_diff_buffers_to_string (d,
								(const ut8*)str, strlen (str),
								(const ut8*)str2, strlen (str2));

						if (diffstr) {
							char *nl = strchr (diffstr, '\n');
							if (nl) {
								nl = strchr (nl + 1, '\n');
								if (nl) {
									nl = strchr (nl + 1, '\n');
									if (nl) {
										r_str_cpy (diffstr, nl + 1);
									}
								}
							}
						}

						if (is_star) {
							char *title = get_title (bbi->addr);
							char *body_b64 = r_base64_encode_dyn (diffstr, -1);
							if (!title  || !body_b64) {
								free (body_b64);
								free (title);
								r_diff_free (d);
								return false;
							}
							body_b64 = r_str_prepend (body_b64, "base64:");
							r_cons_printf ("agn %s %s %d\n", title, body_b64, bbi->diff->type);
							free (body_b64);
							free (title);
						} else {
							diffstr = r_str_replace (diffstr, "\n", "\\l", 1);
							diffstr = r_str_replace (diffstr, "\"", "'", 1);
							r_cons_printf(" \"0x%08"PFMT64x"\" [fillcolor=\"%s\","
							"color=\"black\", fontname=\"%s\","
							" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
							bbi->addr, difftype, font, diffstr, fcn->name,
							bbi->addr);
						}
						free (diffstr);
						c->config = oc;
					} else {
						if (is_star) {
							char *title = get_title (bbi->addr);
							char *body_b64 = r_base64_encode_dyn (str, -1);
							int color = (bbi && bbi->diff) ? bbi->diff->type : 0;
							if (!title  || !body_b64) {
								free (body_b64);
								free (title);
								r_diff_free (d);
								return false;
							}
							body_b64 = r_str_prepend (body_b64, "base64:");
							r_cons_printf ("agn %s %s %d\n", title, body_b64, color);
							free (body_b64);
							free (title);
						} else {
							r_cons_printf(" \"0x%08"PFMT64x"\" [fillcolor=\"%s\","
									"color=\"black\", fontname=\"%s\","
									" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
									bbi->addr, difftype, font, str, fcn->name, bbi->addr);
						}
					}
					r_diff_free (d);
					r_config_set_i (core->config, "scr.color", 1);
					r_config_hold_free (hc);
				}
			} else {
				if (is_html) {
						nodes++;
						r_cons_printf ("<p class=\"block draggable\" style=\""
												"top: %dpx; left: %dpx; width: 400px;\" id=\""
												"_0x%08"PFMT64x"\">\n%s</p>\n",
												top, left, bbi->addr, str);
						left = left? 0: 600;
						if (!left) {
								top += 250;
						}
				} else if (!is_json && !is_keva) {
					bool current = r_anal_block_contains (bbi, core->offset);
					const char *label_color = bbi->traced
							? pal_traced
							: (current && color_current)
							? pal_curr
							: pal_box4;
					const char *fill_color = ((current && color_current) || label_color == pal_traced)? pal_traced: "white";
					nodes++;
					if (is_star) {
						char *title = get_title (bbi->addr);
						char *body_b64 = r_base64_encode_dyn (str, -1);
						int color = (bbi && bbi->diff) ? bbi->diff->type : 0;
						if (!title  || !body_b64) {
								free (body_b64);
								free (title);
								return false;
						}
						body_b64 = r_str_prepend (body_b64, "base64:");
						r_cons_printf ("agn %s %s %d\n", title, body_b64, color);
						free (body_b64);
						free (title);
					} else {
						r_cons_printf ("\t\"0x%08"PFMT64x"\" ["
								"URL=\"%s/0x%08"PFMT64x"\", fillcolor=\"%s\","
								"color=\"%s\", fontname=\"%s\","
								"label=\"%s\"]\n",
								bbi->addr, fcn->name, bbi->addr,
								fill_color, label_color, font, str);
					}
				}
			}
			free (str);
		}
	}
	return nodes;
}

static int core_anal_graph_nodes(RCore *core, RAnalFunction *fcn, int opts, PJ *pj) {
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	int nodes = 0;
	Sdb *DB = NULL;
	char *pal_jump = palColorFor ("graph.true");
	char *pal_fail = palColorFor ("graph.false");
	char *pal_trfa = palColorFor ("graph.trufae");
	char *pal_curr = palColorFor ("graph.current");
	char *pal_traced = palColorFor ("graph.traced");
	char *pal_box4 = palColorFor ("graph.box4");
	if (!fcn || !fcn->bbs) {
		eprintf ("No fcn\n");
		free (pal_jump);
		free (pal_fail);
		free (pal_trfa);
		free (pal_curr);
		free (pal_traced);
		free (pal_box4);
		return -1;
	}

	if (is_keva) {
		char ns[64];
		DB = sdb_ns (core->anal->sdb, "graph", 1);
		snprintf (ns, sizeof (ns), "fcn.0x%08"PFMT64x, fcn->addr);
		DB = sdb_ns (DB, ns, 1);
	}

	if (is_keva) {
		char *ename = sdb_encode ((const ut8*)fcn->name, -1);
		sdb_set (DB, "name", fcn->name, 0);
		sdb_set (DB, "ename", ename, 0);
		free (ename);
		sdb_num_set (DB, "size", r_anal_function_linear_size (fcn), 0);
		if (fcn->maxstack > 0) {
			sdb_num_set (DB, "stack", fcn->maxstack, 0);
		}
		sdb_set (DB, "pos", "0,0", 0); // needs to run layout
		sdb_set (DB, "type", r_anal_fcntype_tostring (fcn->type), 0);
	} else if (is_json) {
		// TODO: show vars, refs and xrefs
		char *fcn_name_escaped = r_str_escape_utf8_for_json (fcn->name, -1);
		pj_o (pj);
		pj_ks (pj, "name", r_str_getf (fcn_name_escaped));
		free (fcn_name_escaped);
		pj_kn (pj, "offset", fcn->addr);
		pj_ki (pj, "ninstr", fcn->ninstr);
		pj_ki (pj, "nargs",
			r_anal_var_count (core->anal, fcn, 'r', 1) +
			r_anal_var_count (core->anal, fcn, 's', 1) +
			r_anal_var_count (core->anal, fcn, 'b', 1));
		pj_ki (pj, "nlocals",
			r_anal_var_count (core->anal, fcn, 'r', 0) +
			r_anal_var_count (core->anal, fcn, 's', 0) +
			r_anal_var_count (core->anal, fcn, 'b', 0));
		pj_kn (pj, "size", r_anal_function_linear_size (fcn));
		pj_ki (pj, "stack", fcn->maxstack);
		pj_ks (pj, "type", r_anal_fcntype_tostring (fcn->type));
		pj_k (pj, "blocks");
		pj_a (pj);
	}
	nodes += core_anal_graph_construct_nodes (core, fcn, opts, pj, DB);
	nodes += core_anal_graph_construct_edges (core, fcn, opts, pj, DB);
	if (is_json) {
		pj_end (pj);
		pj_end (pj);
	}
	free (pal_jump);
	free (pal_fail);
	free (pal_trfa);
	free (pal_curr);
	free (pal_traced);
	free (pal_box4);
	return nodes;
}

/* seek basic block that contains address addr or just addr if there's no such
 * basic block */
R_API bool r_core_anal_bb_seek(RCore *core, ut64 addr) {
	ut64 bbaddr = r_anal_get_bbaddr (core->anal, addr);
	if (bbaddr != UT64_MAX) {
		r_core_seek (core, bbaddr, false);
		return true;
	}
	return false;
}

R_API int r_core_anal_esil_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	const char *esil;
	eprintf ("TODO\n");
	while (1) {
		// TODO: Implement the proper logic for doing esil analysis
		RAnalOp *op = r_core_anal_op (core, at, R_ANAL_OP_MASK_ESIL);
		if (!op) {
			break;
		}
		esil = R_STRBUF_SAFEGET (&op->esil);
		eprintf ("0x%08"PFMT64x" %d %s\n", at, op->size, esil);
		// at += op->size;
		// esilIsRet()
		// esilIsCall()
		// esilIsJmp()
		r_anal_op_free (op);
		break;
	}
	return 0;
}

static int find_sym_flag(const void *a1, const void *a2) {
	const RFlagItem *f = (const RFlagItem *)a2;
	return f->space && !strcmp (f->space->name, R_FLAGS_FS_SYMBOLS)? 0: 1;
}

static bool is_skippable_addr(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		return false;
	}
	if (fcn->addr == addr) {
		return true;
	}
	const RList *flags = r_flag_get_list (core->flags, addr);
	return !(flags && r_list_find (flags, fcn, find_sym_flag));
}

// XXX: This function takes sometimes forever
/* analyze a RAnalFunction at the address 'at'.
 * If the function has been already analyzed, it adds a
 * reference to that fcn */
R_API bool r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	if (depth < 0) {
		if (core->anal->verbose) {
			eprintf ("Message: Early deepness at 0x%08"PFMT64x"\n", at);
		}
		return false;
	}
	if (from == UT64_MAX && is_skippable_addr (core, at)) {
		if (core->anal->verbose) {
			eprintf ("Message: Invalid address for function 0x%08"PFMT64x"\n", at);
		}
		return false;
	}

	const bool use_esil = r_config_get_i (core->config, "anal.esil");
	RAnalFunction *fcn;

	//update bits based on the core->offset otherwise we could have the
	//last value set and blow everything up
	r_core_seek_arch_bits (core, at);

	if (core->io->va) {
		if (!r_io_is_valid_offset (core->io, at, !core->anal->opt.noncode)) {
			if (core->anal->verbose) {
				eprintf ("Warning: Address not mapped or not executable at 0x%08"PFMT64x"\n", at);
			}
			return false;
		}
	}
	if (r_config_get_i (core->config, "anal.a2f")) {
		r_core_cmd0 (core, ".a2f");
		return 0;
	}
	if (use_esil) {
		return r_core_anal_esil_fcn (core, at, from, reftype, depth);
	}

	if ((from != UT64_MAX && !at) || at == UT64_MAX) {
		eprintf ("Invalid address from 0x%08"PFMT64x"\n", from);
		return false;
	}
	if (r_cons_is_breaked ()) {
		return false;
	}
	fcn = r_anal_get_fcn_in (core->anal, at, 0);
	if (fcn) {
		if (fcn->addr == at) {
			// if the function was already analyzed as a "loc.",
			// convert it to function and rename it to "fcn.",
			// because we found a call to this address
			if (reftype == R_ANAL_REF_TYPE_CALL && fcn->type == R_ANAL_FCN_TYPE_LOC) {
				function_rename (core->flags, fcn);
			}
			return 0;  // already analyzed function
		}
		if (r_anal_function_contains (fcn, from)) { // inner function
			RList *l = r_anal_xrefs_get (core->anal, from);
			if (l && !r_list_empty (l)) {
				r_list_free (l);
				return true;
			}
			r_list_free (l);

			// we should analyze and add code ref otherwise aaa != aac
			if (from != UT64_MAX) {
				r_anal_xrefs_set (core->anal, from, at, reftype);
			}
			return true;
		}
	}
	if (__core_anal_fcn (core, at, from, reftype, depth - 1)) {
		// split function if overlaps
		if (fcn) {
			r_anal_function_resize (fcn, at - fcn->addr);
		}
		return true;
	}
	return false;
}

/* if addr is 0, remove all functions
 * otherwise remove the function addr falls into */
R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter, *iter_tmp;

	if (!addr) {
		r_list_purge (core->anal->fcns);
		if (!(core->anal->fcns = r_list_new ())) {
			return false;
		}
	} else {
		r_list_foreach_safe (core->anal->fcns, iter, iter_tmp, fcni) {
			if (r_anal_function_contains (fcni, addr)) {
				r_anal_function_delete (fcni);
			}
		}
	}
	return true;
}

R_API int r_core_print_bb_custom(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	if (!fcn) {
		return false;
	}

	RConfigHold *hc = r_config_hold_new (core->config);
	r_config_hold (hc, "scr.color", "scr.utf8", "asm.marks", "asm.offset", "asm.lines",
	  "asm.cmt.right", "asm.cmt.col", "asm.lines.fcn", "asm.bytes", NULL);
	/*r_config_set_i (core->config, "scr.color", 0);*/
	r_config_set_i (core->config, "scr.utf8", 0);
	r_config_set_i (core->config, "asm.marks", 0);
	r_config_set_i (core->config, "asm.offset", 0);
	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.cmt.right", 0);
	r_config_set_i (core->config, "asm.cmt.col", 0);
	r_config_set_i (core->config, "asm.lines.fcn", 0);
	r_config_set_i (core->config, "asm.bytes", 0);

	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *title = get_title (bb->addr);
		char *body = r_core_cmd_strf (core, "pdb @ 0x%08"PFMT64x, bb->addr);
		char *body_b64 = r_base64_encode_dyn (body, -1);
		if (!title || !body || !body_b64) {
			free (body_b64);
			free (body);
			free (title);
			r_config_hold_restore (hc);
			r_config_hold_free (hc);
			return false;
		}
		body_b64 = r_str_prepend (body_b64, "base64:");
		r_cons_printf ("agn %s %s\n", title, body_b64);
		free (body);
		free (body_b64);
		free (title);
	}

	r_config_hold_restore (hc);
	r_config_hold_free (hc);

	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *u = get_title (bb->addr), *v = NULL;
		if (bb->jump != UT64_MAX) {
			v = get_title (bb->jump);
			r_cons_printf ("age %s %s\n", u, v);
			free (v);
		}
		if (bb->fail != UT64_MAX) {
			v = get_title (bb->fail);
			r_cons_printf ("age %s %s\n", u, v);
			free (v);
		}
		if (bb->switch_op) {
			RListIter *it;
			RAnalCaseOp *cop;
			r_list_foreach (bb->switch_op->cases, it, cop) {
				v = get_title (cop->addr);
				r_cons_printf ("age %s %s\n", u, v);
				free (v);
			}
		}
		free (u);
	}
	return true;
}

#define USE_ID 1
R_API int r_core_print_bb_gml(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	if (!fcn) {
		return false;
	}
	int id = 0;
	HtUUOptions opt = { 0 };
	HtUU *ht = ht_uu_new_opt (&opt);

	r_cons_printf ("graph\n[\n" "hierarchic 1\n" "label \"\"\n" "directed 1\n");

	r_list_foreach (fcn->bbs, iter, bb) {
		RFlagItem *flag = r_flag_get_i (core->flags, bb->addr);
		char *msg = flag? strdup (flag->name): r_str_newf ("0x%08"PFMT64x, bb->addr);
		// TODO char *str = r_str_escape_dot (msg);
#if USE_ID
		ht_uu_insert (ht, bb->addr, id);
		r_cons_printf ("  node [\n"
				"    id  %d\n"
				"    label  \"%s\"\n"
				"  ]\n", id, msg);
		id++;
#else
		r_cons_printf ("  node [\n"
				"    id  %"PFMT64d"\n"
				"    label  \"%s\"\n"
				"  ]\n", bb->addr, msg);
#endif
		free (msg);
	}

	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}

#if USE_ID
		if (bb->jump != UT64_MAX) {
			bool found;
			int i = ht_uu_find (ht, bb->addr, &found);
			if (found) {
				int i2 = ht_uu_find (ht, bb->jump, &found);
				if (found) {
					r_cons_printf ("  edge [\n"
							"    source  %d\n"
							"    target  %d\n"
							"  ]\n", i, i2);
				}
			}
		}
		if (bb->fail != UT64_MAX) {
			bool found;
			int i = ht_uu_find (ht, bb->addr, &found);
			if (found) {
				int i2 = ht_uu_find (ht, bb->fail, &found);
				if (found) {
					r_cons_printf ("  edge [\n"
						"    source  %d\n"
						"    target  %d\n"
						"  ]\n", i, i2);
				}
			}
		}
		if (bb->switch_op) {
			RListIter *it;
			RAnalCaseOp *cop;
			r_list_foreach (bb->switch_op->cases, it, cop) {
				bool found;
				int i = ht_uu_find (ht, bb->addr, &found);
				if (found) {
					int i2 = ht_uu_find (ht, cop->addr, &found);
					if (found) {
						r_cons_printf ("  edge [\n"
								"    source  %d\n"
								"    target  %d\n"
								"  ]\n", i, i2);
					}
				}
			}
		}
#else
		if (bb->jump != UT64_MAX) {
			r_cons_printf ("  edge [\n"
				"    source  %"PFMT64d"\n"
				"    target  %"PFMT64d"\n"
				"  ]\n", bb->addr, bb->jump
				);
		}
		if (bb->fail != UT64_MAX) {
			r_cons_printf ("  edge [\n"
				"    source  %"PFMT64d"\n"
				"    target  %"PFMT64d"\n"
				"  ]\n", bb->addr, bb->fail
				);
		}
		if (bb->switch_op) {
			RListIter *it;
			RAnalCaseOp *cop;
			r_list_foreach (bb->switch_op->cases, it, cop) {
				r_cons_printf ("  edge [\n"
					"    source  %"PFMT64d"\n"
					"    target  %"PFMT64d"\n"
					"  ]\n", bb->addr, cop->addr
					);
			}
		}
#endif
	}
	r_cons_printf ("]\n");
	ht_uu_free (ht);
	return true;
}

R_API void r_core_anal_datarefs(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		bool found = false;
		const char *me = fcn->name;
		RListIter *iter;
		RAnalRef *ref;
		RList *refs = r_anal_function_get_refs (fcn);
		r_list_foreach (refs, iter, ref) {
			RBinObject *obj = r_bin_cur_object (core->bin);
			RBinSection *binsec = r_bin_get_section_at (obj, ref->addr, true);
			if (binsec && binsec->is_data) {
				if (!found) {
					r_cons_printf ("agn %s\n", me);
					found = true;
				}
				RFlagItem *item = r_flag_get_i (core->flags, ref->addr);
				const char *dst = item? item->name: sdb_fmt ("0x%08"PFMT64x, ref->addr);
				r_cons_printf ("agn %s\n", dst);
				r_cons_printf ("age %s %s\n", me, dst);
			}
		}
		r_list_free (refs);
	} else {
		eprintf ("Not in a function. Use 'df' to define it.\n");
	}
}

R_API void r_core_anal_coderefs(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		const char *me = fcn->name;
		RListIter *iter;
		RAnalRef *ref;
		RList *refs = r_anal_function_get_refs (fcn);
		r_cons_printf ("agn %s\n", me);
		r_list_foreach (refs, iter, ref) {
			RFlagItem *item = r_flag_get_i (core->flags, ref->addr);
			const char *dst = item? item->name: sdb_fmt ("0x%08"PFMT64x, ref->addr);
			r_cons_printf ("agn %s\n", dst);
			r_cons_printf ("age %s %s\n", me, dst);
		}
		r_list_free (refs);
	} else {
		eprintf("Not in a function. Use 'df' to define it.\n");
	}
}

static void add_single_addr_xrefs(RCore *core, ut64 addr, RGraph *graph) {
	r_return_if_fail (graph);
	RFlagItem *f = r_flag_get_at (core->flags, addr, false);
	char *me = (f && f->offset == addr)
		? r_str_new (f->name)
		: r_str_newf ("0x%" PFMT64x, addr);

	RGraphNode *curr_node = r_graph_add_node_info (graph, me, NULL, addr);
	R_FREE (me);
	if (!curr_node) {
		return;
	}
	RListIter *iter;
	RAnalRef *ref;
	RList *list = r_anal_xrefs_get (core->anal, addr);
	r_list_foreach (list, iter, ref) {
		RFlagItem *item = r_flag_get_i (core->flags, ref->addr);
		char *src = item? r_str_new (item->name): r_str_newf ("0x%08" PFMT64x, ref->addr);
		RGraphNode *reference_from = r_graph_add_node_info (graph, src, NULL, ref->addr);
		free (src);
		r_graph_add_edge (graph, reference_from, curr_node);
	}
	r_list_free (list);
}

R_API RGraph *r_core_anal_importxrefs(RCore *core) {
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinObject *obj = r_bin_cur_object (core->bin);
	bool lit = info? info->has_lit: false;
	bool va = core->io->va || r_config_get_b (core->config, "cfg.debug");

	RListIter *iter;
	RBinImport *imp;
	if (!obj) {
		return NULL;
	}
	RGraph *graph = r_graph_new ();
	if (!graph) {
		return NULL;
	}
	r_list_foreach (obj->imports, iter, imp) {
		ut64 addr = lit ? r_core_bin_impaddr (core->bin, va, imp->name): 0;
		if (addr) {
			add_single_addr_xrefs (core, addr, graph);
		} else {
			r_graph_add_node_info (graph, imp->name, NULL, 0);
		}
	}
	return graph;
}

R_API RGraph *r_core_anal_codexrefs(RCore *core, ut64 addr) {
	RGraph *graph = r_graph_new ();
	if (!graph) {
		return NULL;
	}
	add_single_addr_xrefs (core, addr, graph);
	return graph;
}

static int RAnalRef_cmp(const RAnalRef* ref1, const RAnalRef* ref2) {
	return ref1->addr != ref2->addr;
}

R_API void r_core_anal_callgraph(RCore *core, ut64 addr, int fmt) {
	const char *font = r_config_get (core->config, "graph.font");
	int is_html = r_cons_context ()->is_html;
	bool refgraph = r_config_get_i (core->config, "graph.refs");
	RListIter *iter, *iter2;
	int usenames = r_config_get_i (core->config, "graph.json.usenames");;
	RAnalFunction *fcni;
	RAnalRef *fcnr;
	PJ *pj = NULL;

	ut64 from = r_config_get_i (core->config, "graph.from");
	ut64 to = r_config_get_i (core->config, "graph.to");

	switch (fmt) {
	case R_GRAPH_FORMAT_JSON:
		pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
		break;
	case R_GRAPH_FORMAT_GML:
	case R_GRAPH_FORMAT_GMLFCN:
		r_cons_printf ("graph\n[\n"
				"hierarchic  1\n"
				"label  \"\"\n"
				"directed  1\n");
		break;
	case R_GRAPH_FORMAT_DOT:
		if (!is_html) {
			const char * gv_edge = r_config_get (core->config, "graph.gv.edge");
			char * gv_node = strdup (r_config_get (core->config, "graph.gv.node"));
			const char * gv_grph = r_config_get (core->config, "graph.gv.graph");
			const char * gv_spline = r_config_get (core->config, "graph.gv.spline");
			if (!gv_edge || !*gv_edge) {
				gv_edge = "arrowhead=\"normal\" style=bold weight=2";
			}
			if (!gv_node || !*gv_node) {
				const char *font = r_config_get (core->config, "graph.font");
				free (gv_node);
				gv_node = r_str_newf ("penwidth=4 fillcolor=white style=filled fontname=\"%s Bold\" fontsize=14 shape=box", font);
			}
			if (!gv_grph || !*gv_grph) {
				gv_grph = "bgcolor=azure";
			}
			if (!gv_spline || !*gv_spline) {
				// ortho for bbgraph and curved for callgraph
				gv_spline = "splines=\"curved\"";
			}
			r_cons_printf ("digraph code {\n"
					"rankdir=LR;\n"
					"outputorder=edgesfirst;\n"
					"graph [%s fontname=\"%s\" %s];\n"
					"node [%s];\n"
					"edge [%s];\n", gv_grph, font, gv_spline,
					gv_node, gv_edge);
			free (gv_node);
		}
		break;
	}
	ut64 base = UT64_MAX;
	int iteration = 0;
repeat:
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (base == UT64_MAX) {
			base = fcni->addr;
		}
		if (from != UT64_MAX && fcni->addr < from) {
			continue;
		}
		if (to != UT64_MAX && fcni->addr > to) {
			continue;
		}
		if (addr != UT64_MAX && addr != fcni->addr) {
			continue;
		}
		RList *refs = r_anal_function_get_refs (fcni);
		RList *calls = r_list_new ();
		// TODO: maybe fcni->calls instead ?
		r_list_foreach (refs, iter2, fcnr) {
			//  TODO: tail calll jumps are also calls
			if (fcnr->type == 'C' && r_list_find(calls, fcnr, (RListComparator)RAnalRef_cmp) == NULL) {
				r_list_append (calls, fcnr);
			}
		}
		if (r_list_empty(calls)) {
			r_list_free (refs);
			r_list_free (calls);
			continue;
		}
		switch (fmt) {
		case R_GRAPH_FORMAT_NO:
			r_cons_printf ("0x%08"PFMT64x"\n", fcni->addr);
			break;
		case R_GRAPH_FORMAT_GML:
		case R_GRAPH_FORMAT_GMLFCN: {
			RFlagItem *flag = r_flag_get_i (core->flags, fcni->addr);
			if (iteration == 0) {
				char *msg = flag? strdup (flag->name): r_str_newf ("0x%08"PFMT64x, fcni->addr);
				r_cons_printf ("  node [\n"
						"  id  %"PFMT64d"\n"
						"    label  \"%s\"\n"
						"  ]\n", fcni->addr - base, msg);
				free (msg);
			}
			break;
		}
		case R_GRAPH_FORMAT_JSON:
			pj_o (pj);
			if (usenames) {
				pj_ks (pj, "name", fcni->name);
			} else {
				char fcni_addr[20];
				snprintf (fcni_addr, sizeof (fcni_addr) - 1, "0x%08" PFMT64x, fcni->addr);
				pj_ks (pj, "name", fcni_addr);
			}
			pj_kn (pj, "size", r_anal_function_linear_size (fcni));
			pj_ka (pj, "imports");
			break;
		case R_GRAPH_FORMAT_DOT:
			r_cons_printf ("  \"0x%08"PFMT64x"\" "
					"[label=\"%s\""
					" URL=\"%s/0x%08"PFMT64x"\"];\n",
					fcni->addr, fcni->name,
					fcni->name, fcni->addr);
		}
		r_list_foreach (calls, iter2, fcnr) {
			// TODO: display only code or data refs?
			RFlagItem *flag = r_flag_get_i (core->flags, fcnr->addr);
			char *fcnr_name = (flag && flag->name) ? flag->name : r_str_newf ("unk.0x%"PFMT64x, fcnr->addr);
			switch (fmt) {
			case R_GRAPH_FORMAT_GMLFCN:
				if (iteration == 0) {
					r_cons_printf ("  node [\n"
							"    id  %"PFMT64d"\n"
							"    label  \"%s\"\n"
							"  ]\n", fcnr->addr - base, fcnr_name);
					r_cons_printf ("  edge [\n"
							"    source  %"PFMT64d"\n"
							"    target  %"PFMT64d"\n"
							"  ]\n", fcni->addr-base, fcnr->addr-base);
				}
			case R_GRAPH_FORMAT_GML:
				if (iteration != 0) {
					r_cons_printf ("  edge [\n"
							"    source  %"PFMT64d"\n"
							"    target  %"PFMT64d"\n"
							"  ]\n", fcni->addr-base, fcnr->addr-base); //, "#000000"
				}
				break;
			case R_GRAPH_FORMAT_DOT:
				r_cons_printf ("  \"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
						"[color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
						//"[label=\"%s\" color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
						fcni->addr, fcnr->addr, //, fcnr_name,
						"#61afef",
						fcnr_name, fcnr->addr);
				r_cons_printf ("  \"0x%08"PFMT64x"\" "
						"[label=\"%s\""
						" URL=\"%s/0x%08"PFMT64x"\"];\n",
						fcnr->addr, fcnr_name,
						fcnr_name, fcnr->addr);
				break;
			case R_GRAPH_FORMAT_JSON:
				if (usenames) {
					pj_s (pj, fcnr_name);
				} else {
					char fcnr_addr[20];
					snprintf (fcnr_addr, sizeof (fcnr_addr) - 1, "0x%08" PFMT64x, fcnr->addr);
					pj_s (pj, fcnr_addr);
				}
				break;
			default:
				if (refgraph || fcnr->type == R_ANAL_REF_TYPE_CALL) {
					// TODO: avoid recreating nodes unnecessarily
					r_cons_printf ("agn %s\n", fcni->name);
					r_cons_printf ("agn %s\n", fcnr_name);
					r_cons_printf ("age %s %s\n", fcni->name, fcnr_name);
				} else {
					r_cons_printf ("# - 0x%08"PFMT64x" (%c)\n", fcnr->addr, fcnr->type);
				}
			}
			if (!(flag && flag->name)) {
				free(fcnr_name);
			}
		}
		r_list_free (refs);
		r_list_free (calls);
		if (fmt == R_GRAPH_FORMAT_JSON) {
			pj_end (pj);
			pj_end (pj);
		}
	}
	if (iteration == 0 && fmt == R_GRAPH_FORMAT_GML) {
		iteration++;
		goto repeat;
	}
	if (iteration == 0 && fmt == R_GRAPH_FORMAT_GMLFCN) {
		iteration++;
	}
	switch (fmt) {
	case R_GRAPH_FORMAT_GML:
	case R_GRAPH_FORMAT_GMLFCN:
	case R_GRAPH_FORMAT_JSON:
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
		break;
	case R_GRAPH_FORMAT_DOT:
		r_cons_printf ("}\n");
		break;
	}
}

static void fcn_list_bbs(RAnalFunction *fcn) {
	RAnalBlock *bbi;
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi) {
		r_cons_printf ("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %" PFMT64u " ",
				   fcn->addr, bbi->addr, bbi->size);
		r_cons_printf ("0x%08"PFMT64x" ", bbi->jump);
		r_cons_printf ("0x%08"PFMT64x, bbi->fail);
		if (bbi->diff) {
			if (bbi->diff->type == R_ANAL_DIFF_TYPE_MATCH) {
				r_cons_printf (" m");
			} else if (bbi->diff->type == R_ANAL_DIFF_TYPE_UNMATCH) {
				r_cons_printf (" u");
			} else {
				r_cons_printf (" n");
			}
		}
		r_cons_printf ("\n");
	}
}

R_API ut64 r_core_anal_fcn_list_size(RCore *core) {
	RAnalFunction *fcn;
	RListIter *iter;
	ut64 total = 0;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		total += r_anal_function_realsize (fcn);
	}
	r_cons_printf ("%"PFMT64u"\n", total);
	return total;
}

/* Fill out metadata struct of functions */
static int fcnlist_gather_metadata(RAnal *anal, RList *fcns) {
	RListIter *iter;
	RAnalFunction *fcn;
	RList *xrefs;

	r_list_foreach (fcns, iter, fcn) {
		// Count the number of references and number of calls
		RListIter *callrefiter;
		RAnalRef *ref;
		RList *refs = r_anal_function_get_refs (fcn);
		int numcallrefs = 0;
		r_list_foreach (refs, callrefiter, ref) {
			if (ref->type == R_ANAL_REF_TYPE_CALL) {
				numcallrefs++;
			}
		}
		r_list_free (refs);
		fcn->meta.numcallrefs = numcallrefs;
		xrefs = r_anal_xrefs_get (anal, fcn->addr);
		fcn->meta.numrefs = xrefs? xrefs->length: 0;
		r_list_free (xrefs);
	}
	// TODO: Determine sgnc, sgec
	return 0;
}

R_API char *r_core_anal_fcn_name(RCore *core, RAnalFunction *fcn) {
	bool demangle = r_config_get_i (core->config, "bin.demangle");
	const char *lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;
	bool keep_lib = r_config_get_i (core->config, "bin.demangle.libs");
	char *name = strdup (r_str_get (fcn->name));
	if (demangle) {
		char *tmp = r_bin_demangle (core->bin->cur, lang, name, fcn->addr, keep_lib);
		if (tmp) {
			free (name);
			name = tmp;
		}
	}
	return name;
}

#define FCN_LIST_VERBOSE_ENTRY "%s0x%0*"PFMT64x" %4"PFMT64d" %5d %5d %5d %4d 0x%0*"PFMT64x" %5"PFMT64d" 0x%0*"PFMT64x" %5d %4d %6d %4d %5d %s%s\n"
static int fcn_print_verbose(RCore *core, RAnalFunction *fcn, bool use_color) {
	char *name = r_core_anal_fcn_name (core, fcn);
	int ebbs = 0;
	int addrwidth = 8;
	const char *color = "";
	const char *color_end = "";
	if (use_color) {
		color_end = Color_RESET;
		if (strstr (name, "sym.imp.")) {
			color = Color_YELLOW;
		} else if (strstr (name, "sym.")) {
			color = Color_GREEN;
		} else if (strstr (name, "sub.")) {
			color = Color_MAGENTA;
		}
	}

	if (core->anal->bits == 64) {
		addrwidth = 16;
	}

	r_cons_printf (FCN_LIST_VERBOSE_ENTRY, color,
			addrwidth, fcn->addr,
			r_anal_function_realsize (fcn),
			r_list_length (fcn->bbs),
			r_anal_function_count_edges (fcn, &ebbs),
			r_anal_function_complexity (fcn),
			r_anal_function_cost (fcn),
			addrwidth, r_anal_function_min_addr (fcn),
			r_anal_function_linear_size (fcn),
			addrwidth, r_anal_function_max_addr (fcn),
			fcn->meta.numcallrefs,
			r_anal_var_count (core->anal, fcn, 's', 0) +
			r_anal_var_count (core->anal, fcn, 'b', 0) +
			r_anal_var_count (core->anal, fcn, 'r', 0),
			r_anal_var_count (core->anal, fcn, 's', 1) +
			r_anal_var_count (core->anal, fcn, 'b', 1) +
			r_anal_var_count (core->anal, fcn, 'r', 1),
			fcn->meta.numrefs,
			fcn->maxstack,
			name,
			color_end);
	free (name);
	return 0;
}

static int fcn_list_verbose(RCore *core, RList *fcns, const char *sortby) {
	bool use_color = r_config_get_i (core->config, "scr.color");
	int headeraddr_width = 10;
	char *headeraddr = "==========";

	if (core->anal->bits == 64) {
		headeraddr_width = 18;
		headeraddr = "==================";
	}

	if (sortby) {
		if (!strcmp (sortby, "size")) {
			r_list_sort (fcns, cmpsize);
		} else if (!strcmp (sortby, "addr")) {
			r_list_sort (fcns, cmpaddr);
		} else if (!strcmp (sortby, "cc")) {
			r_list_sort (fcns, cmpfcncc);
		} else if (!strcmp (sortby, "edges")) {
			r_list_sort (fcns, cmpedges);
		} else if (!strcmp (sortby, "calls")) {
			r_list_sort (fcns, cmpcalls);
		} else if (strstr (sortby, "name")) {
			r_list_sort (fcns, cmpname);
		} else if (strstr (sortby, "frame")) {
			r_list_sort (fcns, cmpframe);
		} else if (strstr (sortby, "ref")) {
			r_list_sort (fcns, cmpxrefs);
		} else if (!strcmp (sortby, "nbbs")) {
			r_list_sort (fcns, cmpnbbs);
		}
	}

	r_cons_printf ("%-*s %4s %5s %5s %5s %4s %*s range %-*s %s %s %s %s %s %s\n",
			headeraddr_width, "address", "size", "nbbs", "edges", "cc", "cost",
			headeraddr_width, "min bound", headeraddr_width, "max bound", "calls",
			"locals", "args", "xref", "frame", "name");
	r_cons_printf ("%s ==== ===== ===== ===== ==== %s ===== %s ===== ====== ==== ==== ===== ====\n",
			headeraddr, headeraddr, headeraddr);
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		fcn_print_verbose (core, fcn, use_color);
	}

	return 0;
}

static void __fcn_print_default(RCore *core, RAnalFunction *fcn, bool quiet) {
	if (quiet) {
		r_cons_printf ("0x%08"PFMT64x" ", fcn->addr);
	} else {
		char *msg, *name = r_core_anal_fcn_name (core, fcn);
		ut64 realsize = r_anal_function_realsize (fcn);
		ut64 size = r_anal_function_linear_size (fcn);
		if (realsize == size) {
			msg = r_str_newf ("%-12"PFMT64u, size);
		} else {
			msg = r_str_newf ("%-4"PFMT64u" -> %-4"PFMT64u, size, realsize);
		}
		r_cons_printf ("0x%08"PFMT64x" %4d %4s %s\n",
				fcn->addr, r_list_length (fcn->bbs), msg, name);
		free (name);
		free (msg);
	}
}

static int fcn_list_default(RCore *core, RList *fcns, bool quiet) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		__fcn_print_default (core, fcn, quiet);
		if (quiet) {
			r_cons_newline ();
		}
	}
	return 0;
}

// for a given function returns an RList of all functions that were called in it
R_API RList *r_core_anal_fcn_get_calls (RCore *core, RAnalFunction *fcn) {
	RAnalRef *refi;
	RListIter *iter, *iter2;

	// get all references from this function
	RList *refs = r_anal_function_get_refs (fcn);
	// sanity check
	if (!r_list_empty (refs)) {
		// iterate over all the references and remove these which aren't of type call
		r_list_foreach_safe (refs, iter, iter2, refi) {
			if (refi->type != R_ANAL_REF_TYPE_CALL) {
				r_list_delete (refs, iter);
			}
		}
	}
	return refs;
}

// Lists function names and their calls (uniqified)
static int fcn_print_makestyle(RCore *core, RList *fcns, char mode) {
	RListIter *refiter;
	RListIter *fcniter;
	RAnalFunction *fcn;
	RAnalRef *refi;
	RList *refs = NULL;
	PJ *pj = NULL;

	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}

	// Iterate over all functions
	r_list_foreach (fcns, fcniter, fcn) {
		// Get all refs for a function
		refs = r_core_anal_fcn_get_calls (core, fcn);
		// Uniquify the list by ref->addr
		refs = r_list_uniq (refs, (RListComparator)RAnalRef_cmp);

		// don't enter for functions with 0 refs
		if (!r_list_empty (refs)) {
			if (pj) { // begin json output of function
				pj_o (pj);
				pj_ks (pj, "name", fcn->name);
				pj_kn (pj, "addr", fcn->addr);
				pj_k (pj, "calls");
				pj_a (pj);
			} else {
				r_cons_printf ("%s", fcn->name);
			}

			if (mode == 'm') {
				r_cons_printf (":\n");
			} else if (mode == 'q') {
				r_cons_printf (" -> ");
			}
			// Iterate over all refs from a function
			r_list_foreach (refs, refiter, refi) {
				RFlagItem *f = r_flag_get_i (core->flags, refi->addr);
				char *dst = r_str_newf ((f? f->name: "0x%08"PFMT64x), refi->addr);
				if (pj) { // Append calee json item
					pj_o (pj);
					pj_ks (pj, "name", dst);
					pj_kn (pj, "addr", refi->addr);
					pj_end (pj); // close referenced item
				} else if (mode == 'q') {
					r_cons_printf ("%s ", dst);
				} else {
					r_cons_printf ("    %s\n", dst);
				}
			}
			if (pj) {
				pj_end (pj); // close list of calls
				pj_end (pj); // close function item
			} else {
				r_cons_newline();
			}
		}
	}

	if (mode == 'j') {
		pj_end (pj); // close json output
		r_cons_printf ("%s\n", pj_string (pj));
	}
	if (pj) {
		pj_free (pj);
	}
	return 0;
}

static int fcn_print_json(RCore *core, RAnalFunction *fcn, PJ *pj) {
	RListIter *iter;
	RAnalRef *refi;
	RList *refs, *xrefs;
	if (!pj) {
		return -1;
	}
	int ebbs = 0;
	pj_o (pj);
	pj_kn (pj, "offset", fcn->addr);
	char *name = r_core_anal_fcn_name (core, fcn);
	if (name) {
		pj_ks (pj, "name", name);
	}
	pj_kn (pj, "size", r_anal_function_linear_size (fcn));
	pj_ks (pj, "is-pure", r_str_bool (r_anal_function_purity (fcn)));
	pj_kn (pj, "realsz", r_anal_function_realsize (fcn));
	pj_kb (pj, "noreturn", fcn->is_noreturn);
	pj_ki (pj, "stackframe", fcn->maxstack);
	if (fcn->cc) {
		pj_ks (pj, "calltype", fcn->cc); // calling conventions
	}
	pj_ki (pj, "cost", r_anal_function_cost (fcn)); // execution cost
	pj_ki (pj, "cc", r_anal_function_complexity (fcn)); // cyclic cost
	pj_ki (pj, "bits", fcn->bits);
	pj_ks (pj, "type", r_anal_fcntype_tostring (fcn->type));
	pj_ki (pj, "nbbs", r_list_length (fcn->bbs));
	pj_ki (pj, "edges", r_anal_function_count_edges (fcn, &ebbs));
	pj_ki (pj, "ebbs", ebbs);
	{
		char *sig = r_core_cmd_strf (core, "afcf @ 0x%"PFMT64x, fcn->addr);
		if (sig) {
			r_str_trim (sig);
			pj_ks (pj, "signature", sig);
			free (sig);
		}

	}
	pj_kn (pj, "minbound", r_anal_function_min_addr (fcn));
	pj_kn (pj, "maxbound", r_anal_function_max_addr (fcn));

	int outdegree = 0;
	refs = r_anal_function_get_refs (fcn);
	if (!r_list_empty (refs)) {
		pj_k (pj, "callrefs");
		pj_a (pj);
		r_list_foreach (refs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_CALL) {
				outdegree++;
			}
			if (refi->type == R_ANAL_REF_TYPE_CODE ||
				refi->type == R_ANAL_REF_TYPE_CALL) {
				pj_o (pj);
				pj_kn (pj, "addr", refi->addr);
				pj_ks (pj, "type", r_anal_xrefs_type_tostring (refi->type));
				pj_kn (pj, "at", refi->at);
				pj_end (pj);
			}
		}
		pj_end (pj);

		pj_k (pj, "datarefs");
		pj_a (pj);
		r_list_foreach (refs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_DATA) {
				pj_n (pj, refi->addr);
			}
		}
		pj_end (pj);
	}
	r_list_free (refs);

	int indegree = 0;
	xrefs = r_anal_function_get_xrefs (fcn);
	if (!r_list_empty (xrefs)) {
		pj_k (pj, "codexrefs");
		pj_a (pj);
		r_list_foreach (xrefs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_CODE ||
				refi->type == R_ANAL_REF_TYPE_CALL) {
				indegree++;
				pj_o (pj);
				pj_kn (pj, "addr", refi->addr);
				pj_ks (pj, "type", r_anal_xrefs_type_tostring (refi->type));
				pj_kn (pj, "at", refi->at);
				pj_end (pj);
			}
		}

		pj_end (pj);
		pj_k (pj, "dataxrefs");
		pj_a (pj);

		r_list_foreach (xrefs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_DATA) {
				pj_n (pj, refi->addr);
			}
		}
		pj_end (pj);
	}
	r_list_free (xrefs);

	pj_ki (pj, "indegree", indegree);
	pj_ki (pj, "outdegree", outdegree);

	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		pj_ki (pj, "nlocals", r_anal_var_count (core->anal, fcn, 'b', 0) +
				r_anal_var_count (core->anal, fcn, 'r', 0) +
				r_anal_var_count (core->anal, fcn, 's', 0));
		pj_ki (pj, "nargs", r_anal_var_count (core->anal, fcn, 'b', 1) +
				r_anal_var_count (core->anal, fcn, 'r', 1) +
				r_anal_var_count (core->anal, fcn, 's', 1));

		pj_k (pj, "bpvars");
		r_anal_var_list_show (core->anal, fcn, 'b', 'j', pj);
		pj_k (pj, "spvars");
		r_anal_var_list_show (core->anal, fcn, 's', 'j', pj);
		pj_k (pj, "regvars");
		r_anal_var_list_show (core->anal, fcn, 'r', 'j', pj);

		pj_ks (pj, "difftype", fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"match":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new");
		if (fcn->diff->addr != -1) {
			pj_kn (pj, "diffaddr", fcn->diff->addr);
		}
		if (fcn->diff->name) {
			pj_ks (pj, "diffname", fcn->diff->name);
		}
	}
	pj_end (pj);
	free (name);
	return 0;
}

static int fcn_list_json(RCore *core, RList *fcns, bool quiet) {
	RListIter *iter;
	RAnalFunction *fcn;
	PJ *pj = r_core_pj_new (core);
	if (!pj) {
		r_cons_println ("[]");
		return -1;
	}
	pj_a (pj);
	r_list_foreach (fcns, iter, fcn) {
		if (quiet) {
			pj_n (pj, fcn->addr);
		} else {
			fcn_print_json (core, fcn, pj);
		}
	}
	pj_end (pj);
	r_cons_println (pj_string (pj));
	pj_free (pj);
	return 0;
}

static int fcn_list_verbose_json(RCore *core, RList *fcns) {
	return fcn_list_json (core, fcns, false);
}

static int fcn_print_detail(RCore *core, RAnalFunction *fcn) {
	const char *defaultCC = r_anal_cc_default (core->anal);
	char *name = r_core_anal_fcn_name (core, fcn);
	r_cons_printf ("\"f %s %"PFMT64u" 0x%08"PFMT64x"\"\n", name, r_anal_function_linear_size (fcn), fcn->addr);
	r_cons_printf ("\"af+ 0x%08"PFMT64x" %s %c %c\"\n",
			fcn->addr, name, //r_anal_fcn_size (fcn), name,
			fcn->type == R_ANAL_FCN_TYPE_LOC?'l':
			fcn->type == R_ANAL_FCN_TYPE_SYM?'s':
			fcn->type == R_ANAL_FCN_TYPE_IMP?'i':'f',
			fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?'m':
			fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?'u':'n');
	// FIXME: this command prints something annoying. Does it have important side-effects?
	fcn_list_bbs (fcn);
	if (fcn->bits != 0) {
		r_cons_printf ("afB %d @ 0x%08"PFMT64x"\n", fcn->bits, fcn->addr);
	}
	// FIXME command injection vuln here
	if (fcn->cc || defaultCC) {
		r_cons_printf ("afc %s @ 0x%08"PFMT64x"\n", fcn->cc?fcn->cc: defaultCC, fcn->addr);
	}
	if (fcn->folded) {
		r_cons_printf ("afF @ 0x%08"PFMT64x"\n", fcn->addr);
	}
	if (fcn) {
		/* show variables  and arguments */
		r_core_cmdf (core, "afvb* @ 0x%"PFMT64x"\n", fcn->addr);
		r_core_cmdf (core, "afvr* @ 0x%"PFMT64x"\n", fcn->addr);
		r_core_cmdf (core, "afvs* @ 0x%"PFMT64x"\n", fcn->addr);
	}
	/* Show references */
	RListIter *refiter;
	RAnalRef *refi;
	RList *refs = r_anal_function_get_refs (fcn);
	r_list_foreach (refs, refiter, refi) {
		switch (refi->type) {
		case R_ANAL_REF_TYPE_CALL:
			r_cons_printf ("axC 0x%"PFMT64x" 0x%"PFMT64x"\n", refi->addr, refi->at);
			break;
		case R_ANAL_REF_TYPE_DATA:
			r_cons_printf ("axd 0x%"PFMT64x" 0x%"PFMT64x"\n", refi->addr, refi->at);
			break;
		case R_ANAL_REF_TYPE_CODE:
			r_cons_printf ("axc 0x%"PFMT64x" 0x%"PFMT64x"\n", refi->addr, refi->at);
			break;
		case R_ANAL_REF_TYPE_STRING:
			r_cons_printf ("axs 0x%"PFMT64x" 0x%"PFMT64x"\n", refi->addr, refi->at);
			break;
		case R_ANAL_REF_TYPE_NULL:
		default:
			r_cons_printf ("ax 0x%"PFMT64x" 0x%"PFMT64x"\n", refi->addr, refi->at);
			break;
		}
	}
	r_list_free (refs);
	/*Saving Function stack frame*/
	r_cons_printf ("afS %d @ 0x%"PFMT64x"\n", fcn->maxstack, fcn->addr);
	free (name);
	return 0;
}

static bool is_fcn_traced(RDebugTrace *traced, RAnalFunction *fcn) {
	int tag = traced->tag;
	RListIter *iter;
	RDebugTracepoint *trace;

	r_list_foreach (traced->traces, iter, trace) {
		if (!trace->tag || (tag & trace->tag)) {
			if (r_anal_function_contains (fcn, trace->addr)) {
				r_cons_printf ("\ntraced: %d\n", trace->times);
				return true;
			}
		}
	}
	return false;
}

static int fcn_print_legacy(RCore *core, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalRef *refi;
	RList *refs, *xrefs;
	int ebbs = 0;
	char *name = r_core_anal_fcn_name (core, fcn);

	r_cons_printf ("#\noffset: 0x%08"PFMT64x"\nname: %s\nsize: %"PFMT64u,
			fcn->addr, name, r_anal_function_linear_size (fcn));
	r_cons_printf ("\nis-pure: %s", r_str_bool (r_anal_function_purity (fcn)));
	r_cons_printf ("\nrealsz: %" PFMT64d, r_anal_function_realsize (fcn));
	r_cons_printf ("\nstackframe: %d", fcn->maxstack);
	if (fcn->cc) {
		r_cons_printf ("\ncall-convention: %s", fcn->cc);
	}
	r_cons_printf ("\ncyclomatic-cost: %d", r_anal_function_cost (fcn));
	r_cons_printf ("\ncyclomatic-complexity: %d", r_anal_function_complexity (fcn));
	r_cons_printf ("\nbits: %d", fcn->bits);
	r_cons_printf ("\ntype: %s", r_anal_fcntype_tostring (fcn->type));
	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		r_cons_printf (" [%s]",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"MATCH":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"UNMATCH":"NEW");
	}
	r_cons_printf ("\nnum-bbs: %d", r_list_length (fcn->bbs));
	r_cons_printf ("\nedges: %d", r_anal_function_count_edges (fcn, &ebbs));
	r_cons_printf ("\nend-bbs: %d", ebbs);
	r_cons_printf ("\ncall-refs:");
	int outdegree = 0;
	refs = r_anal_function_get_refs (fcn);
	r_list_foreach (refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CALL) {
			outdegree++;
		}
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			r_cons_printf (" 0x%08"PFMT64x" %c", refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J');
		}
	}
	r_cons_printf ("\ndata-refs:");
	r_list_foreach (refs, iter, refi) {
		// global or local?
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf (" 0x%08"PFMT64x, refi->addr);
		}
	}
	r_list_free (refs);

	int indegree = 0;
	r_cons_printf ("\ncode-xrefs:");
	xrefs = r_anal_function_get_xrefs (fcn);
	r_list_foreach (xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			indegree++;
			r_cons_printf (" 0x%08"PFMT64x" %c", refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J');
		}
	}
	r_cons_printf ("\nnoreturn: %s", r_str_bool (fcn->is_noreturn));
	r_cons_printf ("\nin-degree: %d", indegree);
	r_cons_printf ("\nout-degree: %d", outdegree);
	r_cons_printf ("\ndata-xrefs:");
	r_list_foreach (xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf (" 0x%08"PFMT64x, refi->addr);
		}
	}
	r_list_free (xrefs);

	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		int args_count = r_anal_var_count (core->anal, fcn, 'b', 1);
		args_count += r_anal_var_count (core->anal, fcn, 's', 1);
		args_count += r_anal_var_count (core->anal, fcn, 'r', 1);
		int var_count = r_anal_var_count (core->anal, fcn, 'b', 0);
		var_count += r_anal_var_count (core->anal, fcn, 's', 0);
		var_count += r_anal_var_count (core->anal, fcn, 'r', 0);

		r_cons_printf ("\nlocals: %d\nargs: %d\n", var_count, args_count);
		r_anal_var_list_show (core->anal, fcn, 'b', 0, NULL);
		r_anal_var_list_show (core->anal, fcn, 's', 0, NULL);
		r_anal_var_list_show (core->anal, fcn, 'r', 0, NULL);
		r_cons_printf ("diff: type: %s",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"match":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new");
		if (fcn->diff->addr != -1) {
			r_cons_printf ("addr: 0x%"PFMT64x, fcn->diff->addr);
		}
		if (fcn->diff->name) {
			r_cons_printf ("function: %s", fcn->diff->name);
		}
	}
	free (name);

	// traced
	if (core->dbg->trace->enabled) {
		is_fcn_traced (core->dbg->trace, fcn);
	}
	return 0;
}

static int fcn_list_detail(RCore *core, RList *fcns) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		fcn_print_detail (core, fcn);
	}
	r_cons_newline ();
	return 0;
}

static int fcn_list_table(RCore *core, const char *q, int fmt) {
	RAnalFunction *fcn;
	RListIter *iter;
	RTable *t = r_core_table (core, "fcns");
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	r_table_add_column (t, typeNumber, "addr", 0);
	r_table_add_column (t, typeNumber, "size", 0);
	r_table_add_column (t, typeString, "name", 0);
	r_table_add_column (t, typeNumber, "nbbs", 0);
	r_table_add_column (t, typeNumber, "xref", 0);
	r_table_add_column (t, typeNumber, "calls", 0);
	r_table_add_column (t, typeNumber, "cc", 0);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		const char *fcnAddr = sdb_fmt ("0x%08"PFMT64x, fcn->addr);
		const char *fcnSize = sdb_fmt ("%"PFMT64u, r_anal_function_linear_size (fcn));
		const char *nbbs = sdb_fmt ("%d", r_list_length (fcn->bbs)); // r_anal_fcn_size (fcn));
		RList *xrefs = r_anal_function_get_xrefs (fcn);
		char xref[128], ccstr[128];
		snprintf (xref, sizeof (xref), "%d", r_list_length (xrefs));
		r_list_free (xrefs);

		RList * calls = r_core_anal_fcn_get_calls (core, fcn);
		// Uniquify the list by ref->addr
		calls = r_list_uniq (calls, (RListComparator)RAnalRef_cmp);
		const char *callstr = sdb_fmt ("%d", r_list_length (calls));
		r_list_free (calls);
		snprintf (ccstr, sizeof (ccstr), "%d", r_anal_function_complexity (fcn));

		r_table_add_row (t, fcnAddr, fcnSize, fcn->name, nbbs, xref, callstr, ccstr, NULL);
	}
	if (r_table_query (t, q)) {
		char *s = (fmt== 'j')
			? r_table_tojson (t)
			: r_table_tostring (t);
		r_cons_printf ("%s\n", s);
		free (s);
	}
	r_table_free (t);
	return 0;
}

static int fcn_list_legacy(RCore *core, RList *fcns) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		fcn_print_legacy (core, fcn);
	}
	r_cons_newline ();
	return 0;
}

R_API int r_core_anal_fcn_list(RCore *core, const char *input, const char *rad) {
	char temp[64];
	r_return_val_if_fail (core && core->anal, 0);
	if (r_list_empty (core->anal->fcns)) {
		if (*rad == 'j') {
			r_cons_println ("[]");
		}
		return 0;
	}
	if (*rad == '.') {
		RList *fcns = r_anal_get_functions_in (core->anal, core->offset);
		if (!fcns || r_list_empty (fcns)) {
			eprintf ("No functions at current address.\n");
			r_list_free (fcns);
			return -1;
		}
		fcn_list_default (core, fcns, false);
		r_list_free (fcns);
		return 0;
	}

	if (rad && (*rad == 'l' || *rad == 'j')) {
		fcnlist_gather_metadata (core->anal, core->anal->fcns);
	}

	const char *name = input;
	ut64 addr = core->offset;
	if (input && *input) {
		name = input + 1;
		addr = r_num_math (core->num, name);
	}

	RList *fcns = r_list_newf (NULL);
	if (!fcns) {
		return -1;
	}
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (!input || r_anal_function_contains (fcn, addr) || (!strcmp (name, fcn->name))) {
			r_list_append (fcns, fcn);
		}
	}

	// Use afls[asn] to sort by address, size or name, dont sort it here .. r_list_sort (fcns, &cmpfcn);
	if (!rad) {
		fcn_list_default (core, fcns, false);
		r_list_free (fcns);
		return 0;
	}
	switch (*rad) {
	case '+':
		r_core_anal_fcn_list_size (core);
		break;
	case '=': { // afl=
		r_list_sort (fcns, cmpaddr);
		RList *flist = r_list_newf ((RListFree) r_listinfo_free);
		if (!flist) {
			r_list_free (fcns);
			return -1;
		}
		ls_foreach (fcns, iter, fcn) {
			RInterval inter = {r_anal_function_min_addr (fcn), r_anal_function_linear_size (fcn) };
			RListInfo *info = r_listinfo_new (r_core_anal_fcn_name (core, fcn), inter, inter, -1, sdb_itoa (fcn->bits, temp, 10));
			if (!info) {
				break;
			}
			r_list_append (flist, info);
		}
		RTable *table = r_core_table (core, "functions");
		r_table_visual_list (table, flist, core->offset, core->blocksize,
			r_cons_get_size (NULL), r_config_get_i (core->config, "scr.color"));
		r_cons_printf ("\n%s\n", r_table_tostring (table));
		r_table_free (table);
		r_list_free (flist);
		break;
		}
	case ',': // "afl," "afl,j"
	case 't': // "aflt" "afltj"
		if (rad[1] == 'j') {
			fcn_list_table (core, r_str_trim_head_ro (rad + 2), 'j');
		} else {
			fcn_list_table (core, r_str_trim_head_ro (rad + 1), rad[1]);
		}
		break;
	case 'l': // "afll" "afllj"
		if (rad[1] == 'j') {
			fcn_list_verbose_json (core, fcns);
		} else {
			char *sp = strchr (rad, ' ');
			fcn_list_verbose (core, fcns, sp?sp+1: NULL);
		}
		break;
	case 'q':
		if (rad[1] == 'j') {
			fcn_list_json (core, fcns, true);
		} else {
			fcn_list_default (core, fcns, true);
		}
		break;
	case 'j':
		fcn_list_json (core, fcns, false);
		break;
	case '*':
		fcn_list_detail (core, fcns);
		break;
	case 'm': // "aflm"
		{
			char mode = 'm';
			if (rad[1] != 0) {
				if (rad[1] == 'j') { // "aflmj"
					mode = 'j';
				} else if (rad[1] == 'q') { // "aflmq"
					mode = 'q';
				}
			}
			fcn_print_makestyle (core, fcns, mode);
			break;
		}
	case 1:
		fcn_list_legacy (core, fcns);
		break;
	default:
		fcn_list_default (core, fcns, false);
		break;
	}
	r_list_free (fcns);
	return 0;
}

static RList *recurse_bb(RCore *core, ut64 addr, RAnalBlock *dest);

static RList *recurse(RCore *core, RAnalBlock *from, RAnalBlock *dest) {
	recurse_bb (core, from->jump, dest);
	recurse_bb (core, from->fail, dest);

	/* same for all calls */
	// TODO: RAnalBlock must contain a linked list of calls
	return NULL;
}

static RList *recurse_bb(RCore *core, ut64 addr, RAnalBlock *dest) {
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, addr);
	if (bb == dest) {
		eprintf ("path found!");
		return NULL;
	}
	return recurse (core, bb, dest);
}

#define REG_SET_SIZE (R_ANAL_CC_MAXARG + 2)

typedef struct {
	int count;
	RPVector reg_set;
	bool argonly;
	RAnalFunction *fcn;
	RCore *core;
} BlockRecurseCtx;

static bool anal_block_on_exit(RAnalBlock *bb, BlockRecurseCtx *ctx) {
	int *cur_regset = r_pvector_pop (&ctx->reg_set);
	int *prev_regset = r_pvector_at (&ctx->reg_set, r_pvector_len (&ctx->reg_set) - 1);
	size_t i;
	for (i = 0; i < REG_SET_SIZE; i++) {
		if (!prev_regset[i] && cur_regset[i] == 1) {
			prev_regset[i] = 1;
		}
	}
	free (cur_regset);
	return true;
}

static bool anal_block_cb(RAnalBlock *bb, BlockRecurseCtx *ctx) {
	if (r_cons_is_breaked ()) {
		return false;
	}
	if (bb->size < 1) {
		return true;
	}
	if (bb->size > ctx->core->anal->opt.bb_max_size) {
		return true;
	}
	int *parent_reg_set = r_pvector_at (&ctx->reg_set, r_pvector_len (&ctx->reg_set) - 1);
	int *reg_set = R_NEWS (int, REG_SET_SIZE);
	memcpy (reg_set, parent_reg_set, REG_SET_SIZE * sizeof (int));
	r_pvector_push (&ctx->reg_set, reg_set);
	RCore *core = ctx->core;
	RAnalFunction *fcn = ctx->fcn;
	fcn->stack = bb->parent_stackptr;
	ut64 pos = bb->addr;
	while (pos < bb->addr + bb->size) {
		if (r_cons_is_breaked ()) {
			break;
		}
		RAnalOp *op = r_core_anal_op (core, pos, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_HINT);
		if (!op) {
			//eprintf ("Cannot get op\n");
			break;
		}
		r_anal_extract_rarg (core->anal, op, fcn, reg_set, &ctx->count);
		if (!ctx->argonly) {
			if (op->stackop == R_ANAL_STACK_INC) {
				fcn->stack += op->stackptr;
			} else if (op->stackop == R_ANAL_STACK_RESET) {
				fcn->stack = 0;
			}
			r_anal_extract_vars (core->anal, fcn, op);
		}
		int opsize = op->size;
		int optype = op->type;
		r_anal_op_free (op);
		if (opsize < 1) {
			break;
		}
		if (optype == R_ANAL_OP_TYPE_CALL) {
			size_t i;
			int max_count = fcn->cc ? r_anal_cc_max_arg (core->anal, fcn->cc) : 0;
			for (i = 0; i < max_count; i++) {
				reg_set[i] = 2;
			}
		}
		pos += opsize;
	}
	return true;
}

// TODO: move this logic into the main anal loop
R_API void r_core_recover_vars(RCore *core, RAnalFunction *fcn, bool argonly) {
	r_return_if_fail (core && core->anal && fcn);
	if (core->anal->opt.bb_max_size < 1) {
		return;
	}
	BlockRecurseCtx ctx = { 0, {{ 0 }}, argonly, fcn, core };
	r_pvector_init (&ctx.reg_set, free);
	int *reg_set = R_NEWS0 (int, REG_SET_SIZE);
	r_pvector_push (&ctx.reg_set, reg_set);
	int saved_stack = fcn->stack;
	RAnalBlock *first_bb = r_anal_get_block_at (fcn->anal, fcn->addr);
	r_anal_block_recurse_depth_first (first_bb, (RAnalBlockCb)anal_block_cb, (RAnalBlockCb)anal_block_on_exit, &ctx);
	r_pvector_fini (&ctx.reg_set);
	fcn->stack = saved_stack;
}

static bool anal_path_exists(RCore *core, ut64 from, ut64 to, RList *bbs, int depth, HtUP *state, HtUP *avoid) {
	r_return_val_if_fail (bbs, false);
	RAnalBlock *bb = r_anal_bb_from_offset (core->anal, from);
	RListIter *iter = NULL;
	RAnalRef *refi;

	if (depth < 0) {
		eprintf ("going too deep\n");
		return false;
	}

	if (!bb) {
		return false;
	}

	ht_up_update (state, from, bb);

	// try to find the target in the current function
	if (r_anal_block_contains (bb, to) ||
		((!ht_up_find (avoid, bb->jump, NULL) &&
			!ht_up_find (state, bb->jump, NULL) &&
			anal_path_exists (core, bb->jump, to, bbs, depth - 1, state, avoid))) ||
		((!ht_up_find (avoid, bb->fail, NULL) &&
			!ht_up_find (state, bb->fail, NULL) &&
			anal_path_exists (core, bb->fail, to, bbs, depth - 1, state, avoid)))) {
		r_list_prepend (bbs, bb);
		return true;
	}

	// find our current function
	RAnalFunction *cur_fcn = r_anal_get_fcn_in (core->anal, from, 0);

	// get call refs from current basic block and find a path from them
	if (cur_fcn) {
		RList *refs = r_anal_function_get_refs (cur_fcn);
		if (refs) {
			r_list_foreach (refs, iter, refi) {
				if (refi->type == R_ANAL_REF_TYPE_CALL) {
					if (r_anal_block_contains (bb, refi->at)) {
						if ((refi->at != refi->addr) && !ht_up_find (state, refi->addr, NULL) && anal_path_exists (core, refi->addr, to, bbs, depth - 1, state, avoid)) {
							r_list_prepend (bbs, bb);
							r_list_free (refs);
							return true;
						}
					}
				}
			}
		}
		r_list_free (refs);
	}

	return false;
}

static RList *anal_graph_to(RCore *core, ut64 addr, int depth, HtUP *avoid) {
	RAnalFunction *cur_fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	RList *list = r_list_new ();
	HtUP *state = ht_up_new0 ();

	if (!list || !state || !cur_fcn) {
		r_list_free (list);
		ht_up_free (state);
		return NULL;
	}

	// forward search
	if (anal_path_exists (core, core->offset, addr, list, depth - 1, state, avoid)) {
		ht_up_free (state);
		return list;
	}

	// backward search
	RList *xrefs = r_anal_xrefs_get (core->anal, cur_fcn->addr);
	if (xrefs) {
		RListIter *iter;
		RAnalRef *xref = NULL;
		r_list_foreach (xrefs, iter, xref) {
			if (xref->type == R_ANAL_REF_TYPE_CALL) {
				ut64 offset = core->offset;
				core->offset = xref->addr;
				r_list_free (list);
				list = anal_graph_to (core, addr, depth - 1, avoid);
				core->offset = offset;
				if (list && r_list_length (list)) {
					r_list_free (xrefs);
					ht_up_free (state);
					return list;
				}
			}
		}
	}

	r_list_free (xrefs);
	ht_up_free (state);
	r_list_free (list);
	return NULL;
}

R_API RList* r_core_anal_graph_to(RCore *core, ut64 addr, int n) {
	int depth = r_config_get_i (core->config, "anal.graph_depth");
	RList *path, *paths = r_list_new ();
	HtUP *avoid = ht_up_new0 ();
	while (n) {
		path = anal_graph_to (core, addr, depth, avoid);
		if (path) {
			r_list_append (paths, path);
			if (r_list_length (path) >= 2) {
				RAnalBlock *last = r_list_get_n (path, r_list_length (path) - 2);
				ht_up_update (avoid, last->addr, last);
				n--;
				continue;
			}
		}
		// no more path found
		break;
	}
	ht_up_free (avoid);
	return paths;
}

R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts) {
	ut64 from = r_config_get_i (core->config, "graph.from");
	ut64 to = r_config_get_i (core->config, "graph.to");
	const char *font = r_config_get (core->config, "graph.font");
	int is_html = r_cons_context ()->is_html;
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_json_format_disasm = opts & R_CORE_ANAL_JSON_FORMAT_DISASM;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	int is_star = opts & R_CORE_ANAL_STAR;
	RConfigHold *hc;
	RAnalFunction *fcni;
	RListIter *iter;
	int nodes = 0;
	PJ *pj = NULL;

	if (!addr) {
		addr = core->offset;
	}
	if (r_list_empty (core->anal->fcns)) {
		return false;
	}
	hc = r_config_hold_new (core->config);
	if (!hc) {
		return false;
	}

	r_config_hold (hc, "asm.lines", "asm.bytes", "asm.dwarf", NULL);
	//opts |= R_CORE_ANAL_GRAPHBODY;
	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.dwarf", 0);
	if (!is_json_format_disasm) {
		r_config_hold (hc, "asm.bytes", NULL);
		r_config_set_i (core->config, "asm.bytes", 0);
	}
	if (!is_html && !is_json && !is_keva && !is_star) {
		const char * gv_edge = r_config_get (core->config, "graph.gv.edge");
		const char * gv_node = r_config_get (core->config, "graph.gv.node");
		const char * gv_spline = r_config_get (core->config, "graph.gv.spline");
		if (!gv_edge || !*gv_edge) {
			gv_edge = "arrowhead=\"normal\"";
		}
		if (!gv_node || !*gv_node) {
			gv_node = "fillcolor=gray style=filled shape=box";
		}
		if (!gv_spline || !*gv_spline) {
			gv_spline = "splines=\"ortho\"";
		}
		r_cons_printf ("digraph code {\n"
			"\tgraph [bgcolor=azure fontsize=8 fontname=\"%s\" %s];\n"
			"\tnode [%s];\n"
			"\tedge [%s];\n", font, gv_spline, gv_node, gv_edge);
	}
	if (is_json) {
		pj = r_core_pj_new (core);
		if (!pj) {
			r_config_hold_restore (hc);
			r_config_hold_free (hc);
			return false;
		}
		pj_a (pj);
	}
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (fcni->type & (R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_FCN |
						  R_ANAL_FCN_TYPE_LOC) &&
			(addr == UT64_MAX || r_anal_get_fcn_in (core->anal, addr, 0) == fcni)) {
			if (addr == UT64_MAX && (from != UT64_MAX && to != UT64_MAX)) {
				if (fcni->addr < from || fcni->addr > to) {
					continue;
				}
			}
			nodes += core_anal_graph_nodes (core, fcni, opts, pj);
			if (addr != UT64_MAX) {
				break;
			}
		}
	}
	if (!nodes) {
		if (!is_html && !is_json && !is_keva) {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (is_star) {
					char *name = get_title(fcn ? fcn->addr: addr);
					r_cons_printf ("agn %s;", name);
			} else {
				r_cons_printf ("\t\"0x%08"PFMT64x"\";\n", fcn? fcn->addr: addr);
			}
		}
	}
	if (!is_keva && !is_html && !is_json && !is_star && !is_json_format_disasm) {
		r_cons_printf ("}\n");
	}
	if (is_json) {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	return true;
}

static int core_anal_followptr(RCore *core, int type, ut64 at, ut64 ptr, ut64 ref, int code, int depth) {
	// SLOW Operation try to reduce as much as possible
	if (!ptr) {
		return false;
	}
	if (ref == UT64_MAX || ptr == ref) {
		const RAnalRefType t = code? type? type: R_ANAL_REF_TYPE_CODE: R_ANAL_REF_TYPE_DATA;
		r_anal_xrefs_set (core->anal, at, ptr, t);
		return true;
	}
	if (depth < 0) {
		return false;
	}
	int wordsize = (int)(core->anal->bits / 8);
	ut64 dataptr;
	if (!r_io_read_i (core->io, ptr, &dataptr, wordsize, false)) {
		// eprintf ("core_anal_followptr: Cannot read word at destination\n");
		return false;
	}
	return core_anal_followptr (core, type, at, dataptr, ref, code, depth - 1);
}

static bool opiscall(RCore *core, RAnalOp *aop, ut64 addr, const ut8* buf, int len, int arch) {
	switch (arch) {
	case R2_ARCH_ARM64:
		aop->size = 4;
		//addr should be aligned by 4 in aarch64
		if (addr % 4) {
			char diff = addr % 4;
			addr = addr - diff;
			buf = buf - diff;
		}
		//if is not bl do not analyze
		if (buf[3] == 0x94) {
			if (r_anal_op (core->anal, aop, addr, buf, len, R_ANAL_OP_MASK_BASIC)) {
				return true;
			}
		}
		break;
	default:
		aop->size = 1;
		if (r_anal_op (core->anal, aop, addr, buf, len, R_ANAL_OP_MASK_BASIC)) {
			switch (aop->type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_CCALL:
				return true;
			}
		}
		break;
	}
	return false;
}

// TODO(maskray) RAddrInterval API
#define OPSZ 8
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref, int mode) {
	ut8 *buf = (ut8 *)malloc (core->blocksize);
	if (!buf) {
		return -1;
	}
	int ptrdepth = r_config_get_i (core->config, "anal.ptrdepth");
	int i, count = 0;
	RAnalOp op = R_EMPTY;
	ut64 at;
	char bckwrds, do_bckwrd_srch;
	int arch = -1;
	if (core->rasm->bits == 64) {
		// speedup search
		if (!strncmp (core->rasm->cur->name, "arm", 3)) {
			arch = R2_ARCH_ARM64;
		}
	}
	// TODO: get current section range here or gtfo
	// ???
	// XXX must read bytes correctly
	do_bckwrd_srch = bckwrds = core->search->bckwrds;
	if (!ref) {
		eprintf ("Null reference search is not supported\n");
		free (buf);
		return -1;
	}
	r_cons_break_push (NULL, NULL);
	if (core->blocksize > OPSZ) {
		if (bckwrds) {
			if (from + core->blocksize > to) {
				at = from;
				do_bckwrd_srch = false;
			} else {
				at = to - core->blocksize;
			}
		} else {
			at = from;
		}
		while ((!bckwrds && at < to) || bckwrds) {
			eprintf ("\r[0x%08"PFMT64x"-0x%08"PFMT64x"] ", at, to);
			if (r_cons_is_breaked ()) {
				break;
			}
			// TODO: this can be probably enhanced
			if (!r_io_read_at (core->io, at, buf, core->blocksize)) {
				eprintf ("Failed to read at 0x%08" PFMT64x "\n", at);
				break;
			}
			for (i = bckwrds ? (core->blocksize - OPSZ - 1) : 0;
				 (!bckwrds && i < core->blocksize - OPSZ) ||
				 (bckwrds && i > 0);
				 bckwrds ? i-- : i++) {
				// TODO: honor anal.align
				if (r_cons_is_breaked ()) {
					break;
				}
				switch (mode) {
				case 'c':
					(void)opiscall (core, &op, at + i, buf + i, core->blocksize - i, arch);
					if (op.size < 1) {
						op.size = 1;
					}
					break;
				case 'r':
				case 'w':
				case 'x':
					{
						r_anal_op (core->anal, &op, at + i, buf + i, core->blocksize - i, R_ANAL_OP_MASK_BASIC);
						int mask = mode=='r' ? 1 : mode == 'w' ? 2: mode == 'x' ? 4: 0;
						if (op.direction == mask) {
							i += op.size;
						}
						r_anal_op_fini (&op);
						continue;
					}
					break;
				default:
					if (!r_anal_op (core->anal, &op, at + i, buf + i, core->blocksize - i, R_ANAL_OP_MASK_BASIC)) {
						r_anal_op_fini (&op);
						continue;
					}
				}
				switch (op.type) {
				case R_ANAL_OP_TYPE_JMP:
				case R_ANAL_OP_TYPE_CJMP:
				case R_ANAL_OP_TYPE_CALL:
				case R_ANAL_OP_TYPE_CCALL:
					if (op.jump != UT64_MAX &&
						core_anal_followptr (core, 'C', at + i, op.jump, ref, true, 0)) {
						count ++;
					}
					break;
				case R_ANAL_OP_TYPE_UCJMP:
				case R_ANAL_OP_TYPE_UJMP:
				case R_ANAL_OP_TYPE_IJMP:
				case R_ANAL_OP_TYPE_RJMP:
				case R_ANAL_OP_TYPE_IRJMP:
				case R_ANAL_OP_TYPE_MJMP:
					if (op.ptr != UT64_MAX &&
						core_anal_followptr (core, 'c', at + i, op.ptr, ref, true ,1)) {
						count ++;
					}
					break;
				case R_ANAL_OP_TYPE_UCALL:
				case R_ANAL_OP_TYPE_ICALL:
				case R_ANAL_OP_TYPE_RCALL:
				case R_ANAL_OP_TYPE_IRCALL:
				case R_ANAL_OP_TYPE_UCCALL:
					if (op.ptr != UT64_MAX &&
						core_anal_followptr (core, 'C', at + i, op.ptr, ref, true ,1)) {
						count ++;
					}
					break;
				default:
					{
						if (!r_anal_op (core->anal, &op, at + i, buf + i, core->blocksize - i, R_ANAL_OP_MASK_BASIC)) {
							r_anal_op_fini (&op);
							continue;
						}
					}
					if (op.ptr != UT64_MAX &&
						core_anal_followptr (core, 'd', at + i, op.ptr, ref, false, ptrdepth)) {
						count ++;
					}
					break;
				}
				if (op.size < 1) {
					op.size = 1;
				}
				i += op.size - 1;
				r_anal_op_fini (&op);
			}
			if (bckwrds) {
				if (!do_bckwrd_srch) {
					break;
				}
				if (at > from + core->blocksize - OPSZ) {
					at -= core->blocksize;
				} else {
					do_bckwrd_srch = false;
					at = from;
				}
			} else {
				at += core->blocksize - OPSZ;
			}
		}
	} else {
		eprintf ("error: block size too small\n");
	}
	r_cons_break_pop ();
	free (buf);
	r_anal_op_fini (&op);
	return count;
}

static bool found_xref(RCore *core, ut64 at, ut64 xref_to, RAnalRefType type, PJ *pj, int rad, bool cfg_debug, bool cfg_anal_strings) {
	// Validate the reference. If virtual addressing is enabled, we
	// allow only references to virtual addresses in order to reduce
	// the number of false positives. In debugger mode, the reference
	// must point to a mapped memory region.
	if (type == R_ANAL_REF_TYPE_NULL) {
		return false;
	}
	if (cfg_debug) {
		if (!r_debug_map_get (core->dbg, xref_to)) {
			return false;
		}
	} else if (core->io->va) {
		if (!r_io_is_valid_offset (core->io, xref_to, 0)) {
			return false;
		}
	}
	if (!rad) {
		if (cfg_anal_strings && type == R_ANAL_REF_TYPE_DATA) {
			int len = 0;
			char *str_string = is_string_at (core, xref_to, &len);
			if (str_string) {
				r_name_filter (str_string, -1);
				char *str_flagname = r_str_newf ("str.%s", str_string);
				r_flag_space_push (core->flags, R_FLAGS_FS_STRINGS);
				(void)r_flag_set (core->flags, str_flagname, xref_to, 1);
				r_flag_space_pop (core->flags);
				free (str_flagname);
				if (len > 0) {
					r_meta_set (core->anal, R_META_TYPE_STRING, xref_to,
								len, (const char *) str_string);
				}
				free (str_string);
			}
		}
		// Add to SDB
		if (xref_to) {
			r_anal_xrefs_set (core->anal, at, xref_to, type);
		}
	} else if (rad == 'j') {
		char *key = sdb_fmt ("0x%"PFMT64x, xref_to);
		char *value = sdb_fmt ("0x%"PFMT64x, at);
		pj_ks (pj, key, value);
	} else {
		int len = 0;
		// Display in radare commands format
		char *cmd;
		switch (type) {
		case R_ANAL_REF_TYPE_CODE: cmd = "axc"; break;
		case R_ANAL_REF_TYPE_CALL: cmd = "axC"; break;
		case R_ANAL_REF_TYPE_DATA: cmd = "axd"; break;
		default: cmd = "ax"; break;
		}
		r_cons_printf ("%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n", cmd, xref_to, at);
		if (cfg_anal_strings && type == R_ANAL_REF_TYPE_DATA) {
			char *str_flagname = is_string_at (core, xref_to, &len);
			if (str_flagname) {
				ut64 str_addr = xref_to;
				r_name_filter (str_flagname, -1);
				r_cons_printf ("f str.%s=0x%"PFMT64x"\n", str_flagname, str_addr);
				r_cons_printf ("Cs %d @ 0x%"PFMT64x"\n", len, str_addr);
				free (str_flagname);
			}
		}
	}
	return true;
}

R_API int r_core_anal_search_xrefs(RCore *core, ut64 from, ut64 to, PJ *pj, int rad) {
	const bool cfg_debug = r_config_get_b (core->config, "cfg.debug");
	bool cfg_anal_strings = r_config_get_i (core->config, "anal.strings");
	ut64 at;
	int count = 0;
	int bsz = 8096;
	RAnalOp op = { 0 };

	if (from == to) {
		return -1;
	}
	if (from > to) {
		eprintf ("Invalid range (0x%"PFMT64x
		" >= 0x%"PFMT64x")\n", from, to);
		return -1;
	}

	if (core->blocksize <= OPSZ) {
		eprintf ("Error: block size too small\n");
		return -1;
	}
	ut8 *buf = malloc (bsz);
	if (!buf) {
		eprintf ("Error: cannot allocate a block\n");
		return -1;
	}
	ut8 *block = malloc (bsz);
	if (!block) {
		eprintf ("Error: cannot allocate a temp block\n");
		free (buf);
		return -1;
	}
	r_cons_break_push (NULL, NULL);
	at = from;
	st64 asm_sub_varmin = r_config_get_i (core->config, "asm.sub.varmin");
	int maxopsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
	int minopsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	if (maxopsz < 1) {
		maxopsz = 4;
	}
	if (minopsz < 1) {
		minopsz = 1;
	}
	if (bsz < maxopsz) {
		// wtf
		eprintf ("Error: Something is really wrong deep inside\n");
		free (block);
		return -1;
	}
	while (at < to && !r_cons_is_breaked ()) {
		int i = 0, ret = bsz;
		if (!r_io_is_valid_offset (core->io, at, R_PERM_X)) {
			break;
		}
		ut64 left = to - at;
		if (bsz > left) {
			bsz = left;
		}
		(void)r_io_read_at (core->io, at, buf, bsz);
		memset (block, -1, bsz);
		if (!memcmp (buf, block, bsz)) {
		//	eprintf ("Error: skipping uninitialized block \n");
			at += ret;
			continue;
		}
		memset (block, 0, bsz);
		if (!memcmp (buf, block, bsz)) {
		//	eprintf ("Error: skipping uninitialized block \n");
			at += ret;
			continue;
		}
		(void) r_anal_op (core->anal, &op, at, buf, bsz, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
		while ((i + maxopsz) < bsz && !r_cons_is_breaked ()) {
			r_anal_op_fini (&op);
			ret = r_anal_op (core->anal, &op, at + i, buf + i, bsz - i, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
			if (ret < 1) {
				i += minopsz;
				continue;
			}
			i += ret;
			if (i > bsz) {
				// at += minopsz;
				break;
			}
			// find references
			if ((st64)op.val > asm_sub_varmin && op.val != UT64_MAX && op.val != UT32_MAX) {
				if (found_xref (core, op.addr, op.val, R_ANAL_REF_TYPE_DATA, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
			}
			// find references
			if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
				if (found_xref (core, op.addr, op.ptr, R_ANAL_REF_TYPE_DATA, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
			}
			// find references
			if (op.addr > 512 && op.disp > 512 && op.disp && op.disp != UT64_MAX) {
				if (found_xref (core, op.addr, op.disp, R_ANAL_REF_TYPE_DATA, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
			}
			switch (op.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
				if (found_xref (core, op.addr, op.jump, R_ANAL_REF_TYPE_CODE, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
				break;
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_CCALL:
				if (found_xref (core, op.addr, op.jump, R_ANAL_REF_TYPE_CALL, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
				break;
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IRJMP:
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UCJMP:
				count++;
				if (found_xref (core, op.addr, op.ptr, R_ANAL_REF_TYPE_CODE, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_IRCALL:
			case R_ANAL_OP_TYPE_UCCALL:
				if (found_xref (core, op.addr, op.ptr, R_ANAL_REF_TYPE_CALL, pj, rad, cfg_debug, cfg_anal_strings)) {
					count++;
				}
				break;
			default:
				break;
			}
		}
		r_anal_op_fini (&op);
		if (i < 1) {
			break;
		}
		at += i + 1;
	}
	r_cons_break_pop ();
	free (buf);
	free (block);
	return count;
}

static bool isValidSymbol(RBinSymbol *symbol) {
	if (symbol && symbol->type) {
		const char *type = symbol->type;
		return (symbol->paddr != UT64_MAX) && (!strcmp (type, R_BIN_TYPE_FUNC_STR) || !strcmp (type, R_BIN_TYPE_HIOS_STR) || !strcmp (type, R_BIN_TYPE_LOOS_STR) || !strcmp (type, R_BIN_TYPE_METH_STR) || !strcmp (type , R_BIN_TYPE_STATIC_STR));
	}
	return false;
}

static bool isSkippable(RBinSymbol *s) {
	if (s && s->name && s->bind) {
		if (r_str_startswith (s->name, "radr://")) {
			return true;
		}
		if (!strcmp (s->name, "__mh_execute_header")) {
			return true;
		}
		if (!strcmp (s->bind, "NONE")) {
			if (s->is_imported && s->libname && strstr(s->libname, ".dll")) {
				return true;
			}
		}
	}
	return false;
}

R_API int r_core_anal_all(RCore *core) {
	RList *list;
	RListIter *iter;
	RFlagItem *item;
	RAnalFunction *fcni;
	RBinAddr *binmain;
	RBinAddr *entry;
	RBinSymbol *symbol;
	const bool anal_vars = r_config_get_i (core->config, "anal.vars");
	const bool anal_calls = r_config_get_i (core->config, "anal.calls");

	/* Analyze Functions */
	/* Entries */
	item = r_flag_get (core->flags, "entry0");
	if (item) {
		r_core_af (core, item->offset, "entry0", anal_calls);
	} else {
		r_core_af (core, core->offset, NULL, anal_calls);
	}

	r_core_task_yield (&core->tasks);

	r_cons_break_push (NULL, NULL);
	/* Symbols (Imports are already analyzed by rabin2 on init) */
	if ((list = r_bin_get_symbols (core->bin)) != NULL) {
		r_list_foreach (list, iter, symbol) {
			if (r_cons_is_breaked ()) {
				break;
			}
			// Stop analyzing PE imports further
			if (isSkippable (symbol)) {
				continue;
			}
			if (isValidSymbol (symbol)) {
				ut64 addr = r_bin_get_vaddr (core->bin, symbol->paddr, symbol->vaddr);
				// TODO: uncomment to: fcn.name = symbol.name, problematic for imports
				// r_core_af (core, addr, symbol->name, anal_calls);
				r_core_af (core, addr, NULL, anal_calls);
			}
		}
	}
	r_core_task_yield (&core->tasks);
	/* Main */
	if ((binmain = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN))) {
		if (binmain->paddr != UT64_MAX) {
			ut64 addr = r_bin_get_vaddr (core->bin, binmain->paddr, binmain->vaddr);
			r_core_af (core, addr, "main", anal_calls);
		}
	}
	r_core_task_yield (&core->tasks);
	if ((list = r_bin_get_entries (core->bin))) {
		r_list_foreach (list, iter, entry) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (entry->paddr == UT64_MAX) {
				continue;
			}
			ut64 addr = r_bin_get_vaddr (core->bin, entry->paddr, entry->vaddr);
			r_core_af (core, addr, NULL, anal_calls);
		}
	}
	r_core_task_yield (&core->tasks);
	if (anal_vars) {
		/* Set fcn type to R_ANAL_FCN_TYPE_SYM for symbols */
		r_list_foreach_prev (core->anal->fcns, iter, fcni) {
			if (r_cons_is_breaked ()) {
				break;
			}
			r_core_recover_vars (core, fcni, true);
			if (!strncmp (fcni->name, "dbg.", 4) || !strncmp (fcni->name, "sym.", 4) || !strncmp (fcni->name, "main", 4)) {
				fcni->type = R_ANAL_FCN_TYPE_SYM;
			}
		}
	}
	r_cons_break_pop ();
	return true;
}

R_API int r_core_anal_data(RCore *core, ut64 addr, int count, int depth, int wordsize) {
	RAnalData *d;
	ut64 dstaddr = 0LL;
	ut8 *buf = core->block;
	int len = core->blocksize;
	int word = wordsize ? wordsize: core->rasm->bits / 8;
	char *str;
	int i, j;

	count = R_MIN (count, len);
	buf = malloc (len + 1);
	if (!buf) {
		return false;
	}
	memset (buf, 0xff, len);
	r_io_read_at (core->io, addr, buf, len);
	buf[len - 1] = 0;

	RConsPrintablePalette *pal = r_config_get_i (core->config, "scr.color")? &r_cons_context ()->pal: NULL;
	for (i = j = 0; j < count; j++) {
		if (i >= len) {
			r_io_read_at (core->io, addr + i, buf, len);
			buf[len] = 0;
			addr += i;
			i = 0;
			continue;
		}
		/* r_anal_data requires null-terminated buffer according to coverity */
		/* but it should not.. so this must be fixed in anal/data.c instead of */
		/* null terminating here */
		d = r_anal_data (core->anal, addr + i, buf + i, len - i, wordsize);
		str = r_anal_data_to_string (d, pal);
		r_cons_println (str);

		if (d) {
			switch (d->type) {
			case R_ANAL_DATA_TYPE_POINTER:
				r_cons_printf ("`- ");
				dstaddr = r_mem_get_num (buf + i, word);
				if (depth > 0) {
					r_core_anal_data (core, dstaddr, 1, depth - 1, wordsize);
				}
				i += word;
				break;
			case R_ANAL_DATA_TYPE_STRING:
				buf[len-1] = 0;
				i += strlen ((const char*)buf + i) + 1;
				break;
			default:
				i += (d->len > 3)? d->len: word;
				break;
			}
		} else {
			i += word;
		}
		free (str);
		r_anal_data_free (d);
	}
	free (buf);
	return true;
}

struct block_flags_stat_t {
	ut64 step;
	ut64 from;
	RCoreAnalStats *as;
};

static bool block_flags_stat(RFlagItem *fi, void *user) {
	struct block_flags_stat_t *u = (struct block_flags_stat_t *)user;
	int piece = (fi->offset - u->from) / u->step;
	u->as->block[piece].flags++;
	return true;
}

/* core analysis stats */
/* stats --- colorful bar */
R_API RCoreAnalStats* r_core_anal_get_stats(RCore *core, ut64 from, ut64 to, ut64 step) {
	RAnalFunction *F;
	RAnalBlock  *B;
	RBinSymbol *S;
	RListIter *iter, *iter2;
	RCoreAnalStats *as = NULL;
	int piece, as_size, blocks;
	ut64 at;

	if (from == to || from == UT64_MAX || to == UT64_MAX) {
		eprintf ("Cannot alloc for this range\n");
		return NULL;
	}
	as = R_NEW0 (RCoreAnalStats);
	if (!as) {
		return NULL;
	}
	if (step < 1) {
		step = 1;
	}
	blocks = (to - from) / step;
	as_size = (1 + blocks) * sizeof (RCoreAnalStatsItem);
	as->block = malloc (as_size);
	if (!as->block) {
		free (as);
		return NULL;
	}
	memset (as->block, 0, as_size);
	for (at = from; at < to; at += step) {
		RIOMap *map = r_io_map_get_at (core->io, at);
		piece = (at - from) / step;
		as->block[piece].perm = map ? map->perm: (core->io->desc ? core->io->desc->perm: 0);
	}
	// iter all flags
	struct block_flags_stat_t u = { .step = step, .from = from, .as = as };
	r_flag_foreach_range (core->flags, from, to + 1, block_flags_stat, &u);
	// iter all functions
	r_list_foreach (core->anal->fcns, iter, F) {
		if (F->addr < from || F->addr > to) {
			continue;
		}
		piece = (F->addr - from) / step;
		as->block[piece].functions++;
		ut64 last_piece = R_MIN ((F->addr + r_anal_function_linear_size (F) - 1) / step, blocks - 1);
		for (; piece <= last_piece; piece++) {
			as->block[piece].in_functions++;
		}
		// iter all basic blocks
		r_list_foreach (F->bbs, iter2, B) {
			if (B->addr < from || B->addr > to) {
				continue;
			}
			piece = (B->addr - from) / step;
			as->block[piece].blocks++;
		}
	}
	// iter all symbols
	r_list_foreach (r_bin_get_symbols (core->bin), iter, S) {
		if (S->vaddr < from || S->vaddr > to) {
			continue;
		}
		piece = (S->vaddr - from) / step;
		as->block[piece].symbols++;
	}
	RPVector *metas = to > from ? r_meta_get_all_intersect (core->anal, from, to - from, R_META_TYPE_ANY) : NULL;
	if (metas) {
		void **it;
		r_pvector_foreach (metas, it) {
			RIntervalNode *node = *it;
			RAnalMetaItem *mi = node->data;
			if (node->start < from || node->end > to) {
				continue;
			}
			piece = (node->start - from) / step;
			switch (mi->type) {
			case R_META_TYPE_STRING:
				as->block[piece].strings++;
				break;
			case R_META_TYPE_COMMENT:
				as->block[piece].comments++;
				break;
			default:
				break;
			}
		}
		r_pvector_free (metas);
	}
	return as;
}

R_API void r_core_anal_stats_free(RCoreAnalStats *s) {
	if (s) {
		free (s->block);
	}
	free (s);
}

R_API RList* r_core_anal_cycles(RCore *core, int ccl) {
	ut64 addr = core->offset;
	int depth = 0;
	RAnalOp *op = NULL;
	RAnalCycleFrame *prev = NULL, *cf = NULL;
	RAnalCycleHook *ch;
	RList *hooks = r_list_new ();
	if (!hooks) {
		return NULL;
	}
	cf = r_anal_cycle_frame_new ();
	r_cons_break_push (NULL, NULL);
	while (cf && !r_cons_is_breaked ()) {
		if ((op = r_core_anal_op (core, addr, R_ANAL_OP_MASK_BASIC)) && (op->cycles) && (ccl > 0)) {
			r_cons_clear_line (1);
			eprintf ("%i -- ", ccl);
			addr += op->size;
			switch (op->type) {
			case R_ANAL_OP_TYPE_JMP:
				addr = op->jump;
				ccl -= op->cycles;
				loganal (op->addr, addr, depth);
				break;
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_IRCALL:
				ch = R_NEW0 (RAnalCycleHook);
				ch->addr = op->addr;
				eprintf ("0x%08"PFMT64x" > ?\r", op->addr);
				ch->cycles = ccl;
				r_list_append (hooks, ch);
				ch = NULL;
				while (!ch && cf) {
					ch = r_list_pop (cf->hooks);
					if (ch) {
						addr = ch->addr;
						ccl = ch->cycles;
						free (ch);
					} else {
						r_anal_cycle_frame_free (cf);
						cf = prev;
						if (cf) {
							prev = cf->prev;
						}
					}
				}
				break;
			case R_ANAL_OP_TYPE_CJMP:
				ch = R_NEW0 (RAnalCycleHook);
				ch->addr = addr;
				ch->cycles = ccl - op->failcycles;
				r_list_push (cf->hooks, ch);
				ch = NULL;
				addr = op->jump;
				loganal (op->addr, addr, depth);
				break;
			case R_ANAL_OP_TYPE_UCJMP:
			case R_ANAL_OP_TYPE_UCCALL:
				ch = R_NEW0 (RAnalCycleHook);
				ch->addr = op->addr;
				ch->cycles = ccl;
				r_list_append (hooks, ch);
				ch = NULL;
				ccl -= op->failcycles;
				eprintf ("0x%08"PFMT64x" > ?\r", op->addr);
				break;
			case R_ANAL_OP_TYPE_CCALL:
				ch = R_NEW0 (RAnalCycleHook);
				ch->addr = addr;
				ch->cycles = ccl - op->failcycles;
				r_list_push (cf->hooks, ch);
				ch = NULL;
			case R_ANAL_OP_TYPE_CALL:
				if (op->addr != op->jump) { //no selfies
					cf->naddr = addr;
					prev = cf;
					cf = r_anal_cycle_frame_new ();
					cf->prev = prev;
				}
				ccl -= op->cycles;
				addr = op->jump;
				loganal (op->addr, addr, depth - 1);
				break;
			case R_ANAL_OP_TYPE_RET:
				ch = R_NEW0 (RAnalCycleHook);
				if (prev) {
					ch->addr = prev->naddr;
					ccl -= op->cycles;
					ch->cycles = ccl;
					r_list_push (prev->hooks, ch);
					eprintf ("0x%08"PFMT64x" < 0x%08"PFMT64x"\r", prev->naddr, op->addr);
				} else {
					ch->addr = op->addr;
					ch->cycles = ccl;
					r_list_append (hooks, ch);
					eprintf ("? < 0x%08"PFMT64x"\r", op->addr);
				}
				ch = NULL;
				while (!ch && cf) {
					ch = r_list_pop (cf->hooks);
					if (ch) {
						addr = ch->addr;
						ccl = ch->cycles;
						free (ch);
					} else {
						r_anal_cycle_frame_free (cf);
						cf = prev;
						if (cf) {
							prev = cf->prev;
						}
					}
				}
				break;
			case R_ANAL_OP_TYPE_CRET:
				ch = R_NEW0 (RAnalCycleHook);
				if (prev) {
					ch->addr = prev->naddr;
					ch->cycles = ccl - op->cycles;
					r_list_push (prev->hooks, ch);
					eprintf ("0x%08"PFMT64x" < 0x%08"PFMT64x"\r", prev->naddr, op->addr);
				} else {
					ch->addr = op->addr;
					ch->cycles = ccl - op->cycles;
					r_list_append (hooks, ch);
					eprintf ("? < 0x%08"PFMT64x"\r", op->addr);
				}
				ccl -= op->failcycles;
				break;
			default:
				ccl -= op->cycles;
				eprintf ("0x%08"PFMT64x"\r", op->addr);
				break;
			}
		} else {
			ch = R_NEW0 (RAnalCycleHook);
			if (!ch) {
				r_anal_cycle_frame_free (cf);
				r_list_free (hooks);
				return NULL;
			}
			ch->addr = addr;
			ch->cycles = ccl;
			r_list_append (hooks, ch);
			ch = NULL;
			while (!ch && cf) {
				ch = r_list_pop (cf->hooks);
				if (ch) {
					addr = ch->addr;
					ccl = ch->cycles;
					free (ch);
				} else {
					r_anal_cycle_frame_free (cf);
					cf = prev;
					if (cf) {
						prev = cf->prev;
					}
				}
			}
		}
		r_anal_op_free (op);
	}
	if (r_cons_is_breaked ()) {
		while (cf) {
			ch = r_list_pop (cf->hooks);
			while (ch) {
				free (ch);
				ch = r_list_pop (cf->hooks);
			}
			prev = cf->prev;
			r_anal_cycle_frame_free (cf);
			cf = prev;
		}
	}
	r_cons_break_pop ();
	return hooks;
}

R_API void r_core_anal_undefine(RCore *core, ut64 off) {
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, off, -1);
	if (f) {
		if (!strncmp (f->name, "fcn.", 4)) {
			r_flag_unset_name (core->flags, f->name);
		}
		r_meta_del (core->anal, R_META_TYPE_ANY, r_anal_function_min_addr (f), r_anal_function_linear_size (f));
	}
	r_anal_fcn_del_locs (core->anal, off);
	r_anal_fcn_del (core->anal, off);
}

/* Join function at addr2 into function at addr */
// addr use to be core->offset
R_API void r_core_anal_fcn_merge(RCore *core, ut64 addr, ut64 addr2) {
	RListIter *iter;
	ut64 min = 0;
	ut64 max = 0;
	int first = 1;
	RAnalBlock *bb;
	RAnalFunction *f1 = r_anal_get_function_at (core->anal, addr);
	RAnalFunction *f2 = r_anal_get_function_at (core->anal, addr2);
	if (!f1 || !f2) {
		eprintf ("Cannot find function\n");
		return;
	}
	if (f1 == f2) {
		eprintf ("Cannot merge the same function\n");
		return;
	}
	// join all basic blocks from f1 into f2 if they are not
	// delete f2
	eprintf ("Merge 0x%08"PFMT64x" into 0x%08"PFMT64x"\n", addr, addr2);
	r_list_foreach (f1->bbs, iter, bb) {
		if (first) {
			min = bb->addr;
			max = bb->addr + bb->size;
			first = 0;
		} else {
			if (bb->addr < min) {
				min = bb->addr;
			}
			if (bb->addr + bb->size > max) {
				max = bb->addr + bb->size;
			}
		}
	}
	r_list_foreach (f2->bbs, iter, bb) {
		if (first) {
			min = bb->addr;
			max = bb->addr + bb->size;
			first = 0;
		} else {
			if (bb->addr < min) {
				min = bb->addr;
			}
			if (bb->addr + bb->size > max) {
				max = bb->addr + bb->size;
			}
		}
		r_anal_function_add_block (f1, bb);
	}
	// TODO: import data/code/refs
	r_anal_function_delete (f2);
	// update size
	r_anal_function_relocate (f2, R_MIN (addr, addr2));
}

static bool esil_anal_stop = false;
static void cccb(void *u) {
	esil_anal_stop = true;
	eprintf ("^C\n");
}

static void add_string_ref(RCore *core, ut64 xref_from, ut64 xref_to) {
	int len = 0;
	if (xref_to == UT64_MAX || !xref_to) {
		return;
	}
	if (!xref_from || xref_from == UT64_MAX) {
		xref_from = core->anal->esil->address;
	}
	char *str_flagname = is_string_at (core, xref_to, &len);
	if (str_flagname) {
		r_anal_xrefs_set (core->anal, xref_from, xref_to, R_ANAL_REF_TYPE_DATA);
		r_name_filter (str_flagname, -1);
		char *flagname = sdb_fmt ("str.%s", str_flagname);
		r_flag_space_push (core->flags, R_FLAGS_FS_STRINGS);
		r_flag_set (core->flags, flagname, xref_to, len);
		r_flag_space_pop (core->flags);
		r_meta_set (core->anal, 's', xref_to, len, str_flagname);
		free (str_flagname);
	}
}


// dup with isValidAddress wtf
static bool myvalid(RIO *io, ut64 addr) {
	if (addr < 0x100) {
		return false;
	}
	if (addr == UT32_MAX || addr == UT64_MAX) {	//the best of the best of the best :(
		return false;
	}
	if (!r_io_is_valid_offset (io, addr, 0)) {
		return false;
	}
	return true;
}

typedef struct {
	RAnalOp *op;
	RAnalFunction *fcn;
	const char *spname;
	ut64 initial_sp;
} EsilBreakCtx;

static const char *reg_name_for_access(RAnalOp* op, RAnalVarAccessType type) {
	if (type == R_ANAL_VAR_ACCESS_TYPE_WRITE) {
		if (op->dst && op->dst->reg) {
			return op->dst->reg->name;
		}
	} else {
		if (op->src[0] && op->src[0]->reg) {
			return op->src[0]->reg->name;
		}
	}
	return NULL;
}

static ut64 delta_for_access(RAnalOp *op, RAnalVarAccessType type) {
	if (type == R_ANAL_VAR_ACCESS_TYPE_WRITE) {
		if (op->dst) {
			return op->dst->imm + op->dst->delta;
		}
	} else {
		if (op->src[1] && (op->src[1]->imm || op->src[1]->delta)) {
			return op->src[1]->imm + op->src[1]->delta;
		}
		if (op->src[0]) {
			return op->src[0]->imm + op->src[0]->delta;
		}
	}
	return 0;
}

static void handle_var_stack_access(RAnalEsil *esil, ut64 addr, RAnalVarAccessType type, int len) {
	EsilBreakCtx *ctx = esil->user;
	const char *regname = reg_name_for_access (ctx->op, type);
	if (ctx->fcn && regname) {
		ut64 spaddr = r_reg_getv (esil->anal->reg, ctx->spname);
		if (addr >= spaddr && addr < ctx->initial_sp) {
			int stack_off = addr - ctx->initial_sp;
			RAnalVar *var = r_anal_function_get_var (ctx->fcn, R_ANAL_VAR_KIND_SPV, stack_off);
			if (!var) {
				var = r_anal_function_get_var (ctx->fcn, R_ANAL_VAR_KIND_BPV, stack_off);
			}
			if (!var && stack_off >= -ctx->fcn->maxstack) {
				char *varname;
				varname = ctx->fcn->anal->opt.varname_stack
					? r_str_newf ("var_%xh", R_ABS (stack_off))
					: r_anal_function_autoname_var (ctx->fcn, R_ANAL_VAR_KIND_SPV, "var", delta_for_access (ctx->op, type));
				var = r_anal_function_set_var (ctx->fcn, stack_off, R_ANAL_VAR_KIND_SPV, NULL, len, false, varname);
				free (varname);
			}
			if (var) {
				r_anal_var_set_access (var, regname, ctx->op->addr, type, delta_for_access (ctx->op, type));
			}
		}
	}
}

static bool esilbreak_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	handle_var_stack_access (esil, addr, R_ANAL_VAR_ACCESS_TYPE_WRITE, len);
	return true;
}

/* TODO: move into RCore? */
static ut64 esilbreak_last_read = UT64_MAX;
static ut64 esilbreak_last_data = UT64_MAX;

static ut64 ntarget = UT64_MAX;

// TODO differentiate endian-aware mem_read with other reads; move ntarget handling to another function
static bool esilbreak_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	ut8 str[128];
	if (addr != UT64_MAX) {
		esilbreak_last_read = addr;
	}
	handle_var_stack_access (esil, addr, R_ANAL_VAR_ACCESS_TYPE_READ, len);
	if (myvalid (mycore->io, addr) && r_io_read_at (mycore->io, addr, (ut8*)buf, len)) {
		ut64 refptr;
		bool trace = true;
		switch (len) {
		case 2:
			esilbreak_last_data = refptr = (ut64)r_read_ble16 (buf, esil->anal->big_endian);
			break;
		case 4:
			esilbreak_last_data = refptr = (ut64)r_read_ble32 (buf, esil->anal->big_endian);
			break;
		case 8:
			esilbreak_last_data = refptr = r_read_ble64 (buf, esil->anal->big_endian);
			break;
		default:
			trace = false;
			r_io_read_at (mycore->io, addr, (ut8*)buf, len);
			break;
		}
		// TODO incorrect
		bool validRef = false;
		if (trace && myvalid (mycore->io, refptr)) {
			if (ntarget == UT64_MAX || ntarget == refptr) {
				str[0] = 0;
				if (r_io_read_at (mycore->io, refptr, str, sizeof (str)) < 1) {
					//eprintf ("Invalid read\n");
					str[0] = 0;
					validRef = false;
				} else {
					r_anal_xrefs_set (mycore->anal, esil->address, refptr, R_ANAL_REF_TYPE_DATA);
					str[sizeof (str) - 1] = 0;
					add_string_ref (mycore, esil->address, refptr);
					esilbreak_last_data = UT64_MAX;
					validRef = true;
				}
			}
		}

		/** resolve ptr */
		if (ntarget == UT64_MAX || ntarget == addr || (ntarget == UT64_MAX && !validRef)) {
			r_anal_xrefs_set (mycore->anal, esil->address, addr, R_ANAL_REF_TYPE_DATA);
		}
	}
	return false; // fallback
}

static bool esilbreak_reg_write(RAnalEsil *esil, const char *name, ut64 *val) {
	if (!esil) {
		return false;
	}
	RAnal *anal = esil->anal;
	EsilBreakCtx *ctx = esil->user;
	RAnalOp *op = ctx->op;
	RCore *core = anal->coreb.core;
	handle_var_stack_access (esil, *val, R_ANAL_VAR_ACCESS_TYPE_PTR, esil->anal->bits / 8);
	//specific case to handle blx/bx cases in arm through emulation
	// XXX this thing creates a lot of false positives
	ut64 at = *val;
	if (anal && anal->opt.armthumb) {
		if (anal->cur && anal->cur->arch && anal->bits < 33 &&
			strstr (anal->cur->arch, "arm") && !strcmp (name, "pc") && op) {
			switch (op->type) {
			case R_ANAL_OP_TYPE_UCALL: // BLX
			case R_ANAL_OP_TYPE_UJMP: // BX
				// maybe UJMP/UCALL is enough here
				if (!(*val & 1)) {
					r_anal_hint_set_bits (anal, *val, 32);
				} else {
					ut64 snv = r_reg_getv (anal->reg, "pc");
					if (snv != UT32_MAX && snv != UT64_MAX) {
						if (r_io_is_valid_offset (anal->iob.io, *val, 1)) {
							r_anal_hint_set_bits (anal, *val - 1, 16);
						}
					}
				}
				break;
			default:
				break;
			}
		}
	}
	if (core->rasm->bits == 32 && strstr (core->rasm->cur->name, "arm")) {
		if ((!(at & 1)) && r_io_is_valid_offset (anal->iob.io, at, 0)) { //  !core->anal->opt.noncode)) {
			add_string_ref (anal->coreb.core, esil->address, at);
		}
	}
	return 0;
}

static void getpcfromstack(RCore *core, RAnalEsil *esil) {
	ut64 cur;
	ut64 addr;
	ut64 size;
	int idx;
	RAnalEsil esil_cpy;
	RAnalOp op = R_EMPTY;
	RAnalFunction *fcn = NULL;
	ut8 *buf = NULL;
	char *tmp_esil_str = NULL;
	int tmp_esil_str_len;
	const char *esilstr;
	const int maxaddrlen = 20;
	const char *spname = NULL;
	if (!esil) {
		return;
	}

	memcpy (&esil_cpy, esil, sizeof (esil_cpy));
	addr = cur = esil_cpy.cur;
	fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn) {
		return;
	}

	size = r_anal_function_linear_size (fcn);
	if (size <= 0) {
		return;
	}

	buf = malloc (size + 2);
	if (!buf) {
		perror ("malloc");
		return;
	}

	r_io_read_at (core->io, addr, buf, size + 1);

	// TODO Hardcoding for 2 instructions (mov e_p,[esp];ret). More work needed
	idx = 0;
	if (r_anal_op (core->anal, &op, cur, buf + idx, size - idx, R_ANAL_OP_MASK_ESIL) <= 0 ||
			op.size <= 0 ||
			(op.type != R_ANAL_OP_TYPE_MOV && op.type != R_ANAL_OP_TYPE_CMOV)) {
		goto err_anal_op;
	}

	r_asm_set_pc (core->rasm, cur);
	esilstr = R_STRBUF_SAFEGET (&op.esil);
	if (!esilstr) {
		goto err_anal_op;
	}
	// Ugly code
	// This is a hack, since ESIL doesn't always preserve values pushed on the stack. That probably needs to be rectified
	spname = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	if (!spname || !*spname) {
		goto err_anal_op;
	}
	tmp_esil_str_len = strlen (esilstr) + strlen (spname) + maxaddrlen;
	tmp_esil_str = (char*) malloc (tmp_esil_str_len);
	if (!tmp_esil_str) {
		goto err_anal_op;
	}
	tmp_esil_str[tmp_esil_str_len - 1] = '\0';
	snprintf (tmp_esil_str, tmp_esil_str_len - 1, "%s,[", spname);
	if (!*esilstr || (strncmp ( esilstr, tmp_esil_str, strlen (tmp_esil_str)))) {
		free (tmp_esil_str);
		goto err_anal_op;
	}

	snprintf (tmp_esil_str, tmp_esil_str_len - 1, "%20" PFMT64u "%s", esil_cpy.old, &esilstr[strlen (spname) + 4]);
	r_str_trim (tmp_esil_str);
	idx += op.size;
	r_anal_esil_set_pc (&esil_cpy, cur);
	r_anal_esil_parse (&esil_cpy, tmp_esil_str);
	r_anal_esil_stack_free (&esil_cpy);
	free (tmp_esil_str);

	cur = addr + idx;
	r_anal_op_fini (&op);
	if (r_anal_op (core->anal, &op, cur, buf + idx, size - idx, R_ANAL_OP_MASK_ESIL) <= 0 ||
			op.size <= 0 ||
			(op.type != R_ANAL_OP_TYPE_RET && op.type != R_ANAL_OP_TYPE_CRET)) {
		goto err_anal_op;
	}
	r_asm_set_pc (core->rasm, cur);

	esilstr = R_STRBUF_SAFEGET (&op.esil);
	r_anal_esil_set_pc (&esil_cpy, cur);
	if (!esilstr || !*esilstr) {
		goto err_anal_op;
	}
	r_anal_esil_parse (&esil_cpy, esilstr);
	r_anal_esil_stack_free (&esil_cpy);

	memcpy (esil, &esil_cpy, sizeof (esil_cpy));

 err_anal_op:
	r_anal_op_fini (&op);
	free (buf);
}

typedef struct {
	ut64 start_addr;
	ut64 end_addr;
	RAnalFunction *fcn;
	RAnalBlock *cur_bb;
	RList *bbl, *path, *switch_path;
} IterCtx;

static int find_bb(ut64 *addr, RAnalBlock *bb) {
	return *addr != bb->addr;
}

static inline bool get_next_i(IterCtx *ctx, size_t *next_i) {
	(*next_i)++;
	ut64 cur_addr = *next_i + ctx->start_addr;
	if (ctx->fcn) {
		if (!ctx->cur_bb) {
			ctx->path = r_list_new ();
			ctx->switch_path = r_list_new ();
			ctx->bbl = r_list_clone (ctx->fcn->bbs);
			ctx->cur_bb = r_anal_get_block_at (ctx->fcn->anal, ctx->fcn->addr);
			if (!ctx->cur_bb) {
				return false;
			}
			r_list_push (ctx->path, ctx->cur_bb);
		}
		RAnalBlock *bb = ctx->cur_bb;
		if (cur_addr >= bb->addr + bb->size) {
			r_reg_arena_push (ctx->fcn->anal->reg);
			RListIter *bbit = NULL;
			if (bb->switch_op) {
				RAnalCaseOp *cop = r_list_first (bb->switch_op->cases);
				bbit = r_list_find (ctx->bbl, &cop->jump, (RListComparator)find_bb);
				if (bbit) {
					r_list_push (ctx->switch_path, bb->switch_op->cases->head);
				}
			} else {
				bbit = r_list_find (ctx->bbl, &bb->jump, (RListComparator)find_bb);
				if (!bbit && bb->fail != UT64_MAX) {
					bbit = r_list_find (ctx->bbl, &bb->fail, (RListComparator)find_bb);
				}
			}
			if (!bbit) {
				RListIter *cop_it = r_list_last (ctx->switch_path);
				RAnalBlock *prev_bb = NULL;
				do {
					r_reg_arena_pop (ctx->fcn->anal->reg);
					prev_bb = r_list_pop (ctx->path);
					if (prev_bb->fail != UT64_MAX) {
						bbit = r_list_find (ctx->bbl, &prev_bb->fail, (RListComparator)find_bb);
						if (bbit) {
							r_reg_arena_push (ctx->fcn->anal->reg);
							r_list_push (ctx->path, prev_bb);
						}
					}
					if (!bbit && cop_it) {
						RAnalCaseOp *cop = cop_it->data;
						if (cop->jump == prev_bb->addr && cop_it->n) {
							cop = cop_it->n->data;
							r_list_pop (ctx->switch_path);
							r_list_push (ctx->switch_path, cop_it->n);
							cop_it = cop_it->n;
							bbit = r_list_find (ctx->bbl, &cop->jump, (RListComparator)find_bb);
						}
					}
					if (cop_it && !cop_it->n) {
						r_list_pop (ctx->switch_path);
						cop_it = r_list_last (ctx->switch_path);
					}
				} while (!bbit && !r_list_empty (ctx->path));
			}
			if (!bbit) {
				r_list_free (ctx->path);
				r_list_free (ctx->switch_path);
				r_list_free (ctx->bbl);
				return false;
			}
			if (!bbit->data) {
				return false;
			}
			if (!bbit->data) {
				return false;
			}
			ctx->cur_bb = bbit->data;
			r_list_push (ctx->path, ctx->cur_bb);
			r_list_delete (ctx->bbl, bbit);
			*next_i = ctx->cur_bb->addr - ctx->start_addr;
		}
	} else if (cur_addr >= ctx->end_addr) {
		return false;
	}
	if (*next_i == 0) {
		return false;
	}
	return true;
}

R_API void r_core_anal_esil(RCore *core, const char *str, const char *target) {
	bool cfg_anal_strings = r_config_get_i (core->config, "anal.strings");
	bool emu_lazy = r_config_get_i (core->config, "emu.lazy");
	bool gp_fixed = r_config_get_i (core->config, "anal.gpfixed");
	RAnalEsil *ESIL = core->anal->esil;
	ut64 refptr = 0LL;
	const char *pcname;
	RAnalOp op = R_EMPTY;
	ut8 *buf = NULL;
	bool end_address_set = false;
	int iend;
	int minopsize = 4; // XXX this depends on asm->mininstrsize
	bool archIsArm = false;
	ut64 addr = core->offset;
	ut64 start = addr;
	ut64 end = 0LL;
	ut64 cur;
	if (esil_anal_stop || r_cons_is_breaked ()) {
		// faster ^C
		return;
	}

	mycore = core;
	if (!strcmp (str, "?")) {
		eprintf ("Usage: aae[f] [len] [addr] - analyze refs in function, section or len bytes with esil\n");
		eprintf ("  aae $SS @ $S             - analyze the whole section\n");
		eprintf ("  aae $SS str.Hello @ $S   - find references for str.Hellow\n");
		eprintf ("  aaef                     - analyze functions discovered with esil\n");
		return;
	}
#define CHECKREF(x) ((refptr && (x) == refptr) || !refptr)
	if (target) {
		const char *expr = r_str_trim_head_ro (target);
		if (*expr) {
			refptr = ntarget = r_num_math (core->num, expr);
			if (!refptr) {
				ntarget = refptr = addr;
			}
		} else {
			ntarget = UT64_MAX;
			refptr = 0LL;
		}
	} else {
		ntarget = UT64_MAX;
		refptr = 0LL;
	}
	RAnalFunction *fcn = NULL;
	if (!strcmp (str, "f")) {
		fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (fcn) {
			start = r_anal_function_min_addr (fcn);
			addr = fcn->addr;
			end = r_anal_function_max_addr (fcn);
			end_address_set = true;
		}
	}

	if (!end_address_set) {
		if (str[0] == ' ') {
			end = addr + r_num_math (core->num, str + 1);
		} else {
			RIOMap *map = r_io_map_get_at (core->io, addr);
			if (map) {
				end = r_io_map_end (map);
			} else {
				end = addr + core->blocksize;
			}
		}
	}

	iend = end - start;
	if (iend < 0) {
		return;
	}
	if (iend > MAX_SCAN_SIZE) {
		eprintf ("Warning: Not going to analyze 0x%08"PFMT64x" bytes.\n", (ut64)iend);
		return;
	}
	buf = malloc ((size_t)iend + 2);
	if (!buf) {
		perror ("malloc");
		return;
	}
	esilbreak_last_read = UT64_MAX;
	r_io_read_at (core->io, start, buf, iend + 1);
	if (!ESIL) {
		r_core_cmd0 (core, "aei");
		ESIL = core->anal->esil;
		if (!ESIL) {
			eprintf ("ESIL not initialized\n");
			return;
		}
		r_core_cmd0 (core, "aeim");
		ESIL = core->anal->esil;
	}
	const char *spname = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	if (!spname) {
		eprintf ("Error: No =SP defined in the reg profile.\n");
		return;
	}
	EsilBreakCtx ctx = {
		&op,
		fcn,
		spname,
		r_reg_getv (core->anal->reg, spname)
	};
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;
	//this is necessary for the hook to read the id of analop
	ESIL->user = &ctx;
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;

	if (fcn && fcn->reg_save_area) {
		r_reg_setv (core->anal->reg, ctx.spname, ctx.initial_sp - fcn->reg_save_area);
	}
	//eprintf ("Analyzing ESIL refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	// TODO: backup/restore register state before/after analysis
	pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	if (!pcname || !*pcname) {
		eprintf ("Cannot find program counter register in the current profile.\n");
		return;
	}
	esil_anal_stop = false;
	r_cons_break_push (cccb, core);

	int arch = -1;
	if (!strcmp (core->anal->cur->arch, "arm")) {
		switch (core->anal->cur->bits) {
		case 64: arch = R2_ARCH_ARM64; break;
		case 32: arch = R2_ARCH_ARM32; break;
		case 16: arch = R2_ARCH_THUMB; break;
		}
		archIsArm = true;
	}

	ut64 gp = r_config_get_i (core->config, "anal.gp");
	const char *gp_reg = NULL;
	if (!strcmp (core->anal->cur->arch, "mips")) {
		gp_reg = "gp";
		arch = R2_ARCH_MIPS;
	}

	const char *sn = r_reg_get_name (core->anal->reg, R_REG_NAME_SN);
	if (!sn) {
		eprintf ("Warning: No SN reg alias for current architecture.\n");
	}
	r_reg_arena_push (core->anal->reg);

	IterCtx ictx = { start, end, fcn, NULL};
	size_t i = addr - start;
	size_t i_old = 0;
	do {
		if (esil_anal_stop || r_cons_is_breaked ()) {
			break;
		}
		cur = start + i;
		if (!r_io_is_valid_offset (core->io, cur, 0)) {
			break;
		}
#if 0
		// disabled because it causes some tests to fail
		{
			RPVector *list = r_meta_get_all_in (core->anal, cur, R_META_TYPE_ANY);
			void **it;
			r_pvector_foreach (list, it) {
				RIntervalNode *node = *it;
				RAnalMetaItem *meta = node->data;
				switch (meta->type) {
				case R_META_TYPE_DATA:
				case R_META_TYPE_STRING:
				case R_META_TYPE_FORMAT:
#if 0
					{
						int msz = r_meta_get_size (core->anal, meta->type);
						i += (msz > 0)? msz: minopsize;
					}
					r_pvector_free (list);
					goto loopback;
#elif 0
					{
						int msz = r_meta_get_size (core->anal, meta->type);
						i += (msz > 0)? msz: minopsize;
						i--;
					}
#else
					i += 4;
					goto repeat;
#endif
				default:
					break;
				}
			}
			r_pvector_free (list);
		}
#endif

		/* realign address if needed */
		r_core_seek_arch_bits (core, cur);
		int opalign = core->anal->pcalign;
		if (opalign > 0) {
			cur -= (cur % opalign);
		}

		r_anal_op_fini (&op);
		r_asm_set_pc (core->rasm, cur);
		i_old = i;
#if 1
		if (i > iend) {
			goto repeat;
		}
#endif
		if (!r_anal_op (core->anal, &op, cur, buf + i, iend - i, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_HINT)) {
			i += minopsize - 1; //   XXX dupe in op.size below
		}
		if (op.type == R_ANAL_OP_TYPE_ILL || op.type == R_ANAL_OP_TYPE_UNK) {
			// i += 2
			r_anal_op_fini (&op);
			goto repeat;
		}
		//we need to check again i because buf+i may goes beyond its boundaries
		//because of i+= minopsize - 1
		if (op.size < 1) {
			i += minopsize - 1;
			goto repeat;
		}
		if (emu_lazy) {
			if (op.type & R_ANAL_OP_TYPE_REP) {
				i += op.size - 1;
				goto repeat;
			}
			switch (op.type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_RET:
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_NOP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_IO:
			case R_ANAL_OP_TYPE_LEAVE:
			case R_ANAL_OP_TYPE_CRYPTO:
			case R_ANAL_OP_TYPE_CPL:
			case R_ANAL_OP_TYPE_SYNC:
			case R_ANAL_OP_TYPE_SWI:
			case R_ANAL_OP_TYPE_CMP:
			case R_ANAL_OP_TYPE_ACMP:
			case R_ANAL_OP_TYPE_NULL:
			case R_ANAL_OP_TYPE_CSWI:
			case R_ANAL_OP_TYPE_TRAP:
				i += op.size - 1;
				goto repeat;
			//  those require write support
			case R_ANAL_OP_TYPE_PUSH:
			case R_ANAL_OP_TYPE_POP:
				i += op.size - 1;
				goto repeat;
			}
		}
		if (sn && op.type == R_ANAL_OP_TYPE_SWI) {
			r_flag_space_set (core->flags, R_FLAGS_FS_SYSCALLS);
			int snv = (arch == R2_ARCH_THUMB)? op.val: (int)r_reg_getv (core->anal->reg, sn);
			RSyscallItem *si = r_syscall_get (core->anal->syscall, snv, -1);
			if (si) {
			//	eprintf ("0x%08"PFMT64x" SYSCALL %-4d %s\n", cur, snv, si->name);
				r_flag_set_next (core->flags, sdb_fmt ("syscall.%s", si->name), cur, 1);
			} else {
				//todo were doing less filtering up top because we can't match against 80 on all platforms
				// might get too many of this path now..
			//	eprintf ("0x%08"PFMT64x" SYSCALL %d\n", cur, snv);
				r_flag_set_next (core->flags, sdb_fmt ("syscall.%d", snv), cur, 1);
			}
			r_flag_space_set (core->flags, NULL);
		}
		const char *esilstr = R_STRBUF_SAFEGET (&op.esil);
		i += op.size - 1;
		if (R_STR_ISEMPTY (esilstr)) {
			goto repeat;
		}
		r_anal_esil_set_pc (ESIL, cur);
		r_reg_setv (core->anal->reg, pcname, cur + op.size);
		if (gp_fixed && gp_reg) {
			r_reg_setv (core->anal->reg, gp_reg, gp);
		}
		(void)r_anal_esil_parse (ESIL, esilstr);
		// looks like ^C is handled by esil_parse !!!!
		//r_anal_esil_dumpstack (ESIL);
		//r_anal_esil_stack_free (ESIL);
		switch (op.type) {
		case R_ANAL_OP_TYPE_LEA:
			// arm64
			if (core->anal->cur && arch == R2_ARCH_ARM64) {
				if (CHECKREF (ESIL->cur)) {
					r_anal_xrefs_set (core->anal, cur, ESIL->cur, R_ANAL_REF_TYPE_STRING);
				}
			} else if ((target && op.ptr == ntarget) || !target) {
				if (CHECKREF (ESIL->cur)) {
					if (op.ptr && r_io_is_valid_offset (core->io, op.ptr, !core->anal->opt.noncode)) {
						r_anal_xrefs_set (core->anal, cur, op.ptr, R_ANAL_REF_TYPE_STRING);
					} else {
						r_anal_xrefs_set (core->anal, cur, ESIL->cur, R_ANAL_REF_TYPE_STRING);
					}
				}
			}
			if (cfg_anal_strings) {
				add_string_ref (core, op.addr, op.ptr);
			}
			break;
		case R_ANAL_OP_TYPE_ADD:
			/* TODO: test if this is valid for other archs too */
			if (core->anal->cur && archIsArm) {
				/* This code is known to work on Thumb, ARM and ARM64 */
				ut64 dst = ESIL->cur;
				if ((target && dst == ntarget) || !target) {
					if (CHECKREF (dst)) {
						int type = core_type_by_addr (core, dst); // R_ANAL_REF_TYPE_DATA;
						r_anal_xrefs_set (core->anal, cur, dst, type);
					}
				}
				if (cfg_anal_strings) {
					add_string_ref (core, op.addr, dst);
				}
			} else if ((core->anal->bits == 32 && core->anal->cur && arch == R2_ARCH_MIPS)) {
				ut64 dst = ESIL->cur;
				if (!op.src[0] || !op.src[0]->reg || !op.src[0]->reg->name) {
					break;
				}
				if (!strcmp (op.src[0]->reg->name, "sp")) {
					break;
				}
				if (!strcmp (op.src[0]->reg->name, "zero")) {
					break;
				}
				if ((target && dst == ntarget) || !target) {
					if (dst > 0xffff && op.src[1] && (dst & 0xffff) == (op.src[1]->imm & 0xffff) && myvalid (mycore->io, dst)) {
						RFlagItem *f;
						char *str;
						if (CHECKREF (dst) || CHECKREF (cur)) {
							r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_DATA);
							if (cfg_anal_strings) {
								add_string_ref (core, op.addr, dst);
							}
							if ((f = r_core_flag_get_by_spaces (core->flags, dst))) {
								r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, f->name);
							} else if ((str = is_string_at (mycore, dst, NULL))) {
								char *str2 = sdb_fmt ("esilref: '%s'", str);
								// HACK avoid format string inside string used later as format
								// string crashes disasm inside agf under some conditions.
								// https://github.com/radareorg/radare2/issues/6937
								r_str_replace_char (str2, '%', '&');
								r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, str2);
								free (str);
							}
						}
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_LOAD:
			{
				ut64 dst = esilbreak_last_read;
				if (dst != UT64_MAX && CHECKREF (dst)) {
					if (myvalid (mycore->io, dst)) {
						r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_DATA);
						if (cfg_anal_strings) {
							add_string_ref (core, op.addr, dst);
						}
					}
				}
				dst = esilbreak_last_data;
				if (dst != UT64_MAX && CHECKREF (dst)) {
					if (myvalid (mycore->io, dst)) {
						r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_DATA);
						if (cfg_anal_strings) {
							add_string_ref (core, op.addr, dst);
						}
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_JMP:
			{
				ut64 dst = op.jump;
				if (CHECKREF (dst)) {
					if (myvalid (core->io, dst)) {
						r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_CODE);
					}
				}
			}
			break;
		case R_ANAL_OP_TYPE_CALL:
			{
				ut64 dst = op.jump;
				if (CHECKREF (dst)) {
					if (myvalid (core->io, dst)) {
						r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_CALL);
					}
					ESIL->old = cur + op.size;
					getpcfromstack (core, ESIL);
				}
			}
			break;
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_IRCALL:
		case R_ANAL_OP_TYPE_MJMP:
			{
				ut64 dst = core->anal->esil->jump_target;
				if (dst == 0 || dst == UT64_MAX) {
					dst = r_reg_getv (core->anal->reg, pcname);
				}
				if (CHECKREF (dst)) {
					if (myvalid (core->io, dst)) {
						RAnalRefType ref =
							(op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL
							? R_ANAL_REF_TYPE_CALL
							: R_ANAL_REF_TYPE_CODE;
						r_anal_xrefs_set (core->anal, cur, dst, ref);
						r_core_anal_fcn (core, dst, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
// analyze function here
#if 0
						if (op.type == R_ANAL_OP_TYPE_UCALL || op.type == R_ANAL_OP_TYPE_RCALL) {
							eprintf ("0x%08"PFMT64x"  RCALL TO %llx\n", cur, dst);
						}
#endif
					}
				}
			}
			break;
		default:
			break;
		}
		r_anal_esil_stack_free (ESIL);
repeat:
		if (!r_anal_get_block_at (core->anal, cur)) {
			size_t fcn_i;
			for (fcn_i = i_old + 1; fcn_i <= i; fcn_i++) {
				if (r_anal_get_function_at (core->anal, start + fcn_i)) {
					i = fcn_i - 1;
					break;
				}
			}
		}
		if (i >= iend) {
			break;
		}
	} while (get_next_i (&ictx, &i));
	free (buf);
	ESIL->cb.hook_mem_read = NULL;
	ESIL->cb.hook_mem_write = NULL;
	ESIL->cb.hook_reg_write = NULL;
	ESIL->user = NULL;
	r_anal_op_fini (&op);
	r_cons_break_pop ();
	// restore register
	r_reg_arena_pop (core->anal->reg);
}

static bool isValidAddress (RCore *core, ut64 addr) {
	// check if address is mapped
	RIOMap* map = r_io_map_get_at (core->io, addr);
	if (!map) {
		return false;
	}
	st64 fdsz = (st64)r_io_fd_size (core->io, map->fd);
	if (fdsz > 0 && map->delta > fdsz) {
		return false;
	}
	// check if associated file is opened
	RIODesc *desc = r_io_desc_get (core->io, map->fd);
	if (!desc) {
		return false;
	}
	// check if current map->fd is null://
	if (!strncmp (desc->name, "null://", 7)) {
		return false;
	}
	return true;
}

static bool stringAt(RCore *core, ut64 addr) {
	ut8 buf[32];
	r_io_read_at (core->io, addr - 1, buf, sizeof (buf));
	// check if previous byte is a null byte, all strings, except pascal ones should be like this
	if (buf[0] != 0) {
		return false;
	}
	return is_string (buf + 1, 31, NULL);
}

R_API int r_core_search_value_in_range(RCore *core, RInterval search_itv, ut64 vmin,
					 ut64 vmax, int vsize, inRangeCb cb, void *cb_user) {
	int i, align = core->search->align, hitctr = 0;
	bool vinfun = r_config_get_i (core->config, "anal.vinfun");
	bool vinfunr = r_config_get_i (core->config, "anal.vinfunrange");
	bool analStrings = r_config_get_i (core->config, "anal.strings");
	mycore = core;
	ut8 buf[4096];
	ut64 v64, value = 0, size;
	ut64 from = search_itv.addr, to = r_itv_end (search_itv);
	ut32 v32;
	ut16 v16;
	if (from >= to) {
		eprintf ("Error: from must be lower than to\n");
		return -1;
	}
	bool maybeThumb = false;
	if (align && core->anal->cur && core->anal->cur->arch) {
		if (!strcmp (core->anal->cur->arch, "arm") && core->anal->bits != 64) {
			maybeThumb = true;
		}
	}

	if (vmin >= vmax) {
		eprintf ("Error: vmin must be lower than vmax\n");
		return -1;
	}
	if (to == UT64_MAX) {
		eprintf ("Error: Invalid destination boundary\n");
		return -1;
	}
	r_cons_break_push (NULL, NULL);

	if (!r_io_is_valid_offset (core->io, from, 0)) {
		return -1;
	}
	while (from < to) {
		size = R_MIN (to - from, sizeof (buf));
		memset (buf, 0xff, sizeof (buf)); // probably unnecessary
		if (r_cons_is_breaked ()) {
			goto beach;
		}
		bool res = r_io_read_at_mapped (core->io, from, buf, size);
		if (!res || !memcmp (buf, "\xff\xff\xff\xff", 4) || !memcmp (buf, "\x00\x00\x00\x00", 4)) {
			if (!isValidAddress (core, from)) {
				ut64 next = from;
				if (!r_io_map_locate (core->io, &next, 1, 0)) {
					from += sizeof (buf);
				} else {
					from += (next - from);
				}
				continue;
			}
		}
		for (i = 0; i <= (size - vsize); i++) {
			void *v = (buf + i);
			ut64 addr = from + i;
			if (r_cons_is_breaked ()) {
				goto beach;
			}
			if (align && (addr) % align) {
				continue;
			}
			int match = false;
			int left = size - i;
			if (vsize > left) {
				break;
			}
			switch (vsize) {
			case 1: value = *(ut8 *)v; match = (buf[i] >= vmin && buf[i] <= vmax); break;
			case 2: v16 = *(uut16 *)v; match = (v16 >= vmin && v16 <= vmax); value = v16; break;
			case 4: v32 = *(uut32 *)v; match = (v32 >= vmin && v32 <= vmax); value = v32; break;
			case 8: v64 = *(uut64 *)v; match = (v64 >= vmin && v64 <= vmax); value = v64; break;
			default: eprintf ("Unknown vsize %d\n", vsize); return -1;
			}
			if (match && !vinfun) {
				if (vinfunr) {
					if (r_anal_get_fcn_in_bounds (core->anal, addr, R_ANAL_FCN_TYPE_NULL)) {
						match = false;
					}
				} else {
					if (r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL)) {
						match = false;
					}
				}
			}
			if (match && value) {
				bool isValidMatch = true;
				if (align && (value % align)) {
					// ignored .. unless we are analyzing arm/thumb and lower bit is 1
					isValidMatch = false;
					if (maybeThumb && (value & 1)) {
						isValidMatch = true;
					}
				}
				if (isValidMatch) {
					cb (core, addr, value, vsize, cb_user);
					if (analStrings && stringAt (core, addr)) {
						add_string_ref (mycore, addr, value);
					}
					hitctr++;
				}
			}
		}
		if (size == to-from) {
			break;
		}
		from += size-vsize+1;
	}
beach:
	r_cons_break_pop ();
	return hitctr;
}


typedef struct {
	dict visited;
	RList *path;
	RCore *core;
	ut64 from;
	RAnalBlock *fromBB;
	ut64 to;
	RAnalBlock *toBB;
	RAnalBlock *cur;
	bool followCalls;
	int followDepth;
	int count; // max number of results
} RCoreAnalPaths;

static bool printAnalPaths(RCoreAnalPaths *p, PJ *pj) {
	RListIter *iter;
	RAnalBlock *path;
	if (pj) {
		pj_a (pj);
	} else {
		r_cons_printf ("pdb @@= ");
	}

	r_list_foreach (p->path, iter, path) {
		if (pj) {
			pj_n (pj, path->addr);
		} else {
			r_cons_printf ("0x%08"PFMT64x" ", path->addr);
		}
	}

	if(pj) {
		pj_end (pj);
	} else {
		r_cons_printf ("\n");
	}
	return (p->count < 1 || --p->count > 0);
}
static void analPaths(RCoreAnalPaths *p, PJ *pj);

static void analPathFollow(RCoreAnalPaths *p, ut64 addr, PJ *pj) {
	if (addr == UT64_MAX) {
		return;
	}
	if (!dict_get (&p->visited, addr)) {
		p->cur = r_anal_bb_from_offset (p->core->anal, addr);
		analPaths (p, pj);
	}
}

static void analPaths(RCoreAnalPaths *p, PJ *pj) {
	RAnalBlock *cur = p->cur;
	if (!cur) {
		// eprintf ("eof\n");
		return;
	}
	/* handle ^C */
	if (r_cons_is_breaked ()) {
		return;
	}
	dict_set (&p->visited, cur->addr, 1, NULL);
	r_list_append (p->path, cur);
	if (p->followDepth && --p->followDepth == 0) {
		return;
	}
	if (p->toBB && cur->addr == p->toBB->addr) {
		if (!printAnalPaths (p, pj)) {
			return;
		}
	} else {
		RAnalBlock *c = cur;
		ut64 j = cur->jump;
		ut64 f = cur->fail;
		analPathFollow (p, j, pj);
		cur = c;
		analPathFollow (p, f, pj);
		if (p->followCalls) {
			int i;
			for (i = 0; i < cur->op_pos_size; i++) {
				ut64 addr = cur->addr + cur->op_pos[i];
				RAnalOp *op = r_core_anal_op (p->core, addr, R_ANAL_OP_MASK_BASIC);
				if (op && op->type == R_ANAL_OP_TYPE_CALL) {
					analPathFollow (p, op->jump, pj);
				}
				cur = c;
				r_anal_op_free (op);
			}
		}
	}
	p->cur = r_list_pop (p->path);
	dict_del (&p->visited, cur->addr);
	if (p->followDepth) {
		p->followDepth++;
	}
}

R_API void r_core_anal_paths(RCore *core, ut64 from, ut64 to, bool followCalls, int followDepth, bool is_json) {
	RAnalBlock *b0 = r_anal_bb_from_offset (core->anal, from);
	RAnalBlock *b1 = r_anal_bb_from_offset (core->anal, to);
	PJ *pj = NULL;
	if (!b0) {
		eprintf ("Cannot find basic block for 0x%08"PFMT64x"\n", from);
		return;
	}
	if (!b1) {
		eprintf ("Cannot find basic block for 0x%08"PFMT64x"\n", to);
		return;
	}
	RCoreAnalPaths rcap = {{0}};
	dict_init (&rcap.visited, 32, free);
	rcap.path = r_list_new ();
	rcap.core = core;
	rcap.from = from;
	rcap.fromBB = b0;
	rcap.to = to;
	rcap.toBB = b1;
	rcap.cur = b0;
	rcap.count = r_config_get_i (core->config, "search.maxhits");;
	rcap.followCalls = followCalls;
	rcap.followDepth = followDepth;

	// Initialize a PJ object for json mode
	if (is_json) {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}

	analPaths (&rcap, pj);

	if (is_json) {
		pj_end (pj);
		r_cons_printf ("%s", pj_string (pj));
	}

	if (pj) {
		pj_free (pj);
	}

	dict_fini (&rcap.visited);
	r_list_free (rcap.path);
}

static bool __cb(RFlagItem *fi, void *user) {
	r_list_append (user, r_str_newf ("0x%08"PFMT64x, fi->offset));
	return true;
}

static int __addrs_cmp(void *_a, void *_b) {
	ut64 a = r_num_get (NULL, _a);
	ut64 b = r_num_get (NULL, _b);
	if (a > b) {
		return 1;
	}
	if (a < b) {
		return -1;
	}
	return 0;
}

R_API void r_core_anal_inflags(RCore *core, const char *glob) {
	RList *addrs = r_list_newf (free);
	RListIter *iter;
	bool a2f = r_config_get_i (core->config, "anal.a2f");
	char *anal_in = strdup (r_config_get (core->config, "anal.in"));
	r_config_set (core->config, "anal.in", "block");
	// aaFa = use a2f instead of af+
	bool simple = (!glob || *glob != 'a');
	glob = r_str_trim_head_ro (glob);
	char *addr;
	r_flag_foreach_glob (core->flags, glob, __cb, addrs);
	// should be sorted already
	r_list_sort (addrs, (RListComparator)__addrs_cmp);
	r_list_foreach (addrs, iter, addr) {
		if (!iter->n || r_cons_is_breaked ()) {
			break;
		}
		char *addr2 = iter->n->data;
		if (!addr || !addr2) {
			break;
		}
		ut64 a0 = r_num_get (NULL, addr);
		ut64 a1 = r_num_get (NULL, addr2);
		if (a0 == a1) {
			// ignore
			continue;
		}
		if (a0 > a1) {
			eprintf ("Warning: unsorted flag list 0x%llx 0x%llx\n", a0, a1);
			continue;
		}
		st64 sz = a1 - a0;
		if (sz < 1 || sz > core->anal->opt.bb_max_size) {
			eprintf ("Warning: invalid flag range from 0x%08"PFMT64x" to 0x%08"PFMT64x"\n", a0, a1);
			continue;
		}
		if (simple) {
			RFlagItem *fi = r_flag_get_at (core->flags, a0, 0);
			r_core_cmdf (core, "af+ %s fcn.%s", addr, fi? fi->name: addr);
			r_core_cmdf (core, "afb+ %s %s %d", addr, addr, (int)sz);
		} else {
			r_core_cmdf (core, "aab@%s!%s-%s\n", addr, addr2, addr);
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, r_num_math (core->num, addr), 0);
			if (fcn) {
				eprintf ("%s  %s %"PFMT64d"    # %s\n", addr, "af", sz, fcn->name);
			} else {
				if (a2f) {
					r_core_cmdf (core, "a2f@%s!%s-%s\n", addr, addr2, addr);
				} else {
					r_core_cmdf (core, "af@%s!%s-%s\n", addr, addr2, addr);
				}
				fcn = r_anal_get_fcn_in (core->anal, r_num_math (core->num, addr), 0);
				eprintf ("%s  %s %.4"PFMT64d"   # %s\n", addr, "aab", sz, fcn?fcn->name: "");
			}
		}
	}
	r_list_free (addrs);
	r_config_set (core->config, "anal.in", anal_in);
	free (anal_in);
}

static bool analyze_noreturn_function(RCore *core, RAnalFunction *f) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (f->bbs, iter, bb) {
		ut64 opaddr = r_anal_bb_opaddr_i (bb, bb->ninstr - 1);
		if (opaddr == UT64_MAX) {
			return false;
		}

		// get last opcode
		RAnalOp *op = r_core_op_anal (core, opaddr, R_ANAL_OP_MASK_HINT);
		if (!op) {
			eprintf ("Cannot analyze opcode at 0x%08" PFMT64x "\n", opaddr);
			return false;
		}

		switch (op->type & R_ANAL_OP_TYPE_MASK) {
		case R_ANAL_OP_TYPE_ILL:
		case R_ANAL_OP_TYPE_RET:
			r_anal_op_free (op);
			return false;
		case R_ANAL_OP_TYPE_JMP:
			if (!r_anal_function_contains (f, op->jump)) {
				r_anal_op_free (op);
				return false;
			}
			break;
		}
		r_anal_op_free (op);
	}
	return true;
}

R_API void r_core_anal_propagate_noreturn(RCore *core, ut64 addr) {
	RList *todo = r_list_newf (free);
	if (!todo) {
		return;
	}

	HtUU *done = ht_uu_new0 ();
	if (!done) {
		r_list_free (todo);
		return;
	}

	RAnalFunction *request_fcn = NULL;
	if (addr != UT64_MAX) {
		request_fcn = r_anal_get_function_at (core->anal, addr);
		if (!request_fcn) {
			r_list_free (todo);
			ht_uu_free (done);
			return;
		}
	}

	// find known noreturn functions to propagate
	RListIter *iter;
	RAnalFunction *f;
	r_list_foreach (core->anal->fcns, iter, f) {
		if (f->is_noreturn) {
			ut64 *n = ut64_new (f->addr);
			r_list_append (todo, n);
		}
	}

	while (!r_list_empty (todo)) {
		ut64 *paddr = (ut64*)r_list_pop (todo);
		ut64 noret_addr = *paddr;
		free (paddr);
		if (r_cons_is_breaked ()) {
			break;
		}
		RList *xrefs = r_anal_xrefs_get (core->anal, noret_addr);
		RAnalRef *xref;
		r_list_foreach (xrefs, iter, xref) {
			RAnalOp *xrefop = r_core_op_anal (core, xref->addr, R_ANAL_OP_MASK_ALL);
			if (!xrefop) {
				eprintf ("Cannot analyze opcode at 0x%08" PFMT64x "\n", xref->addr);
				continue;
			}
			ut64 call_addr = xref->addr;
			ut64 chop_addr = call_addr + xrefop->size;
			r_anal_op_free (xrefop);
			if (xref->type != R_ANAL_REF_TYPE_CALL) {
				continue;
			}

			// Find the block that has an instruction at exactly the xref addr
			RList *blocks = r_anal_get_blocks_in (core->anal, call_addr);
			if (!blocks) {
				continue;
			}
			RAnalBlock *block = NULL;
			RListIter *bit;
			RAnalBlock *block_cur;
			r_list_foreach (blocks, bit, block_cur) {
				if (r_anal_block_op_starts_at (block_cur, call_addr)) {
					block = block_cur;
					break;
				}
			}
			if (block) {
				r_anal_block_ref (block);
			}
			r_list_free (blocks);
			if (!block) {
				continue;
			}

			RList *block_fcns = r_list_clone (block->fcns);
			if (request_fcn) {
				// specific function requested, check if it contains the bb
				if (!r_list_contains (block->fcns, request_fcn)) {
					goto kontinue;
				}
			} else {
				// r_anal_block_chop_noreturn() might free the block!
				block = r_anal_block_chop_noreturn (block, chop_addr);
			}

			RListIter *fit;
			r_list_foreach (block_fcns, fit, f) {
				bool found = ht_uu_find (done, f->addr, NULL) != 0;
				if (f->addr && !found && analyze_noreturn_function (core, f)) {
					f->is_noreturn = true;
					r_anal_noreturn_add (core->anal, NULL, f->addr);
					ut64 *n = malloc (sizeof (ut64));
					*n = f->addr;
					r_list_append (todo, n);
					ht_uu_insert (done, *n, 1);
				}
			}
kontinue:
			if (block) {
				r_anal_block_unref (block);
			}
			r_list_free (block_fcns);
		}
		r_list_free (xrefs);
	}
	r_list_free (todo);
	ht_uu_free (done);
}
