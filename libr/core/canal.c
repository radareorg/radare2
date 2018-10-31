/* radare - LGPL - Copyright 2009-2018 - pancake, nibble */

#include <r_types.h>
#include <r_list.h>
#include <r_flag.h>
#include <r_core.h>
#include <r_bin.h>

#include <string.h>

#define SLOW_IO 0

#define HINTCMD_ADDR(hint,x,y) if((hint)->x) \
	r_cons_printf (y" @ 0x%"PFMT64x"\n", (hint)->x, (hint)->addr)
#define HINTCMD(hint,x,y,json) if((hint)->x) \
	r_cons_printf (y"", (hint)->x)

typedef struct {
	RAnal *a;
	int mode;
	int count;
} HintListState;

// used to speedup strcmp with rconfig.get in loops
enum {
	R2_ARCH_ARM64
} R2Arch;


static void add_string_ref(RCore *core, ut64 xref_to);
static int cmpfcn(const void *_a, const void *_b);

static void loganal(ut64 from, ut64 to, int depth) {
	r_cons_clear_line (1);
	eprintf ("0x%08"PFMT64x" > 0x%08"PFMT64x" %d\r", from, to, depth);
}

static char *getFunctionName(RCore *core, ut64 addr) {
	RBinFile *bf = r_bin_cur (core->bin);
	RBinObject *bo = r_bin_file_object_get_cur (bf);
	if (bo) {
		Sdb *kv = bo->addr2klassmethod;
		char *at = sdb_fmt ("0x%08"PFMT64x, addr);
		char *res = sdb_get (kv, at, 0);
		if (res) {
			return strdup (res);
		}
	}
	RFlagItem *fi = r_flag_get_at (core->flags, addr, false);
	if (fi && fi->name && strncmp (fi->name, "sect", 4)) {
		return strdup (fi->name);
	}
	return NULL;
}

static RCore *mycore = NULL;

// XXX: copypaste from anal/data.c
#define MINLEN 1
static int is_string(const ut8 *buf, int size, int *len) {
	int i;
	if (size < 1) {
		return 0;
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

#if 0
// Detect if there's code in the given address
// - falls in section named 'text'
// - section has exec bit, some const strings are in there
// - addr is in different section than core->offset
static bool iscodesection(RCore *core, ut64 addr) {
	RIOSection *s = r_io_section_vget (core->io, addr);
	if (s && s->name && strstr (s->name, "text")) {
		return true;
	}
	return false;
	// BSS return (s && s->flags & R_PERM_W)? 0: 1;
	// Cstring return (s && s->flags & R_PERM_X)? 1: 0;
}
#endif

static char *is_string_at(RCore *core, ut64 addr, int *olen) {
	ut8 rstr[128] = {0};
	int ret = 0, len = 0;
	ut8 *str;
	//there can be strings in code section
#if 0
	if (iscodesection (core, addr)) {
		return NULL;
	}
#endif
	str = calloc (256, 1);
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
	// eprintf ("PTR %llx [ %llx %llx %llx ]\n", addr, cstr[0], cstr[1], cstr[2]);
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
	if (core->io && core->io->debug && core->dbg) {
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
		RIOSection *ios;
		SdbListIter *iter;
		if (core->io) {
			// sections
			ls_foreach (core->io->sections, iter, ios) {
				if (addr >= ios->vaddr && addr < (ios->vaddr + ios->vsize)) {
					// sections overlap, so we want to get the one with lower perms
					_perm = (_perm != -1) ? R_MIN (_perm, ios->perm) : ios->perm;
					// TODO: we should identify which maps come from the program or other
					//types |= R_ANAL_ADDR_TYPE_PROGRAM;
					// find function those sections should be created by hand or esil init
					if (strstr (ios->name, "heap")) {
						types |= R_ANAL_ADDR_TYPE_HEAP;
					}
					if (strstr (ios->name, "stack")) {
						types |= R_ANAL_ADDR_TYPE_STACK;
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
		"__stack_chk_guard", "__stderrp", "__stdinp", "__stdoutp", "_DefaultRuneLocale"
	};
	int i;
	for (i = 0; i < sizeof (list) / sizeof (list[0]); i++) {
		if (strstr (name, list[i])) { return true; }
	}
	return false;
}

static char *anal_fcn_autoname(RCore *core, RAnalFunction *fcn, int dump) {
	int use_getopt = 0;
	int use_isatty = 0;
	char *do_call = NULL;
	RAnalRef *ref;
	RListIter *iter;
	RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
	r_list_foreach (refs, iter, ref) {
		RFlagItem *f = r_flag_get_i (core->flags, ref->addr);
		if (f) {
			if (dump) {
				r_cons_printf ("0x%08"PFMT64x" 0x%08"PFMT64x" %s\n", ref->at, ref->addr, f->name);
			}
			if (blacklisted_word (f->name)) {
				break;
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
				break;
			}
			if (!strncmp (f->name, "str.", 4)) {
				free (do_call);
				do_call = strdup (f->name + 4);
				break;
			}
			if (!strncmp (f->name, "sym.imp.", 8)) {
				free (do_call);
				do_call = strdup (f->name + 8);
				break;
			}
			if (!strncmp (f->name, "reloc.", 6)) {
				free (do_call);
				do_call = strdup (f->name + 6);
				break;
			}
		}
	}
	r_list_free (refs);
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
		char *ret = r_str_newf ("sub.setup_tty_%s_%x", do_call, fcn->addr & 0xfff);
		free (do_call);
		return ret;
	}
	if (do_call) {
		char *ret = r_str_newf ("sub.%s_%x", do_call, fcn->addr & 0xfff);
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
				char *name = anal_fcn_autoname (core, fcn, 0);
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
	r_flag_space_push (core->flags, "symbols");
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
R_API char *r_core_anal_fcn_autoname(RCore *core, ut64 addr, int dump) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (fcn) {
		return anal_fcn_autoname (core, fcn, dump);
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
	RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_DATA &&
		    r_bin_is_string (core->bin, ref->addr)) {
			r_anal_xrefs_set (core->anal, ref->at, ref->addr, R_ANAL_REF_TYPE_STRING);
		}
	}
	r_list_free (refs);
}

static int r_anal_try_get_fcn(RCore *core, RAnalRef *ref, int fcndepth, int refdepth) {
	ut8 *buf;
	ut16 bufsz = 1000;
	RIOSection *sec;
	if (!refdepth) {
		return 1;
	}
	sec = r_io_section_vget (core->io, ref->addr);
	if (!sec) {
		return 1;
	}
	buf = calloc (bufsz, 1);
	if (!buf) {
		eprintf ("Error: malloc (buf)\n");
		return 0;
	}
	r_io_read_at (core->io, ref->addr, buf, bufsz);

	if (sec->perm & R_PERM_X &&
	    r_anal_check_fcn (core->anal, buf, bufsz, ref->addr, sec->vaddr,
			      sec->vaddr + sec->vsize)) {
		if (core->anal->limit) {
			if (ref->addr < core->anal->limit->from ||
			    ref->addr > core->anal->limit->to) {
				free (buf);
				return 1;
			}
		}
		r_core_anal_fcn (core, ref->addr, ref->at, ref->type, fcndepth - 1);
	} else {
		ut64 offs, sz = core->anal->bits >> 3;
		RAnalRef ref1;
		ref1.type = R_ANAL_REF_TYPE_DATA;
		ref1.at = ref->addr;
		ref1.addr = 0;
		ut32 i32;
		ut16 i16;
		ut8 i8;
		for (offs = 0; offs < bufsz; offs += sz, ref1.at += sz) {
			ut8* bo = buf + offs;
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
	free (buf);
	return 1;
}

static int r_anal_analyze_fcn_refs(RCore *core, RAnalFunction *fcn, int depth) {
	RListIter *iter;
	RAnalRef *ref;
	RList *refs = r_anal_fcn_get_refs (core->anal, fcn);

	r_list_foreach (refs, iter, ref) {
		if (ref->addr == UT64_MAX) {
			continue;
		}
		switch (ref->type) {
		case 'd':
			if (core->anal->opt.followdatarefs) {
				r_anal_try_get_fcn (core, ref, depth, 2);
			}
			break;
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_CALL:
			r_core_anal_fcn (core, ref->addr, ref->at, ref->type, depth-1);
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
		fcnpfx = r_anal_fcn_type_tostring (fcn->type);
		restofname = fcn->name + locsize;
		fcn->name = r_str_newf ("%s.%s", fcnpfx, restofname);

		f = r_flag_get_i (flags, fcn->addr);
		r_flag_rename (flags, f, fcn->name);

		free (fcnname);
	}
}

static int core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	if (depth < 0) {
//		printf ("Too deep for 0x%08"PFMT64x"\n", at);
//		r_sys_backtrace ();
		return false;
	}
	int has_next = r_config_get_i (core->config, "anal.hasnext");
	RAnalHint *hint = NULL;
	ut8 *buf = NULL;
	int i, nexti = 0;
	ut64 *next = NULL;
	int buflen, fcnlen;
	RAnalFunction *fcn = r_anal_fcn_new ();
	const char *fcnpfx = r_config_get (core->config, "anal.fcnprefix");
	if (!fcnpfx) {
		fcnpfx = "fcn";
	}
	if (!fcn) {
		eprintf ("Error: new (fcn)\n");
		return false;
	}
	fcn->cc = r_str_const (r_anal_cc_default (core->anal));
	hint = r_anal_hint_get (core->anal, at);
	if (hint && hint->bits == 16) {
		// expand 16bit for function
		fcn->bits = 16;
	} else {
		fcn->bits = core->anal->bits;
	}
	fcn->addr = at;
	r_anal_fcn_set_size (NULL, fcn, 0);
	fcn->name = getFunctionName (core, at);

	if (!fcn->name) {
		fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnpfx, at);
	}
	buflen = core->anal->opt.bb_max_size;
	buf = calloc (1, buflen);
	if (!buf) {
		eprintf ("Error: malloc (buf)\n");
		goto error;
	}
	do {
		RFlagItem *f;
		int delta = r_anal_fcn_size (fcn);
		// XXX hack slow check io error
		if (core->io->va) {
			if (!r_io_is_valid_offset (core->io, at+delta, !core->anal->opt.noncode)) {
				goto error;
			}
		}
		// TODO bring back old hack, should be fixed
		if (!r_io_read_at (core->io, at + delta, buf, 4)) {
			goto error;
		}
		(void)r_io_read_at (core->io, at + delta, buf, buflen);
		if (r_cons_is_breaked ()) {
			break;
		}
		fcnlen = r_anal_fcn (core->anal, fcn, at + delta, buf, buflen, reftype);
		if (core->anal->opt.searchstringrefs) {
			r_anal_set_stringrefs (core, fcn);
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
		f = r_flag_get_i2 (core->flags, fcn->addr);

		if (f && f->name && strncmp (f->name, "sect", 4)) {
			if (!strncmp (fcn->name, "loc.", 4)) {
				R_FREE (fcn->name);
				fcn->name = strdup (f->name);
			}
			if (!strncmp (fcn->name, "fcn.", 4)) {
				R_FREE (fcn->name);
				fcn->name = strdup (f->name);
			}
		} else {
			R_FREE (fcn->name);
			f = r_flag_get_i (core->flags, fcn->addr);
			if (f && *f->name && strncmp (f->name, "sect", 4)) {
				fcn->name = strdup (f->name);
			} else {

				fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnpfx, fcn->addr);
			}
		}
		if (fcnlen == R_ANAL_RET_ERROR ||
			(fcnlen == R_ANAL_RET_END && r_anal_fcn_size (fcn) < 1)) { /* Error analyzing function */
			if (core->anal->opt.followbrokenfcnsrefs) {
				r_anal_analyze_fcn_refs (core, fcn, depth);
			}
			goto error;
		} else if (fcnlen == R_ANAL_RET_END) { /* Function analysis complete */
			f = r_flag_get_i2 (core->flags, fcn->addr);
			R_FREE (fcn->name);
			if (f && f->name) { /* Check if it's already flagged */
				fcn->name = strdup (f->name);
			} else {
				f = r_flag_get_i (core->flags, fcn->addr);
				if (f && *f->name && strncmp (f->name, "sect", 4)) {
					fcn->name = strdup (f->name);
				} else {
					const char *fcnpfx = r_anal_fcn_type_tostring (fcn->type);
					if (!fcnpfx || !*fcnpfx || !strcmp (fcnpfx, "fcn")) {
						fcnpfx = r_config_get (core->config, "anal.fcnprefix");
					}
					fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnpfx, fcn->addr);
				}
				/* Add flag */
				r_flag_space_push (core->flags, "functions");
				r_flag_set (core->flags, fcn->name, fcn->addr, r_anal_fcn_size (fcn));
				r_flag_space_pop (core->flags);
			}
			// XXX fixes overlined function ranges wtf  // fcn->addr = at;
			/* TODO: Dupped analysis, needs more optimization */
			fcn->depth = 256;
			r_core_anal_bb (core, fcn, fcn->addr, true);
			// hack
			if (!fcn->depth) {
				eprintf ("Analysis depth reached at 0x%08"PFMT64x"\n", fcn->addr);
			} else {
				fcn->depth = 256 - fcn->depth;
			}

			/* New function: Add initial xref */
			if (from != UT64_MAX) {
				if (fcn->type == R_ANAL_FCN_TYPE_LOC) {
					RAnalFunction *f = r_anal_get_fcn_in (core->anal, from, -1);
					if (f) {
						if (!f->fcn_locs) {
							f->fcn_locs = r_list_new ();
						}
						r_list_append (f->fcn_locs, fcn);
						r_list_sort (f->fcn_locs, &cmpfcn);
					}
				}
				r_anal_xrefs_set (core->anal, from, fcn->addr, reftype);
			}
			// XXX: this is wrong. See CID 1134565
			r_anal_fcn_insert (core->anal, fcn);
			if (has_next) {
				ut64 addr = fcn->addr + r_anal_fcn_size (fcn);
				RIOSection *sect = r_io_section_vget (core->io, addr);
				// only get next if found on an executable section
				if (!sect || (sect && sect->perm & R_PERM_X)) {
					for (i = 0; i < nexti; i++) {
						if (next[i] == addr) {
							break;
						}
					}
					if (i == nexti) {
						ut64 at = fcn->addr + r_anal_fcn_size (fcn);
						while (true) {
							const RAnalMetaItem *mi = r_meta_find (core->anal, at, R_META_TYPE_ANY, 0);
							if (!mi) {
								break;
							}
							at += mi->size;
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
	R_FREE (buf);

	if (has_next) {
		for (i = 0; i < nexti; i++) {
			if (!next[i] || r_anal_get_fcn_in (core->anal, next[i], 0)) {
				continue;
			}
			r_core_anal_fcn (core, next[i], from, 0, depth - 1);
		}
		free (next);
	}
	r_anal_hint_free (hint);
	return true;

error:
	free (buf);
	// ugly hack to free fcn
	if (fcn) {
		if (!r_anal_fcn_size (fcn) || fcn->addr == UT64_MAX) {
			r_anal_fcn_free (fcn);
			fcn = NULL;
		} else {
			// TODO: mark this function as not properly analyzed
			if (!fcn->name) {
				// XXX dupped code.
				fcn->name = r_str_newf (
					"%s.%08" PFMT64x,
					r_anal_fcn_type_tostring (fcn->type),
					at);
				/* Add flag */
				r_flag_space_push (core->flags, "functions");
				r_flag_set (core->flags, fcn->name, at, r_anal_fcn_size (fcn));
				r_flag_space_pop (core->flags);
			}
			r_anal_fcn_insert (core->anal, fcn);
		}
		if (fcn && has_next) {
			ut64 newaddr = fcn->addr + r_anal_fcn_size (fcn);
			RIOSection *sect = r_io_section_vget (core->io, newaddr);
			if (!sect || (sect && (sect->perm & R_PERM_X))) {
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
	r_anal_hint_free (hint);
	return false;
}

/* decode and return the RANalOp at the address addr */
R_API RAnalOp* r_core_anal_op(RCore *core, ut64 addr, int mask) {
	int len;
	RAnalOp *op;
	ut8 buf[128];
	ut8 *ptr;
	RAsmOp asmop;

	if (!core || addr == UT64_MAX) {
		return NULL;
	}
	op = R_NEW0 (RAnalOp);
	if (!op) {
		return NULL;
	}
	if (addr >= core->offset && addr + 16 < core->offset + core->blocksize) {
		int delta = (addr - core->offset);
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

	// decode instruction here
	r_asm_set_pc (core->assembler, addr);
	r_asm_op_init (&asmop);
	if (r_asm_disassemble (core->assembler, &asmop, ptr, len) > 0) {
		op->mnemonic = strdup (r_strbuf_get (&asmop.buf_asm));
	}
	r_asm_op_fini (&asmop);
	return op;
err_op:
	free (op);
	return NULL;
}

static void print_hint_h_format(RAnalHint* hint) {
	r_cons_printf (" 0x%08"PFMT64x" - 0x%08"PFMT64x" =>", hint->addr, hint->addr + hint->size);
	HINTCMD (hint, arch, " arch='%s'", false);
	HINTCMD (hint, bits, " bits=%d", false);
	HINTCMD (hint, size, " size=%d", false);
	HINTCMD (hint, opcode, " opcode='%s'", false);
	HINTCMD (hint, syntax, " syntax='%s'", false);
	HINTCMD (hint, immbase, " immbase=%d", false);
	HINTCMD (hint, esil, " esil='%s'", false);
	if (hint->jump != UT64_MAX) {
		r_cons_printf (" jump: 0x%"PFMT64x, hint->jump);
	}
	if (hint->ret != UT64_MAX) {
		r_cons_printf (" ret: 0x%"PFMT64x, hint->ret);
	}
	r_cons_newline ();
}

static int cb(void *p, const char *k, const char *v) {
	HintListState *hls = p;
	RAnalHint *hint = r_anal_hint_from_string (hls->a, sdb_atoi (k + 5), v);
	switch (hls->mode) {
	case 's':
		r_cons_printf ("%s=%s\n", k, v);
		break;
	case '*':
		HINTCMD_ADDR (hint, arch, "aha %s");
		HINTCMD_ADDR (hint, bits, "ahb %d");
		HINTCMD_ADDR (hint, size, "ahs %d");
		HINTCMD_ADDR (hint, opcode, "aho %s");
		HINTCMD_ADDR (hint, syntax, "ahS %s");
		HINTCMD_ADDR (hint, immbase, "ahi %d");
		HINTCMD_ADDR (hint, esil, "ahe %s");
		if (hint->jump != UT64_MAX) {
			r_cons_printf ("ahc 0x%"PFMT64x" @ 0x%"PFMT64x"\n", hint->jump, hint->addr);
		}
		break;
	case 'j':
		r_cons_printf ("%s{\"from\":%"PFMT64d",\"to\":%"PFMT64d,
			hls->count>0?",":"", hint->addr, hint->addr+hint->size);
		HINTCMD (hint, arch, ",\"arch\":\"%s\"", true); // XXX: arch must not contain strange chars
		HINTCMD (hint, bits, ",\"bits\":%d", true);
		HINTCMD (hint, size, ",\"size\":%d", true);
		HINTCMD (hint, opcode, ",\"opcode\":\"%s\"", true);
		HINTCMD (hint, syntax, ",\"syntax\":\"%s\"", true);
		HINTCMD (hint, immbase, ",\"immbase\":%d", true);
		HINTCMD (hint, esil, ",\"esil\":\"%s\"", true);
		HINTCMD (hint, ptr, ",\"ptr\":\"0x%"PFMT64x"x\"", true);
		if (hint->jump != UT64_MAX) {
			r_cons_printf (",\"jump\":\"0x%"PFMT64x"\"", hint->jump);
		}
		r_cons_print ("}");
		break;
	default:
		print_hint_h_format (hint);
		break;
	}
	free (hint);
	return 1;
}

R_API void r_core_anal_hint_print(RAnal* a, ut64 addr, int mode) {
	RAnalHint *hint = r_anal_hint_get (a, addr);
	if (!hint) {
		return;
	}
	if (mode == '*') {
		HINTCMD_ADDR (hint, arch, "aha %s");
		HINTCMD_ADDR (hint, bits, "ahb %d");
		HINTCMD_ADDR (hint, size, "ahs %d");
		HINTCMD_ADDR (hint, opcode, "aho %s");
		HINTCMD_ADDR (hint, syntax, "ahS %s");
		HINTCMD_ADDR (hint, immbase, "ahi %d");
		HINTCMD_ADDR (hint, esil, "ahe %s");
	} else {
		print_hint_h_format (hint);
	}
	free (hint);
}

R_API void r_core_anal_hint_list(RAnal *a, int mode) {
#ifdef _MSC_VER
	HintListState hls = {0};
#else
	HintListState hls = {};
#endif
	hls.mode = mode;
	hls.count = 0;
	hls.a = a;
	if (mode == 'j') {
		r_cons_strcat ("[");
	}
#if 0
	sdb_foreach (a->sdb_hints, cb, &hls);
#else
	SdbList *ls = sdb_foreach_list (a->sdb_hints, true);
	SdbListIter *lsi;
	SdbKv *kv;
	ls_foreach (ls, lsi, kv) {
		cb (&hls, sdbkv_key (kv), sdbkv_value (kv));
	}
	ls_free (ls);
#endif
	if (mode == 'j') {
		r_cons_strcat ("]\n");
	}
}

static char *core_anal_graph_label(RCore *core, RAnalBlock *bb, int opts) {
	int is_html = r_cons_singleton ()->is_html;
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
	} else if (opts & R_CORE_ANAL_GRAPHBODY) {
		const bool scrColor = r_config_get (core->config, "scr.color");
		const bool scrUtf8 = r_config_get (core->config, "scr.utf8");
		r_config_set_i (core->config, "scr.color", COLOR_MODE_DISABLED);
		r_config_set (core->config, "scr.utf8", "false");
		snprintf (cmd, sizeof (cmd), "pD %d @ 0x%08" PFMT64x, bb->size, bb->addr);
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
	bool current = r_anal_bb_is_in_offset (bbi, core->offset);

	if (current && color_current) {
		r_cons_printf ("\t\"0x%08"PFMT64x"\" ", bbi->addr);
		r_cons_printf ("\t[fillcolor=%s style=filled shape=box];\n", pal_curr);
	}
	free (pal_curr);
}

static int core_anal_graph_nodes(RCore *core, RAnalFunction *fcn, int opts) {
	int is_html = r_cons_singleton ()->is_html;
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_json_format_disasm = opts & R_CORE_ANAL_JSON_FORMAT_DISASM;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	RAnalBlock *bbi;
	RListIter *iter;
	int left = 300;
	int count = 0;
	int nodes = 0;
	int top = 0;
	char *str;
	Sdb *DB = NULL;
	char *pal_jump = palColorFor ("graph.true");
	char *pal_fail = palColorFor ("graph.false");
	char *pal_trfa = palColorFor ("graph.trufae");
	char *pal_curr = palColorFor ("graph.current");
	char *pal_traced = palColorFor ("graph.traced");
	char *pal_box4 = palColorFor ("graph.box4");
	const char *font = r_config_get (core->config, "graph.font");
	bool color_current = r_config_get_i (core->config, "graph.gv.current");

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
		if (fcn->nargs > 0) {
			sdb_num_set (DB, "nargs", fcn->nargs, 0);
		}
		sdb_num_set (DB, "size", r_anal_fcn_size (fcn), 0);
		if (fcn->maxstack > 0) {
			sdb_num_set (DB, "stack", fcn->maxstack, 0);
		}
		sdb_set (DB, "pos", "0,0", 0); // needs to run layout
		sdb_set (DB, "type", r_anal_fcn_type_tostring (fcn->type), 0);
	} else if (is_json) {
		// TODO: show vars, refs and xrefs
		r_cons_printf ("{\"name\":\"%s\"", fcn->name);
		r_cons_printf (",\"offset\":%"PFMT64d, fcn->addr);
		r_cons_printf (",\"ninstr\":%"PFMT64d, (ut64)fcn->ninstr);
		r_cons_printf (",\"nargs\":%d",
			r_anal_var_count (core->anal, fcn, 'r', 1) +
			r_anal_var_count (core->anal, fcn, 's', 1) +
			r_anal_var_count (core->anal, fcn, 'b', 1));
		r_cons_printf (",\"nlocals\":%d",
			r_anal_var_count (core->anal, fcn, 'r', 0) +
			r_anal_var_count (core->anal, fcn, 's', 0) +
			r_anal_var_count (core->anal, fcn, 'b', 0));
		r_cons_printf (",\"size\":%d", r_anal_fcn_size (fcn));
		r_cons_printf (",\"stack\":%d", fcn->maxstack);
		r_cons_printf (",\"type\":\"%s\"", r_anal_fcn_type_tostring (fcn->type));
		//r_cons_printf (",\"cc\":%d", fcn->call); // TODO: calling convention
		if (fcn->dsc) {
			r_cons_printf (",\"signature\":\"%s\"", fcn->dsc);
		}
		r_cons_printf (",\"blocks\":[");
	}
	r_list_foreach (fcn->bbs, iter, bbi) {
		count ++;
		if (is_keva) {
			char key[128];
			sdb_array_push_num (DB, "bbs", bbi->addr, 0);
			snprintf (key, sizeof (key), "bb.0x%08"PFMT64x".size", bbi->addr);
			sdb_num_set (DB, key, bbi->size, 0); // bb.<addr>.size=<num>
		} else if (is_json) {
			RDebugTracepoint *t = r_debug_trace_get (core->dbg, bbi->addr);
			ut8 *buf = malloc (bbi->size);
			if (count > 1) {
				r_cons_printf (",");
			}
			r_cons_printf ("{\"offset\":%"PFMT64d",\"size\":%"PFMT64d, bbi->addr, (ut64)bbi->size);
			if (bbi->jump != UT64_MAX) {
				r_cons_printf (",\"jump\":%"PFMT64d, bbi->jump);
			}
			if (bbi->fail != -1) {
				r_cons_printf (",\"fail\":%"PFMT64d, bbi->fail);
			}
			if (bbi->switch_op) {
				RAnalSwitchOp *op = bbi->switch_op;
				r_cons_printf (
						",\"switchop\":{\"offset\":%"PFMT64u
						",\"defval\":%"PFMT64u
						",\"maxval\":%"PFMT64u
						",\"minval\":%"PFMT64u
						",\"cases\":[",
						op->addr, op->def_val, op->max_val, op->min_val);

				RAnalCaseOp *case_op;
				RListIter *case_iter;
				bool first_case = true;
				r_list_foreach (op->cases, case_iter, case_op) {
					if (!first_case) {
						r_cons_print (",");
					} else {
						first_case = false;
					}
					r_cons_printf (
							"{\"offset\":%"PFMT64u
							",\"value\":%"PFMT64u
							",\"jump\":%"PFMT64u"}",
							case_op->addr, case_op->value, case_op->jump);
				}
				r_cons_print ("]}");
			}
			if (t) {
				r_cons_printf (
					",\"trace\":{\"count\":%d,\"times\":%"
					"d}",
					t->count, t->times);
			}
			r_cons_printf (",\"colorize\":%d", bbi->colorize);
			r_cons_printf (",\"ops\":");
			if (buf) {
				r_io_read_at (core->io, bbi->addr, buf, bbi->size);
				if (is_json_format_disasm) {
					r_core_print_disasm (core->print, core, bbi->addr, buf, bbi->size, bbi->size, 0, 1, true, NULL);
				} else {
					r_cons_print ("[");
					r_core_print_disasm_json (core, bbi->addr, buf, bbi->size, 0);
					r_cons_print ("]");
				}
				free (buf);
			} else {
				eprintf ("cannot allocate %d byte(s)\n", bbi->size);
			}
			r_cons_print ("}");
			continue;
		}
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
			} else if (!is_json) {
				//r_cons_printf ("\t\"0x%08"PFMT64x"_0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"_0x%08"PFMT64x"\" "
				//	"[color=\"%s\"];\n", fcn->addr, bbi->addr, fcn->addr, bbi->jump,
				//	bbi->fail != -1 ? "green" : "blue");
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
					"[color=\"%s\"];\n", bbi->addr, bbi->jump,
					bbi->fail != -1 ? pal_jump : pal_trfa);
				core_anal_color_curr_node (core, bbi);
			}
		}
		if (bbi->fail != -1) {
			nodes++;
			if (is_html) {
				r_cons_printf ("<div class=\"connector _0x%08"PFMT64x" _0x%08"PFMT64x"\">\n"
					"  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
					bbi->addr, bbi->fail);
			} else if (!is_keva) {
				//r_cons_printf ("\t\"0x%08"PFMT64x"_0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"_0x%08"PFMT64x"\" "
				//	"[color=\"red\"];\n", fcn->addr, bbi->addr, fcn->addr, bbi->fail);
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
					"[color=\"%s\"];\n", bbi->addr, bbi->fail, pal_fail);
				core_anal_color_curr_node (core, bbi);
			}
		}
		if (bbi->switch_op) {
			RAnalCaseOp *caseop;
			RListIter *iter;

			if (is_html) {
				r_cons_printf ("<div class=\"connector _0x%08"PFMT64x" _0x%08"PFMT64x"\">\n"
					"  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
					bbi->addr, bbi->fail);
			} else if (!is_keva) {
				//r_cons_printf ("\t\"0x%08"PFMT64x"_0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"_0x%08"PFMT64x"\" "
				//	"[color=\"red\"];\n", fcn->addr, bbi->addr, fcn->addr, bbi->fail);
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
					"[color=\"%s\"];\n", bbi->addr, bbi->fail, pal_fail);
				core_anal_color_curr_node (core, bbi);
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
					r_cons_printf ("<div class=\"connector _0x%08"PFMT64x" _0x%08"PFMT64x"\">\n"
						"  <img class=\"connector-end\" src=\"img/arrow.gif\"/></div>\n",
						caseop->addr, caseop->jump);
				} else {
					//r_cons_printf ("\t\"0x%08"PFMT64x"_0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"_0x%08"PFMT64x"\" "
					//	"[color=\"red\"];\n", fcn->addr, caseop->addr, fcn->addr, caseop->jump);
					r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
						"[color2=\"%s\"];\n", caseop->addr, caseop->jump, pal_fail);
					core_anal_color_curr_node (core, bbi);
				}
			}
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
					//r_cons_printf (" \"0x%08"PFMT64x"_0x%08"PFMT64x"\" [color=\"%s\","
					//	" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
					//	fcn->addr, bbi->addr, difftype, str, fcn->name, bbi->addr);
					RConfigHold *hc = r_config_hold_new (core->config);
					r_config_save_num (hc, "scr.color", "scr.utf8", "asm.offset", "asm.lines",
							"asm.cmt.right", "asm.lines.fcn", "asm.bytes", NULL);
					RDiff *d = r_diff_new ();
					r_config_set_i (core->config, "scr.color", 0);
					r_config_set_i (core->config, "scr.utf8", 0);
					r_config_set_i (core->config, "asm.offset", 0);
					r_config_set_i (core->config, "asm.lines", 0);
					r_config_set_i (core->config, "asm.cmt.right", 0);
					r_config_set_i (core->config, "asm.lines.fcn", 0);
					r_config_set_i (core->config, "asm.bytes", 0);

					if (bbi->diff && bbi->diff->type != R_ANAL_DIFF_TYPE_MATCH && core->c2) {
						RCore *c = core->c2;
						RConfig *oc = c->config;
						char *str = r_core_cmd_strf (core, "pdb @ 0x%08"PFMT64x, bbi->addr);
						c->config = core->config;
						// XXX. the bbi->addr doesnt needs to be in the same address in core2
						char *str2 = r_core_cmd_strf (c, "pdb @ 0x%08"PFMT64x, bbi->diff->addr);
						char *diffstr = r_diff_buffers_to_string (d,
							(const ut8*)str, strlen (str),
							(const ut8*)str2, strlen(str2));
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
						diffstr = r_str_replace (diffstr, "\n", "\\l", 1);
						diffstr = r_str_replace (diffstr, "\"", "'", 1);
						// eprintf ("%s\n", diffstr? diffstr: "");
						r_cons_printf (" \"0x%08"PFMT64x"\" [fillcolor=\"%s\","
								"color=\"black\", fontname=\"Courier\","
								" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
								bbi->addr, difftype, diffstr, fcn->name, bbi->addr);
						free (diffstr);
						c->config = oc;
					} else {
						r_cons_printf (" \"0x%08"PFMT64x"\" [fillcolor=\"%s\","
								"color=\"black\", fontname=\"Courier\","
								" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
								bbi->addr, difftype, str, fcn->name, bbi->addr);
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
					bool current = r_anal_bb_is_in_offset (bbi, core->offset);
					const char *label_color = bbi->traced
						? pal_traced
						: (current && color_current)
							? pal_curr
							: pal_box4;
					nodes++;
					//r_cons_printf (" \"0x%08"PFMT64x"_0x%08"PFMT64x"\" ["
					//	"URL=\"%s/0x%08"PFMT64x"\", color=\"%s\", label=\"%s\"]\n",
					//	fcn->addr, bbi->addr,
					//	fcn->name, bbi->addr,
					//	bbi->traced?"yellow":"lightgray", str);
					r_cons_printf ("\t\"0x%08"PFMT64x"\" ["
						"URL=\"%s/0x%08"PFMT64x"\", fillcolor=\"%s\","
						"color=\"%s\", fontname=\"%s\","
						"label=\"%s\"]\n",
						bbi->addr, fcn->name, bbi->addr,
						current? "palegreen": "white", label_color, font, str);
				}
			}
			free (str);
		}
	}
	if (is_json) {
		r_cons_print ("]}");
	}
	free (pal_jump);
	free (pal_fail);
	free (pal_trfa);
	free (pal_curr);
	free (pal_traced);
	free (pal_box4);
	return nodes;
}

/* analyze a RAnalBlock at the address at and add that to the fcn function. */
R_API int r_core_anal_bb(RCore *core, RAnalFunction *fcn, ut64 at, int head) {
	RAnalBlock *bb;
	ut64 jump, fail;
	ut8 *buf = NULL;
	int buflen, bblen = 0, rc = true;
	int ret = R_ANAL_RET_NEW;

	if (--fcn->depth <= 0) {
		return false;
	}

	bb = r_anal_bb_new ();
	if (!bb) {
		return false;
	}

	ret = r_anal_fcn_split_bb (core->anal, fcn, bb, at);
	if (ret == R_ANAL_RET_DUP) {
		/* Dupped basic block */
		goto error;
	}

	if (ret == R_ANAL_RET_NEW) { /* New bb */
		// XXX: use static buffer size of 512 or so
		buf = malloc (core->anal->opt.bb_max_size);
		if (!buf) {
			goto error;
		}
		do {
#if SLOW_IO
			if (!r_io_read_at (core->io, at + bblen, buf, 4)) { // ETOOSLOW
				goto error;
			}
			r_io_read_at (core->io, at + bblen, buf, core->anal->opt.bb_max_size);
#else
			if (!r_io_read_at (core->io, at + bblen, buf, core->anal->opt.bb_max_size)) { // ETOOSLOW
				goto error;
			}
#endif
			if (!r_io_is_valid_offset (core->io, at + bblen, !core->anal->opt.noncode)) {
				goto error;
			}
			buflen = core->anal->opt.bb_max_size;
			bblen = r_anal_bb (core->anal, bb, at+bblen, buf, buflen, head);
			if (bblen == R_ANAL_RET_ERROR || (bblen == R_ANAL_RET_END && bb->size < 1)) { /* Error analyzing bb */
				goto error;
			}
			if (bblen == R_ANAL_RET_END) { /* bb analysis complete */
				ret = r_anal_fcn_bb_overlaps (fcn, bb);
				if (ret == R_ANAL_RET_NEW) {
					r_anal_fcn_bbadd (fcn, bb);
					fail = bb->fail;
					jump = bb->jump;
					if (fail != -1) {
						r_core_anal_bb (core, fcn, fail, false);
					}
					if (jump != -1) {
						r_core_anal_bb (core, fcn, jump, false);
					}
				}
			}
		} while (bblen != R_ANAL_RET_END);
		free (buf);
		return true;
	}
	goto fin;
error:
	rc = false;
fin:
	r_list_delete_data (fcn->bbs, bb);
	r_anal_bb_free (bb);
	free (buf);
	return rc;
}

/* returns the address of the basic block that contains addr or UT64_MAX if
 * there is no such basic block */
R_API ut64 r_core_anal_get_bbaddr(RCore *core, ut64 addr) {
	RAnalBlock *bbi;
	RAnalFunction *fcni;
	RListIter *iter, *iter2;
	r_list_foreach (core->anal->fcns, iter, fcni) {
		r_list_foreach (fcni->bbs, iter2, bbi) {
			if (addr >= bbi->addr && addr < bbi->addr + bbi->size) {
				return bbi->addr;
			}
		}
	}
	return UT64_MAX;
}

/* seek basic block that contains address addr or just addr if there's no such
 * basic block */
R_API int r_core_anal_bb_seek(RCore *core, ut64 addr) {
	ut64 bbaddr = r_core_anal_get_bbaddr (core, addr);
	if (bbaddr != UT64_MAX) {
		addr = bbaddr;
	}
	return r_core_seek (core, addr, false);
}

R_API int r_core_anal_esil_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	const char *esil;
	RAnalOp *op;
	eprintf ("TODO\n");
	while (1) {
		// TODO: Implement the proper logic for doing esil analysis
		op = r_core_anal_op (core, at, R_ANAL_OP_MASK_ESIL);
		if (!op) {
			break;
		}
		esil = R_STRBUF_SAFEGET (&op->esil);
		eprintf ("0x%08"PFMT64x" %d %s\n", at, op->size, esil);
		at += op->size;
		// esilIsRet()
		// esilIsCall()
		// esilIsJmp()
		r_anal_op_free (op);
		break;
	}
	return 0;
}

// XXX: This function takes sometimes forever
/* analyze a RAnalFunction at the address 'at'.
 * If the function has been already analyzed, it adds a
 * reference to that fcn */
R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	if (from == UT64_MAX && r_anal_get_fcn_in (core->anal, at, 0)) {
		return 0;
	}

	bool use_esil = r_config_get_i (core->config, "anal.esil");
	RAnalFunction *fcn;
	RListIter *iter;

	//update bits based on the core->offset otherwise we could have the
	//last value set and blow everything up
	r_anal_build_range_on_hints (core->anal);
	r_core_seek_archbits (core, at);

	if (core->io->va) {
		if (!r_io_is_valid_offset (core->io, at, !core->anal->opt.noncode)) {
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

	/* if there is an anal plugin and it wants to analyze the function itself,
	 * run it instead of the normal analysis */
	if (core->anal->cur && core->anal->cur->analyze_fns) {
		int result = R_ANAL_RET_ERROR;
		result = core->anal->cur->analyze_fns (core->anal, at, from, reftype, depth);
		/* update the flags after running the analysis function of the plugin */
		r_flag_space_push (core->flags, "functions");
		r_list_foreach (core->anal->fcns, iter, fcn) {
			r_flag_set (core->flags, fcn->name, fcn->addr, r_anal_fcn_size (fcn));
		}
		r_flag_space_pop (core->flags);
		return result;
	}
	if (from != UT64_MAX && !at) {
		return false;
	}
	if (at == UT64_MAX || depth < 0) {
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
		if (r_anal_fcn_is_in_offset (fcn, from)) { // inner function
			RList *l = r_anal_xrefs_get (core->anal, from);
			if (l && !r_list_empty (l)) {
				r_list_free (l);
				return true;
			}
			r_list_free (l);

			// we should analyze and add code ref otherwise aaa != aac
			if (from != UT64_MAX) {
				r_anal_xrefs_set (core->anal, from, fcn->addr, reftype);
			}
			return true;
		}
		// split function if overlaps
		r_anal_fcn_resize (core->anal, fcn, at - fcn->addr);
	}
	return core_anal_fcn (core, at, from, reftype, depth - 1);
}

/* if addr is 0, remove all functions
 * otherwise remove the function addr falls into */
R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter, *iter_tmp;

	if (!addr) {
		r_list_purge (core->anal->fcns);
		core->anal->fcn_tree = NULL;
		if (!(core->anal->fcns = r_anal_fcn_list_new ())) {
			return false;
		}
	} else {
		r_list_foreach_safe (core->anal->fcns, iter, iter_tmp, fcni) {
			if (r_anal_fcn_in (fcni, addr)) {
				r_anal_fcn_tree_delete (&core->anal->fcn_tree, fcni);
				r_list_delete (core->anal->fcns, iter);
			}
		}
	}
	return true;
}

static char *get_title(ut64 addr) {
	return r_str_newf ("0x%"PFMT64x, addr);
}

R_API int r_core_print_bb_custom(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	if (!fcn) {
		return false;
	}

	RConfigHold *hc = r_config_hold_new (core->config);
	r_config_save_num (hc, "scr.color", "scr.utf8", "asm.marks", "asm.offset", "asm.lines",
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
			r_config_restore (hc);
			r_config_hold_free (hc);
			return false;
		}
		body_b64 = r_str_prefix (body_b64, "base64:");
		r_cons_printf ("agn %s %s\n", title, body_b64);
		free (body);
		free (body_b64);
		free (title);
	}

	r_config_restore (hc);
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

R_API int r_core_print_bb_gml(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	if (!fcn) {
		return false;
	}

	r_cons_printf ("graph\n[\n" "hierarchic 1\n" "label \"\"\n" "directed 1\n");

	r_list_foreach (fcn->bbs, iter, bb) {
		RFlagItem *flag = r_flag_get_i (core->flags, bb->addr);
		char *msg = flag? strdup (flag->name): r_str_newf ("0x%08"PFMT64x, bb->addr);
		r_cons_printf ("  node [\n"
				"    id  %"PFMT64d"\n"
				"    label  \"%s\"\n"
				"  ]\n", bb->addr, msg);
		free (msg);
	}

	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}

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
	}
	r_cons_printf ("]\n");
	return true;
}

R_API void r_core_anal_datarefs(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		bool found = false;
		const char *me = fcn->name;
		RListIter *iter;
		RAnalRef *ref;
		RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
		r_list_foreach (refs, iter, ref) {
			RBinObject *obj = r_bin_cur_object (core->bin);
			RBinSection *binsec = r_bin_get_section_at (obj, ref->addr, true);
			if (binsec->is_data) {
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
		RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
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

R_API void r_core_anal_importxrefs(RCore *core) {
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinObject *obj = r_bin_cur_object (core->bin);
	bool lit = info ? info->has_lit: false;
	int va = core->io->va || core->io->debug;

	RListIter *iter;
	RBinImport *imp;
	if (!obj) {
		return;
	}
	r_list_foreach (obj->imports, iter, imp) {
		ut64 addr = lit ? r_core_bin_impaddr (core->bin, va, imp->name): 0;
		if (addr) {
			r_core_anal_codexrefs (core, addr);
		} else {
			r_cons_printf ("agn %s\n", imp->name);
		}
	}
}

R_API void r_core_anal_codexrefs(RCore *core, ut64 addr) {
	RFlagItem *f = r_flag_get_at (core->flags, addr, false);
	char *me = (f && f->offset == addr)
		? r_str_new (f->name) : r_str_newf ("0x%"PFMT64x, addr);
	r_cons_printf ("agn %s\n", me);
	RListIter *iter;
	RAnalRef *ref;
	RList *list = r_anal_xrefs_get (core->anal, addr);
	r_list_foreach (list, iter, ref) {
		RFlagItem *item = r_flag_get_i (core->flags, ref->addr);
		const char *src = item? item->name: sdb_fmt ("0x%08"PFMT64x, ref->addr);
		r_cons_printf ("agn %s\n", src);
		r_cons_printf ("age %s %s\n", src, me);
	}
	r_list_free (list);
	free (me);
}

R_API void r_core_anal_callgraph(RCore *core, ut64 addr, int fmt) {
	RAnalFunction fakefr = R_EMPTY;
	const char *font = r_config_get (core->config, "graph.font");
	int is_html = r_cons_singleton ()->is_html;
	bool refgraph = r_config_get_i (core->config, "graph.refs");
	int first, first2, showhdr = 0;
	RListIter *iter, *iter2;
	const int hideempty = 1;
	int usenames = r_config_get_i (core->config, "graph.json.usenames");;
	RAnalFunction *fcni;
	RAnalRef *fcnr;

	ut64 from = r_config_get_i (core->config, "graph.from");
	ut64 to = r_config_get_i (core->config, "graph.to");

	if (fmt == R_GRAPH_FORMAT_JSON) {
		r_cons_printf ("[");
	}
	if (fmt == R_GRAPH_FORMAT_GML || fmt == R_GRAPH_FORMAT_GMLFCN) {
		r_cons_printf ("graph\n[\n"
				"hierarchic  1\n"
				"label  \"\"\n"
				"directed  1\n");
	}
	first = 0;
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
		RList *refs = r_anal_fcn_get_refs (core->anal, fcni);
		if (!fmt) {
			r_cons_printf ("0x%08"PFMT64x"\n", fcni->addr);
		} else if (fmt == R_GRAPH_FORMAT_GML || fmt == R_GRAPH_FORMAT_GMLFCN) {
			RFlagItem *flag = r_flag_get_i (core->flags, fcni->addr);
			if (iteration == 0) {
				char *msg = flag? strdup (flag->name): r_str_newf ("0x%08"PFMT64x, fcni->addr);
				r_cons_printf ("  node [\n"
						"  id  %"PFMT64d"\n"
						"    label  \"%s\"\n"
						"  ]\n", fcni->addr - base, msg);
				free (msg);
			}
		} else if (fmt == R_GRAPH_FORMAT_JSON) {
			if (hideempty && !r_list_length (refs)) {
				r_list_free (refs);
				continue;
			}
			if (usenames) {
				r_cons_printf (
					"%s{\"name\":\"%s\", "
					"\"size\":%d,\"imports\":[",
					first ? "," : "", fcni->name,
					r_anal_fcn_size (fcni));
			} else {
				r_cons_printf ("%s{\"name\":\"0x%08" PFMT64x
					       "\", \"size\":%d,\"imports\":[",
					       first ? "," : "", fcni->addr,
					       r_anal_fcn_size (fcni));
			}
			first = 1;
		}
		first2 = 0;
		// TODO: maybe fcni->calls instead ?
		r_list_foreach (refs, iter2, fcnr) {
			RAnalFunction *fr = r_anal_get_fcn_in (core->anal, fcnr->addr, 0);
			if (!fr) {
				fr = &fakefr;
				if (fr) {
					free (fr->name);
					fr->name = r_str_newf ("unk.0x%"PFMT64x, fcnr->addr);
				}
			}
			if (!is_html && !showhdr) {
				if (fmt == R_GRAPH_FORMAT_DOT) {
					const char * gv_edge = r_config_get (core->config, "graph.gv.edge");
					const char * gv_node = r_config_get (core->config, "graph.gv.node");
					const char * gv_grph = r_config_get (core->config, "graph.gv.graph");
					const char * gv_spline = r_config_get (core->config, "graph.gv.spline");
					if (!gv_edge || !*gv_edge) {
						gv_edge = "arrowhead=\"normal\"";
					}
					if (!gv_node || !*gv_node) {
						gv_node = "fillcolor=gray style=filled shape=box";
					}
					if (!gv_grph || !*gv_grph) {
						gv_grph = "bgcolor=white";
					}
					if (!gv_spline || !*gv_spline) {
						gv_spline = "splines=\"ortho\"";
					}
					r_cons_printf ("digraph code {\n"
							"graph [%s fontname=\"%s\" %s];\n"
							"node [%s];\n"
							"edge [%s];\n", gv_grph, font, gv_spline,
							gv_node, gv_edge);
				}
				showhdr = 1;
			}
			// TODO: display only code or data refs?
			RFlagItem *flag = r_flag_get_i (core->flags, fcnr->addr);
			if (fmt == R_GRAPH_FORMAT_GML || fmt == R_GRAPH_FORMAT_GMLFCN) {
				if (iteration == 0) {
					if (fmt == R_GRAPH_FORMAT_GMLFCN) {
						char *msg = flag? strdup (flag->name): r_str_newf ("0x%08"PFMT64x, fcnr->addr);
						r_cons_printf ("  node [\n"
								"    id  %"PFMT64d"\n"
								"    label  \"%s\"\n"
								"  ]\n", fcnr->addr - base, msg
							      );
						r_cons_printf ("  edge [\n"
								"    source  %"PFMT64d"\n"
								"    target  %"PFMT64d"\n"
								"  ]\n", fcni->addr-base, fcnr->addr-base
							      );
						free (msg);
					}
				} else {
					r_cons_printf ("  edge [\n"
							"    source  %"PFMT64d"\n"
							"    target  %"PFMT64d"\n"
							"  ]\n", fcni->addr-base, fcnr->addr-base //, "#000000"
						      );
				}
			} else if (fmt == R_GRAPH_FORMAT_DOT) {
				if (flag && flag->name) {
					r_cons_printf ("  \"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
							"[label=\"%s\" color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
							fcni->addr, fcnr->addr, flag->name,
							(fcnr->type==R_ANAL_REF_TYPE_CODE ||
							 fcnr->type==R_ANAL_REF_TYPE_CALL)?"green":"red",
							flag->name, fcnr->addr);
					r_cons_printf ("  \"0x%08"PFMT64x"\" "
							"[label=\"%s\""
							" URL=\"%s/0x%08"PFMT64x"\"];\n",
							fcnr->addr, flag->name,
							flag->name, fcnr->addr);
				}
			} else if (fmt == R_GRAPH_FORMAT_JSON) {
				if (fr) {
					RList *refs1 = r_anal_fcn_get_refs (core->anal, fr);
					if (!hideempty || (hideempty && r_list_length (refs1) > 0)) {
						if (usenames) {
							r_cons_printf ("%s\"%s\"", first2?",":"", fr->name);
						} else {
							r_cons_printf ("%s\"0x%08"PFMT64x"\"", first2?",":"", fr->addr);
						}
						first2 = 1;
					}
					r_list_free (refs1);
				}
			} else {
				if (refgraph || fcnr->type == 'C') {
					// TODO: avoid recreating nodes unnecessarily
					r_cons_printf ("agn %s\n", fcni->name);
					r_cons_printf ("agn %s\n", fr->name);
					r_cons_printf ("age %s %s\n", fcni->name, fr->name);
				} else {
					r_cons_printf ("# - 0x%08"PFMT64x" (%c)\n", fcnr->addr, fcnr->type);
				}
			}
		}
		r_list_free (refs);
		if (fmt == R_GRAPH_FORMAT_JSON) {
			r_cons_printf ("]}");
		}
	}
	if (iteration == 0 && fmt == R_GRAPH_FORMAT_GML) {
		iteration++;
		goto repeat;
	}
	if (iteration == 0 && fmt == R_GRAPH_FORMAT_GMLFCN) {
		iteration++;
	}
	if (showhdr && (fmt == R_GRAPH_FORMAT_GML || fmt == R_GRAPH_FORMAT_GMLFCN)) {
		r_cons_printf ("]\n");
	}
	if (fmt == R_GRAPH_FORMAT_DOT) {
		r_cons_printf ("}\n");
	}
	if (fmt == R_GRAPH_FORMAT_JSON) {
		r_cons_printf ("]\n");
	}
}

static void fcn_list_bbs(RAnalFunction *fcn) {
	RAnalBlock *bbi;
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi) {
		r_cons_printf ("afb+ 0x%08" PFMT64x " 0x%08" PFMT64x " %d ",
			       fcn->addr, bbi->addr, bbi->size);
		r_cons_printf ("0x%08"PFMT64x" ", bbi->jump);
		r_cons_printf ("0x%08"PFMT64x" ", bbi->fail);
		if (bbi->type != R_ANAL_BB_TYPE_NULL) {
			if ((bbi->type & R_ANAL_BB_TYPE_BODY)) {
				r_cons_printf ("b");
			}
			if ((bbi->type & R_ANAL_BB_TYPE_FOOT)) {
				r_cons_printf ("f");
			}
			if ((bbi->type & R_ANAL_BB_TYPE_HEAD)) {
				r_cons_printf ("h");
			}
			if ((bbi->type & R_ANAL_BB_TYPE_LAST)) {
				r_cons_printf ("l");
			}
		} else {
			r_cons_printf ("n");
		}
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

R_API int r_core_anal_fcn_list_size(RCore *core) {
	RAnalFunction *fcn;
	RListIter *iter;
	ut32 total = 0;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		total += r_anal_fcn_size (fcn);
	}
	r_cons_printf ("%d\n", total);
	return total;
}

static int cmpfcn(const void *_a, const void *_b) {
	const RAnalFunction *_fcn1 = _a, *_fcn2 = _b;
	return (_fcn1->addr - _fcn2->addr);
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
		RList *refs = r_anal_fcn_get_refs (anal, fcn);
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

		// Determine the bounds of the functions address space
		ut64 min = UT64_MAX;
		ut64 max = UT64_MIN;

		RListIter *bbsiter;
		RAnalBlock *bbi;
		r_list_foreach (fcn->bbs, bbsiter, bbi) {
			if (max < bbi->addr + bbi->size) {
				max = bbi->addr + bbi->size;
			}
			if (min > bbi->addr) {
				min = bbi->addr;
			}
		}
		fcn->meta.min = min;
		fcn->meta.max = max;
	}
	// TODO: Determine sgnc, sgec
	return 0;
}

R_API char *r_core_anal_fcn_name(RCore *core, RAnalFunction *fcn) {
	bool demangle;
	const char *lang;
	demangle = r_config_get_i (core->config, "bin.demangle");
	lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;

	char *name = strdup (fcn->name ? fcn->name : "");
	if (demangle) {
		char *tmp = r_bin_demangle (core->bin->cur, lang, name, fcn->addr);
		if (tmp) {
			free (name);
			name = tmp;
		}
	}
	return name;
}

#define FCN_LIST_VERBOSE_ENTRY "%s0x%0*"PFMT64x" %4d %5d %5d %5d %4d 0x%0*"PFMT64x" %5d 0x%0*"PFMT64x" %5d %4d %6d %4d %5d %s%s\n"
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
			r_anal_fcn_realsize (fcn),
			r_list_length (fcn->bbs),
			r_anal_fcn_count_edges (fcn, &ebbs),
			r_anal_fcn_cc (fcn),
			r_anal_fcn_cost (core->anal, fcn),
			addrwidth, fcn->meta.min,
			r_anal_fcn_size (fcn),
			addrwidth, fcn->meta.max,
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

static int fcn_list_verbose(RCore *core, RList *fcns) {
	bool use_color = r_config_get_i (core->config, "scr.color");
	int headeraddr_width = 10;
	char *headeraddr = "==========";

	if (core->anal->bits == 64) {
		headeraddr_width = 18;
		headeraddr = "==================";
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

static int fcn_print_default(RCore *core, RAnalFunction *fcn, bool quiet) {
	if (quiet) {
		r_cons_printf ("0x%08"PFMT64x" ", fcn->addr);
	} else {
		char *msg, *name = r_core_anal_fcn_name (core, fcn);
		int realsize = r_anal_fcn_realsize (fcn);
		int size = r_anal_fcn_size (fcn);
		if (realsize == size) {
			msg = r_str_newf ("%-12d", size);
		} else {
			msg = r_str_newf ("%-4d -> %-4d", size, realsize);
		}
		r_cons_printf ("0x%08"PFMT64x" %4d %4s %s\n",
				fcn->addr, r_list_length (fcn->bbs), msg, name);
		free (name);
		free (msg);
	}
	return 0;
}

static int fcn_list_default(RCore *core, RList *fcns, bool quiet) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		fcn_print_default (core, fcn, quiet);
		if (quiet) {
			r_cons_newline ();
		}
	}
	return 0;
}

static int fcn_print_json(RCore *core, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalRef *refi;
	RList *refs, *xrefs;
	bool first = true;
	int ebbs = 0;
	char *name = r_core_anal_fcn_name (core, fcn);
	r_cons_printf ("{\"offset\":%"PFMT64d",\"name\":\"%s\",\"size\":%d",
			fcn->addr, name, r_anal_fcn_size (fcn));
	r_cons_printf (",\"realsz\":%d", r_anal_fcn_realsize (fcn));
	r_cons_printf (",\"stackframe\":%d", fcn->maxstack);
	r_cons_printf (",\"calltype\":\"%s\"", fcn->cc);
	r_cons_printf (",\"cost\":%d", r_anal_fcn_cost (core->anal, fcn));
	r_cons_printf (",\"cc\":%d", r_anal_fcn_cc (fcn));
	r_cons_printf (",\"bits\":%d", fcn->bits);
	r_cons_printf (",\"type\":\"%s\"", r_anal_fcn_type_tostring (fcn->type));
	r_cons_printf (",\"nbbs\":%d", r_list_length (fcn->bbs));
	r_cons_printf (",\"edges\":%d", r_anal_fcn_count_edges (fcn, &ebbs));
	r_cons_printf (",\"ebbs\":%d", ebbs);
	r_cons_printf (",\"minbound\":\"%d\"", fcn->meta.min);
	r_cons_printf (",\"maxbound\":\"%d\"", fcn->meta.max);
	int outdegree = 0;
	refs = r_anal_fcn_get_refs (core->anal, fcn);
	if (!r_list_empty (refs)) {
		r_cons_printf (",\"callrefs\":[");
		r_list_foreach (refs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_CALL) {
				outdegree++;
			}
			if (refi->type == R_ANAL_REF_TYPE_CODE ||
			    refi->type == R_ANAL_REF_TYPE_CALL) {
				r_cons_printf ("%s{\"addr\":%"PFMT64d",\"type\":\"%c\",\"at\":%"PFMT64d"}",
						first? "": ",",
						refi->addr,
						refi->type == R_ANAL_REF_TYPE_CALL?'C':'J',
						refi->at);
				first = false;
			}
		}
		r_cons_printf ("]");

		first = true;
		r_cons_printf (",\"datarefs\":[");
		r_list_foreach (refs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_DATA) {
				r_cons_printf ("%s%"PFMT64d, first?"":",", refi->addr);
				first = false;
			}
		}
		r_cons_printf ("]");
	}
	r_list_free (refs);

	int indegree = 0;
	xrefs = r_anal_fcn_get_xrefs (core->anal, fcn);
	if (!r_list_empty (xrefs)) {
		first = true;
		r_cons_printf (",\"codexrefs\":[");
		r_list_foreach (xrefs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_CODE ||
			    refi->type == R_ANAL_REF_TYPE_CALL) {
				indegree++;
				r_cons_printf ("%s{\"addr\":%"PFMT64d",\"type\":\"%c\",\"at\":%"PFMT64d"}",
						first?"":",",
						refi->addr,
						refi->type==R_ANAL_REF_TYPE_CALL?'C':'J',
						refi->at);
				first = 0;
			}
		}

		first = 1;
		r_cons_printf ("],\"dataxrefs\":[");
		r_list_foreach (xrefs, iter, refi) {
			if (refi->type == R_ANAL_REF_TYPE_DATA) {
				r_cons_printf ("%s%"PFMT64d, first?"":",", refi->addr);
				first = 0;
			}
		}
		r_cons_printf ("]");
	}
	r_list_free (xrefs);

	r_cons_printf (",\"indegree\":%d", indegree);
	r_cons_printf (",\"outdegree\":%d", outdegree);

	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		r_cons_printf (",\"nlocals\":%d",
				r_anal_var_count (core->anal, fcn, 'b', 0) +
				r_anal_var_count (core->anal, fcn, 'r', 0) +
				r_anal_var_count (core->anal, fcn, 's', 0));
		r_cons_printf (",\"nargs\":%d",
				r_anal_var_count (core->anal, fcn, 'b', 1) +
				r_anal_var_count (core->anal, fcn, 'r', 1) +
				r_anal_var_count (core->anal, fcn, 's', 1));

		r_cons_print (",\"bpvars\":");
		r_anal_var_list_show (core->anal, fcn, 'b', 'j');
		r_cons_print (",\"spvars\":");
		r_anal_var_list_show (core->anal, fcn, 's', 'j');
		r_cons_print (",\"regvars\":");
		r_anal_var_list_show (core->anal, fcn, 'r', 'j');

		r_cons_printf (",\"difftype\":\"%s\"",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"match":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new");
		if (fcn->diff->addr != -1) {
			r_cons_printf (",\"diffaddr\":%"PFMT64d, fcn->diff->addr);
		}
		if (fcn->diff->name) {
			r_cons_printf (",\"diffname\":\"%s\"", fcn->diff->name);
		}
	}

	r_cons_printf ("}");
	free (name);
	return 0;
}

static int fcn_list_json(RCore *core, RList *fcns, bool quiet) {
	RListIter *iter;
	RAnalFunction *fcn;
	bool first = true;
	r_cons_printf ("[");
	r_list_foreach (fcns, iter, fcn) {
		if (first) {
			first = false;
		} else {
			r_cons_printf (",");
		}
		if (quiet) {
			r_cons_printf ("%d", fcn->addr);
		} else {
			fcn_print_json (core, fcn);
		}
	}
	r_cons_printf ("]\n");
	return 0;
}

static int fcn_list_verbose_json(RCore *core, RList *fcns) {
	return fcn_list_json(core, fcns, false);
}

static int fcn_print_detail(RCore *core, RAnalFunction *fcn) {
	const char *defaultCC = r_anal_cc_default (core->anal);
	char *name = r_core_anal_fcn_name (core, fcn);
	r_cons_printf ("\"f %s %d 0x%08"PFMT64x"\"\n", name, r_anal_fcn_size (fcn), fcn->addr);
	r_cons_printf ("\"af+ 0x%08"PFMT64x" %s %c %c\"\n",
			fcn->addr, name, //r_anal_fcn_size (fcn), name,
			fcn->type == R_ANAL_FCN_TYPE_LOC?'l':
			fcn->type == R_ANAL_FCN_TYPE_SYM?'s':
			fcn->type == R_ANAL_FCN_TYPE_IMP?'i':'f',
			fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?'m':
			fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?'u':'n');
	// FIXME: this command prints something annoying. Does it have important side-effects?
	r_cons_printf ("afc %s @ 0x%08"PFMT64x"\n", fcn->cc?fcn->cc: defaultCC, fcn->addr);
	if (fcn->folded) {
		r_cons_printf ("afF @ 0x%08"PFMT64x"\n", fcn->addr);
	}
	fcn_list_bbs (fcn);
	/* show variables  and arguments */
	r_core_cmdf (core, "afvb* @ 0x%"PFMT64x"\n", fcn->addr);
	r_core_cmdf (core, "afvr* @ 0x%"PFMT64x"\n", fcn->addr);
	r_core_cmdf (core, "afvs* @ 0x%"PFMT64x"\n", fcn->addr);
	/* Show references */
	RListIter *refiter;
	RAnalRef *refi;
	RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
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
	r_cons_printf ("afS %"PFMT64d" @ 0x%"PFMT64x"\n", fcn->maxstack, fcn->addr);
	free (name);
	return 0;
}

static int fcn_print_legacy(RCore *core, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalRef *refi;
	RList *refs, *xrefs;
	int ebbs = 0;
	char *name = r_core_anal_fcn_name (core, fcn);
	r_cons_printf ("#\noffset: 0x%08"PFMT64x"\nname: %s\nsize: %"PFMT64d,
			fcn->addr, name, (ut64)r_anal_fcn_size (fcn));
	r_cons_printf ("\nrealsz: %d", r_anal_fcn_realsize (fcn));
	r_cons_printf ("\nstackframe: %d", fcn->maxstack);
	r_cons_printf ("\ncall-convention: %s", fcn->cc);
	r_cons_printf ("\ncyclomatic-cost : %d", r_anal_fcn_cost (core->anal, fcn));
	r_cons_printf ("\ncyclomatic-complexity: %d", r_anal_fcn_cc (fcn));
	r_cons_printf ("\nbits: %d", fcn->bits);
	r_cons_printf ("\ntype: %s", r_anal_fcn_type_tostring (fcn->type));
	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		r_cons_printf (" [%s]",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"MATCH":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"UNMATCH":"NEW");
	}
	r_cons_printf ("\nnum-bbs: %d", r_list_length (fcn->bbs));
	r_cons_printf ("\nedges: %d", r_anal_fcn_count_edges (fcn, &ebbs));
	r_cons_printf ("\nend-bbs: %d", ebbs);
	r_cons_printf ("\ncall-refs: ");
	int outdegree = 0;
	refs = r_anal_fcn_get_refs (core->anal, fcn);
	r_list_foreach (refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CALL) {
			outdegree++;
		}
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			r_cons_printf ("0x%08"PFMT64x" %c ", refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J');
		}
	}
	r_cons_printf ("\ndata-refs: ");
	r_list_foreach (refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf ("0x%08"PFMT64x" ", refi->addr);
		}
	}
	r_list_free (refs);

	int indegree = 0;
	r_cons_printf ("\ncode-xrefs: ");
	xrefs = r_anal_fcn_get_xrefs (core->anal, fcn);
	r_list_foreach (xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			indegree++;
			r_cons_printf ("0x%08"PFMT64x" %c ", refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J');
		}
	}
	r_cons_printf ("\nin-degree: %d", indegree);
	r_cons_printf ("\nout-degree: %d", outdegree);
	r_cons_printf ("\ndata-xrefs: ");
	r_list_foreach (xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf ("0x%08"PFMT64x" ", refi->addr);
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

		r_cons_printf ("\nlocals:%d\nargs: %d\n", var_count, args_count);
		r_anal_var_list_show (core->anal, fcn, 'b', 0);
		r_anal_var_list_show (core->anal, fcn, 's', 0);
		r_anal_var_list_show (core->anal, fcn, 'r', 0);
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

static int fcn_list_legacy(RCore *core, RList *fcns)
{
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (fcns, iter, fcn) {
		fcn_print_legacy (core, fcn);
	}
	r_cons_newline ();
	return 0;
}

R_API int r_core_anal_fcn_list(RCore *core, const char *input, const char *rad) {
	if (!core || !core->anal || r_list_empty (core->anal->fcns)) {
		return 0;
	}

	if (rad && (*rad == 'l' || *rad == 'j')) {
		fcnlist_gather_metadata (core->anal, core->anal->fcns);
	}

	const char *name = input;
	ut64 addr;
	addr = core->offset;
	if (input && *input) {
		name = input + 1;
		addr = r_num_math (core->num, name);
	}

	RList *fcns = r_list_new ();
	if (!fcns) {
		return -1;
	}
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (!input || r_anal_fcn_in (fcn, addr) || (!strcmp (name, fcn->name))) {
			r_list_append (fcns, fcn);
		}
	}

	r_list_sort (fcns, &cmpfcn);
	if (!rad) {
		fcn_list_default (core, fcns, false);
		r_list_free (fcns);
		return 0;
	}
	switch (*rad) {
	case '+':
		r_core_anal_fcn_list_size (core);
		break;
	case 'l':
		if (rad[1] == 'j') {
			fcn_list_verbose_json (core, fcns);
		} else {
			fcn_list_verbose (core, fcns);
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

static RList *recurse(RCore *core, RAnalBlock *from, RAnalBlock *dest);

static RList *recurse_bb(RCore *core, ut64 addr, RAnalBlock *dest) {
	RAnalBlock *bb;
	RList *ret;
	bb = r_anal_bb_from_offset (core->anal, addr);
	if (bb == dest) {
		eprintf ("path found!");
		return NULL;
	}
	ret = recurse (core, bb, dest);
	return ret? ret : NULL;
}

static RList *recurse(RCore *core, RAnalBlock *from, RAnalBlock *dest) {
	recurse_bb (core, from->jump, dest);
	recurse_bb (core, from->fail, dest);

	/* same for all calls */
	// TODO: RAnalBlock must contain a linked list of calls
	return NULL;
}

R_API void r_core_recover_vars(RCore *core, RAnalFunction *fcn, bool argonly) {
	ut8 *buf;
	RListIter *tmp = NULL;
	RAnalBlock *bb = NULL;
	RAnalOp *op = NULL;
	int count = 0;
	int reg_set[10] = {0};
	ut64 pos;

	if (!core || !core->anal || !fcn || core->anal->opt.bb_max_size < 1) {
		return;
	}
	int bb_size = core->anal->opt.bb_max_size;
	buf = calloc (1, bb_size);
	if (!buf) {
		return;
	}
	r_list_foreach (fcn->bbs, tmp, bb) {
		if (r_cons_is_breaked ()) {
			break;
		}
		if (bb->size < 1) {
			continue;
		}
		if (bb->size > bb_size) {
			continue;
		}
		if (!r_io_read_at (core->io, bb->addr, buf, bb->size)) {
			//eprintf ("read error\n");
			break;
		}
		pos = bb->addr;
		while (pos < bb->addr + bb->size) {
			if (r_cons_is_breaked ()) {
				break;
			}
			op = r_core_anal_op (core, pos, R_ANAL_OP_MASK_ALL);
			if (!op) {
				//eprintf ("Cannot get op\n");
				break;
			}
			extract_rarg (core->anal, op, fcn, reg_set, &count);
			if (!argonly) {
				extract_vars (core->anal, fcn, op);
			}
			int opsize = op->size;
			r_anal_op_free (op);
			if (opsize < 1) {
				break;
			}
			pos += opsize;
		}
	}
	free (buf);
	return;
}

R_API RList* r_core_anal_graph_to(RCore *core, ut64 addr, int n) {
	RAnalBlock *bb, *root = NULL, *dest = NULL;
	RListIter *iter, *iter2;
	RList *list2 = NULL, *list = NULL;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (!r_anal_fcn_is_in_offset (fcn, core->offset)) {
			continue;
		}
		r_list_foreach (fcn->bbs, iter2, bb) {
			if (r_anal_bb_is_in_offset (bb, addr)) {
				dest = bb;
			}
			if (r_anal_bb_is_in_offset (bb, core->offset)) {
				root = bb;
				r_list_append (list, list2);
			}
		}
	}
	if (root && dest) {
		if (dest == root) {
			eprintf ("Source and destination are the same\n");
			return NULL;
		}
		eprintf ("ROOT BB 0x%08"PFMT64x"\n", root->addr);
		eprintf ("DEST BB 0x%08"PFMT64x"\n", dest->addr);
		list = r_list_new ();
		printf ("=>  0x%08"PFMT64x"\n", root->jump);
	} else {
		eprintf ("Unable to find source or destination basic block\n");
	}
	return list;
}

R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts) {
	ut64 from = r_config_get_i (core->config, "graph.from");
	ut64 to = r_config_get_i (core->config, "graph.to");
	const char *font = r_config_get (core->config, "graph.font");
	int is_html = r_cons_singleton ()->is_html;
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_json_format_disasm = opts & R_CORE_ANAL_JSON_FORMAT_DISASM;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	RConfigHold *hc;
	RAnalFunction *fcni;
	RListIter *iter;
	int nodes = 0;
	int count = 0;

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

	r_config_save_num (hc, "asm.lines", "asm.bytes", "asm.dwarf", NULL);
	//opts |= R_CORE_ANAL_GRAPHBODY;
	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.dwarf", 0);
	if (!is_json_format_disasm) {
		r_config_save_num (hc, "asm.bytes", NULL);
		r_config_set_i (core->config, "asm.bytes", 0);
	}
	if (!is_html && !is_json && !is_keva) {
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
		r_cons_printf ("[");
	}
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (fcni->type & (R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_FCN |
		                  R_ANAL_FCN_TYPE_LOC) &&
		    (addr == UT64_MAX || r_anal_fcn_in (fcni, addr))) {
			if (addr == UT64_MAX && (from != UT64_MAX && to != UT64_MAX)) {
				if (fcni->addr < from || fcni->addr > to) {
					continue;
				}
			}
			if (is_json && count++ > 0) {
				r_cons_printf (",");
			}
			nodes += core_anal_graph_nodes (core, fcni, opts);
			if (addr != UT64_MAX) {
				break;
			}
		}
	}
	if (!nodes) {
		if (!is_html && !is_json && !is_keva) {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			r_cons_printf ("\t\"0x%08"PFMT64x"\";\n", fcn? fcn->addr: addr);
		}
	}
	if (!is_keva && !is_html && !is_json) {
		r_cons_printf ("}\n");
	}
	if (is_json) {
		r_cons_printf ("]\n");
	}
	r_config_restore (hc);
	r_config_hold_free (hc);
	return true;
}

static int core_anal_followptr(RCore *core, int type, ut64 at, ut64 ptr, ut64 ref, int code, int depth) {
	// SLOW Operation try to reduce as much as possible -- eprintf ("READ %d %llx\n", wordsize, ptr);
	if (!ptr) {
		return false;
	}
	if (ref == UT64_MAX || ptr == ref) {
		const RAnalRefType t = code? type? type: R_ANAL_REF_TYPE_CODE: R_ANAL_REF_TYPE_DATA;
		r_anal_xrefs_set (core->anal, at, ptr, t);
		return true;
	}
	if (depth < 1) {
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
	if (core->assembler->bits == 64) {
		// speedup search
		if (!strncmp (core->assembler->cur->name, "arm", 3)) {
			arch = R2_ARCH_ARM64;
		}
	}
	// TODO: get current section range here or gtfo
	// ???
	// XXX must read bytes correctly
	do_bckwrd_srch = bckwrds = core->search->bckwrds;
	r_io_use_fd (core->io, core->file->fd);
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
			// TODO: this can be probably enhaced
			if (!r_io_read_at (core->io, at, buf, core->blocksize)) {
				eprintf ("Failed to read at 0x%08" PFMT64x "\n", at);
				break;
			}
			for (i = bckwrds ? (core->blocksize - OPSZ - 1) : 0;
			     (!bckwrds && i < core->blocksize - OPSZ) ||
			     (bckwrds && i > 0);
			     bckwrds ? i-- : i++) {
				if (r_cons_is_breaked ()) {
					break;
				}
				switch (mode) {
				case 'c':
					(void)opiscall (core, &op, at + i, buf + i, core->blocksize - i, arch);
					if (op.size <1) {
						op.size = 1;
					}
					break;
				case 'r':
				case 'w':
				case 'x':
					{
						RAnalOp op ={0};
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
					if (op.jump != -1 &&
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
					if (op.ptr != -1 &&
						core_anal_followptr (core, 'c', at + i, op.ptr, ref, true ,1)) {
						count ++;
					}
					break;
				case R_ANAL_OP_TYPE_UCALL:
				case R_ANAL_OP_TYPE_ICALL:
				case R_ANAL_OP_TYPE_RCALL:
				case R_ANAL_OP_TYPE_IRCALL:
				case R_ANAL_OP_TYPE_UCCALL:
					if (op.ptr != -1 &&
						core_anal_followptr (core, 'C', at + i, op.ptr, ref, true ,1)) {
						count ++;
					}
					break;
				default:
					if (op.ptr != -1 &&
						core_anal_followptr (core, 'd', at + i, op.ptr, ref, false, ptrdepth)) {
						count ++;
					}
					break;
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

static void found_xref(RCore *core, ut64 at, ut64 xref_to, RAnalRefType type, int count, int rad, int cfg_debug, bool cfg_anal_strings) {
	// Validate the reference. If virtual addressing is enabled, we
	// allow only references to virtual addresses in order to reduce
	// the number of false positives. In debugger mode, the reference
	// must point to a mapped memory region.
	if (type == R_ANAL_REF_TYPE_NULL) {
		return;
	}
	if (cfg_debug) {
		if (!r_debug_map_get (core->dbg, xref_to)) {
			return;
		}
	} else if (core->io->va) {
		if (!r_io_is_valid_offset (core->io, xref_to, 0)) {
			return;
		}
	}
	if (!rad) {
		if (cfg_anal_strings && type == R_ANAL_REF_TYPE_DATA) {
			int len = 0;
			char *str_string = is_string_at (core, xref_to, &len);
			if (str_string) {
				r_name_filter (str_string, -1);
				char *str_flagname = r_str_newf ("str.%s", str_string);
				r_flag_space_push (core->flags, "strings");
				(void)r_flag_set (core->flags, str_flagname, xref_to, 1);
				r_flag_space_pop (core->flags);
				free (str_flagname);
				if (len > 0) {
					r_meta_add (core->anal, R_META_TYPE_STRING, xref_to,
							xref_to + len, (const char *)str_string);
				}
				free (str_string);
			}
		}
		// Add to SDB
		if (xref_to) {
			r_anal_xrefs_set (core->anal, at, xref_to, type);
		}
	} else if (rad == 'j') {
		// Output JSON
		if (count > 0) {
			r_cons_printf (",");
		}
		r_cons_printf ("\"0x%"PFMT64x"\":\"0x%"PFMT64x"\"", xref_to, at);
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

}

R_API int r_core_anal_search_xrefs(RCore *core, ut64 from, ut64 to, int rad) {
	int cfg_debug = r_config_get_i (core->config, "cfg.debug");
	bool cfg_anal_strings = r_config_get_i (core->config, "anal.strings");
	ut64 at;
	int count = 0;
	const int bsz = core->blocksize;
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
	if (rad == 'j') {
		r_cons_printf ("{");
	}
	r_cons_break_push (NULL, NULL);
	at = from;
	st64 asm_var_submin = r_config_get_i (core->config, "asm.var.submin");
	while (at < to && !r_cons_is_breaked ()) {
		int i = 0, ret = bsz;
		if (!r_io_is_valid_offset (core->io, at, R_PERM_X)) {
			break;
		}
		(void)r_io_read_at (core->io, at, buf, bsz);
		memset (block, -1, bsz);
		if (!memcmp (buf, block, bsz)) {
		//	eprintf ("Error: skipping uninitialized block \n");
			at += bsz;
			continue;
		}
		memset (block, 0, bsz);
		if (!memcmp (buf, block, bsz)) {
		//	eprintf ("Error: skipping uninitialized block \n");
			at += bsz;
			continue;
		}
		while (at < (at + bsz) && !r_cons_is_breaked ()) {
			if (r_cons_is_breaked ()) {
				break;
			}
			ret = r_anal_op (core->anal, &op, at, buf + i, bsz - i, 0);
			ret = ret > 0 ? ret : 1;
			i += ret;
			if (ret <= 0 || i > bsz) {
				break;
			}
			// find references
			if ((st64)op.val > asm_var_submin && op.val != UT64_MAX && op.val != UT32_MAX) {
				found_xref (core, op.addr, op.val, R_ANAL_REF_TYPE_DATA, count, rad, cfg_debug, cfg_anal_strings);
			}
			// find references
			if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
				found_xref (core, op.addr, op.ptr, R_ANAL_REF_TYPE_DATA, count, rad, cfg_debug, cfg_anal_strings);
			}
			switch (op.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
				found_xref (core, op.addr, op.jump, R_ANAL_REF_TYPE_CODE, count, rad, cfg_debug, cfg_anal_strings);
				break;
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_CCALL:
				found_xref (core, op.addr, op.jump, R_ANAL_REF_TYPE_CALL, count, rad, cfg_debug, cfg_anal_strings);
				break;
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IRJMP:
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UCJMP:
				found_xref (core, op.addr, op.ptr, R_ANAL_REF_TYPE_CODE, count, rad, cfg_debug, cfg_anal_strings);
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_IRCALL:
			case R_ANAL_OP_TYPE_UCCALL:
				found_xref (core, op.addr, op.ptr, R_ANAL_REF_TYPE_CALL, count, rad, cfg_debug, cfg_anal_strings);
				break;
			default:
				break;
			}
			count++;
			at += ret;
			r_anal_op_fini (&op);
		}
		r_anal_op_fini (&op);
	}
	r_cons_break_pop ();
	free (buf);
	free (block);
	if (rad == 'j') {
		r_cons_printf ("}\n");
	}
	return count;
}

static bool isValidSymbol(RBinSymbol *symbol) {
	if (symbol && symbol->type) {
		const char *type = symbol->type;
		return (!strcmp (type, R_BIN_TYPE_FUNC_STR) || !strcmp (type, "METH"));
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
	int depth = core->anal->opt.depth;
	bool anal_vars = r_config_get_i (core->config, "anal.vars");

	/* Analyze Functions */
	/* Entries */
	item = r_flag_get (core->flags, "entry0");
	if (item) {
		r_core_anal_fcn (core, item->offset, -1, R_ANAL_REF_TYPE_NULL, depth);
		r_core_cmdf (core, "afn entry0 0x%08"PFMT64x, item->offset);
	} else {
		r_core_cmd0 (core, "af");
	}

	r_cons_break_push (NULL, NULL);
	/* Symbols (Imports are already analyzed by rabin2 on init) */
	if ((list = r_bin_get_symbols (core->bin)) != NULL) {
		r_list_foreach (list, iter, symbol) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (strstr (symbol->name, ".dll_")) { // Stop analyzing PE imports further
				continue;
			}
			if (isValidSymbol (symbol)) {
				ut64 addr = r_bin_get_vaddr (core->bin, symbol->paddr,
					symbol->vaddr);
				r_core_anal_fcn (core, addr, -1,
					R_ANAL_REF_TYPE_NULL, depth);
			}
		}
	}
	/* Main */
	if ((binmain = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN)) != NULL) {
		if (binmain->paddr != UT64_MAX) {
			ut64 addr = r_bin_get_vaddr (core->bin, binmain->paddr, binmain->vaddr);
			r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
		}
	}
	if ((list = r_bin_get_entries (core->bin)) != NULL) {
		r_list_foreach (list, iter, entry) {
			ut64 addr = r_bin_get_vaddr (core->bin, entry->paddr, entry->vaddr);
			r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
		}
	}
	if (anal_vars) {
		/* Set fcn type to R_ANAL_FCN_TYPE_SYM for symbols */
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (r_cons_is_breaked ()) {
				break;
			}
			r_core_recover_vars (core, fcni, true);
			if (!strncmp (fcni->name, "sym.", 4) || !strncmp (fcni->name, "main", 4)) {
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
	int word = wordsize ? wordsize: core->assembler->bits / 8;
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

	RConsPrintablePalette *pal = r_config_get_i (core->config, "scr.color")? &r_cons_singleton ()->pal: NULL;
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

/* core analysis stats */
/* stats --- colorful bar */
R_API RCoreAnalStats* r_core_anal_get_stats(RCore *core, ut64 from, ut64 to, ut64 step) {
	RFlagItem *f;
	RAnalFunction *F;
	RBinSymbol *S;
	RListIter *iter;
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
		RIOSection *sec = r_io_section_get (core->io, at);
		piece = (at - from) / step;
		as->block[piece].perm = sec ? sec->perm:
				(core->io->desc ? core->io->desc->perm: 0);
	}
	// iter all flags
	r_list_foreach (core->flags->flags, iter, f) {
		//if (f->offset+f->size < from) continue;
		if (f->offset < from || f->offset > to) {
			continue;
		}
		piece = (f->offset - from) / step;
		as->block[piece].flags++;
	}
	// iter all functions
	r_list_foreach (core->anal->fcns, iter, F) {
		if (F->addr < from || F->addr > to) {
			continue;
		}
		piece = (F->addr - from) / step;
		as->block[piece].functions++;
		int last_piece = R_MIN ((F->addr + F->_size - 1) / step, blocks - 1);
		for (; piece <= last_piece; piece++) {
			as->block[piece].in_functions++;
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
	RList *metas = r_meta_enumerate (core->anal, -1);
	RAnalMetaItem *M;
	r_list_foreach (metas, iter, M) {
		if (M->from < from || M->to > to) {
			continue;
		}
		piece = (M->from - from) / step;
		switch (M->type) {
		case R_META_TYPE_STRING:
			as->block[piece].strings++;
			break;
		case R_META_TYPE_COMMENT:
			as->block[piece].comments++;
			break;
		}
	}
	// iter all comments
	// iter all strings
	return as;
}

R_API void r_core_anal_stats_free(RCoreAnalStats *s) {
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
				loganal (op->addr, addr, depth);
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
	RAnalFunction *f;
	r_anal_fcn_del_locs (core->anal, off);
	f = r_anal_get_fcn_in (core->anal, off, 0);
	if (f) {
		if (!strncmp (f->name, "fcn.", 4)) {
			r_flag_unset_name (core->flags, f->name);
		}
		r_meta_del (core->anal, R_META_TYPE_ANY, off, r_anal_fcn_size (f));
	}
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
	RAnalFunction *f1 = r_anal_get_fcn_at (core->anal, addr, 0);
	RAnalFunction *f2 = r_anal_get_fcn_at (core->anal, addr2, 0);
	RAnalFunction *f3 = NULL;
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
		r_anal_fcn_bbadd (f1, bb);
	}
	// TODO: import data/code/refs
	// update size
	f1->addr = R_MIN (addr, addr2);
	r_anal_fcn_set_size (core->anal, f1, max - min);
	// resize
	f2->bbs = NULL;
	r_anal_fcn_tree_delete (&core->anal->fcn_tree, f2);
	r_list_foreach (core->anal->fcns, iter, f2) {
		if (f2 == f3) {
			r_list_delete (core->anal->fcns, iter);
			f3->bbs = NULL;
		}
	}
}

R_API void r_core_anal_auto_merge(RCore *core, ut64 addr) {
	/* TODO: implement me */
}

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

static int esilbreak_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	/* do nothing */
	return 1;
}

/* TODO: move into RCore? */
static ut64 esilbreak_last_read = UT64_MAX;
static ut64 esilbreak_last_data = UT64_MAX;

static ut64 ntarget = UT64_MAX;

// TODO differentiate endian-aware mem_read with other reads; move ntarget handling to another function
static int esilbreak_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	ut8 str[128];
	if (addr != UT64_MAX) {
		esilbreak_last_read = addr;
	}
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
				r_anal_xrefs_set (mycore->anal, esil->address, refptr, R_ANAL_REF_TYPE_DATA);
				str[0] = 0;
				if (r_io_read_at (mycore->io, refptr, str, sizeof (str)) < 1) {
					eprintf ("Invalid read\n");
					str[0] = 0;
				}
				str[sizeof (str) - 1] = 0;
				add_string_ref (mycore, refptr);
				esilbreak_last_data = UT64_MAX;
				validRef = true;
			}
		}

		/** resolve ptr */
		if (ntarget == UT64_MAX || ntarget == addr || (ntarget == UT64_MAX && !validRef)) {
			r_anal_xrefs_set (mycore->anal, esil->address, addr, R_ANAL_REF_TYPE_DATA);
		}
	}
	return 0; // fallback
}

static bool esil_anal_stop = false;
static void cccb(void *u) {
	esil_anal_stop = true;
	eprintf ("^C\n");
}

static void add_string_ref(RCore *core, ut64 xref_to) {
	int len = 0;
	char *str_flagname;
	if (xref_to == UT64_MAX || !xref_to) {
		return;
	}
	str_flagname = is_string_at (core, xref_to, &len);
	if (str_flagname) {
		r_name_filter (str_flagname, -1);
		char *flagname = sdb_fmt ("str.%s", str_flagname);
		r_flag_space_push (core->flags, "strings");
		r_flag_set (core->flags, flagname, xref_to, len);
		r_flag_space_pop (core->flags);
		r_meta_add (core->anal, 's', xref_to, xref_to + len, str_flagname);
		//r_cons_printf ("Cs %d @ 0x%"PFMT64x"\n", len, xref_to);
		free (str_flagname);
	}
}

static int esilbreak_reg_write(RAnalEsil *esil, const char *name, ut64 *val) {
	RAnal *anal = NULL;
	RAnalOp *op = NULL;
	if (!esil) {
		return 0;
	}
	anal = esil->anal;
	op = esil->user;
	//specific case to handle blx/bx cases in arm through emulation
	// XXX this thing creates a lot of false positives
	if (anal && anal->opt.armthumb) {
		if (anal->cur && anal->cur->arch && anal->bits < 33 &&
		    strstr (anal->cur->arch, "arm") && !strcmp (name, "pc") && op) {
			switch (op->id) {
			//Thoses values comes from capstone so basically for others plugin
			//will not work since they not fill analop.id
			//do not include here capstone's headers
			case 14: //ARM_INS_BLX
			case 15: //ARM_INS_BX
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

	size = r_anal_fcn_size (fcn);
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

	r_asm_set_pc (core->assembler, cur);
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
	tmp_esil_str = r_str_trim_head_tail (tmp_esil_str);
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
	r_asm_set_pc (core->assembler, cur);

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

static inline bool canal_isThumb(RCore *core) {
	const char *asmarch = r_config_get (core->config, "asm.arch");
	return (!strcmp (asmarch, "arm") && core->anal->bits == 16);
}

R_API void r_core_anal_esil(RCore *core, const char *str, const char *target) {
	bool cfg_anal_strings = r_config_get_i (core->config, "anal.strings");
	RAnalEsil *ESIL = core->anal->esil;
	ut64 refptr = 0LL;
	const char *pcname;
#if 0
	RAsmOp asmop;
#endif
	RAnalOp op = R_EMPTY;
	ut8 *buf = NULL;
	bool end_address_set = false;
	int i, iend;
	int minopsize = 4; // XXX this depends on asm->mininstrsize
	ut64 addr = core->offset;
	ut64 end = 0LL;
	ut64 cur;

	mycore = core;
	if (!strcmp (str, "?")) {
		eprintf ("Usage: aae[f] [len] [addr] - analyze refs in function, section or len bytes with esil\n");
		eprintf ("  aae $SS @ $S             - analyze the whole section\n");
		eprintf ("  aae $SS str.Hello @ $S   - find references for str.Hellow\n");
		return;
	}
#define CHECKREF(x) ((refptr && (x) == refptr) || !refptr)
	if (target) {
		const char *expr = r_str_trim_ro (target);
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
	if (!strcmp (str, "f")) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (fcn) {
			addr = fcn->addr;
			end = fcn->addr + r_anal_fcn_size (fcn);
			end_address_set = true;
		}
	}

	if (!end_address_set) {
		if (str[0] == ' ') {
			end = addr + r_num_math (core->num, str + 1);
		} else {
			RIOSection *sect = r_io_section_vget (core->io, addr);
			if (sect) {
				end = sect->vaddr + sect->size;
			} else {
				end = addr + core->blocksize;
			}
		}
	}

	iend = end - addr;
	if (iend < 0) {
		return;
	}
	buf = malloc (iend + 2);
	if (!buf) {
		perror ("malloc");
		return;
	}
	esilbreak_last_read = UT64_MAX;
	r_io_read_at (core->io, addr, buf, iend + 1);
	if (!ESIL) {
		r_core_cmd0 (core, "aei");
		ESIL = core->anal->esil;
		if (!ESIL) {
			eprintf ("ESIL not initialized\n");
			return;
		}
	}
	ESIL->cb.hook_reg_write = &esilbreak_reg_write;
	//this is necessary for the hook to read the id of analop
	ESIL->user = &op;
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	ESIL->cb.hook_mem_write = &esilbreak_mem_write;
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
	if (core->anal->bits == 64 && !strcmp (core->anal->cur->arch, "arm")) {
		arch = R2_ARCH_ARM64;
	}

	int opalign = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_ALIGN);
	const char *sn = r_reg_get_name (core->anal->reg, R_REG_NAME_SN);
	r_reg_arena_push (core->anal->reg);
	for (i = 0; i < iend; i++) {
		if (esil_anal_stop || r_cons_is_breaked ()) {
			break;
		}
		cur = addr + i;
		/* realign address if needed */
		if (opalign > 0) {
			cur -= (cur % opalign);
		}
		r_anal_op_fini (&op);
		r_asm_set_pc (core->assembler, cur);
		if (!r_anal_op (core->anal, &op, cur, buf + i, iend - i, R_ANAL_OP_MASK_ALL)) {
			i += minopsize - 1;
		}
		// if (op.type & 0x80000000 || op.type == 0) {
		if (op.type == R_ANAL_OP_TYPE_ILL || op.type == R_ANAL_OP_TYPE_UNK) {
			// i +=2;
			continue;
		}
		//we need to check again i because buf+i may goes beyond its boundaries
		//because of i+= minopsize - 1
		if (i > iend) {
			break;
		}
		if (op.size < 1) {
			i += minopsize - 1;
			continue;
		}
		if (op.type == R_ANAL_OP_TYPE_SWI) {
			r_flag_space_set (core->flags, "syscalls");
			int snv = canal_isThumb (core)? op.val: (int)r_reg_getv (core->anal->reg, sn);
			RSyscallItem *si = r_syscall_get (core->anal->syscall, snv, -1);
			if (si) {
			//	eprintf ("0x%08"PFMT64x" SYSCALL %-4d %s\n", cur, snv, si->name);
				r_flag_set_next (core->flags, sdb_fmt ("syscall.%s", si->name), cur, 1);
			} else {
				//todo were doing less filtering up top because we cant match against 80 on all platforms
				// might get too many of this path now.. 
			//	eprintf ("0x%08"PFMT64x" SYSCALL %d\n", cur, snv);
				r_flag_set_next (core->flags, sdb_fmt ("syscall.%d", snv), cur, 1);
			}
			r_flag_space_set (core->flags, NULL);
		}
		if (1) {
			const char *esilstr = R_STRBUF_SAFEGET (&op.esil);
			i += op.size - 1;
			if (!esilstr || !*esilstr) {
				continue;
			}
			r_anal_esil_set_pc (ESIL, cur);
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
			//		if (core->anal->cur && strcmp (core->anal->cur->arch, "arm")) {
					if (CHECKREF (ESIL->cur)) {
						if (op.ptr && r_io_is_valid_offset (core->io, op.ptr, !core->anal->opt.noncode)) {
							r_anal_xrefs_set (core->anal, cur, op.ptr, R_ANAL_REF_TYPE_STRING);
						} else {
							r_anal_xrefs_set (core->anal, cur, ESIL->cur, R_ANAL_REF_TYPE_STRING);
						}
					}
				}
				if (cfg_anal_strings) {
					add_string_ref (core, op.ptr);
				}
				break;
			case R_ANAL_OP_TYPE_ADD:
				/* TODO: test if this is valid for other archs too */
				if (core->anal->cur && !strcmp (core->anal->cur->arch, "arm")) {
					/* This code is known to work on Thumb, ARM and ARM64 */
					ut64 dst = ESIL->cur;
					if ((target && dst == ntarget) || !target) {
						if (CHECKREF (dst)) {
							r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_DATA);
						}
					}
				//	if (cfg_anal_strings) {
						add_string_ref (core, dst);
				//	}
				} else if ((core->anal->bits == 32 && core->anal->cur && !strcmp (core->anal->cur->arch, "mips"))) {
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
									add_string_ref (core, dst);
								}
								if ((f = r_flag_get_i2 (core->flags, dst))) {
									r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, f->name);
								} else if ((str = is_string_at (mycore, dst, NULL))) {
									char *str2 = sdb_fmt ("esilref: '%s'", str);
									// HACK avoid format string inside string used later as format
									// string crashes disasm inside agf under some conditions.
									// https://github.com/radare/radare2/issues/6937
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
								add_string_ref (core, dst);
							}
						}
					}
					dst = esilbreak_last_data;
					if (dst != UT64_MAX && CHECKREF (dst)) {
						if (myvalid (mycore->io, dst)) {
							r_anal_xrefs_set (core->anal, cur, dst, R_ANAL_REF_TYPE_DATA);
							if (cfg_anal_strings) {
								add_string_ref (core, dst);
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
					if (dst == UT64_MAX) {
						dst = r_reg_getv (core->anal->reg, pcname);
					}
					if (CHECKREF (dst)) {
						if (myvalid (core->io, dst)) {
							RAnalRefType ref =
								(op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL
								? R_ANAL_REF_TYPE_CALL
								: R_ANAL_REF_TYPE_CODE;
							r_anal_xrefs_set (core->anal, cur, dst, ref);
						}
					}
				}
				break;
			}
			r_anal_esil_stack_free (ESIL);
		}
	}
	free (buf);
	r_anal_op_fini (&op);
	r_cons_break_pop ();
	// restore register
	r_reg_arena_pop (core->anal->reg);
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

static bool printAnalPaths(RCoreAnalPaths *p) {
	RListIter *iter;
	RAnalBlock *path;
	r_cons_printf ("pdb @@= ");
	r_list_foreach (p->path, iter, path) {
		r_cons_printf ("0x%08"PFMT64x" ", path->addr);
	}
	r_cons_printf ("\n");
	return (p->count < 1 || --p->count > 0);
}
static void analPaths(RCoreAnalPaths *p);

static void analPathFollow(RCoreAnalPaths *p, ut64 addr) {
	if (addr == UT64_MAX) {
		return;
	}
	if (!dict_get (&p->visited, addr)) {
		p->cur = r_anal_bb_from_offset (p->core->anal, addr);
		analPaths (p);
	}
}

static void analPaths(RCoreAnalPaths *p) {
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
		if (!printAnalPaths (p)) {
			return;
		}
	} else {
		RAnalBlock *c = cur;
		ut64 j = cur->jump;
		ut64 f = cur->fail;
		analPathFollow (p, j);
		cur = c;
		analPathFollow (p, f);
		if (p->followCalls) {
			int i;
			for (i = 0; i < cur->op_pos_size; i++) {
				ut64 addr = cur->addr + cur->op_pos[i];
				RAnalOp *op = r_core_anal_op (p->core, addr, R_ANAL_OP_MASK_BASIC);
				if (op && op->type == R_ANAL_OP_TYPE_CALL) {
					cur = c;
					analPathFollow (p, op->jump);
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

R_API void r_core_anal_paths(RCore *core, ut64 from, ut64 to, bool followCalls, int followDepth) {
	RAnalBlock *b0 = r_anal_bb_from_offset (core->anal, from);
	RAnalBlock *b1 = r_anal_bb_from_offset (core->anal, to);
	if (!b0) {
		eprintf ("Cannot find basic block for 0x%08"PFMT64x"\n", from);
	}
	if (!b1) {
		eprintf ("Cannot find basic block for 0x%08"PFMT64x"\n", to);
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

	analPaths (&rcap);

        dict_fini (&rcap.visited);
	r_list_free (rcap.path);
}
