/* radare - LGPL - Copyright 2009-2016 - pancake, nibble */

#include <r_types.h>
#include <r_list.h>
#include <r_flag.h>
#include <r_core.h>
#include <r_bin.h>

#include <string.h>

#define SLOW_IO 0
#define HASNEXT_FOREVER 1

#define HINTCMD_ADDR(hint,x,y) if(hint->x) \
	r_cons_printf (y" @ 0x%"PFMT64x"\n", hint->x, hint->addr)
#define HINTCMD(hint,x,y,json) if(hint->x) \
	r_cons_printf (y"", hint->x)

typedef struct {
	RAnal *a;
	int mode;
	int count;
} HintListState;

static void add_string_ref(RCore *core, ut64 xref_to);
static int cmpfcn(const void *_a, const void *_b);

static void loganal(ut64 from, ut64 to, int depth) {
	r_cons_clear_line (1);
	eprintf ("0x%08"PFMT64x" > 0x%08"PFMT64x" %d\r", from, to, depth);
}

static RCore *mycore = NULL;

// XXX: copypaste from anal/data.c
#define MINLEN 1
static int is_string (const ut8 *buf, int size, int *len) {
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
	// BSS return (s && s->rwx & R_IO_WRITE)? 0: 1;
	// Cstring return (s && s->rwx & R_IO_EXEC)? 1: 0;
}

static char *is_string_at(RCore *core, ut64 addr, int *olen) {
	ut8 *str;
	int ret, len = 0;
	if (iscodesection (core, addr)) {
		return NULL;
	}
	str = calloc (1024, 1);
	if (!str) {
		return NULL;
	}
	r_io_read_at (core->io, addr, str, 1024);
	str[1023] = 0;
	// check if current section have no exec bit
	ret = is_string (str, 1024, &len);
	if (!ret || len < 1) {
		ret = 0;
		free (str);
		len = -1;
	} else if (olen) {
		*olen = len;
	}
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
			ut64 val = r_reg_getv (core->dbg->reg, r->name);
			if (addr == val) {
				types |= R_ANAL_ADDR_TYPE_REG;
				break;
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
				if (map->perm & R_IO_EXEC) {
					types |= R_ANAL_ADDR_TYPE_EXEC;
				}
				if (map->perm & R_IO_READ) {
					types |= R_ANAL_ADDR_TYPE_READ;
				}
				if (map->perm & R_IO_WRITE) {
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
		int _rwx = -1;
		RIOSection *ios;
		RListIter *iter;
		if (core->io) {
			// sections
			r_list_foreach (core->io->sections, iter, ios) {
				if (addr >= ios->vaddr && addr < (ios->vaddr + ios->vsize)) {
					// sections overlap, so we want to get the one with lower perms
					_rwx = (_rwx != -1) ? R_MIN (_rwx, ios->rwx) : ios->rwx;
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
		if (_rwx != -1) {
			if (_rwx & R_IO_EXEC) {
				types |= R_ANAL_ADDR_TYPE_EXEC;
			}
			if (_rwx & R_IO_READ) {
				types |= R_ANAL_ADDR_TYPE_READ;
			}
			if (_rwx & R_IO_WRITE) {
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

/*this only autoname those function that start with fcn.* or sym.func.* */
R_API void r_core_anal_autoname_all_fcns(RCore *core) {
	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, it, fcn) {
		char *name = r_core_anal_fcn_autoname (core, fcn->addr, 0);
		if (name && (!strncmp (fcn->name, "fcn.", 4) || !strncmp (fcn->name, "sym.func.", 9))) {
			r_flag_rename (core->flags, r_flag_get (core->flags, fcn->name), name);
			free (fcn->name);
			fcn->name = name;
		} else {
			free (name);
		}
	}
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

/* suggest a name for the function at the address 'addr'.
 * If dump is true, every strings associated with the function is printed */
R_API char *r_core_anal_fcn_autoname(RCore *core, ut64 addr, int dump) {
	int use_getopt = 0;
	int use_isatty = 0;
	char *do_call = NULL;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (fcn) {
		RAnalRef *ref;
		RListIter *iter;
		r_list_foreach (fcn->refs, iter, ref) {
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
				if (!strncmp (f->name, "sym.imp.", 8)) {
					free (do_call);
					do_call = strdup (f->name+8);
					break;
				} else if (!strncmp (f->name, "reloc.", 6)) {
					free (do_call);
					do_call = strdup (f->name+6);
					break;
				}
			}
		}
		// TODO: append counter if name already exists
		if (use_getopt) {
			RFlagItem *item = r_flag_get (core->flags, "main");
			free (do_call);
			// if referenced from entrypoint. this should be main
			if (item && item->offset == addr) {
				return strdup ("main"); // main?
			}
			return strdup ("parse_args"); // main?
		}
		if (use_isatty) {
			char *ret = r_str_newf ("sub.setup_tty_%s_%x", do_call, addr & 0xfff);
			free (do_call);
			return ret;
		}
		if (do_call) {
			char *ret = r_str_newf ("sub.%s_%x", do_call, addr & 0xfff);
			free (do_call);
			return ret;
		}
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
	r_list_foreach (fcn->refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_DATA &&
		    r_bin_is_string (core->bin, ref->addr)) {
			ref->type = R_ANAL_REF_TYPE_STRING;
		}
	}
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

	if (sec->rwx & R_IO_EXEC &&
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

	free(buf);
	return 1;
}

static int r_anal_analyze_fcn_refs(RCore *core, RAnalFunction *fcn, int depth) {
	RListIter *iter, *tmp;
	RAnalRef *ref;

	r_list_foreach_safe (fcn->refs, iter, tmp, ref) {
		if (ref->addr != UT64_MAX) {
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
	}

	return 1;
}

static int core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	int has_next = r_config_get_i (core->config, "anal.hasnext");
	RAnalHint *hint;
	ut8 *buf = NULL;
	int i, nexti = 0;
	ut64 *next = NULL;
	int buflen, fcnlen;
	RAnalFunction *fcn = r_anal_fcn_new ();
	if (!fcn) {
		eprintf ("Error: new (fcn)\n");
		return false;
	}
	fcn->cc = r_anal_cc_default (core->anal);
	hint = r_anal_hint_get (core->anal, at);
	if (hint && hint->bits == 16) {
		// expand 16bit for function
		fcn->bits = 16;
	} else {
		fcn->bits = core->anal->bits;
	}
	fcn->addr = at;
	r_anal_fcn_set_size (fcn, 0);
	RFlagItem *fi = r_flag_get_at (core->flags, at);
	if (fi && fi->name && strncmp (fi->name, "sect", 4)) {
		fcn->name = strdup (fi->name);
	} else {
		fcn->name = r_str_newf ("fcn.%08"PFMT64x, at);
	}
	buf = malloc (core->anal->opt.bb_max_size);
	if (!buf) {
		eprintf ("Error: malloc (buf)\n");
		goto error;
	}

	do {
		RFlagItem *f;
		RAnalRef *ref;
		int delta = r_anal_fcn_size (fcn);
		// XXX hack slow check io error
		if ((buflen = r_io_read_at (core->io, at + delta, buf, 4) != 4)) {
			eprintf ("read errro\n");
			goto error;
		}
		// real read.
		// this is unnecessary if its contiguous
		buflen = r_io_read_at (core->io, at+delta, buf, core->anal->opt.bb_max_size);
		if (core->io->va && !core->io->raw) {
			if (!r_io_is_valid_offset (core->io, at+delta, !core->anal->opt.noncode)) {
				goto error;
			}
		}
		if (r_cons_singleton ()->breaked) {
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
		R_FREE (fcn->name);
		if (f && f->name && strncmp (f->name, "sect", 4)) {
			fcn->name = strdup (f->name);
		} else {
			f = r_flag_get_i (core->flags, fcn->addr);
			if (f && *f->name && strncmp (f->name, "sect", 4)) {
				fcn->name = strdup (f->name);
			} else {
				fcn->name = r_str_newf ("fcn.%08"PFMT64x, fcn->addr);
			}
		}
		if (fcnlen == R_ANAL_RET_ERROR ||
			(fcnlen == R_ANAL_RET_END && r_anal_fcn_size (fcn) < 1)) { /* Error analyzing function */
			if (core->anal->opt.followbrokenfcnsrefs) {
				r_anal_analyze_fcn_refs(core, fcn, depth);
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
					fcn->name = r_str_newf ("%s.%08"PFMT64x,
						r_anal_fcn_type_tostring (fcn->type), fcn->addr);
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
				// We shuold not use fcn->xrefs .. because that should be only via api (on top of sdb)
				// the concepts of refs and xrefs are a bit twisted in the old implementation
				ref = r_anal_ref_new ();
				if (!ref) {
					eprintf ("Error: new (xref)\n");
					goto error;
				}
				if (fcn->type == R_ANAL_FCN_TYPE_LOC) {
					RAnalFunction *f = r_anal_get_fcn_in (core->anal, from, -1);
					if (f) {
						if (!f->fcn_locs) {
							f->fcn_locs = r_anal_fcn_list_new ();
						}
						r_list_append (f->fcn_locs, fcn);
						r_list_sort (f->fcn_locs, &cmpfcn);
					}
				}
				ref->addr = from;
				ref->at = fcn->addr;
				ref->type = reftype;
				r_list_append (fcn->xrefs, ref);
				// XXX this is creating dupped entries in the refs list with invalid reftypes, wtf?
				r_anal_xrefs_set (core->anal, reftype, from, fcn->addr);
			}
			// XXX: this is wrong. See CID 1134565
			r_anal_fcn_insert (core->anal, fcn);
			if (has_next) {
				ut64 addr = fcn->addr + r_anal_fcn_size (fcn);
				RIOSection *sect = r_io_section_vget (core->io, addr);
				// only get next if found on an executable section
				if (!sect || (sect && sect->rwx & 1)) {
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
			if (!next[i]) {
				continue;
			}		
			r_core_anal_fcn (core, next[i], from, 0, depth - 1);
		}
		free (next);
	}
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
			if (!sect || (sect && (sect->rwx & 1))) {
				next = next_append (next, &nexti, newaddr);
				for (i = 0; i < nexti; i++) {
					if (!next[i]) continue;
#if HASNEXT_FOREVER
					r_core_anal_fcn (core, next[i], next[i], 0, 9999);
#else
					r_core_anal_fcn (core, next[i], next[i], 0, depth - 1);
#endif
				}
				free (next);
			}
		}
	}
	return false;
}

/* decode and return the RANalOp at the address addr */
R_API RAnalOp* r_core_anal_op(RCore *core, ut64 addr) {
	int len;
	RAnalOp *op;
	ut8 buf[128];
	ut8 *ptr;
	RAsmOp asmop;

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
		if (r_io_read_at (core->io, addr, buf, sizeof (buf)) < 1) {
			goto err_op;
		}
		ptr = buf;
		len = sizeof (buf);
	}
	if (r_anal_op (core->anal, op, addr, ptr, len) < 1) {
		goto err_op;
	}

	// decode instruction here
	r_asm_set_pc (core->assembler, addr);
	if (r_asm_disassemble (core->assembler, &asmop, ptr, len) > 0) {
		op->mnemonic = strdup (asmop.buf_asm);
	}
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
	r_cons_newline ();
}

static int cb(void *p, const char *k, const char *v) {
	RAnalHint *hint;
	HintListState *hls = p;

	hint = r_anal_hint_from_string (hls->a, sdb_atoi (k + 5), v);
	// TODO: format using (mode)
	switch (hls->mode) {
	case 's':
		r_cons_printf ("%s=%s\n", k, v);
	case '*':
		HINTCMD_ADDR (hint, arch, "aha %s");
		HINTCMD_ADDR (hint, bits, "ahb %d");
		HINTCMD_ADDR (hint, size, "ahs %d");
		HINTCMD_ADDR (hint, opcode, "aho %s");
		HINTCMD_ADDR (hint, syntax, "ahS %s");
		HINTCMD_ADDR (hint, immbase, "ahi %d");
		HINTCMD_ADDR (hint, esil, "ahe %s");
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
		r_cons_print ("}");
		break;
	default:
		print_hint_h_format (hint);
		break;
	}
	hls->count++;
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
	HintListState hls = {};
	hls.mode = mode;
	hls.count = 0;
	hls.a = a;
	if (mode == 'j') {
		r_cons_strcat ("[");
	}
	sdb_foreach (a->sdb_hints, cb, &hls);
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
#if R_ANAL_BB_HAS_OPS
		RAnalOp *opi;
		RListIter *iter;
		r_list_foreach (bb->ops, iter, opi) {
			r_bin_addr2line (core->bin, opi->addr, file, sizeof (file) - 1, &line);
#else
		for (at = bb->addr; at < bb->addr + bb->size; at += 2) {
			r_bin_addr2line (core->bin, at, file, sizeof (file) - 1, &line);
#endif
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
		r_cons_push ();
		snprintf (cmd, sizeof (cmd),
			  "pD %d @e:asm.comments=0 @ 0x%08" PFMT64x, bb->size,
			  bb->addr);
		cmdstr = r_core_cmd_str (core, cmd);
		r_cons_pop ();
	}
	if (cmdstr) {
		str = r_str_escape_dot (cmdstr);
		free (cmdstr);
	}
	return str;
}

static char *palColorFor(const char *k) {
	RCons *cons = r_cons_singleton ();
	if (!cons) {
		return NULL;
	}
	const char *c = r_cons_pal_get (k);
	if (c) {
		ut8 r = 0, g = 0, b = 0;
		r_cons_rgb_parse (c, &r, &g, &b, NULL);
		return r_cons_rgb_tostring (r, g, b);
	}
	return NULL;
}

static int core_anal_graph_nodes(RCore *core, RAnalFunction *fcn, int opts) {
	int is_html = r_cons_singleton ()->is_html;
	int is_json = opts & R_CORE_ANAL_JSON;
	int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	struct r_anal_bb_t *bbi;
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
		if (fcn->stack > 0) {
			sdb_num_set (DB, "stack", fcn->stack, 0);
		}
		sdb_set (DB, "pos", "0,0", 0); // needs to run layout
		sdb_set (DB, "type", r_anal_fcn_type_tostring (fcn->type), 0);
	} else if (is_json) {
		// TODO: show vars, refs and xrefs
		r_cons_printf ("{\"name\":\"%s\"", fcn->name);
		r_cons_printf (",\"offset\":%"PFMT64d, fcn->addr);
		r_cons_printf (",\"ninstr\":%"PFMT64d, fcn->ninstr);
		r_cons_printf (",\"nargs\":%d",
			r_anal_var_count (core->anal, fcn, 'r', 1) +
			r_anal_var_count (core->anal, fcn, 's', 1) +
			r_anal_var_count (core->anal, fcn, 'b', 1));
		r_cons_printf (",\"nlocals\":%d",
			r_anal_var_count (core->anal, fcn, 'r', 0) +
			r_anal_var_count (core->anal, fcn, 's', 0) +
			r_anal_var_count (core->anal, fcn, 'b', 0));
		r_cons_printf (",\"size\":%d", r_anal_fcn_size (fcn));
		r_cons_printf (",\"stack\":%d", fcn->stack);
		r_cons_printf (",\"type\":%d", fcn->type); // TODO: output string
		//r_cons_printf (",\"cc\":%d", fcn->call); // TODO: calling convention
		if (fcn->dsc) r_cons_printf (",\"signature\":\"%s\"", fcn->dsc);
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
			r_cons_printf ("{\"offset\":%"PFMT64d",\"size\":%"PFMT64d, bbi->addr, bbi->size);
			if (bbi->jump != UT64_MAX) {
				r_cons_printf (",\"jump\":%"PFMT64d, bbi->jump);
			}
			if (bbi->fail != -1) {
				r_cons_printf (",\"fail\":%"PFMT64d, bbi->fail);
			}
			if (t) {
				r_cons_printf (
					",\"trace\":{\"count\":%d,\"times\":%"
					"d}",
					t->count, t->times);
			}
			r_cons_printf (",\"ops\":");
			if (buf) {
				r_io_read_at (core->io, bbi->addr, buf, bbi->size);
				r_core_print_disasm_json (core, bbi->addr, buf, bbi->size, 0);
				free (buf);
			} else {
				eprintf ("cannot allocate %d bytes\n", bbi->size);
			}
			r_cons_printf ("}");
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
					"[color=\"%s\"];\n", pal_fail, bbi->addr, bbi->fail);
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
						"[color=\"%s\"];\n", pal_fail, caseop->addr, caseop->jump);
				}
			}
		}
		if ((str = core_anal_graph_label (core, bbi, opts))) {
			if (opts & R_CORE_ANAL_GRAPHDIFF) {
				const char *difftype = bbi->diff? (\
					bbi->diff->type==R_ANAL_DIFF_TYPE_MATCH? "lightgray":
					bbi->diff->type==R_ANAL_DIFF_TYPE_UNMATCH? "yellow": "red"): "gray";
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
					r_cons_printf (" \"0x%08"PFMT64x"\" [fillcolor=\"%s\","
						" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
						bbi->addr, difftype, str, fcn->name, bbi->addr);
				}
			} else {
				if (is_html) {
					nodes++;
					r_cons_printf ("<p class=\"block draggable\" style=\""
						"top: %dpx; left: %dpx; width: 400px;\" id=\""
						"_0x%08"PFMT64x"\">\n%s</p>\n",
						top, left, bbi->addr, str);
					left = left? 0: 600;
					if (!left) top += 250;
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
						"URL=\"%s/0x%08"PFMT64x"\", fillcolor=\"%s\", color=\"%s\", label=\"%s\"]\n",
						bbi->addr, fcn->name, bbi->addr,
						current? "yellow": "lightgray", label_color, str);
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
	RAnalBlock *bb, *bbi;
	RListIter *iter;
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

	if (core->anal->split) {
		ret = r_anal_fcn_split_bb (core->anal, fcn, bb, at);
	} else {
		r_list_foreach (fcn->bbs, iter, bbi) {
			if (at == bbi->addr) {
				ret = R_ANAL_RET_DUP;
			}
		}
	}
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
			if (r_io_read_at (core->io, at + bblen, buf, 4) != 4) { // ETOOSLOW
				goto error;
			}
			r_core_read_at (core, at + bblen, buf, core->anal->opt.bb_max_size);
#else
			if (r_io_read_at (core->io, at + bblen, buf, core->anal->opt.bb_max_size) != core->anal->opt.bb_max_size) { // ETOOSLOW
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
				if (core->anal->split) {
					ret = r_anal_fcn_bb_overlaps (fcn, bb);
				}
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
		op = r_core_anal_op (core, at);
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

	if (core->io->va && !core->io->raw) {
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
	if (r_cons_singleton()->breaked) {
		return false;
	}

	fcn = r_anal_get_fcn_in (core->anal, at, 0);
	if (fcn) {
		if (fcn->addr == at) {
			return 0;  // already analyzed function
		}
		if (r_anal_fcn_is_in_offset (fcn, from)) { // inner function
			RAnalRef *ref;

			// XXX: use r_anal-xrefs api and sdb
			// If the xref is new, add it
			// avoid dupes
			r_list_foreach (fcn->xrefs, iter, ref) {
				if (from == ref->addr) {
					return true;
				}
			}
			ref = r_anal_ref_new ();
			if (!ref) {
				eprintf ("Error: new (xref)\n");
				return false;
			}
			ref->addr = from;
			ref->at = at;
			ref->type = reftype;
			if (reftype == R_ANAL_REF_TYPE_DATA) {
				// XXX HACK TO AVOID INVALID REFS
				r_list_append (fcn->xrefs, ref);
			} else {
				free (ref);
			}
			// we should analyze and add code ref otherwise aaa != aac
			if (from != UT64_MAX) {
				// We shuold not use fcn->xrefs .. because that should be only via api (on top of sdb)
				// the concepts of refs and xrefs are a bit twisted in the old implementation
				ref = r_anal_ref_new ();
				if (ref) {
					ref->addr = from;
					ref->at = fcn->addr;
					ref->type = reftype;
					r_list_append (fcn->xrefs, ref);
					// XXX this is creating dupped entries in the refs list with invalid reftypes, wtf?
					r_anal_xrefs_set (core->anal, reftype, from, fcn->addr);
				} else {
					eprintf ("Error: new (xref)\n");
				}
			}
			return true;
		} else {
			// split function if overlaps
			r_anal_fcn_resize (fcn, at - fcn->addr);
		}
	}
	return core_anal_fcn (core, at, from, reftype, depth);
}

/* if addr is 0, remove all functions
 * otherwise remove the function addr falls into */
R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter, *iter_tmp;

	if (addr == 0) {
		r_list_purge (core->anal->fcns);
		if (!(core->anal->fcns = r_anal_fcn_list_new ()))
			return false;
	} else {
		r_list_foreach_safe (core->anal->fcns, iter, iter_tmp, fcni) {
			if (r_anal_fcn_in (fcni, addr)) {
				r_list_delete (core->anal->fcns, iter);
			}
		}
	}
	return true;
}

#define FMT_NO 0
#define FMT_GV 1
#define FMT_JS 2
R_API void r_core_anal_coderefs(RCore *core, ut64 addr, int fmt) {
	RAnalFunction fakefr = {0};
	const char *font = r_config_get (core->config, "graph.font");
	int is_html = r_cons_singleton ()->is_html;
	bool refgraph = r_config_get_i (core->config, "graph.refs");
	int first, first2, showhdr = 0;
	RListIter *iter, *iter2;
	const int hideempty = 1;
	const int usenames = 1;
	RAnalFunction *fcni;
	RAnalRef *fcnr;

	ut64 from = r_config_get_i (core->config, "graph.from");
	ut64 to = r_config_get_i (core->config, "graph.to");

	if (fmt == 2) {
		r_cons_printf ("[");
	}
	first = 0;
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (from != UT64_MAX && addr < from) {
			continue;
		}
		if (to != UT64_MAX && addr > to) {
			continue;
		}
		if (addr != UT64_MAX && addr != fcni->addr) {
			continue;
		}
		if (!fmt) {
			r_cons_printf ("0x%08"PFMT64x"\n", fcni->addr);
		} else if (fmt == 2) {
			if (hideempty && !r_list_length (fcni->refs)) {
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
		r_list_foreach (fcni->refs, iter2, fcnr) {
			RAnalFunction *fr = r_anal_get_fcn_in (core->anal, fcnr->addr, 0);
			if (!fr) {
				fr = &fakefr;
				if (fr) {
					free (fr->name);
					fr->name = r_str_newf ("unk.0x%"PFMT64x, fcnr->addr);
				}
			}
			if (!is_html && !showhdr) {
				if (fmt == 1) {
					const char * gv_edge = r_config_get (core->config, "graph.gv.edge");
					const char * gv_node = r_config_get (core->config, "graph.gv.node");
					const char * gv_grph = r_config_get (core->config, "graph.gv.graph");
					if (!gv_edge || !*gv_edge) {
						gv_edge = "arrowhead=\"vee\"";
					}
					if (!gv_node || !*gv_node) {
						gv_node = "fillcolor=gray style=filled shape=box";
					}
					if (!gv_grph || !*gv_grph) {
						gv_grph = "bgcolor=white";
					}
					r_cons_printf ("digraph code {\n"
							"\tgraph [%s fontname=\"%s\"];\n"
							"\tnode [%s];\n"
							"\tedge [%s];\n", gv_grph, font, gv_node, gv_edge);
				}
				showhdr = 1;
			}
			// TODO: display only code or data refs?
			RFlagItem *flag = r_flag_get_i (core->flags, fcnr->addr);
			if (fmt == 1) {
				if (flag && flag->name) {
					r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
						"[label=\"%s\" color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
						fcni->addr, fcnr->addr, flag->name,
						(fcnr->type==R_ANAL_REF_TYPE_CODE ||
						 fcnr->type==R_ANAL_REF_TYPE_CALL)?"green":"red",
						flag->name, fcnr->addr);
					r_cons_printf ("\t\"0x%08"PFMT64x"\" "
						"[label=\"%s\""
						" URL=\"%s/0x%08"PFMT64x"\"];\n",
						fcnr->addr, flag->name,
						flag->name, fcnr->addr);
				}
			} else if (fmt == 2) {
				if (fr) {
					if (!hideempty || (hideempty && r_list_length (fr->refs) > 0)) {
						if (usenames) {
							r_cons_printf ("%s\"%s\"", first2?",":"", fr->name);
						} else {
							r_cons_printf ("%s\"0x%08"PFMT64x"\"", first2?",":"", fr->addr);
						}
						first2 = 1;
					}
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
		if (fmt == 2) {
			r_cons_printf ("]}");
		}
	}
	if (showhdr && fmt == 1) {
		r_cons_printf ("}\n");
	}
	if (fmt == 2) {
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
	return (_fcn1->addr > _fcn2->addr);
}

/* Fill out metadata struct of functions */
static int fcnlist_gather_metadata(RList *fcns) {
	RListIter *iter;
	RAnalFunction *fcn;

	r_list_foreach (fcns, iter, fcn) {
		// Count the number of references and number of calls
		RListIter *callrefiter;
		RAnalRef *ref;
		int numcallrefs = 0;
		int numrefs = 0;
		r_list_foreach (fcn->refs, callrefiter, ref) {
			if (ref->type == R_ANAL_REF_TYPE_CALL) {
				numcallrefs++;
			}
			numrefs++;
		}
		fcn->meta.numrefs = numrefs;
		fcn->meta.numcallrefs = numcallrefs;

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

static char *get_fcn_name(RCore *core, RAnalFunction *fcn) {
	bool demangle;
	const char *lang;
	demangle = r_config_get_i (core->config, "bin.demangle");
	lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;

	char *name = strdup (fcn->name ? fcn->name : "");
	if (demangle) {
		char *tmp;
		tmp = r_bin_demangle (core->bin->cur, lang, name);
		if (tmp) {
			free (name);
			name = tmp;
		}
	} 
	return name;
}

static int count_edges(RAnalFunction *fcn, int *ebbs) {
	RListIter *iter;
	RAnalBlock *bb;
	int edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges ++;
			}
			if (bb->fail != UT64_MAX) {
				edges ++;
			}
		}
	}
	return edges;
}

#define FCN_LIST_VERBOSE_ENTRY "%s0x%08"PFMT64x" %4d %5d %5d %4d 0x%08"PFMT64x" %5d 0x%08"PFMT64x" %5d %4d %6d %4d %5d %s%s\n"
static int fcn_print_verbose(RCore *core, RAnalFunction *fcn, bool use_color) {
	char *name = get_fcn_name(core, fcn);
	int ebbs = 0;
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

	r_cons_printf (FCN_LIST_VERBOSE_ENTRY, color,
			fcn->addr,
			r_anal_fcn_realsize (fcn),
			r_list_length (fcn->bbs),
			count_edges (fcn, &ebbs),
			r_anal_fcn_cc (fcn),
			fcn->meta.min,
			r_anal_fcn_size (fcn),
			fcn->meta.max,
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

	r_cons_printf ("%-11s %4s %5s %5s %4s %11s range %-11s %s %s %s %s %s %s\n",
			"address", "size", "nbbs", "edges", "cc", "min bound", "max bound",
			"calls", "locals", "args", "xref", "frame", "name");
	r_cons_printf ("%-11s %-4s %-5s %-5s %-4s %-11s ===== %-11s %s %s %s %s %s %s\n",
			"===========", "====", "=====", "=====", "====", "===========", "===========",
			"=====", "======", "====", "====", "=====", "====");

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
		char *msg, *name = get_fcn_name (core, fcn);
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
	}
	if (quiet) {
		r_cons_newline ();
	}
	return 0;
}

static int fcn_print_json(RCore *core, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalRef *refi;
	int first = 1;
	int ebbs = 0;
	char *name = get_fcn_name (core, fcn);
	r_cons_printf ("{\"offset\":%"PFMT64d",\"name\":\"%s\",\"size\":%d",
			fcn->addr, name, r_anal_fcn_size (fcn));
	r_cons_printf (",\"realsz\":%d", r_anal_fcn_realsize (fcn));
	r_cons_printf (",\"cc\":%d", r_anal_fcn_cc (fcn));
	r_cons_printf (",\"nbbs\":%d", r_list_length (fcn->bbs));
	r_cons_printf (",\"edges\":%d", count_edges (fcn, &ebbs));
	r_cons_printf (",\"ebbs\":%d", ebbs);
	r_cons_printf (",\"calltype\":\"%s\"", fcn->cc);
	r_cons_printf (",\"type\":\"%s\"", r_anal_fcn_type_tostring (fcn->type));
	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		r_cons_printf (",\"diff\":\"%s\"",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"MATCH":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"UNMATCH":"NEW");
	}
	r_cons_printf (",\"callrefs\":[");
	int outdegree = 0;
	r_list_foreach (fcn->refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CALL) {
			outdegree++;
		}
		if (refi->type == R_ANAL_REF_TYPE_CODE ||
		    refi->type == R_ANAL_REF_TYPE_CALL) {
			r_cons_printf ("%s{\"addr\":%"PFMT64d",\"type\":\"%c\",\"at\":%"PFMT64d"}",
					first?"":",",
					refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J',
					refi->at);
			first = 0;
		}
	}

	first = 1;
	r_cons_printf ("],\"datarefs\":[");
	r_list_foreach (fcn->refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf ("%s%"PFMT64d, first?"":",", refi->addr);
			first = 0;
		}
	}

	first = 1;
	int indegree = 0;
	r_cons_printf ("],\"codexrefs\":[");
	r_list_foreach (fcn->xrefs, iter, refi) {
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
	r_list_foreach (fcn->xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf ("%s%"PFMT64d, first?"":",", refi->addr);
			first = 0;
		}
	}
	r_cons_printf ("]");

	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		r_cons_printf (",\"difftype\":\"%s\"",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"match":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new");
		if (fcn->diff->addr != -1) {
			r_cons_printf (",\"diffaddr\":%"PFMT64d, fcn->diff->addr);
		}
		if (fcn->diff->name != NULL) {
			r_cons_printf (",\"diffname\":\"%s\"", fcn->diff->name);
		}
	}
	r_cons_printf (",\"indegree\":%d", indegree);
	r_cons_printf (",\"outdegree\":%d", outdegree);
	r_cons_printf (",\"nargs\":%d",
		r_anal_var_count (core->anal, fcn, 'r', 1) +
		r_anal_var_count (core->anal, fcn, 'r', 1) +
		r_anal_var_count (core->anal, fcn, 'r', 1));
	r_cons_printf (",\"nlocals\":%d",
		r_anal_var_count (core->anal, fcn, 'r', 0) +
		r_anal_var_count (core->anal, fcn, 'r', 0) +
		r_anal_var_count (core->anal, fcn, 'r', 0));

	r_cons_printf ("}");
	free (name);
	return 0;
}

static int fcn_list_json(RCore *core, RList *fcns, bool quiet) {
	RListIter *iter;
	RAnalFunction *fcn;
	int first = 1;
	r_cons_printf ("[");
	r_list_foreach (fcns, iter, fcn) {
		if (!first) {
			r_cons_printf (",");
		}
		if (quiet) {
			r_cons_printf ("\"0x%08"PFMT64x"\"", fcn->addr);
		} else {
			fcn_print_json (core, fcn);
		}
		first = 0;
	}
	r_cons_printf ("]\n");
	return 0;
}

static int fcn_print_detail(RCore *core, RAnalFunction *fcn) {
	char *name = get_fcn_name (core, fcn);
	r_cons_printf ("f %s %d 0x%08"PFMT64x"\n", name, r_anal_fcn_size (fcn), fcn->addr);
	r_cons_printf ("af+ 0x%08"PFMT64x" %d %s %c %c\n",
			fcn->addr, r_anal_fcn_size (fcn), name,
			fcn->type == R_ANAL_FCN_TYPE_LOC?'l':
			fcn->type == R_ANAL_FCN_TYPE_SYM?'s':
			fcn->type == R_ANAL_FCN_TYPE_IMP?'i':'f',
			fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?'m':
			fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?'u':'n');
	r_cons_printf ("afC %s @ 0x%08"PFMT64x"\n", fcn->cc, fcn->addr);
	if (fcn->folded) {
		r_cons_printf ("afF @ 0x%08"PFMT64x"\n", fcn->addr);
	}
	fcn_list_bbs (fcn);
	/* show variables  and arguments */
	r_core_cmdf (core, "afvb* @ 0x%"PFMT64x"\n", fcn->addr);
	r_core_cmdf (core, "afvr* @ 0x%"PFMT64x"\n", fcn->addr);
	r_core_cmdf (core, "afvs* @ 0x%"PFMT64x"\n", fcn->addr);
	/*Saving Function stack frame*/
	r_cons_printf ("afS %"PFMT64d" @ 0x%"PFMT64x"\n", fcn->maxstack, fcn->addr);
	free (name);
	return 0;
}

static int fcn_print_legacy(RCore *core, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalRef *refi;
	int ebbs = 0;
	char *name = get_fcn_name (core, fcn);
	r_cons_printf ("#\n offset: 0x%08"PFMT64x"\n name: %s\n size: %"PFMT64d,
			fcn->addr, name, (ut64)r_anal_fcn_size (fcn));
	r_cons_printf ("\n realsz: %d", r_anal_fcn_realsize (fcn));
	r_cons_printf ("\n stackframe: %d", fcn->maxstack);
	r_cons_printf ("\n call-convention: %s", fcn->cc);
	r_cons_printf ("\n cyclomatic-complexity: %d", r_anal_fcn_cc (fcn));
	r_cons_printf ("\n bits: %d", fcn->bits);
	r_cons_printf ("\n type: %s", r_anal_fcn_type_tostring (fcn->type));
	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		r_cons_printf (" [%s]",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"MATCH":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"UNMATCH":"NEW");
	}

	r_cons_printf ("\n num-bbs: %d", r_list_length (fcn->bbs));
	r_cons_printf ("\n edges: %d", count_edges (fcn, &ebbs));
	r_cons_printf ("\n end-bbs: %d", ebbs);
	r_cons_printf ("\n call-refs: ");
	int outdegree = 0;
	r_list_foreach (fcn->refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CALL) {
			outdegree++;
		}
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			r_cons_printf ("0x%08"PFMT64x" %c ", refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J');
		}
	}
	r_cons_printf ("\n data-refs: ");
	r_list_foreach (fcn->refs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf ("0x%08"PFMT64x" ", refi->addr);
		}
	}

	int indegree = 0;
	r_cons_printf ("\n code-xrefs: ");
	r_list_foreach (fcn->xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_CODE || refi->type == R_ANAL_REF_TYPE_CALL) {
			indegree++;
			r_cons_printf ("0x%08"PFMT64x" %c ", refi->addr,
					refi->type == R_ANAL_REF_TYPE_CALL?'C':'J');
		}
	}
	r_cons_printf ("\n in-degree: %d", indegree);
	r_cons_printf ("\n out-degree: %d", outdegree);
	r_cons_printf ("\n data-xrefs: ");
	r_list_foreach (fcn->xrefs, iter, refi) {
		if (refi->type == R_ANAL_REF_TYPE_DATA) {
			r_cons_printf ("0x%08"PFMT64x" ", refi->addr);
		}
	}

	if (fcn->type == R_ANAL_FCN_TYPE_FCN || fcn->type == R_ANAL_FCN_TYPE_SYM) {
		int args_count = r_anal_var_count (core->anal, fcn, 'b', 1);
		args_count += r_anal_var_count (core->anal, fcn, 's', 1);
		args_count += r_anal_var_count (core->anal, fcn, 'r', 1);
		int var_count = r_anal_var_count (core->anal, fcn, 'b', 0);
		var_count += r_anal_var_count (core->anal, fcn, 's', 0);
		var_count += r_anal_var_count (core->anal, fcn, 'r', 0);

		r_cons_printf ("\n locals:%d\n args: %d\n", var_count, args_count);
		r_anal_var_list_show (core->anal, fcn, 'b', 0);
		r_anal_var_list_show (core->anal, fcn, 's', 0);
		r_anal_var_list_show (core->anal, fcn, 'r', 0);
		r_cons_printf (" diff: type: %s",
				fcn->diff->type == R_ANAL_DIFF_TYPE_MATCH?"match":
				fcn->diff->type == R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new");
		if (fcn->diff->addr != -1) {
			r_cons_printf (" addr: 0x%"PFMT64x, fcn->diff->addr);
		}
		if (fcn->diff->name != NULL) {
			r_cons_printf (" function: %s", fcn->diff->name);
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
	RList *fcns = core->anal->fcns;
	if (r_list_empty (fcns)) {
		return 0;
	}

	r_list_sort (fcns, &cmpfcn);
	fcnlist_gather_metadata (fcns);

	if (input) {// input points to a filter argument
		const char *name = input;
		ut64 addr;
		addr = core->offset;
		if (*input) {
			name = input + 1;
			addr = r_num_math (core->num, name);
		}

		fcns = r_list_new ();
		if (!fcns) {
			return -1;
		}
		RListIter *iter;
		RAnalFunction *fcn;
		r_list_foreach (core->anal->fcns, iter, fcn) {
			if (r_anal_fcn_in (fcn, addr) || (!strcmp (name, fcn->name))) {
				r_list_append (fcns, fcn);
			}
		}
	}

	r_list_sort (core->anal->fcns, &cmpfcn);
	switch (*rad) {
	case 's':
		r_core_anal_fcn_list_size (core);
		break;
	case 'l':
		fcn_list_verbose (core, fcns);
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
	//make sure you don't free core->anal->fcns
	if (input && core->anal->fcns != fcns) {
		// The list does not own the its members, so don't purge.
		free (fcns);
	}
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

R_API void fcn_callconv(RCore *core, RAnalFunction *fcn) {
	ut8 *tbuf, *buf;
	RListIter *tmp = NULL;
	RAnalBlock *bb = NULL;
	int i;

	if (!core || !core->anal || !fcn || core->anal->opt.bb_max_size < 1) {
		return;
	}
	int bb_size = core->anal->opt.bb_max_size;
	buf = calloc (1, bb_size);
	if (!buf) {
		return;
	}
	r_list_foreach (fcn->bbs, tmp, bb) {
		if (bb->size < 1) {
			continue;
		}
		if (bb->size > bb_size) {
			tbuf = realloc (buf, bb->size);
			if (!tbuf) {
				break;
			}
			buf = tbuf;
			bb_size = bb->size;
		}
		if (r_io_read_at (core->io, bb->addr, buf, bb->size) != bb->size) {
			eprintf ("read error\n");
			break;
		}
		for (i = 0 ; i < bb->ninstr; i++) {
			RAnalOp op = { 0 };
			int sz, pos = i? bb->op_pos[i - 1]: 0;
			if (pos >= bb->size) {
				/* out of range - internal issue */
				break;
			}
			sz = bb->size - pos;
			r_anal_op (core->anal, &op, 0, buf + pos, sz);
			op.addr = bb->addr + pos;
			fill_args (core->anal, fcn, &op);
			r_anal_op_fini (&op);
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
        int is_keva = opts & R_CORE_ANAL_KEYVALUE;
	int reflines, bytes, dwarf;
	RAnalFunction *fcni;
	RListIter *iter;
	int nodes = 0;
	int count = 0;

	if (!addr) {
		addr = core->offset;
	}
	if (r_list_empty (core->anal->fcns)) {
		eprintf ("No functions to diff\n");
		return false;
	}

	//opts |= R_CORE_ANAL_GRAPHBODY;
	reflines = r_config_get_i (core->config, "asm.lines");
	bytes = r_config_get_i (core->config, "asm.bytes");
	dwarf = r_config_get_i (core->config, "asm.dwarf");
	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.bytes", 0);
	r_config_set_i (core->config, "asm.dwarf", 0);
	if (!is_html && !is_json && !is_keva) {
		const char * gv_edge = r_config_get (core->config, "graph.gv.edge");
		const char * gv_node = r_config_get (core->config, "graph.gv.node");
		if (!gv_edge || !*gv_edge) {
			gv_edge = "arrowhead=\"vee\"";
		}
		if (!gv_node || !*gv_node) {
			gv_node = "fillcolor=gray style=filled shape=box";
		}
		r_cons_printf ("digraph code {\n"
			"\tgraph [bgcolor=white fontsize=8 fontname=\"%s\"];\n"
			"\tnode [%s];\n"
			"\tedge [%s];\n", font, gv_node, gv_edge);
	}
	if (is_json) {
		r_cons_printf ("[");
	}
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (fcni->type & (R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_FCN) &&
		    (!addr || r_anal_fcn_in (fcni, addr))) {
			if (!addr && (from != UT64_MAX && to != UT64_MAX)) {
				if (fcni->addr < from || fcni->addr > to) {
					continue;
				}
			}
			if (is_json && count++ > 0) {
				r_cons_printf (",");
			}
			nodes += core_anal_graph_nodes (core, fcni, opts);
			if (addr != 0) {
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
	r_config_set_i (core->config, "asm.lines", reflines);
	r_config_set_i (core->config, "asm.bytes", bytes);
	r_config_set_i (core->config, "asm.dwarf", dwarf);
	return true;
}

static int core_anal_followptr(RCore *core, int type, ut64 at, ut64 ptr, ut64 ref, int code, int depth) {
	ut64 dataptr;
	int wordsize;

	if (ptr == ref) {
		if (code) {
			r_anal_ref_add (core->anal, ref, at, type? type: 'c');
		} else {
			r_anal_ref_add (core->anal, ref, at, 'd');
		}
		return true;
	}
	if (depth < 1) {
		return false;
	}
	wordsize = (int)(core->anal->bits / 8);
	if ((dataptr = r_io_read_i (core->io, ptr, wordsize)) == -1) {
		return false;
	}
	return core_anal_followptr (core, type, at, dataptr, ref, code, depth - 1);
}

#define OPSZ 8
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref) {
	ut8 *buf = (ut8 *)malloc (core->blocksize);
	int ptrdepth = r_config_get_i (core->config, "anal.ptrdepth");
	int ret, i, count = 0;
	RAnalOp op = {0};
	ut64 at;
	char bckwrds, do_bckwrd_srch;
	// TODO: get current section range here or gtfo
	// ???
	// XXX must read bytes correctly
	do_bckwrd_srch = bckwrds = core->search->bckwrds;
	if (!buf) {
		return -1;
	}
	r_io_use_desc (core->io, core->file->desc);
	if (!ref) {
		eprintf ("Null reference search is not supported\n");
		free (buf);
		return -1;
	}
	r_cons_break (NULL, NULL);
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
			eprintf ("\r[0x%08"PFMT64x"-0x%08"PFMT64x"]", at, to);
			if (r_cons_is_breaked ()) {
				break;
			}
			r_cons_break (NULL, NULL);
			// TODO: this can be probably enhaced
			ret = r_io_read_at (core->io, at, buf, core->blocksize);
			if (ret != core->blocksize) {
				break;
			}
			for (i = bckwrds ? (core->blocksize - OPSZ - 1) : 0;
			     (!bckwrds && i < core->blocksize - OPSZ) ||
			     (bckwrds && i > 0);
			     bckwrds ? i-- : i++) {
				if (r_cons_is_breaked ()) {
					break;	
				}
				r_cons_break (NULL, NULL);
				r_anal_op_fini (&op);
				if (!r_anal_op (core->anal, &op, at + i,
						buf + i, core->blocksize - i)) {
					continue;
				}
				switch (op.type) {
				case R_ANAL_OP_TYPE_JMP:
				case R_ANAL_OP_TYPE_CJMP:
				case R_ANAL_OP_TYPE_CALL:
				case R_ANAL_OP_TYPE_CCALL:
					if (op.jump != -1 &&
						core_anal_followptr (core, 'C',
							at + i, op.jump, ref,
							true, 0)) {
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
						core_anal_followptr (core, 'c',
							at + i, op.ptr, ref,
							true ,1)) {
						count ++;
					}
					break;
				case R_ANAL_OP_TYPE_UCALL:
				case R_ANAL_OP_TYPE_ICALL:
				case R_ANAL_OP_TYPE_RCALL:
				case R_ANAL_OP_TYPE_IRCALL:
				case R_ANAL_OP_TYPE_UCCALL:
					if (op.ptr != -1 &&
						core_anal_followptr (core, 'C',
							at + i, op.ptr, ref,
							true ,1)) {
						count ++;
					}
					break;
				default:
					if (op.ptr != -1 &&
						core_anal_followptr (core, 'd',
							at + i, op.ptr, ref,
							false, ptrdepth)) {
						count ++;
					}
					break;
				}
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
	r_cons_break_end ();
	free (buf);
	r_anal_op_fini (&op);
	return count;
}

R_API int r_core_anal_search_xrefs(RCore *core, ut64 from, ut64 to, int rad) {
	int cfg_debug = r_config_get_i (core->config, "cfg.debug");
	bool cfg_anal_strings = r_config_get_i (core->config, "anal.strings");
	ut8 *buf;
	ut64 at;
	int count = 0;
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
	buf = (ut8 *)malloc (core->blocksize);
	if (!buf) {
		eprintf ("Error: cannot allocate a block\n");
		return -1;
	}
	if (rad == 'j') {
		r_cons_printf ("{");
	}
	r_io_use_desc (core->io, core->file->desc);
	r_cons_break (NULL, NULL);
	at = from;
	while (at < to && !r_cons_singleton()->breaked) {
		int i, ret;
		ret = r_io_read_at (core->io, at, buf, core->blocksize);
		if (ret != core->blocksize && at+ret-OPSZ < to) {
			break;
		}
		i = 0;
		while (at+i < to && i < ret-OPSZ) {
			RAnalRefType type;
			ut64 xref_from, xref_to;
			if (r_cons_singleton()->breaked) {
				break;
			}
			xref_from = at+i;
			r_anal_op_fini (&op);
			ret = r_anal_op (core->anal, &op, at+i, buf+i, core->blocksize-i);
			i += (ret > 0) ? ret : 1;
			if (ret <= 0 || at + i > to) {
				continue;
			}
			// Get reference type and target address
			type = R_ANAL_REF_TYPE_NULL;
			switch (op.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_CJMP:
				type = R_ANAL_REF_TYPE_CODE;
				xref_to = op.jump;
				break;
			case R_ANAL_OP_TYPE_CALL:
			case R_ANAL_OP_TYPE_CCALL:
				type = R_ANAL_REF_TYPE_CALL;
				xref_to = op.jump;
				break;
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IRJMP:
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UCJMP:
				type = R_ANAL_REF_TYPE_CODE;
				xref_to = op.ptr;
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_IRCALL:
			case R_ANAL_OP_TYPE_UCCALL:
				type = R_ANAL_REF_TYPE_CALL;
				xref_to = op.ptr;
				break;
			case R_ANAL_OP_TYPE_LOAD:
				type = R_ANAL_REF_TYPE_DATA;
				xref_to = op.ptr;
				break;
			default:
				if (op.ptr != -1) {
					type = R_ANAL_REF_TYPE_DATA;
					xref_to = op.ptr;
				}
				break;
			}

			// Validate the reference. If virtual addressing is enabled, we
			// allow only references to virtual addresses in order to reduce
			// the number of false positives. In debugger mode, the reference
			// must point to a mapped memory region.
			if (type == R_ANAL_REF_TYPE_NULL) {
				continue;
			}
			if (!r_core_is_valid_offset (core, xref_to)) {
				continue;
			}
			if (cfg_debug) {
				if (!r_debug_map_get (core->dbg, xref_to)) {
					continue;
				}
			} else if (core->io->va) {
				RListIter *iter = NULL;
				RIOSection *s;
				r_list_foreach (core->io->sections, iter, s) {
					if (xref_to >= s->vaddr && xref_to < s->vaddr + s->vsize) {
						if (s->vaddr != 0) {
							break;
						}
					}
				}
				if (!iter) {
					continue;
				}
			}
			if (!rad) {
				if (cfg_anal_strings) {
					int len = 0;
					char *str_string = is_string_at (core, xref_to, &len);
					if (str_string) {
						r_name_filter (str_string, -1);
						char *str_flagname = r_str_newf ("str.%s", str_string);
						(void)r_flag_set (core->flags, str_flagname, xref_to, 1);
						free (str_string);
					}
					if (len > 0) {
						r_core_cmdf (core, "Cs %d @ 0x%"PFMT64x, len, xref_to);
					}
				}
				// Add to SDB
				r_anal_xrefs_set (core->anal, type, xref_from, xref_to);
			} else if (rad == 'j') {
				// Output JSON
				if (count > 0) {
					r_cons_printf (",");
				}
				r_cons_printf ("\"0x%"PFMT64x"\":\"0x%"PFMT64x"\"", xref_to, xref_from);
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
				r_cons_printf ("%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
						cmd, xref_to, xref_from);
				if (cfg_anal_strings) {
					char *str_flagname = is_string_at (core, xref_to, &len);
					if (str_flagname) {
						ut64 str_addr = xref_to;
						r_name_filter (str_flagname, -1);
						r_cons_printf ("f str.%s=0x%"PFMT64x"\n",
							str_flagname, str_addr);
						r_cons_printf ("Cs %d @ 0x%"PFMT64x"\n",
							len, str_addr);
						free (str_flagname);
					}
				}
			}

			count++;
		}

		at += i;
	}
	r_cons_break_end ();
	free (buf);
	r_anal_op_fini (&op);

	if (rad == 'j') {
		r_cons_printf ("}\n");
	}
	return count;
}

R_API int r_core_anal_ref_list(RCore *core, int rad) {
	r_anal_xrefs_list (core->anal, rad);
	return 0;
}

static bool isValidSymbol(RBinSymbol *symbol) {
	if (symbol && symbol->type) {
		const char *type = symbol->type;
		return (!strcmp (type, "FUNC") || !strcmp (type, "METH"));
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
	int depth = r_config_get_i (core->config, "anal.depth");
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

	r_cons_break (NULL, NULL);
	/* Main */
	if ((binmain = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN)) != NULL) {
		ut64 addr = r_bin_get_vaddr (core->bin, binmain->paddr, binmain->vaddr);
		r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
	}
	if ((list = r_bin_get_entries (core->bin)) != NULL) {
		r_list_foreach (list, iter, entry) {
			ut64 addr = r_bin_get_vaddr (core->bin, entry->paddr, entry->vaddr);
			r_core_anal_fcn (core, addr, -1, R_ANAL_REF_TYPE_NULL, depth);
		}
	}
	/* Symbols (Imports are already analyzed by rabin2 on init) */
	if ((list = r_bin_get_symbols (core->bin)) != NULL) {
		r_list_foreach (list, iter, symbol) {
			if (core->cons->breaked) {
				break;
			}
			if (isValidSymbol (symbol)) {
				ut64 addr = r_bin_get_vaddr (core->bin, symbol->paddr,
					symbol->vaddr);
				r_core_anal_fcn (core, addr, -1,
					R_ANAL_REF_TYPE_NULL, depth);
			}
		}
	}
	if (anal_vars) {
		/* Set fcn type to R_ANAL_FCN_TYPE_SYM for symbols */
		r_list_foreach (core->anal->fcns, iter, fcni) {
			if (core->cons->breaked)
				break;
			if (r_config_get_i (core->config, "anal.vars")) {
				r_anal_var_delete_all (core->anal, fcni->addr, 'r');
				r_anal_var_delete_all (core->anal, fcni->addr, 'b');
				r_anal_var_delete_all (core->anal, fcni->addr, 's');
				fcn_callconv (core, fcni);
			}
			if (!strncmp (fcni->name, "sym.", 4) || !strncmp (fcni->name, "main", 4))
				fcni->type = R_ANAL_FCN_TYPE_SYM;
		}
	}
	return true;
}

R_API void r_core_anal_setup_enviroment (RCore *core) {
	char key[128], *str = NULL;
	RListIter *iter;
	RConfigNode *kv;
	r_list_foreach (core->config->nodes, iter, kv) {
		int kvlen = strlen (kv->name);
		if (kvlen >= sizeof (key)) {
			return;
		}
		strcpy (key, kv->name);
		r_str_case (key, 1);
		r_str_replace_char (key, '.', '_');
#define RANAL_PARSE_STRING_ONLY 1
#if RANAL_PARSE_STRING_ONLY
		r_anal_type_define (core->anal, key, kv->value);
#else
		if (kv->flags & CN_INT) {
			r_anal_type_define_i (core->anal, key, kv->i_value);
		} else if (kv->flags & CN_BOOL) {
			r_anal_type_define (core->anal, key, kv->i_value? "": NULL);
		} else r_anal_type_define (core->anal, key, kv->value);
#endif
	}
	r_anal_type_header (core->anal, str);
	free (str);
}

R_API int r_core_anal_data (RCore *core, ut64 addr, int count, int depth) {
	RAnalData *d;
	ut64 dstaddr = 0LL;
	ut8 *buf = core->block;
	int len = core->blocksize;
	int word = core->assembler->bits /8;
	char *str;
	int i, j;

	count = R_MIN (count, len);
	buf = malloc (len + 1);
	if (!buf) {
		return false;
	}
	memset (buf, 0xff, len);
	r_io_read_at (core->io, addr, buf, len);
	buf[len-1] = 0;

	for (i = j = 0; j < count; j++ ) {
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
		d = r_anal_data (core->anal, addr + i, buf + i, len - i);
		str = r_anal_data_to_string (d);
		r_cons_println (str);

		if (d) {
			switch (d->type) {
			case R_ANAL_DATA_TYPE_POINTER:
				r_cons_printf ("`- ");
				dstaddr = r_mem_get_num (buf + i, word);
				if (depth > 0) {
					r_core_anal_data (core, dstaddr, 1, depth - 1);
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
	RListIter *iter;
	RCoreAnalStats *as = NULL;
	int piece, as_size, blocks;

	if (from == to) {
		return NULL;
	}
	as = R_NEW0 (RCoreAnalStats);
	if (!as) {
		return NULL;
	}
	if (step < 1) {
		step = 1;
	}
	blocks = (to-from)/step;
	as_size = (1+blocks) * sizeof (RCoreAnalStatsItem);
	as->block = malloc (as_size);
	if (!as->block) {
		free (as);
		return NULL;
	}
	memset (as->block, 0, as_size);
	// iter all flags
	r_list_foreach (core->flags->flags, iter, f) {
		//if (f->offset+f->size < from) continue;
		if (f->offset< from) {
			continue;
		}
		if (f->offset > to) {
			continue;
		}
		piece = (f->offset-from)/step;
		as->block[piece].flags++;
	}

	r_list_foreach (core->anal->fcns, iter, F) {
		if (F->addr < from) {
			continue;
		}
		if (F->addr > to) {
			continue;
		}
		piece = (F->addr-from)/step;
		as->block[piece].functions++;
	}
	// iter all comments
	// iter all symbols
	// iter all imports
	// iter all functions
	// iter all strings
	return as;
}

R_API void r_core_anal_stats_free (RCoreAnalStats *s) {
	free (s);
}

R_API RList* r_core_anal_cycles (RCore *core, int ccl) {
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
	while (cf && !core->cons->breaked) {
		if ((op = r_core_anal_op (core, addr)) && (op->cycles) && (ccl > 0)) {
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
	if (core->cons->breaked) {
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
	return hooks;
}

R_API void r_core_anal_undefine (RCore *core, ut64 off) {
	RAnalFunction *f;
	r_anal_fcn_del_locs (core->anal, off);
	f = r_anal_get_fcn_in (core->anal, off, 0);
	if (f) {
		if (!strncmp (f->name, "fcn.", 4)) {
			r_flag_unset_name (core->flags, f->name);
		}
		r_meta_del (core->anal, R_META_TYPE_ANY, off, r_anal_fcn_size (f), "");
	}
	r_anal_fcn_del (core->anal, off);
}

/* Join function at addr2 into function at addr */
// addr use to be core->offset
R_API void r_core_anal_fcn_merge (RCore *core, ut64 addr, ut64 addr2) {
	RListIter *iter;
	ut64 min = 0;
	ut64 max = 0;
	int first = 1;
	RAnalBlock *bb;
	RAnalFunction *f1 = r_anal_get_fcn_at (core->anal, addr, 0);
	RAnalFunction *f2 = r_anal_get_fcn_at (core->anal, addr2, 0);
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
	r_anal_fcn_set_size (f1, max - min);
	// resize
	f2->bbs = NULL;
	r_list_delete_data (core->anal->fcns, f2);
}

R_API void r_core_anal_auto_merge (RCore *core, ut64 addr) {
	/* TODO: implement me */
}


static int myvalid(ut64 addr) {
	if (addr < 0x100) {
		return 0;
	}
	if (addr == UT32_MAX || addr == UT64_MAX) {
		return 0;
	}
	return 1;
}

static int esilbreak_mem_write(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	/* do nothing */
	return 1;
}

/* TODO: move into RCore? */
static ut64 esilbreak_last_read = UT64_MAX;
#if 0
static ut32 esilbreak_last_data = UT32_MAX;
#endif

static ut64 ntarget = UT64_MAX;

static int esilbreak_mem_read(RAnalEsil *esil, ut64 addr, ut8 *buf, int len) {
	ut8 str[128];
	char cmd[128];

	if (ntarget == UT64_MAX || ntarget == addr) {
		esilbreak_last_read = addr;

		if (myvalid (addr) && r_io_is_valid_offset (mycore->io, addr, 0)) {
			ut8 buf[4];
			ut64 refptr;
			if (r_io_read_at (mycore->io, addr, (ut8*)buf, sizeof (buf)) != sizeof (buf)) {
				/* invalid read */
				refptr = UT32_MAX;
			} else {
				refptr = r_read_ble32 (buf, esil->anal->big_endian);
			}

			if (myvalid (refptr) && r_io_is_valid_offset (mycore->io, (ut64)refptr, 0)) {
				snprintf (cmd, sizeof (cmd), "axd 0x%"PFMT64x" 0x%"PFMT64x,
						(ut64)refptr, esil->address);
				str[0] = 0;
				if (r_io_read_at (mycore->io, refptr, str, sizeof (str)) < 1) {
					eprintf ("Invalid read\n");
					str[0] = 0;
				}
				str[sizeof(str)-1] = 0;
				add_string_ref (mycore, refptr);
			} else {
				snprintf (cmd, sizeof (cmd), "axd 0x%"PFMT64x" 0x%"PFMT64x,
						addr, esil->address); //, addr);
			}
			if (*cmd) {
				r_core_cmd0 (mycore, cmd);
			}
		}
	}
	return 0; // fallback
}

static bool esil_anal_stop = false;
static void cccb(void*u) {
	esil_anal_stop = true;
	eprintf ("^C\n");
}

static void add_string_ref (RCore *core, ut64 xref_to) {
	int len = 0;
	char *str_flagname;
	if (xref_to == UT64_MAX || xref_to == 0LL) {
		return;
	}
	str_flagname = is_string_at (core, xref_to, &len);
	if (str_flagname) {
		r_name_filter (str_flagname, -1);
		char *flagname = sdb_fmt (0, "str.%s", str_flagname);
		r_flag_space_push (core->flags, "strings");
		r_flag_set (core->flags, flagname, xref_to, len);
		r_flag_space_pop (core->flags);
		r_meta_add (core->anal, 's', xref_to, xref_to + len, str_flagname);
		//r_cons_printf ("Cs %d @ 0x%"PFMT64x"\n", len, xref_to);
		free (str_flagname);
	}
}


R_API void r_core_anal_esil(RCore *core, const char *str, const char *target) {
	bool cfg_anal_strings = r_config_get_i (core->config, "anal.strings");
	RAnalEsil *ESIL = core->anal->esil;
	const char *pcname;
	RAsmOp asmop;
	RAnalOp op = {0};
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
		eprintf ("  aae $SS @ $S            - analyze the whole section\n");
		eprintf ("  aae $SS str.Hello @ $S  - find references for str.Hellow\n");
		return;
	}
	if (target) {
		ntarget = r_num_math (core->num, target);
	} else {
		ntarget = UT64_MAX;
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
	ESIL->cb.hook_mem_read = &esilbreak_mem_read;
	if (!core->io->cached) {
		ESIL->cb.hook_mem_write = &esilbreak_mem_write;
	}
	//eprintf ("Analyzing ESIL refs from 0x%"PFMT64x" - 0x%"PFMT64x"\n", addr, end);
	// TODO: backup/restore register state before/after analysis
	pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	if (!pcname || !*pcname) {
		eprintf ("Cannot find program counter register in the current profile.\n");
		return;
	}
	esil_anal_stop = false;
	r_cons_break (cccb, core);
	//r_cons_break (NULL, NULL);
	for (i = 0; i < iend; i++) {
		if (esil_anal_stop || r_cons_is_breaked ()) {
			break;
		}
		r_cons_break (cccb, core);
		cur = addr + i;
		free (op.mnemonic);
		if (!r_anal_op (core->anal, &op, cur, buf + i, iend - i)) {
			i += minopsize - 1;
		}
		r_asm_set_pc (core->assembler, cur);
		//we need to check again i because buf+i may goes beyond its boundaries
		//because of i+= minopsize - 1
		if (i > iend) {
			break;
		}
		if (r_asm_disassemble (core->assembler, &asmop, buf + i, iend - i) > 0) {
			op.mnemonic = strdup (asmop.buf_asm);
		}
		if (op.size < 1) {
			i += minopsize - 1;
			continue;
		}
		if (1) {
			const char *esilstr = R_STRBUF_SAFEGET (&op.esil);
			r_anal_esil_set_pc (ESIL, cur);
			i += op.size - 1;
			if (!esilstr || !*esilstr) {
				continue;
			}

			(void)r_anal_esil_parse (ESIL, esilstr);
			// looks like ^C is handled by esil_parse !!!!
			r_cons_break (cccb, core);
			//r_anal_esil_dumpstack (ESIL);
			r_anal_esil_stack_free (ESIL);

			switch (op.type) {
			case R_ANAL_OP_TYPE_LEA:
				if ((target && op.ptr == ntarget) || !target) {
					if (strcmp (core->anal->cpu, "arm")) {
						if (cfg_anal_strings) {
							r_anal_ref_add (core->anal, op.ptr, cur, 'd');
							if ((target && op.ptr == ntarget) || !target) {
								add_string_ref (core, op.ptr);
							}
						}
					}
				}
				break;
			case R_ANAL_OP_TYPE_ADD:
				/* TODO: test if this is valid for other archs too */
				if (core->anal->bits == 64 && !strcmp (core->anal->cpu, "arm")) {
					ut64 dst = ESIL->cur;
					if ((target && dst == ntarget) || !target) {
						r_anal_ref_add (core->anal, dst, cur, 'd');
					}
				} else if ((core->anal->bits == 32 && !strcmp (core->anal->cpu, "mips"))) {
					ut64 dst = ESIL->cur;
					if (!op.src[0] || !op.src[0]->reg || !op.src[0]->reg->name)
						break;
					if (!strcmp (op.src[0]->reg->name, "sp"))
						break;
					if (!strcmp (op.src[0]->reg->name, "zero"))
						break;

					if ((target && dst == ntarget) || !target) {
						if (dst > 0xffff && op.src[1] && (dst & 0xffff) == (op.src[1]->imm & 0xffff) &&
								myvalid (dst) && r_io_is_valid_offset (mycore->io, dst, 0)) {
							RFlagItem *f;
							char *str;

							r_anal_ref_add (core->anal, dst, cur, 'd');
							if (cfg_anal_strings) {
								add_string_ref (core, dst);
							}

							if ((f = r_flag_get_i2 (core->flags, dst))) {
								r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, f->name);
							} else if ((str = is_string_at (mycore, dst, NULL))) {
								char *str2 = sdb_fmt (0, "esilref: '%s'", str);
								r_meta_set_string (core->anal, R_META_TYPE_COMMENT, cur, str2);
								free (str);
							}
						}
					}
				}
				break;
			case R_ANAL_OP_TYPE_LOAD:
				{
					ut64 dst = esilbreak_last_read;
					if ((target && dst == ntarget) || !target) {
						if (myvalid (dst) && r_io_is_valid_offset (mycore->io, dst, 0)) {
							r_anal_ref_add (core->anal, dst, cur, 'd');
							if (cfg_anal_strings) {
								add_string_ref (core, dst);
							}
						}
					}
				}
				break;
			case R_ANAL_OP_TYPE_CALL:
				{
					ut64 dst = op.jump;
					if ((target && dst == ntarget) || !target) {
						if (myvalid (dst) && r_io_is_valid_offset (mycore->io, dst, 0)) {
							r_anal_ref_add (core->anal, dst, cur, 'C');
						}
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
					if ((target && dst == ntarget) || !target) {
						if (myvalid (dst) && r_io_is_valid_offset (mycore->io, dst, 0)) {
							RAnalRefType ref =
								(op.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL
								? R_ANAL_REF_TYPE_CALL
								: R_ANAL_REF_TYPE_CODE;
							r_anal_ref_add (core->anal, dst, cur, ref);
						}
					}
				}
				break;
			}
		}
	}
	free (buf);
	free (op.mnemonic);
	r_cons_break_end ();
}
