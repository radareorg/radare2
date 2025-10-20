/* radare2 - LGPL - Copyright 2009-2024 - nibble, pancake, maijin */

#include <r_asm.h>
#include <config.h>

R_LIB_VERSION (r_parse);

R_API RParse *r_parse_new(void) {
	RParse *p = R_NEW0 (RParse);
	p->minval = 0x100;
	return p;
}

R_API void r_parse_free(RParse *p) {
	free (p);
}

// TODO .make it internal?
R_API char *r_asm_parse_pseudo(RAsm *a, const char *data) {
	R_RETURN_VAL_IF_FAIL (a && data, false);
	RAsmParsePseudo parse = R_UNWRAP4 (a, cur, plugin, parse);
	return parse? parse (a->cur, data) : NULL;
}

// TODO: make it internal?
R_API char *r_asm_parse_immtrim(RAsm *a, const char *_opstr) {
	R_RETURN_VAL_IF_FAIL (a && _opstr, NULL);
	if (R_STR_ISEMPTY (_opstr)) {
		return NULL;
	}
	char *opstr = strdup (_opstr);
	char *n = strstr (opstr, "0x");
	if (n) {
		char *p = n + 2;
		while (IS_HEXCHAR (*p)) {
			p++;
		}
		memmove (n, p, strlen (p) + 1);
	}
	if (strstr (opstr, " - ]")) {
		opstr = r_str_replace (opstr, " - ]", "]", 1);
	}
	if (strstr (opstr, " + ]")) {
		opstr = r_str_replace (opstr, " + ]", "]", 1);
	}
	if (strstr (opstr, ", ]")) {
		opstr = r_str_replace (opstr, ", ]", "]", 1);
	}
	if (strstr (opstr, " - ")) {
		opstr = r_str_replace (opstr, " - ", "-", 1);
	}
	if (strstr (opstr, " + ")) {
		opstr = r_str_replace (opstr, " + ", "+", 1);
	}
	r_str_trim (opstr);
	char *last = opstr + strlen (opstr) - 1;
	if (*last == ',') {
		*last = 0;
		r_str_trim (opstr);
	}
	return opstr;
}

// TODO : make them internal?
R_API char *r_asm_parse_subvar(RAsm *a, RAnalFunction * R_NULLABLE f, ut64 addr, int oplen, const char *data) {
	R_RETURN_VAL_IF_FAIL (a, false);
	RAsmPlugin *pcur = R_UNWRAP3 (a, cur, plugin);
	if (pcur && pcur->subvar && data) {
		return pcur->subvar (a->cur, f, addr, oplen, data);
	}
	return NULL;
}

R_API char *r_asm_parse_patch(RAsm *a, RAnalOp *aop, const char *op) {
	R_RETURN_VAL_IF_FAIL (a, false);
	RAsmPlugin *pcur = R_UNWRAP3 (a, cur, plugin);
	if (pcur && pcur->patch) {
		return pcur->patch (a->cur, aop, op);
	}
	return NULL;
}

// TODO: R2_600 - finish reimplementing libr/core/disasm.c: ds_sub_jumps
R_API char *r_asm_parse_subjmp(RAsm *a, RAnalOp *aop, const char *op) {
	R_RETURN_VAL_IF_FAIL (a, false);
	const char* arch = R_UNWRAP3 (a, config, arch);
	const bool x86 = arch && r_str_startswith (arch, "x86");
	const char *name = NULL;
	const char *kw = "";
	ut64 addr = aop->jump;
	int optype = aop->type & R_ANAL_OP_TYPE_MASK;
	switch (optype) {
	case R_ANAL_OP_TYPE_LEA:
		if (x86) {
			// let the pseudo plugin trim the '[]'
			return NULL;
		}
		// for ARM adrp, section is better than adrp, segment
		break;
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_MJMP:
		break;
	case R_ANAL_OP_TYPE_PUSH:
		addr = aop->val;
		if (addr < 10) {
			// ignore push 0
			return NULL;
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UCALL:
		break;
	default:
		return NULL;
	}
#if 0
	RFlag *f = ds->core->flags;
	RAnal *anal = ds->core->anal;
	RBinReloc *rel = NULL;
	RBinObject *bo = r_bin_cur_object (ds->core->bin);
	if (bo && !bo->is_reloc_patched) {
		rel = r_core_getreloc (ds->core, ds->analop.addr, ds->analop.size);
	}
	if (!rel) {
		rel = r_core_getreloc (ds->core, addr, ds->analop.size);
		if (!rel) {
			// some jmp 0 are actually relocs, so we can just ignore it
			if (!addr || addr == UT64_MAX) {
				rel = r_core_getreloc (ds->core, ds->analop.ptr, ds->analop.size);
				if (rel) {
					addr = ds->analop.ptr;
				}
			}
		}
	}
	if (addr == UT64_MAX) {
		if (rel) {
			addr = 0;
		} else {
			addr = ds->analop.ptr;
		}
	}
	RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
	if (fcn) {
		name = fcn->name;
	} else {
		if (rel) {
			if (rel && rel->import && rel->import->name) {
				name = r_bin_name_tostring (rel->import->name);
			} else if (rel && rel->symbol && rel->symbol->name) {
				name = r_bin_name_tostring (rel->symbol->name);
			}
			if (addr) { //  && *name == '.') {
				RFlagItem *flag = r_core_flag_get_by_spaces (f, false, addr);
				if (flag) {
					if (!r_str_startswith (flag->name, "section")) {
						name = flag->name;
						if (f->realnames && flag->realname) {
							name = flag->realname;
						}
					}
				}
			}
		} else {
			RFlagItem *flag = r_core_flag_get_by_spaces (f, false, addr);
			if (flag) {
				// R2R db/anal/jmptbl
				// adrp x0, segment.DATA //instead-of// adrp x0, section.20.__DATA.__objc_const
				if (!r_str_startswith (flag->name, "section")) {
					name = flag->name;
					if (f->realnames && flag->realname) {
						name = flag->realname;
					}
				}
			}
		}
	}
	if (name) {
		char *nptr;
		ut64 numval;
		char *hstr = strdup (str);
		char *ptr = hstr;
		const int bits = ds->core->rasm->config->bits;
		const int seggrn = ds->core->rasm->config->seggrn;
		while ((nptr = _find_next_number (ptr))) {
			ptr = nptr;
			char* colon = strchr (ptr, ':');
			if (x86 && bits == 16 && colon) {
				*colon = '\0';
				ut64 seg = r_num_get (NULL, ptr);
				ut64 off = r_num_get (NULL, colon + 1);
				*colon = ':';
				numval = (seg << seggrn) + off;
			} else {
				numval = r_num_get (NULL, ptr);
			}
			if (numval == addr) {
				while ((*nptr && !IS_SEPARATOR (*nptr) && *nptr != 0x1b) || (x86 && bits == 16 && colon && *nptr == ':')) {
					nptr++;
				}
				char *kwname = r_str_newf ("%s%s", kw, name);
				if (kwname) {
					char* numstr = r_str_ndup (ptr, nptr - ptr);
					if (numstr) {
						hstr = r_str_replace (hstr, numstr, kwname, 0);
						free (numstr);
					}
					free (kwname);
				}
				break;
			}
		}
		return hstr;
	}
#endif
	return NULL;
}
