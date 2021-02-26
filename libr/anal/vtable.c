/* radare - LGPL - Copyright 2009-2020 - pancake, maijin, thestr4ng3r */

#include "r_util.h"
#include "r_anal.h"

#define VTABLE_BUFF_SIZE 10

#define VTABLE_READ_ADDR_FUNC(fname, read_fname, sz) \
	static bool fname(RAnal *anal, ut64 addr, ut64 *buf) {\
		ut8 tmp[sz];\
		if (!anal->iob.read_at (anal->iob.io, addr, tmp, sz)) {\
			return false;\
		}\
		*buf = read_fname (tmp);\
		return true;\
	}
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le8, r_read_le8, 1)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le16, r_read_le16, 2)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le32, r_read_le32, 4)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_le64, r_read_le64, 8)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be8, r_read_be8, 1)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be16, r_read_be16, 2)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be32, r_read_be32, 4)
VTABLE_READ_ADDR_FUNC (vtable_read_addr_be64, r_read_be64, 8)

R_API void r_anal_vtable_info_free(RVTableInfo *vtable) {
	if (!vtable) {
		return;
	}
	r_vector_clear (&vtable->methods);
	free (vtable);
}

R_API ut64 r_anal_vtable_info_get_size(RVTableContext *context, RVTableInfo *vtable) {
	return (ut64)vtable->methods.len * context->word_size;
}

R_API bool r_anal_vtable_begin(RAnal *anal, RVTableContext *context) {
	context->anal = anal;
	context->abi = anal->cpp_abi;
	context->word_size = (ut8) (anal->bits / 8);
	const bool is_arm = anal->cur->arch && r_str_startswith (anal->cur->arch, "arm");
	if (is_arm && context->word_size < 4) {
		context->word_size = 4;
	}
	switch (context->word_size) {
	case 1:
		context->read_addr = anal->big_endian ? vtable_read_addr_be8 : vtable_read_addr_le8;
		break;
	case 2:
		context->read_addr = anal->big_endian ? vtable_read_addr_be16 : vtable_read_addr_le16;
		break;
	case 4:
		context->read_addr = anal->big_endian ? vtable_read_addr_be32 : vtable_read_addr_le32;
		break;
	case 8:
		context->read_addr = anal->big_endian ? vtable_read_addr_be64 : vtable_read_addr_le64;
		break;
	default:
		return false;
	}
	return true;
}

static bool vtable_addr_in_text_section(RVTableContext *context, ut64 curAddress) {
	//section of the curAddress
	RBinSection *value = context->anal->binb.get_vsect_at (context->anal->binb.bin, curAddress);
	//If the pointed value lies in .text section
	return value && strstr (value->name, "text") && (value->perm & 1) != 0;
}

static bool vtable_is_value_in_text_section(RVTableContext *context, ut64 curAddress, ut64 *value) {
	//value at the current address
	ut64 curAddressValue;
	if (!context->read_addr (context->anal, curAddress, &curAddressValue)) {
		return false;
	}
	//if the value is in text section
	bool ret = vtable_addr_in_text_section (context, curAddressValue);
	if (value) {
		*value = curAddressValue;
	}
	return ret;
}

static bool vtable_section_can_contain_vtables(RBinSection *section) {
	if (section->is_segment) {
		return false;
	}
	return !strcmp (section->name, ".rodata") ||
		!strcmp (section->name, ".rdata") ||
		!strcmp (section->name, ".data.rel.ro") ||
		!strcmp (section->name, ".data.rel.ro.local") ||
		r_str_endswith (section->name, "__const");
}

static bool section_can_contain_rtti(RBinSection *section) {
	if (!section) {
		return false;
	}
	if (section->is_data) {
		return true;
	}
	return !strcmp (section->name, ".data.rel.ro") ||
		!strcmp (section->name, ".data.rel.ro.local") ||
		r_str_endswith (section->name, "__const");
}

static bool vtable_is_addr_vtable_start_itanium(RVTableContext *context, RBinSection *section, ut64 curAddress) {
	ut64 value;
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section (context, curAddress, NULL)) { // Vtable beginning referenced from the code
		return false;
	}
	if (!context->read_addr (context->anal, curAddress - context->word_size, &value)) { // get the RTTI pointer
		return false;
	}
	RBinSection *rtti_section = context->anal->binb.get_vsect_at (context->anal->binb.bin, value);
	if (value && !section_can_contain_rtti (rtti_section)) { // RTTI ptr must point somewhere in the data section
		return false;
	}
	if (!context->read_addr (context->anal, curAddress - 2 * context->word_size, &value)) { // Offset to top
		return false;
	}
	if ((st32)value > 0) { // Offset to top has to be negative
		return false;
	}
	return true;
}

static bool vtable_is_addr_vtable_start_msvc(RVTableContext *context, ut64 curAddress) {
	RAnalRef *xref;
	RListIter *xrefIter;

	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (curAddress && !vtable_is_value_in_text_section (context, curAddress, NULL)) {
		return false;
	}
	// total xref's to curAddress
	RList *xrefs = r_anal_xrefs_get (context->anal, curAddress);
	if (r_list_empty (xrefs)) {
		r_list_free (xrefs);
		return false;
	}
	r_list_foreach (xrefs, xrefIter, xref) {
		// section in which currenct xref lies
		if (vtable_addr_in_text_section (context, xref->addr)) {
			ut8 buf[VTABLE_BUFF_SIZE];
			context->anal->iob.read_at (context->anal->iob.io, xref->addr, buf, sizeof(buf));

			RAnalOp analop = { 0 };
			r_anal_op (context->anal, &analop, xref->addr, buf, sizeof(buf), R_ANAL_OP_MASK_BASIC);

			if (analop.type == R_ANAL_OP_TYPE_MOV
				|| analop.type == R_ANAL_OP_TYPE_LEA) {
				r_list_free (xrefs);
				r_anal_op_fini (&analop);
				return true;
			}

			r_anal_op_fini (&analop);
		}
	}
	r_list_free (xrefs);
	return false;
}

static bool vtable_is_addr_vtable_start(RVTableContext *context, RBinSection *section, ut64 curAddress) {
	if (context->abi == R_ANAL_CPP_ABI_MSVC) {
		return vtable_is_addr_vtable_start_msvc (context, curAddress);
	}
	if (context->abi == R_ANAL_CPP_ABI_ITANIUM) {
		return vtable_is_addr_vtable_start_itanium (context, section, curAddress);
	}
	r_return_val_if_reached (false);
	return false;
}

R_API RVTableInfo *r_anal_vtable_parse_at(RVTableContext *context, ut64 addr) {
	ut64 offset_to_top;
	if (!context->read_addr (context->anal, addr - 2 * context->word_size, &offset_to_top)) {
		return NULL;
	}

	RVTableInfo *vtable = calloc (1, sizeof (RVTableInfo));
	if (!vtable) {
		return NULL;
	}

	vtable->saddr = addr;

	r_vector_init (&vtable->methods, sizeof (RVTableMethodInfo), NULL, NULL);

	RVTableMethodInfo meth;
	while (vtable_is_value_in_text_section (context, addr, &meth.addr)) {
		meth.vtable_offset = addr - vtable->saddr;
		if (!r_vector_push (&vtable->methods, &meth)) {
			break;
		}

		addr += context->word_size;

		// a ref means the vtable has ended
		RList *ll = r_anal_xrefs_get (context->anal, addr);
		if (!r_list_empty (ll)) {
			r_list_free (ll);
			break;
		}
		r_list_free (ll);
	}
	return vtable;
}

R_API RList *r_anal_vtable_search(RVTableContext *context) {
	RAnal *anal = context->anal;
	if (!anal) {
		return NULL;
	}

	RList *vtables = r_list_newf ((RListFree)r_anal_vtable_info_free);
	if (!vtables) {
		return NULL;
	}

	RList *sections = anal->binb.get_sections (anal->binb.bin);
	if (!sections) {
		r_list_free (vtables);
		return NULL;
	}

	r_cons_break_push (NULL, NULL);

	RListIter *iter;
	RBinSection *section;
	r_list_foreach (sections, iter, section) {
		if (r_cons_is_breaked ()) {
			break;
		}

		if (!vtable_section_can_contain_vtables (section)) {
			continue;
		}

		ut64 startAddress = section->vaddr;
		ut64 endAddress = startAddress + (section->vsize) - context->word_size;
		ut64 ss = endAddress - startAddress;
		if (ss > ST32_MAX) {
			break;
		}
		while (startAddress <= endAddress) {
			if (r_cons_is_breaked ()) {
				break;
			}
			if (!anal->iob.is_valid_offset (anal->iob.io, startAddress, 0)) {
				break;
			}

			if (vtable_is_addr_vtable_start (context, section, startAddress)) {
				RVTableInfo *vtable = r_anal_vtable_parse_at (context, startAddress);
				if (vtable) {
					r_list_append (vtables, vtable);
					ut64 size = r_anal_vtable_info_get_size (context, vtable);
					if (size > 0) {
						startAddress += size;
						continue;
					}
				}
			}
			startAddress += context->word_size;
		}
	}

	r_cons_break_pop ();

	if (r_list_empty (vtables)) {
		// stripped binary?
		r_list_free (vtables);
		return NULL;
	}
	return vtables;
}

R_API void r_anal_list_vtables(RAnal *anal, int rad) {
	RVTableContext context;
	r_anal_vtable_begin (anal, &context);

	const char *noMethodName = "No Name found";
	RVTableMethodInfo *curMethod;
	RListIter *vtableIter;
	RVTableInfo *table;

	RList *vtables = r_anal_vtable_search (&context);

	if (rad == 'j') {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
		r_list_foreach (vtables, vtableIter, table) {
			pj_o (pj);
			pj_kN (pj, "offset", table->saddr);
			pj_ka (pj, "methods");
			r_vector_foreach (&table->methods, curMethod) {
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				pj_o (pj);
				pj_kN (pj, "offset", curMethod->addr);
				pj_ks (pj, "name", r_str_get_fail (name, noMethodName));
				pj_end (pj);
			}
			pj_end (pj);
			pj_end (pj);
		}
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	} else if (rad == '*') {
		r_list_foreach (vtables, vtableIter, table) {
			r_cons_printf ("f vtable.0x%08"PFMT64x" %"PFMT64d" @ 0x%08"PFMT64x"\n",
						   table->saddr,
						   r_anal_vtable_info_get_size (&context, table),
						   table->saddr);
			r_vector_foreach (&table->methods, curMethod) {
				r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", context.word_size, table->saddr + curMethod->vtable_offset);
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				if (name) {
					r_cons_printf ("f %s=0x%08"PFMT64x"\n", name, curMethod->addr);
				} else {
					r_cons_printf ("f method.virtual.0x%08"PFMT64x"=0x%08"PFMT64x"\n", curMethod->addr, curMethod->addr);
				}
			}
		}
	} else {
		r_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			r_cons_printf ("\nVtable Found at 0x%08"PFMT64x"\n", vtableStartAddress);
			r_vector_foreach (&table->methods, curMethod) {
				RAnalFunction *fcn = r_anal_get_fcn_in (anal, curMethod->addr, 0);
				const char *const name = fcn ? fcn->name : NULL;
				r_cons_printf ("0x%08"PFMT64x" : %s\n", vtableStartAddress, r_str_get_fail (name, noMethodName));
				vtableStartAddress += context.word_size;
			}
			r_cons_newline ();
		}
	}
	r_list_free (vtables);
}
