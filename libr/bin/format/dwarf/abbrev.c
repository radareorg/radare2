/* radare - LGPL - Copyright 2012-2025 - pancake, Fedor Sakharov */

#include "dwarf.h"

static bool init_abbrev_decl(RBinDwarfAbbrevDecl *ad) {
	ad->defs = RVecDwarfAttrDef_new ();
	if (!ad->defs) {
		return false;
	}
	return true;
}

R_API void r_bin_dwarf_free_debug_abbrev(RVecDwarfAbbrevDecl *da) {
	RVecDwarfAbbrevDecl_free (da);
}

static RVecDwarfAbbrevDecl *parse_abbrev_raw(const ut8 *obuf, size_t len) {
	const ut8 *buf = obuf, *buf_end = obuf + len;

	// XXX - Set a suitable value here.
	if (!obuf || len < 3) {
		return NULL;
	}

	RVecDwarfAbbrevDecl *da = RVecDwarfAbbrevDecl_new ();

	while (buf && (buf + 1 < buf_end)) {
		size_t offset = buf - obuf;
		ut64 tmp;
		buf = r_uleb128 (buf, (size_t) (buf_end - buf), &tmp, NULL);
		if (!buf || !tmp || buf >= buf_end) {
			continue;
		}

		RBinDwarfAbbrevDecl decl = { 0 };
		if (!init_abbrev_decl (&decl)) {
			RVecDwarfAbbrevDecl_free (da);
			return NULL;
		}

		decl.code = tmp;
		buf = r_uleb128 (buf, (size_t) (buf_end - buf), &tmp, NULL);
		decl.tag = tmp;

		decl.offset = offset;
		if (buf >= buf_end) {
			RVecDwarfAttrDef_free (decl.defs);
			continue;
		}
		decl.has_children = READ8 (buf);
		ut64 attr_code, attr_form;
		do {
			RBinDwarfAttrDef def = { 0 };
			st64 special;

			buf = r_uleb128 (buf, (size_t) (buf_end - buf), &attr_code, NULL);
			if (buf >= buf_end) {
				RVecDwarfAttrDef_free (decl.defs);
				goto out_while;
			}
			buf = r_uleb128 (buf, (size_t) (buf_end - buf), &attr_form, NULL);
			if (buf >= buf_end) {
				RVecDwarfAttrDef_free (decl.defs);
				goto out_while;
			}
			// https://www.dwarfstd.org/doc/DWARF5.pdf#page=225
			if (attr_form == DW_FORM_implicit_const) {
				buf = r_leb128 (buf, (size_t) (buf_end - buf), &special);
				def.special = special;
			}
			def.attr_name = attr_code;
			def.attr_form = attr_form;

			RVecDwarfAttrDef_push_back (decl.defs, &def);
		} while (attr_code && attr_form);

		RVecDwarfAbbrevDecl_push_back (da, &decl);
	}
out_while:
	return da;
}

R_API RVecDwarfAbbrevDecl *r_bin_dwarf_parse_abbrev(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->rbin, NULL);
	RBinSection *section = dwarf_get_section (bf, DWARF_SN_ABBREV);
	if (!bf || !section) {
		return NULL;
	}
	const ut8 *buf = dwarf_get_section_bytes (bf, section);
	if (!buf) {
		return NULL;
	}
	return parse_abbrev_raw (buf, section->bytes.len);
}
