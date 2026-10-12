/* radare - LGPL - Copyright 2021-2026 - pancake */

#include <r_anal.h>

// R2R db/anal/globals
#define GLOBAL_FLAGSPACE "globals"

static void global_clear_inference(RAnal *anal, ut64 addr) {
	sdb_unsetf (anal->sdb, 0, "global.inferred.0x%" PFMT64x, addr);
	sdb_unsetf (anal->sdb, 0, "global.semantic.0x%" PFMT64x, addr);
	sdb_unsetf (anal->sdb, 0, "global.layout.0x%" PFMT64x, addr);
}

static ut64 global_type_size(RAnal *anal, const char *type_name) {
	char *base = strdup (type_name);
	if (!base) {
		return 0;
	}
	char *array = strchr (base, '[');
	if (array) {
		*array = 0;
	}
	r_str_trim (base);
	while (r_str_endswith (base, " const") || r_str_endswith (base, " volatile")) {
		*strrchr (base, ' ') = 0;
	}
	ut64 size = r_anal_type_bitsize (anal, base) / 8;
	free (base);
	const char *extent = strchr (type_name, '[');
	while (size && extent && !strstr (type_name, "(*")) {
		char *end;
		ut64 count = strtoull (extent + 1, &end, 10);
		if (end == extent + 1 || *end != ']' || !count || r_mul_overflow (size, count, &size)) {
			return 0;
		}
		extent = strchr (end + 1, '[');
	}
	return size;
}

R_API RFlagItem *r_anal_global_get(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal && anal->flb.f, NULL);
	return r_flag_get_by_spaces (anal->flb.f, false, addr, GLOBAL_FLAGSPACE, NULL);
}

R_API bool r_anal_global_add(RAnal *anal, ut64 addr, const char *type_name, const char *name) {
	R_RETURN_VAL_IF_FAIL (anal && anal->flb.f && R_STR_ISNOTEMPTY (name), false);
	RFlag *flags = anal->flb.f;
	ut64 size = type_name? global_type_size (anal, type_name): 0;
	if (type_name && (!size || size > UT32_MAX)) {
		R_LOG_ERROR ("Unknown or oversized global type: %s", type_name);
		return false;
	}
	char *type = type_name? strdup (type_name): NULL;
	if (type_name && !type) {
		return false;
	}
	RFlagItem *fi = r_flag_set_inspace (flags, GLOBAL_FLAGSPACE, name, addr, size);
	if (!fi) {
		free (type);
		return false;
	}
	fi->space = r_flag_space_get (flags, GLOBAL_FLAGSPACE);
	if (type) {
		global_clear_inference (anal, addr);
		r_flag_item_set_type (flags, fi, type);
		char *fmtstr = r_type_format (anal->sdb_types, type);
		r_meta_del (anal, R_META_TYPE_FORMAT, addr, 0);
		if (fmtstr) {
			r_meta_set (anal, R_META_TYPE_FORMAT, addr, size, fmtstr);
			free (fmtstr);
		}
		r_anal_types_unlink (anal, addr);
		r_anal_types_set_link (anal, type, addr);
	}
	free (type);
	return true;
}

R_API bool r_anal_global_del(RAnal *anal, ut64 addr) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		RFlag *flags = anal->flb.f;
		global_clear_inference (anal, addr);
		r_meta_del (anal, R_META_TYPE_FORMAT, addr, 0);
		r_flag_unset (flags, fi);
		r_anal_types_unlink (anal, addr);
		return true;
	}
	return false;
}

R_API bool r_anal_global_retype(RAnal *anal, ut64 addr, const char *new_type) {
	R_RETURN_VAL_IF_FAIL (anal && R_STR_ISNOTEMPTY (new_type), false);
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		return r_anal_global_add (anal, addr, new_type, fi->name);
	}
	return false;
}

R_API bool r_anal_global_rename(RAnal *anal, ut64 addr, const char *new_name) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		return r_flag_rename (anal->flb.f, fi, new_name);
	}
	return false;
}

R_API const char *r_anal_global_get_type(RAnal *anal, ut64 addr) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		RFlag *flags = anal->flb.f;
		RFlagItemMeta *fim = r_flag_get_meta (flags, fi->id);
		if (fim) {
			return fim->type;
		}
	}
	return NULL;
}
