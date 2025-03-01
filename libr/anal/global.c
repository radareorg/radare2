/* radare - LGPL - Copyright 2021-2025 - pancake */

#include <r_anal.h>
#include <r_util/r_print.h>

#define GLOBAL_FLAGSPACE "globals"

R_API RFlagItem *r_anal_global_get(RAnal *anal, ut64 addr) {
	RFlag *flags = anal->flb.f;
	RFlagItem *fi = r_flag_get_in (flags, addr);
	if (fi && fi->space && fi->space->name && !strcmp (fi->space->name, GLOBAL_FLAGSPACE)) {
		return fi;
	}
	return NULL;
}

R_API bool r_anal_global_add(RAnal *anal, ut64 addr, const char *type_name, const char *name) {
	RFlag *flags = anal->flb.f;
	char *fmtstr = r_type_format (anal->sdb_types, type_name);
	if (!fmtstr) {
		R_LOG_ERROR ("Unknown type in format string for a global");
		return false;
	}
	int fmtsize = r_print_format_struct_size (anal->print, fmtstr, 0, 0);
	if (fmtsize < 1) {
		fmtsize = 4;
	}
	// check if type exist
	RFlagItem *fi = r_flag_set_inspace (flags, GLOBAL_FLAGSPACE, name, addr, 1);
	if (fi) {
		r_flag_item_set_type (flags, fi, fmtstr);
	}
	r_meta_set (anal, R_META_TYPE_FORMAT, addr, fmtsize, fmtstr);
	// implicit
	r_type_set_link (anal->sdb_types, fmtstr, addr);
	return true;
}

R_API bool r_anal_global_del(RAnal *anal, ut64 addr) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		RFlag *flags = anal->flb.f;
		r_meta_del (anal, R_META_TYPE_FORMAT, addr, 0);
		r_flag_unset (flags, fi);
		r_type_unlink (anal->sdb_types, addr);
		return true;
	}
	return false;
}

R_API bool r_anal_global_retype(RAnal *anal, ut64 addr, const char *new_type) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		RFlag *flags = anal->flb.f;
		r_flag_item_set_type (flags, fi, new_type);
		return true;
	}
	return false;
}

R_API bool r_anal_global_rename(RAnal *anal, ut64 addr, const char *new_name) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		RFlag *flags = anal->flb.f;
		r_flag_rename (flags, fi, new_name);
		return true;
	}
	return false;
}

R_API const char *r_anal_global_get_type(RAnal *anal, ut64 addr) {
	RFlagItem *fi = r_anal_global_get (anal, addr);
	if (fi) {
		RFlag *flags = anal->flb.f;
		RFlagItemMeta *fim = r_flag_get_meta (flags, fi->id);
		return fim? fim->type: NULL;
	}
	return NULL;
}
