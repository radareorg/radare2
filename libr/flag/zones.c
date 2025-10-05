/* radare - LGPL - Copyright 2016-2025 - pancake */

#include <r_flag.h>

R_API RFlagZoneItem *r_flag_zone_get(RFlag *f, const char *name) {
	RListIter *iter;
	RFlagZoneItem *zi;
	RList *db = f->zones;
	r_list_foreach (db, iter, zi) {
		if (!strcmp (name, zi->name)) {
			return zi;
		}
	}
	return NULL;
}

static RFlagZoneItem *r_flag_zone_get_inrange(RFlag *f, ut64 from, ut64 to) {
	RListIter *iter;
	RFlagZoneItem *zi;
	RList *db = f->zones;
	r_list_foreach (db, iter, zi) {
		if (R_BETWEEN (from, zi->from, to)) {
			return zi;
		}
	}
	return NULL;
}

R_API bool r_flag_zone_add(RFlag *f, const char *name, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (f && R_STR_ISNOTEMPTY (name), false);
	RFlagZoneItem *zi = r_flag_zone_get (f, name);
	if (zi) {
		if (addr < zi->from) {
			zi->from = addr;
		}
		if (addr > zi->to) {
			zi->to = addr;
		}
	} else {
		if (!f->zones) {
			r_flag_zone_reset (f);
		}
		zi = R_NEW0 (RFlagZoneItem);
		zi->name = strdup (name);
		r_name_filter (zi->name, -1);
		zi->from = zi->to = addr;
		r_list_append (f->zones, zi);
	}
	return true;
}

R_API bool r_flag_zone_reset(RFlag *f) {
	R_RETURN_VAL_IF_FAIL (f, false);
	r_list_free (f->zones);
	f->zones = r_list_newf (r_flag_zone_item_free);
	return true;
}

R_API bool r_flag_zone_del(RFlag *f, const char *name) {
	R_RETURN_VAL_IF_FAIL (f && name, false);
	RListIter *iter;
	RFlagZoneItem *zi;
	RList *db = f->zones;
	r_list_foreach (db, iter, zi) {
		if (!strcmp (name, zi->name)) {
			r_list_delete (db, iter);
			return true;
		}
	}
	return false;
}

R_API void r_flag_zone_item_free(void *a) {
	if (R_UNLIKELY (a)) {
		RFlagZoneItem *zi = a;
		free (zi->name);
		free (zi);
	}
}

R_API bool r_flag_zone_around(RFlag *f, ut64 addr, const char ** R_NULLABLE prev, const char ** R_NULLABLE next) {
	R_RETURN_VAL_IF_FAIL (f, false);
	RListIter *iter;
	RFlagZoneItem *zi;
	*prev = *next = NULL;
	ut64 h = UT64_MAX, l = 0LL;
	RList *db = f->zones;

	bool res = false;
	r_list_foreach (db, iter, zi) {
		if (zi->from > addr) {
			if (h == UT64_MAX) {
				h = zi->from;
				*next = zi->name;
				res = true;
			} else {
				if (zi->from < h) {
					h = zi->from;
					*next = zi->name;
					res = true;
				}
			}
		}
		if (zi->from < addr) {
			if (l == UT64_MAX) {
				l = zi->from;
				*prev = zi->name;
				res = true;
			} else {
				if (zi->from >= l) {
					l = zi->from;
					*prev = zi->name;
					res = true;
				}
			}
		}
		if (zi->to <= addr) {
			if (l == UT64_MAX) {
				l = zi->to;
				*prev = zi->name;
				res = true;
			} else {
				if (zi->to >= l) {
					l = zi->to;
					res = true;
					*prev = zi->name;
				}
			}
		}
		if (zi->to > addr) {
			if (h == UT64_MAX) {
				h = zi->to;
				res = true;
				*next = zi->name;
			} else {
				if (zi->to < h) {
					h = zi->to;
					res = true;
					*next = zi->name;
				}
			}
		}
	}
	return res;
}

R_API RList *r_flag_zone_barlist(RFlag *f, ut64 from, ut64 bsize, int rows) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	RList *list = r_list_newf (NULL);
	int i;
	for (i = 0; i < rows; i++) {
		RFlagZoneItem *zi = r_flag_zone_get_inrange (f, from, from + bsize);
		r_list_append (list, zi? zi->name: "");
		from += bsize;
	}
	return list;
}

R_API char *r_flag_zone_list(RFlag *f, int mode) {
	R_RETURN_VAL_IF_FAIL (f, NULL);
	RListIter *iter;
	RFlagZoneItem *zi;
	RList *db = f->zones;
	RStrBuf *sb = r_strbuf_new ("");
	r_list_foreach (db, iter, zi) {
		if (mode == '*') {
			r_strbuf_appendf (sb, "'@0x%08"PFMT64x"'fz %s\n", zi->from, zi->name);
			r_strbuf_appendf (sb, "'f %s %"PFMT64d" 0x08%"PFMT64x"\n", zi->name,
				zi->to - zi->from, zi->from);
		} else if (mode == 'q') {
			r_strbuf_appendf (sb, "%s\n", zi->name);
		} else {
			r_strbuf_appendf (sb, "0x08%"PFMT64x"  0x%08"PFMT64x"  %s\n",
					zi->from, zi->to, zi->name);
		}
	}
	return r_strbuf_drain (sb);
}
