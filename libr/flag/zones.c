/* radare - LGPL - Copyright 2016-2025 - pancake */

#include <r_flag.h>

R_API RFlagZoneItem *r_flag_zone_get(RFlag *f, const char *name) {
	R_RETURN_VAL_IF_FAIL (f && name, NULL);
	RFlagZoneItem *zi;
	R_VEC_FOREACH (&f->zones, zi) {
		if (!strcmp (name, zi->name)) {
			return zi;
		}
	}
	return NULL;
}

static RFlagZoneItem *r_flag_zone_get_inrange(RFlag *f, ut64 from, ut64 to) {
	RFlagZoneItem *zi;
	R_VEC_FOREACH (&f->zones, zi) {
		if (R_INBETWEEN (zi->from, zi->to, from, to)) {
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
		zi = RVecFlagZoneItem_emplace_back (&f->zones);
		if (!zi) {
			return false;
		}
		zi->name = strdup (name);
		if (!zi->name) {
			RVecFlagZoneItem_pop_back (&f->zones);
			return false;
		}
		r_name_filter (zi->name, -1);
		zi->from = zi->to = addr;
	}
	return true;
}

R_API bool r_flag_zone_reset(RFlag *f) {
	R_RETURN_VAL_IF_FAIL (f, false);
	RVecFlagZoneItem_clear (&f->zones);
	return true;
}

R_API bool r_flag_zone_del(RFlag *f, const char *name) {
	R_RETURN_VAL_IF_FAIL (f && name, false);
	size_t i = 0;
	RFlagZoneItem *zi;
	R_VEC_FOREACH (&f->zones, zi) {
		if (!strcmp (name, zi->name)) {
			RVecFlagZoneItem_remove (&f->zones, i);
			return true;
		}
		i++;
	}
	return false;
}

R_API void r_flag_zone_item_free(void *a) {
	if (R_UNLIKELY (a)) {
		RFlagZoneItem *zi = a;
		r_flag_zone_item_fini (zi);
		free (zi);
	}
}

R_API bool r_flag_zone_around(RFlag *f, ut64 addr, const char ** R_NULLABLE prev, const char ** R_NULLABLE next) {
	R_RETURN_VAL_IF_FAIL (f, false);
	RFlagZoneItem *zi;
	if (prev) {
		*prev = NULL;
	}
	if (next) {
		*next = NULL;
	}
	ut64 h = UT64_MAX, l = UT64_MAX;

	bool res = false;
	R_VEC_FOREACH (&f->zones, zi) {
		if (zi->from > addr) {
			if (h == UT64_MAX) {
				h = zi->from;
				if (next) {
					*next = zi->name;
				}
				res = true;
			} else {
				if (zi->from < h) {
					h = zi->from;
					if (next) {
						*next = zi->name;
					}
					res = true;
				}
			}
		}
		if (zi->from < addr) {
			if (l == UT64_MAX) {
				l = zi->from;
				if (prev) {
					*prev = zi->name;
				}
				res = true;
			} else {
				if (zi->from >= l) {
					l = zi->from;
					if (prev) {
						*prev = zi->name;
					}
					res = true;
				}
			}
		}
		if (zi->to <= addr) {
			if (l == UT64_MAX) {
				l = zi->to;
				if (prev) {
					*prev = zi->name;
				}
				res = true;
			} else {
				if (zi->to >= l) {
					l = zi->to;
					res = true;
					if (prev) {
						*prev = zi->name;
					}
				}
			}
		}
		if (zi->to > addr) {
			if (h == UT64_MAX) {
				h = zi->to;
				res = true;
				if (next) {
					*next = zi->name;
				}
			} else {
				if (zi->to < h) {
					h = zi->to;
					res = true;
					if (next) {
						*next = zi->name;
					}
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
	RFlagZoneItem *zi;
	RStrBuf *sb = r_strbuf_new ("");
	R_VEC_FOREACH (&f->zones, zi) {
		if (mode == '*') {
			r_strbuf_appendf (sb, "'@0x%08"PFMT64x"'fz %s\n", zi->from, zi->name);
			r_strbuf_appendf (sb, "'f %s %"PFMT64d" 0x%08"PFMT64x"\n", zi->name,
				zi->to - zi->from, zi->from);
		} else if (mode == 'q') {
			r_strbuf_appendf (sb, "%s\n", zi->name);
		} else {
			r_strbuf_appendf (sb, "0x%08"PFMT64x"  0x%08"PFMT64x"  %s\n",
					zi->from, zi->to, zi->name);
		}
	}
	return r_strbuf_drain (sb);
}
