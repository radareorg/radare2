/* radare - LGPL - Copyright 2016-2021 - pancake */

#include <r_flag.h>
#include <r_util.h>

#define DB f->zones

static RFlagZoneItem *r_flag_zone_get (RFlag *f, const char *name) {
	RListIter *iter;
	RFlagZoneItem *zi;
	r_list_foreach (DB, iter, zi) {
		if (!strcmp (name, zi->name)) {
			return zi;
		}
	}
	return NULL;
}

static RFlagZoneItem *r_flag_zone_get_inrange (RFlag *f, ut64 from, ut64 to) {
	RListIter *iter;
	RFlagZoneItem *zi;
	r_list_foreach (DB, iter, zi) {
		if (R_BETWEEN (from, zi->from, to)) {
			return zi;
		}
	}
	return NULL;
}

R_API bool r_flag_zone_add(RFlag *f, const char *name, ut64 addr) {
	r_return_val_if_fail (f && name && *name, false);
	RFlagZoneItem *zi = r_flag_zone_get (f, name);
	if (zi) {
		if (addr < zi->from) {
			zi->from = addr;
		}
		if (addr > zi->to) {
			zi->to = addr;
		}
	} else {
		if (!DB) {
			r_flag_zone_reset (f);
		}
		zi = R_NEW0 (RFlagZoneItem);
		zi->name = strdup (name);
		zi->from = zi->to = addr;
		r_list_append (DB, zi);
	}
	return true;
}

R_API bool r_flag_zone_reset(RFlag *f) {
	r_list_free (f->zones);
	f->zones = r_list_newf (r_flag_zone_item_free);
	return true;
}

R_API bool r_flag_zone_del(RFlag *f, const char *name) {
	RListIter *iter;
	RFlagZoneItem *zi;
	r_list_foreach (DB, iter, zi) {
		if (!strcmp (name, zi->name)) {
			r_list_delete (DB, iter);
			return true;
		}
	}
	return false;
}


R_API void r_flag_zone_item_free(void *a) {
	RFlagZoneItem *zi = a;
	free (zi->name);
	free (zi);
}

R_API bool r_flag_zone_around(RFlag *f, ut64 addr, const char **prev, const char **next) {
	RListIter *iter;
	RFlagZoneItem *zi;
	*prev = *next = NULL;
	ut64 h = UT64_MAX, l = 0LL;

	r_list_foreach (DB, iter, zi) {
		if (zi->from > addr) {
			if (h == UT64_MAX) {
				h = zi->from;
				*next = zi->name;
			} else {
				if (zi->from < h) {
					h = zi->from;
					*next = zi->name;
				}
			}
		}
		if (zi->from < addr) {
			if (l == UT64_MAX) {
				l = zi->from;
				*prev = zi->name;
			} else {
				if (zi->from >= l) {
					l = zi->from;
					*prev = zi->name;
				}
			}
		}
		if (zi->to <= addr) {
			if (l == UT64_MAX) {
				l = zi->to;
				*prev = zi->name;
			} else {
				if (zi->to >= l) {
					l = zi->to;
					*prev = zi->name;
				}
			}
		}
		if (zi->to > addr) {
			if (h == UT64_MAX) {
				h = zi->to;
				*next = zi->name;
			} else {
				if (zi->to < h) {
					h = zi->to;
					*next = zi->name;
				}
			}
		}
	}
	return true;
}

R_API RList *r_flag_zone_barlist(RFlag *f, ut64 from, ut64 bsize, int rows) {
	RList *list = r_list_newf (NULL);
	int i;
	for (i = 0; i < rows; i++) {
		RFlagZoneItem *zi = r_flag_zone_get_inrange (f, from, from + bsize);
		if (zi) {
			r_list_append (list, zi->name);
		} else {
			r_list_append (list, "");
		}
		from += bsize;
	}
	return list;
}

R_API bool r_flag_zone_list(RFlag *f, int mode) {
	RListIter *iter;
	RFlagZoneItem *zi;
	r_list_foreach (DB, iter, zi) {
		if (mode == '*') {
			f->cb_printf ("fz %s @ 0x08%"PFMT64x"\n", zi->name, zi->from);
			f->cb_printf ("f %s %"PFMT64d" 0x08%"PFMT64x"\n", zi->name,
				zi->to - zi->from, zi->from);
		} else {
			f->cb_printf ("0x08%"PFMT64x"  0x%08"PFMT64x"  %s\n",
					zi->from, zi->to, zi->name);
		}
	}
	return true;
}
