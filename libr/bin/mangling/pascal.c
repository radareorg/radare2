// ported to radare2 by pancake 2022
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <r_util.h>

#define IS_NAME(x) (islower(x) || isdigit(x) || (x) == '_')

static char *demangle_freepascal_function(RStrBuf *ds, char *mangled, size_t mangled_len) {
	char *next = mangled;
	char *end = mangled + mangled_len;
	char *tmp = strchr (next, '$');

	// <func_name>$<type0$type1>$$<ret_type>
	r_strbuf_append_n (ds, next, tmp - next);
	r_strbuf_append (ds, "(");
	next = tmp + strlen ("$");
	size_t n_arg = 0;

	while (next < end && *next != '$' && (tmp = strchr(next, '$')) && tmp > next && tmp > mangled && IS_NAME(tmp[-1])) {
		// <type0$type1>$$<ret_type>
		if (n_arg > 0) {
			r_strbuf_append (ds, ",");
		}
		r_strbuf_append_n (ds, next, tmp - next);
		next = tmp + strlen ("$");
		n_arg++;
	}

	if (next < end && (tmp = strchr (next, '$'))) {
		r_strbuf_append (ds, ")");
		// $$<ret_type>
		next = tmp + strlen ("$");
		if (next < end) {
			r_strbuf_append_n (ds, next, end - next);
			next = end;
		}
	} else {
		if (next < end) {
			// <type0> (sometimes it may not have a return type just args.)
			if (n_arg > 0) {
				r_strbuf_append (ds, ",");
			}
			r_strbuf_append_n (ds, next, end - next);
		}
		r_strbuf_append (ds, ")");
		next = end;
	}

	return next;
}

static void demangle_freepascal_unit(RStrBuf *ds, char *mangled, size_t mangled_len) {
	r_strbuf_append (ds, "unit ");

	char *end = mangled + mangled_len;
	char *tmp = strstr (mangled, "_$");

	if (tmp && tmp < end) {
		r_strbuf_append_n (ds, mangled, tmp - mangled);
		r_strbuf_append (ds, ".");
		mangled = tmp + strlen ("_$");
		if ((tmp = strstr (mangled, "_$$_")) && tmp < end) {
			// <unit>_$$_<sub0>_$_<sub1>_$_..
			r_strbuf_append_n (ds, mangled, tmp - mangled);
			mangled = tmp + strlen ("_$$_");
			while (mangled < end && (tmp = strstr (mangled, "_$_")) && tmp > mangled && tmp < end) {
				// <sub0>_$_<sub1>_$_..
				r_strbuf_append (ds, ".");
				r_strbuf_append_n (ds, mangled, tmp - mangled);
				mangled = tmp + strlen ("_$_");
			}
			if (mangled < end) {
				r_strbuf_append (ds, ".");
				r_strbuf_append_n (ds, mangled, end - mangled);
			}
		} else {
			if (end > mangled) {
				r_strbuf_append_n (ds, mangled, end - mangled);
			} else {
				// should never happen
			}
		}
	} else {
		r_strbuf_append_n (ds, mangled, mangled_len);
	}

	r_strbuf_append (ds, " ");
}

// Demangles freepascal 2.6.x to 3.2.x symbols
R_API char *r_bin_demangle_freepascal(const char *_mangled) {
	char *tmp = NULL;
	bool unit = false;
	char *mangled = strdup (_mangled);
	size_t mangled_len = strlen (mangled);
	char *next = mangled;
	char *end = mangled + mangled_len;
	RStrBuf *ds = r_strbuf_new ("");
	if (!ds) {
		goto demangle_fail;
	}

	size_t i;
	for (i = 0; i < mangled_len; i++) {
		mangled[i] = tolower (mangled[i]);
	}

	if (next < end && (tmp = strstr (next, "$_$")) && tmp > next && IS_NAME(tmp[-1])) {
		// <unit>$_$<object>_$_<unit1>_$$_<func_name>$<type0$type1>$$<ret_type>
		demangle_freepascal_unit (ds, next, tmp - next);
		unit = true;
		next = tmp + strlen ("$_$");
		while ((tmp = strstr (next, "_$_")) && tmp > next && IS_NAME(tmp[-1])) {
			r_strbuf_append_n (ds, next, tmp - next);
			r_strbuf_append (ds, ".");
			next = tmp + strlen ("_$_");
		}
		if ((tmp = strstr (next, "_$$_")) && tmp == next) {
			// often <unit1> is empty, thus we can skip it.
			next += strlen ("_$$_");
		}
	}

	if (next < end && (tmp = strstr (next, "_$$_")) && tmp > next && IS_NAME(tmp[-1])) {
		// <unit1>_$$_<func_name>$<type0$type1>$$<ret_type>
		if (!unit) {
			demangle_freepascal_unit (ds, next, tmp - next);
		} else {
			demangle_freepascal_function (ds, next, tmp - next);
			r_strbuf_append (ds, "::");
		}
		next = tmp + strlen ("_$$_");
	}

	if (next < end && (tmp = strchr(next, '$')) && tmp > next && IS_NAME(tmp[-1])) {
		next = demangle_freepascal_function (ds, next, end - next);
	} else {
		// <func_name>
		r_strbuf_append (ds, next);
		r_strbuf_append (ds, "()");
	}

	if (ds->len < 1) {
		goto demangle_fail;
	}

	free (mangled);
	return r_strbuf_drain (ds);

demangle_fail:
	r_strbuf_free (ds);
	free (mangled);
	return NULL;
}
