/* radare - LGPL - Copyright 2018 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>

// TODO handle va

static void r_print_json_comma(RPrintJSON *j) {
	if (!j->is_key) {
		if (!j->is_first) {
			r_print_json (j, ",");
		}
	}
	j->is_first = false;
	j->is_key = false;
}

R_API void r_print_json(RPrintJSON *j, const char *msg) {
	if (j) {
		if (j->cb) {
			j->cb ("%s", msg);
		} else if (j->sb) {
			r_strbuf_append (j->sb, msg);
		}
	}
}

R_API RPrintJSON *r_print_json_begin(char type, PrintfCallback cb) {
	RPrintJSON *j = R_NEW0 (RPrintJSON);
	if (!j) {
		return NULL;
	}	
	if (cb) {
		j->cb = cb;
	} else {
		j->sb = r_strbuf_new ("");
	}
	return r_print_json_open (j, type);
}

R_API RPrintJSON *r_print_json_open(RPrintJSON *j, char type) {
	if (!j || j->level >= R_PRINT_JSON_DEPTH_LIMIT) {
		return NULL;
	}
	char msg[2] = {type, 0};
	r_print_json (j, msg);
	if (type == '{') type = '}';
	else if (type == '[') type = ']';
	// XXX fix overflow che
	j->braces[j->level] = type;
	j->level ++;
	j->is_first = true;
	return j;
}

R_API RPrintJSON *r_print_json_end(RPrintJSON *j) {
	if (!j || --j->level < 1) {
		if (j->cb) {
			char msg[2] = {j->braces[j->level], 0};
			r_print_json (j, msg);
			r_print_json (j, "\n");
		} else {
			eprintf ("%s\n", r_strbuf_get (j->sb));
			// TODO drain char *?
		}
		r_strbuf_free (j->sb);
		free (j);
		j->level = 0;
		return NULL;
	}
	char msg[2] = {j->braces[j->level], 0};
	r_print_json (j, msg);
	j->level--;
	return j;
}

R_API RPrintJSON *r_print_json_k(RPrintJSON *j, const char *k, char type) {
	r_return_val_if_fail (j, NULL);
	r_return_val_if_fail (k, NULL);
	j->is_key = false;
	r_print_json_comma (j);
	r_print_json (j, "\"");
	// escape string
	r_print_json (j, k);
	r_print_json (j, "\":");
	j->is_first = false;
	RPrintJSON *res = type? r_print_json_open (j, type): j;
	j->is_key = true;
	return res;
}

R_API void r_print_json_kn(RPrintJSON *j, const char *k, ut64 n) {
	r_print_json_k (j, k, 0);
	r_print_json_n (j, n);
}

R_API void r_print_json_ks(RPrintJSON *j, const char *k, const char *v) {
	r_print_json_k (j, k, 0);
	r_print_json_s (j, v);
}

R_API void r_print_json_kb(RPrintJSON *j, const char *k, bool v) {
	r_print_json_k (j, k, 0);
	r_print_json_b (j, v);
}

R_API void r_print_json_b(RPrintJSON *j, bool v) {
	r_print_json_comma (j);
	r_print_json (j, r_str_bool (v));
}

R_API void r_print_json_s(RPrintJSON *j, const char *k) {
	r_print_json_comma (j);
	r_print_json (j, "\"");
	r_print_json (j, k);
	r_print_json (j, "\"");
}

R_API void r_print_json_n(RPrintJSON *j, ut64 n) {
	r_print_json_comma (j);
	r_print_json (j, sdb_fmt ("%"PFMT64u, n));
}

R_API void r_print_json_d(RPrintJSON *j, int d) {
	r_print_json_comma (j);
	r_print_json (j, sdb_fmt ("%d", d));
}

