/* radare - LGPL - Copyright 2018-2025 - pancake */

#include <r_util.h>
#include <r_util/r_print.h>

R_API void pj_raw(PJ *j, const char *msg) {
	R_RETURN_IF_FAIL (j && msg);
	if (*msg) {
		r_strbuf_append (&j->sb, msg);
	}
}

R_API void pj_kraw(PJ *j) {
	j->comma = ":";
}

static void pj_comma(PJ *j) {
	R_RETURN_IF_FAIL (j);
	if (!j->is_key && !j->is_first) {
		pj_raw (j, j->comma);
		j->comma = ",";
	}
	j->is_first = false;
	j->is_key = false;
}

R_API PJ * R_NONNULL pj_new(void) {
	PJ *j = R_NEW0 (PJ);
	r_strbuf_init (&j->sb);
	j->is_first = true;
	j->comma = ",";
	j->str_encoding = PJ_ENCODING_STR_DEFAULT;
	j->num_encoding = PJ_ENCODING_NUM_DEFAULT;
	return j;
}

R_API PJ *pj_new_with_encoding(PJEncodingStr str_encoding, PJEncodingNum num_encoding) {
	PJ *j = pj_new ();
	if (j) {
		j->str_encoding = str_encoding;
		j->num_encoding = num_encoding;
	}
	return j;
}

R_API void pj_free(PJ *pj) {
	if (pj) {
		r_strbuf_fini (&pj->sb);
		free (pj);
	}
}

R_API void pj_reset(PJ *j) {
	R_RETURN_IF_FAIL (j);
	r_strbuf_set (&j->sb, "");
	j->level = 0;
	j->is_first = true;
	j->is_key = false;
}

R_API char *pj_drain(PJ *pj) {
	R_RETURN_VAL_IF_FAIL (pj && pj->level == 0, NULL);
	char *res = r_strbuf_drain_nofree (&pj->sb);
	free (pj);
	return res;
}

R_API const char *pj_string(PJ *j) {
	return j? r_strbuf_get (&j->sb): NULL;
}

static PJ *pj_begin(PJ *j, char type) {
	if (j) {
		if (!j || j->level >= R_PRINT_JSON_DEPTH_LIMIT) {
			R_LOG_ERROR ("JSON depth limit reached");
			return NULL;
		}
		char msg[2] = { type, 0 };
		pj_raw (j, msg);
		j->braces[j->level] = (type == '{') ? '}' : ']';
		j->level++;
		j->is_first = true;
	}
	return j;
}

R_API PJ *pj_o(PJ *j) {
	R_RETURN_VAL_IF_FAIL (j, j);
	pj_comma (j);
	return pj_begin (j, '{');
}

R_API PJ *pj_a(PJ *j) {
	R_RETURN_VAL_IF_FAIL (j, j);
	pj_comma (j);
	return pj_begin (j, '[');
}

R_API PJ *pj_end(PJ *j) {
	R_RETURN_VAL_IF_FAIL (j, j);
	if (j->level < 1) {
		return j;
	}
	if (--j->level < 1) {
		char msg[2] = { j->braces[j->level], 0 };
		pj_raw (j, msg);
		j->level = 0;
		return j;
	}
	j->is_first = false;
	char msg[2] = { j->braces[j->level], 0 };
	pj_raw (j, msg);
	return j;
}

R_API PJ *pj_k(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	j->is_key = false;
	pj_s (j, k);
	pj_raw (j, ":");
	j->is_first = false;
	j->is_key = true;
	return j;
}

R_API PJ *pj_knull(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	pj_null (j);
	return j;
}

R_API PJ *pj_kn(PJ *j, const char *k, ut64 n) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	if (j->num_encoding != PJ_ENCODING_NUM_DEFAULT) {
		pj_ne (j, n);
	} else {
		pj_n (j, n);
	}
	return j;
}

R_API PJ *pj_kN(PJ *j, const char *k, st64 n) {
	if (j && k) {
		pj_k (j, k);
		pj_N (j, n);
	}
	return j;
}

R_API PJ *pj_kd(PJ *j, const char *k, double d) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	if (isinf (d)) {
		pj_s (j, signbit (d)? "-Infinity": "Infinity");
	} else if (isnan (d)) {
		pj_s (j, signbit (d)? "-NaN": "NaN");
	} else {
		pj_d (j, d);
	}
	return j;
}

R_API PJ *pj_kf(PJ *j, const char *k, float d) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	if (isinf (d)) {
		pj_s (j, signbit (d)? "-Infinity": "Infinity");
	} else if (isnan (d)) {
		pj_s (j, signbit (d)? "-NaN": "NaN");
	} else {
		pj_f (j, d);
	}
	return j;
}
R_API PJ *pj_ki(PJ *j, const char *k, int i) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	pj_i (j, i);
	return j;
}

R_API PJ *pj_ko(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	pj_o (j);
	return j;
}

R_API PJ *pj_ka(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	pj_a (j);
	return j;
}

R_API PJ *pj_ks(PJ *j, const char *k, const char *v) {
	R_RETURN_VAL_IF_FAIL (j && k && v, j);
	pj_k (j, k);
	if (j->str_encoding != PJ_ENCODING_STR_DEFAULT) {
		pj_se (j, v);
	} else {
		pj_s (j, v);
	}
	return j;
}

R_API PJ *pj_kb(PJ *j, const char *k, bool v) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_k (j, k);
	pj_b (j, v);
	return j;
}

R_API PJ *pj_null(PJ *j) {
	R_RETURN_VAL_IF_FAIL (j, j);
	pj_comma (j);
	pj_raw (j, "null");
	return j;
}

R_API PJ *pj_b(PJ *j, bool v) {
	R_RETURN_VAL_IF_FAIL (j, j);
	pj_comma (j);
	pj_raw (j, r_str_bool (v));
	return j;
}

R_API PJ *pj_s(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_comma (j);
	pj_raw (j, "\"");
	char *ek = r_str_escape_json (k, -1);
	if (ek) {
		pj_raw (j, ek);
		free (ek);
	} else {
		R_LOG_WARN ("cannot escape string");
	}
	pj_raw (j, "\"");
	return j;
}

R_API PJ *pj_se(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	pj_comma (j);
	if (j->str_encoding == PJ_ENCODING_STR_ARRAY) {
		pj_raw (j, "[");
	} else {
		pj_raw (j, "\"");
	}
	char *en = r_str_encoded_json (k, -1, j->str_encoding);
	if (en) {
		pj_raw (j, en);
		free (en);
	}
	if (j->str_encoding == PJ_ENCODING_STR_ARRAY) {
		pj_raw (j, "]");
	} else {
		pj_raw (j, "\"");
	}
	return j;
}

R_API PJ *pj_r(PJ *j, const unsigned char *v, size_t v_len) {
	R_RETURN_VAL_IF_FAIL (j && v, j);
	size_t i;
	pj_a (j);
	for (i = 0; i < v_len; i++) {
		pj_i (j, v[i]);
	}
	pj_end (j);
	return j;
}

R_API PJ *pj_kr(PJ *j, const char *k, const unsigned char *v, size_t v_len) {
	R_RETURN_VAL_IF_FAIL (j && k && v, j);
	pj_k (j, k);
	pj_r (j, v, v_len);
	return j;
}

R_API PJ *pj_j(PJ *j, const char *k) {
	R_RETURN_VAL_IF_FAIL (j && k, j);
	if (*k) {
		pj_comma (j);
		pj_raw (j, k);
	}
	return j;
}

R_API PJ *pj_n(PJ *j, ut64 n) {
	R_RETURN_VAL_IF_FAIL (j, j);
	pj_comma (j);
	char numstr[32];
	if (j->num_encoding == PJ_ENCODING_NUM_STR) {
		snprintf (numstr, sizeof (numstr), "\"%" PFMT64u "\"", (uint64_t)n);
	} else if (j->num_encoding == PJ_ENCODING_NUM_HEX) {
		snprintf (numstr, sizeof (numstr), "\"0x%" PFMT64x "\"", (uint64_t)n);
	} else {
		snprintf (numstr, sizeof (numstr), "%" PFMT64u, n);
	}
	pj_raw (j, numstr);
	return j;
}

R_API PJ *pj_ne(PJ *j, ut64 n) {
	R_RETURN_VAL_IF_FAIL (j, j);
	pj_n (j, n);
	return j;
}

R_API PJ *pj_N(PJ *j, st64 n) {
	char numstr[64];
	R_RETURN_VAL_IF_FAIL (j, NULL);
	snprintf (numstr, sizeof (numstr), "%"PFMT64d, n);
	pj_comma (j);
	pj_raw (j, numstr);
	return j;
}

R_API PJ *pj_f(PJ *j, float f) {
	R_RETURN_VAL_IF_FAIL (j, NULL);
	char numstr[64];
	snprintf (numstr, sizeof (numstr), "%f", f);
	pj_comma (j);
	pj_raw (j, numstr);
	return j;
}

R_API PJ *pj_d(PJ *j, double d) {
	R_RETURN_VAL_IF_FAIL (j, NULL);
	char numstr[64];
	snprintf (numstr, sizeof (numstr), "%.03lf", d);
	pj_comma (j);
	pj_raw (j, numstr);
	return j;
}

R_API PJ *pj_i(PJ *j, int i) {
	if (j) {
		char numstr[64];
		pj_comma (j);
		snprintf (numstr, sizeof (numstr), "%d", i);
		pj_raw (j, numstr);
	}
	return j;
}
