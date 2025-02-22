/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_core.h>

R_API bool r_core_patch_line(RCore *core, char *str) {
	R_RETURN_VAL_IF_FAIL (core && str, false);
	char *q, *p = strchr (str + 1, ' ');
	if (!p) {
		return false;
	}
	*p = 0;
	p = (char *)r_str_trim_head_ro (p + 1);

	switch (*p) {
	case '"':
		q = strchr (p + 1, '"');
		if (q) {
			*q = 0;
		}
		r_core_cmdf (core, "'s %s", str);
		r_core_cmdf (core, "'w %s", p + 1);
		break;
	case ':':
		r_core_cmdf (core, "'s %s", str);
		r_core_cmdf (core, "'wa %s", p);
		break;
	case 'v':
		q = strchr (p + 1, ' ');
		if (q) {
			*q = 0;
			q = (char *)r_str_trim_head_ro (q + 1);
		} else {
			return 0;
		}
		r_core_cmdf (core, "'s %s", str);
		r_core_cmdf (core, "'wv%s %s", p + 1, q);
		break;
	default:
		r_core_cmdf (core, "'s %s", str);
		r_core_cmdf (core, "'wx %s", p);
		break;
	}
	return true;
}

static bool __core_patch_bracket(RCore *core, const char *str, ut64 *noff) {
	char tmp[128];
	char *s, *p, *q, *off;
	RBuffer *b = r_buf_new ();
	if (!b) {
		return false;
	}
	p = off = strdup (str);
	if (!p) {
		r_buf_free (b);
		return false;
	}
	for (;*p;) {
		if (*p == '\n') {
			*p++ = 0;
		} else {
			p++;
			continue;
		}
		if (*str == '}') {
			break;
		}
		if ((q = strstr (str, "${"))) {
			char *end = strchr (q + 2,'}');
			if (end) {
				*q = *end = 0;
				*noff = r_num_math (core->num, q + 2);
				r_buf_append_bytes (b, (const ut8*)str, strlen (str));
				snprintf (tmp, sizeof (tmp), "0x%08"PFMT64x, *noff);
				r_buf_append_bytes (b, (const ut8*)tmp, strlen (tmp));
				r_buf_append_bytes (b, (const ut8*)end + 1, strlen (end + 1));
			}
		} else {
			r_buf_append_bytes (b, (const ut8*)str, strlen (str));
		}
		str = p;
	}

	s = r_buf_tostring (b);
	r_egg_load (core->egg, s, 0);
	free (s);

	(void)r_egg_compile (core->egg);
	(void)r_egg_assemble (core->egg);

	r_buf_free (b);
	b = r_egg_get_bin (core->egg);

	if (strcmp (off, "+")) {
		*noff = r_num_math (core->num, off);
	}
	ut64 tmpsz;
	const ut8 *tmpbuf = r_buf_data (b, &tmpsz);
	r_core_write_at (core, *noff, tmpbuf, tmpsz);
	*noff += r_buf_size (b);
	free (off);
	return true;
}

R_API bool r_core_patch_file(RCore *core, const char *patch) {
	R_RETURN_VAL_IF_FAIL (core && patch, false);
	char *data = r_file_slurp (patch, NULL);
	if (!data) {
		R_LOG_ERROR ("Cannot open %s", patch);
		return false;
	}
	bool res = r_core_patch (core, data);
	free (data);
	return res;
}


R_API bool r_core_patch(RCore *core, const char *patch) {
	R_RETURN_VAL_IF_FAIL (core && patch, false);
	char *p, *p0, *str;
	ut64 noff = 0LL;

	p = p0 = str = strdup (patch);
	if (!p) {
		return false;
	}
	for (; *p; p++) {
		/* read until newline */
		if (!*p || *p == '\n') {
			*p++ = 0;
		} else {
			continue;
		}

		switch (*str) {
		case '#':
		case '\n':
		case '\r':
		case '\0':
			break;
		case ':':
			r_core_cmd0 (core, str + 1);
			break;
		case '.':
		case '!':
			r_core_cmd0 (core, str);
			break;
		case '{':
			(void)__core_patch_bracket (core, str, &noff);
			break;
		default:
			r_core_patch_line (core, str);
			break;
		}
		if (!*p) {
			break;
		}
		str = p;
	}
	free (p0);
	// TODO do some minimum error checking
	return true;
}
