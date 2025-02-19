/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_core.h>

R_API bool r_core_patch_line(RCore *core, char *str) {
	char *q, *p = strchr (str + 1, ' ');
	if (!p) {
		return false;
	}
	*p = 0;
	p = (char *)r_str_trim_head_ro (p + 1);

	switch (*p) {
	case '"':
		q = strchr (p + 1,'"');
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
		eprintf ("SEEK %s\n", str);
		r_core_cmdf (core, "'s %s", str);
		eprintf ("wx %s\n", p);
		r_core_cmdf (core, "'wx %s", p);
		break;
	}
	eprintf ("BACK\n");
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

static bool getpair(char *s, ut64 *addr, ut64 *size) {
	char *comma = strchr (s, ',');
	if (comma) {
		*comma++ = 0;
		*addr = r_num_get (NULL, s);
		*size = r_num_get (NULL, comma);
		return true;
	}
	return false;
}

static bool ishexchar(const char ch) {
	if (isdigit (ch)) {
		return true;
	}
	if (ch >= 'a' && ch <= 'f') {
		return true;
	}
	if (ch >= 'A' && ch <= 'F') {
		return true;
	}
	return false;
}

R_API bool r_core_patch_unified(RCore *core, const char *patch, int level, bool revert) {
	char *p;
	RIODesc *desc = NULL;
	ut64 sub_addr = 0;
	ut64 sub_size = 0;
	ut64 add_addr = 0;
	ut64 add_size = 0;
	while (true) {
		char *nl = strchr (p, '\n');
		if (!nl) {
			break;
		}
		char *line = r_str_ndup (p, nl - p);
		if (r_str_startswith (line, "--- ")) {
			if (desc) {
				r_io_desc_free (desc);
				desc = NULL;
			}
			char *tab = strchr (line, '\t');
			if (tab) {
				*tab = 0;
			}
			char *file_name = r_str_trim_dup (line + 4);
			if (revert) {
				// TODO
			}
			R_LOG_DEBUG ("OldFile: %s", file_name);
			free (file_name);
		} else if (r_str_startswith (line, "+++ ")) {
			char *tab = strchr (line, '\t');
			if (tab) {
				*tab = 0;
			}
			char *file_name = r_str_trim_dup (line + 4);
			R_LOG_DEBUG ("NewFile: %s", file_name);
			if (desc) {
				R_LOG_WARN ("Invalid patch format, cannot open file twice");

			}
			if (level) {
				R_LOG_TODO ("patch level not implemented yet");
			}
			desc = r_core_file_open (core, file_name, R_PERM_RW, 0);
			if (!desc) {
				R_LOG_ERROR ("Cannot open %s", file_name);
				break;
			}
			ut64 size = r_io_desc_size (desc);
			r_io_map_add (core->io, desc->fd, R_PERM_RW, 0, 0, size);
			free (file_name);
		} else if (r_str_startswith (line, "@@ ")) {
			//  @@ -0x00189ca8,4 +0x00189ca8,4 @@
			// @@ -1612969,char[3] +1612969,char[3] @@
			// @@ -0x00189ca8,char[4] +0x00189ca8,char[4] @@
			// @@ -0x00189ca8,uint32_t[3] +0x00189ca8,uint32_t[3] @@
			// @@ -0x00189ca8,12 +0x00189ca8,12 @@
			char *plus = strchr (line, '+');
			if (!plus) {
				R_LOG_ERROR ("Invalid patch format, Cant find +");
				break;
			}
			if (!getpair (plus + 1, &sub_addr, &sub_size)) {
				R_LOG_ERROR ("Invalid patch format, Cant find comma in @@ line");
				break;
			}
			if (!getpair (line + 3, &add_addr, &add_size)) {
				R_LOG_ERROR ("Invalid patch format, Cant find comma in @@ line");
				break;
			}
		} else if (r_str_startswith (line, "- ")) {
			// - LE 0x001b7358 # 1799000 comment after the # symbol, could be assembly
			if (revert) {
				R_LOG_TODO ("Revert mode not yet implemented");
			}
		} else if (r_str_startswith (line, "+ ")) {
			// + LE 0x001b7358 # 1799000 comment after the # symbol, could be assembly
			if (revert) {
				R_LOG_ERROR ("TODO");
			} else {
				ut64 addr = revert? sub_addr: add_addr;
				ut64 size = revert? sub_size: add_size;
				if (r_str_startswith (line + 2, "LE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_le32 (buf, n);
						r_io_write_at (core->io, addr, buf, 4);
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
					}
				} else if (r_str_startswith (line + 2, "BE ")) {
					if (size == 4) {
						ut8 buf[4] = {0};
						ut32 n = r_num_get (NULL, line + 2 + 3);
						r_write_be32 (buf, n);
						r_io_write_at (core->io, addr, buf, 4);
					} else {
						R_LOG_ERROR ("Unsupported patch size %d", (int)size);
					}
				} else if (line[0] == '\'') {
					// + '4f f2 ba fc' # bl 0x254526
					R_LOG_TODO ("hexpairs");
				} else if (ishexchar (line[0]) && ishexchar (line[1])) {
					// + 30
					R_LOG_TODO ("byte");
				} else {
					R_LOG_ERROR ("Expected LE or BE");
				}
			}
		} else {
			R_LOG_INFO ("Ignored line %s", line);
		}
		free (line);
		p = nl + 1;
	}
	return true;
}

R_API bool r_core_patch(RCore *core, const char *patch) {
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
