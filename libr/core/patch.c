/* radare - LGPL - Copyright 2011-2013 - pancake */

#include <r_core.h>

R_API int r_core_patch (RCore *core, const char *patch) {
	char *p, *p2, *q, str[200], tmp[64];
	ut64 noff = 0LL;
	FILE *fd = r_sandbox_fopen (patch, "r");
	if (fd==NULL) {
		eprintf ("Cannot open patch file\n");
		return 1;
	}

	while (!feof (fd)) {
		fgets (str, sizeof (str), fd);
		if (*str=='#' || *str=='\n' || *str=='\r')
			continue;
		if (*str==':') {
			r_core_cmd0 (core, str+1);
			continue;
		}
		if (*str=='.' || *str=='!') {
			r_core_cmd0 (core, str);
			continue;
		}
		p = strchr (str+1, ' ');
		if (p) {
			*p = 0;
			for (++p; *p==' '; p++); // XXX: skipsspaces here
			switch (*p) {
			case '{': {
				char *s, *off = strdup (str);
				RBuffer *b = r_buf_new ();
				
				while (!feof (fd)) {
					fgets (str, sizeof (str), fd);
					if (*str=='}')
						break;
					if ((q=strstr (str, "${"))) {
						char *end = strchr (q+2,'}');
						if (end) {
							*q = *end = 0;
							noff = r_num_math (core->num, q+2);
							r_buf_append_bytes (b, (const ut8*)str, strlen (str));
							snprintf (tmp, sizeof (tmp), "0x%08"PFMT64x, noff);
							r_buf_append_bytes (b, (const ut8*)tmp, strlen (tmp));
							r_buf_append_bytes (b, (const ut8*)end+1, strlen (end+1));
						}
					} else r_buf_append_bytes (b, (const ut8*)str, strlen (str));
				}

				s = r_buf_to_string (b);
				r_egg_load (core->egg, s, 0);
				free (s);
			
				r_egg_compile (core->egg);
				r_egg_assemble (core->egg);

				r_buf_free (b);
				b = r_egg_get_bin (core->egg);

				if (strcmp (off, "+"))
					noff = r_num_math (core->num, off);
				r_core_write_at (core, noff, b->buf, b->length);
				noff += b->length;
				r_buf_free (b);
				free (off);
				}
				break;
			case '"':
				p2 = strchr (p+1,'"');
				if (p2) *p2=0;
				r_core_cmdf (core, "s %s", str);
				r_core_cmdf (core, "\"w %s\"", p+1);
				break;
			case ':':
				r_core_cmdf (core, "s %s", str);
				r_core_cmdf (core, "wa %s", p);
				break;
			default:
				r_core_cmdf (core, "s %s", str);
				r_core_cmdf (core, "wx %s", p);
				break;
			}
		}
	}
	fclose (fd);
	return 0;
}
