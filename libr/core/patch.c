/* radare - LGPL - Copyright 2011-2014 - pancake */

#include <r_core.h>

R_API int r_core_patch_line (RCore *core, char *str) {
	char *p, *q;
	p = strchr (str+1, ' ');
	if (!p)
		return 0;
	*p = 0;
	for (++p; *p==' '; p++); // XXX: skipsspaces here

	switch (*p) {
	case '"':
		  q = strchr (p+1,'"');
		  if (q) *q = 0;
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
	return 1;
}

R_API int r_core_patch (RCore *core, const char *patch) {
	char *p, *p0, *str;
	ut64 noff = 0LL;

	p = p0 = str = strdup (patch);
	if (!p)
		return 0;
	for (; ; p++) {
		/* read until newline */
		if (!*p || *p=='\n') *p++ = 0; else continue;

		switch (*str) {
		case '#':
		case '\n':
		case '\r':
		case '\0':
			break;
		case ':':
			r_core_cmd0 (core, str+1);
			break;
		case '.':
		case '!':
			r_core_cmd0 (core, str);
			break;
		case '{': {
			  char tmp[128];
			  char *s, *q, *off = strdup (str);
			  RBuffer *b = r_buf_new ();

			  str = p;
			  for (;;) {
				  if (*p=='\n') {
					*p++ = 0;
				  } else continue;
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
				  str = p;
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
		default:
			r_core_patch_line (core, str);
			break;
		}
		if (!*p) break;
		str = p;
	}
//	eprintf ("%d\n", *p);
//	eprintf ("Missing newline\n");
	free (p0);
	return 0;
}
