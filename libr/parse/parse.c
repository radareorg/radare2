/* radare2 - LGPL - Copyright 2009-2017 - nibble, pancake, maijin */

#include <stdio.h>

#include <r_types.h>
#include <r_parse.h>
#include <config.h>

R_LIB_VERSION (r_parse);

static RParsePlugin *parse_static_plugins[] =
	{ R_PARSE_STATIC_PLUGINS };

R_API RParse *r_parse_new() {
	int i;
	RParse *p = R_NEW0 (RParse);
	if (!p) {
		return NULL;
	}
	p->parsers = r_list_new ();
	if (!p->parsers) {
		r_parse_free (p);
		return NULL;
	}
	p->parsers->free = NULL; // memleak
	p->notin_flagspace = -1;
	p->flagspace = -1;
	p->relsub = false;
	p->localvar_only = false;
	for (i = 0; parse_static_plugins[i]; i++) {
		r_parse_add (p, parse_static_plugins[i]);
	}
	return p;
}

R_API void r_parse_free(RParse *p) {
	r_list_free (p->parsers);
	free (p);
}

R_API int r_parse_add(RParse *p, RParsePlugin *foo) {
	if (foo->init) {
		foo->init (p->user);
	}
	r_list_append (p->parsers, foo);
	return true;
}

R_API int r_parse_use(RParse *p, const char *name) {
	RListIter *iter;
	RParsePlugin *h;
	r_list_foreach (p->parsers, iter, h) {
		if (!strcmp (h->name, name)) {
			p->cur = h;
			return true;
		}
	}
	return false;
}

R_API int r_parse_assemble(RParse *p, char *data, char *str) {
	char *in = strdup (str);
	int ret = false;
	char *s, *o;

	data[0]='\0';
	if (p->cur && p->cur->assemble) {
		o = data + strlen (data);
		do {
			s = strchr (str, ';');
			if (s) {
				*s = '\0';
			}
			ret = p->cur->assemble (p, o, str);
			if (!ret) {
				break;
			}
			if (s) {
				str = s + 1;
				o = o + strlen (data);
				o[0] = '\n';
				o[1] = '\0';
				o++;
			}
		} while (s);
	}
	free (in);
	return ret;
}

R_API int r_parse_parse(RParse *p, const char *data, char *str) {
	if (p->cur && p->cur->parse) {
		return p->cur->parse (p, data, str);
	}
	return false;
}

#define isx86separator(x) ( \
	(x)==' '||(x)=='\t'||(x)=='\n'|| (x)=='\r'||(x)==' '|| \
	(x)==','||(x)==';'||(x)=='['||(x)==']'|| \
	(x)=='('||(x)==')'||(x)=='{'||(x)=='}'||(x)=='\x1b')

static bool isvalidflag(RFlagItem *flag) {
	if (flag) {
		if (strchr (flag->name, '.')) {
			return strncmp (flag->name, "section.", 8);
		}
	}
	return false;
}

static char *findNextNumber(char *op) {
	bool ansi_found = false;
	char *p = op;
	if (p && *p) {
		const char *o = NULL;
		while (*p) {
			if (*p == 0x1b) {
				p++;
				if (!*p) {
					break;
				}
				if (*p == '[') {
					p++;
					if (p[0] && p[1] == ';') {
						// "\x1b[%d;2;%d;%d;%dm", fgbg, r, g, b
						// "\x1b[%d;5;%dm", fgbg, rgb (r, g, b)
						for (; p[0] && p[1] && p[0] != 0x1b && p[1] != '\\'; p++);
						if (p[1] == '\\') p++;
					} else {
						// "\x1b[%dm", 30 + k
						for (; *p && *p != 'J' && *p != 'm' && *p != 'H'; p++);
						if (*p) p++;
					}
					ansi_found = true;
				}
				o = p - 1;
			} else {
				bool is_space = ansi_found;
				ansi_found = false;
				if (!is_space) {
					is_space = p == op;
					if (!is_space && o) {
						is_space = (*o == ' ' || *o == ',' || *o == '[');
					}
				}
				if (*p == '[') {
					char *t = p;
					p++;
					if (!IS_DIGIT (*p)) {
						for (;*t && *t != ']'; t++);
						if (*t == ']') {
							continue;
						} else {
							p = t;
						}
					}
				}
				if (is_space && IS_DIGIT (*p)) {
					return p;
				}
				o = p++;
			}
		}
	}
	return NULL;
}

static int filter(RParse *p, RFlag *f, char *data, char *str, int len, bool big_endian) {
	char *ptr = data, *ptr2, *ptr_backup;
	RAnalFunction *fcn;
	RFlagItem *flag;
	ut64 off;
	bool x86 = false;
	bool computed = false;
	if (p && p->cur && p->cur->name) {
		if (strstr (p->cur->name, "x86")) x86 = true;
		if (strstr (p->cur->name, "m68k")) x86 = true;
	}
	if (!data || !p) {
		return 0;
	}
#if FILTER_DWORD
	ptr2 = strstr (ptr, "dword ");
	if (ptr2) {
		memmove (ptr2, ptr2 + 6, strlen (ptr2 + 6) + 1);
	}
	ptr2 = strstr (ptr, "qword ");
	if (ptr2) {
		memmove (ptr2, ptr2 + 6, strlen (ptr2 + 6) + 1);
	}
#endif
	ptr2 = NULL;
	// remove "dword" 2
	char *nptr;
	while ((nptr = findNextNumber (ptr))) {
#if 0
		char *optr = ptr;
		if (nptr[1]== ' ') {
			for (nptr++;*nptr && *nptr >='0' && *nptr <= '9'; nptr++) {
			}
			ptr = nptr;
			continue;
		}
#endif
		ptr = nptr;
		if (x86) {
			for (ptr2 = ptr; *ptr2 && !isx86separator (*ptr2); ptr2++) {
		//		eprintf ("(%s) (%c)\n", optr, *ptr2);
			}
		} else {
			for (ptr2 = ptr; *ptr2 && (*ptr2 != ']' && (*ptr2 != '\x1b') && !ISSEPARATOR (*ptr2)); ptr2++);
		}
		off = r_num_math (NULL, ptr);
		if (off > 0xff) {
			fcn = p->analb.get_fcn_in (p->anal, off, 0);
			if (fcn && fcn->addr == off) {
				*ptr = 0;
				// hack to realign pointer for colours
				ptr2--;
				if (*ptr2 != 0x1b) {
					ptr2++;
				}
				snprintf (str, len, "%s%s%s", data, fcn->name,
					(ptr != ptr2)? ptr2: "");
				return true;
			}
			if (f) {
				RFlagItem *flag2;
				flag = r_flag_get_i2 (f, off);
				computed = false;
				if (!flag) {
					flag = r_flag_get_i (f, off);
				}
				if (!flag && p->relsub_addr) {
					computed = true;
					flag2 = r_flag_get_i2 (f, p->relsub_addr);
					if (!flag2) {
						flag2 = r_flag_get_i (f, p->relsub_addr);
					}
					if (!flag) {
						flag = flag2;
					}
				}

				if (isvalidflag (flag)) {
					if (p->notin_flagspace != -1) {
						if (p->flagspace == flag->space) {
							continue;
						}
					} else if (p->flagspace != -1 && (p->flagspace != flag->space)) {
						ptr = ptr2;
						continue;
					}
					// hack to realign pointer for colours
					ptr2--;
					if (*ptr2 != 0x1b) {
						ptr2++;
					}
					ptr_backup = ptr;
					if (computed && ptr != ptr2 && *ptr) {
						if (*ptr2 == ']') {
							ptr2++;
							for (ptr--; ptr > data && *ptr != '['; ptr--);
							if (ptr == data) {
								ptr = ptr_backup;
							}
						}
					}
					*ptr = 0;
					snprintf (str, len, "%s%s%s", data, flag->name,
							(ptr != ptr2) ? ptr2 : "");
					bool banned = false;
					{
						const char *p = strchr (str, '[');
						const char *a = strchr (str, '+');
						const char *m = strchr (str, '*');
						if (p && (a || m)) {
							banned = true;
						}
					}
					if (p->relsub_addr && !banned) { // && strstr (str, " + ")) {
						int flag_len = strlen (flag->name);
						char *ptr_end = str + strlen (data) + flag_len - 1;
						char *ptr_right = ptr_end + 1, *ptr_left, *ptr_esc;
						bool ansi_found = false;
						int copied_len;
						while (*ptr_right) {
							if (*ptr_right == 0x1b) {
								while (*ptr_right && *ptr_right != 'm') ptr_right++;
								if (*ptr_right) {
									ptr_right++;
								}
								ansi_found = true;
								continue;
							}
							if (*ptr_right == ']') {
								ptr_left = ptr_esc = ptr_end - flag_len;
								while (ptr_left >= str) {
									if (*ptr_left == '[' &&
									(ptr_left == str || *(ptr_left - 1) != 0x1b)) {
										break;
									}
									ptr_left--;
								}
								if (ptr_left < str) {
									break;
								}
								for (; ptr_esc >= str && *ptr_esc != 0x1b; ptr_esc--);
								if (ptr_esc < str) {
									ptr_esc = ptr_end - flag_len + 1;
								}
								copied_len = ptr_end - ptr_esc + 1;
								memmove (ptr_left, ptr_esc, copied_len);
								sprintf (ptr_left + copied_len, "%s%s",
									 ansi_found && ptr_right - ptr_end + 1 >= 4 ? "\x1b[0m" : "",
									 ptr_right + 1);
							}
							break;
						}
					}
					return true;
				}
			}
		}
		if (p->hint) {
			int pnumleft, immbase = p->hint->immbase;
			char num[256], *pnum, *tmp;
			bool is_hex = false;
			int tmp_count;
			strncpy (num, ptr, sizeof (num)-2);
			pnum = num;
			if (!strncmp (pnum, "0x", 2)) {
				is_hex = true;
				pnum += 2;
			}
			for (; *pnum; pnum++) {
				if ((is_hex && ISHEXCHAR (*pnum)) || IS_DIGIT (*pnum)) {
					continue;
				}
				break;
			}
			*pnum = 0;
			switch (immbase) {
			case 0:
				// do nothing
				break;
			case 1:
				r_num_to_bits (num, off);
				strcat (num, "b");
				break;
			case 2: // hack for ascii
				tmp_count = 0;
				for (tmp = data; tmp < ptr; tmp++) {
					if (*tmp == 0x1b) {
						while (tmp < ptr - 1 && *tmp != 'm') {
							tmp++;
						}
						continue;
					} else if (*tmp == '[') {
						tmp_count++;
					} else if (*tmp == ']') {
						tmp_count--;
					}
				}
				if (tmp_count > 0) {
					ptr = ptr2;
					continue;
				}
				memset (num, 0, sizeof (num));
				pnum = num;
				*pnum++ = '\'';
				pnumleft = sizeof (num) - 2;
				// Convert *off* to ascii string, byte by byte.
				// Since *num* is 256 bytes long, we can omit
				// overflow checks.
				while (off) {
					ut8 ch;
					if (big_endian) {
						ch = off & 0xff;
						off >>= 8;
					} else {
						ch = off >> (8 * (sizeof(off) - 1));
						off <<= 8;
					}

					//Skip first '\x00' bytes
					if (num[1] == '\0' && ch == '\0') {
						continue;
					}
					if (IS_PRINTABLE(ch)) {
						*pnum++ = ch;
						pnumleft --;
					} else {
						int sz = snprintf (pnum, pnumleft, "\\x%2.2x", ch);
						if (sz < 0) {
							break;
						}
						pnum += sz;
						pnumleft -= sz;
					}
				}
				*pnum++ = '\'';
				*pnum = '\0';
				break;
			case 8:
				snprintf (num, sizeof (num), "0%o", (int)off);
				break;
			case 10:
				snprintf (num, sizeof (num), "%" PFMT64d, (st64)off);
				break;
			case 32:
				{
					ut32 ip32 = off;
					ut8 *ip = (ut8*)&ip32;
					snprintf (num, sizeof (num), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
				}
				break;
			case 80:
				if (p && p->anal && p->anal->syscall) {
					RSyscallItem *si;
					si = r_syscall_get (p->anal->syscall, off, -1);
					if (si) {
						snprintf (num, sizeof (num), "%s()", si->name);
					} else {
						snprintf (num, sizeof (num), "unknown()");
					}
				}
				break;
			case 16:
				/* do nothing */
			default:
				snprintf (num, sizeof (num), "0x%"PFMT64x, (ut64) off);
				break;
			}
			*ptr = 0;
			snprintf (str, len, "%s%s%s", data, num, (ptr != ptr2)? ptr2: "");
			return true;
		}
		ptr = ptr2;
	}
	strncpy (str, data, len);
	return false;
}

R_API int r_parse_filter(RParse *p, RFlag *f, char *data, char *str, int len, bool big_endian) {
	filter (p, f, data, str, len, big_endian);
	if (p->cur && p->cur->filter) {
		return p->cur->filter (p, f, data, str, len, big_endian);
	}
	return false;
}

R_API bool r_parse_varsub(RParse *p, RAnalFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	if (p->cur && p->cur->varsub) {
		return p->cur->varsub (p, f, addr, oplen, data, str, len);
	}
	return false;
}

/* setters */
R_API void r_parse_set_user_ptr(RParse *p, void *user) {
	p->user = user;
}

R_API void r_parse_set_flagspace(RParse *p, int fs) {
	p->flagspace = fs;
}

/* TODO: DEPRECATE */
R_API int r_parse_list(RParse *p) {
	RListIter *iter;
	RParsePlugin *h;
	r_list_foreach (p->parsers, iter, h) {
		printf ("parse %10s %s\n", h->name, h->desc);
	}
	return false;
}
