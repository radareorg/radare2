/* radare2 - LGPL - Copyright 2009-2019 - nibble, pancake, maijin */

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
	p->notin_flagspace = NULL;
	p->flagspace = NULL;
	p->pseudo = false;
	p->relsub = false;
	p->tailsub = false;
	p->minval = 0x100;
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
				o += strlen (data);
				o[0] = '\n';
				o[1] = '\0';
				o++;
			}
		} while (s);
	}
	free (in);
	return ret;
}

// parse 'data' and generate pseudocode disassemble in 'str'
// TODO: refactooring, this should return char * instead
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
		if (strstr (flag->name, "main") || strstr (flag->name, "entry")) {
			return true;
		}
		if (strchr (flag->name, '.')) {
			return strncmp (flag->name, "section.", 8);
		}
	}
	return false;
}

static char *findNextNumber(char *op) {
	if (!op) {
		return NULL;
	}
	bool ansi_found = false;
	char *p = op;
	const char *o = NULL;
	while (*p) {
		if (p[0] == 0x1b && p[1] == '[') {
			ansi_found = true;
			p += 2;
			for (; *p && *p != 'J' && *p != 'm' && *p != 'H'; p++) {
				;
			}
			if (*p) {
				p++;
				if (!*p) {
					break;
				}
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
				p++;
				if (!*p) {
					break;
				}
				if (!IS_DIGIT (*p)) {
					char *t = p;
					for (; *t && *t != ']'; t++) {
						;
					}
					if (*t == ']') {
						continue;
					}
					p = t;
					if (!*p) {
						break;
					}
				}
			}
			if (is_space && IS_DIGIT (*p)) {
				return p;
			}
			o = p++;
		}
	}
	return NULL;
}

static char *findEnd(const char *s) {
	while (*s == 'x' || IS_HEXCHAR (*s)) {
		s++;
		// also skip ansi escape codes here :?
	}
	return strdup (s);
}

static void insert(char *dst, const char *src) {
	char *endNum = findEnd (dst);
	strcpy (dst, src);
	strcpy (dst + strlen (src), endNum);
	free (endNum);
}

// TODO: move into r_util/r_str
static void replaceWords(char *s, const char *k, const char *v) {
	for (;;) {
		char *p = strstr (s, k);
		if (!p) {
			break;
		}
		char *s = p + strlen (k);
		char *d = p + strlen (v);
		memmove (d, s, strlen (s) + 1);
		memmove (p, v, strlen (v));
		s = p + strlen (v);
	}
}

static void replaceRegisters (RReg *reg, char *s, bool x86) {
	int i;
	for (i = 0; i < 64; i++) {
		const char *k = r_reg_get_name (reg, i);
		if (!k || i == R_REG_NAME_PC) {
			continue;
		}
		const char *v = r_reg_get_role (i);
		if (!v) {
			break;
		}
		if (x86 && *k == 'r') {
			replaceWords (s, k, v);
			char *reg32 = strdup (k);
			*reg32 = 'e';
			replaceWords (s, reg32, v);
		} else {
			replaceWords (s, k, v);
		}
	}
}

static int filter(RParse *p, ut64 addr, RFlag *f, RAnalHint *hint, char *data, char *str, int len, bool big_endian) {
	char *ptr = data, *ptr2, *ptr_backup;
	RAnalFunction *fcn;
	RFlagItem *flag;
	ut64 off;
	bool x86 = false;
	bool arm = false;
	bool computed = false;
	if (p && p->cur && p->cur->name) {
		if (strstr (p->cur->name, "x86")) {
			x86 = true;
		}
		if (strstr (p->cur->name, "m68k")) {
			x86 = true;
		}
		if (strstr (p->cur->name, "arm")) {
			arm = true;
		}
	}
	if (!data || !p) {
		return 0;
	}
#if FILTER_DWORD
	replaceWords (ptr, "dword ", src);
	replaceWords (ptr, "qword ", src);
#endif
	if (p->regsub) {
		replaceRegisters (p->analb.anal->reg, ptr, false);
		if (x86) {
			replaceRegisters (p->analb.anal->reg, ptr, true);
		}
	}
	ptr2 = NULL;
	// remove "dword" 2
	char *nptr;
	int count = 0;
	for (count = 0; (nptr = findNextNumber (ptr)) ; count++) {
		ptr = nptr;
		if (x86) {
			for (ptr2 = ptr; *ptr2 && !isx86separator (*ptr2); ptr2++) {
				;
			}
		} else {
			for (ptr2 = ptr; *ptr2 && (*ptr2 != ']' && (*ptr2 != '\x1b') && !IS_SEPARATOR (*ptr2)); ptr2++) {
				;
			}
		}
		off = r_num_math (NULL, ptr);
		if (off >= p->minval) {
			fcn = p->analb.get_fcn_in (p->analb.anal, off, 0);
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
				flag = p->flag_get (f, off);
				computed = false;
				if ((!flag || arm) && p->relsub_addr) {
					computed = true;
					flag2 = p->flag_get (f, p->relsub_addr);
					if (!flag || arm) {
						flag = flag2;
					}
				}
				if (isvalidflag (flag)) {
					if (p->notin_flagspace) {
						if (p->flagspace == flag->space) {
							continue;
						}
					} else if (p->flagspace && (p->flagspace != flag->space)) {
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
							for (ptr--; ptr > data && *ptr != '['; ptr--) {
								;
							}
							if (ptr == data) {
								ptr = ptr_backup;
							}
						}
					}
					*ptr = 0;
					char *flagname = strdup (f->realnames? flag->realname : flag->name);
					int maxflagname = p->maxflagnamelen;
					if (maxflagname > 0 && strlen (flagname) > maxflagname) {
						char *doublelower = (char *)r_str_rstr (flagname, "__");
						char *doublecolon = (char *)r_str_rstr (flagname, "::");
						char *token = NULL;
						if (doublelower && doublecolon) {
							token = R_MAX (doublelower, doublecolon);
						} else {
							token = doublelower? doublelower: doublecolon;
						}
						if (token) {
							const char *mod = doublecolon? "(cxx)": "(...)";
							char *newstr = r_str_newf ("%s%s", mod, token);
							free (flagname);
							flagname = newstr;
						} else {
							const char *lower = r_str_rstr (flagname, "_");
							char *newstr;
							if (lower) {
								newstr = r_str_newf ("..%s", lower + 1);
							} else {
								newstr = r_str_newf ("..%s", flagname + (strlen (flagname) - maxflagname));
							}
							free (flagname);
							flagname = newstr;
						}
					}
					snprintf (str, len, "%s%s%s", data, flagname, (ptr != ptr2) ? ptr2 : "");
					free (flagname);
					bool banned = false;
					{
						const char *p = strchr (str, '[');
						const char *a = strchr (str, '+');
						const char *m = strchr (str, '*');
						if (p && (a || m)) {
							banned = true;
						}
					}
					if (p->relsub_addr && !banned) {
						int flag_len = strlen (flag->name);
						char *ptr_end = str + strlen (data) + flag_len - 1;
						char *ptr_right = ptr_end + 1, *ptr_left, *ptr_esc;
						bool ansi_found = false;
						if (!*ptr_end) {
							return true;
						}
						while (*ptr_right) {
							if (*ptr_right == 0x1b) {
								while (*ptr_right && *ptr_right != 'm') {
									ptr_right++;
								}
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
								for (; ptr_esc >= str && *ptr_esc != 0x1b; ptr_esc--) {
									;
								}
								if (ptr_esc < str) {
									ptr_esc = ptr_end - flag_len + 1;
								}
								int copied_len = ptr_end - ptr_esc + 1;
								if (copied_len < 1) {
									break;
								}
								memmove (ptr_left, ptr_esc, copied_len);
								char *dptr_left = strcpy (ptr_left + copied_len,
										(ansi_found && ptr_right - ptr_end + 1 >= 4) ? Color_RESET : "");
								int dlen = strlen (dptr_left);
								dptr_left += dlen;
								char *dptr_end = ptr_right + 1;
								while (*dptr_end) {
									dptr_end++;
								}
								int llen = dptr_end - (ptr_right + 1);
								memmove (dptr_left, ptr_right + 1, llen);
								dptr_left[llen] = 0;
							}
							break;
						}
					}
					return true;
				}
				if (p->tailsub) { //  && off > UT32_MAX && addr > UT32_MAX)
					if (off != UT64_MAX) {
						if (off == addr) {
							insert (ptr, "$$");
						} else {
							ut64 tail = r_num_tail_base (NULL, addr, off);
							if (tail != UT64_MAX) {
								char str[128];
								snprintf (str, sizeof (str), "..%"PFMT64x, tail);
								insert (ptr, str);
							}
						}
					}
				}
			}
		}
		if (hint) {
			const int nw = hint->nword;
			if (count != nw) {
				ptr = ptr2;
				continue;
			}
			int pnumleft, immbase = hint->immbase;
			char num[256] = {0}, *pnum, *tmp;
			bool is_hex = false;
			int tmp_count;
			if (hint->offset) {
				*ptr = 0;
				snprintf (str, len, "%s%s%s", data, hint->offset, (ptr != ptr2)? ptr2: "");
				return true;
			}
			strncpy (num, ptr, sizeof (num)-2);
			pnum = num;
			if (!strncmp (pnum, "0x", 2)) {
				is_hex = true;
				pnum += 2;
			}
			for (; *pnum; pnum++) {
				if ((is_hex && IS_HEXCHAR (*pnum)) || IS_DIGIT (*pnum)) {
					continue;
				}
				break;
			}
			*pnum = 0;
			switch (immbase) {
			case 0:
				// do nothing
				break;
			case 1: // hack for ascii
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
						ch = off >> (8 * (sizeof (off) - 1));
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
			case 2:
				r_num_to_bits (num, off);
				strcat (num, "b");
				break;
			case 3:
				{
					ut64 swap = 0;
					if (big_endian) {
						swap = off & 0xffff;
					} else {
						if (off >> 32) {
							r_mem_swapendian ((ut8*)&swap, (const ut8*)&off, sizeof (off));
						} else if (off >> 16) {
							ut32 port = 0;
							r_mem_swapendian ((ut8*)&port, (const ut8*)&off, sizeof (port));
							swap = port;
						} else {
							ut16 port = 0;
							r_mem_swapendian ((ut8*)&port, (const ut8*)&off, sizeof (port));
							swap = port;
						}
					}
					snprintf (num, sizeof (num), "htons (%d)", (int)(swap & 0xFFFF));
				}
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
				if (p && p->analb.anal && p->analb.anal->syscall) {
					RSyscallItem *si;
					si = r_syscall_get (p->analb.anal->syscall, off, -1);
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

R_API char *r_parse_immtrim(char *opstr) {
	if (!opstr || !*opstr) {
		return NULL;
	}
	char *n = strstr (opstr, "0x");
	if (n) {
		char *p = n + 2;
		while (IS_HEXCHAR (*p)) {
			p++;
		}
		memmove (n, p, strlen (p) + 1);
	}
	if (strstr (opstr, " - ]")) {
		opstr = r_str_replace (opstr, " - ]", "]", 1);
	}
	if (strstr (opstr, " + ]")) {
		opstr = r_str_replace (opstr, " + ]", "]", 1);
	}
	if (strstr (opstr, ", ]")) {
		opstr = r_str_replace (opstr, ", ]", "]", 1);
	}
	if (strstr (opstr, " - ")) {
		opstr = r_str_replace (opstr, " - ", "-", 1);
	}
	if (strstr (opstr, " + ")) {
		opstr = r_str_replace (opstr, " + ", "+", 1);
	}
	return opstr;
}

/// filter the opcode in data into str by following the flags and hints information
// XXX this function have too many parameters, we need to simplify this
R_API int r_parse_filter(RParse *p, ut64 addr, RFlag *f, RAnalHint *hint, char *data, char *str, int len, bool big_endian) {
	filter (p, addr, f, hint, data, str, len, big_endian);
	if (p->cur && p->cur->filter) {
		return p->cur->filter (p, addr, f, data, str, len, big_endian);
	}
	return false;
}

R_API char *r_parse_new_filter(RParse *p, ut64 addr, const char *opstr) {
#if 0
	RAnalHint *hint = p->analb.get_hint (p->analb.anal, addr);
	RFlag *f = NULL;
	filter (p, addr, f, hint, data, str, len, big_endian);
	if (p->cur && p->cur->filter) {
		return p->cur->filter (p, addr, f, data, str, len, big_endian);
	}
#endif
	return NULL;
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

/* TODO: DEPRECATE */
R_API int r_parse_list(RParse *p) {
	RListIter *iter;
	RParsePlugin *h;
	r_list_foreach (p->parsers, iter, h) {
		printf ("parse %10s %s\n", h->name, h->desc);
	}
	return false;
}
