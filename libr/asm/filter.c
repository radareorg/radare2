/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#include <r_asm.h>

#define FILTER_DWORD 0

#define isx86separator(x) ( \
	(x) == ' '||(x) == '\t'||(x) == '\n'|| (x) == '\r'||(x) == ' '|| \
	(x) == ','||(x) == ';'||(x) == '['||(x) == ']'|| \
	(x) == '('||(x) == ')'||(x) == '{'||(x) == '}'||(x) == '\x1b')

static bool isvalidflag(RFlagItem *flag) {
	if (flag) {
		if (flag->space) {
			if (!strcmp (flag->space->name, "format")) {
				return false;
			}
		}
		const char *flag_name = flag->name;
		if (strstr (flag_name, "main") || strstr (flag_name, "entry")) {
			return true;
		}
		if (strchr (flag_name, '.')) {
			return true;
		}
	}
	return false;
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
			bool isSpace = ansi_found;
			ansi_found = false;
			if (!isSpace) {
				isSpace = p == op;
				if (!isSpace && o) {
					isSpace = (*o == ' ' || *o == ',' || *o == '[');
				}
			}
			if (*p == '[') {
				p++;
				if (!*p) {
					break;
				}
				if (!isdigit (*p)) {
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
			if (isSpace) {
				if (isdigit (*p)) {
					return p;
				}
				if ((*p == '-') && isdigit (p[1])) {
					return p + 1;
				}
			}
			o = p++;
		}
	}
	return NULL;
}

static void __replaceRegisters(RReg *reg, char *s, bool x86) {
	int i;
	for (i = 0; i < 64; i++) {
		const char *k = r_reg_alias_getname (reg, i);
		if (!k || i == R_REG_ALIAS_PC) {
			continue;
		}
		const char *v = r_reg_alias_tostring (i);
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

static char *filter(RAsmPluginSession *aps, ut64 addr, RFlag *f, RAnalHint *hint, const char *data) {
	RAsm *a = aps->rasm;
	RParse *p = a->parse;
	char *hdata = strdup (data); // XXX
	char *ptr = hdata;
	const bool big_endian = R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config);
	char *ptr2, *ptr_backup;
	RAnalFunction *fcn;
	RFlagItem *flag;
	ut64 off;
	RArchConfig *ac = R_UNWRAP3 (a, analb.anal, config);
	if (!ac) {
		R_LOG_ERROR ("no anal bind?");
		free (hdata);
		return false;
	}
	const int bits = ac->bits;
	// a->analb.anal->config->bits; /// if we move this api into r_asm, we can use a->config->bits directly
	const int seggrn = ac->seggrn;
	// a->analb.anal->config->seggrn;
	bool x86 = false;
	bool arm = false;
	const char *pname = R_UNWRAP4 (a, cur, plugin, meta.name);
	if (pname) {
		if (r_str_startswith (pname, "x86")) {
			x86 = true;
		} else if (r_str_startswith (pname, "m68k")) {
			x86 = true; /// w t f? trick or wat
		} else if (r_str_startswith (pname, "arm")) {
			arm = true;
		}
	}
	if (!data || !p) {
		free (hdata);
		return 0;
	}
#if FILTER_DWORD
	replaceWords (ptr, "dword ", src);
	replaceWords (ptr, "qword ", src);
#endif
	if (p->subreg) {
		__replaceRegisters (a->analb.anal->reg, ptr, false);
		if (x86) {
			__replaceRegisters (a->analb.anal->reg, ptr, true);
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
		char* colon = strstr (ptr, ":");
		if (x86 && bits == 16 && colon) {
			*colon = '\0';
			ut64 s = r_num_get (NULL, ptr);
			ut64 o = r_num_get (NULL, colon + 1);
			off = (s << seggrn) + o;
			*colon = ':';
		} else {
			off = r_num_get (NULL, ptr);
		}
		if (off >= p->minval) {
			fcn = a->analb.get_fcn_in (a->analb.anal, off, 0);
			if (fcn && fcn->addr == off) {
				*ptr = 0;
				// hack to realign pointer for colours
				ptr2--;
				if (*ptr2 != 0x1b) {
					ptr2++;
				}
				const char *name = fcn->name;
				// TODO: implement realname with flags, because functions dont hold this yet
				if (f->realnames) {
					flag = p->flag_get (f, false, off);
					if (flag && flag->realname) {
						name = flag->realname;
					}
				}
				char *res = r_str_newf ("%s%s%s", hdata, name, (ptr != ptr2)? ptr2: "");
				free (hdata);
				return res;
			}
			if (f) {
				RFlagItem *flag2;
				bool lea = x86 && r_str_startswith (hdata, "lea")
						&& (hdata[3] == ' ' || hdata[3] == 0x1b);
				bool remove_brackets = false;
				flag = p->flag_get (f, false, off);
				if ((!flag || arm) && p->subrel_addr) {
					remove_brackets = lea || (arm && p->subrel_addr);
					flag2 = p->flag_get (f, false, p->subrel_addr);
					if (!flag || arm) {
						flag = flag2;
					}
				}
				if (flag && !strncmp (flag->name, "section.", 8)) {
					flag = r_flag_get_in (f, off);
				}
				const char *label = fcn? p->label_get (fcn, off): NULL;
				if (label || isvalidflag (flag)) {
					if (flag) {
						if (p->notin_flagspace) {
							if (p->flagspace == flag->space) {
								continue;
							}
						} else if (p->flagspace && (p->flagspace != flag->space)) {
							ptr = ptr2;
							continue;
						}
					}
					// hack to realign pointer for colours
					ptr2--;
					if (*ptr2 != 0x1b) {
						ptr2++;
					}
					ptr_backup = ptr;
					if (remove_brackets && ptr != ptr2 && *ptr) {
						if (*ptr2 == ']') {
							ptr2++;
							for (ptr--; ptr > hdata && *ptr != '['; ptr--) {
								;
							}
							if (ptr == hdata) {
								ptr = ptr_backup;
							}
						}
					}
					*ptr = 0;
					char *flagname = label
						? r_str_newf (".%s", label)
						: strdup (f->realnames? flag->realname : flag->name);
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
							char *newstr = lower
								? r_str_newf ("..%s", lower + 1)
								: r_str_newf ("..%s", flagname + (strlen (flagname) - maxflagname));
							free (flagname);
							flagname = newstr;
						}
					}
					char *str = r_str_newf ("%s%s%s", hdata, flagname, (ptr != ptr2) ? ptr2 : "");
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
					if (p->subrel_addr && !banned && lea) {  // TODO: use remove_brackets
						int flag_len = strlen (flag->name);
						char *ptr_end = str + strlen (hdata) + flag_len - 1;
						char *ptr_right = ptr_end + 1, *ptr_left, *ptr_esc;
						bool ansi_found = false;
						if (!*ptr_end) {
							free (hdata);
							return str;
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
					free (hdata);
					return str;
				}
				if (p->subtail) { //  && off > UT32_MAX && addr > UT32_MAX)
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
				char *res = r_str_newf ("%s%s%s", hdata, hint->offset, (ptr != ptr2)? ptr2: "");
				free (hdata);
				return res;
			}
			strncpy (num, ptr, sizeof (num)-2);
			pnum = num;
			if (!strncmp (pnum, "0x", 2)) {
				is_hex = true;
				pnum += 2;
			}
			for (; *pnum; pnum++) {
				if ((is_hex && IS_HEXCHAR (*pnum)) || isdigit (*pnum)) {
					continue;
				}
				break;
			}
			if (bits == 16 && x86 && *pnum == ':') {
				pnum++;
				is_hex = false;
				if (r_str_startswith (pnum, "0x")) {
					is_hex = true;
					pnum += 2;
				}
				for (; *pnum; pnum++) {
					if ((is_hex && IS_HEXCHAR (*pnum)) || isdigit (*pnum)) {
						continue;
					}
					break;
				}
			}
			*pnum = 0;
			switch (immbase) {
			case 0:
				// do nothing
				break;
			case 1: // hack for ascii
				tmp_count = 0;
				for (tmp = hdata; tmp < ptr; tmp++) {
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
				{
					RList *regs = r_reg_get_list (a->analb.anal->reg, R_REG_TYPE_GPR);
					RRegItem *reg;
					RListIter *iter;
					bool imm32 = false;
					r_list_foreach (regs, iter, reg) {
						if (reg->size == 32 && r_str_casestr (hdata, reg->name)) {
							imm32 = true;
							break;
						}
					}
					if (imm32) {
						snprintf (num, sizeof (num), "%"PFMT32d, (st32)off);
						break;
					}
					snprintf (num, sizeof (num), "%"PFMT64d, (st64)off);
				}
				break;
			case 11:
				snprintf (num, sizeof (num), "%"PFMT64u, off);
				break;
			case 31: // small integer
				snprintf (num, sizeof (num), "0x%x", (ut32)(off >> 1));
				break;
			case 32:
				{
					ut8 ip[4] = { off & 0xff, (off >> 8) & 0xff, (off >> 16) & 0xff, (off >> 24) & 0xff };
					snprintf (num, sizeof (num), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
				}
				break;
			case 36:
				{
					char b36str[16];
					b36_fromnum (b36str, off);
					r_str_ncpy (num, b36str, sizeof (num));
				}
				break;
			case 80:
				if (a && a->analb.anal && a->analb.anal->syscall) {
					RSyscallItem *si = r_syscall_get (a->analb.anal->syscall, off, -1);
					if (si) {
						snprintf (num, sizeof (num), "%s()", si->name);
					} else {
						snprintf (num, sizeof (num), "unknown()");
					}
					r_syscall_item_free (si);
				}
				break;
			case 16:
				/* do nothing */
			default:
				snprintf (num, sizeof (num), "0x%"PFMT64x, (ut64) off);
				break;
			}
			*ptr = 0;
			char *res = r_str_newf ("%s%s%s", hdata, num, (ptr != ptr2)? ptr2: "");
			free (hdata);
			return res;
		}
		ptr = ptr2;
	}
	free (hdata);
	return NULL;
}

R_API char *r_asm_parse_filter(RAsm *a, ut64 addr, RFlag *f, RAnalHint *hint, const char *data) {
	RAsmPluginSession *aps = a->cur;
	char *str = filter (aps, addr, f, hint, data);
	if (!str) {
		str = strdup (data);
	}
	// Handle immediate base conversion
	if (hint && hint->immbase && a->config) {
		// Use r_asm_parse_immbase for standard bases (8, 10, 16)
		if (hint->immbase == 8 || hint->immbase == 10 || hint->immbase == 16) {
			char *res = r_asm_parse_immbase (a, str, hint->immbase);
			if (res) {
				free (str);
				str = res;
			}
		}
	}
	RAsmPlugin *ap = R_UNWRAP3 (a, cur, plugin);
	if (ap && ap->filter) {
		char *res = ap->filter (aps, addr, f, str);
		if (res) {
			free (str);
			str = res;
		}
	}
	return str;
}
