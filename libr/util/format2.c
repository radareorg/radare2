/* radare - LGPL - Copyright 2007-2025 - pancake & Skia */

#include <r_cons.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <r_util/r_num.h>
#include <r_reg.h>

enum {
	PF_PTR_NONE = 0,
	PF_PTR_SEEK = 1,
	PF_PTR_BACK = 2,
	PF_PTR_NULL = 3,
};

#define STRUCTPTR 100
#define NESTEDSTRUCT 1
#define STRUCTFLAG 10000
#define NESTDEPTH 14
#define ARRAYINDEX_COEF 10000
#define MINUSONE ((void *) (size_t) - 1)

#define MUSTSEE (mode & R_PRINT_MUSTSEE && mode & R_PRINT_ISFIELD && ! (mode & R_PRINT_JSON))
#define ISQUIET (mode & R_PRINT_QUIET)
#define MUSTSET (mode & R_PRINT_MUSTSET && mode & R_PRINT_ISFIELD && setval)
#define SEEVALUE (mode & R_PRINT_VALUE)
#define MUSTSEEJSON (mode & R_PRINT_JSON && mode & R_PRINT_ISFIELD)
#define MUSTSEESTRUCT (mode & R_PRINT_STRUCT)

// Extract array element index from size (size encodes both array size and element index)
#define PF_EXTRACT_ELEM(elem, size) \
	do { \
		elem = -1; \
		if (size >= ARRAYINDEX_COEF) { \
			elem = size / ARRAYINDEX_COEF - 1; \
			size %= ARRAYINDEX_COEF; \
		} \
	} while (0)

// Check if current element should be printed (elem = -1 means all, elem = 0 means this one)
#define PF_ELEM_SHOULD_PRINT(elem) ((elem) == -1 || (elem) == 0)

// Update elem after printing: if elem was 0, mark done (-2); if positive, decrement
#define PF_ELEM_ADVANCE(elem) \
	do { \
		if ((elem) == 0) { \
			(elem) = -2; \
		} else if ((elem) > 0) { \
			(elem)--; \
		} \
	} while (0)

// Print array separator if needed (when printing all elements and more remain)
#define PF_PRINT_SEPARATOR(p, size, elem) \
	do { \
		if ((size) != 0 && (elem) == -1) { \
			r_print_printf ((p), ", "); \
		} \
	} while (0)

// should be private. and PrintFormat should return a string, not int
// or maybe we want to return a struct with size too :?

#if __MINGW32__
#ifndef gmtime_r
static struct tm *gmtime_r(const time_t *t, struct tm *r) {
	// surprisingly gmtime on windows is threadsafe in windows
	struct tm *theTm = gmtime (t);
	if (theTm) {
		*r = *theTm;
	}
	return r;
}
#endif // gmtime_r
#endif

// Threshold for encoding actual buffer length in negative range
// When len is in [THRESHOLD-7, THRESHOLD), actual length = len + THRESHOLD
#define THRESHOLD (-4444)

static void pf_print_byte_escape(const RPrint *p, const char *src, char **dst, int dot_nl) {
	R_RETURN_IF_FAIL (p->strconv_mode);
	r_str_byte_escape (src, dst, dot_nl, !strcmp (p->strconv_mode, "asciidot"), p->esc_bslash);
}

// Read float, 32-bit addr, and/or 64-bit addr64 from buffer
// len parameter: either THRESHOLD-encoded actual length, or any other value (treated as "sufficient")
// Only reads at most 8 bytes
static float updateAddr(const ut8 *buf, int len, int endian, ut64 *addr, ut64 *addr64) {
	float f = 0.0;
	if (len >= THRESHOLD - 7 && len < THRESHOLD) {
		len = len + THRESHOLD;
		if (len < 1) {
			return 0;
		}
	} else {
		len = 8;
	}
	if (len >= 4) {
		r_mem_swaporcopy ((ut8 *)&f, buf, sizeof (float), endian);
		if (addr) {
			*addr = (ut64)r_read_ble32 (buf, endian);
		}
	}
	if (addr64 && len >= 8) {
		*addr64 = r_read_ble64 (buf, endian);
	}
	return f;
}

static int r_get_size(RNum *num, ut8 *buf, int endian, const char *s) {
	size_t len = strlen (s);
	if (s[0] == '*' && len >= 4) { // value pointed by the address
		ut64 addr;
		int offset = (int)r_num_math (num, s + 1);
		(void)updateAddr (buf + offset, 4, endian, &addr, NULL);
		return addr;
	}
	// flag handling doesnt seems to work here
	return r_num_math (num, s);
}

static void pf_u128(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const bool endian = pf->endian;
	const int mode = pf->mode;
	PJ *pj = pf->pj;
	ut64 low = r_read_ble64 (buf, endian);
	ut64 hig = r_read_ble64 (buf + 8, endian);
	if (pj) {
		const char *endianstr = endian? "big": "little";
		pj_ks (pj, "endian", endianstr);
		pj_ks (pj, "ctype", "uint128_t");
		if (endian) {
			pj_kn (pj, "low", low);
			pj_kn (pj, "high", hig);
		} else {
			pj_kn (pj, "low", hig);
			pj_kn (pj, "high", low);
		}
	} else {
		const RPrint *p = pf->p;
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = (uint128_t)", seeki);
		}
		if (endian) {
			r_print_printf (p, "0x%016" PFMT64x, low);
			r_print_printf (p, "%016" PFMT64x, hig);
		} else {
			r_print_printf (p, "0x%016" PFMT64x, hig);
			r_print_printf (p, "%016" PFMT64x, low);
		}
	}
}

static void pf_qword(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	ut64 addr64;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, size - i, pf->endian, NULL, &addr64);
	if (MUSTSET) {
		r_print_printf (p, "wv8 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 8: 0));
	} else if (MUSTSEE || MUSTSEESTRUCT) {
		if (!SEEVALUE && !ISQUIET && !MUSTSEESTRUCT) {
			r_print_printf (p, "0x%08" PFMT64x " = (qword)",
				seeki + ((elem >= 0)? elem * 8: 0));
		}
		if (size == -1) {
			if (addr64 == UT32_MAX || ((st64)addr64 < 0 && (st64)addr64 > -4096)) {
				r_print_printf (p, "%d", (int) (addr64));
			} else {
				if (MUSTSEESTRUCT) {
					r_print_printf (p, "%" PFMT64u, addr64);
				} else {
					r_print_printf (p, "0x%016" PFMT64x, addr64);
				}
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, pf->endian, NULL, &addr64);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					if (MUSTSEESTRUCT) {
						r_print_printf (p, "%" PFMT64u, addr64);
					} else {
						r_print_printf (p, "0x%016" PFMT64x, addr64);
					}
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 8;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			pj_kn (pf->pj, "value", addr64);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				updateAddr (buf + i, size - i, pf->endian, NULL, &addr64);
				pj_kn (pf->pj, "value", addr64);
				i += 8;
			}
			pj_end (pf->pj);
		}
	}
}

static void r_print_format_byte(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	const RPrint *p = pf->p;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	if (MUSTSET) {
		r_print_printf (p, "'0x%08" PFMT64x "'w %s\n", setval, seeki + ((elem >= 0)? elem: 0));
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			pj_kn (pf->pj, "value", buf[i]);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				pj_n (pf->pj, buf[i]);
				i++;
			}
			pj_end (pf->pj);
		}
	} else if (MUSTSEESTRUCT) {
		if (size == -1) {
			r_print_printf (p, "%d", buf[i]);
		} else {
			while (size--) {
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "0x%02x", buf[i]);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i++;
			}
		}
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem: 0));
		}
		if (size == -1) {
			r_print_printf (p, "0x%02x", buf[i]);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "0x%02x", buf[i]);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i++;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	}
}

// Return number of consumed bytes
static int pf_uleb(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size, int len) {
	RPrint *p = pf->p;
	const int mode = pf->mode;
	int s = 0, offset = 0;
	ut64 value = 0;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	if (MUSTSET) {
		ut8 *tmp;
		char *nbr;
		do {
			s = read_u64_leb128 (buf + i, buf + len, &value);
			if (s < 1) {
				break;
			}
			i += s;
			offset += s;
		} while (elem--);
		tmp = (ut8 *)r_uleb128_encode (r_num_math (NULL, setval), &s);
		nbr = r_hex_bin2strdup (tmp, s);
		r_print_printf (p, "\"wx %s\" @ 0x%08" PFMT64x "\n", nbr, seeki + offset - s);
		free (tmp);
		free (nbr);
	} else if (MUSTSEE || MUSTSEESTRUCT) {
		if (!SEEVALUE && !ISQUIET && !MUSTSEESTRUCT) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
		}
		if (size == -1) {
			offset = read_u64_leb128 (buf + i, buf + len, &value);
			if (offset < 1) {
				return 0;
			}
			r_print_printf (p, "%" PFMT64d, value);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					s = read_u64_leb128 (buf + i, buf + len, &value);
					if (s < 1) {
						break;
					}
					i += s;
					offset += s;
					r_print_printf (p, "%" PFMT64d, value);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					r_print_printf (p, ", ");
				}
				if (elem > -1) {
					elem--;
				}
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			offset = read_u64_leb128 (buf + i, buf + len, &value);
			if (offset < 1) {
				return 0;
			}
			pj_kn (pf->pj, "value", value);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				s = read_u64_leb128 (buf + i, buf + len, &value);
				if (s < 1) {
					break;
				}
				i += s;
				offset += s;
				pj_n (pf->pj, value);
			}
			pj_end (pf->pj);
		}
	}
	return offset;
}

static void r_print_format_char(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	const RPrint *p = pf->p;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	if (MUSTSET) {
		r_print_printf (p, "\"w %s\" @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem: 0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem: 0));
		}
		if (size == -1) {
			r_print_printf (p, "'%c'", IS_PRINTABLE (buf[i])? buf[i]: '.');
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "'%c'", IS_PRINTABLE (buf[i])? buf[i]: '.');
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i++;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEESTRUCT) {
		if (!SEEVALUE) {
			r_print_printf (p, "[ ");
		}
		if (size == -1) {
			r_print_printf (p, "'%c'", IS_PRINTABLE (buf[i])? buf[i]: '.');
		} else {
			while (size--) {
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "'%c'", IS_PRINTABLE (buf[i])? buf[i]: '.');
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i++;
			}
		}
		if (!SEEVALUE) {
			r_print_printf (p, " ]");
		}
	} else if (MUSTSEEJSON) {
		char chars[2] = { 0 };
		if (size == -1) {
			chars[0] = buf[i];
			pj_ks (pf->pj, "value", chars);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				chars[0] = buf[i];
				pj_s (pf->pj, chars);
				i++;
			}
			pj_end (pf->pj);
		}
	}
}

static void r_print_format_decchar(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	RPrint *p = pf->p;
	const int mode = pf->mode;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	if (MUSTSET) {
		r_print_printf (p, "\"w %s\" @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem: 0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem: 0));
		}
		if (size == -1) {
			r_print_printf (p, "%d", buf[i]);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%d", buf[i]);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i++;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			pj_kn (pf->pj, "value", buf[i]);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				pj_n (pf->pj, buf[i]);
				i++;
			}
			pj_end (pf->pj);
		}
	}
}

static int pf_string(RPrintFormat *pf, ut64 seeki, ut64 addr64, ut64 addr, int is64) {
	int mode = pf->mode;
	RPrint *p = pf->p;
	ut8 buffer[255];
	memset (buffer, 0, sizeof (buffer));
	if (!p->iob.read_at) {
		R_LOG_ERROR ("(cannot read memory)");
		return -1;
	}
	ut64 at = (is64 == 1)? addr64: (ut64)addr;
	if (p->iob.io && p->iob.io->va) {
		if (p->iob.v2p) {
			ut64 pa = p->iob.v2p (p->iob.io, at);
			if (pa != UT64_MAX) {
				at = pa;
			}
		} else if (p->iob.map_get_at) {
			RIOMap *map = p->iob.map_get_at (p->iob.io, at);
			if (map) {
				ut64 vbegin = map->itv.addr;
				if (at >= vbegin) {
					at = at - vbegin + map->delta;
				}
			} else {
				return 0;
			}
		}
	}
	int res = p->iob.read_at (p->iob.io, at, buffer, sizeof (buffer) - 8);
	if (res > 0 && p->iob.addr_is_mapped && !p->iob.addr_is_mapped (p->iob.io, at)) {
		res = -1;
	}
	if (res > 0) {
		int limit = R_MIN (res, 8);
		bool all_ff = true;
		int j;
		for (j = 0; j < limit; j++) {
			if (buffer[j] != 0xff) {
				all_ff = false;
				break;
			}
		}
		if (all_ff) {
			res = -1;
		}
	}
	if (res <= 0 && p->iob.v2p) {
		ut64 pa = p->iob.v2p (p->iob.io, at);
		if (pa != UT64_MAX) {
			at = pa;
			res = p->iob.read_at (p->iob.io, at, buffer, sizeof (buffer) - 8);
		}
	}
	if (res <= 0) {
		buffer[0] = 0;
	} else {
		int limit = R_MIN (res, 8);
		bool all_ff = true;
		int j;
		for (j = 0; j < limit; j++) {
			if (buffer[j] != 0xff) {
				all_ff = false;
				break;
			}
		}
		if (all_ff) {
			buffer[0] = 0;
		}
	}
	if (MUSTSEEJSON) {
		pj_ks (pf->pj, "string", (const char *)buffer);
	} else if (MUSTSEESTRUCT) {
		char *encstr = r_str_utf16_encode ((const char *)buffer, -1);
		if (encstr) {
			r_print_printf (p, "\"%s\"", encstr);
			free (encstr);
		}
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
		}
		if (!SEEVALUE) {
			if (ISQUIET) {
				if (addr == 0LL) {
					r_print_printf (p, "NULL");
				} else if (addr == UT32_MAX || addr == UT64_MAX) {
					r_print_printf (p, "-1");
				} else {
					r_print_printf (p, "0x%08" PFMT64x " ", addr);
				}
			} else {
				r_print_printf (p, "0x%08" PFMT64x " -> 0x%08" PFMT64x " ", seeki, addr);
			}
		}
		if (res > 0 && buffer[0] != 0xff && buffer[1] != 0xff) {
			r_print_printf (p, "\"%s\"", buffer);
		}
	}
	return 0;
}

static void pf_time(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const RPrint *p = pf->p;
	const int endian = pf->endian;
	const int mode = pf->mode;
	ut64 addr;
	struct tm timestruct;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
	} else if (MUSTSEE) {
		char *timestr = malloc (ASCTIME_BUF_MAXLEN);
		if (!timestr) {
			return;
		}
		r_asctime_r (gmtime_r ((time_t *)&addr, &timestruct), timestr);
		*(timestr + 24) = '\0';
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * 4: 0));
		}
		if (size == -1) {
			r_print_printf (p, "%s", timestr);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				r_asctime_r (gmtime_r ((time_t *)&addr, &timestruct), timestr);
				timestr[24] = 0;
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%s", timestr);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
		free (timestr);
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		char *timestr = malloc (ASCTIME_BUF_MAXLEN);
		if (timestr) {
			if (size == -1) {
				r_asctime_r (gmtime_r ((time_t *)&addr, &timestruct), timestr);
				timestr[24] = 0;
				pj_ks (pf->pj, "value", timestr);
			} else {
				pj_a (pf->pj);
				while (size--) {
					updateAddr (buf + i, size - i, endian, &addr, NULL);
					r_asctime_r (gmtime_r ((time_t *)&addr, &timestruct), timestr);
					timestr[24] = '\0';
					pj_s (pf->pj, timestr);
					i += 4;
				}
				pj_end (pf->pj);
			}
			free (timestr);
		}
	}
}

// TODO: support unsigned int?
static void r_print_format_hex(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	RPrint *p = pf->p;
	const int mode = pf->mode;
	const int endian = pf->endian;
	ut64 addr;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, size - i, pf->endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
	} else if (mode & R_PRINT_DOT) {
		r_print_printf (p, "0x%08" PFMT64x, addr);
	} else if (MUSTSEESTRUCT) {
		r_print_printf (p, "0x%08" PFMT64x, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * 4: 0));
		}
		if (size == -1) {
			if (addr == UT64_MAX || addr == UT32_MAX) {
				r_print_printf (p, "-1");
			} else {
				r_print_printf (p, "0x%08" PFMT64x, addr);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					if (ISQUIET) {
						if (addr == UT64_MAX || addr == UT32_MAX) {
							r_print_printf (p, "-1");
						} else {
							r_print_printf (p, "0x%08" PFMT64x, addr);
						}
					} else {
						r_print_printf (p, "0x%08" PFMT64x, addr);
					}
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			pj_kn (pf->pj, "value", addr);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				updateAddr (buf + i, size - i, pf->endian, &addr, NULL);
				pj_n (pf->pj, addr);
				i += 4;
			}
			pj_end (pf->pj);
		}
	}
}

static void pf_int(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	const int endian = pf->endian;
	ut64 addr;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ %" PFMT64d "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
	} else if (MUSTSEESTRUCT) {
		r_print_printf (p, "0x%08" PFMT64x, addr);
	} else if (mode & R_PRINT_DOT) {
		r_print_printf (p, "0x%08" PFMT64x, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * 4: 0));
		}
		if (size == -1) {
			r_print_printf (p, "%" PFMT64d, (st64) (st32)addr);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%" PFMT64d, (st64) (st32)addr);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			pj_kn (pf->pj, "value", addr);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				pj_n (pf->pj, addr);
				i += 4;
			}
			pj_end (pf->pj);
		}
	}
}

static int r_print_format_disasm(const RPrint *p, ut64 seeki, int size) {
	ut64 prevs = seeki;
	if (!p->disasm || !p->user) {
		return 0;
	}
	size = R_MAX (1, size);
	while (size-- > 0) {
		seeki += p->disasm (p->user, seeki);
	}
	return seeki - prevs;
}

static void r_print_format_octal(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	const int endian = pf->endian;
	ut64 addr;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "0%" PFMT64o, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * 4: 0));
		}
		if (!SEEVALUE) {
			r_print_printf (p, "(octal) ");
		}
		if (size == -1) {
			r_print_printf (p, " 0%08" PFMT64o, addr);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "0%08" PFMT64o, addr);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			pj_kn (pf->pj, "value", addr);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				pj_n (pf->pj, addr);
				i += 4;
			}
			pj_end (pf->pj);
		}
	}
}

static void pf_hexflag(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	RPrint *p = pf->p;
	const int endian = pf->endian;
	const int mode = pf->mode;
	ut64 addr = 0;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "0x%08" PFMT64x, addr & UT32_MAX);
	} else if (pf->pj) {
		if (size == -1) {
			pj_kn (pf->pj, "value", addr);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				pj_n (pf->pj, addr);
				i += 4;
			}
			pj_end (pf->pj);
		}
	} else if (MUSTSEE) {
		ut32 addr32 = (ut32)addr;
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * 4: 0));
		}
		if (size == -1) {
			if (ISQUIET && (addr32 == UT32_MAX)) {
				r_print_printf (p, "-1");
			} else {
				r_print_printf (p, "0x%08" PFMT64x, (ut64)addr32);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "0x%08" PFMT64x, addr);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	}
}

static int r_print_format_10bytes(RPrintFormat *pf, const char *setval, ut64 seeki, ut64 addr, ut8 *buf) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	ut8 buffer[255];
	int j;
	if (MUSTSET) {
		r_print_printf (p, "?e pf B not yet implemented\n");
	} else if (mode & R_PRINT_DOT) {
		for (j = 0; j < 10; j++) {
			r_print_printf (p, "%02x ", buf[j]);
		}
	} else if (MUSTSEE) {
		if (!p->iob.read_at) {
			r_print_printf (p, "(cannot read memory)\n");
			return -1;
		}
		p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
		}
		for (j = 0; j < 10; j++) {
			r_print_printf (p, "%02x ", buf[j]);
		}
		if (!SEEVALUE) {
			r_print_printf (p, " ... (");
		}
		for (j = 0; j < 10; j++) {
			if (!SEEVALUE) {
				if (IS_PRINTABLE (buf[j])) {
					r_print_printf (p, "%c", buf[j]);
				} else {
					r_print_printf (p, ".");
				}
			}
		}
		if (!SEEVALUE) {
			r_print_printf (p, ")");
		}
	} else if (MUSTSEEJSON) {
		if (!p->iob.read_at) {
			R_LOG_ERROR ("Read callback not set");
			return -1;
		}
		pj_ka (pf->pj, "values");
		(void)p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		for (j = 0; j < 10; j++) {
			pj_n (pf->pj, buf[j]);
		}
		pj_end (pf->pj);
	}
	return 0;
}

static int r_print_format_hexpairs(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const RPrint *p = pf->p;
	const int mode = pf->mode;
	int j;
	if (size == -1) {
		size = 1;
	}
	if (MUSTSET) {
		r_print_printf (p, "?e pf X not yet implemented\n");
	} else if (mode & R_PRINT_DOT) {
		for (j = 0; j < size; j++) {
			r_print_printf (p, "%02x", buf[i + j]);
		}
	} else if (MUSTSEE) {
		if (size < 1) {
			size = 1;
		}
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
		}
		for (j = 0; j < size; j++) {
			r_print_printf (p, "%02x ", buf[i + j]);
		}
		if (!SEEVALUE) {
			r_print_printf (p, " ... (");
		}
		for (j = 0; j < size; j++) {
			if (!SEEVALUE) {
				if (IS_PRINTABLE (buf[j])) {
					r_print_printf (p, "%c", buf[i + j]);
				} else {
					r_print_printf (p, ".");
				}
			}
		}
		r_print_printf (p, ")");
	} else if (pf->pj) {
		pj_ka (pf->pj, "values");
		for (j = 0; j < size; j++) {
			pj_n (pf->pj, buf[i + j]);
		}
		pj_end (pf->pj);
	} else if (MUSTSEESTRUCT) {
		if (size < 1) {
			size = 1;
		}
		r_print_printf (p, "[ %d", buf[0]);
		j = 1;
		for (; j < 10; j++) {
			r_print_printf (p, ", %d", buf[j]);
		}
		r_print_printf (p, " ]");
	}
	return size;
}

static void r_print_format_float(RPrintFormat *pf, const char *setval, ut64 seeki, const ut8 *buf, int i, int size) {
	RPrint *p = pf->p;
	const int endian = pf->endian;
	const int mode = pf->mode;
	ut64 addr = 0;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	float val_f = updateAddr (buf + i, 4, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval,
			seeki + ((elem >= 0)? elem * 4: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.9g", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08" PFMT64x " = ",
					seeki + ((elem >= 0)? elem * 4: 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.9g", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				val_f = updateAddr (buf + i, 4, endian, &addr, NULL);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%.9g", val_f);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	}
}

static void r_print_format_bf16(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	RPrint *p = pf->p;
	const int endian = pf->endian;
	const int mode = pf->mode;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	ut16 val_u16 = r_read_ble16 (buf + i, endian);
	float val_f = r_num_bf16_to_float (val_u16);
	if (MUSTSET) {
		r_print_printf (p, "wv2 %s @ 0x%08" PFMT64x "\n", setval,
			seeki + ((elem >= 0)? elem * 2: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.9g", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08" PFMT64x " = ",
					seeki + ((elem >= 0)? elem * 2: 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.9g", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				val_u16 = r_read_ble16 (buf + i, endian);
				val_f = r_num_bf16_to_float (val_u16);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%.9g", val_f);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 2;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	}
}

static void r_print_format_double(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	const RPrint *p = pf->p;
	const int endian = pf->endian;
	double val_f = 0.0;
	ut64 addr = 0;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, 8, endian, &addr, NULL);
	r_mem_swaporcopy ((ut8 *)&val_f, buf + i, sizeof (double), endian);
	if (MUSTSET) {
		r_print_printf (p, "wv8 %s @ 0x%08" PFMT64x "\n", setval,
			seeki + ((elem >= 0)? elem * 8: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.17lg", val_f);
	} else if (pf->pj) {
		if (size == -1) {
			pj_kd (pf->pj, "value", val_f);
			// r_print_printf (p, "%.17lg", val_f);
		} else {
			pj_ka (pf->pj, "values");
			while (size--) {
				updateAddr (buf + i, 8, endian, &addr, NULL);
				r_mem_swaporcopy ((ut8 *)&val_f, buf + i, sizeof (double), endian);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					pj_d (pf->pj, val_f);
				}
				PF_ELEM_ADVANCE (elem);
				i += 8;
			}
			pj_end (pf->pj);
		}
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08" PFMT64x " = ",
					seeki + ((elem >= 0)? elem * 8: 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.17lg", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, 8, endian, &addr, NULL);
				r_mem_swaporcopy ((ut8 *)&val_f, buf + i, sizeof (double), endian);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%.17lg", val_f);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 8;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	}
}

static void r_print_format_long_double(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
#if R2_NO_LONG_DOUBLE
	// just fallback to double
	r_print_format_double (pf, setval, seeki, buf, i, size);
#else
	RPrint *p = pf->p;
	const int endian = pf->endian;
	const int mode = pf->mode;
	long double val_f = 0.0;
	ut64 addr = 0;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	updateAddr (buf + i, 16, endian, &addr, NULL);
	r_mem_swaporcopy ((ut8 *)&val_f, buf + i, sizeof (long double), endian);
	if (MUSTSET) {
		r_print_printf (p, "wv8 %s @ 0x%08" PFMT64x "\n", setval,
			seeki + ((elem >= 0)? elem * 8: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.17Lg", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08" PFMT64x " = ",
					seeki + ((elem >= 0)? elem * 8: 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.17Lg", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, 16, endian, &addr, NULL);
				r_mem_swaporcopy ((ut8 *)&val_f, buf + i, sizeof (long double), endian);
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "%.17Lg", val_f);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 8;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	}
#endif
}

static void r_print_format_word(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int size, bool sign) {
	const int endian = pf->endian;
	const int mode = pf->mode;
	RPrint *p = pf->p;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	ut64 addr = endian
		? (*(buf + i)) << 8 | (*(buf + i + 1))
		: (*(buf + i + 1)) << 8 | (*(buf + i));
	if (MUSTSET) {
		r_print_printf (p, "wv2 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 2: 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		if (size == -1) {
			if (sign) {
				r_print_printf (p, "%d", (int) (short)addr);
			} else {
				r_print_printf (p, "0x%04" PFMT64x, addr);
			}
		}
		while ((size -= 2) > 0) {
			addr = endian
				? (*(buf + i)) << 8 | (*(buf + i + 1))
				: (*(buf + i + 1)) << 8 | (*(buf + i));
			if (sign) {
				addr = (st64) (short)addr;
			}
			if (PF_ELEM_SHOULD_PRINT (elem)) {
				r_print_printf (p, "%" PFMT64d, addr);
			}
			PF_ELEM_ADVANCE (elem);
			PF_PRINT_SEPARATOR (p, size, elem);
			i += 2;
		}
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * 2: 0));
		}
		if (size == -1) {
			if (sign) {
				r_print_printf (p, "%" PFMT64d, (st64) (short)addr);
			} else {
				r_print_printf (p, "0x%04" PFMT64x, addr);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				addr = endian
					? (*(buf + i)) << 8 | (*(buf + i + 1))
					: (*(buf + i + 1)) << 8 | (*(buf + i));
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_printf (p, "0x%04" PFMT64x, addr);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += 2;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			pj_kn (pf->pj, "value", addr);
		} else {
			pj_ka (pf->pj, "values");
			while ((size -= 2) > 0) {
				addr = endian
					? (buf[i]) << 8 | (buf[i + 1])
					: (buf[i + 1]) << 8 | buf[i];
				pj_n (pf->pj, addr);
				i += 2;
			}
			pj_end (pf->pj);
		}
	}
}

static void r_print_format_nulltermstring(RPrintFormat *pf, int len, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	RPrint *p = pf->p;
	const int mode = pf->mode;
	if (!p->iob.is_valid_offset (p->iob.io, seeki, 1)) {
		ut8 ch = 0xff; // oxFF use io->oxff here?
		// XXX there are some cases where the memory is there but is_valid_offset fails wtf
		if (p->iob.read_at (p->iob.io, seeki, &ch, 1) != 1 && ch != 0xff) {
			if (MUSTSEEJSON) {
				pj_kb (pf->pj, "readerror", true);
			}
			return;
		}
	}
	if (p->flags & R_PRINT_FLAGS_UNALLOC && ! (p->iob.io->cache.mode & R_PERM_R)) {
		ut64 total_map_left = 0;
		ut64 addr = seeki;
		RIOMap *map;
		while (total_map_left < len && (map = p->iob.io->va? p->iob.map_get_at (p->iob.io, addr): p->iob.map_get_paddr (p->iob.io, addr)) && map->perm & R_PERM_R) {
			if (!r_io_map_size (map)) {
				total_map_left = addr == 0
					? UT64_MAX
					: UT64_MAX - addr + 1;
				break;
			}
			total_map_left += r_io_map_size (map) - (addr - (p->iob.io->va? r_io_map_begin (map): map->delta));
			addr += total_map_left;
		}
		if (total_map_left < len) {
			len = total_map_left;
		}
	}
	int str_len = r_str_nlen ((char *)buf + i, len - i);
	bool overflow = (size == -1 || size > len - i) && str_len == len - i;
	if (MUSTSET) {
		int buflen = strlen ((const char *)buf + i);
		int vallen = strlen (setval);
		char *ons, *newstring = ons = strdup (setval);
		if ((newstring[0] == '\"' && newstring[vallen - 1] == '\"') || (newstring[0] == '\'' && newstring[vallen - 1] == '\'')) {
			newstring[vallen - 1] = '\0';
			newstring++;
			vallen -= 2;
		}
		if (vallen > buflen) {
			R_LOG_WARN ("new string is longer than previous one");
		}
		r_print_printf (p, "wx ");
		for (i = 0; i < vallen; i++) {
			if (i < vallen - 3 && newstring[i] == '\\' && newstring[i + 1] == 'x') {
				r_print_printf (p, "%c%c", newstring[i + 2], newstring[i + 3]);
				i += 3;
			} else {
				r_print_printf (p, "%2x", newstring[i]);
			}
		}
		r_print_printf (p, " @ 0x%08" PFMT64x "\n", seeki);
		free (ons);
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		int j = i;
		(MUSTSEESTRUCT)? r_print_printf (p, "\""): r_print_printf (p, "\\\"");
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]); j++) {
			char ch = buf[j];
			if (ch == '"') {
				r_print_printf (p, "\\\"");
			} else if (IS_PRINTABLE (ch)) {
				r_print_printf (p, "%c", ch);
			} else {
				r_print_printf (p, ".");
			}
		}
		(MUSTSEESTRUCT)? r_print_printf (p, "\""): r_print_printf (p, "\\\"");
	} else if (MUSTSEE) {
		int j = i;
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = %s", seeki, overflow? "ovf ": "");
		}
		r_print_printf (p, "\"");
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]); j++) {
			char esc_str[5] = { 0 };
			char *ptr = esc_str;
			pf_print_byte_escape (p, (char *)&buf[j], &ptr, false);
			r_print_printf (p, "%s", esc_str);
		}
		r_print_printf (p, "\"");
	} else if (MUSTSEEJSON) {
		int maxlen = str_len;
		if (size != -1 && size < maxlen) {
			maxlen = size;
		}
		char *s = r_str_ndup ((const char *)buf + i, maxlen);
		pj_ks (pf->pj, "value", s);
		free (s);
		if (overflow) {
			pj_kb (pf->pj, "overflow", true);
		}
	}
}

static void r_print_format_nulltermwidestring(RPrintFormat *pf, const int len, const char *setval, ut64 seeki, ut8 *buf, int i, int size) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	if (MUSTSET) {
		int vallen = strlen (setval);
		char *newstring, *ons;
		newstring = ons = strdup (setval);
		if ((newstring[0] == '\"' && newstring[vallen - 1] == '\"') || (newstring[0] == '\'' && newstring[vallen - 1] == '\'')) {
			newstring[vallen - 1] = '\0';
			newstring++;
			vallen -= 2;
		}
		if ((size = vallen) > r_wstr_clen ((char *) (buf + seeki))) {
			R_LOG_WARN ("new string is longer than previous one");
		}
		r_print_printf (p, "ww %s @ 0x%08" PFMT64x "\n", newstring, seeki);
		free (ons);
	} else if (MUSTSEE) {
		int j = i;
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
		}
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]); j += 2) {
			if (IS_PRINTABLE (buf[j])) {
				r_print_printf (p, "%c", buf[j]);
			} else {
				r_print_printf (p, ".");
			}
		}
	} else if (MUSTSEEJSON) {
		pj_ks (pf->pj, "value", (const char *)buf);
	}
}

static void r_print_format_bitfield(RPrintFormat *pf, ut64 seeki, char *fmtname, char *fieldname, ut64 addr, int size) {
	const RPrint *p = pf->p;
	const int mode = pf->mode;
	const ut32 max_shift = (sizeof (ut64) * 8U) - 1;
	if (size <= 0 || size >= 8) {
		addr = 0;
	} else {
		ut32 shift = (ut32)size * 8U;
		if (shift > max_shift) {
			shift = max_shift;
		}
		addr &= (1ULL << shift) - 1;
	}
	if (MUSTSEE && !SEEVALUE) {
		r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
	}
	char *bitfield = r_type_enum_getbitfield (p->sdb_types, fmtname, addr);
	if (R_STR_ISNOTEMPTY (bitfield)) {
		if (MUSTSEEJSON) {
			pj_ks (pf->pj, "value", bitfield);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (bitfield) = %s\n", fieldname, bitfield);
		}
	} else {
		if (MUSTSEEJSON) {
			r_print_printf (p, "\"`tb %s 0x%" PFMT64x "`\"", fmtname, addr);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (bitfield) = `tb %s 0x%" PFMT64x "`\n",
				fieldname, fmtname, addr);
		}
	}
	if (!MUSTSEESTRUCT && MUSTSEE) {
		r_print_printf (p, "\n");
	}
	free (bitfield);
}

static void r_print_format_enum(RPrintFormat *pf, ut64 seeki, char *fmtname, char *fieldname, ut64 addr, int size) {
	const int mode = pf->mode;
	const RPrint *p = pf->p;
	R_RETURN_IF_FAIL (p && fmtname && fieldname);
	if (size >= 8) {
		// avoid shift overflow
	} else {
		addr &= (1ULL << (size * 8)) - 1;
	}
	if (MUSTSEE && !SEEVALUE) {
		r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
	}
	char *enumvalue = r_type_enum_member (p->sdb_types, fmtname, NULL, addr);
	if (R_STR_ISNOTEMPTY (enumvalue)) {
		if (mode & R_PRINT_DOT) {
			r_print_printf (p, "%s.%s", fmtname, enumvalue);
		} else if (MUSTSEEJSON) {
			pj_kn (pf->pj, "value", addr);
			pj_ks (pf->pj, "label", enumvalue);
			pj_ks (pf->pj, "enum", fmtname);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (enum %s) = 0x%" PFMT64x " ; %s\n",
				fieldname, fmtname, addr, enumvalue);
		} else if (MUSTSEESTRUCT) {
			r_print_printf (p, "%s", enumvalue);
		}
	} else {
		if (MUSTSEEJSON) {
			//		r_print_printf (p, "%"PFMT64d",\"enum\":\"%s\"}", addr, fmtname);
			pj_kn (pf->pj, "value", addr);
			pj_ks (pf->pj, "enum", fmtname);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (enum %s) = 0x%" PFMT64x "\n", //`te %s 0x%x`\n",
				fieldname, fmtname, addr); // enumvalue); //fmtname, addr);
		}
	}
	free (enumvalue);
}

static void r_print_format_register(RPrintFormat *pf, const char *name, const char *setval) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	if (!p || !p->get_register || !p->reg) {
		return;
	}
	RRegItem *ri = p->get_register (p->reg, name, R_REG_TYPE_ALL);
	if (ri) {
		if (MUSTSET) {
			r_print_printf (p, "dr %s=%s\n", name, setval);
		} else if (MUSTSEE) {
			if (!SEEVALUE) {
				r_print_printf (p, "%s : 0x%08" PFMT64x "\n", ri->name, p->get_register_value (p->reg, ri));
			} else {
				r_print_printf (p, "0x%08" PFMT64x "\n", p->get_register_value (p->reg, ri));
			}
		} else if (MUSTSEEJSON) {
			pj_kn (pf->pj, "value", p->get_register_value (p->reg, ri));
		}
	} else {
		r_print_printf (p, "Register %s does not exists\n", name);
	}
}

static void r_print_format_num_specifier(const RPrint *p, ut64 addr, int bytes, int sign) {
#define EXT(T) (sign? (signed T) (addr): (unsigned T) (addr))
	const char *fs64 = sign? "%" PFMT64d: "%" PFMT64u;
	const char *fs = sign? "%d": "%u";
	if (bytes == 1) {
		r_print_printf (p, fs, EXT (char));
	} else if (bytes == 2) {
		r_print_printf (p, fs, EXT (short));
	} else if (bytes == 4) {
		r_print_printf (p, fs, EXT (int)); // XXX: int is not necessarily 4 bytes I guess.
	} else if (bytes == 8) {
		r_print_printf (p, fs64, addr);
	}
#undef EXT
}

static void r_print_format_num(RPrintFormat *pf, const char *setval, ut64 seeki, ut8 *buf, int i, int bytes, int sign, int size) {
	RPrint *p = pf->p;
	const int endian = pf->endian;
	const int mode = pf->mode;
	ut64 addr = 0LL;
	int elem;
	PF_EXTRACT_ELEM (elem, size);
	if (bytes == 8) {
		updateAddr (buf + i, size - i, endian, NULL, &addr);
	} else {
		updateAddr (buf + i, size - i, endian, &addr, NULL);
	}
	if (MUSTSET) {
		r_print_printf (p, "wv%d %s @ 0x%08" PFMT64x "\n", bytes, setval, seeki + ((elem >= 0)? elem *(bytes): 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_format_num_specifier (p, addr, bytes, sign);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0)? elem * bytes: 0));
		}
		if (size == -1) {
			r_print_format_num_specifier (p, addr, bytes, sign);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (bytes == 8) {
					updateAddr (buf + i, size - i, endian, NULL, &addr);
				} else {
					updateAddr (buf + i, size - i, endian, &addr, NULL);
				}
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_format_num_specifier (p, addr, bytes, sign);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += bytes;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			r_print_format_num_specifier (p, addr, bytes, sign);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				if (bytes == 8) {
					updateAddr (buf + i, size, endian, NULL, &addr);
				} else {
					updateAddr (buf + i, size, endian, &addr, NULL);
				}
				if (PF_ELEM_SHOULD_PRINT (elem)) {
					r_print_format_num_specifier (p, addr, bytes, sign);
				}
				PF_ELEM_ADVANCE (elem);
				PF_PRINT_SEPARATOR (p, size, elem);
				i += bytes;
			}
			r_print_printf (p, " ]");
		}
	}
}

static int r_print_format_struct(RPrintFormat *pf, ut64 seek, const ut8 *b, int len, const char *name, const char *setval, const char *field, int anon) {
	const int mode = pf->mode;
	RPrint *p = pf->p;
	// Use local slide+1 for header; don't modify pf->slide (already incremented by ? case)
	const int slide = pf->slide + 1;
	if ((slide % STRUCTPTR) > NESTDEPTH || (slide % STRUCTFLAG) / STRUCTPTR > NESTDEPTH) {
		R_LOG_ERROR ("Too much nested struct, too much recursion");
		return 0;
	}
	char *fmt = anon? strdup (name): sdb_get (p->formats, name, NULL);
	if (!fmt) { // Fetch struct info from types DB
		fmt = r_type_format (p->sdb_types, name);
	}
	if (R_STR_ISEMPTY (fmt)) {
		R_LOG_ERROR ("Undefined struct '%s'", name);
		free (fmt);
		return 0;
	}
	if (MUSTSEE && !SEEVALUE) {
		char namefmt[128];
		snprintf (namefmt, sizeof (namefmt), "%%%ds", 10 + 6 * slide % STRUCTPTR);
		const char *typename = (fmt[0] == '0')? "union": "struct";
		r_print_printf (p, namefmt, typename);
		r_print_printf (p, "<%s>\n", name);
	}
	r_print_format_internal (p, pf, seek, b, len, fmt, mode, setval, field);
	int ret = r_print_format_sizeof (p, fmt, mode, 0);
	free (fmt);
	return ret;
}

static char *get_args_offset(const char *arg) {
	char *args = strchr (arg, ' ');
	char *sq_bracket = strchr (arg, '[');
	int max = 30;
	if (args && sq_bracket) {
		char *csq_bracket = strchr (arg, ']');
		while (args && csq_bracket && csq_bracket > args && max--) {
			args = strchr (csq_bracket, ' ');
		}
	}
	return args;
}

static char *get_format_type(const char fmt, const char arg) {
	const char *type = NULL;
	switch (fmt) {
	case 'b':
	case 'C':
		type = "uint8_t";
		break;
	case 'c':
		type = "int8_t";
		break;
	case 'd':
	case 'i':
	case 'o':
	case 'x':
		type = "int32_t";
		break;
	case 'E':
		type = "enum";
		break;
	case 'f':
		type = "float";
		break;
	case 'F':
		type = "double";
		break;
	case 'G':
		type = "long_double";
		break;
	case 'q':
		type = "uint64_t";
		break;
	case 'u':
		type = "uleb128_t";
		break;
	case 'Q':
		type = "uint128_t";
		break;
	case 'w':
		type = "uint16_t";
		break;
	case 'W':
		type = "int16_t";
		break;
	case 'X':
		type = "uint8_t[]";
		break;
	case 'D':
	case 's':
	case 'S':
	case 't':
	case 'z':
	case 'Z':
		type = "char*";
		break;
	case 'n':
	case 'N':
		switch (arg) {
		case '1':
			type = fmt == 'n'? "int8_t": "uint8_t";
			break;
		case '2':
			type = fmt == 'n'? "int16_t": "uint16_t";
			break;
		case '4':
			type = fmt == 'n'? "int32_t": "uint32_t";
			break;
		case '8':
			type = fmt == 'n'? "int64_t": "uint64_t";
			break;
		}
		break;
	}
	return type? strdup (type): NULL;
}

static void pf_init(RPrintFormat *pf, RPrint *p, int mode) {
	memset (pf, 0, sizeof (RPrintFormat));
	pf->mode = mode;
	pf->p = p;
	if ((mode & R_PRINT_JSON) == R_PRINT_JSON) {
		pf->pj = pj_new ();
	}
}

static void pf_fini(RPrintFormat *pf) {
	pj_free (pf->pj);
	pf->pj = NULL;
}

// XXX: this is somewhat incomplete. must be updated to handle all format chars
R_API int r_print_format_sizeof(RPrint *p, const char *f, int mode, int n) {
	char *end, *args, *fmt;
	int size = 0, tabsize = 0, i, idx = 0, biggest = 0, fmt_len = 0, times = 1;
	bool tabsize_set = false;
	bool free_fmt2 = true;
	if (!f) {
		return -1;
	}
	if (n >= 5) { // nesting level limit
		return 0;
	}
	const char *fmt2 = p? sdb_get (p->formats, f, NULL): NULL;
	if (!fmt2) {
		fmt2 = f;
		free_fmt2 = false;
	}
	char *o = strdup (fmt2);
	if (free_fmt2) {
		R_FREE (fmt2);
	}
	if (!o) {
		return -1;
	}
	end = strchr (o, ' ');
	fmt = o;
	if (!end && ! (end = strchr (o, '\0'))) {
		free (o);
		return -1;
	}
	if (*end) {
		*end = 0;
		args = strdup (end + 1);
	} else {
		args = strdup ("");
	}

	i = 0;
	if (fmt[i] == '{') {
		char *end = strchr (fmt + i + 1, '}');
		if (!end) {
			R_LOG_ERROR ("No end curly bracket");
			free (o);
			free (args);
			return -1;
		}
		*end = '\0';
		times = r_num_math (NULL, fmt + i + 1);
		fmt = end + 1;
	}
	if (fmt[0] == '0') {
		mode |= R_PRINT_UNIONMODE;
		fmt++;
	} else {
		mode &= ~R_PRINT_UNIONMODE;
	}

	int p_bits = (p && p->config)? p->config->bits: 32;
	int words = r_str_word_set0_stack (args);
	fmt_len = strlen (fmt);
	for (; i < fmt_len; i++) {
		if (fmt[i] == '[') {
			char *end = strchr (fmt + i, ']');
			if (!end) {
				R_LOG_ERROR ("No end bracket");
				continue;
			}
			*end = '\0';
			tabsize_set = true;
			tabsize = r_num_math (NULL, fmt + i + 1);
			*end = ']';
			while (fmt[i++] != ']') {
				;
			}
		} else {
			tabsize = 1;
		}

		switch (fmt[i]) {
		case '.':
			idx--;
			// fallthrough
		case 'c':
		case 'b':
		case 'X':
			size += tabsize * 1;
			break;
		case 'w':
			size += tabsize * 2;
			break;
		case ':':
			idx--;
			// fallthrough
		case 'd':
		case 'o':
		case 'i':
		case 'x':
		case 'f':
		case 's':
		case 't':
			size += tabsize * 4;
			break;
		case 'S':
		case 'q':
		case 'F':
			size += tabsize * 8;
			break;
		case 'G': // long double (10 byte aligned to 16)
		case 'Q': // uint128
			size += tabsize * 16;
			break;
		case 'z':
		case 'Z':
			size += tabsize;
			break;
		case '*':
			size += tabsize *(p_bits / 8);
			i++;
			idx--; // no need to go ahead for args
			break;
		case 'B':
		case 'E':
			if (tabsize_set) {
				if (tabsize < 1 || tabsize > 8) {
					R_LOG_ERROR ("Unknown enum format size: %d", tabsize);
					break;
				}
				size += tabsize;
			} else {
				size += 4; // Assuming by default enum as int
			}
			break;
		case '?':
			{
				const char *wordAtIndex = NULL;
				const char *format = NULL;
				bool format_owned = false;
				char *endname = NULL, *structname = NULL;
				char tmp = 0;
				int ret = 0;
				if (words < idx) {
					R_LOG_ERROR ("Index out of bounds");
				} else {
					wordAtIndex = r_str_word_get0 (args, idx);
				}
				if (!wordAtIndex) {
					break;
				}
				structname = strdup (wordAtIndex);
				if (!structname) {
					break;
				}
				if (*structname == '(') {
					endname = (char *)r_str_rchr (structname, NULL, ')');
				} else {
					free (structname);
					break;
				}
				if (endname) {
					*endname = '\0';
				}
				format = strchr (structname, ' ');
				if (format) {
					tmp = *format;
					while (tmp == ' ') {
						format++;
						tmp = *format;
					}
				} else {
					format = p? sdb_get (p->formats, structname + 1, NULL): NULL;
				if (format && !strncmp (format, f, strlen (format) - 1)) {
						R_FREE (format);
						ret = -1;
						goto cleanup_struct;
					}
					if (!format) {
						format = r_type_format (p->sdb_types, structname + 1);
					}
					format_owned = true;
				}
				if (!format) {
					R_LOG_ERROR ("Cannot find format for struct `%s'", structname + 1);
					ret = 0;
					goto cleanup_struct;
				}
				int newsize = r_print_format_sizeof (p, format, mode, n + 1);
				if (newsize < 1) {
					R_LOG_ERROR ("Cannot find size for `%s'", format);
					ret = 0;
					goto cleanup_struct;
				}
				if (!ST32_MUL_OVFCHK (tabsize, newsize)) {
					size = size + (tabsize * newsize);
				} else {
					R_LOG_ERROR ("Prevented multiply integer overflow in format2.c");
					ret = 0;
					goto cleanup_struct;
				}
		cleanup_struct:
				free (structname);
				if (format_owned) {
					R_FREE (format);
				}
				if (ret != 0) {
					free (o);
					free (args);
					return ret;
				}
			}
			break;
		case '{':
			while (fmt[i] != '}') {
				if (!fmt[i]) {
					free (o);
					free (args);
					return -1;
				}
				i++;
			}
			i++;
			idx--;
			break;
		case '}':
			free (o);
			free (args);
			return -1;
		case '+':
		case 'e':
			idx--;
			break;
		case 'p':
			if (fmt[i + 1] == '2') {
				size += tabsize * 2;
			} else if (fmt[i + 1] == '4') {
				size += tabsize * 4;
			} else if (fmt[i + 1] == '8') {
				size += tabsize * 8;
			} else {
				size += tabsize *(p_bits / 8);
				break;
			}
			i++;
			break;
		case 'P':
			size += 4;
			i++;
			break;
		case 'r':
			break;
		case 'n':
		case 'N':
			if (fmt[i + 1] == '1') {
				size += tabsize * 1;
			} else if (fmt[i + 1] == '2') {
				size += tabsize * 2;
			} else if (fmt[i + 1] == '4') {
				size += tabsize * 4;
			} else if (fmt[i + 1] == '8') {
				size += tabsize * 8;
			} else {
				R_LOG_ERROR ("Invalid n format in (%s)", fmt);
				free (o);
				free (args);
				return -2;
			}
			i++;
			break;
		case 'g':
			size += tabsize * 2;
			break;
		case 'T':
			size += tabsize * 4;
			break;
		case 'u':
			size += tabsize * 1; // At least one byte
			break;
		case 'D':
			// size += tabsize * 4; // XXX: D is variable size
			break;
		case 'U':
		default:
			break;
		}
		idx++;
		if (mode & R_PRINT_UNIONMODE) {
			if (size > biggest) {
				biggest = size;
			}
			size = 0;
		}
	}
	size *= times;
	free (o);
	free (args);
	return (mode & R_PRINT_UNIONMODE)? biggest: size;
}

#define ISSTRUCT (tmp == '?' || (tmp == '*' && arg[1] == '?'))
R_API int r_print_format_internal(RPrint *p, RPrintFormat *pf, ut64 seek, const ut8 *b, const int len, const char *formatname, int mode, const char *setval, const char *ofield) {
	int nargs, i, j, invalid, nexti, idx, times, otimes;
	const int old_bits = (p && p->config)? p->config->bits: 32;
	int p_bits = old_bits;
	char *args = NULL, tmp, last = 0;
	ut64 addr = 0, addr64 = 0, seeki = 0;
	char namefmt[128], *field = NULL;
	const char *arg = NULL;
	const char *argend;
	int viewflags = 0;
	char *oarg = NULL;
	RPrintFormat _pf = { 0 };

	int isptr = PF_PTR_NONE;

	if (!pf) {
		pf_init (&_pf, p, mode);
		pf = &_pf;
	} else {
		pf->mode = mode; // update mode for recursive calls
	}

	/* Load format from name into fmt */
	if (!formatname) {
		if (pf == &_pf) {
			pf_fini (pf);
		}
		return 0;
	}
	char *internal_format = p? sdb_get (p->formats, formatname, NULL): strdup (formatname);
	if (!internal_format) {
		internal_format = strdup (formatname);
	}
	if (internal_format) {
		const char *fmt = r_str_trim_head_ro (internal_format);
		argend = fmt + strlen (fmt);
		arg = fmt;
	} else {
		argend = arg = "";
	}

	nexti = nargs = i = j = 0;

	if (len < 1) {
		free (internal_format);
		if (pf == &_pf) {
			pf_fini (pf);
		}
		return 0;
	}
	// len+2 to save space for the null termination in wide strings
	ut8 *buf = calloc (1, len + 2);
	if (!buf) {
		free (internal_format);
		if (pf == &_pf) {
			pf_fini (pf);
		}
		return 0;
	}
	memcpy (buf, b, len);
	pf->endian = (p && p->config)? R_ARCH_CONFIG_IS_BIG_ENDIAN (p->config): R_SYS_ENDIAN;

	if (ofield && ofield != MINUSONE) {
		field = strdup (ofield);
	}
	/* get times */
	otimes = times = atoi (arg);
	if (times > 0) {
		while (isdigit (*arg)) {
			arg++;
		}
	}

	char *bracket = strchr (arg, '{');
	if (bracket) {
		char *end = strchr (arg, '}');
		if (!end) {
			R_LOG_ERROR ("No end bracket. Try pf {ecx}b @ esi");
			goto beach;
		}
		*end = '\0';
		times = r_num_math (NULL, bracket + 1);
		arg = end + 1;
	}

	if (*arg == '\0') {
		goto beach;
	}

	/* get args */
	args = get_args_offset (arg);
	if (args) {
		int maxl = 0;
		argend = args;
		tmp = *args;
		while (tmp == ' ') {
			args++;
			tmp = *args;
		}
		args = strdup (args);
		nargs = r_str_word_set0_stack (args);
		if (nargs == 0) {
			R_FREE (args);
		}
		for (i = 0; i < nargs; i++) {
			const char *tmp = r_str_word_get0 (args, i);
			const char *nm = r_str_rchr (tmp, NULL, ')');
			int len = strlen (nm? nm + 1: tmp);
			if (len > maxl) {
				maxl = len;
			}
		}
		const char *ends = " "; // XXX trailing space warning
		snprintf (namefmt, sizeof (namefmt), "%%%ds :%s",
			((maxl + 1) *(1 + pf->slide)) % STRUCTPTR, ends);
	}
#define ISPOINTED ((slide % STRUCTFLAG) / STRUCTPTR <= (oldslide % STRUCTFLAG) / STRUCTPTR)
#define ISNESTED ((slide % STRUCTPTR) <= (oldslide % STRUCTPTR))
	if (pf->mode == R_PRINT_JSON && pf->slide == 0) {
		pj_a (pf->pj);
	}
#if 0
	if (pf->mode == R_PRINT_STRUCT && 0) {
		if (R_STR_ISNOTEMPTY (formatname)) {
			if (strchr (formatname, ' ')) {
				r_print_printf (p, "struct {\n");
			} else {
				r_print_printf (p, "struct %s {\n", formatname);
			}
		} else {
			r_print_printf (p, "struct {\n");
		}
		pf->ident += 4;
	}
#endif
	if (pf->mode && arg[0] == '0') {
		pf->mode |= R_PRINT_UNIONMODE; // XXX this is RPRINT_FORMAT_MODE_UNION
		arg++;
	} else {
		pf->mode &= ~R_PRINT_UNIONMODE;
	}
	mode = pf->mode;
	if (pf->mode & R_PRINT_DOT) {
		char *fmtname;
		if (formatname && *formatname) {
			if (strchr (formatname, ' ')) {
				fmtname = r_str_newf ("0x%" PFMT64x, seek);
			} else {
				fmtname = strdup (formatname);
			}
		} else {
			fmtname = r_str_newf ("0x%" PFMT64x, seek);
		}
		r_print_printf (p, "digraph g { graph [ rank=same; rankdir=LR; ];\n");
		r_print_printf (p, "root [ rank=1; shape=record\nlabel=\"%s", fmtname);
	}

	/* go format */
	i = 0;
	if (!times) {
		otimes = times = 1;
	}
	int oi = 0;
	if ((pf->mode & R_PRINT_STRUCT) && pf->slide == 0) {
		pf->ident = 4;
		const char *sname = (formatname && *formatname && !strchr (formatname, ' '))? formatname: NULL;
		if (sname) {
			r_print_printf (p, "struct %s {\n", sname);
		} else {
			r_print_printf (p, "struct {\n");
		}
	}
	if (pf->pj && otimes > 1) {
		pj_o (pf->pj);
		pj_ka (pf->pj, "array");
	}
	for (; times; times--) { // repeat N times
		const char *orig = arg;
		int first = 1;
		if (otimes > 1) {
			if (pf->mode & R_PRINT_JSON) {
				pj_o (pf->pj);
				pj_kn (pf->pj, "index", otimes - times);
				pj_kn (pf->pj, "offset", seek + i);
				pj_ka (pf->pj, "values");
			} else if (pf->mode) {
				r_print_printf (p, "0x%08" PFMT64x " [%d] {\n", seek + i, otimes - times);
			}
		}
		arg = orig;
		for (idx = 0; i < len && arg < argend && *arg; arg++) {
			int size = 0, elem = 0; /* size of the array, element of the array */
			char *fieldname = NULL, *fmtname = NULL;
			if (pf->mode & R_PRINT_UNIONMODE) {
				i = 0;
			}
			oi = i;
			seeki = seek + i;
			addr = 0LL;
			invalid = 0;
			p_bits = old_bits;
			// DEBUG r_print_printf (p, "(%c)", *arg);
			if (arg[0] == '[') {
				char *end = strchr (arg, ']');
				if (!end) {
					R_LOG_ERROR ("No end bracket");
					goto beach;
				}
				*end = '\0';
				size = r_get_size (p->num, buf, pf->endian, arg + 1);
				arg = end + 1;
				*end = ']';
			} else {
				size = -1;
			}
			int fs = r_print_format_sizeof (p, arg, 0, idx);
			if (fs == -2) {
				i = -1;
				goto beach;
			}
			if (fs < 1) {
				if (*arg != 'D') {
					fs = 4;
				}
			}
			if (i + fs - 1 < len) { // should be +7 to avoid oobread on 'q'
				// Max byte number where updateAddr will look into
				if (len - i < 7) {
					updateAddr (buf + i, THRESHOLD - (len - i), pf->endian, &addr, &addr64);
				} else {
					updateAddr (buf + i, len - i, pf->endian, &addr, &addr64);
				}
				if (p_bits == 64) {
					addr = addr64;
				}
			} else {
				R_LOG_WARN ("format string (%s) is too large for this buffer (%d, %d)", formatname, i + fs, len);
				goto beach;
			}

			tmp = *arg;

			if (pf->mode && !args) {
				pf->mode |= R_PRINT_ISFIELD;
				mode = pf->mode;
			}
			if (! (pf->mode & R_PRINT_QUIET)) {
				if (pf->mode & R_PRINT_MUSTSEE && otimes > 1) {
					r_print_printf (p, "  ");
				}
			}
			if (idx < nargs && tmp != 'e' && isptr == 0) {
				char *dot = NULL, *bracket = NULL;
				if (field) {
					dot = strchr (field, '.');
				}
				if (dot) {
					*dot = '\0';
				}
				free (oarg);
				oarg = fieldname = strdup (r_str_word_get0 (args, idx));
				if (ISSTRUCT || tmp == 'E' || tmp == 'B' || tmp == 'r') {
					if (*fieldname == '(') {
						fmtname = fieldname + 1;
						fieldname = (char *)r_str_rchr (fieldname, NULL, ')');
						if (fieldname) {
							*fieldname++ = '\0';
						} else {
							R_LOG_ERROR ("Missing closing parenthesis in format ')'");
							goto beach;
						}
					} else {
						R_LOG_ERROR ("Missing name (%s)", fieldname);
						goto beach;
					}
				}
				if (pf->mode && (!args || (!field && ofield != MINUSONE) || (field && !strncmp (field, fieldname, strchr (field, '[')? strchr (field, '[') - field: strlen (field) + 1)))) {
					pf->mode |= R_PRINT_ISFIELD;
				} else {
					pf->mode &= ~R_PRINT_ISFIELD;
				}
				mode = pf->mode;

				/* There we handle specific element in array */
				if (field && (bracket = strchr (field, '[')) && (pf->mode & R_PRINT_ISFIELD)) {
					char *end = strchr (field, ']');
					if (!end) {
						R_LOG_ERROR ("Unfortunately it was not possible to find a closing bracket");
						goto beach;
					}
					*end = '\0';
					elem = r_num_math (NULL, bracket + 1) + 1; // +1 to handle 0 index easily
					for (; bracket < end; bracket++) {
						*bracket = '\0';
					}
					size += elem * ARRAYINDEX_COEF;
				} else {
					elem = -1;
				}
				if (tmp != '.' && tmp != ':') {
					idx++;
					if ((pf->mode & R_PRINT_MUSTSEE &&
						pf->mode & R_PRINT_ISFIELD &&
						! (pf->mode & R_PRINT_JSON)) &&
						! (pf->mode & R_PRINT_VALUE)) {
						if (! (pf->mode & R_PRINT_QUIET)) {
							r_print_printf (p, namefmt, fieldname);
						}
					}
				}
			}
		feed_me_again:
			switch (isptr) {
			case PF_PTR_SEEK:
				{
					nexti = i + (p_bits / 8);
					i = 0;
					if (tmp == '?') {
						seeki = addr;
					}
					memset (buf, 0, len);
				// Match pf1 behavior: only print (*addr) when MUSTSEE && !ISQUIET
				if (addr != 0 && addr != UT64_MAX && addr != UT32_MAX) {
					if (MUSTSEE && !ISQUIET) {
							r_print_printf (p, "(*0x%" PFMT64x ")", addr);
						}
					}
					// addr == 0: NULL pointer, print "NULL"
					// addr == UT64_MAX/UT32_MAX: invalid address, run format with empty buffer
					// addr valid: read from memory and run format
					if (addr == 0) {
						isptr = PF_PTR_NULL;
				} else if (addr == UT64_MAX || addr == UT32_MAX) {
						// Invalid address - let format specifier run with empty buffer
						isptr = PF_PTR_BACK;
					} else {
						isptr = PF_PTR_BACK;
						if (p->iob.read_at) {
							int r = p->iob.read_at (p->iob.io, (ut64)addr, buf, len - 4);
						if (r < 1 || (buf[0] == 0xff && buf[1] == 0xff)) {
								memset (buf, 0, len);
							}
						if (((i + 3) < len) || ((i + 7) < len)) {
								// Skip updateAddr for 'D' - we want to disassemble at addr, not at dereferenced value
								if (tmp != 'D') {
									updateAddr (buf + i, len - i, pf->endian, &addr, &addr64);
								}
							} else {
								R_LOG_ERROR ("Likely a heap buffer overflow");
								goto beach;
							}
						} else {
							R_LOG_ERROR ("cannot read at 0x%08" PFMT64x ", block: %s, blocksize: 0x%x", addr, b, len);
							r_print_printf (p, "\n");
							goto beach;
						}
					}
				}
				break;
			case PF_PTR_BACK:
				// restore state after pointer seek
				i = nexti;
				memcpy (buf, b, len);
				isptr = false;
				arg--;
				continue;
			}
			if (tmp == 0 && last != '*') {
				break;
			}
			/* skip chars */
			switch (tmp) {
			case '*': // next char is a pointer
				isptr = PF_PTR_SEEK;
				arg++;
				tmp = *arg; // last;
				goto feed_me_again;
			case '+': // toggle view flags
				viewflags = !viewflags;
				continue;
			case 'e': // tmp swap endian
				pf->endian ^= 1;
				continue;
			case ':': // skip 4 bytes
				if (size == -1) {
					i += 4;
				} else {
					while (size--) {
						i += 4;
					}
				}
				continue;
			case '.': // skip 1 byte
				i += (size == -1)? 1: size;
				continue;
			case 'P': // self-relative pointer reference
				tmp = 'P';
				arg++;
				break;
			case 'p': // pointer reference
				if (*(arg + 1) == '2') {
					tmp = 'w';
					arg++;
				} else if (*(arg + 1) == '4') {
					tmp = 'x';
					arg++;
				} else if (*(arg + 1) == '8') {
					tmp = 'q';
					arg++;
				} else { // If pointer reference is not mentioned explicitly
					switch (p_bits) {
					case 16: tmp = 'w'; break;
					case 32: tmp = 'x'; break;
					default: tmp = 'q'; break;
					}
				}
				break;
			}

			/* flags */
			if (pf->mode & R_PRINT_SEEFLAGS && isptr != PF_PTR_NULL) {
				char *newname = NULL;
				if (!fieldname) {
					newname = fieldname = r_str_newf ("pf.%" PFMT64u, seeki);
				}
				if (pf->mode & R_PRINT_UNIONMODE) {
					r_print_printf (p, "f %s=0x%08" PFMT64x "\n", formatname, seeki);
					goto beach;
				} else if (tmp == '?') {
					r_print_printf (p, "f %s.%s_", fmtname, fieldname);
				} else if (tmp == 'E') {
					r_print_printf (p, "f %s=0x%08" PFMT64x "\n", fieldname, seeki);
				} else if (pf->slide / STRUCTFLAG > 0 && idx == 1) {
					r_print_printf (p, "%s=0x%08" PFMT64x "\n", fieldname, seeki);
				} else {
					r_print_printf (p, "f %s=0x%08" PFMT64x "\n", fieldname, seeki);
				}
				if (newname) {
					R_FREE (newname);
					fieldname = NULL;
				}
			}

			/* dot */
			if (mode & R_PRINT_DOT) {
				if (fieldname) {
					r_print_printf (p, "|{0x%" PFMT64x "|%c|%s|<%s>",
						seeki, tmp, fieldname, fieldname);
				} else {
					r_print_printf (p, "|{0x%" PFMT64x "|%c|", seeki, tmp);
				}
			} else if (pf->pj) {
				if (pf->oldslide <= pf->slide) {
					if (first) {
						first = 0;
					}
				} else if (pf->oldslide) {
					pj_end (pf->pj);
					pj_end (pf->pj);
					// r_print_printf (p, "]},");
					pf->oldslide -= NESTEDSTRUCT;
				}
				pj_o (pf->pj);
				if (fieldname) {
					pj_ks (pf->pj, "name", fieldname);
				}
				if (ISSTRUCT) {
					if (fmtname) {
						pj_ks (pf->pj, "type", fmtname);
					} else {
						pj_ks (pf->pj, "type", "(unknown)");
					}
				} else {
					char *fmt = (tmp == 'n' || tmp == 'N')
						? r_str_newf ("%c%c", tmp, *(arg + 1))
						: r_str_newf ("%c", tmp);
					pj_ks (pf->pj, "type", fmt);
					free (fmt);
				}
				if (isptr) {
					pj_kb (pf->pj, "ptr", isptr);
				}
				pj_kn (pf->pj, "offset", seek + i);
			} else if (MUSTSEESTRUCT) {
				/* c struct */
				if (!fieldname) {
					fieldname = "";
				}
				char *type = get_format_type (tmp, (tmp == 'n' || tmp == 'N')? arg[1]: 0);
				if (type) {
					r_print_printf (p, "%*c%s %s; // ", pf->ident, ' ', type, fieldname);
				} else {
					r_print_printf (p, "%*cstruct %s {\n", pf->ident, ' ', fieldname);
				}
				free (type);
			} else {
				// nothing
			}
			bool noline = false;

			if (isptr == PF_PTR_NULL) {
				if (MUSTSEEJSON) {
					r_print_printf (p, "\"NULL\"}");
				} else if (MUSTSEE) {
					r_print_printf (p, " NULL\n");
				}
				isptr = PF_PTR_BACK;
			} else {
				/* format chars */
				// before to enter in the switch statement check buf boundaries due to  updateAddr
				// might go beyond its len and it's usually called in each of the following functions
				switch (tmp) {
				case 'u':
					i += pf_uleb (pf, setval, seeki, buf, i, size, len);
					break;
				case 't':
					pf_time (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'P':
					{
						st32 sw = (st32)r_read_le32 (buf + i);
						if (MUSTSEEJSON) {
							r_print_printf (p, "\"0x%" PFMT64x "\"", (ut64)seeki + sw);
					} else if (MUSTSEE || MUSTSEESTRUCT) {
							r_print_printf (p, "0x%" PFMT64x, (ut64)seeki + sw);
						} else {
							r_print_printf (p, "0x%" PFMT64x "\n", (ut64)seeki + sw);
						}
						i += 4;
					}
					break;
				case 'q':
					pf_qword (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 8: 8 * size;
					break;
				case 'Q':
					pf_u128 (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 16: 16 * size;
					break;
				case 'b':
					r_print_format_byte (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 1: size;
					break;
				case 'C':
					r_print_format_decchar (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 1: size;
					break;
				case 'c':
					r_print_format_char (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 1: size;
					break;
				case 'X':
					size = r_print_format_hexpairs (pf, setval, seeki, buf, i, size);
					i += size;
					break;
				case 'T':
					if (r_print_format_10bytes (pf, setval, seeki, addr, buf) == 0) {
						i += (size == -1)? 4: 4 * size;
					}
					break;
				case 'f':
					r_print_format_float (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'g':
					r_print_format_bf16 (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 2: 2 * size;
					break;
				case 'F':
					r_print_format_double (pf, setval, seeki, buf, i, size);
					i += (size == -1)? sizeof (double): sizeof (double) * size;
					break;
				case 'G':
					r_print_format_long_double (pf, setval, seeki, buf, i, size);
					i += (size == -1)? sizeof (long double): sizeof (long double) * size;
					break;
				case 'i':
					pf_int (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'd':
					r_print_format_hex (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'D':
					if (MUSTSET) {
						R_LOG_ERROR ("Set val not implemented yet for disassembler!");
					}
					{
						ut64 at = isptr? ((p_bits == 64)? addr64: addr): seeki;
						i += r_print_format_disasm (p, at, size);
					}
					break;
				case 'o':
					r_print_format_octal (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case ';':
					noline = true;
					i -= (size == -1)? 4: 4 * size;
					if (i < 0) {
						i = 0;
					}
					break;
				case ',':
					noline = true;
					i -= (size == -1)? 1: size;
					if (i < 0) {
						i = 0;
					}
					break;
				case 'x':
					pf_hexflag (pf, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'w':
					r_print_format_word (pf, setval, seeki, buf, i, size, false);
					i += (size == -1)? 2: 2 * size;
					break;
				case 'W':
					r_print_format_word (pf, setval, seeki, buf, i, size, true);
					i += (size == -1)? 2: 2 * size;
					break;
				case 'z': // zero terminated string
					r_print_format_nulltermstring (pf, len, setval, seeki, buf, i, size);
					if (size == -1) {
						i += strlen ((char *)buf + i) + 1;
					} else {
						// i += size; size = 0;
						while (size--) {
							i++;
						}
					}
					break;
				case 'Z': // zero terminated wide string
					r_print_format_nulltermwidestring (pf, len, setval, seeki, buf, i, size);
					if (size == -1) {
						i += r_wstr_clen ((char *) (buf + i)) * 2 + 2;
					} else {
						while (size--) {
							i += 2;
						}
					}
					break;
				case 's':
					if (MUSTSET) {
						R_LOG_ERROR ("Set val not implemented yet for strings!");
					}
					if (pf_string (pf, seeki, addr64, addr, 0) == 0) {
						i += (size == -1)? 4: 4 * size;
					}
					break;
				case 'S':
					if (MUSTSET) {
						R_LOG_ERROR ("Set val not implemented yet for strings!");
					}
					if (pf_string (pf, seeki, addr64, addr, 1) == 0) {
						i += (size == -1)? 8: 8 * size;
					}
					break;
				case 'B': // resolve bitfield
					PF_EXTRACT_ELEM (elem, size);
					if (MUSTSET) {
						r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
						// R_LOG_ERROR ("Set val not implemented yet for bitfields!");
					}
					if (pf->endian) {
						int el_size = (size == -1)? 1: size;
						int read_size = 8; // updateAddr always reads 8 bytes in format2.c
						if (el_size < 8 && el_size < read_size) {
							addr >>= (read_size - el_size) * 8;
						}
					}
					r_print_format_bitfield (pf, seeki, fmtname, fieldname, addr, size);
					i += (size == -1)? 1: size;
					break;
				case 'E': // resolve enum
					PF_EXTRACT_ELEM (elem, size);
					if (MUSTSET) {
						r_print_printf (p, "wv4 %s @ 0x%08" PFMT64x "\n", setval, seeki + ((elem >= 0)? elem * 4: 0));
					}
					if (pf->endian) {
						int el_size = (size == -1)? 1: size;
						int read_size = 8; // updateAddr always reads 8 bytes in format2.c
						if (el_size < 8 && el_size < read_size) {
							addr >>= (read_size - el_size) * 8;
						}
					}
					if (fmtname) {
						r_print_format_enum (pf, seeki, fmtname, fieldname, addr, size);
					} else {
						R_LOG_ERROR ("Missing enum type after the E()");
					}
					i += (size == -1)? 1: size;
					break;
				case 'r':
					if (fmtname) {
						r_print_format_register (pf, fmtname, setval);
					} else {
						R_LOG_ERROR ("Unknown register %s", fmtname);
					}
					break;
				case '?':
					{
						int s = 0;
						char *format = NULL;
						int anon = 0;
						bool ident_inc = false;
						if (size >= ARRAYINDEX_COEF) {
							elem = size / ARRAYINDEX_COEF - 1;
							size %= ARRAYINDEX_COEF;
						}
						const char *nxtfield = NULL;
						if (! (mode & R_PRINT_ISFIELD)) {
							nxtfield = MINUSONE;
					} else if (ofield && ofield != MINUSONE) {
							nxtfield = strchr (ofield, '.');
						}
					if (nxtfield != MINUSONE && nxtfield) {
							nxtfield++;
						}
					if (MUSTSEE && !SEEVALUE) {
							r_print_printf (p, "\n");
						}
						if (MUSTSEEJSON) {
							if (isptr) {
								R_LOG_DEBUG ("ptr handling for structs");
								pj_kn (pf->pj, "ptraddr", seeki);
							}
							pj_ka (pf->pj, "value");
						} else if (MUSTSEESTRUCT) {
							if (isptr) {
								r_print_printf (p, "%" PFMT64d, seeki);
							} else {
								pf->ident += 4;
								ident_inc = true;
							}
						} else if (mode & R_PRINT_SEEFLAGS) {
							pf->slide += STRUCTFLAG;
						}
						if (!fmtname) {
							break;
						}
						format = strchr (fmtname, ' ');
						if (format) {
							anon = 1;
							fmtname = (char *)r_str_trim_head_ro (format);
						}
						pf->oldslide = pf->slide;
						pf->slide += NESTEDSTRUCT;
						if (size == -1) {
							s = r_print_format_struct (pf, seeki, buf + i, len - i, fmtname, setval, nxtfield, anon);
							i += isptr? (p_bits / 8): s;
							if (MUSTSEEJSON) {
							if (!isptr && (!arg[1] || arg[1] == ' ')) {
									pj_end (pf->pj);
								}
							}
						} else {
							if (mode & R_PRINT_ISFIELD) {
								if (!SEEVALUE) {
									r_print_printf (p, "[\n");
								}
							}
							while (size--) {
							if (mode && (elem == -1 || elem == 0)) {
									mode |= R_PRINT_MUSTSEE;
									if (elem == 0) {
										elem = -2;
									}
								} else {
									mode &= ~R_PRINT_MUSTSEE;
								}
								pf->mode = mode; // sync mode before recursive call
								s = r_print_format_struct (pf, seek + i, buf + i, len - i, fmtname, setval, nxtfield, anon);
							if ((MUSTSEE || MUSTSEESTRUCT) && size != 0 && elem == -1) {
								if (MUSTSEE || MUSTSEESTRUCT) {
										r_print_printf (p, "\n");
									}
								}
								if (elem > -1) {
									elem--;
								}
								i += (isptr)? (p_bits / 8): s;
							}
							if (mode & R_PRINT_ISFIELD) {
								if (!SEEVALUE) {
									r_print_printf (p, "]\n");
								}
							}
							if (MUSTSEEJSON) {
								pj_end (pf->pj);
							}
						}
						pf->oldslide = pf->slide;
						pf->slide -= NESTEDSTRUCT;
						if (mode & R_PRINT_SEEFLAGS) {
							pf->oldslide = pf->slide;
							pf->slide -= STRUCTFLAG;
						}
					if (ident_inc && pf->ident >= 4) {
							pf->ident -= 4;
						}
						break;
					}
				case 'n':
				case 'N':
					{
						int bytes = 0;
						int sign = (tmp == 'n')? 1: 0;
						if (arg[1] == '1') {
							bytes = 1;
						} else if (arg[1] == '2') {
							bytes = 2;
						} else if (arg[1] == '4') {
							bytes = 4;
						} else if (arg[1] == '8') {
							bytes = 8;
						} else {
							invalid = 1;
							break;
							// or goto beach;???
						}
						r_print_format_num (pf, setval, seeki, buf, i, bytes, sign, size);
						i += (size == -1)? bytes: size * bytes;
						arg++;
						break;
					}
				default:
					/* ignore unknown chars */
					invalid = 1;
					break;
				} // switch
			}
			// FIX r_print_printf (p, "\n");
			if (MUSTSEESTRUCT) {
				if (pf->oldslide) {
					// pf->ident -= 4;
					pf->oldslide -= NESTEDSTRUCT;
				}
				if (tmp != '?') {
					r_print_printf (p, "\n");
				}
			} else if (pf->pj && mode & R_PRINT_JSON) {
				pj_end (pf->pj);
			} else if (mode & R_PRINT_DOT) {
				r_print_printf (p, "}");
			} else if (mode & R_PRINT_SEEFLAGS && isptr != PF_PTR_NULL) {
				int sz = i - oi;
				if (sz > 1) {
					r_print_printf (p, "fl %d @ 0x%08" PFMT64x "\n", sz, seeki);
					r_print_printf (p, "Cd %d @ 0x%08" PFMT64x "\n", sz, seeki);
				}
			}
			if (viewflags && p->offname) {
				const char *s = p->offname (p->user, seeki);
				if (s) {
					r_print_printf (p, "@(%s)", s);
				}
				s = p->offname (p->user, addr);
				if (s) {
					r_print_printf (p, "*(%s)", s);
				}
			}
			if (!noline && tmp != 'D' && !invalid && !fmtname && MUSTSEE) {
				r_print_printf (p, "\n");
			}
			last = tmp;

			// XXX: Due to the already noted issues with the above, we need to strip
			// args from fmt:args the same way we strip fmt BUT only for enums as
			// nested structs seem to be handled correctly above!
			if (arg[0] == 'E') {
				char *end_fmt = strchr (arg, ' ');
				if (!end_fmt) {
					goto beach;
				}
				char *next_args = strchr (end_fmt + 1, ' ');
				if (next_args) {
					while (*next_args != '\0') {
						*end_fmt++ = *next_args++;
					}
				}
				*end_fmt = '\0';
			}
		}
		if (otimes > 1) {
			if (pf->pj) {
				pj_end (pf->pj);
				pj_end (pf->pj);
			} else if (mode) {
				r_print_printf (p, "}\n");
			}
		}
		arg = orig;
		pf->oldslide = 0;
	}
	if (pf->slide == 0) {
		if (pf->pj) {
			// pj_end (pf->pj);
		}
		if (MUSTSEESTRUCT) {
			r_print_printf (p, "}\n");
		}
	}
	if (mode & R_PRINT_DOT) {
		r_print_printf (p, "\"];\n}\n");
		// TODO: show nested structs and field reference lines
	}
beach:
	if (pf->pj && otimes > 1) {
		pj_end (pf->pj);
		pj_end (pf->pj);
		pj_end (pf->pj);
	}
	if (MUSTSEESTRUCT && pf->slide > 0) {
		char *pad = r_str_pad (NULL, 0, ' ', R_MAX (0, pf->ident - 4));
		r_print_printf (p, "%s}\n", pad);
		free (pad);
		// r_print_printf (p, "%*c}\n", pf->ident - 4, ' ');
	}
	if (pf->pj && pf->slide == 0) {
		pj_end (pf->pj);
		char *s = pj_drain (pf->pj);
		pf->pj = NULL;
		r_print_printf (p, "%s\n", s);
		free (s);
	}
	if (pf->slide == 0) {
		pf->oldslide = 0;
		pf_fini (pf);
	}
	free (internal_format);
	free (oarg);
	free (buf);
	free (field);
	free (args);
	return i;
}

R_API int r_print_format2(RPrint *p, ut64 seek, const ut8 *b, const int len, const char *formatname, int mode, const char *setval, const char *ofield) {
	return r_print_format_internal (p, NULL, seek, b, len, formatname, mode, setval, ofield);
}
