/* radare - LGPL - Copyright 2007-2025 - pancake & Skia */

#include <r_cons.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <r_reg.h>

// W T F :D
#define NOPTR 0
#define PTRSEEK 1
#define PTRBACK 2
#define NULLPTR 3
#define STRUCTPTR 100
#define NESTEDSTRUCT 1
#define STRUCTFLAG 10000
#define NESTDEPTH 14
#define ARRAYINDEX_COEF 10000

#define MUSTSEE (mode & R_PRINT_MUSTSEE && mode & R_PRINT_ISFIELD && !(mode & R_PRINT_JSON))
#define ISQUIET (mode & R_PRINT_QUIET)
#define MUSTSET (mode & R_PRINT_MUSTSET && mode & R_PRINT_ISFIELD && setval)
#define SEEVALUE (mode & R_PRINT_VALUE)
#define MUSTSEEJSON (mode & R_PRINT_JSON && mode & R_PRINT_ISFIELD)
#define MUSTSEESTRUCT (mode & R_PRINT_STRUCT)

// Color macros for pf output
#define COLOR(x) (p->consb.cons && p->consb.cons->context) ? p->consb.cons->context->pal.x : ""
#define COLOR_ADDR COLOR(addr)
#define COLOR_NUM COLOR(num)
#define COLOR_RESET Color_RESET

// Helper functions for colorized pf output
static inline const char *pf_color_addr(const RPrint *p) {
	return (p->consb.cons && p->consb.cons->context && p->consb.cons->context->color_mode) ? p->consb.cons->context->pal.addr : "";
}

static inline const char *pf_color_num(const RPrint *p) {
	return (p->consb.cons && p->consb.cons->context && p->consb.cons->context->color_mode) ? p->consb.cons->context->pal.b0xff : "";
}

static inline const char *pf_color_for_value(const RPrint *p, ut64 value) {
	if (!p->consb.cons || !p->consb.cons->context || !p->consb.cons->context->color_mode) {
		return "";
	}
	if (p->colorfor && (p->flags & R_PRINT_FLAGS_REFS)) {
		const char *color = p->colorfor (p->user, value, 0, true);
		if (color) {
			return color;
		}
	}
	return pf_color_num (p);
}

static inline const char *pf_color_reset(const RPrint *p) {
	return (p->consb.cons && p->consb.cons->context && p->consb.cons->context->color_mode) ? Color_RESET : "";
}

// Print address with color (used in pf output)
static inline void pf_print_addr(const RPrint *p, ut64 addr) {
	r_print_printf (p, "%s0x%08"PFMT64x"%s", pf_color_addr(p), addr, pf_color_reset(p));
}

static inline void pf_print_value_hex(const RPrint *p, const char *fmt, ut64 value) {
	r_print_printf (p, "%s", pf_color_for_value(p, value));
	r_print_printf (p, fmt, value);
	r_print_printf (p, "%s", pf_color_reset(p));
}

// FOR MINGW only
#if __MINGW32__
// gmtime_r can be defined by mingw
#ifndef gmtime_r
static struct tm* gmtime_r(const time_t* t, struct tm* r) {
	// gmtime is threadsafe in windows because it uses TLS
	struct tm *theTm = gmtime(t);
	if (theTm) {
		*r = *theTm;
		return r;
	}
	return 0;
}
#endif // gmtime_r
#endif

//this define is used as a way to acknowledge when updateAddr should take len
//as real len of the buffer
#define THRESHOLD (-4444)

static float updateAddr(const ut8 *buf, int len, int endian, ut64 *addr, ut64 *addr64) {
	float f = 0.0;
	// assert sizeof (float) == sizeof (ut32))
	// XXX 999 is used as an implicit buffer size, we should pass the buffer size to every function too, otherwise this code will give us some problems
	if (len >= THRESHOLD - 7 && len < THRESHOLD) {
		len = len + THRESHOLD; // get the real len to avoid oob
	} else {
		len = 999;
	}
	if (len < 1) {
		return 0;
	}
	if (len >= sizeof (float)) {
		r_mem_swaporcopy ((ut8*)&f, buf, sizeof (float), endian);
	}
	if (addr && len > 3) {
		ut32 tmpaddr = r_read_ble32 (buf, endian);
		*addr = (ut64)tmpaddr;
	}
	if (addr64 && len > 7) {
		*addr64 = r_read_ble64 (buf, endian);
	}
	return f;
}

static int r_get_size(RNum *num, ut8 *buf, int endian, const char *s) {
	size_t len = strlen (s);
	if (s[0] == '*' && len >= 4) { // value pointed by the address
		ut64 addr;
		int offset = (int)r_num_math (num, s + 1);
		(void)updateAddr (buf + offset, 999, endian, &addr, NULL);
		return addr;
	}
	// flag handling doesnt seems to work here
	return r_num_math (num, s);
}

static void r_print_format_u128(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 low = r_read_ble64 (buf, endian);
	ut64 hig = r_read_ble64 (buf + 8, endian);
	if (MUSTSEEJSON) {
		r_print_printf (p, "\"");
	} else if (!SEEVALUE && !ISQUIET) {
		r_print_printf (p, "0x%08"PFMT64x" = (uint128_t)", seeki);
	}
	if (endian) {
		r_print_printf (p, "0x%016"PFMT64x, low);
		r_print_printf (p, "%016"PFMT64x, hig);
	} else {
		r_print_printf (p, "0x%016"PFMT64x, hig);
		r_print_printf (p, "%016"PFMT64x, low);
	}
	if (MUSTSEEJSON) {
		const char *end = endian? "big": "little";
		r_print_printf (p, "\",\"endian\":\"%s\",\"ctype\":\"uint128_t\"}", end);
	}
}

static void r_print_format_quadword(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr64;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size / ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, NULL, &addr64);
	if (MUSTSET) {
		r_print_printf (p, "wv8 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*8:0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki + ((elem >= 0)? elem * 8: 0));
			r_print_printf (p, " = (qword)");
		}
		if (size == -1) {
			if (addr64 == UT32_MAX || ((st64)addr64 < 0 && (st64)addr64 > -4096)) {
				r_print_printf (p, "%s%d%s", pf_color_num(p), (int)(addr64), pf_color_reset(p));
			} else {
				pf_print_value_hex (p, "0x%016"PFMT64x, addr64);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, NULL, &addr64);
				if (elem == -1 || elem == 0) {
					pf_print_value_hex (p, "0x%016"PFMT64x, addr64);
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
				i += 8;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			r_print_printf (p, "%"PFMT64d, addr64);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, NULL, &addr64);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%"PFMT64d, addr64);
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
				i += 8;
			}
			r_print_printf (p, " ]");
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

static void r_print_format_byte(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size / ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		r_print_printf (p, "\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki + ((elem >= 0) ? elem : 0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki + ((elem >= 0) ? elem : 0));
			r_print_printf (p, " = ");
		}
		if (size == -1) {
			pf_print_value_hex (p, "0x%02x", buf[i]);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					pf_print_value_hex (p, "0x%02x", buf[i]);
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
				i++;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			r_print_printf (p, "%d", buf[i]);
		} else {
			r_print_printf (p, "[ ");
			const char *comma = "";
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%s%d", comma, buf[i]);
					comma = ",";
					if (elem == 0) {
						elem = -2;
					}
				}
				if (elem > -1) {
					elem--;
				}
				i++;
			}
			r_print_printf (p, " ]");
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

// Return number of consumed bytes
static int r_print_format_uleb(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	int s = 0, offset = 0;
	ut64 value = 0;
	if (size >= ARRAYINDEX_COEF) {
		elem = size / ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		ut8 *tmp;
		char *nbr;
		do {
			r_uleb128_decode (buf+i, &s, &value);
			i += s;
			offset += s;
		} while (elem--);
		tmp = (ut8*) r_uleb128_encode (r_num_math (NULL, setval), &s);
		nbr = r_hex_bin2strdup (tmp, s);
		r_print_printf (p, "\"wx %s\" @ 0x%08"PFMT64x"\n", nbr, seeki+offset-s);
		free (tmp);
		free (nbr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki);
		}
		if (size==-1) {
			r_uleb128_decode (buf+i, &offset, &value);
			r_print_printf (p, "%"PFMT64d, value);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_uleb128_decode (buf+i, &s, &value);
					i += s;
					offset += s;
					r_print_printf (p, "%"PFMT64d, value);
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
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size==-1) {
			r_uleb128_decode (buf+i, &offset, &value);
			r_print_printf (p, "\"%"PFMT64d"\"", value);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_uleb128_decode (buf+i, &s, &value);
					i += s;
					offset += s;
					r_print_printf (p, "\"%"PFMT64d"\"", value);
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
			r_print_printf (p, " ]");
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
	return offset;
}

static void r_print_format_char(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		r_print_printf (p, "\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 2 : 0)); //XXX:: shouldn't it be elem*1??
		}
		if (size == -1) {
			r_print_printf (p, "'%c'", IS_PRINTABLE (buf[i])?buf[i]:'.');
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "'%c'", IS_PRINTABLE (buf[i])?buf[i]:'.');
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
				i++;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			r_print_printf (p, "\"%c\"", IS_PRINTABLE (buf[i])?buf[i]:'.');
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "\"%c\"", IS_PRINTABLE (buf[i])?buf[i]:'.');
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
				i++;
			}
			r_print_printf (p, " ]");
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

static void r_print_format_decchar(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		r_print_printf (p, "\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem : 0));
		}
		if (size == -1) {
			r_print_printf (p, "%d", buf[i]);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%d", buf[i]);
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
				i++;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			r_print_printf (p, "\"%d\"", buf[i]);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "\"%d\"", buf[i]);
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
				i++;
			}
			r_print_printf (p, " ]");
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

static int r_print_format_string(const RPrint* p, ut64 seeki, ut64 addr64, ut64 addr, int is64, int mode) {
	ut8 buffer[255];
	buffer[0] = 0;
	if (!p->iob.read_at) {
		R_LOG_ERROR ("(cannot read memory)");
		return -1;
	}
	const ut64 at = (is64 == 1)? addr64: (ut64)addr;
	int res = p->iob.read_at (p->iob.io, at, buffer, sizeof (buffer) - 8);
	if (MUSTSEEJSON) {
		char *encstr = r_str_utf16_encode ((const char *)buffer, -1);
		if (encstr) {
			r_print_printf (p, "%"PFMT64d",\"string\":\"%s\"}", seeki, encstr);
			free (encstr);
		}
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

static void r_print_format_time(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	struct tm timestruct;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if (MUSTSEE) {
		char *timestr = malloc (ASCTIME_BUF_MAXLEN);
		if (!timestr) {
			return;
		}
		r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
		*(timestr+24) = '\0';
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 4 : 0));
		}
		if (size==-1) {
			r_print_printf (p, "%s", timestr);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
				timestr[24] = 0;
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%s", timestr);
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
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
		free (timestr);
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		char *timestr = malloc (ASCTIME_BUF_MAXLEN);
		if (!timestr) {
			return;
		}
		r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
		timestr[24] = 0;
		if (size == -1) {
			r_print_printf (p, "\"%s\"", timestr);
		} else {
			PJ *pj = pj_new ();
			pj_a (pj);
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
				*(timestr+24) = '\0';
				if (elem == -1 || elem == 0) {
					pj_s (pj, timestr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_print_printf (p, "%s", s);
			free (s);
		}
		free (timestr);
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

// TODO: support unsigned int?
static void r_print_format_hex(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "0x%08"PFMT64x, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki + ((elem >= 0) ? elem * 4 : 0));
			r_print_printf (p, " = ");
		}
		if (size == -1) {
			if (addr == UT64_MAX || addr == UT32_MAX) {
				r_print_printf (p, "-1");
			} else {
				pf_print_value_hex (p, "0x%08"PFMT64x, addr);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					if (ISQUIET) {
						if (addr == UT64_MAX || addr == UT32_MAX) {
							r_print_printf (p, "-1");
						} else {
							pf_print_value_hex (p, "0x%08"PFMT64x, addr);
						}
					} else {
						pf_print_value_hex (p, "0x%08"PFMT64x, addr);
					}
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
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			r_print_printf (p, "%"PFMT64d, addr);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "0x%08"PFMT64x, addr);
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
				i += 4;
			}
			r_print_printf (p, " ]");
		}
		r_print_printf (p, "}");
	}
}

static void r_print_format_int(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ %"PFMT64d"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "0x%08"PFMT64x, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki+((elem>=0)?elem*4:0));
			r_print_printf (p, " = ");
		}
		if (size == -1) {
			r_print_printf (p, "%s%"PFMT64d"%s", pf_color_num(p), (st64)(st32)addr, pf_color_reset(p));
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%s%"PFMT64d"%s", pf_color_num(p), (st64)(st32)addr, pf_color_reset(p));
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
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			r_print_printf (p, "%"PFMT64d, addr);
		} else {
			r_print_printf (p, "[");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%"PFMT64d, addr);
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
				i += 4;
			}
			r_print_printf (p, " ]");
		}
		r_print_printf (p, "}");
	}
}

static int r_print_format_disasm(const RPrint* p, ut64 seeki, int size) {
	ut64 prevseeki = seeki;

	if (!p->disasm || !p->user) {
		return 0;
	}

	size = R_MAX (1, size);

	while (size-- > 0) {
		seeki += p->disasm (p->user, seeki);
	}

	return seeki - prevseeki;
}

static void r_print_format_octal(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "0%"PFMT64o, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki + ((elem >= 0) ? elem * 4 : 0));
			r_print_printf (p, " = ");
		}
		if (!SEEVALUE) {
			r_print_printf (p, "(octal) ");
		}
		if (size == -1) {
			r_print_printf (p, "%s 0%08"PFMT64o"%s", pf_color_num(p), addr, pf_color_reset(p));
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%s0%08"PFMT64o"%s", pf_color_num(p), addr, pf_color_reset(p));
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
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			r_print_printf (p, "%"PFMT64d, addr);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%"PFMT64d, addr);
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
				i += 4;
			}
			r_print_printf (p, " ]");
		}
		r_print_printf (p, "}");
	}
}

static void r_print_format_hexflag(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr = 0;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "0x%08"PFMT64x, addr & UT32_MAX);
	} else if (MUSTSEE) {
		ut32 addr32 = (ut32)addr;
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki + ((elem >= 0) ? elem * 4 : 0));
			r_print_printf (p, " = ");
		}
		if (size == -1) {
			if (ISQUIET && (addr32 == UT32_MAX)) {
				r_print_printf (p, "-1");
			} else {
				pf_print_value_hex (p, "0x%08"PFMT64x, (ut64)addr32);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					pf_print_value_hex (p, "0x%08"PFMT64x, addr);
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
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			r_print_printf (p, "%"PFMT64d, addr);
		} else {
			r_print_printf (p, "[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					r_print_printf (p, ",");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			r_print_printf (p, " ]");
		}
		r_print_printf (p, "}");
	}
}

static int r_print_format_10bytes(const RPrint* p, int mode, const char *setval, ut64 seeki, ut64 addr, ut8* buf) {
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
			printf ("(cannot read memory)\n");
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
			printf ("(cannot read memory)\n");
			return -1;
		} else {
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		}
		r_print_printf (p, "[ %d", buf[0]);
		j = 1;
		for (; j < 10; j++) {
			r_print_printf (p, ", %d", buf[j]);
		}
		r_print_printf (p, " ]");
		return 0;
	}
	return 0;
}

static int r_print_format_hexpairs(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int j;
	size = (size == -1) ? 1 : size;
	if (MUSTSET) {
		r_print_printf (p, "?e pf X not yet implemented\n");
	} else if (mode & R_PRINT_DOT) {
		for (j = 0; j < size; j++) {
			r_print_printf (p, "%02x", buf[i + j]);
		}
	} else if (MUSTSEE) {
		size = (size < 1) ? 1 : size;
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
					r_print_printf (p, "%c", buf[i+j]);
				} else {
					r_print_printf (p, ".");
				}
			}
		}
		r_print_printf (p, ")");
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		size = (size < 1) ? 1 : size;
		r_print_printf (p, "[ %d", buf[0]);
		j = 1;
		for (; j < 10; j++) {
			r_print_printf (p, ", %d", buf[j]);
		}
		r_print_printf (p, " ]");
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
		return size;
	}
	return size;
}

static void r_print_format_float(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, const ut8* buf, int i, int size) {
	ut64 addr = 0;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size / ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	float val_f = updateAddr (buf + i, 999, endian, &addr, NULL);
	if (MUSTSET) {
		r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval,
			seeki + ((elem >= 0) ? elem * 4 : 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.9g", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08"PFMT64x" = ",
					seeki + ((elem >= 0) ? elem * 4 : 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.9g", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				val_f = updateAddr (buf + i, 9999, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%.9g", val_f);
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
				i += 4;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

static void r_print_format_double(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	double val_f = 0.0;
	ut64 addr = 0;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, 999, endian, &addr, NULL);
	r_mem_swaporcopy ((ut8*)&val_f, buf + i, sizeof (double), endian);
	if (MUSTSET) {
		r_print_printf (p, "wv8 %s @ 0x%08"PFMT64x"\n", setval,
			seeki + ((elem >= 0) ? elem * 8 : 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.17lg", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08"PFMT64x" = ",
					seeki + ((elem >= 0) ? elem * 8 : 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.17lg", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				// XXX this 999 is scary
				updateAddr (buf + i, 9999, endian, &addr, NULL);
				r_mem_swaporcopy ((ut8*)&val_f, buf + i, sizeof (double), endian);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%.17lg", val_f);
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
				i += 8;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
}

static void r_print_format_long_double(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size) {
#if R2_NO_LONG_DOUBLE
	// just fallback to double
	r_print_format_double (p, endian, mode, setval, seeki, buf, i, size);
#else
	long double val_f = 0.0;
	ut64 addr = 0;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, 999, endian, &addr, NULL);
	// Read value using the appropriate size
	r_mem_swaporcopy ((ut8*)&val_f, buf + i, sizeof (long double), endian);
	if (MUSTSET) {
		r_print_printf (p, "wv8 %s @ 0x%08"PFMT64x"\n", setval,
				seeki + ((elem >= 0) ? elem * 8 : 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_printf (p, "%.17Lg", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				r_print_printf (p, "0x%08"PFMT64x" = ",
						seeki + ((elem >= 0) ? elem * 8 : 0));
			}
		}
		if (size == -1) {
			r_print_printf (p, "%.17Lg", val_f);
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				// XXX this 999 is scary
				updateAddr (buf + i, 9999, endian, &addr, NULL);
				r_mem_swaporcopy ((ut8*)&val_f, buf + i, sizeof (double), endian);
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%.17Lg", val_f);
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
				i += 8;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
		if (MUSTSEEJSON) {
			r_print_printf (p, "}");
		}
	}
#endif
}

static void r_print_format_word(const RPrint* p, int endian, int mode, const char *setval, ut64 seeki, ut8* buf, int i, int size, bool sign) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	addr = endian
		? (*(buf + i)) << 8 | (*(buf + i + 1))
		: (*(buf + i + 1)) << 8 | (*(buf + i));
	if (MUSTSET) {
		r_print_printf (p, "wv2 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*2:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		if (size == -1) {
			if (sign) {
				r_print_printf (p, "%d", (int)(short)addr);
			} else {
				r_print_printf (p, "0x%04"PFMT64x, addr);
			}
		}
		while ((size -= 2) > 0) {
			addr = endian
				? (*(buf+i))<<8 | (*(buf+i+1))
				: (*(buf+i+1))<<8 | (*(buf+i));
			if (sign) {
				addr = (st64)(short)addr;
			}
			if (elem == -1 || elem == 0) {
				r_print_printf (p, "%"PFMT64d, addr);
				if (elem == 0) {
					elem = -2;
				}
			}
			if (size != 0 && elem == -1) {
				r_print_printf (p, ",");
			}
			if (elem > -1) {
				elem--;
			}
			i += 2;
		}
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			pf_print_addr (p, seeki+((elem>=0)?elem*2:0));
			r_print_printf (p, " = ");
		}
		if (size == -1) {
			if (sign) {
				r_print_printf (p, "%s%"PFMT64d"%s", pf_color_num(p), (st64)(short)addr, pf_color_reset(p));
			} else {
				pf_print_value_hex (p, "0x%04"PFMT64x, addr);
			}
		} else {
			if (!SEEVALUE) {
				r_print_printf (p, "[ ");
			}
			while (size--) {
				addr = endian
					? (*(buf+i))<<8 | (*(buf+i+1))
					: (*(buf+i+1))<<8 | (*(buf+i));
				if (elem == -1 || elem == 0) {
					pf_print_value_hex (p, "0x%04"PFMT64x, addr);
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
				i += 2;
			}
			if (!SEEVALUE) {
				r_print_printf (p, " ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size==-1) {
			r_print_printf (p, "%"PFMT64d, addr);
		} else {
			r_print_printf (p, "[ ");
			while ( (size -= 2) >0) {
				addr = endian
					? (*(buf+i))<<8 | (*(buf+i+1))
					: (*(buf+i+1))<<8 | (*(buf+i));
				if (elem == -1 || elem == 0) {
					r_print_printf (p, "%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					r_print_printf (p, ",");
				}
				if (elem > -1) {
					elem--;
				}
				i += 2;
			}
			r_print_printf (p, " ]");
		}
		r_print_printf (p, "}");
	}
}

static void r_print_byte_escape(const RPrint* p, const char *src, char **dst, int dot_nl) {
	R_RETURN_IF_FAIL (p->strconv_mode);
	r_str_byte_escape (src, dst, dot_nl, !strcmp (p->strconv_mode, "asciidot"), p->esc_bslash);
}

static void r_print_format_nulltermstring(const RPrint* p, int len, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	if (!p->iob.is_valid_offset (p->iob.io, seeki, 1)) {
		ut8 ch = 0xff;
		// XXX there are some cases where the memory is there but is_valid_offset fails wtf
		if (p->iob.read_at (p->iob.io, seeki, &ch, 1) != 1 && ch != 0xff) {
			r_print_printf (p, "\"\"");
			if (MUSTSEEJSON) {
				r_print_printf (p, "}");
			}
			return;
		}
	}
	if (p->flags & R_PRINT_FLAGS_UNALLOC && !(p->iob.io->cache.mode & R_PERM_R)) {
		ut64 total_map_left = 0;
		ut64 addr = seeki;
		RIOMap *map;
		while (total_map_left < len
				&& (map = p->iob.io->va
					? p->iob.map_get_at (p->iob.io, addr)
					: p->iob.map_get_paddr (p->iob.io, addr))
				&& map->perm & R_PERM_R) {
			if (!r_io_map_size (map)) {
				total_map_left = addr == 0
					? UT64_MAX
					: UT64_MAX - addr + 1;
				break;
			}
			total_map_left += r_io_map_size (map) - (addr
				- (p->iob.io->va ? r_io_map_begin (map) : map->delta));
			addr += total_map_left;
		}
		if (total_map_left < len) {
			len = total_map_left;
		}
	}
	int str_len = r_str_nlen ((char *)buf + i, len - i);
	bool overflow = (size == -1 || size > len - i) && str_len == len - i;
	if (MUSTSET) {
		int buflen = strlen ((const char *)buf + seeki);
		int vallen = strlen (setval);
		char *ons, *newstring = ons = strdup (setval);
		if ((newstring[0] == '\"' && newstring[vallen - 1] == '\"')
				|| (newstring[0] == '\'' && newstring[vallen - 1] == '\'')) {
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
		r_print_printf (p, " @ 0x%08"PFMT64x"\n", seeki);
		free (ons);
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		int j = i;
		(MUSTSEESTRUCT) ?
			r_print_printf (p, "\"") :
			r_print_printf (p, "\\\"");
		for (; j < len && ((size==-1 || size-- >0) && buf[j]) ; j++) {
			char ch = buf[j];
			if (ch == '"') {
				r_print_printf (p, "\\\"");
			} else if (IS_PRINTABLE (ch)) {
				r_print_printf (p, "%c", ch);
			} else {
				r_print_printf (p, ".");
			}
		}
		(MUSTSEESTRUCT) ?
			r_print_printf (p, "\"") :
			r_print_printf (p, "\\\"");
	} else if (MUSTSEE) {
		int j = i;
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08" PFMT64x " = %s", seeki, overflow ? "ovf " : "");
		}
		r_print_printf (p, "\"");
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]) ; j++) {
			char esc_str[5] = {0};
			char *ptr = esc_str;
			r_print_byte_escape (p, (char *)&buf[j], &ptr, false);
			r_print_printf (p, "%s", esc_str);
		}
		r_print_printf (p, "\"");
	} else if (MUSTSEEJSON) {
		char *utf_encoded_buf = NULL;
		r_print_printf (p, "\"");
		utf_encoded_buf = r_str_escape_json (
		    (char *)buf + i, size == -1 ? str_len : R_MIN (size, str_len));
		if (utf_encoded_buf) {
			r_print_printf (p, "%s", utf_encoded_buf);
			free (utf_encoded_buf);
		}
		r_print_printf (p, "\"");
		if (overflow) {
			r_print_printf (p, ",\"overflow\":true");
		}
		r_print_printf (p, "}");
	}
}

static void r_print_format_nulltermwidestring(const RPrint* p, const int len, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	if (MUSTSET) {
		int vallen = strlen(setval);
		char *newstring, *ons;
		newstring = ons = strdup(setval);
		if ((newstring[0] == '\"' && newstring[vallen-1] == '\"')
				|| (newstring[0] == '\'' && newstring[vallen-1] == '\'')) {
			newstring[vallen - 1] = '\0';
			newstring++;
			vallen -= 2;
		}
		if ((size = vallen) > r_wstr_clen((char*)(buf+seeki))) {
			R_LOG_WARN ("new string is longer than previous one");
		}
		r_print_printf (p, "ww %s @ 0x%08"PFMT64x"\n", newstring, seeki);
		free (ons);
	} else if (MUSTSEE) {
		int j = i;
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08"PFMT64x" = ", seeki);
		}
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]) ; j += 2) {
			if (IS_PRINTABLE (buf[j])) {
				r_print_printf (p, "%c", buf[j]);
			} else {
				r_print_printf (p, ".");
			}
		}
	} else if (MUSTSEEJSON) {
		int j = i;
		r_print_printf (p, "%"PFMT64d",\"string\":\"", seeki);
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]); j += 2) {
			if (IS_PRINTABLE (buf[j])) {
				r_print_printf (p, "%c", buf[j]);
			} else {
				r_print_printf (p, ".");
			}
		}
		r_print_printf (p, "\"}");
	}
}

static void r_print_format_bitfield(const RPrint* p, ut64 seeki, char *fmtname,
		char *fieldname, ut64 addr, int mode, int size) {
	char *bitfield = NULL;
	if (size >= 8) {
		addr = 0;
	} else {
		addr &= (1ULL << (size * 8)) - 1;
	}
	if (MUSTSEE && !SEEVALUE) {
		r_print_printf (p, "0x%08"PFMT64x" = ", seeki);
	}
	bitfield = r_type_enum_getbitfield (p->sdb_types, fmtname, addr);
	if (bitfield && *bitfield) {
		if (MUSTSEEJSON) {
			r_print_printf (p, "\"%s\"}", bitfield);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (bitfield) = %s\n", fieldname, bitfield);
		}
	} else {
		if (MUSTSEEJSON) {
			r_print_printf (p, "\"`tb %s 0x%"PFMT64x"`\"}", fmtname, addr);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (bitfield) = `tb %s 0x%"PFMT64x"`\n",
				fieldname, fmtname, addr);
		}
	}
	free (bitfield);
}

static void r_print_format_enum(const RPrint* p, ut64 seeki, char *fmtname,
		char *fieldname, ut64 addr, int mode, int size) {
	R_RETURN_IF_FAIL (p && fmtname && fieldname);
	if (size >= 8) {
		// avoid shift overflow
	} else {
		addr &= (1ULL << (size * 8)) - 1;
	}
	if (MUSTSEE && !SEEVALUE) {
		r_print_printf (p, "0x%08"PFMT64x" = ", seeki);
	}
	char *enumvalue = r_type_enum_member (p->sdb_types, fmtname, NULL, addr);
	if (R_STR_ISNOTEMPTY (enumvalue)) {
		if (mode & R_PRINT_DOT) {
			r_print_printf (p, "%s.%s", fmtname, enumvalue);
		} else if (MUSTSEEJSON) {
			r_print_printf (p, "%"PFMT64d",\"label\":\"%s\",\"enum\":\"%s\"}",
				addr, enumvalue, fmtname);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (enum %s) = 0x%"PFMT64x" ; %s\n",
				fieldname, fmtname, addr, enumvalue);
		} else if (MUSTSEESTRUCT) {
			r_print_printf (p, "%s", enumvalue);
		}
	} else {
		if (MUSTSEEJSON) {
			r_print_printf (p, "%"PFMT64d",\"enum\":\"%s\"}", addr, fmtname);
		} else if (MUSTSEE) {
			r_print_printf (p, "%s (enum %s) = 0x%"PFMT64x"\n",//`te %s 0x%x`\n",
				fieldname, fmtname, addr); //enumvalue); //fmtname, addr);
		}
	}
	free (enumvalue);
}

static void r_print_format_register(const RPrint* p, int mode,
		const char *name, const char *setval) {
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
			r_print_printf (p, "%"PFMT64d"}", p->get_register_value (p->reg, ri));
		}
	} else {
		r_print_printf (p, "Register %s does not exists\n", name);
	}
}

static void r_print_format_num_specifier(const RPrint *p, ut64 addr, int bytes, int sign) {
#define EXT(T) (sign ? (signed T)(addr) : (unsigned T)(addr) )
	const char *fs64 = sign ? "%"PFMT64d : "%"PFMT64u;
	const char *fs = sign ? "%d" : "%u";
	if (bytes == 1) {
		r_print_printf (p, fs, EXT(char));
	} else if (bytes == 2) {
		r_print_printf (p, fs, EXT(short));
	} else if (bytes == 4) {
		r_print_printf (p, fs, EXT(int)); //XXX: int is not necessarily 4 bytes I guess.
	} else if (bytes == 8) {
		r_print_printf (p, fs64, addr);
	}
#undef EXT
}

static void r_print_format_num(const RPrint *p, int endian, int mode, const char *setval, ut64 seeki, ut8 *buf, int i, int bytes, int sign, int size) {
	ut64 addr = 0LL;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size / ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	if (bytes == 8) {
		updateAddr (buf + i, size - i, endian, NULL, &addr);
	} else {
		updateAddr (buf + i, size - i, endian, &addr, NULL);
	}
	if (MUSTSET) {
		r_print_printf (p, "wv%d %s @ 0x%08"PFMT64x"\n", bytes, setval, seeki+((elem>=0)?elem*(bytes):0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_format_num_specifier (p, addr, bytes, sign);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			r_print_printf (p, "0x%08"PFMT64x" = ", seeki + ((elem >= 0)? elem * bytes: 0));
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
				if (elem == -1 || elem == 0) {
					r_print_format_num_specifier (p, addr, bytes, sign);
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
				if (elem == -1 || elem == 0) {
					r_print_format_num_specifier (p, addr, bytes, sign);
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
				i += bytes;
			}
			r_print_printf (p, " ]");
		}
		r_print_printf (p, "}");
	}
}

R_API const char *r_print_format_byname(RPrint *p, const char *name) {
	return sdb_const_get (p->formats, name, NULL);
}

// XXX: this is somewhat incomplete. must be updated to handle all format chars
R_API int r_print_format_struct_size(RPrint *p, const char *f, int mode, int n) {
	char *end, *args, *fmt;
	int size = 0, tabsize = 0, i, idx = 0, biggest = 0, fmt_len = 0, times = 1;
	bool tabsize_set = false;
	bool free_fmt2 = true;
	if (!f) {
		return -1;
	}
	if (n >= 5) {  // This is the nesting level, is this not a bit arbitrary?!
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
	if (!end && !(end = strchr (o, '\0'))) {
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
			char *end = strchr (fmt + i,']');
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
			size += tabsize * (p_bits / 8);
			i++;
			idx--;	//no need to go ahead for args
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
			bool format_owned = false; /* We may or may not free format */
			char *endname = NULL, *structname = NULL;
			char tmp = 0;
			if (words < idx) {
				R_LOG_ERROR ("Index out of bounds");
			} else {
				wordAtIndex = r_str_word_get0 (args, idx);
			}
			if (!wordAtIndex) {
				break;
			}
			structname = strdup (wordAtIndex);
			if (*structname == '(') {
				endname = (char*)r_str_rchr (structname, NULL, ')');
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
				if (format && !strncmp (format, f, strlen (format) - 1)) { // Avoid recursion here
					R_FREE (format);
					free (o);
					free (structname);
					return -1;
				}
				if (!format) { // Fetch format from types db
					format = r_type_format (p->sdb_types, structname + 1);
				}
				format_owned = true;
			}
			if (!format) {
				R_LOG_ERROR ("Cannot find format for struct `%s'", structname + 1);
				free (structname);
				free (o);
				return 0;
			}
			int newsize = r_print_format_struct_size (p, format, mode, n + 1);
			if (newsize < 1) {
				R_LOG_ERROR ("Cannot find size for `%s'", format);
				free (structname);
				free (o);
				return 0;
			}
			if (format) {
				if (!ST32_MUL_OVFCHK (tabsize, newsize)) {
					size = size + (tabsize * newsize);
				} else {
					R_LOG_ERROR ("Prevented multiply integer overflow in format.c");
					return 0;
				}
			}
			free (structname);
			if (format_owned) {
				R_FREE (format);
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
			if (fmt[i+1] == '2') {
				size += tabsize * 2;
			} else if (fmt[i+1] == '4') {
				size += tabsize * 4;
			} else if (fmt[i+1] == '8') {
				size += tabsize * 8;
			} else {
				size += tabsize * (p_bits / 8);
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
		case 'u':
		case 'D':
		case 'T':
			//TODO complete this.
		default:
			//idx--; //Does this makes sense?
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
	return (mode & R_PRINT_UNIONMODE)? biggest : size;
}

static int r_print_format_struct(RPrint* p, ut64 seek, const ut8* b, int len, const char *name,
		int slide, int mode, const char *setval, char *field, int anon) {
	const char *fmt;
	bool fmt_owned = false;
	char namefmt[128];
	int ret;

	slide++;
	if ((slide % STRUCTPTR) > NESTDEPTH || (slide % STRUCTFLAG)/STRUCTPTR > NESTDEPTH) {
		R_LOG_ERROR ("Too much nested struct, too much recursion");
		return 0;
	}
	if (anon) {
		fmt = name;
	} else {
		fmt = sdb_get (p->formats, name, NULL);
		if (!fmt) { // Fetch struct info from types DB
			fmt = r_type_format (p->sdb_types, name);
		}
		fmt_owned = true;
	}
	if (!fmt || !*fmt) {
		R_LOG_ERROR ("Undefined struct '%s'", name);
		return 0;
	}
	if (MUSTSEE && !SEEVALUE) {
		snprintf (namefmt, sizeof (namefmt), "%%%ds", 10+6*slide%STRUCTPTR);
		if (fmt[0] == '0') {
			r_print_printf (p, namefmt, "union");
		} else {
			r_print_printf (p, namefmt, "struct");
		}
		r_print_printf (p, "<%s>\n", name);
	}
	r_print_format (p, seek, b, len, fmt, mode, setval, field);
	ret = r_print_format_struct_size (p, fmt, mode, 0);
	if (fmt_owned) {
		R_FREE (fmt);
	}
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
	char *type = NULL;
	switch (fmt) {
	case 'b':
	case 'C':
		type = strdup ("uint8_t");
		break;
	case 'c':
		type = strdup ("int8_t");
		break;
	case 'd':
	case 'i':
	case 'o':
	case 'x':
		type = strdup ("int32_t");
		break;
	case 'E':
		type = strdup ("enum");
		break;
	case 'f':
		type = strdup ("float");
		break;
	case 'F':
		type = strdup ("double");
		break;
	case 'G':
		type = strdup ("long_double");
		break;
	case 'q':
		type = strdup ("uint64_t");
		break;
	case 'u':
		type = strdup ("uleb128_t");
		break;
	case 'Q':
		type = strdup ("uint128_t");
		break;
	case 'w':
		type = strdup ("uint16_t");
		break;
	case 'W':
		type = strdup ("int16_t");
		break;
	case 'X':
		type = strdup ("uint8_t[]");
		break;
	case 'D':
	case 's':
	case 'S':
	case 't':
	case 'z':
	case 'Z':
		type = strdup ("char*");
		break;
	case 'n':
	case 'N':
		switch (arg) {
		case '1':
			type = strdup (fmt == 'n' ? "int8_t" : "uint8_t");
			break;
		case '2':
			type = strdup (fmt == 'n' ? "int16_t" : "uint16_t");
			break;
		case '4':
			type = strdup (fmt == 'n' ? "int32_t" : "uint32_t");
			break;
		case '8':
			type = strdup (fmt == 'n' ? "int64_t" : "uint64_t");
			break;
		}
		break;
	}
	return type;
}

//TODO PJ
#define MINUSONE ((void*)(size_t)-1)
#define ISSTRUCT (tmp == '?' || (tmp == '*' && *(arg+1) == '?'))
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* b, const int len, const char *formatname, int mode, const char *setval, char *ofield) {
	int nargs, i, j, invalid, nexti, idx, times, otimes, endian, isptr = 0;
	const int old_bits = (p && p->config)? p->config->bits: 32;
	int p_bits = old_bits;
	char *args = NULL, *bracket, tmp, last = 0;
	ut64 addr = 0, addr64 = 0, seeki = 0;
	// XXX delete global
	static R_TH_LOCAL int slide = 0, oldslide = 0, ident = 4;
	char namefmt[128], *field = NULL;
	const char *arg = NULL;
	const char *fmt = NULL;
	bool fmt_owned = false;
	const char *argend;
	int viewflags = 0;
	char *oarg = NULL;
	char *internal_format = NULL;

	/* Load format from name into fmt */
	if (!formatname) {
		return 0;
	}
	fmt = p? sdb_get (p->formats, formatname, NULL): NULL;
	if (fmt) {
		fmt_owned = true;
	} else {
		fmt = formatname;
	}
	internal_format = strdup (fmt);
	if (fmt_owned) {
		R_FREE (fmt);
	}
	fmt = internal_format;
	while (*fmt && IS_WHITECHAR (*fmt)) {
		fmt++;
	}
	argend = fmt + strlen (fmt);
	arg = fmt;

	nexti = nargs = i = j = 0;

	if (len < 1) {
		free (internal_format);
		return 0;
	}
	// len+2 to save space for the null termination in wide strings
	ut8 *buf = calloc (1, len + 2);
	if (!buf) {
		free (internal_format);
		return 0;
	}
	memcpy (buf, b, len);
	endian = (p && p->config)? R_ARCH_CONFIG_IS_BIG_ENDIAN (p->config): R_SYS_ENDIAN;

	if (ofield && ofield != MINUSONE) {
		field = strdup (ofield);
	}
	/* get times */
	otimes = times = atoi (arg);
	if (times > 0) {
		while (isdigit(*arg)) {
			arg++;
		}
	}

	bracket = strchr (arg,'{');
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
			int len = strlen (nm ? nm + 1 : tmp);
			if (len > maxl) {
				maxl = len;
			}
		}
		const char *ends = " "; // XXX trailing space warning
		snprintf (namefmt, sizeof (namefmt), "%%%ds :%s",
			((maxl + 1) * (1 + slide)) % STRUCTPTR, ends);
	}
#define ISPOINTED ((slide%STRUCTFLAG)/STRUCTPTR<=(oldslide%STRUCTFLAG)/STRUCTPTR)
#define ISNESTED ((slide%STRUCTPTR)<=(oldslide%STRUCTPTR))
	if (mode == R_PRINT_JSON && slide == 0) {
		r_print_printf (p, "[");
	}
	if (mode == R_PRINT_STRUCT) {
		if (formatname && *formatname) {
			if (strchr (formatname, ' ')) {
				r_print_printf (p, "struct {\n");
			} else {
				r_print_printf (p, "struct %s {\n", formatname);
			}
		} else {
			r_print_printf (p, "struct {\n");
		}
	}
	if (mode && arg[0] == '0') {
		mode |= R_PRINT_UNIONMODE;
		arg++;
	} else {
		mode &= ~R_PRINT_UNIONMODE;
	}
	if (mode & R_PRINT_DOT) {
		char *fmtname;
		if (formatname && *formatname) {
			if (strchr (formatname, ' ')) {
				fmtname = r_str_newf ("0x%"PFMT64x, seek);
			} else {
				fmtname = strdup (formatname);
			}
		} else {
			fmtname = r_str_newf ("0x%"PFMT64x, seek);
		}
		r_print_printf (p, "digraph g { graph [ rank=same; rankdir=LR; ];\n");
		r_print_printf (p, "root [ rank=1; shape=record\nlabel=\"%s", fmtname);
	}

	/* go format */
	i = 0;
	if (!times) {
		otimes = times = 1;
	}
	for (; times; times--) { // repeat N times
		const char *orig = arg;
		int first = 1;
		if (otimes > 1) {
			if (mode & R_PRINT_JSON) {
				if (otimes > times) {
					r_print_printf (p, ",");
				}
				r_print_printf (p, "[{\"index\":%d,\"offset\":%"PFMT64d"},", otimes-times, seek+i);
			} else if (mode) {
				r_print_printf (p, "0x%08"PFMT64x" [%d] {\n", seek + i, otimes-times);
			}
		}
		arg = orig;
		for (idx = 0; i < len && arg < argend && *arg; arg++) {
			int size = 0, elem = 0; /* size of the array, element of the array */
			char *fieldname = NULL, *fmtname = NULL;
			if (mode & R_PRINT_UNIONMODE) {
				i = 0;
			}
			seeki = seek + i;
			addr = 0LL;
			invalid = 0;
			p_bits = old_bits;
			if (arg[0] == '[') {
				char *end = strchr (arg,']');
				if (!end) {
					R_LOG_ERROR ("No end bracket");
					goto beach;
				}
				*end = '\0';
				size = r_get_size (p->num, buf, endian, arg + 1);
				arg = end + 1;
				*end = ']';
			} else {
				size = -1;
			}
			int fs = r_print_format_struct_size (p, arg, 0, idx);
			if (fs == -2) {
				i = -1;
				goto beach;
			}
			if (fs < 1) {
				fs = 4;
			}
			if (i + fs - 1 < len) { // should be +7 to avoid oobread on 'q'
					// Max byte number where updateAddr will look into
				if (len - i < 7) {
					updateAddr (buf + i, THRESHOLD - (len - i), endian, &addr, &addr64);
				} else {
					updateAddr (buf + i, len - i, endian, &addr, &addr64);
				}
				if (p_bits == 64) {
					addr = addr64;
				}
			} else {
				R_LOG_WARN ("format string (%s) is too large for this buffer (%d, %d)", formatname, i + fs, len);
				goto beach;
			}

			tmp = *arg;

			if (mode && !args) {
				mode |= R_PRINT_ISFIELD;
			}
			if (!(mode & R_PRINT_QUIET)) {
				if (mode & R_PRINT_MUSTSEE && otimes > 1) {
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
						fieldname = (char*)r_str_rchr (fieldname, NULL, ')');
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
				if (mode && (!args || (!field && ofield != MINUSONE)
						|| (field && !strncmp (field, fieldname, \
							strchr (field, '[')
						? strchr (field, '[') - field
						: strlen (field) + 1)))) {
					mode |= R_PRINT_ISFIELD;
				} else {
					mode &= ~R_PRINT_ISFIELD;
				}

				/* There we handle specific element in array */
				if (field && (bracket = strchr (field, '[')) && mode & R_PRINT_ISFIELD) {
					char *end = strchr (field, ']');
					if (!end) {
						R_LOG_ERROR ("Missing closing bracket");
						goto beach;
					}
					*end = '\0';
					elem = r_num_math (NULL, bracket + 1) + 1; // +1 to handle 0 index easily
					for ( ; bracket < end; bracket++) {
						*bracket = '\0';
					}
					size += elem * ARRAYINDEX_COEF;
				} else {
					elem = -1;
				}
				if (tmp != '.' && tmp != ':') {
					idx++;
					if (MUSTSEE && !SEEVALUE) {
						if (!ISQUIET) {
							r_print_printf (p, namefmt, fieldname);
						}
					}
				}
			}
		feed_me_again:
			switch (isptr) {
			case PTRSEEK:
				{
				nexti = i + (p_bits / 8);
				i = 0;
				if (tmp == '?') {
					seeki = addr;
				}
				memset (buf, '\0', len);
				if (MUSTSEE && !ISQUIET) {
					r_print_printf (p, "(*0x%"PFMT64x")", addr);
				}
				isptr = (addr)? PTRBACK: NULLPTR;
				if (p->iob.read_at) {
					p->iob.read_at (p->iob.io, (ut64)addr, buf, len - 4);
					if (((i + 3) < len) || ((i + 7) < len)) {
						// XXX this breaks pf *D
						if (tmp != 'D') {
							updateAddr (buf + i, len - i, endian, &addr, &addr64);
						}
					} else {
						R_LOG_ERROR ("Likely a heap buffer overflow");
						goto beach;
					}
				} else {
					R_LOG_ERROR ("cannot read at 0x%08"PFMT64x", block: %s, blocksize: 0x%x", addr, b, len);
					r_print_printf (p, "\n");
					goto beach;
				}
				}
				break;
			case PTRBACK:
				// restore state after pointer seek
				i = nexti;
				memcpy (buf, b, len);
				isptr = NOPTR;
				arg--;
				continue;
			}
			if (tmp == 0 && last != '*') {
				break;
			}

			/* skip chars */
			switch (tmp) {
			case '*': // next char is a pointer
				isptr = PTRSEEK;
				arg++;
				tmp = *arg; //last;
				goto feed_me_again;
			case '+': // toggle view flags
				viewflags = !viewflags;
				continue;
			case 'e': // tmp swap endian
				endian ^= 1;
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
			if (mode & R_PRINT_SEEFLAGS && isptr != NULLPTR) {
				char *newname = NULL;
				if (!fieldname) {
					newname = fieldname = r_str_newf ("pf.%"PFMT64u, seeki);
				}
				if (mode & R_PRINT_UNIONMODE) {
					r_print_printf (p, "f %s=0x%08"PFMT64x"\n", formatname, seeki);
					goto beach;
				} else if (tmp == '?') {
					r_print_printf (p, "f %s.%s_", fmtname, fieldname);
				} else if (tmp == 'E') {
					r_print_printf (p, "f %s=0x%08"PFMT64x"\n", fieldname, seeki);
				} else if (slide/STRUCTFLAG>0 && idx == 1) {
					r_print_printf (p, "%s=0x%08"PFMT64x"\n", fieldname, seeki);
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
					r_print_printf (p, "|{0x%"PFMT64x"|%c|%s|<%s>",
						seeki, tmp, fieldname, fieldname);
				} else {
					r_print_printf (p, "|{0x%"PFMT64x"|%c|",
						seeki, tmp);
				}
			}

			/* json */
			if (MUSTSEEJSON && mode & R_PRINT_JSON) {
				if (oldslide <= slide) {
					if (first) {
						first = 0;
					} else {
						r_print_printf (p, ",");
					}
				} else if (oldslide) {
					r_print_printf (p, "]},");
					oldslide -= NESTEDSTRUCT;
				}
				if (fieldname) {
					r_print_printf (p, "{\"name\":\"%s\",\"type\":\"", fieldname);
				} else {
					r_print_printf (p, "{\"type\":\"");
				}
				if (ISSTRUCT) {
					r_print_printf (p, "%s", fmtname);
				} else {
					if (tmp == 'n' || tmp == 'N') {
						r_print_printf (p, "%c%c", tmp, *(arg+1));
					} else {
						r_print_printf (p, "%c", tmp);
					}
				}
				if (isptr) {
					r_print_printf (p, "*");
				}
				r_print_printf (p, "\",\"offset\":%"PFMT64d",\"value\":",
					(isptr)? (seek + nexti - (p_bits / 8)) : seek + i);
			}

			/* c struct */
			if (MUSTSEESTRUCT) {
				char *type = get_format_type (tmp, (tmp == 'n' || tmp == 'N') ? arg[1] : 0);
				if (type) {
					r_print_printf (p, "%*c%s %s; // ", ident, ' ', type, fieldname);
				} else {
					r_print_printf (p, "%*cstruct %s {", ident, ' ', fieldname);
				}
				free (type);
			}
			bool noline = false;

			int oi = i;
			if (isptr == NULLPTR) {
				if (MUSTSEEJSON) {
					r_print_printf (p, "\"NULL\"}");
				} else if (MUSTSEE) {
					r_print_printf (p, " NULL\n");
				}
				isptr = PTRBACK;
			} else {
				/* format chars */
				// before to enter in the switch statement check buf boundaries due to  updateAddr
				// might go beyond its len and it's usually called in each of the following functions
				switch (tmp) {
				case 'u':
					i += r_print_format_uleb (p, endian, mode, setval, seeki, buf, i, size);
					break;
				case 't':
					r_print_format_time (p, endian, mode, setval, seeki, buf, i, size);
					i += (size==-1)? 4: 4 * size;
					break;
				case 'P':
					{
						st32 sw = (st32) r_read_le32 (buf + i);
						if (MUSTSEEJSON) {
							r_print_printf (p, "\"0x%"PFMT64x"\"}", (ut64)seeki + sw);
						} else if (MUSTSEE) {
							r_print_printf (p, "0x%"PFMT64x, (ut64)seeki + sw);
						} else {
							r_print_printf (p, "0x%"PFMT64x"\n", (ut64)seeki + sw);
						}
						i += 4;
					}
					break;
				case 'q':
					r_print_format_quadword (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? 8: 8 * size;
					break;
				case 'Q':
					r_print_format_u128 (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? 16: 16 * size;
					break;
				case 'b':
					r_print_format_byte (p, endian, mode, setval, seeki, buf, i, size);
					i += (size==-1)? 1: size;
					break;
				case 'C':
					r_print_format_decchar (p, endian, mode, setval, seeki, buf, i, size);
					i += (size==-1)? 1: size;
					break;
				case 'c':
					r_print_format_char (p, endian, mode, setval, seeki, buf, i, size);
					i += (size==-1)? 1: size;
					break;
				case 'X':
					size = r_print_format_hexpairs (p, endian, mode, setval, seeki, buf, i, size);
					i += size;
					break;
				case 'T':
					if (r_print_format_10bytes (p, mode,
						setval, seeki, addr, buf) == 0) {
						i += (size == -1)? 4: 4 * size;
					}
					break;
				case 'f':
					r_print_format_float (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'F':
					r_print_format_double (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? sizeof (double): sizeof (double) * size;
					break;
				case 'G':
					r_print_format_long_double (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? sizeof (long double): sizeof (long double) * size;
					break;
				case 'i':
					r_print_format_int (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4 * size;
					break;
				case 'd':
					r_print_format_hex (p, endian, mode, setval, seeki, buf, i, size);
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
					r_print_format_octal (p, endian, mode, setval, seeki, buf, i, size);
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
					r_print_format_hexflag (p, endian, mode, setval, seeki, buf, i, size);
					i += (size == -1)? 4: 4*size;
					break;
				case 'w':
					r_print_format_word (p, endian, mode, setval, seeki, buf, i, size, false);
					i += (size == -1)? 2: 2 * size;
					break;
				case 'W':
					r_print_format_word (p, endian, mode, setval, seeki, buf, i, size, true);
					i += (size == -1)? 2: 2 * size;
					break;
				case 'z': // zero terminated string
					r_print_format_nulltermstring (p, len, endian, mode, setval, seeki, buf, i, size);
					if (size == -1) {
						i += strlen ((char*)buf + i) + 1;
					} else {
						while (size--) {
							i++;
						}
					}
					break;
				case 'Z': // zero terminated wide string
					r_print_format_nulltermwidestring (p, len, endian, mode, setval, seeki, buf, i, size);
					if (size == -1) {
						i += r_wstr_clen((char*)(buf+i))*2+2;
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
					if (r_print_format_string (p, seeki, addr64, addr, 0, mode) == 0) {
						i += (size==-1) ? 4 : 4*size;
					}
					break;
				case 'S':
					if (MUSTSET) {
						R_LOG_ERROR ("Set val not implemented yet for strings!");
					}
					if (r_print_format_string (p, seeki, addr64, addr, 1, mode) == 0) {
						i += (size == -1) ? 8 : 8 * size;
					}
					break;
				case 'B': // resolve bitfield
					if (size >= ARRAYINDEX_COEF) {
						size %= ARRAYINDEX_COEF;
					}
					if (MUSTSET) {
						r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
						// R_LOG_ERROR ("Set val not implemented yet for bitfields!");
					}
					r_print_format_bitfield (p, seeki, fmtname, fieldname, addr, mode, size);
					i += (size == -1)? 1: size;
					break;
				case 'E': // resolve enum
					if (MUSTSET) {
						r_print_printf (p, "wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
					}
					if (size >= ARRAYINDEX_COEF) {
						size %= ARRAYINDEX_COEF;
					}
					if (fmtname) {
						r_print_format_enum (p, seeki, fmtname, fieldname, addr, mode, size);
					} else {
						R_LOG_ERROR ("Missing enum type after the E()");
					}
					i += (size == -1)? 1: size;
					break;
				case 'r':
					if (fmtname) {
						r_print_format_register (p, mode, fmtname, setval);
					} else {
						R_LOG_ERROR ("Unknown register");
					}
					break;
				case '?':
					{
					int s = 0;
					char *nxtfield = NULL;
					char *format = NULL;
					int anon = 0;
					if (size >= ARRAYINDEX_COEF) {
						elem = size / ARRAYINDEX_COEF - 1;
						size %= ARRAYINDEX_COEF;
					}
					if (!(mode & R_PRINT_ISFIELD)) {
						nxtfield = MINUSONE;
					} else if (field) {
						nxtfield = strchr (ofield, '.');
					}
					if (nxtfield != MINUSONE && nxtfield) {
						nxtfield++;
					}

					if (MUSTSEE) {
						if (!SEEVALUE) {
							r_print_printf (p, "\n");
						}
					}
					if (MUSTSEEJSON) {
						if (isptr) {
							r_print_printf (p, "%"PFMT64d"},", seeki);
						} else {
							r_print_printf (p, "[");
						}
					}
					if (MUSTSEESTRUCT) {
						if (isptr) {
							r_print_printf (p, "%"PFMT64d, seeki);
						} else {
							ident += 4;
							r_print_printf (p, "\n");
						}
					}
					if (mode & R_PRINT_SEEFLAGS) {
						slide += STRUCTFLAG;
					}
					if (!fmtname) {
						break;
					}
					format = strchr (fmtname, ' ');
					if (format) {
						anon = 1;
						fmtname = (char *)r_str_trim_head_ro (format);
					}
					oldslide = slide;
					//slide += (isptr) ? STRUCTPTR : NESTEDSTRUCT;
					slide += NESTEDSTRUCT;
					if (size == -1) {
						s = r_print_format_struct (p, seeki,
									buf + i, len - i, fmtname, slide,
									mode, setval, nxtfield, anon);
						i += (isptr) ? (p_bits / 8) : s;
						if (MUSTSEEJSON) {
							if (!isptr && (!arg[1] || arg[1] == ' ')) {
								r_print_printf (p, "]}");
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
							s = r_print_format_struct (p, seek + i,
									buf+i, len-i, fmtname, slide, mode, setval, nxtfield, anon);
							if ((MUSTSEE || MUSTSEEJSON || MUSTSEESTRUCT) && size != 0 && elem == -1) {
								if (MUSTSEEJSON) {
									r_print_printf (p, ",");
								} else if (MUSTSEE || MUSTSEESTRUCT) {
									r_print_printf (p, "\n");
								}
							}
							if (elem > -1) {
								elem--;
							}
							i += (isptr) ? (p_bits / 8) : s;
						}
						if (mode & R_PRINT_ISFIELD) {
							if (!SEEVALUE) {
								r_print_printf (p, "]\n");
							}
						}
						if (MUSTSEEJSON) {
							r_print_printf (p, "]}");
						}
					}
					oldslide = slide;
					//slide -= (isptr) ? STRUCTPTR : NESTEDSTRUCT;
					slide -= NESTEDSTRUCT;
					if (mode & R_PRINT_SEEFLAGS) {
						oldslide = slide;
						slide -= STRUCTFLAG;
					}
					break;
					}
				case 'n':
				case 'N':
					{
						int bytes = 0;
						int sign = (tmp == 'n') ? 1 : 0;
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
							//or goto beach;???
						}
						r_print_format_num (p, endian, mode, setval, seeki, buf, i, bytes, sign, size);
						i += (size == -1)? bytes: size * bytes;
						arg++;
						break;
					}
				default:
					/* ignore unknown chars */
					invalid = 1;
					break;
				} //switch
			}
			if (MUSTSEESTRUCT) {
				if (oldslide) {
					ident -= 4;
					r_print_printf (p, "%*c}", ident, ' ');
					oldslide -= NESTEDSTRUCT;
				}
				r_print_printf (p, "\n");
			}
			if (mode & R_PRINT_DOT) {
				r_print_printf (p, "}");
			}
			if (mode & R_PRINT_SEEFLAGS && isptr != NULLPTR) {
				int sz = i - oi;
				if (sz > 1) {
					r_print_printf (p, "fl %d @ 0x%08"PFMT64x"\n", sz, seeki);
					r_print_printf (p, "Cd %d @ 0x%08"PFMT64x"\n", sz, seeki);
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
			if (MUSTSEEJSON) {
				r_print_printf (p, "]");
			} else if (mode) {
				r_print_printf (p, "}\n");
			}
		}
		arg = orig;
		oldslide = 0;
	}
	if (mode & R_PRINT_JSON && slide == 0) {
		r_print_printf (p, "]\n");
	}
	if (MUSTSEESTRUCT && slide == 0) {
		r_print_printf (p, "}\n");
	}
	if (mode & R_PRINT_DOT) {
		r_print_printf (p, "\"];\n}\n");
		// TODO: show nested structs and field reference lines
	}
beach:
	if (slide == 0) {
		oldslide = 0;
	}
	free (internal_format);
	free (oarg);
	free (buf);
	free (field);
	free (args);
	return i;
}
