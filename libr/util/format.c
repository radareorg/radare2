/* radare - LGPL - Copyright 2007-2020 - pancake & Skia */

#include "r_cons.h"
#include "r_util.h"
#include "r_util/r_print.h"
#include "r_reg.h"
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

//this define is used as a way to acknowledge when updateAddr should take len
//as real len of the buffer
#define THRESHOLD (-4444)

//TODO REWRITE THIS IS BECOMING A NIGHTMARE

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
		p->cb_printf ("\"");
	} else if (!SEEVALUE && !ISQUIET) {
		p->cb_printf ("0x%08"PFMT64x" = (uint128_t)", seeki);
	}
	if (endian) {
		p->cb_printf ("0x%016"PFMT64x"", low);
		p->cb_printf ("%016"PFMT64x, hig);
	} else {
		p->cb_printf ("0x%016"PFMT64x"", hig);
		p->cb_printf ("%016"PFMT64x, low);
	}
	if (MUSTSEEJSON) {
		const char *end = endian? "big": "little";
		p->cb_printf ("\",\"endian\":\"%s\",\"ctype\":\"uint128_t\"}", end);
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
		p->cb_printf ("wv8 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*8:0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08"PFMT64x" = (qword)",
				seeki + ((elem >= 0)? elem * 8: 0));
		}
		if (size == -1) {
			if (addr64 == UT32_MAX || ((st64)addr64 < 0 && (st64)addr64 > -4096)) {
				p->cb_printf ("%d", (int)(addr64));
			} else {
				p->cb_printf ("0x%016"PFMT64x, addr64);
			}
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, NULL, &addr64);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("0x%016"PFMT64x, addr64);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 8;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			p->cb_printf ("%"PFMT64d, addr64);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, NULL, &addr64);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, addr64);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 8;
			}
			p->cb_printf (" ]");
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
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
		p->cb_printf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki + ((elem >= 0) ? elem : 0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08"PFMT64x" = ", seeki + ((elem >= 0) ? elem : 0));
		}
		if (size == -1) {
			p->cb_printf ("0x%02x", buf[i]);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->cb_printf ("0x%02x", buf[i]);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i++;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			p->cb_printf ("%d", buf[i]);
		} else {
			p->cb_printf ("[ ");
			const char *comma = "";
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%s%d", comma, buf[i]);
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
			p->cb_printf (" ]");
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
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
		p->cb_printf ("\"wx %s\" @ 0x%08"PFMT64x"\n", nbr, seeki+offset-s);
		free (tmp);
		free (nbr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki);
		}
		if (size==-1) {
			r_uleb128_decode (buf+i, &offset, &value);
			p->cb_printf ("%"PFMT64d, value);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_uleb128_decode (buf+i, &s, &value);
					i += s;
					offset += s;
					p->cb_printf ("%"PFMT64d, value);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size==-1) {
			r_uleb128_decode (buf+i, &offset, &value);
			p->cb_printf ("\"%"PFMT64d"\"", value);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_uleb128_decode (buf+i, &s, &value);
					i += s;
					offset += s;
					p->cb_printf ("\"%"PFMT64d"\"", value);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
			}
			p->cb_printf (" ]");
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
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
		p->cb_printf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 2 : 0)); //XXX:: shouldn't it be elem*1??
		}
		if (size == -1) {
			p->cb_printf ("'%c'", IS_PRINTABLE (buf[i])?buf[i]:'.');
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->cb_printf ("'%c'", IS_PRINTABLE (buf[i])?buf[i]:'.');
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i++;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			p->cb_printf ("\"%c\"", IS_PRINTABLE (buf[i])?buf[i]:'.');
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->cb_printf ("\"%c\"", IS_PRINTABLE (buf[i])?buf[i]:'.');
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i++;
			}
			p->cb_printf (" ]");
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
		}
	}
}

static void r_print_format_decchar(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		p->cb_printf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem : 0));
		}
		if (size == -1) {
			p->cb_printf ("%d", buf[i]);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%d", buf[i]);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i++;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		if (size == -1) {
			p->cb_printf ("\"%d\"", buf[i]);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->cb_printf ("\"%d\"", buf[i]);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i++;
			}
			p->cb_printf (" ]");
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
		}
	}
}

static int r_print_format_string(const RPrint* p, ut64 seeki, ut64 addr64, ut64 addr, int is64, int mode) {
	ut8 buffer[255];
	buffer[0] = 0;
	if (!p->iob.read_at) {
		eprintf ("(cannot read memory)\n");
		return -1;
	}
	const ut64 at = (is64 == 1)? addr64: (ut64)addr;
	int res = p->iob.read_at (p->iob.io, at, buffer, sizeof (buffer) - 8);
	if (MUSTSEEJSON) {
		char *encstr = r_str_utf16_encode ((const char *)buffer, -1);
		if (encstr) {
			p->cb_printf ("%"PFMT64d",\"string\":\"%s\"}", seeki, encstr);
			free (encstr);
		}
	} else if (MUSTSEESTRUCT) {
		char *encstr = r_str_utf16_encode ((const char *)buffer, -1);
		if (encstr) {
			p->cb_printf ("\"%s\"", encstr);
			free (encstr);
		}
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki);
		}
		if (!SEEVALUE) {
			if (ISQUIET) {
				if (addr == 0LL) {
					p->cb_printf ("NULL");
				} else if (addr == UT32_MAX || addr == UT64_MAX) {
					p->cb_printf ("-1");
				} else {
					p->cb_printf ("0x%08" PFMT64x " ", addr);
				}
			} else {
				p->cb_printf ("0x%08" PFMT64x " -> 0x%08" PFMT64x " ", seeki, addr);
			}
		}
		if (res > 0 && buffer[0] != 0xff && buffer[1] != 0xff) {
			p->cb_printf ("\"%s\"", buffer);
		}
	}
	return 0;
}

static void r_print_format_time(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	struct tm timestruct;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		p->cb_printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if (MUSTSEE) {
		char *timestr = malloc (ASCTIME_BUF_MINLEN);
		if (!timestr) {
			return;
		}
		r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
		*(timestr+24) = '\0';
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 4 : 0));
		}
		if (size==-1) {
			p->cb_printf ("%s", timestr);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
				*(timestr+24) = '\0';
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%s", timestr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
		free (timestr);
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		char *timestr = malloc (ASCTIME_BUF_MINLEN);
		if (!timestr) {
			return;
		}
		r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
		*(timestr+24) = '\0';
		if (size==-1) {
			p->cb_printf ("\"%s\"", timestr);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				r_asctime_r (gmtime_r ((time_t*)&addr, &timestruct), timestr);
				*(timestr+24) = '\0';
				if (elem == -1 || elem == 0) {
					p->cb_printf ("\"%s\"", timestr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			p->cb_printf (" ]");
		}
		free (timestr);
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
		}
	}
}

// TODO: support unsigned int?
static void r_print_format_hex(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		p->cb_printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		p->cb_printf ("%"PFMT64d, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 4 : 0));
		}
		if (size == -1) {
			if (addr == UT64_MAX || addr == UT32_MAX) {
				p->cb_printf ("-1");
			} else {
				p->cb_printf ("%"PFMT64d, addr);
			}
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					if (ISQUIET) {
						if (addr == UT64_MAX || addr == UT32_MAX) {
							p->cb_printf ("-1");
						} else {
							p->cb_printf ("%"PFMT64d, addr);
						}
					} else {
						p->cb_printf ("%"PFMT64d, addr);
					}
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			p->cb_printf ("%"PFMT64d, addr);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i+=4;
			}
			p->cb_printf (" ]");
		}
		p->cb_printf ("}");
	}
}

static void r_print_format_int(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		p->cb_printf ("wv4 %s @ %"PFMT64d"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		p->cb_printf ("0x%08"PFMT64x, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*4:0));
		}
		if (size == -1) {
			p->cb_printf ("%"PFMT64d, (st64)(st32)addr);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, (st64)(st32)addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			p->cb_printf ("%"PFMT64d, addr);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i+=4;
			}
			p->cb_printf (" ]");
		}
		p->cb_printf ("}");
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

static void r_print_format_octal(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		p->cb_printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		p->cb_printf ("0%"PFMT64o, addr);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 4 : 0));
		}
		if (!SEEVALUE) {
			p->cb_printf ("(octal) ");
		}
		if (size == -1) {
			p->cb_printf (" 0%08"PFMT64o, addr);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("0%08"PFMT64o, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i+=4;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			p->cb_printf ("%"PFMT64d, addr);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i+=4;
			}
			p->cb_printf (" ]");
		}
		p->cb_printf ("}");
	}
}

static void r_print_format_hexflag(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr = 0;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf + i, size - i, endian, &addr, NULL);
	if (MUSTSET) {
		p->cb_printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		p->cb_printf ("0x%08"PFMT64x, addr & UT32_MAX);
	} else if (MUSTSEE) {
		ut32 addr32 = (ut32)addr;
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki + ((elem >= 0) ? elem * 4 : 0));
		}
		if (size==-1) {
			if (ISQUIET && (addr32 == UT32_MAX)) {
				p->cb_printf ("-1");
			} else {
				p->cb_printf ("0x%08"PFMT64x, (ut64)addr32);
			}
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("0x%08"PFMT64x, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i+=4;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			p->cb_printf ("%"PFMT64d, addr);
		} else {
			p->cb_printf ("[ ");
			while (size--) {
				updateAddr (buf + i, size - i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (",");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			p->cb_printf (" ]");
		}
		p->cb_printf ("}");
	}
}

static int r_print_format_10bytes(const RPrint* p, int mode, const char *setval,
		ut64 seeki, ut64 addr, ut8* buf) {
	ut8 buffer[255];
	int j;
	if (MUSTSET) {
		p->cb_printf ("?e pf B not yet implemented\n");
	} else if (mode & R_PRINT_DOT) {
		for (j = 0; j<10; j++) {
			p->cb_printf ("%02x ", buf[j]);
		}
	} else if (MUSTSEE) {
		if (!p->iob.read_at) {
			printf ("(cannot read memory)\n");
			return -1;
		}
		p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki);
		}
		for (j=0; j<10; j++) {
			p->cb_printf ("%02x ", buf[j]);
		}
		if (!SEEVALUE) {
			p->cb_printf (" ... (");
		}
		for (j = 0; j < 10; j++) {
			if (!SEEVALUE) {
				if (IS_PRINTABLE (buf[j])) {
					p->cb_printf ("%c", buf[j]);
				} else {
					p->cb_printf (".");
				}
			}
		}
		if (!SEEVALUE) {
			p->cb_printf (")");
		}
	} else if (MUSTSEEJSON) {
		if (!p->iob.read_at) {
			printf ("(cannot read memory)\n");
			return -1;
		} else {
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		}
		p->cb_printf ("[ %d", buf[0]);
		j = 1;
		for (; j < 10; j++) {
			p->cb_printf (", %d", buf[j]);
		}
		p->cb_printf ("]");
		return 0;
	}
	return 0;
}

static int r_print_format_hexpairs(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	int j;
	size = (size == -1) ? 1 : size;
	if (MUSTSET) {
		p->cb_printf ("?e pf X not yet implemented\n");
	} else if (mode & R_PRINT_DOT) {
		for (j = 0; j < size; j++) {
			p->cb_printf ("%02x", buf[i + j]);
		}
	} else if (MUSTSEE) {
		size = (size < 1) ? 1 : size;
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = ", seeki);
		}
		for (j = 0; j < size; j++) {
			p->cb_printf ("%02x ", buf[i + j]);
		}
		if (!SEEVALUE) {
			p->cb_printf (" ... (");
		}
		for (j=0; j<size; j++) {
			if (!SEEVALUE) {
				if (IS_PRINTABLE (buf[j])) {
					p->cb_printf ("%c", buf[i+j]);
				} else {
					p->cb_printf (".");
				}
			}
		}
		p->cb_printf (")");
	} else if (MUSTSEEJSON || MUSTSEESTRUCT) {
		size = (size < 1) ? 1 : size;
		p->cb_printf ("[ %d", buf[0]);
		j = 1;
		for (; j < 10; j++) {
			p->cb_printf (", %d", buf[j]);
		}
		p->cb_printf ("]");
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
		}
		return size;
	}
	return size;
}

static void r_print_format_float(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	float val_f = 0.0f;
	ut64 addr = 0;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF - 1;
		size %= ARRAYINDEX_COEF;
	}
	val_f = updateAddr (buf + i, 999, endian, &addr, NULL);
	if (MUSTSET) {
		p->cb_printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval,
			seeki + ((elem >= 0) ? elem * 4 : 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		p->cb_printf ("%.9g", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				p->cb_printf ("0x%08"PFMT64x" = ",
					seeki + ((elem >= 0) ? elem * 4 : 0));
			}
		}
		if (size == -1) {
			p->cb_printf ("%.9g", val_f);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				val_f = updateAddr (buf + i, 9999, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%.9g", val_f);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 4;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
		}
	}
}


static void r_print_format_double(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
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
		p->cb_printf ("wv8 %s @ 0x%08"PFMT64x"\n", setval,
			seeki + ((elem >= 0) ? elem * 8 : 0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		p->cb_printf ("%.17g", val_f);
	} else {
		if (MUSTSEE) {
			if (!SEEVALUE && !ISQUIET) {
				p->cb_printf ("0x%08"PFMT64x" = ",
					seeki + ((elem >= 0) ? elem * 8 : 0));
			}
		}
		if (size == -1) {
			p->cb_printf ("%.17g", val_f);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				// XXX this 999 is scary
				updateAddr (buf + i, 9999, endian, &addr, NULL);
				r_mem_swaporcopy ((ut8*)&val_f, buf + i, sizeof (double), endian);
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%.17g", val_f);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 8;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
		if (MUSTSEEJSON) {
			p->cb_printf ("}");
		}
	}
}

static void r_print_format_word(const RPrint* p, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	addr = endian
		? (*(buf + i)) << 8 | (*(buf + i + 1))
		: (*(buf + i + 1)) << 8 | (*(buf + i));
	if (MUSTSET) {
		p->cb_printf ("wv2 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*2:0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		if (size == -1) {
			p->cb_printf ("0x%04"PFMT64x, addr);
		}
		while ((size -= 2) > 0) {
			addr = endian
				? (*(buf+i))<<8 | (*(buf+i+1))
				: (*(buf+i+1))<<8 | (*(buf+i));
			if (elem == -1 || elem == 0) {
				p->cb_printf ("%"PFMT64d, addr);
				if (elem == 0) {
					elem = -2;
				}
			}
			if (size != 0 && elem == -1) {
				p->cb_printf (",");
			}
			if (elem > -1) {
				elem--;
			}
			i += 2;
		}
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*2:0));
		}
		if (size==-1) {
			p->cb_printf ("0x%04"PFMT64x, addr);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
			}
			while (size--) {
				addr = endian
					? (*(buf+i))<<8 | (*(buf+i+1))
					: (*(buf+i+1))<<8 | (*(buf+i));
				if (elem == -1 || elem == 0) {
					p->cb_printf ("0x%04"PFMT64x, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += 2;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size==-1) {
			p->cb_printf ("%"PFMT64d, addr);
		} else {
			p->cb_printf ("[ ");
			while ( (size -= 2) >0) {
				addr = endian
					? (*(buf+i))<<8 | (*(buf+i+1))
					: (*(buf+i+1))<<8 | (*(buf+i));
				if (elem == -1 || elem == 0) {
					p->cb_printf ("%"PFMT64d, addr);
					if (elem == 0) {
						elem = -2;
					}
				}
				if (size != 0 && elem == -1) {
					p->cb_printf (",");
				}
				if (elem > -1) {
					elem--;
				}
				i += 2;
			}
			p->cb_printf (" ]");
		}
		p->cb_printf ("}");
	}
}

static void r_print_byte_escape(const RPrint* p, const char *src, char **dst, int dot_nl) {
	r_return_if_fail (p->strconv_mode);
	r_str_byte_escape (src, dst, dot_nl, !strcmp (p->strconv_mode, "asciidot"), p->esc_bslash);
}

static void r_print_format_nulltermstring(const RPrint* p, int len, int endian, int mode,
		const char *setval, ut64 seeki, ut8* buf, int i, int size) {
	if (!p->iob.is_valid_offset (p->iob.io, seeki, 1)) {
		ut8 ch = 0xff;
		// XXX there are some cases where the memory is there but is_valid_offset fails wtf
		if (p->iob.read_at (p->iob.io, seeki, &ch, 1) != 1 && ch != 0xff) {
			p->cb_printf ("-1");
			return;
		}
	}
	if (p->flags & R_PRINT_FLAGS_UNALLOC && !(p->iob.io->cached & R_PERM_R)) {
		ut64 total_map_left = 0;
		ut64 addr = seeki;
		RIOMap *map;
		while (total_map_left < len
		       && (map = p->iob.io->va
		           ? p->iob.map_get_at (p->iob.io, addr)
		           : p->iob.map_get_paddr (p->iob.io, addr))
		       && map->perm & R_PERM_R) {
			if (!r_io_map_size(map)) {
				total_map_left = addr == 0 ? UT64_MAX : UT64_MAX - addr + 1;
				break;
			}
			total_map_left += r_io_map_size (map) - (addr - (p->iob.io->va ? r_io_map_begin (map) : map->delta));
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
			eprintf ("Warning: new string is longer than previous one\n");
		}
		p->cb_printf ("wx ");
		for (i = 0; i < vallen; i++) {
			if (i < vallen - 3 && newstring[i] == '\\' && newstring[i + 1] == 'x') {
				p->cb_printf ("%c%c", newstring[i + 2], newstring[i + 3]);
				i += 3;
			} else {
				p->cb_printf ("%2x", newstring[i]);
			}
		}
		p->cb_printf (" @ 0x%08"PFMT64x"\n", seeki);
		free (ons);
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		int j = i;
		(MUSTSEESTRUCT) ?
			p->cb_printf ("\"") :
			p->cb_printf ("\\\"");
		for (; j<len && ((size==-1 || size-- >0) && buf[j]) ; j++) {
			char ch = buf[j];
			if (ch == '"') {
				p->cb_printf ("\\\"");
			} else if (IS_PRINTABLE (ch)) {
				p->cb_printf ("%c", ch);
			} else {
				p->cb_printf (".");
			}
		}
		(MUSTSEESTRUCT) ?
			p->cb_printf ("\"") :
			p->cb_printf ("\\\"");
	} else if (MUSTSEE) {
		int j = i;
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08" PFMT64x " = %s", seeki, overflow ? "ovf " : "");
		}
		p->cb_printf ("\"");
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]) ; j++) {
			char esc_str[5] = { 0 };
			char *ptr = esc_str;
			r_print_byte_escape (p, (char *)&buf[j], &ptr, false);
			p->cb_printf ("%s", esc_str);
		}
		p->cb_printf ("\"");
	} else if (MUSTSEEJSON) {
		char *utf_encoded_buf = NULL;
		p->cb_printf ("\"");
		utf_encoded_buf = r_str_escape_utf8_for_json (
		    (char *)buf + i, size == -1 ? str_len : R_MIN (size, str_len));
		if (utf_encoded_buf){
			p->cb_printf ("%s", utf_encoded_buf);
			free (utf_encoded_buf);
		}
		p->cb_printf ("\"");
		if (overflow) {
			p->cb_printf (",\"overflow\":true");
		}
		p->cb_printf ("}");
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
			eprintf ("Warning: new string is longer than previous one\n");
		}
		p->cb_printf ("ww %s @ 0x%08"PFMT64x"\n", newstring, seeki);
		free(ons);
	} else if (MUSTSEE) {
		int j = i;
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08"PFMT64x" = ", seeki);
		}
		for (; j<len && ((size==-1 || size-->0) && buf[j]) ; j+=2) {
			if (IS_PRINTABLE (buf[j])) {
				p->cb_printf ("%c", buf[j]);
			} else {
				p->cb_printf (".");
			}
		}
	} else if (MUSTSEEJSON) {
		int j = i;
		p->cb_printf ("%"PFMT64d",\"string\":\"", seeki);
		for (; j < len && ((size == -1 || size-- > 0) && buf[j]); j += 2) {
			if (IS_PRINTABLE (buf[j])) {
				p->cb_printf ("%c", buf[j]);
			} else {
				p->cb_printf (".");
			}
		}
		p->cb_printf ("\"}");
	}
}

static void r_print_format_bitfield(const RPrint* p, ut64 seeki, char *fmtname,
		char *fieldname, ut64 addr, int mode, int size) {
	char *bitfield = NULL;
	addr &= (1ULL << (size * 8)) - 1;
	if (MUSTSEE && !SEEVALUE) {
		p->cb_printf ("0x%08"PFMT64x" = ", seeki);
	}
	bitfield = r_type_enum_getbitfield (p->sdb_types, fmtname, addr);
	if (bitfield && *bitfield) {
		if (MUSTSEEJSON) {
			p->cb_printf ("\"%s\"}", bitfield);
		} else if (MUSTSEE) {
			p->cb_printf ("%s (bitfield) = %s\n", fieldname, bitfield);
		}
	} else {
		if (MUSTSEEJSON) {
			p->cb_printf ("\"`tb %s 0x%"PFMT64x"`\"}", fmtname, addr);
		} else if (MUSTSEE) {
			p->cb_printf ("%s (bitfield) = `tb %s 0x%"PFMT64x"`\n",
				fieldname, fmtname, addr);
		}
	}
	free (bitfield);
}

static void r_print_format_enum(const RPrint* p, ut64 seeki, char *fmtname,
		char *fieldname, ut64 addr, int mode, int size) {
	char *enumvalue = NULL;
	addr &= (1ULL << (size * 8)) - 1;
	if (MUSTSEE && !SEEVALUE) {
		p->cb_printf ("0x%08"PFMT64x" = ", seeki);
	}
	enumvalue = r_type_enum_member (p->sdb_types, fmtname, NULL, addr);
	if (enumvalue && *enumvalue) {
		if (mode & R_PRINT_DOT) {
			p->cb_printf ("%s.%s", fmtname, enumvalue);
		} else if (MUSTSEEJSON) {
			p->cb_printf ("%"PFMT64d",\"label\":\"%s\",\"enum\":\"%s\"}",
				addr, enumvalue, fmtname);
		} else if (MUSTSEE) {
			p->cb_printf ("%s (enum %s) = 0x%"PFMT64x" ; %s\n",
				fieldname, fmtname, addr, enumvalue);
		} else if (MUSTSEESTRUCT) {
			p->cb_printf ("%s", enumvalue);
		}
	} else {
		if (MUSTSEEJSON) {
			p->cb_printf ("%"PFMT64d",\"enum\":\"%s\"}", addr, fmtname);
		} else if (MUSTSEE) {
			p->cb_printf ("%s (enum %s) = 0x%"PFMT64x"\n",//`te %s 0x%x`\n",
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
			p->cb_printf ("dr %s=%s\n", name, setval);
		} else if (MUSTSEE) {
			if (!SEEVALUE) {
				p->cb_printf ("%s : 0x%08" PFMT64x "\n", ri->name, p->get_register_value (p->reg, ri));
			} else {
				p->cb_printf ("0x%08" PFMT64x "\n", p->get_register_value (p->reg, ri));
			}
		} else if (MUSTSEEJSON) {
			p->cb_printf ("%"PFMT64d"}", p->get_register_value (p->reg, ri));
		}
	} else {
		p->cb_printf ("Register %s does not exists\n", name);
	}
}

static void r_print_format_num_specifier(const RPrint *p, ut64 addr, int bytes, int sign) {
#define EXT(T) (sign ? (signed T)(addr) : (unsigned T)(addr) )
	const char *fs64 = sign ? "%"PFMT64d : "%"PFMT64u;
	const char *fs = sign ? "%d" : "%u";
	if (bytes == 1) {
		p->cb_printf (fs, EXT(char));
	} else if (bytes == 2) {
		p->cb_printf (fs, EXT(short));
	} else if (bytes == 4) {
		p->cb_printf (fs, EXT(int)); //XXX: int is not necessarily 4 bytes I guess.
	} else if (bytes == 8) {
		p->cb_printf (fs64, addr);
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
		p->cb_printf ("wv%d %s @ 0x%08"PFMT64x"\n", bytes, setval, seeki+((elem>=0)?elem*(bytes):0));
	} else if ((mode & R_PRINT_DOT) || MUSTSEESTRUCT) {
		r_print_format_num_specifier (p, addr, bytes, sign);
	} else if (MUSTSEE) {
		if (!SEEVALUE && !ISQUIET) {
			p->cb_printf ("0x%08"PFMT64x" = ", seeki + ((elem >= 0)? elem * bytes: 0));
		}
		if (size == -1) {
			r_print_format_num_specifier (p, addr, bytes, sign);
		} else {
			if (!SEEVALUE) {
				p->cb_printf ("[ ");
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
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += bytes;
			}
			if (!SEEVALUE) {
				p->cb_printf (" ]");
			}
		}
	} else if (MUSTSEEJSON) {
		if (size == -1) {
			r_print_format_num_specifier (p, addr, bytes, sign);
		} else {
			p->cb_printf ("[ ");
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
					p->cb_printf (", ");
				}
				if (elem > -1) {
					elem--;
				}
				i += bytes;
			}
			p->cb_printf (" ]");
		}
		p->cb_printf ("}");
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
	if (!f) {
		return -1;
	}
	if (n >= 5) {  // This is the nesting level, is this not a bit arbitrary?!
		return 0;
	}
	const char *fmt2 = sdb_get (p->formats, f, NULL);
	if (!fmt2) {
		fmt2 = f;
	}
	char *o = strdup (fmt2);
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
			eprintf ("No end curly bracket.\n");
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

	int words = r_str_word_set0_stack (args);
	fmt_len = strlen (fmt);
	for (; i < fmt_len; i++) {
		if (fmt[i] == '[') {
			char *end = strchr (fmt + i,']');
			if (!end) {
				eprintf ("No end bracket.\n");
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
		case 'Q': // uint128
			size += tabsize * 16;
			break;
		case 'z':
		case 'Z':
			size += tabsize;
			break;
		case '*':
			size += tabsize * (p->bits / 8);
			i++;
			idx--;	//no need to go ahead for args
			break;
		case 'B':
		case 'E':
			if (tabsize_set) {
				if (tabsize < 1 || tabsize > 8) {
					eprintf ("Unknown enum format size: %d\n", tabsize);
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
			char *endname = NULL, *structname = NULL;
			char tmp = 0;
			if (words < idx) {
				eprintf ("Index out of bounds\n");
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
				format = sdb_get (p->formats, structname + 1, NULL);
				if (format && !strncmp (format, f, strlen (format) - 1)) { // Avoid recursion here
					free (o);
					free (structname);
					return -1;
				}
				if (!format) { // Fetch format from types db
					format = r_type_format (p->sdb_types, structname + 1);
				}
			}
			if (!format) {
				eprintf ("Cannot find format for struct `%s'\n", structname + 1);
				free (structname);
				free (o);
				return 0;
			}
			int newsize = r_print_format_struct_size (p, format, mode, n + 1);
			if (newsize < 1) {
				eprintf ("Cannot find size for `%s'\n", format);
				free (structname);
				free (o);
				return 0;
			}
			if (format) {
				size += tabsize * newsize;
			}
			free (structname);
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
				size += tabsize * (p->bits / 8);
				break;
			}
			i++;
			break;
		case 'r':
			break;
		case 'n':
		case 'N':
			if (fmt[i+1] == '1') {
				size += tabsize * 1;
			} else if (fmt[i+1] == '2') {
				size += tabsize * 2;
			} else if (fmt[i+1] == '4') {
				size += tabsize * 4;
			} else if (fmt[i+1] == '8') {
				size += tabsize * 8;
			} else {
				eprintf ("Invalid n format in (%s)\n", fmt);
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
	char namefmt[128];
	slide++;
	if ((slide % STRUCTPTR) > NESTDEPTH || (slide % STRUCTFLAG)/STRUCTPTR > NESTDEPTH) {
		eprintf ("Too much nested struct, recursion too deep...\n");
		return 0;
	}
	if (anon) {
		fmt = name;
	} else {
		fmt = sdb_get (p->formats, name, NULL);
		if (!fmt) { // Fetch struct info from types DB
			fmt = r_type_format (p->sdb_types, name);
		}
	}
	if (!fmt || !*fmt) {
		eprintf ("Undefined struct '%s'.\n", name);
		return 0;
	}
	if (MUSTSEE && !SEEVALUE) {
		snprintf (namefmt, sizeof (namefmt), "%%%ds", 10+6*slide%STRUCTPTR);
		if (fmt[0] == '0') {
			p->cb_printf (namefmt, "union");
		} else {
			p->cb_printf (namefmt, "struct");
		}
		p->cb_printf ("<%s>\n", name);
	}
	r_print_format (p, seek, b, len, fmt, mode, setval, field);
	return r_print_format_struct_size (p, fmt, mode, 0);
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
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* b, const int len,
		const char *formatname, int mode, const char *setval, char *ofield) {
	int nargs, i, j, invalid, nexti, idx, times, otimes, endian, isptr = 0;
	const int old_bits = p->bits;
	char *args = NULL, *bracket, tmp, last = 0;
	ut64 addr = 0, addr64 = 0, seeki = 0;
	static int slide = 0, oldslide = 0, ident = 4;
	char namefmt[32], *field = NULL;
	const char *arg = NULL;
	const char *fmt = NULL;
	const char *argend;
	int viewflags = 0;
	char *oarg = NULL;
	char *internal_format = NULL;

	/* Load format from name into fmt */
	if (!formatname) {
		return 0;
	}
	fmt = sdb_get (p->formats, formatname, NULL);
	if (!fmt) {
		fmt = formatname;
	}
	internal_format = strdup (fmt);
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
	endian = p->big_endian;

	if (ofield && ofield != MINUSONE) {
		field = strdup (ofield);
	}
	/* get times */
	otimes = times = atoi (arg);
	if (times > 0) {
		while (IS_DIGIT(*arg)) {
			arg++;
		}
	}

	bracket = strchr (arg,'{');
	if (bracket) {
		char *end = strchr (arg, '}');
		if (!end) {
			eprintf ("No end bracket. Try pf {ecx}b @ esi\n");
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
		int l = 0, maxl = 0;
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
		l++;
		const char *ends = " "; // XXX trailing space warning
		snprintf (namefmt, sizeof (namefmt), "%%%ds :%s",
			((maxl + 1) * (1 + slide)) % STRUCTPTR, ends);
	}
#define ISPOINTED ((slide%STRUCTFLAG)/STRUCTPTR<=(oldslide%STRUCTFLAG)/STRUCTPTR)
#define ISNESTED ((slide%STRUCTPTR)<=(oldslide%STRUCTPTR))
	if (mode == R_PRINT_JSON && slide == 0) {
		p->cb_printf ("[");
	}
	if (mode == R_PRINT_STRUCT) {
		if (formatname && *formatname) {
			if (strchr (formatname, ' ')) {
				p->cb_printf ("struct {\n");
			} else {
				p->cb_printf ("struct %s {\n", formatname);
			}
		} else {
			p->cb_printf ("struct {\n");
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
		p->cb_printf ("digraph g { graph [ rank=same; rankdir=LR; ];\n");
		p->cb_printf ("root [ rank=1; shape=record\nlabel=\"%s", fmtname);
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
					p->cb_printf (",");
				}
				p->cb_printf ("[{\"index\":%d,\"offset\":%"PFMT64d"},", otimes-times, seek+i);
			} else if (mode) {
				p->cb_printf ("0x%08"PFMT64x" [%d] {\n", seek + i, otimes-times);
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
			p->bits = old_bits;
			if (arg[0] == '[') {
				char *end = strchr (arg,']');
				if (!end) {
					eprintf ("No end bracket.\n");
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
				if (p->bits == 64) {
					addr = addr64;
				}
			} else {
				// eprintf ("Format strings is too big for this buffer\n");
				goto beach;
			}

			tmp = *arg;

			if (mode && !args) {
				mode |= R_PRINT_ISFIELD;
			}
			if (!(mode & R_PRINT_QUIET)) {
				if (mode & R_PRINT_MUSTSEE && otimes > 1) {
					p->cb_printf ("  ");
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
				if (ISSTRUCT || tmp=='E' || tmp=='B' || tmp=='r') {
					if (*fieldname == '(') {
						fmtname = fieldname + 1;
						fieldname = (char*)r_str_rchr (fieldname, NULL, ')');
						if (fieldname) {
							*fieldname++ = '\0';
						} else {
							eprintf ("Missing closing parenthesis in format ')'\n");
							goto beach;
						}
					} else {
						eprintf ("Missing name (%s)\n", fieldname);
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
						eprintf ("Missing closing bracket\n");
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
							p->cb_printf (namefmt, fieldname);
						}
					}
				}
			}
		feed_me_again:
			switch (isptr) {
			case PTRSEEK:
				{
				nexti = i + (p->bits / 8);
				i = 0;
				if (tmp == '?') {
					seeki = addr;
				}
				memset (buf, '\0', len);
				if (MUSTSEE && !ISQUIET) {
					p->cb_printf ("(*0x%"PFMT64x")", addr);
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
						eprintf ("Likely a heap buffer overflow.\n");
						goto beach;
					}
				} else {
					eprintf ("(cannot read at 0x%08"PFMT64x", block: %s, blocksize: 0x%x)\n",
							addr, b, len);
					p->cb_printf ("\n");
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
				} else {	//If pointer reference is not mentioned explicitly
					switch (p->bits) {
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
					p->cb_printf ("f %s=0x%08"PFMT64x"\n", formatname, seeki);
					goto beach;
				} else if (tmp == '?') {
					p->cb_printf ("f %s.%s_", fmtname, fieldname);
				} else if (tmp == 'E') {
					p->cb_printf ("f %s=0x%08"PFMT64x"\n", fieldname, seeki);
				} else if (slide/STRUCTFLAG>0 && idx==1) {
					p->cb_printf ("%s=0x%08"PFMT64x"\n", fieldname, seeki);
				} else {
					p->cb_printf ("f %s=0x%08" PFMT64x "\n", fieldname, seeki);
				}
				if (newname) {
					R_FREE (newname);
					fieldname = NULL;
				}
			}

			/* dot */
			if (mode & R_PRINT_DOT) {
				if (fieldname) {
					p->cb_printf ("|{0x%"PFMT64x"|%c|%s|<%s>",
						seeki, tmp, fieldname, fieldname);
				} else {
					p->cb_printf ("|{0x%"PFMT64x"|%c|",
						seeki, tmp);
				}
			}

			/* json */
			if (MUSTSEEJSON && mode & R_PRINT_JSON) {
				if (oldslide <= slide) {
					if (first) {
						first = 0;
					} else {
						p->cb_printf (",");
					}
				} else if (oldslide) {
					p->cb_printf ("]},");
					oldslide -= NESTEDSTRUCT;
				}
				if (fieldname) {
					p->cb_printf ("{\"name\":\"%s\",\"type\":\"", fieldname);
				} else {
					p->cb_printf ("{\"type\":\"");
				}
				if (ISSTRUCT) {
					p->cb_printf ("%s", fmtname);
				} else {
					if (tmp == 'n' || tmp == 'N') {
						p->cb_printf ("%c%c", tmp, *(arg+1));
					} else {
						p->cb_printf ("%c", tmp);
					}
				}
				if (isptr) {
					p->cb_printf ("*");
				}
				p->cb_printf ("\",\"offset\":%"PFMT64d",\"value\":",
					isptr? (seek + nexti - (p->bits / 8)) : seek + i);
			}

			/* c struct */
			if (MUSTSEESTRUCT) {
				char *type = get_format_type (tmp, (tmp == 'n' || tmp == 'N') ? arg[1] : 0);
				if (type) {
					p->cb_printf ("%*c%s %s; // ", ident, ' ', type, fieldname);
				} else {
					p->cb_printf ("%*cstruct %s {", ident, ' ', fieldname);
				}
				free (type);
			}
			bool noline = false;

			int oi = i;
			if (isptr == NULLPTR) {
				if (MUSTSEEJSON) {
					p->cb_printf ("\"NULL\"}");
				} else if (MUSTSEE) {
					p->cb_printf (" NULL\n");
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
					i += (size == -1)? 8: 8 * size;
					break;
				case 'i':
					r_print_format_int (p, endian, mode, setval, seeki, buf, i, size);
					i+= (size == -1)? 4: 4 * size;
					break;
				case 'd': //WHY?? help says: 0x%%08x hexadecimal value (4 bytes)
					r_print_format_hex (p, endian, mode, setval, seeki, buf, i, size);
					i+= (size == -1)? 4: 4 * size;
					break;
				case 'D':
					if (MUSTSET) {
						eprintf ("Set val not implemented yet for disassembler!\n");
					}
					if (isptr) {
						if (p->bits == 64) {
							i += r_print_format_disasm (p, addr64, size);
						} else {
							i += r_print_format_disasm (p, addr, size);
						}
					} else {
						i += r_print_format_disasm (p, seeki, size);
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
					r_print_format_word (p, endian, mode, setval, seeki, buf, i, size);
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
						eprintf ("Set val not implemented yet for strings!\n");
					}
					if (r_print_format_string (p, seeki, addr64, addr, 0, mode) == 0) {
						i += (size==-1) ? 4 : 4*size;
					}
					break;
				case 'S':
					if (MUSTSET) {
						eprintf ("Set val not implemented yet for strings!\n");
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
						eprintf ("Set val not implemented yet for bitfields!\n");
					}
					r_print_format_bitfield (p, seeki, fmtname, fieldname, addr, mode, size);
					i+=(size == -1)? 1: size;
					break;
				case 'E': // resolve enum
					if (MUSTSET) {
						eprintf ("Set val not implemented yet for enums!\n");
					}
					if (size >= ARRAYINDEX_COEF) {
						size %= ARRAYINDEX_COEF;
					}
					r_print_format_enum (p, seeki, fmtname, fieldname, addr, mode, size);
					i += (size == -1)? 1: size;
					break;
				case 'r':
					if (fmtname) {
						r_print_format_register (p, mode, fmtname, setval);
					} else {
						eprintf ("Unknown register\n");
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
							p->cb_printf ("\n");
						}
					}
					if (MUSTSEEJSON) {
						if (isptr) {
							p->cb_printf ("%"PFMT64d"},", seeki);
						} else {
							p->cb_printf ("[");
						}
					}
					if (MUSTSEESTRUCT) {
						if (isptr) {
							p->cb_printf ("%"PFMT64d, seeki);
						} else {
							ident += 4;
							p->cb_printf ("\n");
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
						fmtname = format;
						while (*fmtname == ' ') {
							fmtname++;
						}
					}
					oldslide = slide;
					//slide += (isptr) ? STRUCTPTR : NESTEDSTRUCT;
					slide += NESTEDSTRUCT;
					if (size == -1) {
						s = r_print_format_struct (p, seeki,
									buf + i, len - i, fmtname, slide,
									mode, setval, nxtfield, anon);
						i += (isptr) ? (p->bits / 8) : s;
						if (MUSTSEEJSON) {
							if (!isptr && (!arg[1] || arg[1] == ' ')) {
								p->cb_printf ("]}");
							}
						}
					} else {
						if (mode & R_PRINT_ISFIELD) {
							if (!SEEVALUE) {
								p->cb_printf ("[\n");
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
							s = r_print_format_struct (p, seek+i,
									buf+i, len-i, fmtname, slide, mode, setval, nxtfield, anon);
							if ((MUSTSEE || MUSTSEEJSON || MUSTSEESTRUCT) && size != 0 && elem == -1) {
								if (MUSTSEEJSON) {
									p->cb_printf (",");
								} else if (MUSTSEE || MUSTSEESTRUCT) {
									p->cb_printf ("\n");
								}
							}
							if (elem > -1) {
								elem--;
							}
							i += (isptr) ? (p->bits / 8) : s;
						}
						if (mode & R_PRINT_ISFIELD) {
							if (!SEEVALUE) {
								p->cb_printf ("]\n");
							}
						}
						if (MUSTSEEJSON) {
							p->cb_printf ("]}");
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
					p->cb_printf ("%*c}", ident, ' ');
					oldslide -= NESTEDSTRUCT;
				}
				p->cb_printf ("\n");
			}
			if (mode & R_PRINT_DOT) {
				p->cb_printf ("}");
			}
			if (mode & R_PRINT_SEEFLAGS && isptr != NULLPTR) {
				int sz = i - oi;
				if (sz > 1) {
					p->cb_printf ("fl %d @ 0x%08"PFMT64x"\n", sz, seeki);
					p->cb_printf ("Cd %d @ 0x%08"PFMT64x"\n", sz, seeki);
				}
			}
			if (viewflags && p->offname) {
				const char *s = p->offname (p->user, seeki);
				if (s) {
					p->cb_printf ("@(%s)", s);
				}
				s = p->offname (p->user, addr);
				if (s) {
					p->cb_printf ("*(%s)", s);
				}
			}
			if (!noline && tmp != 'D' && !invalid && !fmtname && MUSTSEE) {
				p->cb_printf ("\n");
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
				p->cb_printf ("]");
			} else if (mode) {
				p->cb_printf ("}\n");
			}
		}
		arg = orig;
		oldslide = 0;
	}
	if (mode & R_PRINT_JSON && slide == 0) {
		p->cb_printf("]\n");
	}
	if (MUSTSEESTRUCT && slide == 0) {
		p->cb_printf ("}\n");
	}
	if (mode & R_PRINT_DOT) {
		p->cb_printf ("\"];\n}\n");
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
