/* radare - LGPL - Copyright 2007-2015 - pancake & Skia */

#include "r_cons.h"
#include "r_util.h"
#include "r_print.h"

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
#define MUSTSET (mode & R_PRINT_MUSTSET && mode & R_PRINT_ISFIELD && setval)
#define MUSTSEEJSON (mode & R_PRINT_JSON && mode & R_PRINT_ISFIELD)

static void updateAddr(const ut8 *buf, int i, int endian, ut64 *addr, ut64 *addr64) {
	if (addr) {
		if (endian)
			*addr = (*(buf+i))<<24
			| (*(buf+i+1))<<16
			| (*(buf+i+2))<<8
			| (*(buf+i+3));
		else
			*addr = (*(buf+i+3))<<24
			| (*(buf+i+2))<<16
			| (*(buf+i+1))<<8
			| (*(buf+i));
	}
	if (addr64) {
		if (endian)
			*addr64 = (((ut64)(*(buf+i))<<56))
			| ((ut64)(*(buf+i+1))<<48)
			| ((ut64)(*(buf+i+2))<<40)
			| ((ut64)(*(buf+i+3))<<32)
			| ((ut64)(*(buf+i+4))<<24)
			| ((ut64)(*(buf+i+5))<<16)
			| ((ut64)(*(buf+i+6))<<8)
			| ((ut64)(*(buf+i+7)));
		else
			*addr64 =(((ut64)(*(buf+i+7))<<56))
			| ((ut64)(*(buf+i+6))<<48)
			| ((ut64)(*(buf+i+5))<<40)
			| ((ut64)(*(buf+i+4))<<32)
			| ((ut64)(*(buf+i+3))<<24)
			| ((ut64)(*(buf+i+2))<<16)
			| ((ut64)(*(buf+i+1))<<8)
			| ((ut64)(*(buf+i)));
	}
}

static int r_get_size(RNum *num, ut8 *buf, int endian, const char *s) {
	int size=0, len = strlen(s);
	ut64 addr;

	if (s[0] == '*' && len >= 4) { // value pointed by the address
		int offset = r_num_math (num, s+1);
		updateAddr (buf, offset, endian, &addr, NULL);
		return addr;
	} else {
		size = r_num_math (num, s); // this should handle also the flags, but doesn't work... :/
		// eprintf ("SIZE: %s --> %d\n", s, size);
	}
	return size;
}


static void r_print_format_quadword(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr64;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf, i, endian, NULL, &addr64);
	if (MUSTSET) {
		p->printf ("wv8 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*8:0));
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*2:0));
		p->printf ("(qword) ");
		if (size==-1)
			p->printf ("0x%016"PFMT64x, addr64);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, NULL, &addr64);
				if (elem == -1 || elem == 0) {
					p->printf ("0x%016"PFMT64x, addr64);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=8;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1)
			p->printf ("%d", addr64);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, NULL, &addr64);
				if (elem == -1 || elem == 0) {
					p->printf ("%d", addr64);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=8;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static void r_print_format_byte(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		p->printf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem:0));
		if (size==-1)
			p->printf ("0x%02x", buf[i]);
		else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->printf ("0x%02x", buf[i]);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i++;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1)
			p->printf ("%d", buf[i]);
		else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->printf (", %d", buf[i]);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i++;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static int r_print_format_uleb(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	int s = 0, sum = 0;
	ut64 value = 0, offset = 0;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	// offset = seeki+((elem>=0)?16*elem:0);
	if (MUSTSET) {
		ut8 *tmp;
		char *nbr;
		do {
			offset += s;
			r_uleb128_decode (buf+offset, &s, &value);
		} while (elem--);
		tmp = (ut8*) r_uleb128_encode (r_num_math (NULL, setval), &s);
		nbr = r_hex_bin2strdup (tmp, s);
		p->printf ("\"wx %s\" @ 0x%08"PFMT64x"\n", nbr, seeki+offset);
		free (tmp);
		free (nbr);
		// sum = size of the converted number
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+offset);
		if (size==-1) {
			r_uleb128_decode (buf+offset, &s, &value);
			p->printf ("%"PFMT64d, value);
			sum = s;
		} else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_uleb128_decode (buf+i, &s, &value);
					sum += s;
					p->printf ("%"PFMT64d, value);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=s;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1) {
			r_uleb128_decode (buf+offset, &s, &value);
			p->printf ("\"%"PFMT64d"\"", value);
			sum = s;
		} else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					r_uleb128_decode (buf+i, &s, &value);
					sum += s;
					p->printf ("\"%"PFMT64d"\"", value);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=s;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
	return sum;
}

static void r_print_format_char(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		p->printf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*2:0));
		if (size==-1)
			p->printf ("'%c'", IS_PRINTABLE (buf[i])?buf[i]:'.');
		else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->printf ("'%c'", IS_PRINTABLE (buf[i])?buf[i]:'.');
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i++;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1)
			p->printf ("\"%c\"", buf[i]);
		else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->printf ("\"%c\"", buf[i]);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i++;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static void r_print_format_decchar(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (MUSTSET) {
		p->printf ("\"w %s\" @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem:0));
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem:0));
		if (size==-1)
			p->printf ("%d", buf[i]);
		else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->printf ("%d", buf[i]);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i++;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1)
			p->printf ("\"%d\"", buf[i]);
		else {
			p->printf ("[ ");
			while (size--) {
				if (elem == -1 || elem == 0) {
					p->printf ("\"%d\"", buf[i]);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i++;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static int r_print_format_string(const RPrint* p, ut64 seeki, ut64 addr64, ut64 addr, int is64, int mode) {
	ut8 buffer[255];
	buffer[0] = 0;
	if (p->iob.read_at) {
		if (is64 == 1)
			p->iob.read_at (p->iob.io, addr64, buffer, sizeof (buffer)-8);
		else
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, sizeof (buffer)-8);
	} else {
		eprintf ("(cannot read memory)\n");
		return -1;
	}
	if (MUSTSEEJSON) {
		p->printf ("%d,\"string\":\"%s\"}", seeki, buffer);
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki);
		p->printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" ", seeki, addr);
		p->printf ("%s", buffer);
	}
	return 0;
}

static void r_print_format_time(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf, i, endian, &addr, NULL);
	if (MUSTSET) {
		p->printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if (MUSTSEE) {
		char *timestr = strdup(asctime (gmtime ((time_t*)&addr)));
		*(timestr+24) = '\0';
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*4:0));
		if (size==-1) {
			p->printf ("%s", timestr);
		} else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				free (timestr);
				timestr = strdup (asctime (gmtime ((time_t*)&addr)));
				*(timestr+24) = '\0';
				if (elem == -1 || elem == 0) {
					p->printf ("%s", timestr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i += 4;
			}
			p->printf (" ]");
		}
		free (timestr);
	} else if (MUSTSEEJSON) {
		char *timestr = strdup (asctime (gmtime ((time_t*)&addr)));
		*(timestr+24) = '\0';
		if (size==-1) {
			p->printf ("\"%s\"", timestr);
		} else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				free (timestr);
				timestr = strdup (asctime (gmtime ((time_t*)&addr)));
				*(timestr+24) = '\0';
				if (elem == -1 || elem == 0) {
					p->printf ("\"%s\"", timestr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i += 4;
			}
			p->printf (" ]");
		}
		free (timestr);
		p->printf ("}");
	}
}

// TODO: support unsigned int?
static void r_print_format_hex(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf, i, endian, &addr, NULL);
	if (MUSTSET) {
		p->printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*4:0));
		if (size==-1)
			p->printf ("%"PFMT64d, addr);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->printf ("%"PFMT64d, addr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1)
			p->printf ("%d", addr);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->printf ("%d", addr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static void r_print_format_octal (const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf, i, endian, &addr, NULL);
	if (MUSTSET) {
		p->printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if (MUSTSEE) {
		ut32 addr32 = (ut32)addr;
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*4:0));
		p->printf ("(octal) ");
		if (size==-1)
			p->printf ("0%08"PFMT64o, addr32);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				addr32 = (ut32)addr;
				if (elem == -1 || elem == 0) {
					p->printf ("0%08"PFMT64o, addr32);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		ut32 addr32 = (ut32)addr;
		if (size==-1)
			p->printf ("%d", addr32);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				addr32 = (ut32)addr;
				if (elem == -1 || elem == 0) {
					p->printf ("%d", addr32);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static void r_print_format_hexflag(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf, i, endian, &addr, NULL);
	if (MUSTSET) {
		p->printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else if (MUSTSEE) {
		ut32 addr32 = (ut32)addr;
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*4:0));
		if (size==-1)
			p->printf ("0x%08"PFMT64x, addr32);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				addr32 = (ut32)addr;
				if (elem == -1 || elem == 0) {
					p->printf ("0x%08"PFMT64x, addr32);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		ut32 addr32 = (ut32)addr;
		if (size==-1)
			p->printf ("%d", addr32);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				addr32 = (ut32)addr;
				if (elem == -1 || elem == 0) {
					p->printf ("%d", addr32);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (",");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static int r_print_format_10bytes(const RPrint* p, int mode, const char* setval,
		ut64 seeki, ut64 addr, ut8* buf) {
	ut8 buffer[255];
	int j;
	if (MUSTSET) {
		p->printf ("?e pf B not yet implemented\n");
	} else if (MUSTSEE) {
		if (!p->iob.read_at) {
			printf ("(cannot read memory)\n");
			return -1;
		} else
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		p->printf ("0x%08"PFMT64x" = ", seeki);
		j=0;
		for (; j<10; j++)
			p->printf ("%02x ", buf[j]);
		p->printf (" ... (");
		for (j=0; j<10; j++)
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[j]);
			else
				p->printf (".");
		p->printf (")");
	} else if (MUSTSEEJSON) {
		if (!p->iob.read_at) {
			printf ("(cannot read memory)\n");
			return -1;
		} else
			p->iob.read_at (p->iob.io, (ut64)addr, buffer, 248);
		p->printf ("[ %d", buf[0]);
		j=1;
		for (; j<10; j++)
			p->printf (", %d", buf[j]);
		p->printf ("]}");
		return 0;
	}
	return 0;
}

static int r_print_format_hexpairs(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	int j;
	size = (size==-1) ? 1 : size;
	if (MUSTSET) {
		p->printf ("?e pf X not yet implemented\n");
	} else if (MUSTSEE) {
		size = (size < 1) ? 1 : size;
		p->printf ("0x%08"PFMT64x" = ", seeki);
		j=0;
		for (; j<size; j++)
				p->printf ("%02x ", buf[i+j]);
		p->printf (" ... (");
		for (j=0; j<size; j++)
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[i+j]);
			else
				p->printf (".");
		p->printf (")");
	} else if (MUSTSEEJSON) {
		size = (size < 1) ? 1 : size;
		p->printf ("[ %d", buf[0]);
		j=1;
		for (; j<10; j++)
			p->printf (", %d", buf[j]);
		p->printf ("]}");
		return size;
	}
	return size;
}

static void r_print_format_float(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	updateAddr (buf, i, endian, &addr, NULL);
	if (MUSTSET) {
		p->printf ("wv4 %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*4:0));
	} else {
		if (MUSTSEE)
			p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*4:0));
		if (size==-1)
			p->printf ("%f", (float)addr);
		else {
			p->printf ("[ ");
			while (size--) {
				updateAddr (buf, i, endian, &addr, NULL);
				if (elem == -1 || elem == 0) {
					p->printf ("%f", (float)addr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=4;
			}
			p->printf (" ]");
		}
		if (MUSTSEEJSON) p->printf ("}");
	}
}

static void r_print_format_word(const RPrint* p, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	ut64 addr;
	int elem = -1;
	if (size >= ARRAYINDEX_COEF) {
		elem = size/ARRAYINDEX_COEF-1;
		size %= ARRAYINDEX_COEF;
	}
	if (endian)
		addr = (*(buf+i))<<8 | (*(buf+i+1));
	else addr = (*(buf+i+1))<<8 | (*(buf+i));
	if (MUSTSET) {
		p->printf ("wx %s @ 0x%08"PFMT64x"\n", setval, seeki+((elem>=0)?elem*2:0));
	} else if (MUSTSEE) {
		p->printf ("0x%08"PFMT64x" = ", seeki+((elem>=0)?elem*2:0));
		if (size==-1)
			p->printf ("0x%04x", addr);
		else {
			p->printf ("[ ");
			while (size--) {
				if (endian)
					addr = (*(buf+i))<<8 | (*(buf+i+1));
				else addr = (*(buf+i+1))<<8 | (*(buf+i));
				if (elem == -1 || elem == 0) {
					p->printf ("0x%04x", addr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (", ");
				if (elem > -1) elem--;
				i+=2;
			}
			p->printf (" ]");
		}
	} else if (MUSTSEEJSON) {
		if (size==-1)
			p->printf ("%d", addr);
		else {
			p->printf ("[ ");
			while (size--) {
				if (endian)
					addr = (*(buf+i))<<8 | (*(buf+i+1));
				else addr = (*(buf+i+1))<<8 | (*(buf+i));
				if (elem == -1 || elem == 0) {
					p->printf ("%d", addr);
					if (elem == 0) elem = -2;
				}
				if (size != 0 && elem == -1)
					p->printf (",");
				if (elem > -1) elem--;
				i+=2;
			}
			p->printf (" ]");
		}
		p->printf ("}");
	}
}

static void r_print_format_nulltermstring(const RPrint* p, const int len, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	if (MUSTSET) {
		int buflen = strlen ((const char *)buf+seeki), vallen = strlen(setval);
		char *newstring, *ons;
		newstring = ons = strdup(setval);
		if ((newstring[0] == '\"' && newstring[vallen-1] == '\"')
				|| (newstring[0] == '\'' && newstring[vallen-1] == '\'')) {
			newstring[vallen-1] = '\0';
			newstring++;
			vallen-=2;
		}
		if (vallen > buflen) {
			eprintf ("Warning: new string is longer than previous one\n");
		}
		p->printf ("wx ");
		for (i=0;i<vallen;i++) {
			if (i < vallen-3 && newstring[i] == '\\' && newstring[i+1] == 'x') {
				p->printf ("%c%c", newstring[i+2], newstring[i+3]);
				i+=3;
			} else {
				p->printf ("%2x", newstring[i]);
			}
		}
		p->printf (" @ 0x%08"PFMT64x"\n", seeki);
		free(ons);
	} else if (MUSTSEE) {
		int j = i;
		p->printf ("0x%08"PFMT64x" = ", seeki);
		for (; j<len && ((size==-1 || size-- >0) && buf[j]) ; j++) {
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[j]);
			else p->printf (".");
		}
	} else if (MUSTSEEJSON) {
		int j = i;
		p->printf ("%d,\"string\":\"", seeki);
		for (; j<len && ((size==-1 || size-- >0) && buf[j]) ; j++) {
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[j]);
			else p->printf (".");
		}
		p->printf ("\"}");
	}
}

static void r_print_format_nulltermwidestring(const RPrint* p, const int len, int endian, int mode,
		const char* setval, ut64 seeki, ut8* buf, int i, int size) {
	if (MUSTSET) {
		int vallen = strlen(setval);
		char *newstring, *ons;
		newstring = ons = strdup(setval);
		if ((newstring[0] == '\"' && newstring[vallen-1] == '\"')
				|| (newstring[0] == '\'' && newstring[vallen-1] == '\'')) {
			newstring[vallen-1] = '\0';
			newstring++;
			vallen-=2;
		}
		if ((size = strlen (setval)) > r_wstr_clen((char*)(buf+seeki)))
			eprintf ("Warning: new string is longer than previous one\n");
		p->printf ("ww %s @ 0x%08"PFMT64x"\n", newstring, seeki);
		free(ons);
	} else if (MUSTSEE) {
		int j = i;
		p->printf ("0x%08"PFMT64x" = ", seeki);
		for (; j<len && ((size==-1 || size-->0) && buf[j]) ; j+=2) {
			if (IS_PRINTABLE (buf[j]))
				p->printf ("%c", buf[j]);
			else p->printf (".");
		}
	}
}

static void r_print_format_bitfield(const RPrint* p, ut64 seeki, char* fmtname,
		char* fieldname, ut64 addr, int mode, int size) {
	char *bitfield = NULL;
	switch (size) {
		case 1: addr &= UT8_MAX; break;
		case 2: addr &= UT16_MAX; break;
		case 4: addr &= UT32_MAX; break;
	}
	if (MUSTSEE)
		p->printf ("0x%08"PFMT64x" = ", seeki);
	if (p->get_bitfield)
		bitfield = p->get_bitfield (p->user, fmtname, addr);
	if (bitfield && *bitfield) {
		if (MUSTSEEJSON) p->printf ("\"%s\"}", bitfield);
		else if (MUSTSEE) p->printf (" %s (bitfield) = %s\n", fieldname, bitfield);
	} else {
		if (MUSTSEEJSON) p->printf ("\"`tb %s 0x%x`\"}", fmtname, addr);
		else if (MUSTSEE) p->printf (" %s (bitfield) = `tb %s 0x%x`\n",
				fieldname, fmtname, addr);
	}
	free (bitfield);
}

static void r_print_format_enum (const RPrint* p, ut64 seeki, char* fmtname,
		char* fieldname, ut64 addr, int mode, int size) {
	char *enumvalue = NULL;
	switch (size) {
		case 1: addr &= UT8_MAX; break;
		case 2: addr &= UT16_MAX; break;
		case 4: addr &= UT32_MAX; break;
	}
	if (MUSTSEE)
		p->printf ("0x%08"PFMT64x" = ", seeki);
	if (p->get_enumname)
		enumvalue = p->get_enumname (p->user, fmtname, addr);
	if (enumvalue && *enumvalue) {
		if (MUSTSEEJSON) p->printf ("\"%s\"}", fmtname);
		else if (MUSTSEE) p->printf (" %s (enum) = 0x%"PFMT64x" ; %s\n",
				fieldname, addr, enumvalue);
	} else {
		if (MUSTSEEJSON) p->printf ("\"`te %s 0x%x`\"}", fmtname, addr);
		else if (MUSTSEE) p->printf (" %s (enum) = `te %s 0x%x`\n",
				fieldname, fmtname, addr);
	}
	free (enumvalue);
}

// XXX: this is very incomplete. must be updated to handle all format chars
int r_print_format_struct_size(const char *f, RPrint *p, int mode) {
	char *o = strdup(f);
	char *end = strchr (o, ' '), *args, *fmt = o;
	int size = 0, tabsize=0, i, idx=0, biggest = 0;
	if (!end && !(end = strchr (o, '\0')))
		return -1;
	if (*end) {
		*end = 0;
		args = strdup (end+1);
	} else {
		args = strdup ("");
	}
	if (fmt[0] == '0') {
		mode |= R_PRINT_UNIONMODE;
		fmt++;
	} else {
		mode &= ~R_PRINT_UNIONMODE;
	}

	r_str_word_set0 (args);
	for (i=0; i<strlen (fmt); i++) {
		if (fmt[i] == '[') {
			char *end = strchr (fmt+i,']');
			if (end == NULL) {
				eprintf ("No end bracket.\n");
				continue;
			}
			*end = '\0';
			tabsize = r_num_math (NULL, fmt+i+1);
			*end = ']';
			while (fmt[i++]!=']');
		} else {
			tabsize = 1;
		}

		switch (fmt[i]) {
			case 'c':
			case 'b':
			case '.':
			case 'X':
				size += tabsize*1;
				break;
			case 'w':
				size += tabsize*2;
				break;
			case 'd':
			case 'o':
			case 'i':
			case 'x':
			case 'f':
			case 's':
			case 't':
			case ':':
				size += tabsize*4;
				break;
			case 'S':
			case 'q':
				size += tabsize*8;
				break;
			case 'z':
			case 'Z':
				size += tabsize;
				break;
			case '*':
				size += tabsize*4;
				i++;
				break;
			case 'B':
			case 'E':
				switch (tabsize) {
				case 1: size+=1; break;
				case 2: size+=2; break;
				case 4: size+=4; break;
				default: break;
				}
				break;
			case '?':
				{
				const char *format = NULL;
				char *endname = NULL, *structname = NULL;
				structname = strdup(r_str_word_get0 (args, idx));
				if (*structname == '(') {
					endname = strchr (structname, ')');
				} else {
					eprintf ("Struct name missing (%s)\n", structname);
					free(structname);
					break;
				}
				if (endname) *endname = '\0';
				format = r_strht_get (p->formats, structname+1);
				free (structname);
				size += tabsize * r_print_format_struct_size (format, p, mode);
				}
				break;
				// TODO continue list
			default:
				break;
		}
		idx++;
		if (mode & R_PRINT_UNIONMODE) {
			if (size > biggest) biggest = size;
			size = 0;
		}
	}
	free (o);
	free (args);
	if (mode & R_PRINT_UNIONMODE)
		return biggest;
	else
		return size;
}

static int r_print_format_struct(RPrint* p, ut64 seek, const ut8* b, int len,
		char *name, int slide, int mode, const char *setval, char *field) {
	const char *fmt;
	char namefmt[8];
	if ((slide%STRUCTPTR) > NESTDEPTH || (slide%STRUCTFLAG)/STRUCTPTR > NESTDEPTH) {
		eprintf ("Too much nested struct, recursion too deep...\n");
		return 0;
	}
	fmt = r_strht_get (p->formats, name);
	if (!fmt || !*fmt) {
		eprintf ("Undefined struct '%s'.\n", name);
		return 0;
	}
	if (MUSTSEE) {
		snprintf (namefmt, sizeof (namefmt), "%%%ds", 10+6*slide%STRUCTPTR);
		if (fmt[0] == '0')
			p->printf (namefmt, "union");
		else
			p->printf (namefmt, "struct");
		p->printf ("<%s>\n", name);
	}
	r_print_format (p, seek, b, len, fmt, mode, setval, field);
	return r_print_format_struct_size(fmt, p, mode);
}

#define MINUSONE ((void*)(size_t)-1)
//#define MUSTSET (setval && field && isfield && mode == R_PRINT_MUSTSET)
//#define MUSTSEE (ofield != MINUSONE && (field == NULL || (setval == NULL && isfield)) && mode == R_PRINT_MUSTSEE)
#define ISSTRUCT (tmp == '?' || (tmp == '*' && *(arg+1) == '?'))
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* b, const int len,
		const char *formatname, int mode, const char *setval, char *ofield) {
	int nargs, i, j, invalid, nexti, idx, times, otimes, endian, isptr = 0;
	const char *argend;
	ut64 addr = 0, addr64 = 0, seeki = 0;;
	const char *fmt = NULL;
	char *args = NULL, *bracket, tmp, last = 0;
	const char *arg = NULL;
	int viewflags = 0;
	char namefmt[8], *field = NULL;
	char *oarg = NULL;
	static int slide=0, oldslide=0;
	ut8 *buf;
	if (!formatname)
		return 0;
	fmt = r_strht_get (p->formats, formatname);
	if (fmt == NULL)
		fmt = formatname;
	argend = fmt+strlen (fmt);
	arg = fmt;

	nexti = nargs = i = j = 0;

	if (len < 1)
		return 0;
	buf = malloc (len);
	if (!buf)
		return 0;
	memcpy (buf, b, len);
	endian = p->big_endian;

	if (ofield && ofield != MINUSONE) field = strdup (ofield);

	while (*arg && iswhitechar (*arg)) arg++;

	/* get times */
	otimes = times = atoi (arg);
	if (times > 0)
		while ((*arg>='0'&&*arg<='9')) arg++;

	bracket = strchr (arg,'{');
	if (bracket) {
		char *end = strchr (arg, '}');
		if (end == NULL) {
			eprintf ("No end bracket. Try pm {ecx}b @ esi\n");
			goto beach;
		}
		*end='\0';
		times = r_num_math (NULL, bracket+1);
		arg = end + 1;
	}

	if (*arg=='\0') {
		goto beach;
	}

	/* get args */
	args = strchr (arg, ' ');
	if (args) {
		int l=0, maxl = 0;
		argend = args;
		args = strdup (args+1);
		nargs = r_str_word_set0 (args);
		if (nargs == 0)
			R_FREE (args);
		for (i=0; i<nargs; i++) {
			const int len = strlen (r_str_word_get0 (args, i));
			if (len > maxl)
				maxl = len;
		}
		l++;
		snprintf (namefmt, sizeof (namefmt), "%%%ds : ", maxl+6*slide%STRUCTPTR);
	}
#define ISPOINTED ((slide%STRUCTFLAG)/STRUCTPTR<=(oldslide%STRUCTFLAG)/STRUCTPTR)
#define ISNESTED ((slide%STRUCTPTR)<=(oldslide%STRUCTPTR))
	if (mode == R_PRINT_JSON && slide==0) p->printf("[");
	if (arg[0] == '0') {
		mode |= R_PRINT_UNIONMODE;
		arg++;
	} else {
		mode &= ~R_PRINT_UNIONMODE;
	}

	/* go format */
	i = 0;
	if (!times)
		otimes = times = 1;
	for (; times; times--) { // repeat N times
		const char * orig = arg;
		int first = 1;
		if (otimes>1) {
			if (mode & R_PRINT_JSON) {
				if (otimes > times) p->printf (",");
				p->printf ("[{\"index\":%d,\"offset\":%d},", otimes-times, seek+i);
			} else
				p->printf ("0x%08"PFMT64x" [%d] {\n", seek+i, otimes-times);
		}
		arg = orig;
		for (idx=0; i<len && arg<argend && *arg; arg++) {
			int size = 0, elem = 0; /* size of the array, element of the array */
			char *fieldname = NULL, *fmtname = NULL;
			if (mode & R_PRINT_UNIONMODE) {
				i = 0;
			}
			seeki = seek+i;
			addr = 0LL;
			invalid = 0;
			if (arg[0] == '[') {
				char *end = strchr (arg,']');
				if (end == NULL) {
					eprintf ("No end bracket.\n");
					goto beach;
				}
				*end = '\0';
				size = r_get_size (p->num, buf, endian, arg+1);
				arg = end + 1;
				*end = ']';
			} else {
				size = -1;
			}
			updateAddr (buf, i, endian, &addr, &addr64);

			tmp = *arg;

			if (args == NULL)
				mode |= R_PRINT_ISFIELD;
			if (mode & R_PRINT_MUSTSEE && otimes>1)
				p->printf ("   ");
			if (idx<nargs && tmp != 'e' && isptr == 0) {
				char *dot = NULL, *bracket = NULL;
				if (field)
					dot = strchr (field, '.');
				if (dot)
					*dot = '\0';
				if (oarg != NULL)
					free (oarg);
				oarg = fieldname = strdup(r_str_word_get0 (args, idx));
				if (ISSTRUCT || tmp=='E' || tmp=='B') {
					if (*fieldname == '(') {
						fmtname = fieldname+1;
						fieldname = strchr (fieldname, ')');
						if (fieldname) *fieldname++ = '\0';
						else {
							eprintf ("Missing closing parenthesis in format ')'\n");
							goto beach;
						}
					} else {
						eprintf ("Missing name (%s)\n", fieldname);
						goto beach;
					}
				}
				if (args == NULL || (field==NULL && ofield != MINUSONE)
						|| (field && !strncmp(field, fieldname, strlen(fieldname)))) {
					mode |= R_PRINT_ISFIELD;
				} else {
					mode &= ~R_PRINT_ISFIELD;
				}
				/* There we handle specific element in array */
				if (field != NULL && (bracket = strchr (field, '[')) != NULL && mode & R_PRINT_ISFIELD) {
					char *end = strchr (field, ']');
					if (end == NULL) {
						eprintf ("Missing closing bracket\n");
						goto beach;
					}
					*end = '\0';
					elem = r_num_math (NULL, bracket+1)+1; // +1 to handle 0 index easily
					for ( ; bracket < end; bracket++)
						*bracket = '\0';
					size += elem*ARRAYINDEX_COEF;
				} else {
					elem = -1;
				}
				idx++;
				if (MUSTSEE) {
					p->printf (namefmt, fieldname);
				}
			}

		feed_me_again:
			switch (isptr) {
			case 1:
				{
				nexti = i + (p->bits/8);
				i = 0;
				if(tmp == '?' )seeki = addr;
				memset (buf, '\0', len);
				if (MUSTSEE)
					p->printf ("(*0x%"PFMT64x") ", addr);
				if (addr == 0) isptr = NULLPTR;
				else isptr = PTRBACK;
				if (/*addr<(b+len) && addr>=b && */p->iob.read_at) { /* The test was here to avoid segfault in the next line,
						but len make it doesnt work... */
					p->iob.read_at (p->iob.io, (ut64)addr, buf, len-4);
					updateAddr (buf, i, endian, &addr, &addr64);
				} else {
					eprintf ("(SEGFAULT: cannot read memory at 0x%08"PFMT64x", Block: %s, blocksize: 0x%x)\n",
							addr, b, len);
					p->printf("\n");
					goto beach;
				}
				}
				break;
			case 2:
				// restore state after pointer seek
				i = nexti;
				seeki = seek+i;
				memcpy (buf, b, len);
				isptr = NOPTR;
				arg--;
				continue;
			}
			if (tmp == 0 && last != '*')
				break;

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
				if (size == -1) i+=4;
				else while (size--) i+=4;
				continue;
			case '.': // skip 1 byte
				if (size == -1) i++;
				else i+=size;
				continue;
			case 'p': // pointer reference
				tmp = (p->bits == 64)? 'q': 'x';
				break;
			}

			/* flags */
			if (mode & R_PRINT_SEEFLAGS && isptr != NULLPTR) {
				if (mode & R_PRINT_UNIONMODE) {
					p->printf ("f %s=0x%08"PFMT64x"\n", formatname, seeki);
					goto beach;
				} else if (tmp == '?') {
					p->printf ("f %s.%s_", fmtname, fieldname);
				} else if (tmp == 'E') {
					p->printf ("f %s=0x%08"PFMT64x"\n", fieldname, seeki);
				} else if (slide/STRUCTFLAG>0 && idx==1) {
					p->printf ("%s=0x%08"PFMT64x"\n", fieldname, seeki);
				} else p->printf ("f %s=0x%08"PFMT64x"\n", fieldname , seeki);
			}

			/* json */
			if (MUSTSEEJSON && mode & R_PRINT_JSON) {
				if (oldslide<=slide) {
					if (!first)
						p->printf (",");
					else
						first = 0;
				} else if(oldslide!=0) {
					p->printf ("]},");
				}
				p->printf ("{\"name\":\"%s\",\"type\":\"", fieldname);
				if (ISSTRUCT) {
					p->printf ("%s", fmtname);
				} else {
					p->printf ("%c", tmp);
				}
				if (isptr) p->printf ("*");
				p->printf ("\",\"offset\":%d,\"value\":",(isptr)?(seek+nexti-(p->bits/8)):seek+i);
			}

			if (isptr == NULLPTR) {
				if (MUSTSEEJSON)
					p->printf ("\"NULL\"}", tmp, seek+i);
				else if (MUSTSEE)
					p->printf ("NULL\n");
				isptr = PTRBACK;
			} else
			/* format chars */
			switch (tmp) {
			case 'u':
				i+= r_print_format_uleb(p, endian, mode, setval, seeki, buf, i, size);
				break;
			case 't':
				r_print_format_time(p, endian, mode, setval, seeki, buf, i, size);
				i+= (size==-1) ? 4 : 4*size;
				break;
			case 'q':
				r_print_format_quadword(p, endian, mode, setval, seeki, buf, i, size);
				i += (size==-1) ? 8 : 8*size;
				break;
			case 'b':
				r_print_format_byte(p, endian, mode, setval, seeki, buf, i, size);
				i+= (size==-1) ? 1 : size;
				break;
			case 'C':
				r_print_format_decchar (p, endian, mode,
					setval, seeki, buf, i, size);
				i+= (size==-1) ? 1 : size;
				break;
			case 'c':
				r_print_format_char (p, endian, mode,
					setval, seeki, buf, i, size);
				i+= (size==-1) ? 1 : size;
				break;
			case 'X':
				size = r_print_format_hexpairs (p, endian, mode,
					setval, seeki, buf, i, size);
				i += size;
				break;
			case 'T':
				if(r_print_format_10bytes(p, mode,
					setval, seeki, addr, buf) == 0)
					i += (size==-1) ? 4 : 4*size;
				break;
			case 'f':
				r_print_format_float(p, endian, mode, setval, seeki, buf, i, size);
				i += (size==-1) ? 4 : 4*size;
				break;
			case 'i':
			case 'd':
				r_print_format_hex(p, endian, mode, setval, seeki, buf, i, size);
				i+= (size==-1) ? 4 : 4*size;
				break;
			case 'D':
				if (size>0) p->printf ("Size not yet implemented\n");
				if (p->disasm && p->user)
					i += p->disasm (p->user, seeki);
				break;
			case 'o':
				r_print_format_octal (p, endian, mode, setval, seeki, buf, i, size);
				i+= (size==-1) ? 4 : 4*size;
				break;
			case 'x':
				r_print_format_hexflag(p, endian, mode, setval, seeki, buf, i, size);
				i+= (size==-1) ? 4 : 4*size;
				break;
			case 'w':
				r_print_format_word(p, endian, mode, setval, seeki, buf, i, size);
				i+= (size==-1) ? 2 : 2*size;
				break;
			case 'z': // zero terminated string
				r_print_format_nulltermstring (p, len, endian, mode, setval, seeki, buf, i, size);
				if (size == -1)
					i+=strlen((char*)buf+i)+1;
				else
					while (size--) i++;
				break;
			case 'Z': // zero terminated wide string
				r_print_format_nulltermwidestring (p, len, endian, mode, setval, seeki, buf, i, size);
				if (size == -1)
					i+=r_wstr_clen((char*)(buf+i))*2+2;
				else
					while (size--) i+=2;
				break;
			case 's':
				if (r_print_format_string (p, seeki, addr64, addr, 0, mode) == 0)
					i += (size==-1) ? 4 : 4*size;
				break;
			case 'S':
				if (r_print_format_string (p, seeki, addr64, addr, 1, mode) == 0)
					i += (size==-1) ? 8 : 8*size;
				break;
			case 'B': // resolve bitfield
				if (size >= ARRAYINDEX_COEF) size %= ARRAYINDEX_COEF;
				r_print_format_bitfield (p, seeki, fmtname, fieldname, addr, mode, size);
				i+=(size==-1)?1:size;
				break;
			case 'E': // resolve enum
				if (size >= ARRAYINDEX_COEF) size %= ARRAYINDEX_COEF;
				r_print_format_enum (p, seeki, fmtname, fieldname, addr, mode, size);
				i+=(size==-1)?1:size;
				break;
			case '?':
				{
				int s = 0;
				char *nxtfield = NULL;
				if (size >= ARRAYINDEX_COEF) {
					elem = size/ARRAYINDEX_COEF-1;
					size %= ARRAYINDEX_COEF;
				}
				if (!(mode & R_PRINT_ISFIELD)) nxtfield = MINUSONE;
				else if (field) nxtfield = strchr (ofield, '.');
				if (nxtfield != MINUSONE && nxtfield != NULL) nxtfield++;

				if (MUSTSEE)
					p->printf ("\n");
				if (MUSTSEEJSON) {
					if (isptr)
						p->printf ("%d},", seeki);
					else
						p->printf ("[");
				}
				if (mode & R_PRINT_SEEFLAGS) slide+=STRUCTFLAG;
				oldslide = slide;
				slide += (isptr) ? STRUCTPTR : NESTEDSTRUCT;
				if (size == -1) {
					s = r_print_format_struct (p, seeki,
						buf+i, len-i, fmtname, slide,
						mode, setval, nxtfield);
					i+= (isptr) ? 4 : s;
				} else {
					if (mode & R_PRINT_ISFIELD)
						p->printf ("[\n");
					while (size--) {
						if (elem == -1 || elem == 0) {
							mode |= R_PRINT_MUSTSEE;
							if (elem == 0) elem = -2;
						} else {
							mode &= ~R_PRINT_MUSTSEE;
						}
						s = r_print_format_struct (p, seek+i,
							buf+i, len-i, fmtname, slide, mode, setval, nxtfield);
						if ((MUSTSEE || MUSTSEEJSON) && size != 0 && elem == -1) {
							p->printf (",");
							if (MUSTSEE) p->printf ("\n");
						}
						if (elem > -1) elem--;
						i+= (isptr) ? 4 : s;
					}
					if (mode & R_PRINT_ISFIELD)
						p->printf ("]");
					if (MUSTSEEJSON) p->printf ("]}]}");
				}
				oldslide = slide;
				slide -= (isptr) ? STRUCTPTR : NESTEDSTRUCT;
				if (mode & R_PRINT_SEEFLAGS) {
					oldslide = slide;
					slide-=STRUCTFLAG;
				}
				break;
				}
			default:
				/* ignore unknown chars */
				invalid = 1;
				break;
			}
			if (viewflags && p->offname) {
				const char *s = p->offname (p->user, seeki);
				if (s)
					p->printf ("@(%s)", s);
				s = p->offname (p->user, addr);
				if (s)
					p->printf ("*(%s)", s);
			}
			if (tmp != 'D' && !invalid && fmtname==NULL && MUSTSEE)
				p->printf ("\n");
			last = tmp;
		}
		if (otimes>1) {
			if (MUSTSEEJSON) p->printf ("]");
			else p->printf ("}\n");
		}
		arg = orig;
		oldslide = 0;
	}
	if (mode & R_PRINT_JSON && slide==0) p->printf("]");
beach:
	if (oarg != NULL)
		free (oarg);
	free (buf);
	free (field);
	free (args);
	return i;
}
