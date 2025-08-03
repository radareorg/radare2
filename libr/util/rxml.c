/* r_xml is based on yxml from Yoran Heling (2013-2014) */
/* License: BSD */
/* $ git clone https://g.blicky.net/yxml.git */
/* https://dev.yorhel.nl/r_xml */

#include <r_util.h>
#include <r_util/r_xml.h>

#define R_XML_IS_CHAR(c) true
/* 0xd should be part of SP, too, but r_xml_parse() already normalizes that into 0xa */
#define R_XML_IS_SP(c) ((c) == 0x20 || (c) == 0x09 || (c) == 0x0a)
#define R_XML_IS_ALPHA(c) (((c)|32)-'a' < 26)
#define R_XML_IS_NUM(c) ((c) - '0' < 10)
#define r_xml_isHex(c) (R_XML_IS_NUM(c) || ((c)|32)-'a' < 6)
#define r_xml_isEncName(c) (R_XML_IS_ALPHA(c) || R_XML_IS_NUM(c) || (c) == '.' || (c) == '_' || (c) == '-')
#define R_XML_IS_NAME_START(c) (R_XML_IS_ALPHA(c) || (c) == ':' || (c) == '_' || (c) >= 128)
#define R_XML_IS_NAME(x) (R_XML_IS_NAME_START (x) || R_XML_IS_NUM(x) || (x) == '-' || (x) == '.')
/* XXX: The valid characters are dependent on the quote char, hence the access to x->quote */
#define r_xml_isAttValue(c) (R_XML_IS_CHAR(c) && (c) != x->quote && (c) != '<' && (c) != '&')
/* Anything between '&' and ';', the r_xml_ref* functions will do further
 * validation. Strictly speaking, this is "R_XML_IS_NAME(c) || c == '#'", but
 * this parser doesn't understand entities with '.', ':', etc, anwyay.  */
#define R_XML_IS_REF(c) (R_XML_IS_NUM(c) || R_XML_IS_ALPHA (c) || (c) == '#')

#define INTFROM5CHARS(a, b, c, d, e) ((((ut64)(a))<<32) | (((ut64)(b))<<24) | (((ut64)(c))<<16) | (((ut64)(d))<<8) | (ut64)(e))


/* Set the given char value to ch (0<=ch<=255). */
static inline void r_xml_setchar(char *dest, unsigned ch) {
	*(ut8 *)dest = ch;
}

/* Similar to r_xml_setchar(), but will convert ch (any valid unicode point) to
 * UTF-8 and appends a '\0'. dest must have room for at least 5 bytes. */
static void r_xml_setutf8(char *dest, unsigned ch) {
	if (ch <= 0x007F) {
		r_xml_setchar (dest++, ch);
	} else if (ch <= 0x07FF) {
		r_xml_setchar (dest++, 0xC0 | (ch>>6));
		r_xml_setchar (dest++, 0x80 | (ch & 0x3F));
	} else if (ch <= 0xFFFF) {
		r_xml_setchar (dest++, 0xE0 | (ch>>12));
		r_xml_setchar (dest++, 0x80 | ((ch>>6) & 0x3F));
		r_xml_setchar (dest++, 0x80 | (ch & 0x3F));
	} else {
		r_xml_setchar (dest++, 0xF0 | (ch>>18));
		r_xml_setchar (dest++, 0x80 | ((ch>>12) & 0x3F));
		r_xml_setchar (dest++, 0x80 | ((ch>>6) & 0x3F));
		r_xml_setchar (dest++, 0x80 | (ch & 0x3F));
	}
	*dest = 0;
}

static inline RXmlRet r_xml_datacontent(RXml *x, unsigned ch) {
	r_xml_setchar (x->data, ch);
	x->data[1] = 0;
	return R_XML_CONTENT;
}

static inline RXmlRet r_xml_datapi1(RXml *x, unsigned ch) {
	r_xml_setchar (x->data, ch);
	x->data[1] = 0;
	return R_XML_PICONTENT;
}

static inline RXmlRet r_xml_datapi2(RXml *x, unsigned ch) {
	x->data[0] = '?';
	r_xml_setchar (x->data + 1, ch);
	x->data[2] = 0;
	return R_XML_PICONTENT;
}

static inline RXmlRet r_xml_datacd1(RXml *x, unsigned ch) {
	x->data[0] = ']';
	r_xml_setchar (x->data + 1, ch);
	x->data[2] = 0;
	return R_XML_CONTENT;
}

static inline RXmlRet r_xml_datacd2(RXml *x, unsigned ch) {
	x->data[0] = ']';
	x->data[1] = ']';
	r_xml_setchar (x->data + 2, ch);
	x->data[3] = 0;
	return R_XML_CONTENT;
}

static inline RXmlRet r_xml_dataattr(RXml *x, unsigned ch) {
	/* Normalize attribute values according to the XML spec section 3.3.3. */
	r_xml_setchar (x->data, ch == 0x9 || ch == 0xa ? 0x20 : ch);
	x->data[1] = 0;
	return R_XML_ATTRVAL;
}

static RXmlRet r_xml_pushstack(RXml *x, char **res, unsigned ch) {
	if (x->stacklen + 2 >= x->stacksize) {
		return R_XML_ESTACK;
	}
	x->stacklen++;
	*res = (char *)x->stack+x->stacklen;
	x->stack[x->stacklen] = ch;
	x->stacklen++;
	x->stack[x->stacklen] = 0;
	return R_XML_OK;
}

static RXmlRet r_xml_pushstackc(RXml *x, unsigned ch) {
	if (x->stacklen + 1 >= x->stacksize) {
		return R_XML_ESTACK;
	}
	x->stack[x->stacklen] = ch;
	x->stacklen++;
	x->stack[x->stacklen] = 0;
	return R_XML_OK;
}

static void r_xml_popstack(RXml *x) {
	do {
		x->stacklen--;
	} while (x->stack[x->stacklen]);
}

static inline RXmlRet xml_elemstart(RXml *x, unsigned ch) { return r_xml_pushstack(x, &x->elem, ch); }
static inline RXmlRet xml_elemname(RXml *x, unsigned ch) { return r_xml_pushstackc(x, ch); }
static inline RXmlRet xml_elemnameend(RXml *x, unsigned ch) { return R_XML_ELEMSTART; }

/* Also used in xml_elemcloseend (), since this function just removes the last
 * element from the stack and returns ELEMEND. */
static RXmlRet r_xml_selfclose(RXml *x, unsigned ch) {
	r_xml_popstack (x);
	if (x->stacklen) {
		x->elem = (char *)x->stack+x->stacklen-1;
		while (*(x->elem-1)) {
			x->elem--;
		}
		return R_XML_ELEMEND;
	}
	x->elem = (char *)x->stack;
	x->state = R_XML_STATE_MISC3;
	return R_XML_ELEMEND;
}

static inline RXmlRet xml_elemclose(RXml *x, unsigned ch) {
	if (*((ut8 *)x->elem) != ch) {
		return R_XML_ECLOSE;
	}
	x->elem++;
	return R_XML_OK;
}

static inline RXmlRet xml_elemcloseend (RXml *x, unsigned ch) {
	if (*x->elem) {
		return R_XML_ECLOSE;
	}
	return r_xml_selfclose (x, ch);
}

static inline RXmlRet r_xml_attrstart(RXml *x, unsigned ch) { return r_xml_pushstack(x, &x->attr, ch); }
static inline RXmlRet r_xml_attrname(RXml *x, unsigned ch) { return r_xml_pushstackc(x, ch); }
static inline RXmlRet r_xml_attrnameend(RXml *x, unsigned ch) { return R_XML_ATTRSTART; }
static inline RXmlRet r_xml_attrvalend(RXml *x, unsigned ch) { r_xml_popstack(x); return R_XML_ATTREND; }


static inline RXmlRet r_xml_pistart(RXml *x, unsigned ch) { return r_xml_pushstack(x, &x->pi, ch); }
static inline RXmlRet r_xml_piname(RXml *x, unsigned ch) { return r_xml_pushstackc(x, ch); }
static inline RXmlRet r_xml_piabort(RXml *x, unsigned ch) { r_xml_popstack(x); return R_XML_OK; }
static inline RXmlRet r_xml_pinameend(RXml *x, unsigned ch) {
	return (x->pi[0]|32) == 'x' && (x->pi[1]|32) == 'm' && (x->pi[2]|32) == 'l' && !x->pi[3] ? R_XML_ESYN : R_XML_PISTART;
}
static inline RXmlRet r_xml_pivalend(RXml *x, unsigned ch) { r_xml_popstack(x); x->pi = (char *)x->stack; return R_XML_PIEND; }

static inline RXmlRet r_xml_refstart(RXml *x, unsigned ch) {
	memset (x->data, 0, sizeof (x->data));
	x->reflen = 0;
	return R_XML_OK;
}

static RXmlRet r_xml_ref(RXml *x, unsigned ch) {
	if (x->reflen >= sizeof (x->data) - 1) {
		return R_XML_EREF;
	}
	r_xml_setchar (x->data + x->reflen, ch);
	x->reflen++;
	return R_XML_OK;
}

static RXmlRet r_xml_refend (RXml *x, RXmlRet ret) {
	ut8 *r = (ut8 *)x->data;
	unsigned ch = 0;
	if (*r == '#') {
		if (r[1] == 'x') {
			for (r += 2; r_xml_isHex((ut8)*r); r++) {
				ch = (ch<<4) + (*r <= '9' ? *r-'0' : (*r|32)-'a' + 10);
			}
		} else {
			for (r++; R_XML_IS_NUM((ut8)*r); r++) {
				ch = (ch*10) + (*r-'0');
			}
		}
		if (*r)
			ch = 0;
	} else {
		ut64 i = INTFROM5CHARS (r[0], r[1], r[2], r[3], r[4]);
		ch =
			i == INTFROM5CHARS ('l','t', 0,  0, 0) ? '<' :
			i == INTFROM5CHARS ('g','t', 0,  0, 0) ? '>' :
			i == INTFROM5CHARS ('a','m','p', 0, 0) ? '&' :
			i == INTFROM5CHARS ('a','p','o','s',0) ? '\'':
			i == INTFROM5CHARS ('q','u','o','t',0) ? '"' : 0;
	}

	/* Codepoints not allowed in the XML 1.1 definition of a Char */
	if (!ch || ch > 0x10FFFF || ch == 0xFFFE || ch == 0xFFFF || (ch-0xDFFF) < 0x7FF) {
		return R_XML_EREF;
	}
	r_xml_setutf8 (x->data, ch);
	return ret;
}

static inline RXmlRet r_xml_refcontent(RXml *x, ut8 ch) { return r_xml_refend (x, R_XML_CONTENT); }
static inline RXmlRet r_xml_refattrval(RXml *x, ut8 ch) { return r_xml_refend (x, R_XML_ATTRVAL); }

R_API void r_xml_init(RXml *x, void *stack, size_t stacksize) {
	R_RETURN_IF_FAIL (x);
	memset (x, 0, sizeof (*x)); // probably unnecessary
	x->line = 1;
	x->stack = (ut8*)stack;
	x->stacksize = stacksize;
	*x->stack = 0;
	x->elem = x->pi = x->attr = (char *)x->stack;
	x->state = R_XML_STATE_INIT;
}

R_API RXml *r_xml_new(int stacksize) {
	RXml *x = R_NEW (RXml);
	if (x) {
		r_xml_init (x, malloc (stacksize), stacksize);
	}
	return x;
}

R_API void r_xml_free(RXml *x) {
	if (x) {
		free (x->stack);
		free (x);
	}
}

R_API RXmlRet r_xml_parse(RXml *x, int _ch) {
	/* Ensure that characters are in the range of 0..255 rather than -126..125.
	 * All character comparisons are done with positive integers. */
	ut32 ch = (ut32)(_ch + 256) & 0xff;
	if (!ch) {
		return R_XML_ESYN;
	}
	x->total++;

	/* End-of-Line normalization, "\rX", "\r\n" and "\n" are recognized and
	 * normalized to a single '\n' as per XML 1.0 section 2.11. XML 1.1 adds
	 * some non-ASCII character sequences to this list, but we can only handle
	 * ASCII here without making assumptions about the input encoding. */
	if (x->ignore == ch) {
		x->ignore = 0;
		return R_XML_OK;
	}
	x->ignore = (ch == 0xd) * 0xa;
	if (ch == 0xa || ch == 0xd) {
		ch = 0xa;
		x->line++;
		x->byte = 0;
	}
	x->byte++;

	switch (x->state) {
	case R_XML_STATE_STRING:
		if (ch == *x->string) {
			x->string++;
			if (!*x->string) {
				x->state = x->nextstate;
			}
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ATTR0:
		if (R_XML_IS_NAME (ch)) {
			return r_xml_attrname (x, ch);
		}
		if (R_XML_IS_SP (ch) || ch == (ut8)'=') {
			x->state = (R_XML_IS_SP (ch))? R_XML_STATE_ATTR1: R_XML_STATE_ATTR2;
			return r_xml_attrnameend (x, ch);
		}
		break;
	case R_XML_STATE_ATTR1:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'=') {
			x->state = R_XML_STATE_ATTR2;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ATTR2:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'\'' || ch == (ut8)'"') {
			x->state = R_XML_STATE_ATTR3;
			x->quote = ch;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ATTR3:
		if (r_xml_isAttValue(ch)) {
			return r_xml_dataattr (x, ch);
		}
		if (ch == (ut8)'&') {
			x->state = R_XML_STATE_ATTR4;
			return r_xml_refstart (x, ch);
		}
		if (x->quote == ch) {
			x->state = R_XML_STATE_ELEM2;
			return r_xml_attrvalend (x, ch);
		}
		break;
	case R_XML_STATE_ATTR4:
		if (R_XML_IS_REF (ch)) {
			return r_xml_ref (x, ch);
		}
		if (ch == (ut8)'\x3b') {
			x->state = R_XML_STATE_ATTR3;
			return r_xml_refattrval (x, ch);
		}
		break;
	case R_XML_STATE_CD0:
		if (ch == (ut8)']') {
			x->state = R_XML_STATE_CD1;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			return r_xml_datacontent(x, ch);
		}
		break;
	case R_XML_STATE_CD1:
		if (ch == (ut8)']') {
			x->state = R_XML_STATE_CD2;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			x->state = R_XML_STATE_CD0;
			return r_xml_datacd1 (x, ch);
		}
		break;
	case R_XML_STATE_CD2:
		if (ch == (ut8)']') {
			return r_xml_datacontent (x, ch);
		}
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC2;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			x->state = R_XML_STATE_CD0;
			return r_xml_datacd2 (x, ch);
		}
		break;
	case R_XML_STATE_COMMENT0:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT1;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_COMMENT1:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT2;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_COMMENT2:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT3;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_COMMENT3:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT4;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			x->state = R_XML_STATE_COMMENT2;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_COMMENT4:
		if (ch == (ut8)'>') {
			x->state = x->nextstate;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_DT0:
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC1;
			return R_XML_OK;
		}
		if (ch == (ut8)'\'' || ch == (ut8)'"') {
			x->state = R_XML_STATE_DT1;
			x->quote = ch;
			x->nextstate = R_XML_STATE_DT0;
			return R_XML_OK;
		}
		if (ch == (ut8)'<') {
			x->state = R_XML_STATE_DT2;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_DT1:
		if (x->quote == ch) {
			x->state = x->nextstate;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_DT2:
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_PI0;
			x->nextstate = R_XML_STATE_DT0;
			return R_XML_OK;
		}
		if (ch == (ut8)'!') {
			x->state = R_XML_STATE_DT3;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_DT3:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT1;
			x->nextstate = R_XML_STATE_DT0;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			x->state = R_XML_STATE_DT4;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_DT4:
		if (ch == (ut8)'\'' || ch == (ut8)'"') {
			x->state = R_XML_STATE_DT1;
			x->quote = ch;
			x->nextstate = R_XML_STATE_DT4;
			return R_XML_OK;
		}
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_DT0;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ELEM0:
		if (R_XML_IS_NAME (ch)) {
			return xml_elemname (x, ch);
		}
		if (R_XML_IS_SP (ch) || ch == (ut8)'/' || ch == (ut8)'>') {
			if (R_XML_IS_SP (ch)) {
				x->state = R_XML_STATE_ELEM1;
			} else if (ch == (ut8)'/') {
				x->state = R_XML_STATE_ELEM3;
			} else { /* ch == '>' */
				x->state = R_XML_STATE_MISC2;
			}
			return xml_elemnameend (x, ch);
		}
		break;
	case R_XML_STATE_ELEM1:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'/') {
			x->state = R_XML_STATE_ELEM3;
			return R_XML_OK;
		}
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC2;
			return R_XML_OK;
		}
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_ATTR0;
			return r_xml_attrstart (x, ch);
		}
		break;
	case R_XML_STATE_ELEM2:
		if (R_XML_IS_SP (ch)) {
			x->state = R_XML_STATE_ELEM1;
			return R_XML_OK;
		}
		if (ch == (ut8)'/') {
			x->state = R_XML_STATE_ELEM3;
			return R_XML_OK;
		}
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC2;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ELEM3:
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC2;
			return r_xml_selfclose(x, ch);
		}
		break;
	case R_XML_STATE_ENC0:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'=') {
			x->state = R_XML_STATE_ENC1;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ENC1:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'\'' || ch == (ut8)'"') {
			x->state = R_XML_STATE_ENC2;
			x->quote = ch;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ENC2:
		if (R_XML_IS_ALPHA (ch)) {
			x->state = R_XML_STATE_ENC3;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ENC3:
		if (r_xml_isEncName (ch)) {
			return R_XML_OK;
		}
		if (x->quote == ch) {
			x->state = R_XML_STATE_XMLDECL6;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_ETAG0:
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_ETAG1;
			return xml_elemclose(x, ch);
		}
		break;
	case R_XML_STATE_ETAG1:
		if (R_XML_IS_NAME (ch)) {
			return xml_elemclose(x, ch);
		}
		if (R_XML_IS_SP (ch) || ch == (ut8)'>') {
			x->state = (R_XML_IS_SP (ch))? R_XML_STATE_ETAG2: R_XML_STATE_MISC2;
			return xml_elemcloseend (x, ch);
		}
		break;
	case R_XML_STATE_ETAG2:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC2;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_INIT:
		if (ch == (ut8)'\xef') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_MISC0;
			x->string = (ut8 *)"\xbb\xbf";
			return R_XML_OK;
		}
		if (R_XML_IS_SP (ch)) {
			x->state = R_XML_STATE_MISC0;
			return R_XML_OK;
		}
		if (ch == (ut8)'<') {
			x->state = R_XML_STATE_le0;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_le0:
		if (ch == (ut8)'!') {
			x->state = R_XML_STATE_LEE1;
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_LEQ0;
			return R_XML_OK;
		}
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_ELEM0;
			return xml_elemstart (x, ch);
		}
		break;
	case R_XML_STATE_le1:
		if (ch == (ut8)'!') {
			x->state = R_XML_STATE_LEE1;
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_PI0;
			x->nextstate = R_XML_STATE_MISC1;
			return R_XML_OK;
		}
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_ELEM0;
			return xml_elemstart (x, ch);
		}
		break;
	case R_XML_STATE_le2:
		if (ch == (ut8)'!') {
			x->state = R_XML_STATE_LEE2;
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_PI0;
			x->nextstate = R_XML_STATE_MISC2;
			return R_XML_OK;
		}
		if (ch == (ut8)'/') {
			x->state = R_XML_STATE_ETAG0;
			return R_XML_OK;
		}
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_ELEM0;
			return xml_elemstart (x, ch);
		}
		break;
	case R_XML_STATE_le3:
		if (ch == (ut8)'!') {
			x->state = R_XML_STATE_COMMENT0;
			x->nextstate = R_XML_STATE_MISC3;
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_PI0;
			x->nextstate = R_XML_STATE_MISC3;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_LEE1:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT1;
			x->nextstate = R_XML_STATE_MISC1;
			return R_XML_OK;
		}
		if (ch == (ut8)'D') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_DT0;
			x->string = (ut8 *)"OCTYPE";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_LEE2:
		if (ch == (ut8)'-') {
			x->state = R_XML_STATE_COMMENT1;
			x->nextstate = R_XML_STATE_MISC2;
			return R_XML_OK;
		}
		if (ch == (ut8)'[') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_CD0;
			x->string = (ut8 *)"CDATA[";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_LEQ0:
		if (ch == (ut8)'x') {
			x->state = R_XML_STATE_XMLDECL0;
			x->nextstate = R_XML_STATE_MISC1;
			return r_xml_pistart (x, ch);
		}
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_PI1;
			x->nextstate = R_XML_STATE_MISC1;
			return r_xml_pistart (x, ch);
		}
		break;
	case R_XML_STATE_MISC0:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'<') {
			x->state = R_XML_STATE_le0;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_MISC1:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'<') {
			x->state = R_XML_STATE_le1;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_MISC2:
		if (ch == (ut8)'<') {
			x->state = R_XML_STATE_le2;
			return R_XML_OK;
		}
		if (ch == (ut8)'&') {
			x->state = R_XML_STATE_MISC2a;
			return r_xml_refstart (x, ch);
		}
		if (R_XML_IS_CHAR (ch)) {
			return r_xml_datacontent(x, ch);
		}
		break;
	case R_XML_STATE_MISC2a:
		if (R_XML_IS_REF (ch)) {
			return r_xml_ref(x, ch);
		}
		if (ch == (ut8)'\x3b') {
			x->state = R_XML_STATE_MISC2;
			return r_xml_refcontent(x, ch);
		}
		break;
	case R_XML_STATE_MISC3:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'<') {
			x->state = R_XML_STATE_le3;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_PI0:
		if (R_XML_IS_NAME_START (ch)) {
			x->state = R_XML_STATE_PI1;
			return r_xml_pistart (x, ch);
		}
		break;
	case R_XML_STATE_PI1:
		if (R_XML_IS_NAME (ch)) {
			return r_xml_piname (x, ch);
		}
		if (ch == (ut8)'?' || R_XML_IS_SP (ch)) {
			x->state = (ch == (ut8)'?')? R_XML_STATE_PI4: R_XML_STATE_PI2;
			return r_xml_pinameend (x, ch);
		}
		break;
	case R_XML_STATE_PI2:
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_PI3;
			return R_XML_OK;
		}
		if (R_XML_IS_CHAR (ch)) {
			return r_xml_datapi1 (x, ch);
		}
		break;
	case R_XML_STATE_PI3:
		if (ch == (ut8)'>') {
			x->state = x->nextstate;
			return r_xml_pivalend (x, ch);
		}
		if (R_XML_IS_CHAR (ch)) {
			x->state = R_XML_STATE_PI2;
			return r_xml_datapi2(x, ch);
		}
		break;
	case R_XML_STATE_PI4:
		if (ch == (ut8)'>') {
			x->state = x->nextstate;
			return r_xml_pivalend (x, ch);
		}
		break;
	case R_XML_STATE_STD0:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'=') {
			x->state = R_XML_STATE_STD1;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_STD1:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'\'' || ch == (ut8)'"') {
			x->state = R_XML_STATE_STD2;
			x->quote = ch;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_STD2:
		if (ch == (ut8)'y') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_STD3;
			x->string = (ut8 *)"es";
			return R_XML_OK;
		}
		if (ch == (ut8)'n') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_STD3;
			x->string = (ut8 *)"o";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_STD3:
		if (x->quote == ch) {
			x->state = R_XML_STATE_XMLDECL8;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_VER0:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'=') {
			x->state = R_XML_STATE_VER1;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_VER1:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'\'' || ch == (ut8)'"') {
			x->state = R_XML_STATE_STRING;
			x->quote = ch;
			x->nextstate = R_XML_STATE_VER2;
			x->string = (ut8 *)"1.";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_VER2:
		if (R_XML_IS_NUM(ch)) {
			x->state = R_XML_STATE_VER3;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_VER3:
		if (R_XML_IS_NUM (ch)) {
			return R_XML_OK;
		}
		if (x->quote == ch) {
			x->state = R_XML_STATE_XMLDECL4;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL0:
		if (ch == (ut8)'m') {
			x->state = R_XML_STATE_XMLDECL1;
			return r_xml_piname (x, ch);
		}
		if (R_XML_IS_NAME (ch)) {
			x->state = R_XML_STATE_PI1;
			return r_xml_piname (x, ch);
		}
		if (ch == (ut8)'?' || R_XML_IS_SP (ch)) {
			x->state = (ch == (ut8)'?')? R_XML_STATE_PI4: R_XML_STATE_PI2;
			return r_xml_pinameend (x, ch);
		}
		break;
	case R_XML_STATE_XMLDECL1:
		if (ch == (ut8)'l') {
			x->state = R_XML_STATE_XMLDECL2;
			return r_xml_piname (x, ch);
		}
		if (R_XML_IS_NAME (ch)) {
			x->state = R_XML_STATE_PI1;
			return r_xml_piname (x, ch);
		}
		if (ch == (ut8)'?' || R_XML_IS_SP (ch)) {
			x->state = (ch == (ut8)'?')? R_XML_STATE_PI4: R_XML_STATE_PI2;
			return r_xml_pinameend (x, ch);
		}
		break;
	case R_XML_STATE_XMLDECL2:
		if (R_XML_IS_SP (ch)) {
			x->state = R_XML_STATE_XMLDECL3;
			return r_xml_piabort (x, ch);
		}
		if (R_XML_IS_NAME (ch)) {
			x->state = R_XML_STATE_PI1;
			return r_xml_piname (x, ch);
		}
		break;
	case R_XML_STATE_XMLDECL3:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'v') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_VER0;
			x->string = (ut8 *)"ersion";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL4:
		if (R_XML_IS_SP (ch)) {
			x->state = R_XML_STATE_XMLDECL5;
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_XMLDECL9;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL5:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_XMLDECL9;
			return R_XML_OK;
		}
		if (ch == (ut8)'e') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_ENC0;
			x->string = (ut8 *)"ncoding";
			return R_XML_OK;
		}
		if (ch == (ut8)'s') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_STD0;
			x->string = (ut8 *)"tandalone";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL6:
		if (R_XML_IS_SP (ch)) {
			x->state = R_XML_STATE_XMLDECL7;
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_XMLDECL9;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL7:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_XMLDECL9;
			return R_XML_OK;
		}
		if (ch == (ut8)'s') {
			x->state = R_XML_STATE_STRING;
			x->nextstate = R_XML_STATE_STD0;
			x->string = (ut8 *)"tandalone";
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL8:
		if (R_XML_IS_SP (ch)) {
			return R_XML_OK;
		}
		if (ch == (ut8)'?') {
			x->state = R_XML_STATE_XMLDECL9;
			return R_XML_OK;
		}
		break;
	case R_XML_STATE_XMLDECL9:
		if (ch == (ut8)'>') {
			x->state = R_XML_STATE_MISC1;
			return R_XML_OK;
		}
		break;
	}
	return R_XML_ESYN;
}

R_API RXmlRet r_xml_eof(RXml *x) {
	return (x->state == R_XML_STATE_MISC3)? R_XML_OK: R_XML_EEOF;
}

R_API char *r_xml_indent(const char *s) {
	RStrBuf *sb = r_strbuf_new ("");
	int level = -1;
	bool open = false;
	bool klose = false;
	bool fin = false;
	const char *os = s;
	while (*s) {
		if (open) {
			if (*s == '>') {
				open = false;
				fin = true;
				level++;
			}
		} else {
			if (*s == '<') {
				if (s[1] == '/') {
					klose = true;
					level--;
				}
				open = true;
				size_t len = s - os;
				r_strbuf_append_n (sb, os, len);
				r_strbuf_append (sb, "\n");
				os = s;
			}
		}
		s = r_str_trim_head_ro (s + 1);
		if (fin) {
			size_t len = s - os;
			int i;
			for (i = 0; i < level; i++) {
				r_strbuf_append (sb, "  ");
			}
			r_strbuf_append_n (sb, os, len);
			r_strbuf_append (sb, "\n");
			if (klose) {
				klose = false;
				level --;
			}
			for (i = 0; i < level; i++) {
				r_strbuf_append (sb, "  ");
			}
			os = s;
			fin = false;
		}
	}
	return r_strbuf_drain (sb);
}
