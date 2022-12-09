#include "jsi.h"
#include "jslex.h"
#include "utf.h"

JS_NORETURN static void jsY_error(js_State *J, const char *fmt, ...) JS_PRINTFLIKE(2,3);

static void jsY_error(js_State *J, const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	char msgbuf[256];

	va_start(ap, fmt);
	vsnprintf(msgbuf, 256, fmt, ap);
	va_end(ap);

	snprintf(buf, 256, "%s:%d: ", J->filename, J->lexline);
	strcat(buf, msgbuf);

	js_newsyntaxerror(J, buf);
	js_throw(J);
}

static const char *tokenstring[] = {
	"(end-of-file)",
	"'\\x01'", "'\\x02'", "'\\x03'", "'\\x04'", "'\\x05'", "'\\x06'", "'\\x07'",
	"'\\x08'", "'\\x09'", "'\\x0A'", "'\\x0B'", "'\\x0C'", "'\\x0D'", "'\\x0E'", "'\\x0F'",
	"'\\x10'", "'\\x11'", "'\\x12'", "'\\x13'", "'\\x14'", "'\\x15'", "'\\x16'", "'\\x17'",
	"'\\x18'", "'\\x19'", "'\\x1A'", "'\\x1B'", "'\\x1C'", "'\\x1D'", "'\\x1E'", "'\\x1F'",
	"' '", "'!'", "'\"'", "'#'", "'$'", "'%'", "'&'", "'\\''",
	"'('", "')'", "'*'", "'+'", "','", "'-'", "'.'", "'/'",
	"'0'", "'1'", "'2'", "'3'", "'4'", "'5'", "'6'", "'7'",
	"'8'", "'9'", "':'", "';'", "'<'", "'='", "'>'", "'?'",
	"'@'", "'A'", "'B'", "'C'", "'D'", "'E'", "'F'", "'G'",
	"'H'", "'I'", "'J'", "'K'", "'L'", "'M'", "'N'", "'O'",
	"'P'", "'Q'", "'R'", "'S'", "'T'", "'U'", "'V'", "'W'",
	"'X'", "'Y'", "'Z'", "'['", "'\'", "']'", "'^'", "'_'",
	"'`'", "'a'", "'b'", "'c'", "'d'", "'e'", "'f'", "'g'",
	"'h'", "'i'", "'j'", "'k'", "'l'", "'m'", "'n'", "'o'",
	"'p'", "'q'", "'r'", "'s'", "'t'", "'u'", "'v'", "'w'",
	"'x'", "'y'", "'z'", "'{'", "'|'", "'}'", "'~'", "'\\x7F'",

	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,

	"(identifier)", "(number)", "(string)", "(regexp)",

	"'<='", "'>='", "'=='", "'!='", "'==='", "'!=='",
	"'<<'", "'>>'", "'>>>'", "'&&'", "'||'",
	"'+='", "'-='", "'*='", "'/='", "'%='",
	"'<<='", "'>>='", "'>>>='", "'&='", "'|='", "'^='",
	"'++'", "'--'",

	"'break'", "'case'", "'catch'", "'continue'", "'debugger'",
	"'default'", "'delete'", "'do'", "'else'", "'false'", "'finally'", "'for'",
	"'function'", "'if'", "'in'", "'instanceof'", "'new'", "'null'", "'return'",
	"'switch'", "'this'", "'throw'", "'true'", "'try'", "'typeof'", "'var'",
	"'void'", "'while'", "'with'",
};

const char *jsY_tokenstring(int token)
{
	if (token >= 0 && token < (int)nelem(tokenstring))
		if (tokenstring[token])
			return tokenstring[token];
	return "<unknown>";
}

static const char *keywords[] = {
	"break", "case", "catch", "continue", "debugger", "default", "delete",
	"do", "else", "false", "finally", "for", "function", "if", "in",
	"instanceof", "new", "null", "return", "switch", "this", "throw",
	"true", "try", "typeof", "var", "void", "while", "with",
};

int jsY_findword(const char *s, const char **list, int num)
{
	int l = 0;
	int r = num - 1;
	while (l <= r) {
		int m = (l + r) >> 1;
		int c = strcmp(s, list[m]);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return m;
	}
	return -1;
}

static int jsY_findkeyword(js_State *J, const char *s)
{
	int i = jsY_findword(s, keywords, nelem(keywords));
	if (i >= 0) {
		J->text = keywords[i];
		return TK_BREAK + i; /* first keyword + i */
	}
	J->text = js_intern(J, s);
	return TK_IDENTIFIER;
}

int jsY_iswhite(int c)
{
	return c == 0x9 || c == 0xB || c == 0xC || c == 0x20 || c == 0xA0 || c == 0xFEFF;
}

int jsY_isnewline(int c)
{
	return c == 0xA || c == 0xD || c == 0x2028 || c == 0x2029;
}

#ifndef isalpha
#define isalpha(c) ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
#endif
#ifndef isdigit
#define isdigit(c) (c >= '0' && c <= '9')
#endif
#ifndef ishex
#define ishex(c) ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
#endif

static int jsY_isidentifierstart(int c)
{
	return isalpha(c) || c == '$' || c == '_' || isalpharune(c);
}

static int jsY_isidentifierpart(int c)
{
	return isdigit(c) || isalpha(c) || c == '$' || c == '_' || isalpharune(c);
}

static int jsY_isdec(int c)
{
	return isdigit(c);
}

int jsY_ishex(int c)
{
	return isdigit(c) || ishex(c);
}

int jsY_tohex(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 0xA;
	if (c >= 'A' && c <= 'F') return c - 'A' + 0xA;
	return 0;
}

static void jsY_next(js_State *J)
{
	Rune c;
	if (*J->source == 0) {
		J->lexchar = EOF;
		return;
	}
	J->source += chartorune(&c, J->source);
	/* consume CR LF as one unit */
	if (c == '\r' && *J->source == '\n')
		++J->source;
	if (jsY_isnewline(c)) {
		J->line++;
		c = '\n';
	}
	J->lexchar = c;
}

#define jsY_accept(J, x) (J->lexchar == x ? (jsY_next(J), 1) : 0)

#define jsY_expect(J, x) if (!jsY_accept(J, x)) jsY_error(J, "expected '%c'", x)

static void jsY_unescape(js_State *J)
{
	if (jsY_accept(J, '\\')) {
		if (jsY_accept(J, 'u')) {
			int x = 0;
			if (!jsY_ishex(J->lexchar)) { goto error; } x |= jsY_tohex(J->lexchar) << 12; jsY_next(J);
			if (!jsY_ishex(J->lexchar)) { goto error; } x |= jsY_tohex(J->lexchar) << 8; jsY_next(J);
			if (!jsY_ishex(J->lexchar)) { goto error; } x |= jsY_tohex(J->lexchar) << 4; jsY_next(J);
			if (!jsY_ishex(J->lexchar)) { goto error; } x |= jsY_tohex(J->lexchar);
			J->lexchar = x;
			return;
		}
error:
		jsY_error(J, "unexpected escape sequence");
	}
}

static void textinit(js_State *J)
{
	if (!J->lexbuf.text) {
		J->lexbuf.cap = 4096;
		J->lexbuf.text = js_malloc(J, J->lexbuf.cap);
	}
	J->lexbuf.len = 0;
}

static void textpush(js_State *J, Rune c)
{
	int n;
	if (c == EOF)
		n = 1;
	else
		n = runelen(c);
	if (J->lexbuf.len + n > J->lexbuf.cap) {
		J->lexbuf.cap = J->lexbuf.cap * 2;
		J->lexbuf.text = js_realloc(J, J->lexbuf.text, J->lexbuf.cap);
	}
	if (c == EOF)
		J->lexbuf.text[J->lexbuf.len++] = 0;
	else
		J->lexbuf.len += runetochar(J->lexbuf.text + J->lexbuf.len, &c);
}

static char *textend(js_State *J)
{
	textpush(J, EOF);
	return J->lexbuf.text;
}

static void lexlinecomment(js_State *J)
{
	while (J->lexchar != EOF && J->lexchar != '\n')
		jsY_next(J);
}

static int lexcomment(js_State *J)
{
	/* already consumed initial '/' '*' sequence */
	while (J->lexchar != EOF) {
		if (jsY_accept(J, '*')) {
			while (J->lexchar == '*')
				jsY_next(J);
			if (jsY_accept(J, '/'))
				return 0;
		}
		else
			jsY_next(J);
	}
	return -1;
}

static double lexhex(js_State *J)
{
	double n = 0;
	if (!jsY_ishex(J->lexchar))
		jsY_error(J, "malformed hexadecimal number");
	while (jsY_ishex(J->lexchar)) {
		n = n * 16 + jsY_tohex(J->lexchar);
		jsY_next(J);
	}
	return n;
}

#if 0

static double lexinteger(js_State *J)
{
	double n = 0;
	if (!jsY_isdec(J->lexchar))
		jsY_error(J, "malformed number");
	while (jsY_isdec(J->lexchar)) {
		n = n * 10 + (J->lexchar - '0');
		jsY_next(J);
	}
	return n;
}

static double lexfraction(js_State *J)
{
	double n = 0;
	double d = 1;
	while (jsY_isdec(J->lexchar)) {
		n = n * 10 + (J->lexchar - '0');
		d = d * 10;
		jsY_next(J);
	}
	return n / d;
}

static double lexexponent(js_State *J)
{
	double sign;
	if (jsY_accept(J, 'e') || jsY_accept(J, 'E')) {
		if (jsY_accept(J, '-')) sign = -1;
		else if (jsY_accept(J, '+')) sign = 1;
		else sign = 1;
		return sign * lexinteger(J);
	}
	return 0;
}

static int lexnumber(js_State *J)
{
	double n;
	double e;

	if (jsY_accept(J, '0')) {
		if (jsY_accept(J, 'x') || jsY_accept(J, 'X')) {
			J->number = lexhex(J);
			return TK_NUMBER;
		}
		if (jsY_isdec(J->lexchar))
			jsY_error(J, "number with leading zero");
		n = 0;
		if (jsY_accept(J, '.'))
			n += lexfraction(J);
	} else if (jsY_accept(J, '.')) {
		if (!jsY_isdec(J->lexchar))
			return '.';
		n = lexfraction(J);
	} else {
		n = lexinteger(J);
		if (jsY_accept(J, '.'))
			n += lexfraction(J);
	}

	e = lexexponent(J);
	if (e < 0)
		n /= pow(10, -e);
	else if (e > 0)
		n *= pow(10, e);

	if (jsY_isidentifierstart(J->lexchar))
		jsY_error(J, "number with letter suffix");

	J->number = n;
	return TK_NUMBER;
}

#else

static int lexnumber(js_State *J)
{
	const char *s = J->source - 1;

	if (jsY_accept(J, '0')) {
		if (jsY_accept(J, 'x') || jsY_accept(J, 'X')) {
			J->number = lexhex(J);
			return TK_NUMBER;
		}
		if (jsY_isdec(J->lexchar))
			jsY_error(J, "number with leading zero");
		if (jsY_accept(J, '.')) {
			while (jsY_isdec(J->lexchar))
				jsY_next(J);
		}
	} else if (jsY_accept(J, '.')) {
		if (!jsY_isdec(J->lexchar))
			return '.';
		while (jsY_isdec(J->lexchar))
			jsY_next(J);
	} else {
		while (jsY_isdec(J->lexchar))
			jsY_next(J);
		if (jsY_accept(J, '.')) {
			while (jsY_isdec(J->lexchar))
				jsY_next(J);
		}
	}

	if (jsY_accept(J, 'e') || jsY_accept(J, 'E')) {
		if (J->lexchar == '-' || J->lexchar == '+')
			jsY_next(J);
		if (jsY_isdec(J->lexchar))
			while (jsY_isdec(J->lexchar))
				jsY_next(J);
		else
			jsY_error(J, "missing exponent");
	}

	if (jsY_isidentifierstart(J->lexchar))
		jsY_error(J, "number with letter suffix");

	J->number = js_strtod(s, NULL);
	return TK_NUMBER;
}

#endif

static int lexescape(js_State *J)
{
	int x = 0;

	/* already consumed '\' */

	if (jsY_accept(J, '\n'))
		return 0;

	switch (J->lexchar) {
	case EOF: jsY_error(J, "unterminated escape sequence");
	case 'u':
		jsY_next(J);
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 12; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 8; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 4; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar); jsY_next(J); }
		textpush(J, x);
		break;
	case 'x':
		jsY_next(J);
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 4; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar); jsY_next(J); }
		textpush(J, x);
		break;
	case '0': textpush(J, 0); jsY_next(J); break;
	case '\\': textpush(J, '\\'); jsY_next(J); break;
	case '\'': textpush(J, '\''); jsY_next(J); break;
	case '"': textpush(J, '"'); jsY_next(J); break;
	case 'b': textpush(J, '\b'); jsY_next(J); break;
	case 'f': textpush(J, '\f'); jsY_next(J); break;
	case 'n': textpush(J, '\n'); jsY_next(J); break;
	case 'r': textpush(J, '\r'); jsY_next(J); break;
	case 't': textpush(J, '\t'); jsY_next(J); break;
	case 'v': textpush(J, '\v'); jsY_next(J); break;
	default: textpush(J, J->lexchar); jsY_next(J); break;
	}
	return 0;
}

static int lexstring(js_State *J)
{
	const char *s;

	int q = J->lexchar;
	jsY_next(J);

	textinit(J);

	while (J->lexchar != q) {
		if (J->lexchar == EOF || J->lexchar == '\n')
			jsY_error(J, "string not terminated");
		if (jsY_accept(J, '\\')) {
			if (lexescape(J))
				jsY_error(J, "malformed escape sequence");
		} else {
			textpush(J, J->lexchar);
			jsY_next(J);
		}
	}
	jsY_expect(J, q);

	s = textend(J);

	J->text = js_intern(J, s);
	return TK_STRING;
}

/* the ugliest language wart ever... */
static int isregexpcontext(int last)
{
	switch (last) {
	case ']':
	case ')':
	case '}':
	case TK_IDENTIFIER:
	case TK_NUMBER:
	case TK_STRING:
	case TK_FALSE:
	case TK_NULL:
	case TK_THIS:
	case TK_TRUE:
		return 0;
	default:
		return 1;
	}
}

static int lexregexp(js_State *J)
{
	const char *s;
	int g, m, i;
	int inclass = 0;

	/* already consumed initial '/' */

	textinit(J);

	/* regexp body */
	while (J->lexchar != '/' || inclass) {
		if (J->lexchar == EOF || J->lexchar == '\n') {
			jsY_error(J, "regular expression not terminated");
		} else if (jsY_accept(J, '\\')) {
			if (jsY_accept(J, '/')) {
				textpush(J, '/');
			} else {
				textpush(J, '\\');
				if (J->lexchar == EOF || J->lexchar == '\n')
					jsY_error(J, "regular expression not terminated");
				textpush(J, J->lexchar);
				jsY_next(J);
			}
		} else {
			if (J->lexchar == '[' && !inclass)
				inclass = 1;
			if (J->lexchar == ']' && inclass)
				inclass = 0;
			textpush(J, J->lexchar);
			jsY_next(J);
		}
	}
	jsY_expect(J, '/');

	s = textend(J);

	/* regexp flags */
	g = i = m = 0;

	while (jsY_isidentifierpart(J->lexchar)) {
		if (jsY_accept(J, 'g')) ++g;
		else if (jsY_accept(J, 'i')) ++i;
		else if (jsY_accept(J, 'm')) ++m;
		else jsY_error(J, "illegal flag in regular expression: %c", J->lexchar);
	}

	if (g > 1 || i > 1 || m > 1)
		jsY_error(J, "duplicated flag in regular expression");

	J->text = js_intern(J, s);
	J->number = 0;
	if (g) J->number += JS_REGEXP_G;
	if (i) J->number += JS_REGEXP_I;
	if (m) J->number += JS_REGEXP_M;
	return TK_REGEXP;
}

/* simple "return [no Line Terminator here] ..." contexts */
static int isnlthcontext(int last)
{
	switch (last) {
	case TK_BREAK:
	case TK_CONTINUE:
	case TK_RETURN:
	case TK_THROW:
		return 1;
	default:
		return 0;
	}
}

static int jsY_lexx(js_State *J)
{
	J->newline = 0;

	while (1) {
		J->lexline = J->line; /* save location of beginning of token */

		while (jsY_iswhite(J->lexchar))
			jsY_next(J);

		if (jsY_accept(J, '\n')) {
			J->newline = 1;
			if (isnlthcontext(J->lasttoken))
				return ';';
			continue;
		}

		if (jsY_accept(J, '/')) {
			if (jsY_accept(J, '/')) {
				lexlinecomment(J);
				continue;
			} else if (jsY_accept(J, '*')) {
				if (lexcomment(J))
					jsY_error(J, "multi-line comment not terminated");
				continue;
			} else if (isregexpcontext(J->lasttoken)) {
				return lexregexp(J);
			} else if (jsY_accept(J, '=')) {
				return TK_DIV_ASS;
			} else {
				return '/';
			}
		}

		if (J->lexchar >= '0' && J->lexchar <= '9') {
			return lexnumber(J);
		}

		switch (J->lexchar) {
		case '(': jsY_next(J); return '(';
		case ')': jsY_next(J); return ')';
		case ',': jsY_next(J); return ',';
		case ':': jsY_next(J); return ':';
		case ';': jsY_next(J); return ';';
		case '?': jsY_next(J); return '?';
		case '[': jsY_next(J); return '[';
		case ']': jsY_next(J); return ']';
		case '{': jsY_next(J); return '{';
		case '}': jsY_next(J); return '}';
		case '~': jsY_next(J); return '~';

		case '\'':
		case '"':
			return lexstring(J);

		case '.':
			return lexnumber(J);

		case '<':
			jsY_next(J);
			if (jsY_accept(J, '<')) {
				if (jsY_accept(J, '='))
					return TK_SHL_ASS;
				return TK_SHL;
			}
			if (jsY_accept(J, '='))
				return TK_LE;
			return '<';

		case '>':
			jsY_next(J);
			if (jsY_accept(J, '>')) {
				if (jsY_accept(J, '>')) {
					if (jsY_accept(J, '='))
						return TK_USHR_ASS;
					return TK_USHR;
				}
				if (jsY_accept(J, '='))
					return TK_SHR_ASS;
				return TK_SHR;
			}
			if (jsY_accept(J, '='))
				return TK_GE;
			return '>';

		case '=':
			jsY_next(J);
			if (jsY_accept(J, '=')) {
				if (jsY_accept(J, '='))
					return TK_STRICTEQ;
				return TK_EQ;
			}
			return '=';

		case '!':
			jsY_next(J);
			if (jsY_accept(J, '=')) {
				if (jsY_accept(J, '='))
					return TK_STRICTNE;
				return TK_NE;
			}
			return '!';

		case '+':
			jsY_next(J);
			if (jsY_accept(J, '+'))
				return TK_INC;
			if (jsY_accept(J, '='))
				return TK_ADD_ASS;
			return '+';

		case '-':
			jsY_next(J);
			if (jsY_accept(J, '-'))
				return TK_DEC;
			if (jsY_accept(J, '='))
				return TK_SUB_ASS;
			return '-';

		case '*':
			jsY_next(J);
			if (jsY_accept(J, '='))
				return TK_MUL_ASS;
			return '*';

		case '%':
			jsY_next(J);
			if (jsY_accept(J, '='))
				return TK_MOD_ASS;
			return '%';

		case '&':
			jsY_next(J);
			if (jsY_accept(J, '&'))
				return TK_AND;
			if (jsY_accept(J, '='))
				return TK_AND_ASS;
			return '&';

		case '|':
			jsY_next(J);
			if (jsY_accept(J, '|'))
				return TK_OR;
			if (jsY_accept(J, '='))
				return TK_OR_ASS;
			return '|';

		case '^':
			jsY_next(J);
			if (jsY_accept(J, '='))
				return TK_XOR_ASS;
			return '^';

		case EOF:
			return 0; /* EOF */
		}

		/* Handle \uXXXX escapes in identifiers */
		jsY_unescape(J);
		if (jsY_isidentifierstart(J->lexchar)) {
			textinit(J);
			textpush(J, J->lexchar);

			jsY_next(J);
			jsY_unescape(J);
			while (jsY_isidentifierpart(J->lexchar)) {
				textpush(J, J->lexchar);
				jsY_next(J);
				jsY_unescape(J);
			}

			textend(J);

			return jsY_findkeyword(J, J->lexbuf.text);
		}

		if (J->lexchar >= 0x20 && J->lexchar <= 0x7E)
			jsY_error(J, "unexpected character: '%c'", J->lexchar);
		jsY_error(J, "unexpected character: \\u%04X", J->lexchar);
	}
}

void jsY_initlex(js_State *J, const char *filename, const char *source)
{
	J->filename = filename;
	J->source = source;
	J->line = 1;
	J->lasttoken = 0;
	jsY_next(J); /* load first lookahead character */
}

int jsY_lex(js_State *J)
{
	return J->lasttoken = jsY_lexx(J);
}

static int lexjsonnumber(js_State *J)
{
	const char *s = J->source - 1;

	if (J->lexchar == '-')
		jsY_next(J);

	if (J->lexchar == '0')
		jsY_next(J);
	else if (J->lexchar >= '1' && J->lexchar <= '9')
		while (isdigit(J->lexchar))
			jsY_next(J);
	else
		jsY_error(J, "unexpected non-digit");

	if (jsY_accept(J, '.')) {
		if (isdigit(J->lexchar))
			while (isdigit(J->lexchar))
				jsY_next(J);
		else
			jsY_error(J, "missing digits after decimal point");
	}

	if (jsY_accept(J, 'e') || jsY_accept(J, 'E')) {
		if (J->lexchar == '-' || J->lexchar == '+')
			jsY_next(J);
		if (isdigit(J->lexchar))
			while (isdigit(J->lexchar))
				jsY_next(J);
		else
			jsY_error(J, "missing digits after exponent indicator");
	}

	J->number = js_strtod(s, NULL);
	return TK_NUMBER;
}

static int lexjsonescape(js_State *J)
{
	int x = 0;

	/* already consumed '\' */

	switch (J->lexchar) {
	default: jsY_error(J, "invalid escape sequence");
	case 'u':
		jsY_next(J);
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 12; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 8; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar) << 4; jsY_next(J); }
		if (!jsY_ishex(J->lexchar)) return 1; else { x |= jsY_tohex(J->lexchar); jsY_next(J); }
		textpush(J, x);
		break;
	case '"': textpush(J, '"'); jsY_next(J); break;
	case '\\': textpush(J, '\\'); jsY_next(J); break;
	case '/': textpush(J, '/'); jsY_next(J); break;
	case 'b': textpush(J, '\b'); jsY_next(J); break;
	case 'f': textpush(J, '\f'); jsY_next(J); break;
	case 'n': textpush(J, '\n'); jsY_next(J); break;
	case 'r': textpush(J, '\r'); jsY_next(J); break;
	case 't': textpush(J, '\t'); jsY_next(J); break;
	}
	return 0;
}

static int lexjsonstring(js_State *J)
{
	const char *s;

	textinit(J);

	while (J->lexchar != '"') {
		if (J->lexchar == EOF)
			jsY_error(J, "unterminated string");
		else if (J->lexchar < 32)
			jsY_error(J, "invalid control character in string");
		else if (jsY_accept(J, '\\'))
			lexjsonescape(J);
		else {
			textpush(J, J->lexchar);
			jsY_next(J);
		}
	}
	jsY_expect(J, '"');

	s = textend(J);

	J->text = js_intern(J, s);
	return TK_STRING;
}

int jsY_lexjson(js_State *J)
{
	while (1) {
		J->lexline = J->line; /* save location of beginning of token */

		while (jsY_iswhite(J->lexchar) || J->lexchar == '\n')
			jsY_next(J);

		if ((J->lexchar >= '0' && J->lexchar <= '9') || J->lexchar == '-')
			return lexjsonnumber(J);

		switch (J->lexchar) {
		case ',': jsY_next(J); return ',';
		case ':': jsY_next(J); return ':';
		case '[': jsY_next(J); return '[';
		case ']': jsY_next(J); return ']';
		case '{': jsY_next(J); return '{';
		case '}': jsY_next(J); return '}';

		case '"':
			jsY_next(J);
			return lexjsonstring(J);

		case 'f':
			jsY_next(J); jsY_expect(J, 'a'); jsY_expect(J, 'l'); jsY_expect(J, 's'); jsY_expect(J, 'e');
			return TK_FALSE;

		case 'n':
			jsY_next(J); jsY_expect(J, 'u'); jsY_expect(J, 'l'); jsY_expect(J, 'l');
			return TK_NULL;

		case 't':
			jsY_next(J); jsY_expect(J, 'r'); jsY_expect(J, 'u'); jsY_expect(J, 'e');
			return TK_TRUE;

		case EOF:
			return 0; /* EOF */
		}

		if (J->lexchar >= 0x20 && J->lexchar <= 0x7E)
			jsY_error(J, "unexpected character: '%c'", J->lexchar);
		jsY_error(J, "unexpected character: \\u%04X", J->lexchar);
	}
}
