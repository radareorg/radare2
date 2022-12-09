#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <limits.h>

#include "regexp.h"
#include "utf.h"

#define emit regemit
#define next regnext
#define accept regaccept

#define nelem(a) (int)(sizeof (a) / sizeof (a)[0])

#define REPINF 255
#ifndef REG_MAXPROG
#define REG_MAXPROG (32 << 10)
#endif
#ifndef REG_MAXREC
#define REG_MAXREC 1024
#endif
#ifndef REG_MAXSPAN
#define REG_MAXSPAN 64
#endif
#ifndef REG_MAXCLASS
#define REG_MAXCLASS 16
#endif

typedef struct Reclass Reclass;
typedef struct Renode Renode;
typedef struct Reinst Reinst;
typedef struct Rethread Rethread;

struct Reclass {
	Rune *end;
	Rune spans[REG_MAXSPAN];
};

struct Reprog {
	Reinst *start, *end;
	int flags;
	int nsub;
	Reclass cclass[REG_MAXCLASS];
};

struct cstate {
	Reprog *prog;
	Renode *pstart, *pend;

	const char *source;
	int ncclass;
	int nsub;
	Renode *sub[REG_MAXSUB];

	int lookahead;
	Rune yychar;
	Reclass *yycc;
	int yymin, yymax;

	const char *error;
	jmp_buf kaboom;
};

static void die(struct cstate *g, const char *message)
{
	g->error = message;
	longjmp(g->kaboom, 1);
}

static int canon(Rune c)
{
	Rune u = toupperrune(c);
	if (c >= 128 && u < 128)
		return c;
	return u;
}

/* Scan */

enum {
	L_CHAR = 256,
	L_CCLASS,	/* character class */
	L_NCCLASS,	/* negative character class */
	L_NC,		/* "(?:" no capture */
	L_PLA,		/* "(?=" positive lookahead */
	L_NLA,		/* "(?!" negative lookahead */
	L_WORD,		/* "\b" word boundary */
	L_NWORD,	/* "\B" non-word boundary */
	L_REF,		/* "\1" back-reference */
	L_COUNT,	/* {M,N} */
};

static int hex(struct cstate *g, int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 0xA;
	if (c >= 'A' && c <= 'F') return c - 'A' + 0xA;
	die(g, "invalid escape sequence");
	return 0;
}

static int dec(struct cstate *g, int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	die(g, "invalid quantifier");
	return 0;
}

#define ESCAPES "BbDdSsWw^$\\.*+?()[]{}|-0123456789"

static int isunicodeletter(int c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || isalpharune(c);
}

static int nextrune(struct cstate *g)
{
	if (!*g->source) {
		g->yychar = EOF;
		return 0;
	}
	g->source += chartorune(&g->yychar, g->source);
	if (g->yychar == '\\') {
		if (!*g->source)
			die(g, "unterminated escape sequence");
		g->source += chartorune(&g->yychar, g->source);
		switch (g->yychar) {
		case 'f': g->yychar = '\f'; return 0;
		case 'n': g->yychar = '\n'; return 0;
		case 'r': g->yychar = '\r'; return 0;
		case 't': g->yychar = '\t'; return 0;
		case 'v': g->yychar = '\v'; return 0;
		case 'c':
			if (!g->source[0])
				die(g, "unterminated escape sequence");
			g->yychar = (*g->source++) & 31;
			return 0;
		case 'x':
			if (!g->source[0] || !g->source[1])
				die(g, "unterminated escape sequence");
			g->yychar = hex(g, *g->source++) << 4;
			g->yychar += hex(g, *g->source++);
			if (g->yychar == 0) {
				g->yychar = '0';
				return 1;
			}
			return 0;
		case 'u':
			if (!g->source[0] || !g->source[1] || !g->source[2] || !g->source[3])
				die(g, "unterminated escape sequence");
			g->yychar = hex(g, *g->source++) << 12;
			g->yychar += hex(g, *g->source++) << 8;
			g->yychar += hex(g, *g->source++) << 4;
			g->yychar += hex(g, *g->source++);
			if (g->yychar == 0) {
				g->yychar = '0';
				return 1;
			}
			return 0;
		case 0:
			g->yychar = '0';
			return 1;
		}
		if (strchr(ESCAPES, g->yychar))
			return 1;
		if (isunicodeletter(g->yychar) || g->yychar == '_') /* check identity escape */
			die(g, "invalid escape character");
		return 0;
	}
	return 0;
}

static int lexcount(struct cstate *g)
{
	g->yychar = *g->source++;

	g->yymin = dec(g, g->yychar);
	g->yychar = *g->source++;
	while (g->yychar != ',' && g->yychar != '}') {
		g->yymin = g->yymin * 10 + dec(g, g->yychar);
		g->yychar = *g->source++;
		if (g->yymin >= REPINF)
			die(g, "numeric overflow");
	}

	if (g->yychar == ',') {
		g->yychar = *g->source++;
		if (g->yychar == '}') {
			g->yymax = REPINF;
		} else {
			g->yymax = dec(g, g->yychar);
			g->yychar = *g->source++;
			while (g->yychar != '}') {
				g->yymax = g->yymax * 10 + dec(g, g->yychar);
				g->yychar = *g->source++;
				if (g->yymax >= REPINF)
					die(g, "numeric overflow");
			}
		}
	} else {
		g->yymax = g->yymin;
	}

	return L_COUNT;
}

static void newcclass(struct cstate *g)
{
	if (g->ncclass >= nelem(g->prog->cclass))
		die(g, "too many character classes");
	g->yycc = g->prog->cclass + g->ncclass++;
	g->yycc->end = g->yycc->spans;
}

static void addrange(struct cstate *g, Rune a, Rune b)
{
	if (a > b)
		die(g, "invalid character class range");
	if (g->yycc->end + 2 >= g->yycc->spans + nelem(g->yycc->spans))
		die(g, "too many character class ranges");
	*g->yycc->end++ = a;
	*g->yycc->end++ = b;
}

static void addranges_d(struct cstate *g)
{
	addrange(g, '0', '9');
}

static void addranges_D(struct cstate *g)
{
	addrange(g, 0, '0'-1);
	addrange(g, '9'+1, 0xFFFF);
}

static void addranges_s(struct cstate *g)
{
	addrange(g, 0x9, 0xD);
	addrange(g, 0x20, 0x20);
	addrange(g, 0xA0, 0xA0);
	addrange(g, 0x2028, 0x2029);
	addrange(g, 0xFEFF, 0xFEFF);
}

static void addranges_S(struct cstate *g)
{
	addrange(g, 0, 0x9-1);
	addrange(g, 0xD+1, 0x20-1);
	addrange(g, 0x20+1, 0xA0-1);
	addrange(g, 0xA0+1, 0x2028-1);
	addrange(g, 0x2029+1, 0xFEFF-1);
	addrange(g, 0xFEFF+1, 0xFFFF);
}

static void addranges_w(struct cstate *g)
{
	addrange(g, '0', '9');
	addrange(g, 'A', 'Z');
	addrange(g, '_', '_');
	addrange(g, 'a', 'z');
}

static void addranges_W(struct cstate *g)
{
	addrange(g, 0, '0'-1);
	addrange(g, '9'+1, 'A'-1);
	addrange(g, 'Z'+1, '_'-1);
	addrange(g, '_'+1, 'a'-1);
	addrange(g, 'z'+1, 0xFFFF);
}

static int lexclass(struct cstate *g)
{
	int type = L_CCLASS;
	int quoted, havesave, havedash;
	Rune save = 0;

	newcclass(g);

	quoted = nextrune(g);
	if (!quoted && g->yychar == '^') {
		type = L_NCCLASS;
		quoted = nextrune(g);
	}

	havesave = havedash = 0;
	for (;;) {
		if (g->yychar == EOF)
			die(g, "unterminated character class");
		if (!quoted && g->yychar == ']')
			break;

		if (!quoted && g->yychar == '-') {
			if (havesave) {
				if (havedash) {
					addrange(g, save, '-');
					havesave = havedash = 0;
				} else {
					havedash = 1;
				}
			} else {
				save = '-';
				havesave = 1;
			}
		} else if (quoted && strchr("DSWdsw", g->yychar)) {
			if (havesave) {
				addrange(g, save, save);
				if (havedash)
					addrange(g, '-', '-');
			}
			switch (g->yychar) {
			case 'd': addranges_d(g); break;
			case 's': addranges_s(g); break;
			case 'w': addranges_w(g); break;
			case 'D': addranges_D(g); break;
			case 'S': addranges_S(g); break;
			case 'W': addranges_W(g); break;
			}
			havesave = havedash = 0;
		} else {
			if (quoted) {
				if (g->yychar == 'b')
					g->yychar = '\b';
				else if (g->yychar == '0')
					g->yychar = 0;
				/* else identity escape */
			}
			if (havesave) {
				if (havedash) {
					addrange(g, save, g->yychar);
					havesave = havedash = 0;
				} else {
					addrange(g, save, save);
					save = g->yychar;
				}
			} else {
				save = g->yychar;
				havesave = 1;
			}
		}

		quoted = nextrune(g);
	}

	if (havesave) {
		addrange(g, save, save);
		if (havedash)
			addrange(g, '-', '-');
	}

	return type;
}

static int lex(struct cstate *g)
{
	int quoted = nextrune(g);
	if (quoted) {
		switch (g->yychar) {
		case 'b': return L_WORD;
		case 'B': return L_NWORD;
		case 'd': newcclass(g); addranges_d(g); return L_CCLASS;
		case 's': newcclass(g); addranges_s(g); return L_CCLASS;
		case 'w': newcclass(g); addranges_w(g); return L_CCLASS;
		case 'D': newcclass(g); addranges_d(g); return L_NCCLASS;
		case 'S': newcclass(g); addranges_s(g); return L_NCCLASS;
		case 'W': newcclass(g); addranges_w(g); return L_NCCLASS;
		case '0': g->yychar = 0; return L_CHAR;
		}
		if (g->yychar >= '0' && g->yychar <= '9') {
			g->yychar -= '0';
			if (*g->source >= '0' && *g->source <= '9')
				g->yychar = g->yychar * 10 + *g->source++ - '0';
			return L_REF;
		}
		return L_CHAR;
	}

	switch (g->yychar) {
	case EOF:
	case '$': case ')': case '*': case '+':
	case '.': case '?': case '^': case '|':
		return g->yychar;
	}

	if (g->yychar == '{')
		return lexcount(g);
	if (g->yychar == '[')
		return lexclass(g);
	if (g->yychar == '(') {
		if (g->source[0] == '?') {
			if (g->source[1] == ':') {
				g->source += 2;
				return L_NC;
			}
			if (g->source[1] == '=') {
				g->source += 2;
				return L_PLA;
			}
			if (g->source[1] == '!') {
				g->source += 2;
				return L_NLA;
			}
		}
		return '(';
	}

	return L_CHAR;
}

/* Parse */

enum {
	P_CAT, P_ALT, P_REP,
	P_BOL, P_EOL, P_WORD, P_NWORD,
	P_PAR, P_PLA, P_NLA,
	P_ANY, P_CHAR, P_CCLASS, P_NCCLASS,
	P_REF,
};

struct Renode {
	unsigned char type;
	unsigned char ng, m, n;
	Rune c;
	Reclass *cc;
	Renode *x;
	Renode *y;
};

static Renode *newnode(struct cstate *g, int type)
{
	Renode *node = g->pend++;
	node->type = type;
	node->cc = NULL;
	node->c = 0;
	node->ng = 0;
	node->m = 0;
	node->n = 0;
	node->x = node->y = NULL;
	return node;
}

static int empty(Renode *node)
{
	if (!node) return 1;
	switch (node->type) {
	default: return 1;
	case P_CAT: return empty(node->x) && empty(node->y);
	case P_ALT: return empty(node->x) || empty(node->y);
	case P_REP: return empty(node->x) || node->m == 0;
	case P_PAR: return empty(node->x);
	case P_REF: return empty(node->x);
	case P_ANY: case P_CHAR: case P_CCLASS: case P_NCCLASS: return 0;
	}
}

static Renode *newrep(struct cstate *g, Renode *atom, int ng, int min, int max)
{
	Renode *rep = newnode(g, P_REP);
	if (max == REPINF && empty(atom))
		die(g, "infinite loop matching the empty string");
	rep->ng = ng;
	rep->m = min;
	rep->n = max;
	rep->x = atom;
	return rep;
}

static void next(struct cstate *g)
{
	g->lookahead = lex(g);
}

static int accept(struct cstate *g, int t)
{
	if (g->lookahead == t) {
		next(g);
		return 1;
	}
	return 0;
}

static Renode *parsealt(struct cstate *g);

static Renode *parseatom(struct cstate *g)
{
	Renode *atom;
	if (g->lookahead == L_CHAR) {
		atom = newnode(g, P_CHAR);
		atom->c = g->yychar;
		next(g);
		return atom;
	}
	if (g->lookahead == L_CCLASS) {
		atom = newnode(g, P_CCLASS);
		atom->cc = g->yycc;
		next(g);
		return atom;
	}
	if (g->lookahead == L_NCCLASS) {
		atom = newnode(g, P_NCCLASS);
		atom->cc = g->yycc;
		next(g);
		return atom;
	}
	if (g->lookahead == L_REF) {
		atom = newnode(g, P_REF);
		if (g->yychar == 0 || g->yychar >= g->nsub || !g->sub[g->yychar])
			die(g, "invalid back-reference");
		atom->n = g->yychar;
		atom->x = g->sub[g->yychar];
		next(g);
		return atom;
	}
	if (accept(g, '.'))
		return newnode(g, P_ANY);
	if (accept(g, '(')) {
		atom = newnode(g, P_PAR);
		if (g->nsub == REG_MAXSUB)
			die(g, "too many captures");
		atom->n = g->nsub++;
		atom->x = parsealt(g);
		g->sub[atom->n] = atom;
		if (!accept(g, ')'))
			die(g, "unmatched '('");
		return atom;
	}
	if (accept(g, L_NC)) {
		atom = parsealt(g);
		if (!accept(g, ')'))
			die(g, "unmatched '('");
		return atom;
	}
	if (accept(g, L_PLA)) {
		atom = newnode(g, P_PLA);
		atom->x = parsealt(g);
		if (!accept(g, ')'))
			die(g, "unmatched '('");
		return atom;
	}
	if (accept(g, L_NLA)) {
		atom = newnode(g, P_NLA);
		atom->x = parsealt(g);
		if (!accept(g, ')'))
			die(g, "unmatched '('");
		return atom;
	}
	die(g, "syntax error");
	return NULL;
}

static Renode *parserep(struct cstate *g)
{
	Renode *atom;

	if (accept(g, '^')) return newnode(g, P_BOL);
	if (accept(g, '$')) return newnode(g, P_EOL);
	if (accept(g, L_WORD)) return newnode(g, P_WORD);
	if (accept(g, L_NWORD)) return newnode(g, P_NWORD);

	atom = parseatom(g);
	if (g->lookahead == L_COUNT) {
		int min = g->yymin, max = g->yymax;
		next(g);
		if (max < min)
			die(g, "invalid quantifier");
		return newrep(g, atom, accept(g, '?'), min, max);
	}
	if (accept(g, '*')) return newrep(g, atom, accept(g, '?'), 0, REPINF);
	if (accept(g, '+')) return newrep(g, atom, accept(g, '?'), 1, REPINF);
	if (accept(g, '?')) return newrep(g, atom, accept(g, '?'), 0, 1);
	return atom;
}

static Renode *parsecat(struct cstate *g)
{
	Renode *cat, *head, **tail;
	if (g->lookahead != EOF && g->lookahead != '|' && g->lookahead != ')') {
		/* Build a right-leaning tree by splicing in new 'cat' at the tail. */
		head = parserep(g);
		tail = &head;
		while (g->lookahead != EOF && g->lookahead != '|' && g->lookahead != ')') {
			cat = newnode(g, P_CAT);
			cat->x = *tail;
			cat->y = parserep(g);
			*tail = cat;
			tail = &cat->y;
		}
		return head;
	}
	return NULL;
}

static Renode *parsealt(struct cstate *g)
{
	Renode *alt, *x;
	alt = parsecat(g);
	while (accept(g, '|')) {
		x = alt;
		alt = newnode(g, P_ALT);
		alt->x = x;
		alt->y = parsecat(g);
	}
	return alt;
}

/* Compile */

enum {
	I_END, I_JUMP, I_SPLIT, I_PLA, I_NLA,
	I_ANYNL, I_ANY, I_CHAR, I_CCLASS, I_NCCLASS, I_REF,
	I_BOL, I_EOL, I_WORD, I_NWORD,
	I_LPAR, I_RPAR
};

struct Reinst {
	unsigned char opcode;
	unsigned char n;
	Rune c;
	Reclass *cc;
	Reinst *x;
	Reinst *y;
};

static int count(struct cstate *g, Renode *node, int depth)
{
	int min, max, n;
	if (!node) return 0;
	if (++depth > REG_MAXREC) die(g, "stack overflow");
	switch (node->type) {
	default: return 1;
	case P_CAT: return count(g, node->x, depth) + count(g, node->y, depth);
	case P_ALT: return count(g, node->x, depth) + count(g, node->y, depth) + 2;
	case P_REP:
		min = node->m;
		max = node->n;
		if (min == max) n = count(g, node->x, depth) * min;
		else if (max < REPINF) n = count(g, node->x, depth) * max + (max - min);
		else n = count(g, node->x, depth) * (min + 1) + 2;
		if (n < 0 || n > REG_MAXPROG) die(g, "program too large");
		return n;
	case P_PAR: return count(g, node->x, depth) + 2;
	case P_PLA: return count(g, node->x, depth) + 2;
	case P_NLA: return count(g, node->x, depth) + 2;
	}
}

static Reinst *emit(Reprog *prog, int opcode)
{
	Reinst *inst = prog->end++;
	inst->opcode = opcode;
	inst->n = 0;
	inst->c = 0;
	inst->cc = NULL;
	inst->x = inst->y = NULL;
	return inst;
}

static void compile(Reprog *prog, Renode *node)
{
	Reinst *inst, *split, *jump;
	int i;

loop:
	if (!node)
		return;

	switch (node->type) {
	case P_CAT:
		compile(prog, node->x);
		node = node->y;
		goto loop;

	case P_ALT:
		split = emit(prog, I_SPLIT);
		compile(prog, node->x);
		jump = emit(prog, I_JUMP);
		compile(prog, node->y);
		split->x = split + 1;
		split->y = jump + 1;
		jump->x = prog->end;
		break;

	case P_REP:
		inst = NULL; /* silence compiler warning. assert(node->m > 0). */
		for (i = 0; i < node->m; ++i) {
			inst = prog->end;
			compile(prog, node->x);
		}
		if (node->m == node->n)
			break;
		if (node->n < REPINF) {
			for (i = node->m; i < node->n; ++i) {
				split = emit(prog, I_SPLIT);
				compile(prog, node->x);
				if (node->ng) {
					split->y = split + 1;
					split->x = prog->end;
				} else {
					split->x = split + 1;
					split->y = prog->end;
				}
			}
		} else if (node->m == 0) {
			split = emit(prog, I_SPLIT);
			compile(prog, node->x);
			jump = emit(prog, I_JUMP);
			if (node->ng) {
				split->y = split + 1;
				split->x = prog->end;
			} else {
				split->x = split + 1;
				split->y = prog->end;
			}
			jump->x = split;
		} else {
			split = emit(prog, I_SPLIT);
			if (node->ng) {
				split->y = inst;
				split->x = prog->end;
			} else {
				split->x = inst;
				split->y = prog->end;
			}
		}
		break;

	case P_BOL: emit(prog, I_BOL); break;
	case P_EOL: emit(prog, I_EOL); break;
	case P_WORD: emit(prog, I_WORD); break;
	case P_NWORD: emit(prog, I_NWORD); break;

	case P_PAR:
		inst = emit(prog, I_LPAR);
		inst->n = node->n;
		compile(prog, node->x);
		inst = emit(prog, I_RPAR);
		inst->n = node->n;
		break;
	case P_PLA:
		split = emit(prog, I_PLA);
		compile(prog, node->x);
		emit(prog, I_END);
		split->x = split + 1;
		split->y = prog->end;
		break;
	case P_NLA:
		split = emit(prog, I_NLA);
		compile(prog, node->x);
		emit(prog, I_END);
		split->x = split + 1;
		split->y = prog->end;
		break;

	case P_ANY:
		emit(prog, I_ANY);
		break;
	case P_CHAR:
		inst = emit(prog, I_CHAR);
		inst->c = (prog->flags & REG_ICASE) ? canon(node->c) : node->c;
		break;
	case P_CCLASS:
		inst = emit(prog, I_CCLASS);
		inst->cc = node->cc;
		break;
	case P_NCCLASS:
		inst = emit(prog, I_NCCLASS);
		inst->cc = node->cc;
		break;
	case P_REF:
		inst = emit(prog, I_REF);
		inst->n = node->n;
		break;
	}
}

#ifdef TEST
static void dumpnode(Renode *node)
{
	Rune *p;
	if (!node) { printf("Empty"); return; }
	switch (node->type) {
	case P_CAT: printf("Cat("); dumpnode(node->x); printf(", "); dumpnode(node->y); printf(")"); break;
	case P_ALT: printf("Alt("); dumpnode(node->x); printf(", "); dumpnode(node->y); printf(")"); break;
	case P_REP:
		printf(node->ng ? "NgRep(%d,%d," : "Rep(%d,%d,", node->m, node->n);
		dumpnode(node->x);
		printf(")");
		break;
	case P_BOL: printf("Bol"); break;
	case P_EOL: printf("Eol"); break;
	case P_WORD: printf("Word"); break;
	case P_NWORD: printf("NotWord"); break;
	case P_PAR: printf("Par(%d,", node->n); dumpnode(node->x); printf(")"); break;
	case P_PLA: printf("PLA("); dumpnode(node->x); printf(")"); break;
	case P_NLA: printf("NLA("); dumpnode(node->x); printf(")"); break;
	case P_ANY: printf("Any"); break;
	case P_CHAR: printf("Char(%c)", node->c); break;
	case P_CCLASS:
		printf("Class(");
		for (p = node->cc->spans; p < node->cc->end; p += 2) printf("%02X-%02X,", p[0], p[1]);
		printf(")");
		break;
	case P_NCCLASS:
		printf("NotClass(");
		for (p = node->cc->spans; p < node->cc->end; p += 2) printf("%02X-%02X,", p[0], p[1]);
		printf(")");
		break;
	case P_REF: printf("Ref(%d)", node->n); break;
	}
}

static void dumpcclass(Reclass *cc) {
	Rune *p;
	for (p = cc->spans; p < cc->end; p += 2) {
		if (p[0] > 32 && p[0] < 127)
			printf(" %c", p[0]);
		else
			printf(" \\x%02x", p[0]);
		if (p[1] > 32 && p[1] < 127)
			printf("-%c", p[1]);
		else
			printf("-\\x%02x", p[1]);
	}
	putchar('\n');
}

static void dumpprog(Reprog *prog)
{
	Reinst *inst;
	int i;
	for (i = 0, inst = prog->start; inst < prog->end; ++i, ++inst) {
		printf("% 5d: ", i);
		switch (inst->opcode) {
		case I_END: puts("end"); break;
		case I_JUMP: printf("jump %d\n", (int)(inst->x - prog->start)); break;
		case I_SPLIT: printf("split %d %d\n", (int)(inst->x - prog->start), (int)(inst->y - prog->start)); break;
		case I_PLA: printf("pla %d %d\n", (int)(inst->x - prog->start), (int)(inst->y - prog->start)); break;
		case I_NLA: printf("nla %d %d\n", (int)(inst->x - prog->start), (int)(inst->y - prog->start)); break;
		case I_ANY: puts("any"); break;
		case I_ANYNL: puts("anynl"); break;
		case I_CHAR: printf(inst->c >= 32 && inst->c < 127 ? "char '%c'\n" : "char U+%04X\n", inst->c); break;
		case I_CCLASS: printf("cclass"); dumpcclass(inst->cc); break;
		case I_NCCLASS: printf("ncclass"); dumpcclass(inst->cc); break;
		case I_REF: printf("ref %d\n", inst->n); break;
		case I_BOL: puts("bol"); break;
		case I_EOL: puts("eol"); break;
		case I_WORD: puts("word"); break;
		case I_NWORD: puts("nword"); break;
		case I_LPAR: printf("lpar %d\n", inst->n); break;
		case I_RPAR: printf("rpar %d\n", inst->n); break;
		}
	}
}
#endif

Reprog *regcompx(void *(*alloc)(void *ctx, void *p, int n), void *ctx,
	const char *pattern, int cflags, const char **errorp)
{
	struct cstate g;
	Renode *node;
	Reinst *split, *jump;
	int i, n;

	g.pstart = NULL;
	g.prog = NULL;

	if (setjmp(g.kaboom)) {
		if (errorp) *errorp = g.error;
		alloc(ctx, g.pstart, 0);
		alloc(ctx, g.prog, 0);
		return NULL;
	}

	g.prog = alloc(ctx, NULL, sizeof (Reprog));
	if (!g.prog)
		die(&g, "cannot allocate regular expression");
	n = strlen(pattern) * 2;
	if (n > REG_MAXPROG)
		die(&g, "program too large");
	if (n > 0) {
		g.pstart = g.pend = alloc(ctx, NULL, sizeof (Renode) * n);
		if (!g.pstart)
			die(&g, "cannot allocate regular expression parse list");
	}

	g.source = pattern;
	g.ncclass = 0;
	g.nsub = 1;
	for (i = 0; i < REG_MAXSUB; ++i)
		g.sub[i] = 0;

	g.prog->flags = cflags;

	next(&g);
	node = parsealt(&g);
	if (g.lookahead == ')')
		die(&g, "unmatched ')'");
	if (g.lookahead != EOF)
		die(&g, "syntax error");

#ifdef TEST
	dumpnode(node);
	putchar('\n');
#endif

	n = 6 + count(&g, node, 0);
	if (n < 0 || n > REG_MAXPROG)
		die(&g, "program too large");

	g.prog->nsub = g.nsub;
	g.prog->start = g.prog->end = alloc(ctx, NULL, n * sizeof (Reinst));
	if (!g.prog->start)
		die(&g, "cannot allocate regular expression instruction list");

	split = emit(g.prog, I_SPLIT);
	split->x = split + 3;
	split->y = split + 1;
	emit(g.prog, I_ANYNL);
	jump = emit(g.prog, I_JUMP);
	jump->x = split;
	emit(g.prog, I_LPAR);
	compile(g.prog, node);
	emit(g.prog, I_RPAR);
	emit(g.prog, I_END);

#ifdef TEST
	dumpprog(g.prog);
#endif

	alloc(ctx, g.pstart, 0);

	if (errorp) *errorp = NULL;
	return g.prog;
}

void regfreex(void *(*alloc)(void *ctx, void *p, int n), void *ctx, Reprog *prog)
{
	if (prog) {
		alloc(ctx, prog->start, 0);
		alloc(ctx, prog, 0);
	}
}

static void *default_alloc(void *ctx, void *p, int n)
{
	if (n == 0) {
		free(p);
		return NULL;
	}
	return realloc(p, (size_t)n);
}

Reprog *regcomp(const char *pattern, int cflags, const char **errorp)
{
	return regcompx(default_alloc, NULL, pattern, cflags, errorp);
}

void regfree(Reprog *prog)
{
	regfreex(default_alloc, NULL, prog);
}

/* Match */

static int isnewline(int c)
{
	return c == 0xA || c == 0xD || c == 0x2028 || c == 0x2029;
}

static int iswordchar(int c)
{
	return c == '_' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9');
}

static int incclass(Reclass *cc, Rune c)
{
	Rune *p;
	for (p = cc->spans; p < cc->end; p += 2)
		if (p[0] <= c && c <= p[1])
			return 1;
	return 0;
}

static int incclasscanon(Reclass *cc, Rune c)
{
	Rune *p, r;
	for (p = cc->spans; p < cc->end; p += 2)
		for (r = p[0]; r <= p[1]; ++r)
			if (c == canon(r))
				return 1;
	return 0;
}

static int strncmpcanon(const char *a, const char *b, int n)
{
	Rune ra, rb;
	int c;
	while (n--) {
		if (!*a) return -1;
		if (!*b) return 1;
		a += chartorune(&ra, a);
		b += chartorune(&rb, b);
		c = canon(ra) - canon(rb);
		if (c)
			return c;
	}
	return 0;
}

static int match(Reinst *pc, const char *sp, const char *bol, int flags, Resub *out, int depth)
{
	Resub scratch;
	int result;
	int i;
	Rune c;

	/* stack overflow */
	if (depth > REG_MAXREC)
		return -1;

	for (;;) {
		switch (pc->opcode) {
		case I_END:
			return 0;
		case I_JUMP:
			pc = pc->x;
			break;
		case I_SPLIT:
			scratch = *out;
			result = match(pc->x, sp, bol, flags, &scratch, depth+1);
			if (result == -1)
				return -1;
			if (result == 0) {
				*out = scratch;
				return 0;
			}
			pc = pc->y;
			break;

		case I_PLA:
			result = match(pc->x, sp, bol, flags, out, depth+1);
			if (result == -1)
				return -1;
			if (result == 1)
				return 1;
			pc = pc->y;
			break;
		case I_NLA:
			scratch = *out;
			result = match(pc->x, sp, bol, flags, &scratch, depth+1);
			if (result == -1)
				return -1;
			if (result == 0)
				return 1;
			pc = pc->y;
			break;

		case I_ANYNL:
			if (!*sp) return 1;
			sp += chartorune(&c, sp);
			pc = pc + 1;
			break;
		case I_ANY:
			if (!*sp) return 1;
			sp += chartorune(&c, sp);
			if (isnewline(c))
				return 1;
			pc = pc + 1;
			break;
		case I_CHAR:
			if (!*sp) return 1;
			sp += chartorune(&c, sp);
			if (flags & REG_ICASE)
				c = canon(c);
			if (c != pc->c)
				return 1;
			pc = pc + 1;
			break;
		case I_CCLASS:
			if (!*sp) return 1;
			sp += chartorune(&c, sp);
			if (flags & REG_ICASE) {
				if (!incclasscanon(pc->cc, canon(c)))
					return 1;
			} else {
				if (!incclass(pc->cc, c))
					return 1;
			}
			pc = pc + 1;
			break;
		case I_NCCLASS:
			if (!*sp) return 1;
			sp += chartorune(&c, sp);
			if (flags & REG_ICASE) {
				if (incclasscanon(pc->cc, canon(c)))
					return 1;
			} else {
				if (incclass(pc->cc, c))
					return 1;
			}
			pc = pc + 1;
			break;
		case I_REF:
			i = out->sub[pc->n].ep - out->sub[pc->n].sp;
			if (flags & REG_ICASE) {
				if (strncmpcanon(sp, out->sub[pc->n].sp, i))
					return 1;
			} else {
				if (strncmp(sp, out->sub[pc->n].sp, i))
					return 1;
			}
			if (i > 0)
				sp += i;
			pc = pc + 1;
			break;

		case I_BOL:
			if (sp == bol && !(flags & REG_NOTBOL)) {
				pc = pc + 1;
				break;
			}
			if (flags & REG_NEWLINE) {
				if (sp > bol && isnewline(sp[-1])) {
					pc = pc + 1;
					break;
				}
			}
			return 1;
		case I_EOL:
			if (*sp == 0) {
				pc = pc + 1;
				break;
			}
			if (flags & REG_NEWLINE) {
				if (isnewline(*sp)) {
					pc = pc + 1;
					break;
				}
			}
			return 1;
		case I_WORD:
			i = sp > bol && iswordchar(sp[-1]);
			i ^= iswordchar(sp[0]);
			if (!i)
				return 1;
			pc = pc + 1;
			break;
		case I_NWORD:
			i = sp > bol && iswordchar(sp[-1]);
			i ^= iswordchar(sp[0]);
			if (i)
				return 1;
			pc = pc + 1;
			break;

		case I_LPAR:
			out->sub[pc->n].sp = sp;
			pc = pc + 1;
			break;
		case I_RPAR:
			out->sub[pc->n].ep = sp;
			pc = pc + 1;
			break;
		default:
			return 1;
		}
	}
}

int regexec(Reprog *prog, const char *sp, Resub *sub, int eflags)
{
	Resub scratch;
	int i;

	if (!sub)
		sub = &scratch;

	sub->nsub = prog->nsub;
	for (i = 0; i < REG_MAXSUB; ++i)
		sub->sub[i].sp = sub->sub[i].ep = NULL;

	return match(prog->start, sp, sp, prog->flags | eflags, sub, 0);
}

#ifdef TEST
int main(int argc, char **argv)
{
	const char *error;
	const char *s;
	Reprog *p;
	Resub m;
	int i;

	if (argc > 1) {
		p = regcomp(argv[1], 0, &error);
		if (!p) {
			fprintf(stderr, "regcomp: %s\n", error);
			return 1;
		}

		if (argc > 2) {
			s = argv[2];
			printf("nsub = %d\n", p->nsub);
			if (!regexec(p, s, &m, 0)) {
				for (i = 0; i < m.nsub; ++i) {
					int n = m.sub[i].ep - m.sub[i].sp;
					if (n > 0)
						printf("match %d: s=%d e=%d n=%d '%.*s'\n", i, (int)(m.sub[i].sp - s), (int)(m.sub[i].ep - s), n, n, m.sub[i].sp);
					else
						printf("match %d: n=0 ''\n", i);
				}
			} else {
				printf("no match\n");
			}
		}
	}

	return 0;
}
#endif
