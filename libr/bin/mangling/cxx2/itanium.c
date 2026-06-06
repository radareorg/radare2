// SPDX-FileCopyrightText: 2026 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT
//
// Itanium C++ ABI demangler.
//
// Two-pass design: parse the mangled string into a small AST (nodes are bump
// allocated and freed in one shot), then print the AST with a C-declarator
// model so that pointers, references, arrays and function types nest with the
// correct parenthesization. There is no global mutable state: everything the
// parser and printer need lives in the CTX structure passed around explicitly.

#include <r_util.h>
#include "cxx2.h"

#define MAX_DEPTH 256
#define MAX_NODES 200000

typedef enum {
	K_EMPTY = 0, // prints nothing
	K_NAME,      // s/len: literal identifier text
	K_NESTED,    // a "::" b
	K_TEMPLATE,  // a "<" b ">"  (b == K_LIST)
	K_LIST,      // kids[]: comma separated (template-args / call args)
	K_PARAMS,    // kids[]: function parameter types -> "(...)"
	K_CTOR,      // a == class prefix node
	K_DTOR,      // a == class prefix node
	K_OPERATOR,  // s: spelling after "operator"; num == arity
	K_CONV,      // "operator " + type(a)
	K_LITOP,     // user-defined literal operator: s == suffix
	K_BUILTIN,   // s: type spelling
	K_VENDORTY,  // s: vendor extended type (u<source-name>)
	K_PTR,       // a == pointee
	K_LREF,      // a
	K_RREF,      // a
	K_QUAL,      // flags == cv; a == inner type
	K_FUNC,      // a == ret (maybe NULL), b == K_PARAMS, flags == cv/ref
	K_ARRAY,     // a == elem; b == dim expr (maybe NULL); s/len == dim literal
	K_PTRMEM,    // a == class type, b == member type
	K_VEC,       // a == elem; b == size expr
	K_PACK,      // a == pattern (Dp <type>)
	K_TPARAM,    // a == resolved referenced node
	K_DECLTYPE,  // a == expr -> "decltype(expr)"
	K_SPECIAL,   // s == label prefix; a == target
	K_LOCAL,     // a == enclosing fn, b == entity -> "a::b"
	K_STRINGLIT, // "string literal"
	K_ABITAG,    // a == name, s == tag -> name[abi:tag]
	K_LITERAL,   // a == type, s/len == value; flags F_NEG
	K_EXPR_UNARY,
	K_EXPR_BINARY,
	K_EXPR_TRINARY,
	K_EXPR_CALL,
	K_EXPR_PAREN,
} Kind;

#define Q_CONST    (1 << 0)
#define Q_VOLATILE (1 << 1)
#define Q_RESTRICT (1 << 2)
#define REF_LV     (1 << 3)
#define REF_RV     (1 << 4)
#define F_NEG      (1 << 5)
#define F_POSTFIX  (1 << 6)
#define F_GLOBAL   (1 << 7) // ::operator name
#define F_LAMBDA   (1 << 8) // K_NAME holds a lambda closure (b == params, num == #)
#define F_UNNAMED  (1 << 9) // K_NAME holds an unnamed type (num == #)
#define F_PACKARG  (1 << 10) // K_LIST is a J...E template argument pack
#define F_NOEXCEPT (1 << 11) // K_FUNC type is noexcept

typedef struct node_t {
	ut16 kind;
	ut16 flags;
	const char *s; // borrowed slice into the mangled input, or a static literal
	int len;       // length of s (0 => use strlen)
	struct node_t *a, *b, *c;
	struct node_t **kids;
	int nkids;
	int num;
} Node;

typedef struct {
	const char *buf;
	const char *p;
	const char *end;
	bool fail;
	bool tagging; // true only while parsing the entity name (defines T_ scope)
	int depth;
	// arena of all allocated nodes (single bulk free)
	Node **all;
	int nall, capall;
	// substitution table (borrowed pointers into the arena)
	Node **subs;
	int nsubs, capsubs;
	// template-arg stack: the innermost active <template-args> list (for T_)
	Node **tpl;
	int ntpl;
} CTX;

// ---------------------------------------------------------------------------
// arena + small vectors
// ---------------------------------------------------------------------------

static Node *node_new(CTX *c, Kind k) {
	if (c->fail || c->nall >= MAX_NODES) {
		c->fail = true;
		return NULL;
	}
	Node *n = R_NEW0 (Node);
	if (!n) {
		c->fail = true;
		return NULL;
	}
	n->kind = k;
	if (c->nall == c->capall) {
		int ncap = c->capall ? c->capall * 2 : 64;
		Node **na = realloc (c->all, ncap * sizeof (Node *));
		if (!na) {
			free (n);
			c->fail = true;
			return NULL;
		}
		c->all = na;
		c->capall = ncap;
	}
	c->all[c->nall++] = n;
	return n;
}

static void node_push_kid(CTX *c, Node *list, Node *kid) {
	if (c->fail || !list || !kid) {
		return;
	}
	Node **nk = realloc (list->kids, (list->nkids + 1) * sizeof (Node *));
	if (!nk) {
		c->fail = true;
		return;
	}
	list->kids = nk;
	list->kids[list->nkids++] = kid;
}

static void sub_add(CTX *c, Node *n) {
	if (c->fail || !n) {
		return;
	}
	if (c->nsubs == c->capsubs) {
		int ncap = c->capsubs ? c->capsubs * 2 : 32;
		Node **ns = realloc (c->subs, ncap * sizeof (Node *));
		if (!ns) {
			c->fail = true;
			return;
		}
		c->subs = ns;
		c->capsubs = ncap;
	}
	c->subs[c->nsubs++] = n;
}

// ---------------------------------------------------------------------------
// cursor helpers
// ---------------------------------------------------------------------------

static inline char peek(CTX *c) {
	return (c->p < c->end) ? *c->p : 0;
}

static inline char peek2(CTX *c) {
	return (c->p + 1 < c->end) ? c->p[1] : 0;
}

static inline char take(CTX *c) {
	return (c->p < c->end) ? *c->p++ : 0;
}

static inline bool eat(CTX *c, char ch) {
	if (peek (c) == ch) {
		c->p++;
		return true;
	}
	return false;
}

// parse a non-negative decimal; returns -1 if no digit
static int parse_num(CTX *c) {
	if (!isdigit ((unsigned char)peek (c))) {
		return -1;
	}
	int n = 0;
	while (isdigit ((unsigned char)peek (c))) {
		if (n > (INT_MAX - 9) / 10) { // overflow guard
			c->fail = true;
			return -1;
		}
		n = n * 10 + (take (c) - '0');
	}
	return n;
}

// <seq-id> ::= <0-9A-Z>+ (base 36); returns value, advances. -1 on none.
static int parse_seqid(CTX *c) {
	int n = 0;
	bool any = false;
	while (true) {
		char ch = peek (c);
		int d;
		if (ch >= '0' && ch <= '9') {
			d = ch - '0';
		} else if (ch >= 'A' && ch <= 'Z') {
			d = ch - 'A' + 10;
		} else {
			break;
		}
		any = true;
		if (n > (INT_MAX - 36) / 36) { // overflow: index far beyond any real table
			c->fail = true;
			return -1;
		}
		n = n * 36 + d;
		c->p++;
	}
	return any ? n : -1;
}

// ---------------------------------------------------------------------------
// forward declarations
// ---------------------------------------------------------------------------

static Node *parse_type(CTX *c);
static Node *parse_name(CTX *c);
static Node *parse_unscoped(CTX *c, bool *is_sub);
static Node *parse_prefix(CTX *c);
static Node *parse_unqualified_name(CTX *c, Node *enclosing);
static Node *parse_template_args(CTX *c, bool tag);
static Node *parse_template_arg(CTX *c);
static Node *parse_template_param(CTX *c);
static Node *parse_expression(CTX *c);
static Node *parse_expr_primary(CTX *c);
static Node *parse_encoding(CTX *c, bool top);
static void emit_name(RStrBuf *o, Node *n, int depth);
static void emit_type(RStrBuf *o, Node *t, const char *inner, int depth);
static void emit_encoding(RStrBuf *o, Node *n, int depth);
static void emit_encoding_ex(RStrBuf *o, Node *n, int depth, bool with_ret);
static void emit_expr(RStrBuf *o, Node *n, int depth);

// quick constructors -------------------------------------------------------

static Node *mk_lit(CTX *c, Kind k, const char *lit) {
	Node *n = node_new (c, k);
	if (n) {
		n->s = lit;
		n->len = (int)strlen (lit);
	}
	return n;
}

static Node *mk1(CTX *c, Kind k, Node *a) {
	Node *n = node_new (c, k);
	if (n) {
		n->a = a;
	}
	return n;
}

static Node *mk2(CTX *c, Kind k, Node *a, Node *b) {
	Node *n = node_new (c, k);
	if (n) {
		n->a = a;
		n->b = b;
	}
	return n;
}

// ---------------------------------------------------------------------------
// substitutions
// ---------------------------------------------------------------------------

typedef struct {
	char code;
	const char *expansion;
} StdSub;

// Short display forms, matching the GNU demangler's default (non-verbose)
// output. Constructor/destructor names use distinct forms (see emit_basename).
static const StdSub std_subs[] = {
	{ 't', "std" },
	{ 'a', "std::allocator" },
	{ 'b', "std::basic_string" },
	{ 's', "std::string" },
	{ 'i', "std::istream" },
	{ 'o', "std::ostream" },
	{ 'd', "std::iostream" },
	{ 0, NULL }
};

// <substitution> ::= S <seq-id> _ | S_ | St | Sa | ...
static Node *parse_substitution(CTX *c) {
	if (!eat (c, 'S')) {
		return NULL;
	}
	char ch = peek (c);
	// standard abbreviations
	int i;
	for (i = 0; std_subs[i].expansion; i++) {
		if (ch == std_subs[i].code) {
			c->p++;
			Node *n = mk_lit (c, K_NAME, std_subs[i].expansion);
			if (n && std_subs[i].code != 't') {
				// the longer std::X abbreviations are also "std-qualified"
				n->flags |= F_GLOBAL; // marks "already fully qualified"
			}
			return n;
		}
	}
	// S_ or S<seq-id>_
	int idx = 0;
	if (eat (c, '_')) {
		idx = 0;
	} else {
		int seq = parse_seqid (c);
		if (seq < 0 || !eat (c, '_')) {
			c->fail = true;
			return NULL;
		}
		idx = seq + 1;
	}
	if (idx < 0 || idx >= c->nsubs) {
		c->fail = true;
		return NULL;
	}
	return c->subs[idx];
}

// ---------------------------------------------------------------------------
// names
// ---------------------------------------------------------------------------

// <source-name> ::= <number> <identifier>
static Node *parse_source_name(CTX *c) {
	int n = parse_num (c);
	if (n <= 0) {
		c->fail = true;
		return NULL;
	}
	if (c->p + n > c->end) {
		c->fail = true;
		return NULL;
	}
	Node *node = node_new (c, K_NAME);
	if (node) {
		node->s = c->p;
		node->len = n;
	}
	c->p += n;
	return node;
}

typedef struct {
	const char *code;
	const char *name;
	int arity;
} OpInfo;

static const OpInfo operators[] = {
	{ "nw", " new", 1 }, { "na", " new[]", 1 },
	{ "dl", " delete", 1 }, { "da", " delete[]", 1 },
	{ "aw", " co_await", 1 },
	{ "ps", "+", 1 }, { "ng", "-", 1 }, { "ad", "&", 1 }, { "de", "*", 1 },
	{ "co", "~", 1 },
	{ "pl", "+", 2 }, { "mi", "-", 2 }, { "ml", "*", 2 }, { "dv", "/", 2 },
	{ "rm", "%", 2 }, { "an", "&", 2 }, { "or", "|", 2 }, { "eo", "^", 2 },
	{ "aS", "=", 2 }, { "pL", "+=", 2 }, { "mI", "-=", 2 }, { "mL", "*=", 2 },
	{ "dV", "/=", 2 }, { "rM", "%=", 2 }, { "aN", "&=", 2 }, { "oR", "|=", 2 },
	{ "eO", "^=", 2 }, { "ls", "<<", 2 }, { "rs", ">>", 2 }, { "lS", "<<=", 2 },
	{ "rS", ">>=", 2 }, { "eq", "==", 2 }, { "ne", "!=", 2 }, { "lt", "<", 2 },
	{ "gt", ">", 2 }, { "le", "<=", 2 }, { "ge", ">=", 2 }, { "ss", "<=>", 2 },
	{ "nt", "!", 1 }, { "aa", "&&", 2 }, { "oo", "||", 2 }, { "pp", "++", 1 },
	{ "mm", "--", 1 }, { "cm", ",", 2 }, { "pm", "->*", 2 }, { "pt", "->", 2 },
	{ "cl", "()", 0 }, { "ix", "[]", 2 }, { "qu", "?", 3 },
	{ NULL, NULL, 0 }
};

// <operator-name>
static Node *parse_operator_name(CTX *c) {
	char a = peek (c), b = peek2 (c);
	// conversion operator: cv <type>
	if (a == 'c' && b == 'v') {
		c->p += 2;
		Node *t = parse_type (c);
		return mk1 (c, K_CONV, t);
	}
	// literal operator: li <source-name>
	if (a == 'l' && b == 'i') {
		c->p += 2;
		Node *nm = parse_source_name (c);
		Node *n = node_new (c, K_LITOP);
		if (n && nm) {
			n->s = nm->s;
			n->len = nm->len;
		}
		return n;
	}
	// vendor extended operator: v <digit> <source-name>
	if (a == 'v' && isdigit ((unsigned char)b)) {
		c->p += 2;
		Node *nm = parse_source_name (c);
		return nm;
	}
	int i;
	for (i = 0; operators[i].code; i++) {
		if (a == operators[i].code[0] && b == operators[i].code[1]) {
			c->p += 2;
			Node *n = node_new (c, K_OPERATOR);
			if (n) {
				n->s = operators[i].name;
				n->len = (int)strlen (operators[i].name);
				n->num = operators[i].arity;
			}
			return n;
		}
	}
	c->fail = true;
	return NULL;
}

// <ctor-dtor-name>
static Node *parse_ctor_dtor(CTX *c, Node *enclosing) {
	char a = peek (c);
	if (a == 'C') {
		char b = peek2 (c);
		if (b == '1' || b == '2' || b == '3' || b == '4' || b == '5') {
			c->p += 2;
			Node *n = mk1 (c, K_CTOR, enclosing);
			if (n) {
				n->num = b - '0';
			}
			return n;
		}
		if (b == 'I') { // inheriting constructor: CI <type>
			c->p += 2;
			Node *base = parse_type (c);
			Node *n = mk1 (c, K_CTOR, enclosing);
			(void)base;
			return n;
		}
	} else if (a == 'D') {
		char b = peek2 (c);
		if (b == '0' || b == '1' || b == '2' || b == '4' || b == '5') {
			c->p += 2;
			Node *n = mk1 (c, K_DTOR, enclosing);
			if (n) {
				n->num = b - '0';
			}
			return n;
		}
	}
	c->fail = true;
	return NULL;
}

// abi-tags: ( B <source-name> )*  attached to an unqualified-name
static Node *maybe_abi_tags(CTX *c, Node *n) {
	while (peek (c) == 'B') {
		c->p++;
		Node *tag = parse_source_name (c);
		if (c->fail) {
			return n;
		}
		Node *w = node_new (c, K_ABITAG);
		if (w && tag) {
			w->a = n;
			w->s = tag->s;
			w->len = tag->len;
			n = w;
		}
	}
	return n;
}

// <unqualified-name>
static Node *parse_unqualified_name(CTX *c, Node *enclosing) {
	char ch = peek (c);
	Node *n = NULL;
	if (isdigit ((unsigned char)ch)) {
		n = parse_source_name (c);
	} else if (ch == 'C' || ch == 'D') {
		n = parse_ctor_dtor (c, enclosing);
		return n; // ctor/dtor take no abi-tags here
	} else if (ch == 'U') {
		// unnamed type: Ut [<number>] _   or   Ul <lambda-sig> E [<number>] _
		if (peek2 (c) == 't') {
			c->p += 2;
			int idx = parse_num (c); // -1 if absent
			(void)eat (c, '_');
			Node *u = node_new (c, K_NAME);
			if (u) {
				u->flags |= F_UNNAMED;
				u->num = (idx < 0) ? 1 : idx + 2;
			}
			n = u;
		} else if (peek2 (c) == 'l') {
			// lambda closure: Ul <lambda-sig> E [<number>] _
			// A generic lambda introduces its own template params for its auto
			// parameters; clear the scope so T_ prints as "auto:N", not the
			// enclosing template's argument.
			c->p += 2;
			Node **saved_tpl = c->tpl;
			int saved_ntpl = c->ntpl;
			c->tpl = NULL;
			c->ntpl = 0;
			Node *params = node_new (c, K_PARAMS);
			while (peek (c) && peek (c) != 'E') {
				Node *t = parse_type (c);
				if (c->fail) {
					break;
				}
				node_push_kid (c, params, t);
			}
			c->tpl = saved_tpl;
			c->ntpl = saved_ntpl;
			(void)eat (c, 'E');
			int idx = parse_num (c); // -1 if absent
			(void)eat (c, '_');
			Node *lam = node_new (c, K_NAME);
			if (lam) {
				lam->flags |= F_LAMBDA;
				lam->b = params;
				lam->num = (idx < 0) ? 1 : idx + 2;
			}
			n = lam;
		} else {
			c->fail = true;
			return NULL;
		}
	} else if (ch == 'L') {
		// local-source-name: L <source-name> [<discriminator>]
		c->p++;
		n = parse_source_name (c);
	} else {
		n = parse_operator_name (c);
	}
	if (c->fail) {
		return NULL;
	}
	return maybe_abi_tags (c, n);
}

// Build a nested qualified node a::b, propagating "fully-qualified" flag.
static Node *qualify(CTX *c, Node *a, Node *b) {
	if (!a) {
		return b;
	}
	return mk2 (c, K_NESTED, a, b);
}

// strip a class node down to its simple name (for ctor/dtor printing)
static Node *simple_name_of(Node *n) {
	int guard = 0;
	while (n && guard++ < 64) {
		if (n->kind == K_NESTED) {
			n = n->b;
		} else if (n->kind == K_TEMPLATE) {
			n = n->a;
		} else if (n->kind == K_ABITAG) {
			n = n->a;
		} else {
			break;
		}
	}
	return n;
}

// <prefix> / <template-prefix>: builds up a qualified name component by
// component. Every component is registered as a substitution candidate; the
// caller (parse_nested_name) pops the final one, since the full nested-name
// entity is not itself a candidate. Mirrors LLVM's parseNestedName.
static Node *parse_prefix(CTX *c) {
	if (c->fail || c->depth > MAX_DEPTH) {
		c->fail = true;
		return NULL;
	}
	Node *cur = NULL;
	while (!c->fail) {
		char ch = peek (c);
		if (ch == 'E' || ch == 0) {
			break;
		}
		if (ch == 'T') {
			// <template-param> — only valid as the first component
			if (cur) {
				c->fail = true;
				break;
			}
			cur = parse_template_param (c);
		} else if (ch == 'I') {
			// <template-prefix> <template-args> — needs a prefix
			if (!cur || cur->kind == K_TEMPLATE) {
				c->fail = true;
				break;
			}
			Node *args = parse_template_args (c, c->tagging);
			if (c->fail) {
				break;
			}
			cur = mk2 (c, K_TEMPLATE, cur, args);
		} else if (ch == 'D' && (peek2 (c) == 't' || peek2 (c) == 'T')) {
			// <decltype> — only valid as the first component
			if (cur) {
				c->fail = true;
				break;
			}
			cur = parse_type (c); // decltype path already registers a sub
			continue;
		} else if (ch == 'S') {
			// <substitution> or St — only as the first component, not pushed
			if (cur) {
				c->fail = true;
				break;
			}
			if (peek2 (c) == 't') {
				c->p += 2;
				cur = mk_lit (c, K_NAME, "std");
			} else {
				cur = parse_substitution (c);
			}
			continue; // do not push a fresh substitution
		} else {
			// [<prefix>] <unqualified-name>
			Node *u = parse_unqualified_name (c, cur);
			if (c->fail) {
				break;
			}
			cur = cur ? qualify (c, cur, u) : u;
		}
		if (c->fail || !cur) {
			break;
		}
		sub_add (c, cur);
		(void)eat (c, 'M'); // data-member-prefix terminator (unused output)
	}
	return cur;
}

// <nested-name> ::= N [CV] [refq] <prefix> E
static Node *parse_nested_name(CTX *c) {
	if (!eat (c, 'N')) {
		c->fail = true;
		return NULL;
	}
	ut16 cv = 0, refq = 0;
	// CV-qualifiers
	for (;;) {
		char ch = peek (c);
		if (ch == 'r') { cv |= Q_RESTRICT; c->p++; }
		else if (ch == 'V') { cv |= Q_VOLATILE; c->p++; }
		else if (ch == 'K') { cv |= Q_CONST; c->p++; }
		else break;
	}
	if (eat (c, 'R')) {
		refq = REF_LV;
	} else if (eat (c, 'O')) {
		refq = REF_RV;
	}
	c->depth++;
	Node *pfx = parse_prefix (c);
	c->depth--;
	if (!eat (c, 'E')) {
		c->fail = true;
		return NULL;
	}
	// the full nested-name entity is not itself a substitution candidate
	if (c->nsubs > 0) {
		c->nsubs--;
	}
	if (pfx) {
		pfx->flags |= cv | refq;
	}
	return pfx;
}

// <local-name> ::= Z <encoding> E <name> [<discriminator>]
//              ::= Z <encoding> E s [<discriminator>]
static Node *parse_local_name(CTX *c) {
	if (!eat (c, 'Z')) {
		c->fail = true;
		return NULL;
	}
	Node *fn = parse_encoding (c, false);
	if (!eat (c, 'E')) {
		c->fail = true;
		return NULL;
	}
	Node *entity;
	int defarg = 0;
	if (eat (c, 's')) {
		entity = mk_lit (c, K_STRINGLIT, "string literal");
	} else {
		if (eat (c, 'd')) {
			// Z <enc> E d [<number>] _ <entity>  (default argument scope)
			int num = parse_num (c);
			(void)eat (c, '_');
			defarg = (num < 0) ? 1 : num + 2;
		}
		// the entity may itself be a function (e.g. a lambda's operator())
		entity = parse_encoding (c, false);
	}
	// optional discriminator
	if (peek (c) == '_') {
		c->p++;
		if (peek (c) == '_') {
			c->p++;
			(void)parse_num (c);
			(void)eat (c, '_');
		} else {
			(void)parse_num (c);
		}
	}
	Node *loc = mk2 (c, K_LOCAL, fn, entity);
	if (loc) {
		loc->num = defarg; // 0 = none, else {default arg#defarg}
	}
	return loc;
}

// Parses the base of a <name>/<class-enum-type>: a substitution, a std::-
// prefixed unqualified-name (St <unqualified-name>), or a plain unscoped-name.
// The trailing optional <template-args> and substitution bookkeeping are the
// caller's responsibility. *is_sub is set when the result is a bare
// substitution (which must not be re-added to the substitution table).
static Node *parse_unscoped(CTX *c, bool *is_sub) {
	if (is_sub) {
		*is_sub = false;
	}
	char ch = peek (c);
	if (ch == 'S') {
		if (peek2 (c) == 't') {
			// St <unqualified-name>  =>  std::name   (or bare "std")
			c->p += 2;
			Node *std = mk_lit (c, K_NAME, "std");
			char n = peek (c);
			if (n == 0 || n == 'I' || n == 'E' || n == '.') {
				if (is_sub) {
					*is_sub = true;
				}
				return std;
			}
			Node *u = parse_unqualified_name (c, std);
			return qualify (c, std, u);
		}
		if (is_sub) {
			*is_sub = true;
		}
		return parse_substitution (c);
	}
	return parse_unqualified_name (c, NULL);
}

// <name>
static Node *parse_name(CTX *c) {
	if (c->fail || c->depth > MAX_DEPTH) {
		c->fail = true;
		return NULL;
	}
	char ch = peek (c);
	if (ch == 'N') {
		return parse_nested_name (c);
	}
	if (ch == 'Z') {
		return parse_local_name (c);
	}
	if (ch == 'D' && (peek2 (c) == 't' || peek2 (c) == 'T')) {
		return parse_type (c); // decltype used as a name
	}
	Node *base = parse_unscoped (c, NULL);
	if (c->fail) {
		return NULL;
	}
	// <unscoped-template-name> <template-args>
	if (peek (c) == 'I') {
		sub_add (c, base); // the template-name becomes a substitution
		Node *args = parse_template_args (c, c->tagging);
		return mk2 (c, K_TEMPLATE, base, args);
	}
	return base;
}

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

static const char *builtin_type(char ch) {
	switch (ch) {
	case 'v': return "void";
	case 'w': return "wchar_t";
	case 'b': return "bool";
	case 'c': return "char";
	case 'a': return "signed char";
	case 'h': return "unsigned char";
	case 's': return "short";
	case 't': return "unsigned short";
	case 'i': return "int";
	case 'j': return "unsigned int";
	case 'l': return "long";
	case 'm': return "unsigned long";
	case 'x': return "long long";
	case 'y': return "unsigned long long";
	case 'n': return "__int128";
	case 'o': return "unsigned __int128";
	case 'f': return "float";
	case 'd': return "double";
	case 'e': return "long double";
	case 'g': return "__float128";
	case 'z': return "...";
	}
	return NULL;
}

// builtin types that start with 'D'
static const char *builtin_type_D(char ch) {
	switch (ch) {
	case 'd': return "decimal64";
	case 'e': return "decimal128";
	case 'f': return "decimal32";
	case 'h': return "half";
	case 'F': return "_Float"; // DF<n>_ handled specially
	case 'i': return "char32_t";
	case 's': return "char16_t";
	case 'u': return "char8_t";
	case 'a': return "auto";
	case 'c': return "decltype(auto)";
	case 'n': return "decltype(nullptr)";
	}
	return NULL;
}

// <function-type> ::= [CV] [Dx] F [Y] <bare-function-type> [refq] E
static Node *parse_function_type(CTX *c) {
	ut16 cv = 0;
	for (;;) {
		char ch = peek (c);
		if (ch == 'r') { cv |= Q_RESTRICT; c->p++; }
		else if (ch == 'V') { cv |= Q_VOLATILE; c->p++; }
		else if (ch == 'K') { cv |= Q_CONST; c->p++; }
		else break;
	}
	// exception specification: Do (noexcept), DO <expr> E (computed noexcept),
	// Dw <type>* E (dynamic). Dx is a transaction-safe marker.
	ut16 noex = 0;
	if (peek (c) == 'D') {
		char d = peek2 (c);
		if (d == 'o') {
			c->p += 2;
			noex = F_NOEXCEPT;
		} else if (d == 'O') {
			c->p += 2;
			(void)parse_expression (c);
			(void)eat (c, 'E');
			noex = F_NOEXCEPT;
		} else if (d == 'w') {
			c->p += 2;
			while (peek (c) && peek (c) != 'E') {
				(void)parse_type (c);
			}
			(void)eat (c, 'E');
		} else if (d == 'x') {
			c->p += 2;
		}
	}
	if (!eat (c, 'F')) {
		c->fail = true;
		return NULL;
	}
	(void)eat (c, 'Y'); // extern "C"
	Node *ret = parse_type (c);
	Node *params = node_new (c, K_PARAMS);
	while (peek (c) && peek (c) != 'E') {
		char ch = peek (c);
		if (ch == 'R' && (peek2 (c) == 'E')) { // ref-qualifier at the end
			break;
		}
		if (ch == 'O' && (peek2 (c) == 'E')) {
			break;
		}
		Node *t = parse_type (c);
		if (c->fail) {
			return NULL;
		}
		node_push_kid (c, params, t);
	}
	ut16 refq = 0;
	if (eat (c, 'R')) {
		refq = REF_LV;
	} else if (eat (c, 'O')) {
		refq = REF_RV;
	}
	if (!eat (c, 'E')) {
		c->fail = true;
		return NULL;
	}
	Node *fn = node_new (c, K_FUNC);
	if (fn) {
		fn->a = ret;
		fn->b = params;
		fn->flags = cv | refq | noex;
	}
	return fn;
}

// <array-type> ::= A <number> _ <type> | A [<expr>] _ <type>
static Node *parse_array_type(CTX *c) {
	if (!eat (c, 'A')) {
		c->fail = true;
		return NULL;
	}
	Node *arr = node_new (c, K_ARRAY);
	if (isdigit ((unsigned char)peek (c))) {
		const char *start = c->p;
		(void)parse_num (c);
		if (arr) {
			arr->s = start;
			arr->len = (int)(c->p - start);
		}
	} else if (peek (c) != '_') {
		Node *e = parse_expression (c);
		if (arr) {
			arr->b = e;
		}
	}
	if (!eat (c, '_')) {
		c->fail = true;
		return NULL;
	}
	Node *elem = parse_type (c);
	if (arr) {
		arr->a = elem;
	}
	return arr;
}

// <pointer-to-member-type> ::= M <class type> <member type>
static Node *parse_ptr_to_member(CTX *c) {
	if (!eat (c, 'M')) {
		c->fail = true;
		return NULL;
	}
	Node *cls = parse_type (c);
	Node *mem = parse_type (c);
	// a pointer to a (cv-qualified) member function encodes the cv on the
	// function type; fold it in so it prints as a trailing "() const"
	if (mem && mem->kind == K_QUAL && mem->a && mem->a->kind == K_FUNC) {
		mem->a->flags |= (mem->flags & (Q_CONST | Q_VOLATILE | Q_RESTRICT | REF_LV | REF_RV));
		mem = mem->a;
	}
	return mk2 (c, K_PTRMEM, cls, mem);
}

// <template-param> ::= T_ | T <number> _
static Node *parse_template_param(CTX *c) {
	if (!eat (c, 'T')) {
		c->fail = true;
		return NULL;
	}
	int idx = 0;
	if (eat (c, '_')) {
		idx = 0;
	} else {
		int n = parse_num (c);
		if (n < 0 || !eat (c, '_')) {
			c->fail = true;
			return NULL;
		}
		idx = n + 1;
	}
	Node *resolved = (idx >= 0 && idx < c->ntpl) ? c->tpl[idx] : NULL;
	Node *tp = node_new (c, K_TPARAM);
	if (tp) {
		tp->a = resolved;
		tp->num = idx;
	}
	return tp;
}

// Build a reference type, applying C++ reference collapsing: a reference to a
// reference collapses to one reference, lvalue winning over rvalue.
static Node *make_ref(CTX *c, Kind k, Node *inner) {
	Node *res = inner;
	if (res && res->kind == K_TPARAM && res->a) {
		res = res->a;
	}
	if (res && (res->kind == K_LREF || res->kind == K_RREF)) {
		Kind nk = (k == K_LREF || res->kind == K_LREF) ? K_LREF : K_RREF;
		return mk1 (c, nk, res->a);
	}
	return mk1 (c, k, inner);
}

// <type>. Substitutions are added once, at the end, for every successfully
// parsed type EXCEPT builtin types and bare substitution references (which set
// `no_push`). This mirrors LLVM's parseType, where those two cases bail early.
static Node *parse_type(CTX *c) {
	if (c->fail || c->depth > MAX_DEPTH) {
		c->fail = true;
		return NULL;
	}
	c->depth++;
	// Any template-args met while parsing a type are argument lists, not
	// parameter-defining scopes, so tagging is disabled for the whole subtree.
	bool saved_tag = c->tagging;
	c->tagging = false;
	Node *r = NULL;
	bool no_push = false;
	char ch = peek (c);
	switch (ch) {
	case 'r': case 'V': case 'K': {
		ut16 cv = 0;
		for (;;) {
			char q = peek (c);
			if (q == 'r') { cv |= Q_RESTRICT; c->p++; }
			else if (q == 'V') { cv |= Q_VOLATILE; c->p++; }
			else if (q == 'K') { cv |= Q_CONST; c->p++; }
			else break;
		}
		r = mk1 (c, K_QUAL, parse_type (c));
		if (r) {
			r->flags = cv;
		}
		break;
	}
	case 'P': c->p++; r = mk1 (c, K_PTR, parse_type (c)); break;
	case 'R': c->p++; r = make_ref (c, K_LREF, parse_type (c)); break;
	case 'O': c->p++; r = make_ref (c, K_RREF, parse_type (c)); break;
	case 'C': c->p++; r = mk1 (c, K_QUAL, parse_type (c)); if (r) { r->s = "_Complex"; } break;
	case 'G': c->p++; r = mk1 (c, K_QUAL, parse_type (c)); if (r) { r->s = "_Imaginary"; } break;
	case 'F': r = parse_function_type (c); break;
	case 'A': r = parse_array_type (c); break;
	case 'M': r = parse_ptr_to_member (c); break;
	case 'T': {
		r = parse_template_param (c);
		// <template-template-param> <template-args>
		if (!c->fail && peek (c) == 'I') {
			sub_add (c, r); // the template-param itself is a candidate
			Node *args = parse_template_args (c, false);
			r = mk2 (c, K_TEMPLATE, r, args);
		}
		break;
	}
	case 'S': {
		bool is_sub = false;
		r = parse_unscoped (c, &is_sub); // substitution or std::-prefixed name
		if (!c->fail && peek (c) == 'I') {
			if (!is_sub) {
				sub_add (c, r);
			}
			Node *args = parse_template_args (c, false);
			r = mk2 (c, K_TEMPLATE, r, args);
		} else if (is_sub) {
			no_push = true; // a bare substitution is already in the table
		}
		break;
	}
	case 'N': r = parse_nested_name (c); break;
	case 'Z': r = parse_local_name (c); break;
	case 'u': { // vendor extended type: u <source-name>
		c->p++;
		Node *nm = parse_source_name (c);
		r = node_new (c, K_VENDORTY);
		if (r && nm) {
			r->s = nm->s;
			r->len = nm->len;
		}
		break;
	}
	case 'D': {
		char d = peek2 (c);
		if (d == 'o' || d == 'O' || d == 'w' || d == 'x') {
			// exception-spec qualified function type (Do = noexcept, etc.)
			r = parse_function_type (c);
			break;
		}
		if (d == 'p') { // pack expansion
			c->p += 2;
			r = mk1 (c, K_PACK, parse_type (c));
			no_push = true; // expansion is not itself a candidate
			break;
		}
		if (d == 't' || d == 'T') { // <decltype> ::= Dt <expr> E | DT <expr> E
			c->p += 2;
			r = mk1 (c, K_DECLTYPE, parse_expression (c));
			(void)eat (c, 'E');
			break;
		}
		if (d == 'v') { // vector type: Dv <num/expr> _ <type>
			c->p += 2;
			Node *vec = node_new (c, K_VEC);
			if (isdigit ((unsigned char)peek (c))) {
				const char *st = c->p;
				(void)parse_num (c);
				if (vec) { vec->s = st; vec->len = (int)(c->p - st); }
			} else if (peek (c) != '_') {
				if (vec) { vec->b = parse_expression (c); }
			}
			(void)eat (c, '_');
			if (vec) { vec->a = parse_type (c); }
			r = vec;
			break;
		}
		const char *bt = builtin_type_D (d);
		if (bt) {
			no_push = true; // builtin
			if (d == 'F') {
				// DF <number> _   -> _FloatN
				// DF <number> x   -> _FloatNx (extended)
				// DF <number> b   -> std::bfloatN_t  (DF16b == std::bfloat16_t)
				c->p += 2;
				const char *st = c->p;
				(void)parse_num (c);
				int blen = (int)(c->p - st);
				char *lbl;
				if (eat (c, 'b')) {
					lbl = r_str_newf ("std::bfloat%.*s_t", blen, st);
				} else if (eat (c, 'x')) {
					lbl = r_str_newf ("_Float%.*sx", blen, st);
				} else {
					(void)eat (c, '_');
					lbl = (blen > 0 && blen < 16)
						? r_str_newf ("_Float%.*s", blen, st)
						: strdup ("_Float");
				}
				r = node_new (c, K_BUILTIN);
				if (r) {
					r->s = lbl; // owned: freed via the owned-string marker below
					r->len = (int)strlen (lbl);
					r->num = 1;
				}
			} else {
				c->p += 2;
				r = mk_lit (c, K_BUILTIN, bt);
			}
			break;
		}
		c->fail = true;
		break;
	}
	default: {
		const char *bt = builtin_type (ch);
		if (bt) {
			c->p++;
			r = mk_lit (c, K_BUILTIN, bt);
			no_push = true; // builtin types are never substitution candidates
		} else if (isdigit ((unsigned char)ch)) {
			r = parse_name (c); // class-enum-type
		} else {
			c->fail = true;
		}
		break;
	}
	}
	c->depth--;
	c->tagging = saved_tag;
	if (r && !no_push && !c->fail) {
		sub_add (c, r);
	}
	return r;
}

// ---------------------------------------------------------------------------
// template args & expressions
// ---------------------------------------------------------------------------

// <template-args> ::= I <template-arg>+ E
//
// `tag` is true only for the template-args that belong to a *name* (an entity's
// template-id): those define the <template-param> scope (T_, T0_, ...) and may
// be referenced by later args in the same list. Type-level argument lists (e.g.
// the `<T_>` in a parameter type `shared_ptr<T_>`) must NOT establish a new
// scope, otherwise inner T_ would resolve against the wrong list.
static Node *parse_template_args(CTX *c, bool tag) {
	if (!eat (c, 'I')) {
		c->fail = true;
		return NULL;
	}
	Node *list = node_new (c, K_LIST);
	Node **saved_tpl = c->tpl;
	int saved_ntpl = c->ntpl;
	while (peek (c) && peek (c) != 'E') {
		Node *arg = parse_template_arg (c);
		if (c->fail) {
			break;
		}
		node_push_kid (c, list, arg);
		if (tag && list) {
			// allow later args to reference earlier ones via T_
			c->tpl = list->kids;
			c->ntpl = list->nkids;
		}
	}
	if (!eat (c, 'E')) {
		c->fail = true;
	}
	if (tag) {
		// the enclosing encoding re-establishes the signature scope itself
		c->tpl = saved_tpl;
		c->ntpl = saved_ntpl;
	}
	return list;
}

// <template-arg> ::= <type> | X <expr> E | <expr-primary> | J <arg>* E
static Node *parse_template_arg(CTX *c) {
	char ch = peek (c);
	if (ch == 'X') {
		c->p++;
		Node *e = parse_expression (c);
		(void)eat (c, 'E');
		return e;
	}
	if (ch == 'L') {
		return parse_expr_primary (c);
	}
	if (ch == 'J') {
		// J <template-arg>* E : an argument pack
		c->p++;
		Node *list = node_new (c, K_LIST);
		if (list) {
			list->flags |= F_PACKARG;
		}
		while (peek (c) && peek (c) != 'E') {
			Node *a = parse_template_arg (c);
			if (c->fail) {
				break;
			}
			node_push_kid (c, list, a);
		}
		(void)eat (c, 'E');
		return list;
	}
	return parse_type (c);
}

// <expr-primary> ::= L <type> <number> E | L <type> <float> E | L <mangled-name> E
static Node *parse_expr_primary(CTX *c) {
	if (!eat (c, 'L')) {
		c->fail = true;
		return NULL;
	}
	if (peek (c) == '_' && peek2 (c) == 'Z') {
		// L <mangled-name> E : the address of an external entity
		c->p += 2; // skip the "_Z" of the nested mangled name
		Node *e = parse_encoding (c, false);
		(void)eat (c, 'E');
		// GNU shows a qualified function by name only (&A::foo), but an
		// unscoped function with its full call form (&(foo(int))).
		if (e && e->kind == K_FUNC && e->num == 1 && e->b && e->b->kind == K_NESTED) {
			return e->b;
		}
		return e;
	}
	Node *ty = parse_type (c);
	if (c->fail) {
		return NULL;
	}
	Node *lit = node_new (c, K_LITERAL);
	if (lit) {
		lit->a = ty;
	}
	if (eat (c, 'n')) { // negative
		if (lit) {
			lit->flags |= F_NEG;
		}
	}
	const char *st = c->p;
	while (peek (c) && peek (c) != 'E') {
		c->p++;
	}
	if (lit) {
		lit->s = st;
		lit->len = (int)(c->p - st);
	}
	(void)eat (c, 'E');
	return lit;
}

// <simple-id> ::= <source-name> [<template-args>]
static Node *parse_simple_id(CTX *c) {
	Node *nm = parse_source_name (c);
	if (!c->fail && peek (c) == 'I') {
		Node *args = parse_template_args (c, false);
		nm = mk2 (c, K_TEMPLATE, nm, args);
	}
	return nm;
}

// <base-unresolved-name> ::= <simple-id>
//                        ::= on <operator-name> [<template-args>]
//                        ::= dn <destructor-name>
static Node *parse_base_unresolved_name(CTX *c) {
	if (peek (c) == 'o' && peek2 (c) == 'n') {
		c->p += 2;
		Node *op = parse_operator_name (c);
		if (!c->fail && peek (c) == 'I') {
			Node *args = parse_template_args (c, false);
			op = mk2 (c, K_TEMPLATE, op, args);
		}
		return op;
	}
	if (peek (c) == 'd' && peek2 (c) == 'n') {
		c->p += 2;
		Node *t = isdigit ((unsigned char)peek (c)) ? parse_simple_id (c) : parse_type (c);
		return mk1 (c, K_DTOR, t);
	}
	return parse_simple_id (c);
}

// <unresolved-type> ::= <template-param> | <decltype> | <substitution>
static Node *parse_unresolved_type(CTX *c) {
	char a = peek (c);
	if (a == 'T') {
		return parse_template_param (c);
	}
	if (a == 'S') {
		bool is_sub = false;
		return parse_unscoped (c, &is_sub);
	}
	return parse_type (c); // decltype etc.
}

// <unresolved-name> ::= [gs] <base-unresolved-name>
//                   ::= sr <unresolved-type> <base-unresolved-name>
//                   ::= srN <unresolved-type> <unresolved-qualifier-level>+ E <base-unresolved-name>
//                   ::= [gs] sr <unresolved-qualifier-level>+ E <base-unresolved-name>
static Node *parse_unresolved_name(CTX *c) {
	(void)(peek (c) == 'g' && peek2 (c) == 's' && (c->p += 2)); // optional global scope
	if (peek (c) == 's' && peek2 (c) == 'r') {
		c->p += 2;
		Node *base = NULL;
		if (peek (c) == 'N') {
			c->p++;
			base = parse_unresolved_type (c);
			while (!c->fail && peek (c) && peek (c) != 'E') {
				base = qualify (c, base, parse_simple_id (c));
			}
			(void)eat (c, 'E');
		} else if (peek (c) == 'T' || peek (c) == 'D'
				|| (peek (c) == 'S' && peek2 (c) != 't')) {
			base = parse_unresolved_type (c);
		} else {
			while (!c->fail && peek (c) && peek (c) != 'E') {
				Node *ql = parse_simple_id (c);
				base = base ? qualify (c, base, ql) : ql;
			}
			(void)eat (c, 'E');
		}
		Node *nm = parse_base_unresolved_name (c);
		return qualify (c, base, nm);
	}
	return parse_base_unresolved_name (c);
}

// a compact <expression> grammar: enough for common non-type template args
static Node *parse_expression(CTX *c) {
	if (c->fail || c->depth > MAX_DEPTH) {
		c->fail = true;
		return NULL;
	}
	c->depth++;
	Node *r = NULL;
	char a = peek (c), b = peek2 (c);
	if (a == 'L') {
		r = parse_expr_primary (c);
	} else if (a == 'T') {
		r = parse_template_param (c);
	} else if (a == 'c' && b == 'l') {
		// cl <callee> <arg>* E : function call expression
		c->p += 2;
		Node *callee = parse_expression (c);
		Node *args = node_new (c, K_LIST);
		while (peek (c) && peek (c) != 'E') {
			Node *arg = parse_expression (c);
			if (c->fail) {
				break;
			}
			node_push_kid (c, args, arg);
		}
		(void)eat (c, 'E');
		r = mk2 (c, K_EXPR_CALL, callee, args);
	} else if (isdigit ((unsigned char)a)
			|| (a == 's' && b == 'r') || (a == 'g' && b == 's')
			|| (a == 'o' && b == 'n') || (a == 'd' && b == 'n')) {
		// an <unresolved-name>: x, A::x, T::x, std::is_signed<T>::value, ...
		r = parse_unresolved_name (c);
	} else if (a == 'S') {
		// a substitution / std name used as an expression operand
		bool is_sub = false;
		Node *nm = parse_unscoped (c, &is_sub);
		if (!c->fail && peek (c) == 'I') {
			Node *args = parse_template_args (c, false);
			nm = mk2 (c, K_TEMPLATE, nm, args);
		}
		r = nm;
	} else if ((a == 'd' && b == 't') || (a == 'p' && b == 't')) {
		// dt <expr> <unresolved-name> : member access  (x.m / x->m)
		const char *op = (a == 'd') ? "." : "->";
		c->p += 2;
		Node *obj = parse_expression (c);
		Node *mem = parse_unresolved_name (c);
		r = mk2 (c, K_EXPR_BINARY, obj, mem);
		if (r) {
			r->s = op;
			r->flags |= F_GLOBAL; // member access: no surrounding parens
		}
	} else if (a == 's' && b == 'p') {
		c->p += 2;
		r = mk1 (c, K_PACK, parse_expression (c));
	} else if (a == 'f' && b == 'p') {
		// function parameter: fp_ -> {parm#1}, fp<N>_ -> {parm#(N+2)}
		c->p += 2;
		int num = parse_num (c);
		(void)eat (c, '_');
		r = node_new (c, K_NAME);
		if (r) {
			char buf[32];
			snprintf (buf, sizeof (buf), "{parm#%d}", (num < 0) ? 1 : num + 2);
			r->s = strdup (buf);
			r->len = (int)strlen (r->s);
			r->num = 1; // owned string marker
			r->kind = K_BUILTIN; // reuse the owned-string free path
		}
	} else if (a == 's' && b == 'Z') {
		c->p += 2;
		Node *e = parse_template_param (c);
		r = mk1 (c, K_EXPR_UNARY, e);
		if (r) {
			r->s = "sizeof...";
		}
	} else {
		// operator expression
		int i;
		const OpInfo *op = NULL;
		for (i = 0; operators[i].code; i++) {
			if (a == operators[i].code[0] && b == operators[i].code[1]) {
				op = &operators[i];
				break;
			}
		}
		if (op) {
			c->p += 2;
			if (op->arity == 1) {
				Node *x = parse_expression (c);
				r = mk1 (c, K_EXPR_UNARY, x);
				if (r) {
					r->s = op->name;
				}
			} else if (op->arity == 2) {
				Node *x = parse_expression (c);
				Node *y = parse_expression (c);
				r = mk2 (c, K_EXPR_BINARY, x, y);
				if (r) {
					r->s = op->name;
				}
			} else if (op->arity == 3) {
				Node *x = parse_expression (c);
				Node *y = parse_expression (c);
				Node *z = parse_expression (c);
				r = node_new (c, K_EXPR_TRINARY);
				if (r) {
					r->a = x;
					r->b = y;
					r->c = z;
				}
			} else {
				c->fail = true;
			}
		} else if (a == 'c' && b == 'v') {
			// conversion: cv <type> <expr>
			c->p += 2;
			Node *ty = parse_type (c);
			Node *e = parse_expression (c);
			r = mk2 (c, K_EXPR_CALL, ty, e);
		} else {
			c->fail = true;
		}
	}
	c->depth--;
	return r;
}

// ---------------------------------------------------------------------------
// special names & encoding
// ---------------------------------------------------------------------------

// <call-offset> ::= h <number> _ | v <number> _ <number> _
static void parse_call_offset(CTX *c) {
	if (eat (c, 'h')) {
		(void)eat (c, 'n');
		(void)parse_num (c);
		(void)eat (c, '_');
	} else if (eat (c, 'v')) {
		(void)eat (c, 'n');
		(void)parse_num (c);
		(void)eat (c, '_');
		(void)eat (c, 'n');
		(void)parse_num (c);
		(void)eat (c, '_');
	}
}

static Node *mk_special(CTX *c, const char *label, Node *target) {
	Node *n = node_new (c, K_SPECIAL);
	if (n) {
		n->s = label;
		n->a = target;
	}
	return n;
}

// <special-name>
static Node *parse_special_name(CTX *c) {
	if (eat (c, 'T')) {
		char ch = take (c);
		switch (ch) {
		case 'V': return mk_special (c, "vtable for ", parse_type (c));
		case 'T': return mk_special (c, "VTT for ", parse_type (c));
		case 'I': return mk_special (c, "typeinfo for ", parse_type (c));
		case 'S': return mk_special (c, "typeinfo name for ", parse_type (c));
		case 'C': { // TC <type> <offset> _ <type> : construction vtable
			Node *t1 = parse_type (c);
			(void)parse_num (c);
			(void)eat (c, '_');
			Node *t2 = parse_type (c);
			// printed as "construction vtable for <derived>-in-<base>"
			Node *n = mk_special (c, "construction vtable for ", t2);
			if (n) {
				n->b = t1;
			}
			return n;
		}
		case 'h': { c->p--; parse_call_offset (c); return mk_special (c, "non-virtual thunk to ", parse_encoding (c, false)); }
		case 'v': { c->p--; parse_call_offset (c); return mk_special (c, "virtual thunk to ", parse_encoding (c, false)); }
		case 'c': {
			parse_call_offset (c);
			parse_call_offset (c);
			return mk_special (c, "covariant return thunk to ", parse_encoding (c, false));
		}
		case 'W': return mk_special (c, "TLS wrapper function for ", parse_name (c));
		case 'H': return mk_special (c, "TLS init function for ", parse_name (c));
		case 'A': return mk_special (c, "template parameter object for ", parse_template_arg (c));
		default: c->fail = true; return NULL;
		}
	}
	if (eat (c, 'G')) {
		char ch = take (c);
		switch (ch) {
		case 'V': return mk_special (c, "guard variable for ", parse_name (c));
		case 'T': // GTt <encoding> / GTn <encoding>: transactional clones
			if (eat (c, 't')) {
				return mk_special (c, "transaction clone for ", parse_encoding (c, false));
			}
			if (eat (c, 'n')) {
				return mk_special (c, "non-transaction clone for ", parse_encoding (c, false));
			}
			c->fail = true;
			return NULL;
		case 'R': {
			Node *nm = parse_name (c);
			if (!eat (c, '_')) {
				(void)parse_seqid (c);
				(void)eat (c, '_');
			}
			return mk_special (c, "reference temporary for ", nm);
		}
		case 'A': // hidden alias / global
			return parse_encoding (c, false);
		default: c->fail = true; return NULL;
		}
	}
	c->fail = true;
	return NULL;
}

// Find the <template-args> in scope for a function name: the rightmost
// template in the name's spine (the function's own template if it is one,
// otherwise the enclosing class template).
static Node *find_active_targs(Node *n) {
	if (!n) {
		return NULL;
	}
	if (n->kind == K_TEMPLATE) {
		return n->b;
	}
	if (n->kind == K_NESTED) {
		Node *r = find_active_targs (n->b);
		return r ? r : find_active_targs (n->a);
	}
	if (n->kind == K_ABITAG) {
		return find_active_targs (n->a);
	}
	return NULL;
}

// <encoding> ::= <function name> <bare-function-type> | <data name> | <special-name>
static Node *parse_encoding(CTX *c, bool top) {
	(void)top;
	if (c->fail || c->depth > MAX_DEPTH) {
		c->fail = true;
		return NULL;
	}
	char ch = peek (c);
	if ((ch == 'T' || ch == 'G') && peek2 (c) != 0) {
		// could be a special-name; but 'T...' could also be a template-param
		// type which never starts an encoding, so treat as special-name.
		Node *sp = parse_special_name (c);
		return sp;
	}
	// the entity name establishes the <template-param> scope for the signature
	bool outer_tag = c->tagging;
	c->tagging = true;
	Node *name = parse_name (c);
	c->tagging = outer_tag;
	if (c->fail || !name) {
		return NULL;
	}
	// data name: nothing follows (or end / E / '.')
	char nx = peek (c);
	if (nx == 0 || nx == 'E' || nx == '.') {
		return name;
	}
	// function: parse the bare-function-type (one or more types).
	// The return type is encoded first iff the function name is a template-id,
	// EXCEPT for constructors, destructors and conversion operators (which never
	// encode a return type even when templated).
	bool is_template = false;
	{
		// rightmost component of the name
		Node *last = name;
		int g = 0;
		while (last && g++ < 64) {
			if (last->kind == K_NESTED) { last = last->b; continue; }
			if (last->kind == K_ABITAG) { last = last->a; continue; }
			break;
		}
		if (last && last->kind == K_TEMPLATE) {
			Node *nm = last->a; // the templated name
			int h = 0;
			while (nm && h++ < 64) {
				if (nm->kind == K_NESTED) { nm = nm->b; continue; }
				if (nm->kind == K_ABITAG) { nm = nm->a; continue; }
				break;
			}
			Kind nk = nm ? (Kind)nm->kind : K_EMPTY;
			is_template = !(nk == K_CTOR || nk == K_DTOR || nk == K_CONV);
		}
	}
	// Template parameters (T_) in the signature resolve against the innermost
	// enclosing template's args (the function's own, or its class's).
	Node *targs = find_active_targs (name);
	Node **saved_tpl = c->tpl;
	int saved_ntpl = c->ntpl;
	if (targs) {
		c->tpl = targs->kids;
		c->ntpl = targs->nkids;
	}
	Node *ret = NULL;
	if (is_template) {
		ret = parse_type (c);
		if (c->fail) {
			c->tpl = saved_tpl;
			c->ntpl = saved_ntpl;
			return NULL;
		}
	}
	Node *params = node_new (c, K_PARAMS);
	while (peek (c) && peek (c) != 'E' && peek (c) != '.') {
		Node *t = parse_type (c);
		if (c->fail) {
			c->tpl = saved_tpl;
			c->ntpl = saved_ntpl;
			return NULL;
		}
		node_push_kid (c, params, t);
	}
	c->tpl = saved_tpl;
	c->ntpl = saved_ntpl;
	Node *fn = node_new (c, K_FUNC);
	if (fn) {
		fn->a = ret;
		fn->b = name; // reuse: for an encoding, "name" lives in b, params in...
		fn->c = params;
		// carry member cv/ref qualifiers from the (nested) name
		fn->flags = name->flags & (Q_CONST | Q_VOLATILE | Q_RESTRICT | REF_LV | REF_RV);
		fn->num = 1; // mark: this is an encoding-level function (has a name)
	}
	return fn;
}

// ---------------------------------------------------------------------------
// printing
// ---------------------------------------------------------------------------

static void emit_cv(RStrBuf *o, ut16 flags) {
	if (flags & Q_CONST) {
		r_strbuf_append (o, " const");
	}
	if (flags & Q_VOLATILE) {
		r_strbuf_append (o, " volatile");
	}
	if (flags & Q_RESTRICT) {
		r_strbuf_append (o, " restrict");
	}
	if (flags & REF_LV) {
		r_strbuf_append (o, " &");
	}
	if (flags & REF_RV) {
		r_strbuf_append (o, " &&");
	}
}

// Collect the template-params inside `n` that are bound to an argument pack
// (a J...E list). These drive a parameter-pack expansion. Recursion stops at
// each template-param (its binding is the pack itself, not something to scan).
static void collect_packs(Node *n, Node **out, int *cnt, int max, int depth) {
	if (!n || depth > MAX_DEPTH || *cnt >= max) {
		return;
	}
	if (n->kind == K_TPARAM) {
		if (n->a && n->a->kind == K_LIST && (n->a->flags & F_PACKARG)) {
			int i;
			for (i = 0; i < *cnt; i++) {
				if (out[i] == n) {
					return;
				}
			}
			out[(*cnt)++] = n;
		}
		return;
	}
	collect_packs (n->a, out, cnt, max, depth + 1);
	collect_packs (n->b, out, cnt, max, depth + 1);
	collect_packs (n->c, out, cnt, max, depth + 1);
	int i;
	for (i = 0; i < n->nkids; i++) {
		collect_packs (n->kids[i], out, cnt, max, depth + 1);
	}
}

// Expand a Dp pack-expansion node into the output list. The referenced packs
// (bound J...E lists) determine the count: each element is printed with the
// referenced template-params temporarily rebound to that element.
static void emit_pack(RStrBuf *o, Node *pack, int depth, bool *first) {
	Node *tps[16];
	int ntp = 0;
	collect_packs (pack->a, tps, &ntp, 16, 0);
	if (ntp == 0) {
		// no bound pack found: the pattern's params are bound to single types,
		// so the expansion contributes exactly one element
		if (!*first) {
			r_strbuf_append (o, ", ");
		}
		*first = false;
		emit_type (o, pack->a, "", depth + 1);
		return;
	}
	int n = tps[0]->a->nkids;
	Node *saved[16];
	int j;
	for (j = 0; j < ntp; j++) {
		saved[j] = tps[j]->a; // the J-pack list
	}
	int i;
	for (i = 0; i < n; i++) {
		for (j = 0; j < ntp; j++) {
			Node *pk = saved[j];
			tps[j]->a = (i < pk->nkids) ? pk->kids[i] : NULL;
		}
		if (!*first) {
			r_strbuf_append (o, ", ");
		}
		*first = false;
		emit_type (o, pack->a, "", depth + 1);
	}
	for (j = 0; j < ntp; j++) {
		tps[j]->a = saved[j];
	}
}

// emit a comma-separated argument list (params or template-args), flattening
// J-packs and expanding Dp pack-expansions.
static void emit_list_items(RStrBuf *o, Node *list, int depth, bool *first) {
	int i;
	for (i = 0; list && i < list->nkids; i++) {
		Node *k = list->kids[i];
		if (!k) {
			continue;
		}
		if (k->kind == K_LIST && (k->flags & F_PACKARG)) {
			emit_list_items (o, k, depth, first); // flatten argument pack
		} else if (k->kind == K_PACK) {
			emit_pack (o, k, depth, first);
		} else {
			if (!*first) {
				r_strbuf_append (o, ", ");
			}
			*first = false;
			emit_type (o, k, "", depth + 1);
		}
	}
}

static void emit_typelist(RStrBuf *o, Node *list, int depth) {
	bool first = true;
	emit_list_items (o, list, depth, &first);
}

// like emit_typelist but elides a single "void" parameter (-> empty)
static void emit_params(RStrBuf *o, Node *params, int depth) {
	if (params && params->nkids == 1 && params->kids[0]
			&& params->kids[0]->kind == K_BUILTIN
			&& !strcmp (params->kids[0]->s, "void")) {
		return;
	}
	emit_typelist (o, params, depth);
}

// close a template argument list with correct ">"/" >" spacing
static void emit_template_close(RStrBuf *o) {
	char *s = r_strbuf_get (o);
	int len = s ? (int)strlen (s) : 0;
	if (len > 0 && s[len - 1] == '>') {
		r_strbuf_append (o, " >");
	} else {
		r_strbuf_append (o, ">");
	}
}

// true if `n` is a template argument that expands to zero elements (an empty
// J-pack or a Dp expansion over an empty pack). Such a trailing argument
// suppresses the "> >" separating space (matching GNU: vector<...>>).
static bool is_empty_pack_arg(Node *n) {
	if (!n) {
		return false;
	}
	if (n->kind == K_LIST && (n->flags & F_PACKARG)) {
		return n->nkids == 0;
	}
	if (n->kind == K_PACK) {
		Node *tps[16];
		int ntp = 0;
		collect_packs (n->a, tps, &ntp, 16, 0);
		return ntp > 0 && tps[0]->a->nkids == 0;
	}
	return false;
}

static void emit_template_args(RStrBuf *o, Node *args, int depth) {
	// avoid "<<" ambiguity when the name ends in '<' (e.g. operator< / operator<<
	// become "operator< <T>" / "operator<< <T>"). A trailing '>' does not need
	// separating: c++filt prints "operator>><T>" with no space.
	char *cur = r_strbuf_get (o);
	int clen = cur ? (int)strlen (cur) : 0;
	if (clen > 0 && cur[clen - 1] == '<') {
		r_strbuf_append (o, " ");
	}
	r_strbuf_append (o, "<");
	emit_typelist (o, args, depth);
	// a trailing empty pack closes with ">" regardless of the last char
	bool empty_tail = args && args->nkids > 0
		&& is_empty_pack_arg (args->kids[args->nkids - 1]);
	if (empty_tail) {
		r_strbuf_append (o, ">");
	} else {
		emit_template_close (o);
	}
}

// emit just the bare class name for a ctor/dtor: the last top-level "::"
// component with any template-argument list stripped. Handles std abbreviations
// like "std::basic_string<char, std::char_traits<char>, ...>" -> "basic_string"
// where naive "::" / "<" scanning would be misled by the nested commas/angles.
static void emit_basename(RStrBuf *o, Node *n, int depth) {
	RStrBuf *t = r_strbuf_new ("");
	emit_name (t, n, depth);
	char *s = r_strbuf_drain (t);
	if (!s) {
		return;
	}
	// std abbreviations spell their ctor/dtor name differently from their
	// short display form (std::string -> basic_string).
	static const struct { const char *disp, *ctor; } stdctor[] = {
		{ "std::string", "basic_string" },
		{ "std::istream", "basic_istream" },
		{ "std::ostream", "basic_ostream" },
		{ "std::iostream", "basic_iostream" },
		{ NULL, NULL }
	};
	int si;
	for (si = 0; stdctor[si].disp; si++) {
		if (!strcmp (s, stdctor[si].disp)) {
			r_strbuf_append (o, stdctor[si].ctor);
			free (s);
			return;
		}
	}
	const char *base = s;
	int d = 0;
	const char *p;
	for (p = s; *p; p++) {
		if (*p == '<') {
			d++;
		} else if (*p == '>') {
			d--;
		} else if (d == 0 && p[0] == ':' && p[1] == ':') {
			base = p + 2;
			p++;
		}
	}
	// length up to the first top-level '<'
	int len = 0;
	d = 0;
	for (p = base; *p; p++) {
		if (*p == '<') {
			break;
		}
		len++;
	}
	r_strbuf_append_n (o, base, len);
	free (s);
}

// print a "name-ish" node (no declarator)
static void emit_name(RStrBuf *o, Node *n, int depth) {
	if (!n || depth > MAX_DEPTH) {
		return;
	}
	switch (n->kind) {
	case K_EMPTY:
		break;
	case K_NAME:
		if (n->flags & F_LAMBDA) {
			r_strbuf_append (o, "{lambda(");
			emit_params (o, n->b, depth);
			r_strbuf_appendf (o, ")#%d}", n->num);
			break;
		}
		if (n->flags & F_UNNAMED) {
			r_strbuf_appendf (o, "{unnamed type#%d}", n->num);
			break;
			}
			// the unnamed namespace mangles as the source-name "_GLOBAL__N_1"
			if (n->len >= 11 && r_str_startswith (n->s, "_GLOBAL__N_")) {
				r_strbuf_append (o, "(anonymous namespace)");
				break;
			}
		if (n->s) {
			r_strbuf_append_n (o, n->s, n->len ? n->len : (int)strlen (n->s));
		}
		break;
	case K_BUILTIN:
	case K_VENDORTY:
		if (n->s) {
			r_strbuf_append_n (o, n->s, n->len ? n->len : (int)strlen (n->s));
		}
		break;
	case K_NESTED:
		emit_name (o, n->a, depth + 1);
		r_strbuf_append (o, "::");
		emit_name (o, n->b, depth + 1);
		break;
	case K_TEMPLATE:
		emit_name (o, n->a, depth + 1);
		emit_template_args (o, n->b, depth);
		break;
	case K_CTOR:
		emit_basename (o, simple_name_of (n->a), depth + 1);
		break;
	case K_DTOR:
		r_strbuf_append (o, "~");
		emit_basename (o, simple_name_of (n->a), depth + 1);
		break;
	case K_OPERATOR:
		r_strbuf_append (o, "operator");
		r_strbuf_append_n (o, n->s, n->len);
		break;
	case K_CONV:
		r_strbuf_append (o, "operator ");
		emit_type (o, n->a, "", depth + 1);
		break;
	case K_LITOP:
		r_strbuf_append (o, "operator\"\" ");
		r_strbuf_append_n (o, n->s, n->len);
		break;
	case K_ABITAG:
		emit_name (o, n->a, depth + 1);
		r_strbuf_append (o, "[abi:");
		r_strbuf_append_n (o, n->s, n->len);
		r_strbuf_append (o, "]");
		break;
	case K_LOCAL:
		// the enclosing function is shown as a scope, without its return type;
		// the entity itself may be a function (e.g. a lambda's operator())
		emit_encoding_ex (o, n->a, depth + 1, false);
		r_strbuf_append (o, "::");
		if (n->num > 0) {
			r_strbuf_appendf (o, "{default arg#%d}::", n->num);
		}
		emit_encoding_ex (o, n->b, depth + 1, false);
		break;
	case K_STRINGLIT:
		r_strbuf_append (o, "string literal");
		break;
	case K_SPECIAL:
		r_strbuf_append (o, n->s);
		emit_encoding (o, n->a, depth + 1); // target may be an encoding or a type
		if (n->b) { // construction vtable: "...for T1-in-T2"
			r_strbuf_append (o, "-in-");
			emit_encoding (o, n->b, depth + 1);
		}
		break;
	case K_TPARAM:
		if (n->a) {
			emit_name (o, n->a, depth + 1);
		} else {
			r_strbuf_appendf (o, "auto:%d", n->num + 1);
		}
		break;
	case K_DECLTYPE:
		r_strbuf_append (o, "decltype (");
		emit_expr (o, n->a, depth + 1);
		r_strbuf_append (o, ")");
		break;
	default:
		// fall back to type printing for anything type-shaped
		emit_type (o, n, "", depth + 1);
		break;
	}
}

// print a literal (non-type template argument)
static void emit_literal(RStrBuf *o, Node *n, int depth) {
	Node *ty = n->a;
	const char *tb = (ty && ty->kind == K_BUILTIN) ? ty->s : NULL;
	if (tb && !strcmp (tb, "bool")) {
		if (n->len == 1 && n->s[0] == '1') {
			r_strbuf_append (o, "true");
		} else if (n->len == 1 && n->s[0] == '0') {
			r_strbuf_append (o, "false");
		} else {
			r_strbuf_append_n (o, n->s, n->len);
		}
		return;
	}
	if (tb && (!strcmp (tb, "decltype(nullptr)") || !strcmp (tb, "std::nullptr_t"))) {
		r_strbuf_append (o, "nullptr");
		return;
	}
	// The standard integer types print as a bare value with a type suffix; any
	// other type (enums, etc.) is shown with an explicit (type) cast.
	const char *suffix = NULL;
	bool bare = false;
	if (tb) {
		struct { const char *t, *sfx; } ints[] = {
			{ "int", "" }, { "unsigned int", "u" }, { "long", "l" },
			{ "unsigned long", "ul" }, { "long long", "ll" },
			{ "unsigned long long", "ull" }, { NULL, NULL }
		};
		int i;
		for (i = 0; ints[i].t; i++) {
			if (!strcmp (tb, ints[i].t)) {
				bare = true;
				suffix = ints[i].sfx;
				break;
			}
		}
	}
	if (!bare) {
		r_strbuf_append (o, "(");
		emit_type (o, ty, "", depth + 1);
		r_strbuf_append (o, ")");
	}
	if (n->flags & F_NEG) {
		r_strbuf_append (o, "-");
	}
	r_strbuf_append_n (o, n->s, n->len);
	if (suffix) {
		r_strbuf_append (o, suffix);
	}
}

static void emit_expr(RStrBuf *o, Node *n, int depth) {
	if (!n || depth > MAX_DEPTH) {
		return;
	}
	switch (n->kind) {
	case K_LITERAL:
		emit_literal (o, n, depth);
		break;
	case K_EXPR_UNARY: {
		// a simple primary operand needs no parentheses (&var), but a compound
		// one does (&(foo())).
		Node *x = n->a;
		bool simple = x && (x->kind == K_NAME || x->kind == K_NESTED
			|| x->kind == K_TEMPLATE || x->kind == K_TPARAM
			|| x->kind == K_LITERAL || x->kind == K_ABITAG);
		if (n->flags & F_POSTFIX) {
			emit_expr (o, x, depth + 1);
			r_strbuf_append (o, n->s);
		} else {
			r_strbuf_append (o, n->s);
			if (simple) {
				emit_expr (o, x, depth + 1);
			} else {
				r_strbuf_append (o, "(");
				emit_expr (o, x, depth + 1);
				r_strbuf_append (o, ")");
			}
		}
		break;
	}
	case K_EXPR_BINARY: {
		// member access (x.m / x->m) prints without spaces or parens; other
		// binary operators wrap compound operands but not themselves.
		bool member = (n->flags & F_GLOBAL) != 0;
		Node *l = n->a, *rr = n->b;
		bool lcomp = l && (l->kind == K_EXPR_BINARY || l->kind == K_EXPR_UNARY
			|| l->kind == K_EXPR_TRINARY);
		bool rcomp = rr && (rr->kind == K_EXPR_BINARY || rr->kind == K_EXPR_UNARY
			|| rr->kind == K_EXPR_TRINARY);
		if (lcomp) {
			r_strbuf_append (o, "(");
			emit_expr (o, l, depth + 1);
			r_strbuf_append (o, ")");
		} else {
			emit_expr (o, l, depth + 1);
		}
		r_strbuf_append (o, n->s);
		if (rcomp && !member) {
			r_strbuf_append (o, "(");
			emit_expr (o, rr, depth + 1);
			r_strbuf_append (o, ")");
		} else {
			emit_expr (o, rr, depth + 1);
		}
		break;
	}
	case K_EXPR_TRINARY:
		emit_expr (o, n->a, depth + 1);
		r_strbuf_append (o, " ? ");
		emit_expr (o, n->b, depth + 1);
		r_strbuf_append (o, " : ");
		emit_expr (o, n->c, depth + 1);
		break;
	case K_EXPR_CALL:
		if (n->b && n->b->kind == K_LIST) {
			// function call: (callee)(args)
			int i;
			r_strbuf_append (o, "(");
			emit_expr (o, n->a, depth + 1);
			r_strbuf_append (o, ")(");
			for (i = 0; i < n->b->nkids; i++) {
				if (i) {
					r_strbuf_append (o, ", ");
				}
				emit_expr (o, n->b->kids[i], depth + 1);
			}
			r_strbuf_append (o, ")");
		} else {
			// conversion cast: (type)(expr)
			r_strbuf_append (o, "(");
			emit_type (o, n->a, "", depth + 1);
			r_strbuf_append (o, ")(");
			emit_expr (o, n->b, depth + 1);
			r_strbuf_append (o, ")");
		}
		break;
	case K_TPARAM:
		emit_name (o, n, depth);
		break;
	case K_FUNC:
		if (n->num == 1) {
			emit_encoding_ex (o, n, depth, false); // a called external entity
		} else {
			emit_type (o, n, "", depth + 1);
		}
		break;
	default:
		emit_name (o, n, depth);
		break;
	}
}

// print a type T with the declarator string `inner` in name position.
static void emit_type(RStrBuf *o, Node *t, const char *inner, int depth) {
	if (!t || depth > MAX_DEPTH) {
		if (inner && *inner) {
			r_strbuf_append (o, inner);
		}
		return;
	}
	switch (t->kind) {
	case K_PTR:
	case K_LREF:
	case K_RREF: {
		Kind k = (Kind)t->kind;
		Node *pointee = t->a;
		if (k != K_PTR) {
			// reference collapsing through resolved template params
			Node *res = pointee;
			int g = 0;
			while (res && res->kind == K_TPARAM && res->a && g++ < 64) {
				res = res->a;
			}
			if (res && (res->kind == K_LREF || res->kind == K_RREF)) {
				k = (k == K_LREF || res->kind == K_LREF) ? K_LREF : K_RREF;
				pointee = res->a;
			}
		}
		const char *sign = (k == K_PTR) ? "*" : (k == K_LREF) ? "&" : "&&";
		bool wrap = pointee && (pointee->kind == K_FUNC || pointee->kind == K_ARRAY || pointee->kind == K_PTRMEM);
		char *ni;
		if (wrap) {
			ni = r_str_newf ("(%s%s)", sign, inner);
		} else if (inner && inner[0] == '(') {
			// separate the sign from a following declarator group: "void* (*)()"
			ni = r_str_newf ("%s %s", sign, inner);
		} else {
			ni = r_str_newf ("%s%s", sign, inner);
		}
		emit_type (o, pointee, ni, depth + 1);
		free (ni);
		break;
	}
	case K_QUAL: {
		// const/volatile/restrict applied to t->a, plus the _Complex marker
		RStrBuf *q = r_strbuf_new ("");
		if (t->flags & Q_CONST) { r_strbuf_append (q, " const"); }
		if (t->flags & Q_VOLATILE) { r_strbuf_append (q, " volatile"); }
		if (t->flags & Q_RESTRICT) { r_strbuf_append (q, " restrict"); }
		if (t->s) { r_strbuf_appendf (q, " %s", t->s); } // _Complex
		// keep a separating space before a declarator group ("const (&) [16]")
		if (inner && (inner[0] == '(' || inner[0] == '[')) {
			r_strbuf_append (q, " ");
		}
		r_strbuf_append (q, inner);
		char *ni = r_strbuf_drain (q);
		emit_type (o, t->a, ni, depth + 1);
		free (ni);
		break;
	}
	case K_FUNC: {
		// ret inner(params) cv
		RStrBuf *pb = r_strbuf_new ("");
		emit_params (pb, t->c ? t->c : t->b, depth);
		char *params = r_strbuf_drain (pb);
		RStrBuf *cvb = r_strbuf_new ("");
		emit_cv (cvb, t->flags);
		if (t->flags & F_NOEXCEPT) {
			r_strbuf_append (cvb, " noexcept");
		}
		char *cv = r_strbuf_drain (cvb);
		char *ni = r_str_newf ("%s(%s)%s", inner ? inner : "", params, cv);
		emit_type (o, t->a, ni, depth + 1);
		free (ni);
		free (params);
		free (cv);
		break;
	}
	case K_ARRAY: {
		char dim[64];
		if (t->s) {
			snprintf (dim, sizeof (dim), "%.*s", t->len, t->s);
		} else if (t->b) {
			RStrBuf *eb = r_strbuf_new ("");
			emit_expr (eb, t->b, depth);
			char *e = r_strbuf_drain (eb);
			snprintf (dim, sizeof (dim), "%s", r_str_get (e));
			free (e);
		} else {
			dim[0] = 0;
		}
		// "T [N]" but consecutive dimensions abut: "T [N][M]"
		const char *pre = inner ? inner : "";
		size_t pl = strlen (pre);
		char *ni = (pl > 0 && pre[pl - 1] == ']')
			? r_str_newf ("%s[%s]", pre, dim)
			: r_str_newf ("%s [%s]", pre, dim);
		emit_type (o, t->a, ni, depth + 1);
		free (ni);
		break;
	}
	case K_PTRMEM: {
		RStrBuf *cb = r_strbuf_new ("");
		emit_type (cb, t->a, "", depth + 1);
		char *cls = r_strbuf_drain (cb);
		Node *mem = t->b;
		bool wrap = mem && (mem->kind == K_FUNC || mem->kind == K_ARRAY);
		char *ni = wrap
			? r_str_newf ("(%s::*%s)", cls, inner ? inner : "")
			: r_str_newf ("%s::*%s", cls, inner ? inner : "");
		emit_type (o, mem, ni, depth + 1);
		free (ni);
		free (cls);
		break;
	}
	case K_PACK:
		emit_type (o, t->a, inner, depth + 1);
		r_strbuf_append (o, "...");
		break;
	case K_VEC: {
		emit_type (o, t->a, "", depth + 1);
		r_strbuf_append (o, " __vector(");
		if (t->s) {
			r_strbuf_append_n (o, t->s, t->len);
		} else if (t->b) {
			emit_expr (o, t->b, depth);
		}
		r_strbuf_append (o, ")");
		if (inner && *inner) {
			r_strbuf_appendf (o, " %s", inner);
		}
		break;
	}
	case K_TPARAM:
		if (t->a) {
			emit_type (o, t->a, inner, depth + 1);
		} else {
			r_strbuf_appendf (o, "auto:%d", t->num + 1);
			if (inner && *inner) {
				if (inner[0] == '*' || inner[0] == '&' || inner[0] == ' ') {
					r_strbuf_append (o, inner);
				} else {
					r_strbuf_appendf (o, " %s", inner);
				}
			}
		}
		break;
	case K_LITERAL:
		emit_literal (o, t, depth);
		if (inner && *inner) {
			r_strbuf_appendf (o, " %s", inner);
		}
		break;
	case K_LIST: // argument pack used as a template arg
		emit_typelist (o, t, depth);
		break;
	case K_EXPR_UNARY:
	case K_EXPR_BINARY:
	case K_EXPR_TRINARY:
		emit_expr (o, t, depth);
		break;
	default: {
		// terminal name-ish type; the `inner` declarator carries its own
		// leading space when it needs one (e.g. " const"), so only insert a
		// separating space when it starts with an alnum/paren/bracket.
		emit_name (o, t, depth);
		if (inner && *inner) {
			if (inner[0] == '*' || inner[0] == '&' || inner[0] == ' ') {
				r_strbuf_append (o, inner);
			} else {
				r_strbuf_appendf (o, " %s", inner);
			}
		}
		break;
	}
	}
}

// top-level encoding printer
static void emit_encoding_ex(RStrBuf *o, Node *n, int depth, bool with_ret) {
	if (!n) {
		return;
	}
	if (n->kind == K_FUNC && n->num == 1) {
		// encoding-level function: [ret] name(params) cv
		Node *name = n->b;
		Node *params = n->c;
		if (n->a && with_ret) { // return type present (template specialization)
			emit_type (o, n->a, "", depth + 1);
			r_strbuf_append (o, " ");
		}
		emit_name (o, name, depth + 1);
		r_strbuf_append (o, "(");
		emit_params (o, params, depth);
		r_strbuf_append (o, ")");
		emit_cv (o, n->flags);
		return;
	}
	emit_name (o, n, depth);
}

static void emit_encoding(RStrBuf *o, Node *n, int depth) {
	emit_encoding_ex (o, n, depth, true);
}

// ---------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------

char *r_demangle_itanium(const char *mangled) {
	if (!mangled) {
		return NULL;
	}
	const char *p = mangled;
	// accept an optional leading underscore (some platforms prefix symbols)
	if (p[0] == '_' && p[1] == '_' && p[2] == 'Z') {
		p++;
	}
	if (!(p[0] == '_' && p[1] == 'Z')) {
		return NULL;
	}
	p += 2;
	CTX c = { 0 };
	c.buf = p;
	c.p = p;
	c.end = p + strlen (p);
	Node *root = parse_encoding (&c, true);
	char *result = NULL;
	if (!c.fail && root) {
		// allow an optional vendor-specific suffix of clone markers, e.g.
		// ".cold", ".part.0", ".constprop.0.cold" -> " [clone .part.0] [clone .cold]"
		const char *rest = c.p;
		bool clean = (*rest == 0) || (*rest == '.');
		if (clean) {
			RStrBuf *o = r_strbuf_new ("");
			emit_encoding (o, root, 0);
			while (*rest == '.') {
				const char *start = rest;
				rest++; // skip '.'
				while (*rest && *rest != '.') {
					rest++;
				}
				// numeric ".N" groups attach to the current clone unit
				while (rest[0] == '.' && isdigit ((unsigned char)rest[1])) {
					rest++;
					while (isdigit ((unsigned char)*rest)) {
						rest++;
					}
				}
				r_strbuf_append (o, " [clone ");
				r_strbuf_append_n (o, start, (int)(rest - start));
				r_strbuf_append (o, "]");
			}
			result = r_strbuf_drain (o);
		}
	}
	// bulk free the arena
	int i;
	for (i = 0; i < c.nall; i++) {
		Node *n = c.all[i];
		if (n->kind == K_BUILTIN && n->num == 1) {
			free ((void *)n->s); // owned _FloatN label
		}
		free (n->kids);
		free (n);
	}
	free (c.all);
	free (c.subs);
	if (result && !*result) {
		free (result);
		result = NULL;
	}
	return result;
}
