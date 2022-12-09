#include "jsi.h"
#include "jsparse.h"
#include "jscompile.h"
#include "jsvalue.h"

#include "utf.h"

#include <assert.h>

static const char *astname[] = {
#include "astnames.h"
NULL
};

static const char *opname[] = {
#include "opnames.h"
NULL
};

static int minify = 0;

const char *jsP_aststring(enum js_AstType type)
{
	if (type < nelem(astname)-1)
		return astname[type];
	return "<unknown>";
}

const char *jsC_opcodestring(enum js_OpCode opcode)
{
	if (opcode < nelem(opname)-1)
		return opname[opcode];
	return "<unknown>";
}

static int prec(enum js_AstType type)
{
	switch (type) {
	case AST_IDENTIFIER:
	case EXP_IDENTIFIER:
	case EXP_NUMBER:
	case EXP_STRING:
	case EXP_REGEXP:
	case EXP_UNDEF:
	case EXP_NULL:
	case EXP_TRUE:
	case EXP_FALSE:
	case EXP_THIS:
	case EXP_ARRAY:
	case EXP_OBJECT:
		return 170;

	case EXP_FUN:
	case EXP_INDEX:
	case EXP_MEMBER:
	case EXP_CALL:
	case EXP_NEW:
		return 160;

	case EXP_POSTINC:
	case EXP_POSTDEC:
		return 150;

	case EXP_DELETE:
	case EXP_VOID:
	case EXP_TYPEOF:
	case EXP_PREINC:
	case EXP_PREDEC:
	case EXP_POS:
	case EXP_NEG:
	case EXP_BITNOT:
	case EXP_LOGNOT:
		return 140;

	case EXP_MOD:
	case EXP_DIV:
	case EXP_MUL:
		return 130;

	case EXP_SUB:
	case EXP_ADD:
		return 120;

	case EXP_USHR:
	case EXP_SHR:
	case EXP_SHL:
		return 110;

	case EXP_IN:
	case EXP_INSTANCEOF:
	case EXP_GE:
	case EXP_LE:
	case EXP_GT:
	case EXP_LT:
		return 100;

	case EXP_STRICTNE:
	case EXP_STRICTEQ:
	case EXP_NE:
	case EXP_EQ:
		return 90;

	case EXP_BITAND: return 80;
	case EXP_BITXOR: return 70;
	case EXP_BITOR: return 60;
	case EXP_LOGAND: return 50;
	case EXP_LOGOR: return 40;

	case EXP_COND:
		return 30;

	case EXP_ASS:
	case EXP_ASS_MUL:
	case EXP_ASS_DIV:
	case EXP_ASS_MOD:
	case EXP_ASS_ADD:
	case EXP_ASS_SUB:
	case EXP_ASS_SHL:
	case EXP_ASS_SHR:
	case EXP_ASS_USHR:
	case EXP_ASS_BITAND:
	case EXP_ASS_BITXOR:
	case EXP_ASS_BITOR:
		return 20;

#define COMMA 15

	case EXP_COMMA:
		return 10;

	default:
		return 0;
	}
}

static void pc(int c)
{
	putchar(c);
}

static void ps(const char *s)
{
	fputs(s, stdout);
}

static void pn(int n)
{
	printf("%d", n);
}

static void in(int d)
{
	if (minify < 1)
		while (d-- > 0)
			putchar('\t');
}

static void nl(void)
{
	if (minify < 2)
		putchar('\n');
}

static void sp(void)
{
	if (minify < 1)
		putchar(' ');
}

static void comma(void)
{
	putchar(',');
	sp();
}

/* Pretty-printed Javascript syntax */

static void pstmlist(int d, js_Ast *list);
static void pexpi(int d, int i, js_Ast *exp);
static void pstm(int d, js_Ast *stm);
static void slist(int d, js_Ast *list);
static void sblock(int d, js_Ast *list);

static void pargs(int d, js_Ast *list)
{
	while (list) {
		assert(list->type == AST_LIST);
		pexpi(d, COMMA, list->a);
		list = list->b;
		if (list)
			comma();
	}
}

static void parray(int d, js_Ast *list)
{
	pc('[');
	while (list) {
		assert(list->type == AST_LIST);
		pexpi(d, COMMA, list->a);
		list = list->b;
		if (list)
			comma();
	}
	pc(']');
}

static void pobject(int d, js_Ast *list)
{
	pc('{');
	if (list) {
		nl();
		in(d+1);
	}
	while (list) {
		js_Ast *kv = list->a;
		assert(list->type == AST_LIST);
		switch (kv->type) {
		default: break;
		case EXP_PROP_VAL:
			pexpi(d+1, COMMA, kv->a);
			pc(':'); sp();
			pexpi(d+1, COMMA, kv->b);
			break;
		case EXP_PROP_GET:
			ps("get ");
			pexpi(d+1, COMMA, kv->a);
			ps("()"); sp(); pc('{'); nl();
			pstmlist(d+1, kv->c);
			in(d+1); pc('}');
			break;
		case EXP_PROP_SET:
			ps("set ");
			pexpi(d+1, COMMA, kv->a);
			pc('(');
			pargs(d+1, kv->b);
			pc(')'); sp(); pc('{'); nl();
			pstmlist(d+1, kv->c);
			in(d+1); pc('}');
			break;
		}
		list = list->b;
		if (list) {
			pc(',');
			nl();
			in(d+1);
		} else {
			nl();
			in(d);
		}
	}
	pc('}');
}

static void pstr(const char *s)
{
	static const char *HEX = "0123456789ABCDEF";
	Rune c;
	pc(minify ? '\'' : '"');
	while (*s) {
		s += chartorune(&c, s);
		switch (c) {
		case '\'': ps("\\'"); break;
		case '"': ps("\\\""); break;
		case '\\': ps("\\\\"); break;
		case '\b': ps("\\b"); break;
		case '\f': ps("\\f"); break;
		case '\n': ps("\\n"); break;
		case '\r': ps("\\r"); break;
		case '\t': ps("\\t"); break;
		default:
			if (c < ' ' || c > 127) {
				ps("\\u");
				pc(HEX[(c>>12)&15]);
				pc(HEX[(c>>8)&15]);
				pc(HEX[(c>>4)&15]);
				pc(HEX[c&15]);
			} else {
				pc(c); break;
			}
		}
	}
	pc(minify ? '\'' : '"');
}

static void pregexp(const char *prog, int flags)
{
	pc('/');
	while (*prog) {
		if (*prog == '/')
			pc('\\');
		pc(*prog);
		++prog;
	}
	pc('/');
	if (flags & JS_REGEXP_G) pc('g');
	if (flags & JS_REGEXP_I) pc('i');
	if (flags & JS_REGEXP_M) pc('m');
}

static void pbin(int d, int p, js_Ast *exp, const char *op)
{
	pexpi(d, p, exp->a);
	sp();
	ps(op);
	sp();
	pexpi(d, p, exp->b);
}

static void puna(int d, int p, js_Ast *exp, const char *pre, const char *suf)
{
	ps(pre);
	pexpi(d, p, exp->a);
	ps(suf);
}

static void pexpi(int d, int p, js_Ast *exp)
{
	int tp, paren;

	if (!exp) return;

	tp = prec(exp->type);
	paren = 0;
	if (tp < p) {
		pc('(');
		paren = 1;
	}
	p = tp;

	switch (exp->type) {
	case AST_IDENTIFIER: ps(exp->string); break;
	case EXP_IDENTIFIER: ps(exp->string); break;
	case EXP_NUMBER: printf("%.9g", exp->number); break;
	case EXP_STRING: pstr(exp->string); break;
	case EXP_REGEXP: pregexp(exp->string, exp->number); break;

	case EXP_UNDEF: break;
	case EXP_NULL: ps("null"); break;
	case EXP_TRUE: ps("true"); break;
	case EXP_FALSE: ps("false"); break;
	case EXP_THIS: ps("this"); break;

	case EXP_OBJECT: pobject(d, exp->a); break;
	case EXP_ARRAY: parray(d, exp->a); break;

	case EXP_DELETE: puna(d, p, exp, "delete ", ""); break;
	case EXP_VOID: puna(d, p, exp, "void ", ""); break;
	case EXP_TYPEOF: puna(d, p, exp, "typeof ", ""); break;
	case EXP_PREINC: puna(d, p, exp, "++", ""); break;
	case EXP_PREDEC: puna(d, p, exp, "--", ""); break;
	case EXP_POSTINC: puna(d, p, exp, "", "++"); break;
	case EXP_POSTDEC: puna(d, p, exp, "", "--"); break;
	case EXP_POS: puna(d, p, exp, "+", ""); break;
	case EXP_NEG: puna(d, p, exp, "-", ""); break;
	case EXP_BITNOT: puna(d, p, exp, "~", ""); break;
	case EXP_LOGNOT: puna(d, p, exp, "!", ""); break;

	case EXP_LOGOR: pbin(d, p, exp, "||"); break;
	case EXP_LOGAND: pbin(d, p, exp, "&&"); break;
	case EXP_BITOR: pbin(d, p, exp, "|"); break;
	case EXP_BITXOR: pbin(d, p, exp, "^"); break;
	case EXP_BITAND: pbin(d, p, exp, "&"); break;
	case EXP_EQ: pbin(d, p, exp, "=="); break;
	case EXP_NE: pbin(d, p, exp, "!="); break;
	case EXP_STRICTEQ: pbin(d, p, exp, "==="); break;
	case EXP_STRICTNE: pbin(d, p, exp, "!=="); break;
	case EXP_LT: pbin(d, p, exp, "<"); break;
	case EXP_GT: pbin(d, p, exp, ">"); break;
	case EXP_LE: pbin(d, p, exp, "<="); break;
	case EXP_GE: pbin(d, p, exp, ">="); break;
	case EXP_IN: pbin(d, p, exp, "in"); break;
	case EXP_SHL: pbin(d, p, exp, "<<"); break;
	case EXP_SHR: pbin(d, p, exp, ">>"); break;
	case EXP_USHR: pbin(d, p, exp, ">>>"); break;
	case EXP_ADD: pbin(d, p, exp, "+"); break;
	case EXP_SUB: pbin(d, p, exp, "-"); break;
	case EXP_MUL: pbin(d, p, exp, "*"); break;
	case EXP_DIV: pbin(d, p, exp, "/"); break;
	case EXP_MOD: pbin(d, p, exp, "%"); break;
	case EXP_ASS: pbin(d, p, exp, "="); break;
	case EXP_ASS_MUL: pbin(d, p, exp, "*="); break;
	case EXP_ASS_DIV: pbin(d, p, exp, "/="); break;
	case EXP_ASS_MOD: pbin(d, p, exp, "%="); break;
	case EXP_ASS_ADD: pbin(d, p, exp, "+="); break;
	case EXP_ASS_SUB: pbin(d, p, exp, "-="); break;
	case EXP_ASS_SHL: pbin(d, p, exp, "<<="); break;
	case EXP_ASS_SHR: pbin(d, p, exp, ">>="); break;
	case EXP_ASS_USHR: pbin(d, p, exp, ">>>="); break;
	case EXP_ASS_BITAND: pbin(d, p, exp, "&="); break;
	case EXP_ASS_BITXOR: pbin(d, p, exp, "^="); break;
	case EXP_ASS_BITOR: pbin(d, p, exp, "|="); break;

	case EXP_INSTANCEOF:
		pexpi(d, p, exp->a);
		ps(" instanceof ");
		pexpi(d, p, exp->b);
		break;

	case EXP_COMMA:
		pexpi(d, p, exp->a);
		pc(','); sp();
		pexpi(d, p, exp->b);
		break;

	case EXP_COND:
		pexpi(d, p, exp->a);
		sp(); pc('?'); sp();
		pexpi(d, p, exp->b);
		sp(); pc(':'); sp();
		pexpi(d, p, exp->c);
		break;

	case EXP_INDEX:
		pexpi(d, p, exp->a);
		pc('[');
		pexpi(d, 0, exp->b);
		pc(']');
		break;

	case EXP_MEMBER:
		pexpi(d, p, exp->a);
		pc('.');
		pexpi(d, 0, exp->b);
		break;

	case EXP_CALL:
		pexpi(d, p, exp->a);
		pc('(');
		pargs(d, exp->b);
		pc(')');
		break;

	case EXP_NEW:
		ps("new ");
		pexpi(d, p, exp->a);
		pc('(');
		pargs(d, exp->b);
		pc(')');
		break;

	case EXP_FUN:
		if (p == 0) pc('(');
		ps("function ");
		pexpi(d, 0, exp->a);
		pc('(');
		pargs(d, exp->b);
		pc(')'); sp(); pc('{'); nl();
		pstmlist(d, exp->c);
		in(d); pc('}');
		if (p == 0) pc(')');
		break;

	default:
		ps("<UNKNOWN>");
		break;
	}

	if (paren) pc(')');
}

static void pexp(int d, js_Ast *exp)
{
	pexpi(d, 0, exp);
}

static void pvar(int d, js_Ast *var)
{
	assert(var->type == EXP_VAR);
	pexp(d, var->a);
	if (var->b) {
		sp(); pc('='); sp();
		pexp(d, var->b);
	}
}

static void pvarlist(int d, js_Ast *list)
{
	while (list) {
		assert(list->type == AST_LIST);
		pvar(d, list->a);
		list = list->b;
		if (list)
			comma();
	}
}

static void pblock(int d, js_Ast *block)
{
	assert(block->type == STM_BLOCK);
	pc('{'); nl();
	pstmlist(d, block->a);
	in(d); pc('}');
}

static void pstmh(int d, js_Ast *stm)
{
	if (stm->type == STM_BLOCK) {
		sp();
		pblock(d, stm);
	} else {
		nl();
		pstm(d+1, stm);
	}
}

static void pcaselist(int d, js_Ast *list)
{
	while (list) {
		js_Ast *stm = list->a;
		if (stm->type == STM_CASE) {
			in(d); ps("case "); pexp(d, stm->a); pc(':'); nl();
			pstmlist(d, stm->b);
		}
		if (stm->type == STM_DEFAULT) {
			in(d); ps("default:"); nl();
			pstmlist(d, stm->a);
		}
		list = list->b;
	}
}

static void pstm(int d, js_Ast *stm)
{
	if (stm->type == STM_BLOCK) {
		pblock(d, stm);
		return;
	}

	in(d);

	switch (stm->type) {
	case AST_FUNDEC:
		ps("function ");
		pexp(d, stm->a);
		pc('(');
		pargs(d, stm->b);
		pc(')'); sp(); pc('{'); nl();
		pstmlist(d, stm->c);
		in(d); pc('}');
		break;

	case STM_EMPTY:
		pc(';');
		break;

	case STM_VAR:
		ps("var ");
		pvarlist(d, stm->a);
		pc(';');
		break;

	case STM_IF:
		ps("if"); sp(); pc('('); pexp(d, stm->a); pc(')');
		pstmh(d, stm->b);
		if (stm->c) {
			nl(); in(d); ps("else");
			pstmh(d, stm->c);
		}
		break;

	case STM_DO:
		ps("do");
		pstmh(d, stm->a);
		nl();
		in(d); ps("while"); sp(); pc('('); pexp(d, stm->b); pc(')'); pc(';');
		break;

	case STM_WHILE:
		ps("while"); sp(); pc('('); pexp(d, stm->a); pc(')');
		pstmh(d, stm->b);
		break;

	case STM_FOR:
		ps("for"); sp(); pc('(');
		pexp(d, stm->a); pc(';'); sp();
		pexp(d, stm->b); pc(';'); sp();
		pexp(d, stm->c); pc(')');
		pstmh(d, stm->d);
		break;
	case STM_FOR_VAR:
		ps("for"); sp(); ps("(var ");
		pvarlist(d, stm->a); pc(';'); sp();
		pexp(d, stm->b); pc(';'); sp();
		pexp(d, stm->c); pc(')');
		pstmh(d, stm->d);
		break;
	case STM_FOR_IN:
		ps("for"); sp(); pc('(');
		pexp(d, stm->a); ps(" in ");
		pexp(d, stm->b); pc(')');
		pstmh(d, stm->c);
		break;
	case STM_FOR_IN_VAR:
		ps("for"); sp(); ps("(var ");
		pvarlist(d, stm->a); ps(" in ");
		pexp(d, stm->b); pc(')');
		pstmh(d, stm->c);
		break;

	case STM_CONTINUE:
		ps("continue");
		if (stm->a) {
			pc(' '); pexp(d, stm->a);
		}
		pc(';');
		break;

	case STM_BREAK:
		ps("break");
		if (stm->a) {
			pc(' '); pexp(d, stm->a);
		}
		pc(';');
		break;

	case STM_RETURN:
		ps("return");
		if (stm->a) {
			pc(' '); pexp(d, stm->a);
		}
		pc(';');
		break;

	case STM_WITH:
		ps("with"); sp(); pc('('); pexp(d, stm->a); pc(')');
		pstmh(d, stm->b);
		break;

	case STM_SWITCH:
		ps("switch"); sp(); pc('(');
		pexp(d, stm->a);
		pc(')'); sp(); pc('{'); nl();
		pcaselist(d, stm->b);
		in(d); pc('}');
		break;

	case STM_THROW:
		ps("throw "); pexp(d, stm->a); pc(';');
		break;

	case STM_TRY:
		ps("try");
		if (minify && stm->a->type != STM_BLOCK)
			pc(' ');
		pstmh(d, stm->a);
		if (stm->b && stm->c) {
			nl(); in(d); ps("catch"); sp(); pc('('); pexp(d, stm->b); pc(')');
			pstmh(d, stm->c);
		}
		if (stm->d) {
			nl(); in(d); ps("finally");
			pstmh(d, stm->d);
		}
		break;

	case STM_LABEL:
		pexp(d, stm->a); pc(':'); sp(); pstm(d, stm->b);
		break;

	case STM_DEBUGGER:
		ps("debugger");
		pc(';');
		break;

	default:
		pexp(d, stm);
		pc(';');
	}
}

static void pstmlist(int d, js_Ast *list)
{
	while (list) {
		assert(list->type == AST_LIST);
		pstm(d+1, list->a);
		nl();
		list = list->b;
	}
}

void jsP_dumpsyntax(js_State *J, js_Ast *prog, int dominify)
{
	minify = dominify;
	if (prog) {
		if (prog->type == AST_LIST)
			pstmlist(-1, prog);
		else {
			pstm(0, prog);
			nl();
		}
	}
	if (minify > 1)
		putchar('\n');
}

/* S-expression list representation */

static void snode(int d, js_Ast *node)
{
	void (*afun)(int,js_Ast*) = snode;
	void (*bfun)(int,js_Ast*) = snode;
	void (*cfun)(int,js_Ast*) = snode;
	void (*dfun)(int,js_Ast*) = snode;

	if (!node) {
		return;
	}

	if (node->type == AST_LIST) {
		slist(d, node);
		return;
	}

	pc('(');
	ps(astname[node->type]);
	pc(':');
	pn(node->line);
	switch (node->type) {
	default: break;
	case AST_IDENTIFIER: pc(' '); ps(node->string); break;
	case EXP_IDENTIFIER: pc(' '); ps(node->string); break;
	case EXP_STRING: pc(' '); pstr(node->string); break;
	case EXP_REGEXP: pc(' '); pregexp(node->string, node->number); break;
	case EXP_NUMBER: printf(" %.9g", node->number); break;
	case STM_BLOCK: afun = sblock; break;
	case AST_FUNDEC: case EXP_FUN: cfun = sblock; break;
	case EXP_PROP_GET: cfun = sblock; break;
	case EXP_PROP_SET: cfun = sblock; break;
	case STM_SWITCH: bfun = sblock; break;
	case STM_CASE: bfun = sblock; break;
	case STM_DEFAULT: afun = sblock; break;
	}
	if (node->a) { pc(' '); afun(d, node->a); }
	if (node->b) { pc(' '); bfun(d, node->b); }
	if (node->c) { pc(' '); cfun(d, node->c); }
	if (node->d) { pc(' '); dfun(d, node->d); }
	pc(')');
}

static void slist(int d, js_Ast *list)
{
	pc('[');
	while (list) {
		assert(list->type == AST_LIST);
		snode(d, list->a);
		list = list->b;
		if (list)
			pc(' ');
	}
	pc(']');
}

static void sblock(int d, js_Ast *list)
{
	ps("[\n");
	in(d+1);
	while (list) {
		assert(list->type == AST_LIST);
		snode(d+1, list->a);
		list = list->b;
		if (list) {
			nl();
			in(d+1);
		}
	}
	nl(); in(d); pc(']');
}

void jsP_dumplist(js_State *J, js_Ast *prog)
{
	minify = 0;
	if (prog) {
		if (prog->type == AST_LIST)
			sblock(0, prog);
		else
			snode(0, prog);
		nl();
	}
}

/* Compiled code */

void jsC_dumpfunction(js_State *J, js_Function *F)
{
	js_Instruction *p = F->code;
	js_Instruction *end = F->code + F->codelen;
	char *s;
	double n;
	int i;

	minify = 0;

	printf("%s(%d)\n", F->name, F->numparams);
	if (F->strict) printf("\tstrict\n");
	if (F->lightweight) printf("\tlightweight\n");
	if (F->arguments) printf("\targuments\n");
	printf("\tsource %s:%d\n", F->filename, F->line);
	for (i = 0; i < F->funlen; ++i)
		printf("\tfunction %d %s\n", i, F->funtab[i]->name);
	for (i = 0; i < F->varlen; ++i)
		printf("\tlocal %d %s\n", i + 1, F->vartab[i]);

	printf("{\n");
	while (p < end) {
		int ln = *p++;
		int c = *p++;

		printf("%5d(%3d): ", (int)(p - F->code) - 2, ln);
		ps(opname[c]);

		switch (c) {
		case OP_INTEGER:
			printf(" %ld", (long)((*p++) - 32768));
			break;
		case OP_NUMBER:
			memcpy(&n, p, sizeof(n));
			p += sizeof(n) / sizeof(*p);
			printf(" %.9g", n);
			break;
		case OP_STRING:
			memcpy(&s, p, sizeof(s));
			p += sizeof(s) / sizeof(*p);
			pc(' ');
			pstr(s);
			break;
		case OP_NEWREGEXP:
			pc(' ');
			memcpy(&s, p, sizeof(s));
			p += sizeof(s) / sizeof(*p);
			pregexp(s, *p++);
			break;

		case OP_GETVAR:
		case OP_HASVAR:
		case OP_SETVAR:
		case OP_DELVAR:
		case OP_GETPROP_S:
		case OP_SETPROP_S:
		case OP_DELPROP_S:
		case OP_CATCH:
			memcpy(&s, p, sizeof(s));
			p += sizeof(s) / sizeof(*p);
			pc(' ');
			ps(s);
			break;

		case OP_GETLOCAL:
		case OP_SETLOCAL:
		case OP_DELLOCAL:
			printf(" %s", F->vartab[*p++ - 1]);
			break;

		case OP_CLOSURE:
		case OP_CALL:
		case OP_NEW:
		case OP_JUMP:
		case OP_JTRUE:
		case OP_JFALSE:
		case OP_JCASE:
		case OP_TRY:
			printf(" %ld", (long)*p++);
			break;
		}

		nl();
	}
	printf("}\n");

	for (i = 0; i < F->funlen; ++i) {
		if (F->funtab[i] != F) {
			printf("function %d ", i);
			jsC_dumpfunction(J, F->funtab[i]);
		}
	}
}

/* Runtime values */

void js_dumpvalue(js_State *J, js_Value v)
{
	minify = 0;
	switch (v.type) {
	case JS_TUNDEFINED: printf("undefined"); break;
	case JS_TNULL: printf("null"); break;
	case JS_TBOOLEAN: printf(v.u.boolean ? "true" : "false"); break;
	case JS_TNUMBER: printf("%.9g", v.u.number); break;
	case JS_TSHRSTR: printf("'%s'", v.u.shrstr); break;
	case JS_TLITSTR: printf("'%s'", v.u.litstr); break;
	case JS_TMEMSTR: printf("'%s'", v.u.memstr->p); break;
	case JS_TOBJECT:
		if (v.u.object == J->G) {
			printf("[Global]");
			break;
		}
		switch (v.u.object->type) {
		case JS_COBJECT: printf("[Object %p]", (void*)v.u.object); break;
		case JS_CARRAY: printf("[Array %p]", (void*)v.u.object); break;
		case JS_CFUNCTION:
			printf("[Function %p, %s, %s:%d]",
				(void*)v.u.object,
				v.u.object->u.f.function->name,
				v.u.object->u.f.function->filename,
				v.u.object->u.f.function->line);
			break;
		case JS_CSCRIPT: printf("[Script %s]", v.u.object->u.f.function->filename); break;
		case JS_CCFUNCTION: printf("[CFunction %s]", v.u.object->u.c.name); break;
		case JS_CBOOLEAN: printf("[Boolean %d]", v.u.object->u.boolean); break;
		case JS_CNUMBER: printf("[Number %g]", v.u.object->u.number); break;
		case JS_CSTRING: printf("[String'%s']", v.u.object->u.s.string); break;
		case JS_CERROR: printf("[Error]"); break;
		case JS_CARGUMENTS: printf("[Arguments %p]", (void*)v.u.object); break;
		case JS_CITERATOR: printf("[Iterator %p]", (void*)v.u.object); break;
		case JS_CUSERDATA:
			printf("[Userdata %s %p]", v.u.object->u.user.tag, v.u.object->u.user.data);
			break;
		default: printf("[Object %p]", (void*)v.u.object); break;
		}
		break;
	}
}

static void js_dumpproperty(js_State *J, js_Property *node)
{
	minify = 0;
	if (node->left->level)
		js_dumpproperty(J, node->left);
	printf("\t%s: ", node->name);
	js_dumpvalue(J, node->value);
	printf(",\n");
	if (node->right->level)
		js_dumpproperty(J, node->right);
}

void js_dumpobject(js_State *J, js_Object *obj)
{
	minify = 0;
	printf("{\n");
	if (obj->properties->level)
		js_dumpproperty(J, obj->properties);
	printf("}\n");
}
