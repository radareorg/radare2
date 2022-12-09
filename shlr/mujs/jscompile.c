#include "jsi.h"
#include "jslex.h"
#include "jsparse.h"
#include "jscompile.h"
#include "jsvalue.h" /* for jsV_numbertostring */

#define cexp jsC_cexp /* collision with math.h */

#define JF js_State *J, js_Function *F

JS_NORETURN void jsC_error(js_State *J, js_Ast *node, const char *fmt, ...) JS_PRINTFLIKE(3,4);

static void cfunbody(JF, js_Ast *name, js_Ast *params, js_Ast *body);
static void cexp(JF, js_Ast *exp);
static void cstmlist(JF, js_Ast *list);
static void cstm(JF, js_Ast *stm);

void jsC_error(js_State *J, js_Ast *node, const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	char msgbuf[256];

	va_start(ap, fmt);
	vsnprintf(msgbuf, 256, fmt, ap);
	va_end(ap);

	snprintf(buf, 256, "%s:%d: ", J->filename, node->line);
	strcat(buf, msgbuf);

	js_newsyntaxerror(J, buf);
	js_throw(J);
}

static const char *futurewords[] = {
	"class", "const", "enum", "export", "extends", "import", "super",
};

static const char *strictfuturewords[] = {
	"implements", "interface", "let", "package", "private", "protected",
	"public", "static", "yield",
};

static void checkfutureword(JF, js_Ast *exp)
{
	if (jsY_findword(exp->string, futurewords, nelem(futurewords)) >= 0)
		jsC_error(J, exp, "'%s' is a future reserved word", exp->string);
	if (F->strict) {
		if (jsY_findword(exp->string, strictfuturewords, nelem(strictfuturewords)) >= 0)
			jsC_error(J, exp, "'%s' is a strict mode future reserved word", exp->string);
	}
}

static js_Function *newfun(js_State *J, int line, js_Ast *name, js_Ast *params, js_Ast *body, int script, int default_strict)
{
	js_Function *F = js_malloc(J, sizeof *F);
	memset(F, 0, sizeof *F);
	F->gcmark = 0;
	F->gcnext = J->gcfun;
	J->gcfun = F;
	++J->gccounter;

	F->filename = js_intern(J, J->filename);
	F->line = line;
	F->script = script;
	F->strict = default_strict;
	F->name = name ? name->string : "";

	cfunbody(J, F, name, params, body);

	return F;
}

/* Emit opcodes, constants and jumps */

static void emitraw(JF, int value)
{
	if (value != (js_Instruction)value)
		js_syntaxerror(J, "integer overflow in instruction coding");
	if (F->codelen >= F->codecap) {
		F->codecap = F->codecap ? F->codecap * 2 : 64;
		F->code = js_realloc(J, F->code, F->codecap * sizeof *F->code);
	}
	F->code[F->codelen++] = value;
}

static void emit(JF, int value)
{
	emitraw(J, F, F->lastline);
	emitraw(J, F, value);
}

static void emitarg(JF, int value)
{
	emitraw(J, F, value);
}

static void emitline(JF, js_Ast *node)
{
	F->lastline = node->line;
}

static int addfunction(JF, js_Function *value)
{
	if (F->funlen >= F->funcap) {
		F->funcap = F->funcap ? F->funcap * 2 : 16;
		F->funtab = js_realloc(J, F->funtab, F->funcap * sizeof *F->funtab);
	}
	F->funtab[F->funlen] = value;
	return F->funlen++;
}

static int addlocal(JF, js_Ast *ident, int reuse)
{
	const char *name = ident->string;
	if (F->strict) {
		if (!strcmp(name, "arguments"))
			jsC_error(J, ident, "redefining 'arguments' is not allowed in strict mode");
		if (!strcmp(name, "eval"))
			jsC_error(J, ident, "redefining 'eval' is not allowed in strict mode");
	} else {
		if (!strcmp(name, "eval"))
			js_evalerror(J, "%s:%d: invalid use of 'eval'", J->filename, ident->line);
	}
	if (reuse || F->strict) {
		int i;
		for (i = 0; i < F->varlen; ++i) {
			if (!strcmp(F->vartab[i], name)) {
				if (reuse)
					return i+1;
				if (F->strict)
					jsC_error(J, ident, "duplicate formal parameter '%s'", name);
			}
		}
	}
	if (F->varlen >= F->varcap) {
		F->varcap = F->varcap ? F->varcap * 2 : 16;
		F->vartab = js_realloc(J, F->vartab, F->varcap * sizeof *F->vartab);
	}
	F->vartab[F->varlen] = name;
	return ++F->varlen;
}

static int findlocal(JF, const char *name)
{
	int i;
	for (i = F->varlen; i > 0; --i)
		if (!strcmp(F->vartab[i-1], name))
			return i;
	return -1;
}

static void emitfunction(JF, js_Function *fun)
{
	F->lightweight = 0;
	emit(J, F, OP_CLOSURE);
	emitarg(J, F, addfunction(J, F, fun));
}

static void emitnumber(JF, double num)
{
	if (num == 0) {
		emit(J, F, OP_INTEGER);
		emitarg(J, F, 32768);
		if (signbit(num))
			emit(J, F, OP_NEG);
	} else if (num >= SHRT_MIN && num <= SHRT_MAX && num == (int)num) {
		emit(J, F, OP_INTEGER);
		emitarg(J, F, num + 32768);
	} else {
#define N (sizeof(num) / sizeof(js_Instruction))
		js_Instruction x[N];
		size_t i;
		emit(J, F, OP_NUMBER);
		memcpy(x, &num, sizeof(num));
		for (i = 0; i < N; ++i)
			emitarg(J, F, x[i]);
#undef N
	}
}

static void emitstring(JF, int opcode, const char *str)
{
#define N (sizeof(str) / sizeof(js_Instruction))
	js_Instruction x[N];
	size_t i;
	emit(J, F, opcode);
	memcpy(x, &str, sizeof(str));
	for (i = 0; i < N; ++i)
		emitarg(J, F, x[i]);
#undef N
}

static void emitlocal(JF, int oploc, int opvar, js_Ast *ident)
{
	int is_arguments = !strcmp(ident->string, "arguments");
	int is_eval = !strcmp(ident->string, "eval");
	int i;

	if (is_arguments) {
		F->lightweight = 0;
		F->arguments = 1;
	}

	checkfutureword(J, F, ident);
	if (F->strict && oploc == OP_SETLOCAL) {
		if (is_arguments)
			jsC_error(J, ident, "'arguments' is read-only in strict mode");
		if (is_eval)
			jsC_error(J, ident, "'eval' is read-only in strict mode");
	}
	if (is_eval)
		js_evalerror(J, "%s:%d: invalid use of 'eval'", J->filename, ident->line);

	i = findlocal(J, F, ident->string);
	if (i < 0) {
		emitstring(J, F, opvar, ident->string);
	} else {
		emit(J, F, oploc);
		emitarg(J, F, i);
	}
}

static int here(JF)
{
	return F->codelen;
}

static int emitjump(JF, int opcode)
{
	int inst;
	emit(J, F, opcode);
	inst = F->codelen;
	emitarg(J, F, 0);
	return inst;
}

static void emitjumpto(JF, int opcode, int dest)
{
	emit(J, F, opcode);
	if (dest != (js_Instruction)dest)
		js_syntaxerror(J, "jump address integer overflow");
	emitarg(J, F, dest);
}

static void labelto(JF, int inst, int addr)
{
	if (addr != (js_Instruction)addr)
		js_syntaxerror(J, "jump address integer overflow");
	F->code[inst] = addr;
}

static void label(JF, int inst)
{
	labelto(J, F, inst, F->codelen);
}

/* Expressions */

static void ctypeof(JF, js_Ast *exp)
{
	if (exp->a->type == EXP_IDENTIFIER) {
		emitline(J, F, exp->a);
		emitlocal(J, F, OP_GETLOCAL, OP_HASVAR, exp->a);
	} else {
		cexp(J, F, exp->a);
	}
	emitline(J, F, exp);
	emit(J, F, OP_TYPEOF);
}

static void cunary(JF, js_Ast *exp, int opcode)
{
	cexp(J, F, exp->a);
	emitline(J, F, exp);
	emit(J, F, opcode);
}

static void cbinary(JF, js_Ast *exp, int opcode)
{
	cexp(J, F, exp->a);
	cexp(J, F, exp->b);
	emitline(J, F, exp);
	emit(J, F, opcode);
}

static void carray(JF, js_Ast *list)
{
	while (list) {
		emitline(J, F, list->a);
		cexp(J, F, list->a);
		emit(J, F, OP_INITARRAY);
		list = list->b;
	}
}

static void checkdup(JF, js_Ast *list, js_Ast *end)
{
	char nbuf[32], sbuf[32];
	const char *needle, *straw;

	if (end->a->type == EXP_NUMBER)
		needle = jsV_numbertostring(J, nbuf, end->a->number);
	else
		needle = end->a->string;

	while (list->a != end) {
		if (list->a->type == end->type) {
			js_Ast *prop = list->a->a;
			if (prop->type == EXP_NUMBER)
				straw = jsV_numbertostring(J, sbuf, prop->number);
			else
				straw =  prop->string;
			if (!strcmp(needle, straw))
				jsC_error(J, list, "duplicate property '%s' in object literal", needle);
		}
		list = list->b;
	}
}

static void cobject(JF, js_Ast *list)
{
	js_Ast *head = list;

	while (list) {
		js_Ast *kv = list->a;
		js_Ast *prop = kv->a;

		if (prop->type == AST_IDENTIFIER || prop->type == EXP_STRING) {
			emitline(J, F, prop);
			emitstring(J, F, OP_STRING, prop->string);
		} else if (prop->type == EXP_NUMBER) {
			emitline(J, F, prop);
			emitnumber(J, F, prop->number);
		} else {
			jsC_error(J, prop, "invalid property name in object initializer");
		}

		if (F->strict)
			checkdup(J, F, head, kv);

		switch (kv->type) {
		default: /* impossible */ break;
		case EXP_PROP_VAL:
			cexp(J, F, kv->b);
			emitline(J, F, kv);
			emit(J, F, OP_INITPROP);
			break;
		case EXP_PROP_GET:
			emitfunction(J, F, newfun(J, prop->line, NULL, NULL, kv->c, 0, F->strict));
			emitline(J, F, kv);
			emit(J, F, OP_INITGETTER);
			break;
		case EXP_PROP_SET:
			emitfunction(J, F, newfun(J, prop->line, NULL, kv->b, kv->c, 0, F->strict));
			emitline(J, F, kv);
			emit(J, F, OP_INITSETTER);
			break;
		}

		list = list->b;
	}
}

static int cargs(JF, js_Ast *list)
{
	int n = 0;
	while (list) {
		cexp(J, F, list->a);
		list = list->b;
		++n;
	}
	return n;
}

static void cassign(JF, js_Ast *exp)
{
	js_Ast *lhs = exp->a;
	js_Ast *rhs = exp->b;
	switch (lhs->type) {
	case EXP_IDENTIFIER:
		cexp(J, F, rhs);
		emitline(J, F, exp);
		emitlocal(J, F, OP_SETLOCAL, OP_SETVAR, lhs);
		break;
	case EXP_INDEX:
		cexp(J, F, lhs->a);
		cexp(J, F, lhs->b);
		cexp(J, F, rhs);
		emitline(J, F, exp);
		emit(J, F, OP_SETPROP);
		break;
	case EXP_MEMBER:
		cexp(J, F, lhs->a);
		cexp(J, F, rhs);
		emitline(J, F, exp);
		emitstring(J, F, OP_SETPROP_S, lhs->b->string);
		break;
	default:
		jsC_error(J, lhs, "invalid l-value in assignment");
	}
}

static void cassignforin(JF, js_Ast *stm)
{
	js_Ast *lhs = stm->a;

	if (stm->type == STM_FOR_IN_VAR) {
		if (lhs->b)
			jsC_error(J, lhs->b, "more than one loop variable in for-in statement");
		emitline(J, F, lhs->a);
		emitlocal(J, F, OP_SETLOCAL, OP_SETVAR, lhs->a->a); /* list(var-init(ident)) */
		emit(J, F, OP_POP);
		return;
	}

	switch (lhs->type) {
	case EXP_IDENTIFIER:
		emitline(J, F, lhs);
		emitlocal(J, F, OP_SETLOCAL, OP_SETVAR, lhs);
		emit(J, F, OP_POP);
		break;
	case EXP_INDEX:
		cexp(J, F, lhs->a);
		cexp(J, F, lhs->b);
		emitline(J, F, lhs);
		emit(J, F, OP_ROT3);
		emit(J, F, OP_SETPROP);
		emit(J, F, OP_POP);
		break;
	case EXP_MEMBER:
		cexp(J, F, lhs->a);
		emitline(J, F, lhs);
		emit(J, F, OP_ROT2);
		emitstring(J, F, OP_SETPROP_S, lhs->b->string);
		emit(J, F, OP_POP);
		break;
	default:
		jsC_error(J, lhs, "invalid l-value in for-in loop assignment");
	}
}

static void cassignop1(JF, js_Ast *lhs)
{
	switch (lhs->type) {
	case EXP_IDENTIFIER:
		emitline(J, F, lhs);
		emitlocal(J, F, OP_GETLOCAL, OP_GETVAR, lhs);
		break;
	case EXP_INDEX:
		cexp(J, F, lhs->a);
		cexp(J, F, lhs->b);
		emitline(J, F, lhs);
		emit(J, F, OP_DUP2);
		emit(J, F, OP_GETPROP);
		break;
	case EXP_MEMBER:
		cexp(J, F, lhs->a);
		emitline(J, F, lhs);
		emit(J, F, OP_DUP);
		emitstring(J, F, OP_GETPROP_S, lhs->b->string);
		break;
	default:
		jsC_error(J, lhs, "invalid l-value in assignment");
	}
}

static void cassignop2(JF, js_Ast *lhs, int postfix)
{
	switch (lhs->type) {
	case EXP_IDENTIFIER:
		emitline(J, F, lhs);
		if (postfix) emit(J, F, OP_ROT2);
		emitlocal(J, F, OP_SETLOCAL, OP_SETVAR, lhs);
		break;
	case EXP_INDEX:
		emitline(J, F, lhs);
		if (postfix) emit(J, F, OP_ROT4);
		emit(J, F, OP_SETPROP);
		break;
	case EXP_MEMBER:
		emitline(J, F, lhs);
		if (postfix) emit(J, F, OP_ROT3);
		emitstring(J, F, OP_SETPROP_S, lhs->b->string);
		break;
	default:
		jsC_error(J, lhs, "invalid l-value in assignment");
	}
}

static void cassignop(JF, js_Ast *exp, int opcode)
{
	js_Ast *lhs = exp->a;
	js_Ast *rhs = exp->b;
	cassignop1(J, F, lhs);
	cexp(J, F, rhs);
	emitline(J, F, exp);
	emit(J, F, opcode);
	cassignop2(J, F, lhs, 0);
}

static void cdelete(JF, js_Ast *exp)
{
	js_Ast *arg = exp->a;
	switch (arg->type) {
	case EXP_IDENTIFIER:
		if (F->strict)
			jsC_error(J, exp, "delete on an unqualified name is not allowed in strict mode");
		emitline(J, F, exp);
		emitlocal(J, F, OP_DELLOCAL, OP_DELVAR, arg);
		break;
	case EXP_INDEX:
		cexp(J, F, arg->a);
		cexp(J, F, arg->b);
		emitline(J, F, exp);
		emit(J, F, OP_DELPROP);
		break;
	case EXP_MEMBER:
		cexp(J, F, arg->a);
		emitline(J, F, exp);
		emitstring(J, F, OP_DELPROP_S, arg->b->string);
		break;
	default:
		jsC_error(J, exp, "invalid l-value in delete expression");
	}
}

static void ceval(JF, js_Ast *fun, js_Ast *args)
{
	int n = cargs(J, F, args);
	F->lightweight = 0;
	F->arguments = 1;
	if (n == 0)
		emit(J, F, OP_UNDEF);
	else while (n-- > 1)
		emit(J, F, OP_POP);
	emit(J, F, OP_EVAL);
}

static void ccall(JF, js_Ast *fun, js_Ast *args)
{
	int n;
	switch (fun->type) {
	case EXP_INDEX:
		cexp(J, F, fun->a);
		emit(J, F, OP_DUP);
		cexp(J, F, fun->b);
		emit(J, F, OP_GETPROP);
		emit(J, F, OP_ROT2);
		break;
	case EXP_MEMBER:
		cexp(J, F, fun->a);
		emit(J, F, OP_DUP);
		emitstring(J, F, OP_GETPROP_S, fun->b->string);
		emit(J, F, OP_ROT2);
		break;
	case EXP_IDENTIFIER:
		if (!strcmp(fun->string, "eval")) {
			ceval(J, F, fun, args);
			return;
		}
		/* fallthrough */
	default:
		cexp(J, F, fun);
		emit(J, F, OP_UNDEF);
		break;
	}
	n = cargs(J, F, args);
	emit(J, F, OP_CALL);
	emitarg(J, F, n);
}

static void cexp(JF, js_Ast *exp)
{
	int then, end;
	int n;

	switch (exp->type) {
	case EXP_STRING:
		emitline(J, F, exp);
		emitstring(J, F, OP_STRING, exp->string);
		break;
	case EXP_NUMBER:
		emitline(J, F, exp);
		emitnumber(J, F, exp->number);
		break;
	case EXP_UNDEF:
		emitline(J, F, exp);
		emit(J, F, OP_UNDEF);
		break;
	case EXP_NULL:
		emitline(J, F, exp);
		emit(J, F, OP_NULL);
		break;
	case EXP_TRUE:
		emitline(J, F, exp);
		emit(J, F, OP_TRUE);
		break;
	case EXP_FALSE:
		emitline(J, F, exp);
		emit(J, F, OP_FALSE);
		break;
	case EXP_THIS:
		emitline(J, F, exp);
		emit(J, F, OP_THIS);
		break;

	case EXP_REGEXP:
		emitline(J, F, exp);
		emitstring(J, F, OP_NEWREGEXP, exp->string);
		emitarg(J, F, exp->number);
		break;

	case EXP_OBJECT:
		emitline(J, F, exp);
		emit(J, F, OP_NEWOBJECT);
		cobject(J, F, exp->a);
		break;

	case EXP_ARRAY:
		emitline(J, F, exp);
		emit(J, F, OP_NEWARRAY);
		carray(J, F, exp->a);
		break;

	case EXP_FUN:
		emitline(J, F, exp);
		emitfunction(J, F, newfun(J, exp->line, exp->a, exp->b, exp->c, 0, F->strict));
		break;

	case EXP_IDENTIFIER:
		emitline(J, F, exp);
		emitlocal(J, F, OP_GETLOCAL, OP_GETVAR, exp);
		break;

	case EXP_INDEX:
		cexp(J, F, exp->a);
		cexp(J, F, exp->b);
		emitline(J, F, exp);
		emit(J, F, OP_GETPROP);
		break;

	case EXP_MEMBER:
		cexp(J, F, exp->a);
		emitline(J, F, exp);
		emitstring(J, F, OP_GETPROP_S, exp->b->string);
		break;

	case EXP_CALL:
		ccall(J, F, exp->a, exp->b);
		break;

	case EXP_NEW:
		cexp(J, F, exp->a);
		n = cargs(J, F, exp->b);
		emitline(J, F, exp);
		emit(J, F, OP_NEW);
		emitarg(J, F, n);
		break;

	case EXP_DELETE:
		cdelete(J, F, exp);
		break;

	case EXP_PREINC:
		cassignop1(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_INC);
		cassignop2(J, F, exp->a, 0);
		break;

	case EXP_PREDEC:
		cassignop1(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_DEC);
		cassignop2(J, F, exp->a, 0);
		break;

	case EXP_POSTINC:
		cassignop1(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_POSTINC);
		cassignop2(J, F, exp->a, 1);
		emit(J, F, OP_POP);
		break;

	case EXP_POSTDEC:
		cassignop1(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_POSTDEC);
		cassignop2(J, F, exp->a, 1);
		emit(J, F, OP_POP);
		break;

	case EXP_VOID:
		cexp(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_POP);
		emit(J, F, OP_UNDEF);
		break;

	case EXP_TYPEOF: ctypeof(J, F, exp); break;
	case EXP_POS: cunary(J, F, exp, OP_POS); break;
	case EXP_NEG: cunary(J, F, exp, OP_NEG); break;
	case EXP_BITNOT: cunary(J, F, exp, OP_BITNOT); break;
	case EXP_LOGNOT: cunary(J, F, exp, OP_LOGNOT); break;

	case EXP_BITOR: cbinary(J, F, exp, OP_BITOR); break;
	case EXP_BITXOR: cbinary(J, F, exp, OP_BITXOR); break;
	case EXP_BITAND: cbinary(J, F, exp, OP_BITAND); break;
	case EXP_EQ: cbinary(J, F, exp, OP_EQ); break;
	case EXP_NE: cbinary(J, F, exp, OP_NE); break;
	case EXP_STRICTEQ: cbinary(J, F, exp, OP_STRICTEQ); break;
	case EXP_STRICTNE: cbinary(J, F, exp, OP_STRICTNE); break;
	case EXP_LT: cbinary(J, F, exp, OP_LT); break;
	case EXP_GT: cbinary(J, F, exp, OP_GT); break;
	case EXP_LE: cbinary(J, F, exp, OP_LE); break;
	case EXP_GE: cbinary(J, F, exp, OP_GE); break;
	case EXP_INSTANCEOF: cbinary(J, F, exp, OP_INSTANCEOF); break;
	case EXP_IN: cbinary(J, F, exp, OP_IN); break;
	case EXP_SHL: cbinary(J, F, exp, OP_SHL); break;
	case EXP_SHR: cbinary(J, F, exp, OP_SHR); break;
	case EXP_USHR: cbinary(J, F, exp, OP_USHR); break;
	case EXP_ADD: cbinary(J, F, exp, OP_ADD); break;
	case EXP_SUB: cbinary(J, F, exp, OP_SUB); break;
	case EXP_MUL: cbinary(J, F, exp, OP_MUL); break;
	case EXP_DIV: cbinary(J, F, exp, OP_DIV); break;
	case EXP_MOD: cbinary(J, F, exp, OP_MOD); break;

	case EXP_ASS: cassign(J, F, exp); break;
	case EXP_ASS_MUL: cassignop(J, F, exp, OP_MUL); break;
	case EXP_ASS_DIV: cassignop(J, F, exp, OP_DIV); break;
	case EXP_ASS_MOD: cassignop(J, F, exp, OP_MOD); break;
	case EXP_ASS_ADD: cassignop(J, F, exp, OP_ADD); break;
	case EXP_ASS_SUB: cassignop(J, F, exp, OP_SUB); break;
	case EXP_ASS_SHL: cassignop(J, F, exp, OP_SHL); break;
	case EXP_ASS_SHR: cassignop(J, F, exp, OP_SHR); break;
	case EXP_ASS_USHR: cassignop(J, F, exp, OP_USHR); break;
	case EXP_ASS_BITAND: cassignop(J, F, exp, OP_BITAND); break;
	case EXP_ASS_BITXOR: cassignop(J, F, exp, OP_BITXOR); break;
	case EXP_ASS_BITOR: cassignop(J, F, exp, OP_BITOR); break;

	case EXP_COMMA:
		cexp(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_POP);
		cexp(J, F, exp->b);
		break;

	case EXP_LOGOR:
		cexp(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_DUP);
		end = emitjump(J, F, OP_JTRUE);
		emit(J, F, OP_POP);
		cexp(J, F, exp->b);
		label(J, F, end);
		break;

	case EXP_LOGAND:
		cexp(J, F, exp->a);
		emitline(J, F, exp);
		emit(J, F, OP_DUP);
		end = emitjump(J, F, OP_JFALSE);
		emit(J, F, OP_POP);
		cexp(J, F, exp->b);
		label(J, F, end);
		break;

	case EXP_COND:
		cexp(J, F, exp->a);
		emitline(J, F, exp);
		then = emitjump(J, F, OP_JTRUE);
		cexp(J, F, exp->c);
		end = emitjump(J, F, OP_JUMP);
		label(J, F, then);
		cexp(J, F, exp->b);
		label(J, F, end);
		break;

	default:
		jsC_error(J, exp, "unknown expression: (%s)", jsP_aststring(exp->type));
	}
}

/* Patch break and continue statements */

static void addjump(JF, enum js_AstType type, js_Ast *target, int inst)
{
	js_JumpList *jump = js_malloc(J, sizeof *jump);
	jump->type = type;
	jump->inst = inst;
	jump->next = target->jumps;
	target->jumps = jump;
}

static void labeljumps(JF, js_Ast *stm, int baddr, int caddr)
{
	js_JumpList *jump = stm->jumps;
	while (jump) {
		js_JumpList *next = jump->next;
		if (jump->type == STM_BREAK)
			labelto(J, F, jump->inst, baddr);
		if (jump->type == STM_CONTINUE)
			labelto(J, F, jump->inst, caddr);
		js_free(J, jump);
		jump = next;
	}
	stm->jumps = NULL;
}

static int isloop(enum js_AstType T)
{
	return T == STM_DO || T == STM_WHILE ||
		T == STM_FOR || T == STM_FOR_VAR ||
		T == STM_FOR_IN || T == STM_FOR_IN_VAR;
}

static int isfun(enum js_AstType T)
{
	return T == AST_FUNDEC || T == EXP_FUN || T == EXP_PROP_GET || T == EXP_PROP_SET;
}

static int matchlabel(js_Ast *node, const char *label)
{
	while (node && node->type == STM_LABEL) {
		if (!strcmp(node->a->string, label))
			return 1;
		node = node->parent;
	}
	return 0;
}

static js_Ast *breaktarget(JF, js_Ast *node, const char *label)
{
	while (node) {
		if (isfun(node->type))
			break;
		if (!label) {
			if (isloop(node->type) || node->type == STM_SWITCH)
				return node;
		} else {
			if (matchlabel(node->parent, label))
				return node;
		}
		node = node->parent;
	}
	return NULL;
}

static js_Ast *continuetarget(JF, js_Ast *node, const char *label)
{
	while (node) {
		if (isfun(node->type))
			break;
		if (isloop(node->type)) {
			if (!label)
				return node;
			else if (matchlabel(node->parent, label))
				return node;
		}
		node = node->parent;
	}
	return NULL;
}

static js_Ast *returntarget(JF, js_Ast *node)
{
	while (node) {
		if (isfun(node->type))
			return node;
		node = node->parent;
	}
	return NULL;
}

/* Emit code to rebalance stack and scopes during an abrupt exit */

static void cexit(JF, enum js_AstType T, js_Ast *node, js_Ast *target)
{
	js_Ast *prev;
	do {
		prev = node, node = node->parent;
		switch (node->type) {
		default:
			/* impossible */
			break;
		case STM_WITH:
			emitline(J, F, node);
			emit(J, F, OP_ENDWITH);
			break;
		case STM_FOR_IN:
		case STM_FOR_IN_VAR:
			emitline(J, F, node);
			/* pop the iterator if leaving the loop */
			if (F->script) {
				if (T == STM_RETURN || T == STM_BREAK || (T == STM_CONTINUE && target != node)) {
					/* pop the iterator, save the return or exp value */
					emit(J, F, OP_ROT2);
					emit(J, F, OP_POP);
				}
				if (T == STM_CONTINUE)
					emit(J, F, OP_ROT2); /* put the iterator back on top */
			} else {
				if (T == STM_RETURN) {
					/* pop the iterator, save the return value */
					emit(J, F, OP_ROT2);
					emit(J, F, OP_POP);
				}
				if (T == STM_BREAK || (T == STM_CONTINUE && target != node))
					emit(J, F, OP_POP); /* pop the iterator */
			}
			break;
		case STM_TRY:
			emitline(J, F, node);
			/* came from try block */
			if (prev == node->a) {
				emit(J, F, OP_ENDTRY);
				if (node->d) cstm(J, F, node->d); /* finally */
			}
			/* came from catch block */
			if (prev == node->c) {
				/* ... with finally */
				if (node->d) {
					emit(J, F, OP_ENDCATCH);
					emit(J, F, OP_ENDTRY);
					cstm(J, F, node->d); /* finally */
				} else {
					emit(J, F, OP_ENDCATCH);
				}
			}
			break;
		}
	} while (node != target);
}

/* Try/catch/finally */

static void ctryfinally(JF, js_Ast *trystm, js_Ast *finallystm)
{
	int L1;
	L1 = emitjump(J, F, OP_TRY);
	{
		/* if we get here, we have caught an exception in the try block */
		cstm(J, F, finallystm); /* inline finally block */
		emit(J, F, OP_THROW); /* rethrow exception */
	}
	label(J, F, L1);
	cstm(J, F, trystm);
	emit(J, F, OP_ENDTRY);
	cstm(J, F, finallystm);
}

static void ctrycatch(JF, js_Ast *trystm, js_Ast *catchvar, js_Ast *catchstm)
{
	int L1, L2;
	L1 = emitjump(J, F, OP_TRY);
	{
		/* if we get here, we have caught an exception in the try block */
		checkfutureword(J, F, catchvar);
		if (F->strict) {
			if (!strcmp(catchvar->string, "arguments"))
				jsC_error(J, catchvar, "redefining 'arguments' is not allowed in strict mode");
			if (!strcmp(catchvar->string, "eval"))
				jsC_error(J, catchvar, "redefining 'eval' is not allowed in strict mode");
		}
		emitline(J, F, catchvar);
		emitstring(J, F, OP_CATCH, catchvar->string);
		cstm(J, F, catchstm);
		emit(J, F, OP_ENDCATCH);
		L2 = emitjump(J, F, OP_JUMP); /* skip past the try block */
	}
	label(J, F, L1);
	cstm(J, F, trystm);
	emit(J, F, OP_ENDTRY);
	label(J, F, L2);
}

static void ctrycatchfinally(JF, js_Ast *trystm, js_Ast *catchvar, js_Ast *catchstm, js_Ast *finallystm)
{
	int L1, L2, L3;
	L1 = emitjump(J, F, OP_TRY);
	{
		/* if we get here, we have caught an exception in the try block */
		L2 = emitjump(J, F, OP_TRY);
		{
			/* if we get here, we have caught an exception in the catch block */
			cstm(J, F, finallystm); /* inline finally block */
			emit(J, F, OP_THROW); /* rethrow exception */
		}
		label(J, F, L2);
		if (F->strict) {
			checkfutureword(J, F, catchvar);
			if (!strcmp(catchvar->string, "arguments"))
				jsC_error(J, catchvar, "redefining 'arguments' is not allowed in strict mode");
			if (!strcmp(catchvar->string, "eval"))
				jsC_error(J, catchvar, "redefining 'eval' is not allowed in strict mode");
		}
		emitline(J, F, catchvar);
		emitstring(J, F, OP_CATCH, catchvar->string);
		cstm(J, F, catchstm);
		emit(J, F, OP_ENDCATCH);
		emit(J, F, OP_ENDTRY);
		L3 = emitjump(J, F, OP_JUMP); /* skip past the try block to the finally block */
	}
	label(J, F, L1);
	cstm(J, F, trystm);
	emit(J, F, OP_ENDTRY);
	label(J, F, L3);
	cstm(J, F, finallystm);
}

/* Switch */

static void cswitch(JF, js_Ast *ref, js_Ast *head)
{
	js_Ast *node, *clause, *def = NULL;
	int end;

	cexp(J, F, ref);

	/* emit an if-else chain of tests for the case clause expressions */
	for (node = head; node; node = node->b) {
		clause = node->a;
		if (clause->type == STM_DEFAULT) {
			if (def)
				jsC_error(J, clause, "more than one default label in switch");
			def = clause;
		} else {
			cexp(J, F, clause->a);
			emitline(J, F, clause);
			clause->casejump = emitjump(J, F, OP_JCASE);
		}
	}
	emit(J, F, OP_POP);
	if (def) {
		emitline(J, F, def);
		def->casejump = emitjump(J, F, OP_JUMP);
		end = 0;
	} else {
		end = emitjump(J, F, OP_JUMP);
	}

	/* emit the case clause bodies */
	for (node = head; node; node = node->b) {
		clause = node->a;
		label(J, F, clause->casejump);
		if (clause->type == STM_DEFAULT)
			cstmlist(J, F, clause->a);
		else
			cstmlist(J, F, clause->b);
	}

	if (end)
		label(J, F, end);
}

/* Statements */

static void cvarinit(JF, js_Ast *list)
{
	while (list) {
		js_Ast *var = list->a;
		if (var->b) {
			cexp(J, F, var->b);
			emitline(J, F, var);
			emitlocal(J, F, OP_SETLOCAL, OP_SETVAR, var->a);
			emit(J, F, OP_POP);
		}
		list = list->b;
	}
}

static void cstm(JF, js_Ast *stm)
{
	js_Ast *target;
	int loop, cont, then, end;

	emitline(J, F, stm);

	switch (stm->type) {
	case AST_FUNDEC:
		break;

	case STM_BLOCK:
		cstmlist(J, F, stm->a);
		break;

	case STM_EMPTY:
		if (F->script) {
			emitline(J, F, stm);
			emit(J, F, OP_POP);
			emit(J, F, OP_UNDEF);
		}
		break;

	case STM_VAR:
		cvarinit(J, F, stm->a);
		break;

	case STM_IF:
		if (stm->c) {
			cexp(J, F, stm->a);
			emitline(J, F, stm);
			then = emitjump(J, F, OP_JTRUE);
			cstm(J, F, stm->c);
			emitline(J, F, stm);
			end = emitjump(J, F, OP_JUMP);
			label(J, F, then);
			cstm(J, F, stm->b);
			label(J, F, end);
		} else {
			cexp(J, F, stm->a);
			emitline(J, F, stm);
			end = emitjump(J, F, OP_JFALSE);
			cstm(J, F, stm->b);
			label(J, F, end);
		}
		break;

	case STM_DO:
		loop = here(J, F);
		cstm(J, F, stm->a);
		cont = here(J, F);
		cexp(J, F, stm->b);
		emitline(J, F, stm);
		emitjumpto(J, F, OP_JTRUE, loop);
		labeljumps(J, F, stm, here(J,F), cont);
		break;

	case STM_WHILE:
		loop = here(J, F);
		cexp(J, F, stm->a);
		emitline(J, F, stm);
		end = emitjump(J, F, OP_JFALSE);
		cstm(J, F, stm->b);
		emitline(J, F, stm);
		emitjumpto(J, F, OP_JUMP, loop);
		label(J, F, end);
		labeljumps(J, F, stm, here(J,F), loop);
		break;

	case STM_FOR:
	case STM_FOR_VAR:
		if (stm->type == STM_FOR_VAR) {
			cvarinit(J, F, stm->a);
		} else {
			if (stm->a) {
				cexp(J, F, stm->a);
				emit(J, F, OP_POP);
			}
		}
		loop = here(J, F);
		if (stm->b) {
			cexp(J, F, stm->b);
			emitline(J, F, stm);
			end = emitjump(J, F, OP_JFALSE);
		} else {
			end = 0;
		}
		cstm(J, F, stm->d);
		cont = here(J, F);
		if (stm->c) {
			cexp(J, F, stm->c);
			emit(J, F, OP_POP);
		}
		emitline(J, F, stm);
		emitjumpto(J, F, OP_JUMP, loop);
		if (end)
			label(J, F, end);
		labeljumps(J, F, stm, here(J,F), cont);
		break;

	case STM_FOR_IN:
	case STM_FOR_IN_VAR:
		cexp(J, F, stm->b);
		emitline(J, F, stm);
		emit(J, F, OP_ITERATOR);
		loop = here(J, F);
		{
			emitline(J, F, stm);
			emit(J, F, OP_NEXTITER);
			end = emitjump(J, F, OP_JFALSE);
			cassignforin(J, F, stm);
			if (F->script) {
				emit(J, F, OP_ROT2);
				cstm(J, F, stm->c);
				emit(J, F, OP_ROT2);
			} else {
				cstm(J, F, stm->c);
			}
			emitline(J, F, stm);
			emitjumpto(J, F, OP_JUMP, loop);
		}
		label(J, F, end);
		labeljumps(J, F, stm, here(J,F), loop);
		break;

	case STM_SWITCH:
		cswitch(J, F, stm->a, stm->b);
		labeljumps(J, F, stm, here(J,F), 0);
		break;

	case STM_LABEL:
		cstm(J, F, stm->b);
		/* skip consecutive labels */
		while (stm->type == STM_LABEL)
			stm = stm->b;
		/* loops and switches have already been labelled */
		if (!isloop(stm->type) && stm->type != STM_SWITCH)
			labeljumps(J, F, stm, here(J,F), 0);
		break;

	case STM_BREAK:
		if (stm->a) {
			checkfutureword(J, F, stm->a);
			target = breaktarget(J, F, stm->parent, stm->a->string);
			if (!target)
				jsC_error(J, stm, "break label '%s' not found", stm->a->string);
		} else {
			target = breaktarget(J, F, stm->parent, NULL);
			if (!target)
				jsC_error(J, stm, "unlabelled break must be inside loop or switch");
		}
		cexit(J, F, STM_BREAK, stm, target);
		emitline(J, F, stm);
		addjump(J, F, STM_BREAK, target, emitjump(J, F, OP_JUMP));
		break;

	case STM_CONTINUE:
		if (stm->a) {
			checkfutureword(J, F, stm->a);
			target = continuetarget(J, F, stm->parent, stm->a->string);
			if (!target)
				jsC_error(J, stm, "continue label '%s' not found", stm->a->string);
		} else {
			target = continuetarget(J, F, stm->parent, NULL);
			if (!target)
				jsC_error(J, stm, "continue must be inside loop");
		}
		cexit(J, F, STM_CONTINUE, stm, target);
		emitline(J, F, stm);
		addjump(J, F, STM_CONTINUE, target, emitjump(J, F, OP_JUMP));
		break;

	case STM_RETURN:
		if (stm->a)
			cexp(J, F, stm->a);
		else
			emit(J, F, OP_UNDEF);
		target = returntarget(J, F, stm->parent);
		if (!target)
			jsC_error(J, stm, "return not in function");
		cexit(J, F, STM_RETURN, stm, target);
		emitline(J, F, stm);
		emit(J, F, OP_RETURN);
		break;

	case STM_THROW:
		cexp(J, F, stm->a);
		emitline(J, F, stm);
		emit(J, F, OP_THROW);
		break;

	case STM_WITH:
		F->lightweight = 0;
		if (F->strict)
			jsC_error(J, stm->a, "'with' statements are not allowed in strict mode");
		cexp(J, F, stm->a);
		emitline(J, F, stm);
		emit(J, F, OP_WITH);
		cstm(J, F, stm->b);
		emitline(J, F, stm);
		emit(J, F, OP_ENDWITH);
		break;

	case STM_TRY:
		emitline(J, F, stm);
		if (stm->b && stm->c) {
			F->lightweight = 0;
			if (stm->d)
				ctrycatchfinally(J, F, stm->a, stm->b, stm->c, stm->d);
			else
				ctrycatch(J, F, stm->a, stm->b, stm->c);
		} else {
			ctryfinally(J, F, stm->a, stm->d);
		}
		break;

	case STM_DEBUGGER:
		emitline(J, F, stm);
		emit(J, F, OP_DEBUGGER);
		break;

	default:
		if (F->script) {
			emitline(J, F, stm);
			emit(J, F, OP_POP);
			cexp(J, F, stm);
		} else {
			cexp(J, F, stm);
			emitline(J, F, stm);
			emit(J, F, OP_POP);
		}
		break;
	}
}

static void cstmlist(JF, js_Ast *list)
{
	while (list) {
		cstm(J, F, list->a);
		list = list->b;
	}
}

/* Declarations and programs */

static int listlength(js_Ast *list)
{
	int n = 0;
	while (list) ++n, list = list->b;
	return n;
}

static void cparams(JF, js_Ast *list, js_Ast *fname)
{
	F->numparams = listlength(list);
	while (list) {
		checkfutureword(J, F, list->a);
		addlocal(J, F, list->a, 0);
		list = list->b;
	}
}

static void cvardecs(JF, js_Ast *node)
{
	if (node->type == AST_LIST) {
		while (node) {
			cvardecs(J, F, node->a);
			node = node->b;
		}
		return;
	}

	if (isfun(node->type))
		return; /* stop at inner functions */

	if (node->type == EXP_VAR) {
		checkfutureword(J, F, node->a);
		addlocal(J, F, node->a, 1);
	}

	if (node->a) cvardecs(J, F, node->a);
	if (node->b) cvardecs(J, F, node->b);
	if (node->c) cvardecs(J, F, node->c);
	if (node->d) cvardecs(J, F, node->d);
}

static void cfundecs(JF, js_Ast *list)
{
	while (list) {
		js_Ast *stm = list->a;
		if (stm->type == AST_FUNDEC) {
			emitline(J, F, stm);
			emitfunction(J, F, newfun(J, stm->line, stm->a, stm->b, stm->c, 0, F->strict));
			emitline(J, F, stm);
			emit(J, F, OP_SETLOCAL);
			emitarg(J, F, addlocal(J, F, stm->a, 1));
			emit(J, F, OP_POP);
		}
		list = list->b;
	}
}

static void cfunbody(JF, js_Ast *name, js_Ast *params, js_Ast *body)
{
	F->lightweight = 1;
	F->arguments = 0;

	if (F->script)
		F->lightweight = 0;

	/* Check if first statement is 'use strict': */
	if (body && body->type == AST_LIST && body->a && body->a->type == EXP_STRING)
		if (!strcmp(body->a->string, "use strict"))
			F->strict = 1;

	F->lastline = F->line;

	cparams(J, F, params, name);

	if (body) {
		cvardecs(J, F, body);
		cfundecs(J, F, body);
	}

	if (name) {
		checkfutureword(J, F, name);
		if (findlocal(J, F, name->string) < 0) {
			emit(J, F, OP_CURRENT);
			emit(J, F, OP_SETLOCAL);
			emitarg(J, F, addlocal(J, F, name, 1));
			emit(J, F, OP_POP);
		}
	}

	if (F->script) {
		emit(J, F, OP_UNDEF);
		cstmlist(J, F, body);
		emit(J, F, OP_RETURN);
	} else {
		cstmlist(J, F, body);
		emit(J, F, OP_UNDEF);
		emit(J, F, OP_RETURN);
	}
}

js_Function *jsC_compilefunction(js_State *J, js_Ast *prog)
{
	return newfun(J, prog->line, prog->a, prog->b, prog->c, 0, J->default_strict);
}

js_Function *jsC_compilescript(js_State *J, js_Ast *prog, int default_strict)
{
	return newfun(J, prog ? prog->line : 0, NULL, NULL, prog, 1, default_strict);
}
