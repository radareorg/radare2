#include "jsi.h"
#include "jslex.h"
#include "jsparse.h"

#define LIST(h)			jsP_newnode(J, AST_LIST, 0, h, 0, 0, 0)

#define EXP0(x)			jsP_newnode(J, EXP_ ## x, line, 0, 0, 0, 0)
#define EXP1(x,a)		jsP_newnode(J, EXP_ ## x, line, a, 0, 0, 0)
#define EXP2(x,a,b)		jsP_newnode(J, EXP_ ## x, line, a, b, 0, 0)
#define EXP3(x,a,b,c)		jsP_newnode(J, EXP_ ## x, line, a, b, c, 0)

#define STM0(x)			jsP_newnode(J, STM_ ## x, line, 0, 0, 0, 0)
#define STM1(x,a)		jsP_newnode(J, STM_ ## x, line, a, 0, 0, 0)
#define STM2(x,a,b)		jsP_newnode(J, STM_ ## x, line, a, b, 0, 0)
#define STM3(x,a,b,c)		jsP_newnode(J, STM_ ## x, line, a, b, c, 0)
#define STM4(x,a,b,c,d)		jsP_newnode(J, STM_ ## x, line, a, b, c, d)

static js_Ast *expression(js_State *J, int notin);
static js_Ast *assignment(js_State *J, int notin);
static js_Ast *memberexp(js_State *J);
static js_Ast *statement(js_State *J);
static js_Ast *funbody(js_State *J);

JS_NORETURN static void jsP_error(js_State *J, const char *fmt, ...) JS_PRINTFLIKE(2,3);

#define INCREC() if (++J->astdepth > JS_ASTLIMIT) jsP_error(J, "too much recursion")
#define DECREC() --J->astdepth
#define SAVEREC() int SAVE=J->astdepth
#define POPREC() J->astdepth=SAVE

static void jsP_error(js_State *J, const char *fmt, ...)
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

static void jsP_warning(js_State *J, const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	char msg[256];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof msg, fmt, ap);
	va_end(ap);

	snprintf(buf, sizeof buf, "%s:%d: warning: %s", J->filename, J->lexline, msg);
	js_report(J, buf);
}

static js_Ast *jsP_newnode(js_State *J, enum js_AstType type, int line, js_Ast *a, js_Ast *b, js_Ast *c, js_Ast *d)
{
	js_Ast *node = js_malloc(J, sizeof *node);

	node->type = type;
	node->line = line;
	node->a = a;
	node->b = b;
	node->c = c;
	node->d = d;
	node->number = 0;
	node->string = NULL;
	node->jumps = NULL;
	node->casejump = 0;

	node->parent = NULL;
	if (a) a->parent = node;
	if (b) b->parent = node;
	if (c) c->parent = node;
	if (d) d->parent = node;

	node->gcnext = J->gcast;
	J->gcast = node;

	return node;
}

static js_Ast *jsP_list(js_Ast *head)
{
	/* set parent pointers in list nodes */
	js_Ast *prev = head, *node = head->b;
	while (node) {
		node->parent = prev;
		prev = node;
		node = node->b;
	}
	return head;
}

static js_Ast *jsP_newstrnode(js_State *J, enum js_AstType type, const char *s)
{
	js_Ast *node = jsP_newnode(J, type, J->lexline, 0, 0, 0, 0);
	node->string = s;
	return node;
}

static js_Ast *jsP_newnumnode(js_State *J, enum js_AstType type, double n)
{
	js_Ast *node = jsP_newnode(J, type, J->lexline, 0, 0, 0, 0);
	node->number = n;
	return node;
}

static void jsP_freejumps(js_State *J, js_JumpList *node)
{
	while (node) {
		js_JumpList *next = node->next;
		js_free(J, node);
		node = next;
	}
}

void jsP_freeparse(js_State *J)
{
	js_Ast *node = J->gcast;
	while (node) {
		js_Ast *next = node->gcnext;
		jsP_freejumps(J, node->jumps);
		js_free(J, node);
		node = next;
	}
	J->gcast = NULL;
}

/* Lookahead */

static void jsP_next(js_State *J)
{
	J->lookahead = jsY_lex(J);
}

#define jsP_accept(J,x) (J->lookahead == x ? (jsP_next(J), 1) : 0)

#define jsP_expect(J,x) if (!jsP_accept(J, x)) jsP_error(J, "unexpected token: %s (expected %s)", jsY_tokenstring(J->lookahead), jsY_tokenstring(x))

static void semicolon(js_State *J)
{
	if (J->lookahead == ';') {
		jsP_next(J);
		return;
	}
	if (J->newline || J->lookahead == '}' || J->lookahead == 0)
		return;
	jsP_error(J, "unexpected token: %s (expected ';')", jsY_tokenstring(J->lookahead));
}

/* Literals */

static js_Ast *identifier(js_State *J)
{
	js_Ast *a;
	if (J->lookahead == TK_IDENTIFIER) {
		a = jsP_newstrnode(J, AST_IDENTIFIER, J->text);
		jsP_next(J);
		return a;
	}
	jsP_error(J, "unexpected token: %s (expected identifier)", jsY_tokenstring(J->lookahead));
}

static js_Ast *identifieropt(js_State *J)
{
	if (J->lookahead == TK_IDENTIFIER)
		return identifier(J);
	return NULL;
}

static js_Ast *identifiername(js_State *J)
{
	if (J->lookahead == TK_IDENTIFIER || J->lookahead >= TK_BREAK) {
		js_Ast *a = jsP_newstrnode(J, AST_IDENTIFIER, J->text);
		jsP_next(J);
		return a;
	}
	jsP_error(J, "unexpected token: %s (expected identifier or keyword)", jsY_tokenstring(J->lookahead));
}

static js_Ast *arrayelement(js_State *J)
{
	int line = J->lexline;
	if (J->lookahead == ',')
		return EXP0(UNDEF);
	return assignment(J, 0);
}

static js_Ast *arrayliteral(js_State *J)
{
	js_Ast *head, *tail;
	if (J->lookahead == ']')
		return NULL;
	head = tail = LIST(arrayelement(J));
	while (jsP_accept(J, ',')) {
		if (J->lookahead != ']')
			tail = tail->b = LIST(arrayelement(J));
	}
	return jsP_list(head);
}

static js_Ast *propname(js_State *J)
{
	js_Ast *name;
	if (J->lookahead == TK_NUMBER) {
		name = jsP_newnumnode(J, EXP_NUMBER, J->number);
		jsP_next(J);
	} else if (J->lookahead == TK_STRING) {
		name = jsP_newstrnode(J, EXP_STRING, J->text);
		jsP_next(J);
	} else {
		name = identifiername(J);
	}
	return name;
}

static js_Ast *propassign(js_State *J)
{
	js_Ast *name, *value, *arg, *body;
	int line = J->lexline;

	name = propname(J);

	if (J->lookahead != ':' && name->type == AST_IDENTIFIER) {
		if (!strcmp(name->string, "get")) {
			name = propname(J);
			jsP_expect(J, '(');
			jsP_expect(J, ')');
			body = funbody(J);
			return EXP3(PROP_GET, name, NULL, body);
		}
		if (!strcmp(name->string, "set")) {
			name = propname(J);
			jsP_expect(J, '(');
			arg = identifier(J);
			jsP_expect(J, ')');
			body = funbody(J);
			return EXP3(PROP_SET, name, LIST(arg), body);
		}
	}

	jsP_expect(J, ':');
	value = assignment(J, 0);
	return EXP2(PROP_VAL, name, value);
}

static js_Ast *objectliteral(js_State *J)
{
	js_Ast *head, *tail;
	if (J->lookahead == '}')
		return NULL;
	head = tail = LIST(propassign(J));
	while (jsP_accept(J, ',')) {
		if (J->lookahead == '}')
			break;
		tail = tail->b = LIST(propassign(J));
	}
	return jsP_list(head);
}

/* Functions */

static js_Ast *parameters(js_State *J)
{
	js_Ast *head, *tail;
	if (J->lookahead == ')')
		return NULL;
	head = tail = LIST(identifier(J));
	while (jsP_accept(J, ',')) {
		tail = tail->b = LIST(identifier(J));
	}
	return jsP_list(head);
}

static js_Ast *fundec(js_State *J, int line)
{
	js_Ast *a, *b, *c;
	a = identifier(J);
	jsP_expect(J, '(');
	b = parameters(J);
	jsP_expect(J, ')');
	c = funbody(J);
	return jsP_newnode(J, AST_FUNDEC, line, a, b, c, 0);
}

static js_Ast *funstm(js_State *J, int line)
{
	js_Ast *a, *b, *c;
	a = identifier(J);
	jsP_expect(J, '(');
	b = parameters(J);
	jsP_expect(J, ')');
	c = funbody(J);
	/* rewrite function statement as "var X = function X() {}" */
	return STM1(VAR, LIST(EXP2(VAR, a, EXP3(FUN, a, b, c))));
}

static js_Ast *funexp(js_State *J, int line)
{
	js_Ast *a, *b, *c;
	a = identifieropt(J);
	jsP_expect(J, '(');
	b = parameters(J);
	jsP_expect(J, ')');
	c = funbody(J);
	return EXP3(FUN, a, b, c);
}

/* Expressions */

static js_Ast *primary(js_State *J)
{
	js_Ast *a;
	int line = J->lexline;

	if (J->lookahead == TK_IDENTIFIER) {
		a = jsP_newstrnode(J, EXP_IDENTIFIER, J->text);
		jsP_next(J);
		return a;
	}
	if (J->lookahead == TK_STRING) {
		a = jsP_newstrnode(J, EXP_STRING, J->text);
		jsP_next(J);
		return a;
	}
	if (J->lookahead == TK_REGEXP) {
		a = jsP_newstrnode(J, EXP_REGEXP, J->text);
		a->number = J->number;
		jsP_next(J);
		return a;
	}
	if (J->lookahead == TK_NUMBER) {
		a = jsP_newnumnode(J, EXP_NUMBER, J->number);
		jsP_next(J);
		return a;
	}

	if (jsP_accept(J, TK_THIS)) return EXP0(THIS);
	if (jsP_accept(J, TK_NULL)) return EXP0(NULL);
	if (jsP_accept(J, TK_TRUE)) return EXP0(TRUE);
	if (jsP_accept(J, TK_FALSE)) return EXP0(FALSE);
	if (jsP_accept(J, '{')) {
		a = EXP1(OBJECT, objectliteral(J));
		jsP_expect(J, '}');
		return a;
	}
	if (jsP_accept(J, '[')) {
		a = EXP1(ARRAY, arrayliteral(J));
		jsP_expect(J, ']');
		return a;
	}
	if (jsP_accept(J, '(')) {
		a = expression(J, 0);
		jsP_expect(J, ')');
		return a;
	}

	jsP_error(J, "unexpected token in expression: %s", jsY_tokenstring(J->lookahead));
}

static js_Ast *arguments(js_State *J)
{
	js_Ast *head, *tail;
	if (J->lookahead == ')')
		return NULL;
	head = tail = LIST(assignment(J, 0));
	while (jsP_accept(J, ',')) {
		tail = tail->b = LIST(assignment(J, 0));
	}
	return jsP_list(head);
}

static js_Ast *newexp(js_State *J)
{
	js_Ast *a, *b;
	int line = J->lexline;

	if (jsP_accept(J, TK_NEW)) {
		a = memberexp(J);
		if (jsP_accept(J, '(')) {
			b = arguments(J);
			jsP_expect(J, ')');
			return EXP2(NEW, a, b);
		}
		return EXP1(NEW, a);
	}

	if (jsP_accept(J, TK_FUNCTION))
		return funexp(J, line);

	return primary(J);
}

static js_Ast *memberexp(js_State *J)
{
	js_Ast *a = newexp(J);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, '.')) { a = EXP2(MEMBER, a, identifiername(J)); goto loop; }
	if (jsP_accept(J, '[')) { a = EXP2(INDEX, a, expression(J, 0)); jsP_expect(J, ']'); goto loop; }
	POPREC();
	return a;
}

static js_Ast *callexp(js_State *J)
{
	js_Ast *a = newexp(J);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, '.')) { a = EXP2(MEMBER, a, identifiername(J)); goto loop; }
	if (jsP_accept(J, '[')) { a = EXP2(INDEX, a, expression(J, 0)); jsP_expect(J, ']'); goto loop; }
	if (jsP_accept(J, '(')) { a = EXP2(CALL, a, arguments(J)); jsP_expect(J, ')'); goto loop; }
	POPREC();
	return a;
}

static js_Ast *postfix(js_State *J)
{
	js_Ast *a = callexp(J);
	int line = J->lexline;
	if (!J->newline && jsP_accept(J, TK_INC)) return EXP1(POSTINC, a);
	if (!J->newline && jsP_accept(J, TK_DEC)) return EXP1(POSTDEC, a);
	return a;
}

static js_Ast *unary(js_State *J)
{
	js_Ast *a;
	int line = J->lexline;
	INCREC();
	if (jsP_accept(J, TK_DELETE)) a = EXP1(DELETE, unary(J));
	else if (jsP_accept(J, TK_VOID)) a = EXP1(VOID, unary(J));
	else if (jsP_accept(J, TK_TYPEOF)) a = EXP1(TYPEOF, unary(J));
	else if (jsP_accept(J, TK_INC)) a = EXP1(PREINC, unary(J));
	else if (jsP_accept(J, TK_DEC)) a = EXP1(PREDEC, unary(J));
	else if (jsP_accept(J, '+')) a = EXP1(POS, unary(J));
	else if (jsP_accept(J, '-')) a = EXP1(NEG, unary(J));
	else if (jsP_accept(J, '~')) a = EXP1(BITNOT, unary(J));
	else if (jsP_accept(J, '!')) a = EXP1(LOGNOT, unary(J));
	else a = postfix(J);
	DECREC();
	return a;
}

static js_Ast *multiplicative(js_State *J)
{
	js_Ast *a = unary(J);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, '*')) { a = EXP2(MUL, a, unary(J)); goto loop; }
	if (jsP_accept(J, '/')) { a = EXP2(DIV, a, unary(J)); goto loop; }
	if (jsP_accept(J, '%')) { a = EXP2(MOD, a, unary(J)); goto loop; }
	POPREC();
	return a;
}

static js_Ast *additive(js_State *J)
{
	js_Ast *a = multiplicative(J);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, '+')) { a = EXP2(ADD, a, multiplicative(J)); goto loop; }
	if (jsP_accept(J, '-')) { a = EXP2(SUB, a, multiplicative(J)); goto loop; }
	POPREC();
	return a;
}

static js_Ast *shift(js_State *J)
{
	js_Ast *a = additive(J);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, TK_SHL)) { a = EXP2(SHL, a, additive(J)); goto loop; }
	if (jsP_accept(J, TK_SHR)) { a = EXP2(SHR, a, additive(J)); goto loop; }
	if (jsP_accept(J, TK_USHR)) { a = EXP2(USHR, a, additive(J)); goto loop; }
	POPREC();
	return a;
}

static js_Ast *relational(js_State *J, int notin)
{
	js_Ast *a = shift(J);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, '<')) { a = EXP2(LT, a, shift(J)); goto loop; }
	if (jsP_accept(J, '>')) { a = EXP2(GT, a, shift(J)); goto loop; }
	if (jsP_accept(J, TK_LE)) { a = EXP2(LE, a, shift(J)); goto loop; }
	if (jsP_accept(J, TK_GE)) { a = EXP2(GE, a, shift(J)); goto loop; }
	if (jsP_accept(J, TK_INSTANCEOF)) { a = EXP2(INSTANCEOF, a, shift(J)); goto loop; }
	if (!notin && jsP_accept(J, TK_IN)) { a = EXP2(IN, a, shift(J)); goto loop; }
	POPREC();
	return a;
}

static js_Ast *equality(js_State *J, int notin)
{
	js_Ast *a = relational(J, notin);
	int line;
	SAVEREC();
loop:
	INCREC();
	line = J->lexline;
	if (jsP_accept(J, TK_EQ)) { a = EXP2(EQ, a, relational(J, notin)); goto loop; }
	if (jsP_accept(J, TK_NE)) { a = EXP2(NE, a, relational(J, notin)); goto loop; }
	if (jsP_accept(J, TK_STRICTEQ)) { a = EXP2(STRICTEQ, a, relational(J, notin)); goto loop; }
	if (jsP_accept(J, TK_STRICTNE)) { a = EXP2(STRICTNE, a, relational(J, notin)); goto loop; }
	POPREC();
	return a;
}

static js_Ast *bitand(js_State *J, int notin)
{
	js_Ast *a = equality(J, notin);
	SAVEREC();
	int line = J->lexline;
	while (jsP_accept(J, '&')) {
		INCREC();
		a = EXP2(BITAND, a, equality(J, notin));
		line = J->lexline;
	}
	POPREC();
	return a;
}

static js_Ast *bitxor(js_State *J, int notin)
{
	js_Ast *a = bitand(J, notin);
	SAVEREC();
	int line = J->lexline;
	while (jsP_accept(J, '^')) {
		INCREC();
		a = EXP2(BITXOR, a, bitand(J, notin));
		line = J->lexline;
	}
	POPREC();
	return a;
}

static js_Ast *bitor(js_State *J, int notin)
{
	js_Ast *a = bitxor(J, notin);
	SAVEREC();
	int line = J->lexline;
	while (jsP_accept(J, '|')) {
		INCREC();
		a = EXP2(BITOR, a, bitxor(J, notin));
		line = J->lexline;
	}
	POPREC();
	return a;
}

static js_Ast *logand(js_State *J, int notin)
{
	js_Ast *a = bitor(J, notin);
	int line = J->lexline;
	if (jsP_accept(J, TK_AND)) {
		INCREC();
		a = EXP2(LOGAND, a, logand(J, notin));
		DECREC();
	}
	return a;
}

static js_Ast *logor(js_State *J, int notin)
{
	js_Ast *a = logand(J, notin);
	int line = J->lexline;
	if (jsP_accept(J, TK_OR)) {
		INCREC();
		a = EXP2(LOGOR, a, logor(J, notin));
		DECREC();
	}
	return a;
}

static js_Ast *conditional(js_State *J, int notin)
{
	js_Ast *a = logor(J, notin);
	int line = J->lexline;
	if (jsP_accept(J, '?')) {
		js_Ast *b, *c;
		INCREC();
		b = assignment(J, 0);
		jsP_expect(J, ':');
		c = assignment(J, notin);
		DECREC();
		return EXP3(COND, a, b, c);
	}
	return a;
}

static js_Ast *assignment(js_State *J, int notin)
{
	js_Ast *a = conditional(J, notin);
	int line = J->lexline;
	INCREC();
	if (jsP_accept(J, '=')) a = EXP2(ASS, a, assignment(J, notin));
	else if (jsP_accept(J, TK_MUL_ASS)) a = EXP2(ASS_MUL, a, assignment(J, notin));
	else if (jsP_accept(J, TK_DIV_ASS)) a = EXP2(ASS_DIV, a, assignment(J, notin));
	else if (jsP_accept(J, TK_MOD_ASS)) a = EXP2(ASS_MOD, a, assignment(J, notin));
	else if (jsP_accept(J, TK_ADD_ASS)) a = EXP2(ASS_ADD, a, assignment(J, notin));
	else if (jsP_accept(J, TK_SUB_ASS)) a = EXP2(ASS_SUB, a, assignment(J, notin));
	else if (jsP_accept(J, TK_SHL_ASS)) a = EXP2(ASS_SHL, a, assignment(J, notin));
	else if (jsP_accept(J, TK_SHR_ASS)) a = EXP2(ASS_SHR, a, assignment(J, notin));
	else if (jsP_accept(J, TK_USHR_ASS)) a = EXP2(ASS_USHR, a, assignment(J, notin));
	else if (jsP_accept(J, TK_AND_ASS)) a = EXP2(ASS_BITAND, a, assignment(J, notin));
	else if (jsP_accept(J, TK_XOR_ASS)) a = EXP2(ASS_BITXOR, a, assignment(J, notin));
	else if (jsP_accept(J, TK_OR_ASS)) a = EXP2(ASS_BITOR, a, assignment(J, notin));
	DECREC();
	return a;
}

static js_Ast *expression(js_State *J, int notin)
{
	js_Ast *a = assignment(J, notin);
	SAVEREC();
	int line = J->lexline;
	while (jsP_accept(J, ',')) {
		INCREC();
		a = EXP2(COMMA, a, assignment(J, notin));
		line = J->lexline;
	}
	POPREC();
	return a;
}

/* Statements */

static js_Ast *vardec(js_State *J, int notin)
{
	js_Ast *a = identifier(J);
	int line = J->lexline;
	if (jsP_accept(J, '='))
		return EXP2(VAR, a, assignment(J, notin));
	return EXP1(VAR, a);
}

static js_Ast *vardeclist(js_State *J, int notin)
{
	js_Ast *head, *tail;
	head = tail = LIST(vardec(J, notin));
	while (jsP_accept(J, ','))
		tail = tail->b = LIST(vardec(J, notin));
	return jsP_list(head);
}

static js_Ast *statementlist(js_State *J)
{
	js_Ast *head, *tail;
	if (J->lookahead == '}' || J->lookahead == TK_CASE || J->lookahead == TK_DEFAULT)
		return NULL;
	head = tail = LIST(statement(J));
	while (J->lookahead != '}' && J->lookahead != TK_CASE && J->lookahead != TK_DEFAULT)
		tail = tail->b = LIST(statement(J));
	return jsP_list(head);
}

static js_Ast *caseclause(js_State *J)
{
	js_Ast *a, *b;
	int line = J->lexline;

	if (jsP_accept(J, TK_CASE)) {
		a = expression(J, 0);
		jsP_expect(J, ':');
		b = statementlist(J);
		return STM2(CASE, a, b);
	}

	if (jsP_accept(J, TK_DEFAULT)) {
		jsP_expect(J, ':');
		a = statementlist(J);
		return STM1(DEFAULT, a);
	}

	jsP_error(J, "unexpected token in switch: %s (expected 'case' or 'default')", jsY_tokenstring(J->lookahead));
}

static js_Ast *caselist(js_State *J)
{
	js_Ast *head, *tail;
	if (J->lookahead == '}')
		return NULL;
	head = tail = LIST(caseclause(J));
	while (J->lookahead != '}')
		tail = tail->b = LIST(caseclause(J));
	return jsP_list(head);
}

static js_Ast *block(js_State *J)
{
	js_Ast *a;
	int line = J->lexline;
	jsP_expect(J, '{');
	a = statementlist(J);
	jsP_expect(J, '}');
	return STM1(BLOCK, a);
}

static js_Ast *forexpression(js_State *J, int end)
{
	js_Ast *a = NULL;
	if (J->lookahead != end)
		a = expression(J, 0);
	jsP_expect(J, end);
	return a;
}

static js_Ast *forstatement(js_State *J, int line)
{
	js_Ast *a, *b, *c, *d;
	jsP_expect(J, '(');
	if (jsP_accept(J, TK_VAR)) {
		a = vardeclist(J, 1);
		if (jsP_accept(J, ';')) {
			b = forexpression(J, ';');
			c = forexpression(J, ')');
			d = statement(J);
			return STM4(FOR_VAR, a, b, c, d);
		}
		if (jsP_accept(J, TK_IN)) {
			b = expression(J, 0);
			jsP_expect(J, ')');
			c = statement(J);
			return STM3(FOR_IN_VAR, a, b, c);
		}
		jsP_error(J, "unexpected token in for-var-statement: %s", jsY_tokenstring(J->lookahead));
	}

	if (J->lookahead != ';')
		a = expression(J, 1);
	else
		a = NULL;
	if (jsP_accept(J, ';')) {
		b = forexpression(J, ';');
		c = forexpression(J, ')');
		d = statement(J);
		return STM4(FOR, a, b, c, d);
	}
	if (jsP_accept(J, TK_IN)) {
		b = expression(J, 0);
		jsP_expect(J, ')');
		c = statement(J);
		return STM3(FOR_IN, a, b, c);
	}
	jsP_error(J, "unexpected token in for-statement: %s", jsY_tokenstring(J->lookahead));
}

static js_Ast *statement(js_State *J)
{
	js_Ast *a, *b, *c, *d;
	js_Ast *stm;
	int line = J->lexline;

	INCREC();

	if (J->lookahead == '{') {
		stm = block(J);
	}

	else if (jsP_accept(J, TK_VAR)) {
		a = vardeclist(J, 0);
		semicolon(J);
		stm = STM1(VAR, a);
	}

	/* empty statement */
	else if (jsP_accept(J, ';')) {
		stm = STM0(EMPTY);
	}

	else if (jsP_accept(J, TK_IF)) {
		jsP_expect(J, '(');
		a = expression(J, 0);
		jsP_expect(J, ')');
		b = statement(J);
		if (jsP_accept(J, TK_ELSE))
			c = statement(J);
		else
			c = NULL;
		stm = STM3(IF, a, b, c);
	}

	else if (jsP_accept(J, TK_DO)) {
		a = statement(J);
		jsP_expect(J, TK_WHILE);
		jsP_expect(J, '(');
		b = expression(J, 0);
		jsP_expect(J, ')');
		semicolon(J);
		stm = STM2(DO, a, b);
	}

	else if (jsP_accept(J, TK_WHILE)) {
		jsP_expect(J, '(');
		a = expression(J, 0);
		jsP_expect(J, ')');
		b = statement(J);
		stm = STM2(WHILE, a, b);
	}

	else if (jsP_accept(J, TK_FOR)) {
		stm = forstatement(J, line);
	}

	else if (jsP_accept(J, TK_CONTINUE)) {
		a = identifieropt(J);
		semicolon(J);
		stm = STM1(CONTINUE, a);
	}

	else if (jsP_accept(J, TK_BREAK)) {
		a = identifieropt(J);
		semicolon(J);
		stm = STM1(BREAK, a);
	}

	else if (jsP_accept(J, TK_RETURN)) {
		if (J->lookahead != ';' && J->lookahead != '}' && J->lookahead != 0)
			a = expression(J, 0);
		else
			a = NULL;
		semicolon(J);
		stm = STM1(RETURN, a);
	}

	else if (jsP_accept(J, TK_WITH)) {
		jsP_expect(J, '(');
		a = expression(J, 0);
		jsP_expect(J, ')');
		b = statement(J);
		stm = STM2(WITH, a, b);
	}

	else if (jsP_accept(J, TK_SWITCH)) {
		jsP_expect(J, '(');
		a = expression(J, 0);
		jsP_expect(J, ')');
		jsP_expect(J, '{');
		b = caselist(J);
		jsP_expect(J, '}');
		stm = STM2(SWITCH, a, b);
	}

	else if (jsP_accept(J, TK_THROW)) {
		a = expression(J, 0);
		semicolon(J);
		stm = STM1(THROW, a);
	}

	else if (jsP_accept(J, TK_TRY)) {
		a = block(J);
		b = c = d = NULL;
		if (jsP_accept(J, TK_CATCH)) {
			jsP_expect(J, '(');
			b = identifier(J);
			jsP_expect(J, ')');
			c = block(J);
		}
		if (jsP_accept(J, TK_FINALLY)) {
			d = block(J);
		}
		if (!b && !d)
			jsP_error(J, "unexpected token in try: %s (expected 'catch' or 'finally')", jsY_tokenstring(J->lookahead));
		stm = STM4(TRY, a, b, c, d);
	}

	else if (jsP_accept(J, TK_DEBUGGER)) {
		semicolon(J);
		stm = STM0(DEBUGGER);
	}

	else if (jsP_accept(J, TK_FUNCTION)) {
		jsP_warning(J, "function statements are not standard");
		stm = funstm(J, line);
	}

	/* labelled statement or expression statement */
	else if (J->lookahead == TK_IDENTIFIER) {
		a = expression(J, 0);
		if (a->type == EXP_IDENTIFIER && jsP_accept(J, ':')) {
			a->type = AST_IDENTIFIER;
			b = statement(J);
			stm = STM2(LABEL, a, b);
		} else {
			semicolon(J);
			stm = a;
		}
	}

	/* expression statement */
	else {
		stm = expression(J, 0);
		semicolon(J);
	}

	DECREC();
	return stm;
}

/* Program */

static js_Ast *scriptelement(js_State *J)
{
	int line = J->lexline;
	if (jsP_accept(J, TK_FUNCTION))
		return fundec(J, line);
	return statement(J);
}

static js_Ast *script(js_State *J, int terminator)
{
	js_Ast *head, *tail;
	if (J->lookahead == terminator)
		return NULL;
	head = tail = LIST(scriptelement(J));
	while (J->lookahead != terminator)
		tail = tail->b = LIST(scriptelement(J));
	return jsP_list(head);
}

static js_Ast *funbody(js_State *J)
{
	js_Ast *a;
	jsP_expect(J, '{');
	a = script(J, '}');
	jsP_expect(J, '}');
	return a;
}

/* Constant folding */

static int toint32(double d)
{
	double two32 = 4294967296.0;
	double two31 = 2147483648.0;

	if (!isfinite(d) || d == 0)
		return 0;

	d = fmod(d, two32);
	d = d >= 0 ? floor(d) : ceil(d) + two32;
	if (d >= two31)
		return d - two32;
	else
		return d;
}

static unsigned int touint32(double d)
{
	return (unsigned int)toint32(d);
}

static int jsP_setnumnode(js_Ast *node, double x)
{
	node->type = EXP_NUMBER;
	node->number = x;
	node->a = node->b = node->c = node->d = NULL;
	return 1;
}

static int jsP_foldconst(js_Ast *node)
{
	double x, y;
	int a, b;

	if (node->type == AST_LIST) {
		while (node) {
			jsP_foldconst(node->a);
			node = node->b;
		}
		return 0;
	}

	if (node->type == EXP_NUMBER)
		return 1;

	a = node->a ? jsP_foldconst(node->a) : 0;
	b = node->b ? jsP_foldconst(node->b) : 0;
	if (node->c) jsP_foldconst(node->c);
	if (node->d) jsP_foldconst(node->d);

	if (a) {
		x = node->a->number;
		switch (node->type) {
		default: break;
		case EXP_NEG: return jsP_setnumnode(node, -x);
		case EXP_POS: return jsP_setnumnode(node, x);
		case EXP_BITNOT: return jsP_setnumnode(node, ~toint32(x));
		}

		if (b) {
			y = node->b->number;
			switch (node->type) {
			default: break;
			case EXP_MUL: return jsP_setnumnode(node, x * y);
			case EXP_DIV: return jsP_setnumnode(node, x / y);
			case EXP_MOD: return jsP_setnumnode(node, fmod(x, y));
			case EXP_ADD: return jsP_setnumnode(node, x + y);
			case EXP_SUB: return jsP_setnumnode(node, x - y);
			case EXP_SHL: return jsP_setnumnode(node, toint32(x) << (touint32(y) & 0x1F));
			case EXP_SHR: return jsP_setnumnode(node, toint32(x) >> (touint32(y) & 0x1F));
			case EXP_USHR: return jsP_setnumnode(node, touint32(x) >> (touint32(y) & 0x1F));
			case EXP_BITAND: return jsP_setnumnode(node, toint32(x) & toint32(y));
			case EXP_BITXOR: return jsP_setnumnode(node, toint32(x) ^ toint32(y));
			case EXP_BITOR: return jsP_setnumnode(node, toint32(x) | toint32(y));
			}
		}
	}

	return 0;
}

/* Main entry point */

js_Ast *jsP_parse(js_State *J, const char *filename, const char *source)
{
	js_Ast *p;

	jsY_initlex(J, filename, source);
	jsP_next(J);
	J->astdepth = 0;
	p = script(J, 0);
	if (p)
		jsP_foldconst(p);

	return p;
}

js_Ast *jsP_parsefunction(js_State *J, const char *filename, const char *params, const char *body)
{
	js_Ast *p = NULL;
	int line = 0;
	if (params) {
		jsY_initlex(J, filename, params);
		jsP_next(J);
		J->astdepth = 0;
		p = parameters(J);
	}
	return EXP3(FUN, NULL, p, jsP_parse(J, filename, body));
}
