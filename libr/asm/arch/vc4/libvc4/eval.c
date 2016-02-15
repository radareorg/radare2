#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <ctype.h>

#include "eval.h"

struct ev_input
{
	const char *buf;
};

static int64_t eval_factor(struct ev_input *e);
static int64_t eval_term(struct ev_input *e);
static int64_t eval_expr(struct ev_input *e);

static int ev_getc(struct ev_input *e);
static int ev_peekc(struct ev_input *e);
static int64_t ev_strtoll(struct ev_input *e);

int ev_getc(struct ev_input *e)
{
	if (e->buf == NULL)
		return 0;
	if (*e->buf == 0)
		return 0;
	return *e->buf++;
}

int ev_peekc(struct ev_input *e)
{
	if (e->buf == NULL)
		return 0;
	if (*e->buf == 0)
		return 0;
	return *e->buf;
}

int64_t ev_strtoll(struct ev_input *e)
{
	char *end;
	int64_t v;

	v = strtoll(e->buf, &end, 10);

	if (end != e->buf) {
		return 0LL;
	}

	e->buf += (end - e->buf);

	return v;
}

int64_t eval_factor(struct ev_input *e)
{
	int64_t v;

	if (isdigit(ev_peekc(e))) {
		v = ev_strtoll(e);
	} else if (ev_peekc(e) == '-') {
		ev_getc(e);
		v = -ev_strtoll(e);
	} else if (ev_peekc(e) == '(') {
		ev_getc(e);
		v = eval_expr(e);
		// assert(ev_peekc(e)  == ')');
		if (ev_peekc(e) != ')') {
			return 0LL;
		}
		ev_getc(e);
	} else {
		// assert(0);
		return 0LL;
	}

	return v;
}

int64_t eval_term(struct ev_input *e)
{
	int64_t v0, v1;
	char op;

	v0 = eval_factor(e);

	while (ev_peekc(e) == '*' || ev_peekc(e) == '/' || ev_peekc(e) == '&') {
		op = ev_getc(e);

		v1 = eval_factor(e);

		if (op == '*')
			v0 = v0 * v1;
		else if (op == '&')
			v0 = v0 & v1;
		else
			v0 = v0 / v1;
	}

	return v0;
}

int64_t eval_expr(struct ev_input *e)
{
	int64_t v0, v1;
	char op = '+';

	if (ev_peekc(e) == '+' || ev_peekc(e) == '-') {
		op = ev_getc(e);
	}

	v0 = eval_term(e);
	if (op == '-')
		v0 = -v0;

	while (ev_peekc(e)  == '+' || ev_peekc(e)  == '-') {
		op = ev_getc(e);

		v1 = eval_term(e);

		if (op == '-')
			v0 = v0 - v1;
		else
			v0 = v0 + v1;
	}

	return v0;
}

int64_t eval(const char *s)
{
	int64_t v;
	struct ev_input ei;

	if (!s) return 0LL;

	ei.buf = s;

	v = eval_expr(&ei);

	if (*ei.buf != 0) {
		return 0LL;
	}

	return v;
}
