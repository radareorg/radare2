#ifndef PARSER_H
#define PARSER_H
#include "../list.h"

struct regs_off {
	char *reg;
	int off; // XXX 32 bit only !? wtf?
};

/* token types */
enum {
	GROUP_TOK = 0,
	REG_TOK,
	MEM_TOK
};

/* token structure */
struct tok {
	ut64 off;
	int type;
	int op, log_op;
	char *val;
	int len;

	struct list_head list;
	struct list_head next;
};

/* arithmetical operations */
enum {
	_OP_LT = 1,
	_OP_LE,
	_OP_EQ,
	_OP_NE,
	_OP_GE,
	_OP_GT
};

/* logical operations */
enum {
	LOG_OR = 1,
	LOG_AND
}; 

char skip_chars(const char **c);
struct tok* parse_cond(const char *cond);
int eval_cond(struct tok *group);
void free_cond(struct tok *group);

#endif
