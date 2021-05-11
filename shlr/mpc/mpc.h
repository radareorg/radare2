/*
** mpc - Micro Parser Combinator library for C
**
** https://github.com/orangeduck/mpc
**
** Daniel Holden - contact@daniel-holden.com
** Licensed under BSD3
*/

#ifndef mpc_h
#define mpc_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>

/*
** State Type
*/

typedef struct {
  long pos;
  long row;
  long col;
  int term;
} mpc_state_t;

/*
** Error Type
*/

typedef struct {
  mpc_state_t state;
  int expected_num;
  char *filename;
  char *failure;
  char **expected;
  char received;
} mpc_err_t;

void mpc_err_delete(mpc_err_t *e);
char *mpc_err_string(mpc_err_t *e);
void mpc_err_print(mpc_err_t *e);
void mpc_err_print_to(mpc_err_t *e, FILE *f);

/*
** Parsing
*/

typedef void mpc_val_t;

typedef union {
  mpc_err_t *error;
  mpc_val_t *output;
} mpc_result_t;

struct mpc_parser_t;
typedef struct mpc_parser_t mpc_parser_t;

int mpc_parse(const char *filename, const char *string, mpc_parser_t *p, mpc_result_t *r);
int mpc_nparse(const char *filename, const char *string, size_t length, mpc_parser_t *p, mpc_result_t *r);
int mpc_parse_file(const char *filename, FILE *file, mpc_parser_t *p, mpc_result_t *r);
int mpc_parse_pipe(const char *filename, FILE *pipe, mpc_parser_t *p, mpc_result_t *r);
int mpc_parse_contents(const char *filename, mpc_parser_t *p, mpc_result_t *r);

/*
** Function Types
*/

typedef void(*mpc_dtor_t)(mpc_val_t*);
typedef mpc_val_t*(*mpc_ctor_t)(void);

typedef mpc_val_t*(*mpc_apply_t)(mpc_val_t*);
typedef mpc_val_t*(*mpc_apply_to_t)(mpc_val_t*,void*);
typedef mpc_val_t*(*mpc_fold_t)(int,mpc_val_t**);

typedef int(*mpc_check_t)(mpc_val_t**);
typedef int(*mpc_check_with_t)(mpc_val_t**,void*);

/*
** Building a Parser
*/

mpc_parser_t *mpc_new(const char *name);
mpc_parser_t *mpc_copy(mpc_parser_t *a);
mpc_parser_t *mpc_define(mpc_parser_t *p, mpc_parser_t *a);
mpc_parser_t *mpc_undefine(mpc_parser_t *p);

void mpc_delete(mpc_parser_t *p);
void mpc_cleanup(int n, ...);

/*
** Basic Parsers
*/

mpc_parser_t *mpc_any(void);
mpc_parser_t *mpc_char(char c);
mpc_parser_t *mpc_range(char s, char e);
mpc_parser_t *mpc_oneof(const char *s);
mpc_parser_t *mpc_noneof(const char *s);
mpc_parser_t *mpc_satisfy(int(*f)(char));
mpc_parser_t *mpc_string(const char *s);

/*
** Other Parsers
*/

mpc_parser_t *mpc_pass(void);
mpc_parser_t *mpc_fail(const char *m);
mpc_parser_t *mpc_failf(const char *fmt, ...);
mpc_parser_t *mpc_lift(mpc_ctor_t f);
mpc_parser_t *mpc_lift_val(mpc_val_t *x);
mpc_parser_t *mpc_anchor(int(*f)(char,char));
mpc_parser_t *mpc_state(void);

/*
** Combinator Parsers
*/

mpc_parser_t *mpc_expect(mpc_parser_t *a, const char *e);
mpc_parser_t *mpc_expectf(mpc_parser_t *a, const char *fmt, ...);
mpc_parser_t *mpc_apply(mpc_parser_t *a, mpc_apply_t f);
mpc_parser_t *mpc_apply_to(mpc_parser_t *a, mpc_apply_to_t f, void *x);
mpc_parser_t *mpc_check(mpc_parser_t *a, mpc_dtor_t da, mpc_check_t f, const char *e);
mpc_parser_t *mpc_check_with(mpc_parser_t *a, mpc_dtor_t da, mpc_check_with_t f, void *x, const char *e);
mpc_parser_t *mpc_checkf(mpc_parser_t *a, mpc_dtor_t da, mpc_check_t f, const char *fmt, ...);
mpc_parser_t *mpc_check_withf(mpc_parser_t *a, mpc_dtor_t da, mpc_check_with_t f, void *x, const char *fmt, ...);

mpc_parser_t *mpc_not(mpc_parser_t *a, mpc_dtor_t da);
mpc_parser_t *mpc_not_lift(mpc_parser_t *a, mpc_dtor_t da, mpc_ctor_t lf);
mpc_parser_t *mpc_maybe(mpc_parser_t *a);
mpc_parser_t *mpc_maybe_lift(mpc_parser_t *a, mpc_ctor_t lf);

mpc_parser_t *mpc_many(mpc_fold_t f, mpc_parser_t *a);
mpc_parser_t *mpc_many1(mpc_fold_t f, mpc_parser_t *a);
mpc_parser_t *mpc_count(int n, mpc_fold_t f, mpc_parser_t *a, mpc_dtor_t da);

mpc_parser_t *mpc_or(int n, ...);
mpc_parser_t *mpc_and(int n, mpc_fold_t f, ...);

mpc_parser_t *mpc_predictive(mpc_parser_t *a);

/*
** Common Parsers
*/

mpc_parser_t *mpc_eoi(void);
mpc_parser_t *mpc_soi(void);

mpc_parser_t *mpc_boundary(void);
mpc_parser_t *mpc_boundary_newline(void);

mpc_parser_t *mpc_whitespace(void);
mpc_parser_t *mpc_whitespaces(void);
mpc_parser_t *mpc_blank(void);

mpc_parser_t *mpc_newline(void);
mpc_parser_t *mpc_tab(void);
mpc_parser_t *mpc_escape(void);

mpc_parser_t *mpc_digit(void);
mpc_parser_t *mpc_hexdigit(void);
mpc_parser_t *mpc_octdigit(void);
mpc_parser_t *mpc_digits(void);
mpc_parser_t *mpc_hexdigits(void);
mpc_parser_t *mpc_octdigits(void);

mpc_parser_t *mpc_lower(void);
mpc_parser_t *mpc_upper(void);
mpc_parser_t *mpc_alpha(void);
mpc_parser_t *mpc_underscore(void);
mpc_parser_t *mpc_alphanum(void);

mpc_parser_t *mpc_int(void);
mpc_parser_t *mpc_hex(void);
mpc_parser_t *mpc_oct(void);
mpc_parser_t *mpc_number(void);

mpc_parser_t *mpc_real(void);
mpc_parser_t *mpc_float(void);

mpc_parser_t *mpc_char_lit(void);
mpc_parser_t *mpc_string_lit(void);
mpc_parser_t *mpc_regex_lit(void);

mpc_parser_t *mpc_ident(void);

/*
** Useful Parsers
*/

mpc_parser_t *mpc_startwith(mpc_parser_t *a);
mpc_parser_t *mpc_endwith(mpc_parser_t *a, mpc_dtor_t da);
mpc_parser_t *mpc_whole(mpc_parser_t *a, mpc_dtor_t da);

mpc_parser_t *mpc_stripl(mpc_parser_t *a);
mpc_parser_t *mpc_stripr(mpc_parser_t *a);
mpc_parser_t *mpc_strip(mpc_parser_t *a);
mpc_parser_t *mpc_tok(mpc_parser_t *a);
mpc_parser_t *mpc_sym(const char *s);
mpc_parser_t *mpc_total(mpc_parser_t *a, mpc_dtor_t da);

mpc_parser_t *mpc_between(mpc_parser_t *a, mpc_dtor_t ad, const char *o, const char *c);
mpc_parser_t *mpc_parens(mpc_parser_t *a, mpc_dtor_t ad);
mpc_parser_t *mpc_braces(mpc_parser_t *a, mpc_dtor_t ad);
mpc_parser_t *mpc_brackets(mpc_parser_t *a, mpc_dtor_t ad);
mpc_parser_t *mpc_squares(mpc_parser_t *a, mpc_dtor_t ad);

mpc_parser_t *mpc_tok_between(mpc_parser_t *a, mpc_dtor_t ad, const char *o, const char *c);
mpc_parser_t *mpc_tok_parens(mpc_parser_t *a, mpc_dtor_t ad);
mpc_parser_t *mpc_tok_braces(mpc_parser_t *a, mpc_dtor_t ad);
mpc_parser_t *mpc_tok_brackets(mpc_parser_t *a, mpc_dtor_t ad);
mpc_parser_t *mpc_tok_squares(mpc_parser_t *a, mpc_dtor_t ad);

/*
** Common Function Parameters
*/

void mpcf_dtor_null(mpc_val_t *x);

mpc_val_t *mpcf_ctor_null(void);
mpc_val_t *mpcf_ctor_str(void);

mpc_val_t *mpcf_free(mpc_val_t *x);
mpc_val_t *mpcf_int(mpc_val_t *x);
mpc_val_t *mpcf_hex(mpc_val_t *x);
mpc_val_t *mpcf_oct(mpc_val_t *x);
mpc_val_t *mpcf_float(mpc_val_t *x);
mpc_val_t *mpcf_strtriml(mpc_val_t *x);
mpc_val_t *mpcf_strtrimr(mpc_val_t *x);
mpc_val_t *mpcf_strtrim(mpc_val_t *x);

mpc_val_t *mpcf_escape(mpc_val_t *x);
mpc_val_t *mpcf_escape_regex(mpc_val_t *x);
mpc_val_t *mpcf_escape_string_raw(mpc_val_t *x);
mpc_val_t *mpcf_escape_char_raw(mpc_val_t *x);

mpc_val_t *mpcf_unescape(mpc_val_t *x);
mpc_val_t *mpcf_unescape_regex(mpc_val_t *x);
mpc_val_t *mpcf_unescape_string_raw(mpc_val_t *x);
mpc_val_t *mpcf_unescape_char_raw(mpc_val_t *x);

mpc_val_t *mpcf_null(int n, mpc_val_t** xs);
mpc_val_t *mpcf_fst(int n, mpc_val_t** xs);
mpc_val_t *mpcf_snd(int n, mpc_val_t** xs);
mpc_val_t *mpcf_trd(int n, mpc_val_t** xs);

mpc_val_t *mpcf_fst_free(int n, mpc_val_t** xs);
mpc_val_t *mpcf_snd_free(int n, mpc_val_t** xs);
mpc_val_t *mpcf_trd_free(int n, mpc_val_t** xs);
mpc_val_t *mpcf_all_free(int n, mpc_val_t** xs);

mpc_val_t *mpcf_freefold(int n, mpc_val_t** xs);
mpc_val_t *mpcf_strfold(int n, mpc_val_t** xs);
mpc_val_t *mpcf_maths(int n, mpc_val_t** xs);

/*
** Regular Expression Parsers
*/

enum {
  MPC_RE_DEFAULT   = 0,
  MPC_RE_M         = 1,
  MPC_RE_S         = 2,
  MPC_RE_MULTILINE = 1,
  MPC_RE_DOTALL    = 2
};

mpc_parser_t *mpc_re(const char *re);
mpc_parser_t *mpc_re_mode(const char *re, int mode);

/*
** AST
*/

typedef struct mpc_ast_t {
  char *tag;
  char *contents;
  mpc_state_t state;
  int children_num;
  struct mpc_ast_t** children;
} mpc_ast_t;

mpc_ast_t *mpc_ast_new(const char *tag, const char *contents);
mpc_ast_t *mpc_ast_build(int n, const char *tag, ...);
mpc_ast_t *mpc_ast_add_root(mpc_ast_t *a);
mpc_ast_t *mpc_ast_add_child(mpc_ast_t *r, mpc_ast_t *a);
mpc_ast_t *mpc_ast_add_tag(mpc_ast_t *a, const char *t);
mpc_ast_t *mpc_ast_add_root_tag(mpc_ast_t *a, const char *t);
mpc_ast_t *mpc_ast_tag(mpc_ast_t *a, const char *t);
mpc_ast_t *mpc_ast_state(mpc_ast_t *a, mpc_state_t s);

void mpc_ast_delete(mpc_ast_t *a);
void mpc_ast_print(mpc_ast_t *a);
void mpc_ast_print_to(mpc_ast_t *a, FILE *fp);

int mpc_ast_get_index(mpc_ast_t *ast, const char *tag);
int mpc_ast_get_index_lb(mpc_ast_t *ast, const char *tag, int lb);
mpc_ast_t *mpc_ast_get_child(mpc_ast_t *ast, const char *tag);
mpc_ast_t *mpc_ast_get_child_lb(mpc_ast_t *ast, const char *tag, int lb);

typedef enum {
  mpc_ast_trav_order_pre,
  mpc_ast_trav_order_post
} mpc_ast_trav_order_t;

typedef struct mpc_ast_trav_t {
  mpc_ast_t             *curr_node;
  struct mpc_ast_trav_t *parent;
  int                    curr_child;
  mpc_ast_trav_order_t   order;
} mpc_ast_trav_t;

mpc_ast_trav_t *mpc_ast_traverse_start(mpc_ast_t *ast,
                                       mpc_ast_trav_order_t order);

mpc_ast_t *mpc_ast_traverse_next(mpc_ast_trav_t **trav);

void mpc_ast_traverse_free(mpc_ast_trav_t **trav);

/*
** Warning: This function currently doesn't test for equality of the `state` member!
*/
int mpc_ast_eq(mpc_ast_t *a, mpc_ast_t *b);

mpc_val_t *mpcf_fold_ast(int n, mpc_val_t **as);
mpc_val_t *mpcf_str_ast(mpc_val_t *c);
mpc_val_t *mpcf_state_ast(int n, mpc_val_t **xs);

mpc_parser_t *mpca_tag(mpc_parser_t *a, const char *t);
mpc_parser_t *mpca_add_tag(mpc_parser_t *a, const char *t);
mpc_parser_t *mpca_root(mpc_parser_t *a);
mpc_parser_t *mpca_state(mpc_parser_t *a);
mpc_parser_t *mpca_total(mpc_parser_t *a);

mpc_parser_t *mpca_not(mpc_parser_t *a);
mpc_parser_t *mpca_maybe(mpc_parser_t *a);

mpc_parser_t *mpca_many(mpc_parser_t *a);
mpc_parser_t *mpca_many1(mpc_parser_t *a);
mpc_parser_t *mpca_count(int n, mpc_parser_t *a);

mpc_parser_t *mpca_or(int n, ...);
mpc_parser_t *mpca_and(int n, ...);

enum {
  MPCA_LANG_DEFAULT              = 0,
  MPCA_LANG_PREDICTIVE           = 1,
  MPCA_LANG_WHITESPACE_SENSITIVE = 2
};

mpc_parser_t *mpca_grammar(int flags, const char *grammar, ...);

mpc_err_t *mpca_lang(int flags, const char *language, ...);
mpc_err_t *mpca_lang_file(int flags, FILE *f, ...);
mpc_err_t *mpca_lang_pipe(int flags, FILE *f, ...);
mpc_err_t *mpca_lang_contents(int flags, const char *filename, ...);

/*
** Misc
*/


void mpc_print(mpc_parser_t *p);
void mpc_optimise(mpc_parser_t *p);
void mpc_stats(mpc_parser_t *p);

int mpc_test_pass(mpc_parser_t *p, const char *s, const void *d,
  int(*tester)(const void*, const void*),
  mpc_dtor_t destructor,
  void(*printer)(const void*));

int mpc_test_fail(mpc_parser_t *p, const char *s, const void *d,
  int(*tester)(const void*, const void*),
  mpc_dtor_t destructor,
  void(*printer)(const void*));

#ifdef __cplusplus
}
#endif

#endif
