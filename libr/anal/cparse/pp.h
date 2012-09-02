/* pp.h: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#ifndef	_pp_h_
#define	_pp_h_

/* Matimum nesting level of #if statements */
#define STACK_SIZE 1024

/*
 * The ppproc object does the actual work of identifying preprocessor
 * statements affected by the user's requested definitions and
 * undefintions, and determining what the resulting output needs to
 * contain.
 */

typedef struct ppproc CparsePP;
typedef struct symset CparseSYM;

/* The partial preprocessor.
 */
struct ppproc {
    struct pplex  *cl;			/* the lexer */
    struct symset  *defs;		/* list of defined symbols */
    struct symset  *undefs;		/* list of undefined symbols */
    char	   *line;		/* the current line of input */
    int		    linealloc;		/* memory allocated for line */
    int		    copy;		/* true if input is going to output */
    int		    absorb;		/* true if input is being suppressed */
    int		    endline;		/* false if line has no '\n' at end */
    int		    level;		/* current nesting level */
    int		    stack[STACK_SIZE];	/* state flags for each level */
};

/* Creates a ppproc object initialized with pre-defined sets of defined
 * and undefined symbols */
CparsePP *initppproc(CparseSYM *defs, CparseSYM *undefs);

/* Deallocates the ppproc object */
void freeppproc(CparsePP *pp);

/* Preprocesses infile's contents to outfile */
void preprocess_file(CparsePP *pp, void *infile, void *outfile);

/* Preprocess inbuf contents and return result */
char* preprocess_buf(CparsePP *pp, char *inbuf);

void cparsepp_file (FILE *infile, FILE* outfile);
char* cparsepp_buf (char* inbuf);

#endif
