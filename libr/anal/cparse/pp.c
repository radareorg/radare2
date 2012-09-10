/* pp.c: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gen.h"
#include "error.h"
#include "symset.h"
#include "pplex.h"
#include "exptree.h"
#include "pp.h"

/* State flags tracking the current state of ppproc.
 */
#define F_If		0x0001		/* inside a #if section */
#define F_Else		0x0002		/* inside a #else section */
#define F_Elif		0x0004		/* inside a #elif section */
#define F_Ours		0x0010		/* guarded by user-specified symbol */
#define F_Copy		0x0020		/* section is passed to output */
#define F_IfModify	0x0040		/* modified #if expression */
#define F_ElseModify	0x0080		/* modified #elif expression */

/* Return codes for the seqif() function.
 */
enum status
{
    statError, statDefined, statUndefined, statPartDefined, statUnaffected
};

/* Allocates a partial preprocessor object.
 */
CparsePP *initppproc(CparseSYM *defs, CparseSYM *undefs)
{
    CparsePP *ppp;

    ppp = allocate(sizeof *ppp);
    ppp->cl = initpplex();
    ppp->defs = defs;
    ppp->undefs = undefs;
    ppp->linealloc = 128;
    ppp->line = allocate(ppp->linealloc);
    return ppp;
}

/* Deallocates the partial preprocessor object.
 */
void freeppproc(CparsePP *ppp)
{
    freepplex(ppp->cl);
    deallocate(ppp->line);
    deallocate(ppp);
}

/* Set the state appropriate for the beginning of a file.
 */
static void begin_pp(CparsePP *ppp)
{
    ppp->level = -1;
    ppp->copy = TRUE;
    ppp->absorb = FALSE;
}

/* Mark the ppproc as having reached the end of the current file.
 */
static void end_pp(CparsePP *ppp)
{
    endstream(ppp->cl);
    if (ppp->level != -1)
	error(errOpenIf);
    ppp->line[0] = '\0';
}

/* Partially preprocesses a #if expression. ifexp points to the text
 * immediately following the #if. The function seeks to the end of the
 * expression and evaluates it. The return value points to the text
 * immediately following the expression. If the expression has a
 * defined state, status receives either statDefined or statUndefined.
 * If the expression's contents are disjoint from the defined and
 * undefined symbols, status receives statUnaffected. Otherwise the
 * expression is in a partial state, in which case status receives
 * statPartDefined, and the original string is modified so as to
 * remove the parts of the expression that have a defined state.
 */
static char const *seqif(CparsePP *ppp, char *ifexp, enum status *status)
{
    struct exptree *tree;
    char const *ret;
    char *str;
    int defined, n;

    tree = initexptree();
    *status = statUnaffected;

    n = geterrormark();
    ret = parseexptree(tree, ppp->cl, ifexp);
    if (errorsincemark(n)) {
	*status = statError;
	goto quit;
    }

    n = 0;
    if (ppp->defs)
	n += markdefined(tree, ppp->defs, TRUE);
    if (ppp->undefs)
	n += markdefined(tree, ppp->undefs, FALSE);
    if (n) {
	*status = evaltree(tree, &defined) ? statDefined : statUndefined;
	if (!defined) {
	    *status = statPartDefined;
	    str = allocate(strlen(ifexp) + 1);
	    n = unparseevaluated(tree, str);
	    strcpy(str + n, ifexp + getexplength(tree));
	    strcpy(ifexp, str);
	    deallocate(str);
	}
    }

  quit:
    freeexptree(tree);
    return ret;
}

/* Partially preprocesses the current line of input. If the input
 * contains a preprocessor statement, the state of ppproc is updated
 * to reflect the current section, and if necessary the line of input
 * will be altered for output.
 */
static void seq(CparsePP *ppp)
{
    char const *input;
    char const *cmd;
    enum status status;
    int incomment;
    enum ppcmd id;
    int size, n;

    incomment = ccommentp(ppp->cl);
    ppp->absorb = FALSE;
    input = examinechar(ppp->cl, ppp->line);
    while (!preproclinep(ppp->cl)) {
	if (endoflinep(ppp->cl))
	    return;
	input = nextchar(ppp->cl, input);
   }

    cmd = skipwhite(ppp->cl, nextchar(ppp->cl, input));
    input = getpreprocessorcmd(ppp->cl, cmd, &id);

    switch (id) {
      case cmdIfdef:
      case cmdIfndef:
	if (ppp->level + 1 >= sizearray(ppp->stack)) {
	    error(errIfsTooDeep);
	    break;
	}
	++ppp->level;
	ppp->stack[ppp->level] = ppp->copy ? F_Copy : 0;
	if (!ppp->copy) {
	    input = restofline(ppp->cl, input);
	    break;
	}
	size = getidentifierlength(input);
	if (!size) {
	    error(errEmptyIf);
	    break;
	}
	if (ppp->defs && findsymbolinset(ppp->defs, input, NULL))
	    n = statDefined;
	else if (ppp->undefs && findsymbolinset(ppp->undefs, input, NULL))
	    n = statUndefined;
	else
	    n = statUnaffected;
	input = skipwhite(ppp->cl, nextchars(ppp->cl, input, size));
	if (!endoflinep(ppp->cl)) {
	    error(errSyntax);
	    break;
	}
	if (n != statUnaffected) {
	    ppp->absorb = TRUE;
	    ppp->stack[ppp->level] |= F_Ours;
	    ppp->copy = n == (id == cmdIfdef ? statDefined : statUndefined);
	}
	break;

      case cmdIf:
	if (ppp->level + 1 >= sizearray(ppp->stack)) {
	    error(errIfsTooDeep);
	    break;
	}
	++ppp->level;
	ppp->stack[ppp->level] = F_If | (ppp->copy ? F_Copy : 0);
	if (!ppp->copy) {
	    input = restofline(ppp->cl, input);
	    break;
	}
	input = seqif(ppp, (char*)input, &status);
	if (status == statError)
	    break;
	input = skipwhite(ppp->cl, input);
	if (!endoflinep(ppp->cl)) {
	    error(errIfSyntax);
	    break;
	}
	if (status == statDefined || status == statUndefined) {
	    ppp->absorb = TRUE;
	    ppp->stack[ppp->level] |= F_Ours;
	    ppp->copy = status == statDefined;
	}
	break;

      case cmdElse:
	if (ppp->level < 0 || (ppp->stack[ppp->level] & F_Else)) {
	    error(errDanglingElse);
	    break;
	}
	ppp->stack[ppp->level] |= F_Else;
	if (!endoflinep(ppp->cl)) {
	    error(errSyntax);
	    break;
	}
	if (ppp->stack[ppp->level] & F_Ours) {
	    ppp->copy = !ppp->copy;
	    ppp->absorb = TRUE;
	    n = ppp->level;
	    while (ppp->stack[n] & F_Elif) {
		if (ppp->stack[n] & F_ElseModify) {
		    ppp->absorb = TRUE;
		    break;
		}
		--n;
		if (!(ppp->stack[n] & F_Ours))
		    ppp->absorb = FALSE;
	    }
	}
	break;

      case cmdElif:
	if (ppp->level < 0 || !(ppp->stack[ppp->level] & F_If)
			   || (ppp->stack[ppp->level] & F_Else)) {
	    error(errDanglingElse);
	    break;
	} else if (ppp->level + 1 >= sizearray(ppp->stack)) {
	    error(errIfsTooDeep);
	    break;
	}
	ppp->stack[ppp->level] |= F_Else;
	if (ppp->stack[ppp->level] & F_Ours)
	    ppp->copy = !ppp->copy;
	++ppp->level;
	ppp->stack[ppp->level] = F_If | F_Elif | (ppp->copy ? F_Copy : 0);
	if (!ppp->copy) {
	    input = restofline(ppp->cl, input);
	    break;
	}
	input = seqif(ppp, (char*)input, &status);
	if (status == statError)
	    break;
	input = skipwhite(ppp->cl, input);
	if (!endoflinep(ppp->cl)) {
	    error(errIfSyntax);
	    break;
	}
	if (status == statUndefined) {
	    ppp->copy = FALSE;
	    ppp->absorb = TRUE;
	    ppp->stack[ppp->level] |= F_Ours;
	} else if (status == statDefined) {
	    ppp->absorb = TRUE;
	    n = ppp->level;
	    while (ppp->stack[n] & F_Elif) {
		--n;
		if (!(ppp->stack[n] & F_Ours)) {
		    strcpy((char*)cmd, "else");
		    ppp->stack[ppp->level] |= F_ElseModify;
		    ppp->absorb = FALSE;
		    break;
		}
	    }
	    ppp->stack[ppp->level] |= F_Ours;
	} else {
	    n = ppp->level;
	    while (ppp->stack[n] & F_Elif) {
		--n;
		if (!(ppp->stack[n] & F_Ours)) {
		    n = -1;
		    break;
		}
	    }
	    if (n >= 0) {
		memmove((char*)cmd, cmd + 2, strlen(cmd + 2) + 1);
		ppp->stack[ppp->level] |= F_IfModify;
	    }
	}
	break;

      case cmdEndif:
	if (ppp->level < 0) {
	    error(errDanglingEnd);
	    break;
	}
	if (!endoflinep(ppp->cl)) {
	    error(errSyntax);
	    break;
	}
	ppp->absorb = TRUE;
	for ( ; ppp->stack[ppp->level] & F_Elif ; --ppp->level) {
	    if (ppp->stack[ppp->level] & (F_IfModify | F_ElseModify))
		ppp->absorb = FALSE;
	}
	if (ppp->absorb)
	    ppp->absorb = ppp->stack[ppp->level] & F_Ours;
	ppp->copy = ppp->stack[ppp->level] & F_Copy;
	--ppp->level;
	break;

      default:
	input = restofline(ppp->cl, input);
	break;
    }

    if (ppp->absorb && incomment != ccommentp(ppp->cl))
	error(errBrokenComment);
}

/* Reads in one line of source code and run it through the partial
 * preprocessor. The return value is zero if the file has reached the
 * end or if the file can't be read.
 */
static int readline(CparsePP *ppp, FILE *infile)
{
    int size;
    int prev, ch;

    ch = fgetc(infile);
    if (ch == EOF)
	return 0;
    prev = EOF;
    for (size = 0 ; ch != EOF ; ++size) {
	if (ch == '\n' && prev != '\\')
	    break;
	if (size + 1 == ppp->linealloc) {
	    ppp->linealloc *= 2;
	    ppp->line = reallocate(ppp->line, ppp->linealloc);
	}
	ppp->line[size] = ch;
	prev = ch;
	ch = fgetc(infile);
    }
    if (ferror(infile)) {
	error(errFileIO);
	return 0;
    }
    ppp->endline = ch != EOF;
    ppp->line[size] = '\0';

    seq(ppp);

    nextline(ppp->cl, NULL);
    return 1;
}

/* Reads in one line of source code and run it through the partial
 * preprocessor. The return value is zero if the file has reached the
 * end or if the file can't be read.
 */
static int readline_buf(CparsePP *ppp, const char *inbuf)
{
    int size, i = 1;
    int prev, ch;

    ch = inbuf[0];
    if (ch == '\0')
	return 0;
    prev = '\0';
    for (size = 0 ; ch != '\0' ; ++size) {
		if (ch == '\n' && prev != '\\')
		    break;
		if (size + 1 == ppp->linealloc) {
			ppp->linealloc *= 2;
			ppp->line = reallocate(ppp->line, ppp->linealloc);
		}
		ppp->line[size] = ch;
		prev = ch;
		ch = inbuf[i++];
    }
    ppp->endline = ch != '\0';
    ppp->line[size] = '\0';

    seq(ppp);

    nextline(ppp->cl, NULL);
    return 1;
}


/* Outputs the partially preprocessed line to the output file,
 * assuming anything is left to be output. The return value is false
 * if an error occurs.
 */
static int writeline(CparsePP *ppp, FILE *outfile)
{
    size_t size;

    if (!ppp->line)
	return 1;
    if (!ppp->copy || ppp->absorb)
	return 1;

    size = strlen(ppp->line);
    if (size) {
	if (fwrite(ppp->line, size, 1, outfile) != 1) {
	    seterrorfile(NULL);
	    error(errFileIO);
	    return 0;
	}
    }
    if (ppp->endline)
	fputc('\n', outfile);
    ppp->endline = FALSE;
    return 1;
}

/* Outputs the partially preprocessed line to the output file,
 * assuming anything is left to be output. The return value is false
 * if an error occurs.
 */
static int writeline_buf(CparsePP *ppp, char *outbuf) {
    size_t size;

    if (!ppp->line)
		return 1;
    if (!ppp->copy || ppp->absorb)
		return 1;

    size = strlen (ppp->line);
    if (size>0) strncpy (outbuf, ppp->line, size);
    if (ppp->endline)
		strcat (outbuf, "\n");
    ppp->endline = FALSE;
    return 1;
}


/* Increments the line number count, checking for embedded line break
 * characters.
 */
static void advanceline(char const *line)
{
    char const *p;

    for (p = line - 1 ; p ; p = strchr(p + 1, '\n'))
	nexterrorline();
}

/* Partially preprocesses the contents of infile to outfile.
 */
void preprocess_file(CparsePP *pp, void *infile, void *outfile)
{
    begin_pp(pp);
    seterrorline(1);
    while (readline(pp, infile) && writeline(pp, outfile))
	advanceline(pp->line);
    seterrorline(0);
    end_pp(pp);
}

char* preprocess_buf(CparsePP *pp, const char *inbuf)
{
	// TODO: implement more dynamic allocation
	char* outbuf = malloc(4098);

	begin_pp(pp);
	seterrorline(1);
	while (readline_buf(pp, inbuf) && writeline_buf(pp, outbuf))
	advanceline(pp->line);
	seterrorline(0);
	end_pp(pp);
	return outbuf;
}

// TODO: Import enviroment variables?
// TODO: return error if failed
void cparsepp_file_fd (FILE *infile, FILE *outfile) {
	CparseSYM *defs = initsymset ();
	CparseSYM *undefs = initsymset ();
	CparsePP *pp = initppproc (defs, undefs);
	preprocess_file (pp, infile, outfile);
	freeppproc (pp);
	freesymset (defs);
	freesymset (undefs);
}

void cparsepp_file (const char *infile, const char *outfile) {
	FILE *in = fopen (infile, "r");
	FILE *out = fopen (outfile, "w");
	if (in && out) {
		cparsepp_file_fd (in, out);
	}
	fclose (in);
	fclose (out);
}

// TODO: Import enviroment variables?
char* cparsepp_buf (const char *inbuf) {
	char* outbuf = NULL;

	CparseSYM *defs = initsymset ();
	CparseSYM *undefs = initsymset ();
	CparsePP *pp = initppproc (defs, undefs);
	outbuf = preprocess_buf (pp, inbuf);
	freeppproc (pp);
	freesymset (defs);
	freesymset (undefs);
	return outbuf;
}


