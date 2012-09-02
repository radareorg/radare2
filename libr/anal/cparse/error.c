/* error.c: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "gen.h"
#include "error.h"

/* Persistent data needed to report and track errors.
 */
struct errhandler {
    char const	   *file;	/* a filename to prefix error messages with */
    unsigned long   lineno;	/* a line number to accompany the filename */
    int		    count;	/* total number of errors seen */
    enum errortype  type;	/* the most recent error */
};

/* There is only one error handler for the program.
 */
struct errhandler err;

/* Sets the name of the file to report errors for.
 */
void seterrorfile(char const *file)
{
    err.file = file;
    err.lineno = 0;
    err.type = errNone;
}

/* Sets the file's current line number.
 */
void seterrorline(unsigned long lineno)
{
    err.lineno = lineno;
}

/* Increments the current line number.
 */
void nexterrorline(void)
{
    ++err.lineno;
}

/* Returns the current error count.
 */
int geterrormark(void)
{
    return err.count;
}

/* Returns true if new errors have been recorded since the last
 * retrieved count.
 */
int errorsincemark(int mark)
{
    return err.count > mark;
}

/* Logs an error. The error is recorded in the error handler, and a
 * formatted message is displayed to the user.
 */
void error(enum errortype type)
{
    err.type = type;
    if (type == errNone)
	return;
    ++err.count;

    if (err.file) {
	if (err.lineno)
	    fprintf(stderr, "%s:%lu: ", err.file, err.lineno);
	else
	    fprintf(stderr, "%s: ", err.file);
    } else {
	if (err.lineno)
	    fprintf(stderr, "line %lu: ", err.lineno);
	else
	    fprintf(stderr, "error: ");
    }

    switch (type) {
      case errSyntax:
	fputs("preprocessor syntax error.", stderr);
	break;
      case errFileIO:
	if (errno)
	    fputs(strerror(errno), stderr);
	else
	    fputs("file I/O error.", stderr);
	break;
      case errIfsTooDeep:
	fputs("too many nested #ifs.", stderr);
	break;
      case errDanglingElse:
	fputs("#else not matched to any #if.", stderr);
	break;
      case errDanglingEnd:
	fputs("#endif found without any #if.", stderr);
	break;
      case errOpenIf:
	fputs("#if not closed.", stderr);
	break;
      case errBadCharLiteral:
	fputs("bad character literal.", stderr);
	break;
      case errOpenCharLiteral:
	fputs("last character literal not closed.", stderr);
	break;
      case errOpenStringLiteral:
	fputs("last string literal not closed.", stderr);
	break;
      case errOpenComment:
	fputs("last comment not closed.", stderr);
	break;
      case errOpenParenthesis:
	fputs("unmatched left parenthesis.", stderr);
	break;
      case errEmptyIf:
	fputs("#if with no argument.", stderr);
	break;
      case errMissingOperand:
	fputs("operator with missing expression.", stderr);
	break;
      case errZeroDiv:
	fputs("division by zero in expression.", stderr);
	break;
      case errIfSyntax:
	fputs("bad syntax in #if expression.", stderr);
	break;
      case errDefinedSyntax:
	fputs("bad syntax in defined operator.", stderr);
      case errBrokenComment:
	fputs("comment spans deleted line.", stderr);
	break;
      default:
	fprintf(stderr, "unspecified error (%d).", type);
	break;
    }
    fputc('\n', stderr);
}
