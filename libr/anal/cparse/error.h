/* error.h: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#ifndef _error_h_
#define _error_h_

/*
 * This module provides basic reporting and tracking of errors that
 * occur while processing input files.
 */

/* The complete list of error message types.
 */
enum errortype
{
    errNone = 0,
    errSyntax,			/* general syntax error */
    errFileIO,			/* file I/O failure (see errno) */
    errBadCharLiteral,		/* invalid character sequence in quotes */
    errOpenCharLiteral,		/* unclosed single quote */
    errOpenStringLiteral,	/* unclosed double quote */
    errOpenComment,		/* unclosed multi-line comment */
    errBrokenComment,		/* comment spanning removed line */
    errDanglingElse,		/* unmatched #else found */
    errDanglingEnd,		/* unmatched #end found */
    errOpenIf,			/* unclosed #if */
    errIfsTooDeep,		/* way too many nested #ifs */
    errOpenParenthesis,		/* unclosed left parenthesis */
    errMissingOperand,		/* operand expected to follow expression */
    errZeroDiv,			/* division by zero in an expression */
    errEmptyIf,			/* missing #if parameter */
    errIfSyntax,		/* general syntax error inside #if parameter */
    errDefinedSyntax,		/* general syntax error in defined operand */
    errCount
};

/* Displays a formatted error message to the user.
 */
extern void error(enum errortype type);

/* Sets the input filename to display in error messages.
 */
extern void seterrorfile(char const *file);

/* Sets the current line number for the input filename, to be
 * displayed when errors are reported.
 */
extern void seterrorline(unsigned long lineno);

/* Increments the current line number.
 */
extern void nexterrorline(void);

/* Returns the number of errors that have occurred so far.
 */
extern int geterrormark(void);

/* Returns true if any new errors have occurred since the given mark
 * was retrieved.
 */
extern int errorsincemark(int mark);

#endif
