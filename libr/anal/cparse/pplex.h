/* pplex.h: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#ifndef	_pplex_h_
#define	_pplex_h_

/*
 * The C lexer object does basic lexical analysis on the input stream.
 * It knows enough C syntax to find the lines containing preprocessor
 * statements. The C lexer works by feeding it input text, and
 * advancing it through each character of input.
 */

struct pplex;

/* A list of identifiers for the preprocessor commands that the
 * program cares about.
 */
enum ppcmd
{
    cmdNone = 0,
    cmdDefine, cmdElif, cmdElse, cmdEndif,
    cmdIf, cmdIfdef, cmdIfndef, cmdUndef,
    cmdOther
};

/* Returns the length of the C identifier located at input, or zero if
 * input does not point to a valid C identifier.
 */
extern int getidentifierlength(char const *input);

/* Creates a new C lexer.
 */
extern struct pplex *initpplex(void);

/* Deallocates a lexer.
 */
extern void freepplex(struct pplex *cl);

/* These functions all return true or false depending on what the
 * lexer has last examined.
 */
extern int endoflinep(struct pplex const *cl);
extern int whitespacep(struct pplex const *cl);
extern int charquotep(struct pplex const *cl);
extern int ccommentp(struct pplex const *cl);
extern int preproclinep(struct pplex const *cl);

/* Returns the current number of nested parentheses.
 */
extern int getparenlevel(struct pplex const *cl);

/* Examines the next character in the given line of input, and updates
 * state as necessary.
 */
extern char const *examinechar(struct pplex *cl, char const *input);

/* Examines the first character token in input, and returns a pointer
 * to the byte immediately following.
 */
extern char const *nextchar(struct pplex *cl, char const *input);

/* Examines n character tokens in input, updating state along the way,
 * and returns a pointer to the byte immediately following them.
 */
extern char const *nextchars(struct pplex *cl, char const *input, int skip);

/* Examines all character tokens in input until reaching the end of
 * the line.
 */
extern char const *restofline(struct pplex *cl, char const *input);

/* Examines characters tokens until a whitespace character is found.
 */
extern char const *skiptowhite(struct pplex *cl, char const *input);

/* Examines characters tokens until a non-whitespace character is
 * found.
 */
extern char const *skipwhite(struct pplex *cl, char const *input);

/* Mark the beginning of a new line. If input is not null, it will
 * be used as the new line; otherwise, the lexer will take the next
 * input as the beginning of the new line.
 */
extern char const *nextline(struct pplex *cl, char const *input);

/* Mark the end of the current input file.
 */
extern void endstream(struct pplex *cl);

/* Examines character tokens until the end of an identifier is
 * found. The identifier itself is returned via buffer.
 */
extern char const *getidentifier(struct pplex *cl, char const *input,
				 char *buffer);

/* Examines character tokens until the end of the preprocessor
 * statement is found. The value identifying the preprocessor statement
 * is returned via cmdid.
 */
extern char const *getpreprocessorcmd(struct pplex *cl, char const *input,
				      enum ppcmd *cmdid);

#endif
