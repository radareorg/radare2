#ifndef YYSTYPE
typedef struct {
	long dval;
	char *sval;
} yystype;
#define YYSTYPE yystype
#endif

/* extern YYSTYPE yylval; */
YYSTYPE yylval;
char *yytext;

