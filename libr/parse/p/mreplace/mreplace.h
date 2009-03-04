//
// Library: Experimental PERL alike "search & replace", Copyleft, 2009-02-20
// Author : Mandingo, mandingo [ at ] yoire.com
//


#if !defined INPUTLINE_BUFFER_REPLACE_SIZE
	#define INPUTLINE_BUFFER_REPLACE_SIZE 32768
#endif

//search & replace strings - no regexp
extern void  sreplace(char *s,char *orig,char *rep,char multi,long dsize);

//search & replace strings - regexp + multiline safe
extern char *treplace(char *string,char *search,char *replace);

extern char *mreplace(char *string, char *search,char *replace);
