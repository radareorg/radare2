/* radare - LGPL - Copyright 2007-2009 esteve<eslack.org> */
/* contribs: pancake <nopcode.org> */

#include "r_search.h"

#if 0
#include "main.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "binparse.h"
#include "utils.h"
#endif

#if 0

token file example:
------------------------------
token:  Library token
        string: lib
        mask:   ff 00 ff
token:  Fruit for the loom
        string: rt
        mask:   ff ff
------------------------------
#endif

R_API void r_search_binparse_apply_mask (char * maskout, int masklen , token* tlist , int ntok)
{	
	int i;
	for(i=0; i < ntok ; i ++ )
		tlist[i].mask = maskout[masklen?i%masklen:0];
}

static ut8 get_byte(char *str, int len)
{
	int value;
	char* strp = alloca(sizeof(char)*len);
	memcpy(strp, str, len);
	if (strp[0] == '\\') {
		strp[0] = '0';
		sscanf (strp,"%x",&value );
	} else	sscanf (strp,"%c",(char *)&value );
	return (ut8)(value & 0xFF);
}

#if 0
static unsigned char get_num(const char * str, int len)
{
        ut8 * strp;
        int value;

        strp = alloca(len+1);
        memset(strp, 0, len);
        memcpy(strp, str, len );

        if (strp[0] == '\\') {
                strp[0] = '0';
                sscanf (strp,"%x",&value );
        } else  value = strp[0]; //sscanf (strp,"%c",(char *)&value );
        value = value & 0xFF ;

        return (unsigned char)value ;
}
#endif

static int get_range(char *str, int len, unsigned char *cbase)
{
	int g;
	ut8 min, max;
	for ( g= 0; (g < len ) && ( str[g] != '-' ) ; g++ );
	min = get_byte ( str, g );
	max = get_byte ( str+g+1, len-g-1 );
	*cbase = min;
	return (max-min);
}

static int tok_parse (char* str, int len, token * tlist )
{
	int i;
	int stat;
	unsigned char tokaux;
	int tokact=0;
	char straux[5];
	int rangemin = 0; // XXX BUGGY ???
	int rangemax;
	unsigned char cmin;

	stat = 0;	
	for (i=0 ; i < len ; i ++ ) {
		switch (str[i]) {
		case '\\':
			if (stat!=1&&( (stat < 10) || ( stat > 22 ) )) stat = 1;
			else stat++;
			break;
		case '[':
			if ( (stat!=1) && (stat!=10)) {
				stat = 10;
				rangemin = i+1 ;
			}
			else stat++;
			break;
		default:
			if (stat != 0 ) stat ++;
			break;
		}

		if ( stat == 0 ) {
			tlist[tokact].mintok =  str[i];
                        tlist[tokact].range = 0;
			tokact++;
		} else
		if (stat == 2 ) { // parse \xAA
			if (str[i]=='x' ) {
				//stat = 3;
			} else {
				//Caracter escapat
				tlist[tokact].mintok =  str[i];
                	        tlist[tokact].range = 0;
				tokact++;
				stat = 0;
			}
		} else
		if (stat == 3 ) {
			//primer despres de \x <--
			straux[0]='0';
			straux[1]='x';
			straux[2]=str[i];		
		} else
		if (stat == 4 ) {
			//Ja tinc tot el byte
			straux[3]=str[i];		
			straux[4]=0;		
			
			sscanf ( straux ,"%hhx",&tokaux);
			//tokaux = 0xFF&((straux[0]-'0')*16 + (straux[1]-'0'));
			tlist[tokact].mintok =  tokaux;
			tlist[tokact].range = 0;
			tokact++;
			stat = 0;
		} else
		if ( (stat >= 11) && (stat <= 22 ) ) {
			if ( str[i] == ']' ) {
				int irange;
				rangemax = i-1;

				irange = get_range( str+rangemin, rangemax-rangemin+1 , &cmin);
	
				tlist[tokact].mintok =  cmin;
				tlist[tokact].range = irange;
				tokact++;
				
				stat = 0;
			}
		}
	}

	return tokact;
}

static int r_search_binparse_get_mask_list(char* mask, char* maskout)
{
	int i,j,k;
	char num[3];

	num[2] = 0;
	j = k = 0;
	for(i=0; mask[i] ; i++) {
		if (mask[i] != ' ') {
			num[j] = mask[i];
			j++;
		}
		if (j == 2) {
			sscanf(num, "%hhx", (unsigned char*)&maskout[k]);
			k++;
			j = 0;
		}
	}

	return k;
}

static tokenlist *r_search_binparse_token_mask(char *name, char *token, char *mask)
{
	tokenlist *tls;
	void *tlist = 0;
	int ntok = 0;
	int len;
	int masklen;
	char maskout[300];

	tls = malloc( sizeof(tokenlist) );
	// TODO mask not yet done
	len = strlen(token);
	tlist = malloc( (sizeof (token) * len) + 1 );
	ntok = tok_parse(token, len, tlist);

	tls->tl = tlist;
	tls->numtok = ntok;
	/* tls->lastpos = 0; */
	tls->stat = 0;
	strcpy ( tls->name , name ); // XXX bof here!
	
	if ( mask == NULL )
		mask = "ff";

	masklen = r_search_binparse_get_mask_list(mask , maskout);
	r_search_binparse_apply_mask(maskout, masklen, tlist, ntok);

	//print_tok_list ( tls ) ;
	return tls;
}


#if 0
// line , IN rep linia tokens, surt llista token
static tokenlist* get_tok_list(char* line, int maxlen) 
{
	int i ,p;
	token * tlist;
	tokenlist *tls;
	int ntok;

	tls = malloc ( sizeof ( tokenlist ) ) ;

	for ( i = 0 ; i < maxlen ; i ++ ) if ( line[i] == '$' ) break;
	for ( p = i+1 ; p < maxlen ; p ++ )
		if ( line[p] == '$' && line[p-1] != '\\' ) break;
	
	//Prova, cada caracter un token
	if ( i == (p-1) ) {
		tlist = malloc ( sizeof (token) ) ;
		tlist[0].mintok = 0;
		tlist[0].range = 0xFF;
		ntok = 1;
	} else {
		ntok  = p - i;	
		tlist = malloc( sizeof (token) * ( ntok ) );
		ntok  = tok_parse( line+1, ntok-1, tlist );
	}

	tls->tl = tlist;
	tls->numtok = ntok;
	/* tls->lastpos = 0; */
	tls->stat = 0;

	strncpy(tls->name, line+p+1, 256);
	tls->name[strlen(tls->name)-1] = '\0'; 

	return tls;
}

static const char *str_get_arg(const char *buf)
{
	const char *str;
	str = strchr(buf, ':');
	if (str != NULL)
		str = strchr(str+1, '\t');
	if (str == NULL)
		return NULL;
	str = strdup(str+1);
	return str;
}
#endif

/* public api */

//tokenizer* binparse_new(int kws)
R_API struct r_search_binparse_t *binparse_new(int kws)
{
	struct r_search_binparse_t *tll = R_NEW(struct r_search_binparse_t);
	if (tll == NULL)
		return NULL;
	tll->tls = (tokenlist**)malloc(sizeof (tokenlist*) * kws);
	if (tll->tls == NULL) {
		free(tll);
		return NULL;
	}
	tll->nlists = 0;
	tll->interrupted = 0;
	return tll;
}

//int binparser_free(tokenizer* ptokenizer)
R_API int r_search_binparse_free(struct r_search_binparse_t *ptokenizer)
{
	int i;
	if (ptokenizer == NULL)
		return 0;
	for (i=0; i<ptokenizer->nlists; i++) {
		free(ptokenizer->tls[i]->tl);
		free(ptokenizer->tls[i]);
	}
	free(ptokenizer->tls);
	free(ptokenizer);

	return 0;
}

//int binparse_add(tokenizer *t, char *string, char *mask)
R_API int r_search_binparse_add(struct r_search_binparse_t *t, const char *string, const char *mask)
{
	int n = t->nlists;
	char name[32];

	if (string == NULL)
		return -1;
	t->nlists++;
	//snprintf(name, 31, "SEARCH[%d]", n);
	snprintf(name, 31, "kw[%d]", n);
	t->tls    = (tokenlist **) realloc(t->tls, t->nlists*sizeof(tokenlist*));
	t->tls[n] = r_search_binparse_token_mask(name, string, mask);

	return n;
}

// XXX name needs to be changed in runtime?
R_API int r_search_binparse_add_named(struct r_search_binparse_t *t, const char *name, const char *string, const char *mask)
{
	int ret = r_search_binparse_add(t, string, mask);
	if (ret != -1)
		strncpy(t->tls[ret]->name, name, 200);
	return ret;
}

/* -1 = error, 0 = skip, 1 = hit found */
R_API int r_search_binparse_update(struct r_search_binparse_t *t, ut8 inchar, ut64 where)
//int update_tlist(tokenizer* t, ut8 inchar, ut64 where )
{
	ut8 cmin, cmax, cmask;
	int i;

	if (t->nlists == 0) {
		fprintf(stderr, "No tokens defined\n");
		//config.interrupted = 1;
		t->interrupted = 1;
		return -1;
	}

	for (i=0; i<t->nlists; i++ ) {
		cmin = (t->tls[i]->tl[t->tls[i]->stat]).mintok;

		if ((t->tls[i]->tl[t->tls[i]->stat]).range > 0) {
			// RANGE
			cmax = cmin + (t->tls[i]->tl[t->tls[i]->stat]).range;
		
			if ((inchar >= cmin) && (inchar <= cmax))
				t->tls[i]->actp[t->tls[i]->stat++] = inchar;
			else	t->tls[i]->stat = 0;
		} else {
			// 1 char
			cmask = (t->tls[i]->tl[t->tls[i]->stat]).mask;
			if ((inchar&cmask) == (cmin&cmask))
				t->tls[i]->actp[t->tls[i]->stat++] = inchar;
			else	t->tls[i]->stat = 0;
		}

		if (t->tls[i]->stat == (t->tls[i]->numtok)) {
			t->tls[i]->actp[t->tls[i]->stat+1] = 0 ;
			t->tls[i]->actp[0] = 0 ; //rststr
			if (t->callback != NULL)  // t->tls[i] is the hit
				if (!t->callback(t, i, (ut64)(where-(t->tls[i]->numtok-1))))
					return 1;
			t->tls[i]->stat = 0 ;
		}
	}
	return 0;
}
