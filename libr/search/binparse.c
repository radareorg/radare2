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

void r_search_binparse_apply_mask (char * maskout, int masklen , token* tlist , int ntok)
{	
	int i;
	for(i=0; i < ntok ; i ++ )
		tlist[i].mask = maskout[masklen?i%masklen:0];
}

static u8 get_byte(char *str, int len)
{
	int value;
	char* strp = alloca(sizeof(char)*len);
	memcpy(strp, str, len);
	if (strp[0] == '\\') {
		strp[0] = '0';
		sscanf (strp,"%x",&value );
	} else	sscanf (strp,"%c",(char *)&value );
	return (u8)(value & 0xFF);
}

#if 0
static unsigned char get_num(const char * str, int len)
{
        u8 * strp;
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
	u8 min, max;
	
	// busca guio
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
struct r_search_binparse_t *binparse_new(int kws)
{
	struct r_search_binparse_t *tll = MALLOC_STRUCT(struct r_search_binparse_t);
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
int r_search_binparse_free(struct r_search_binparse_t *ptokenizer)
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
int r_search_binparse_add(struct r_search_binparse_t *t, const char *string, const char *mask)
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
int r_search_binparse_add_named(struct r_search_binparse_t *t, const char *name, const char *string, const char *mask)
{
	int ret = r_search_binparse_add(t, string, mask);
	if (ret != -1)
		strncpy(t->tls[ret]->name, name, 200);
	return ret;
}

/* -1 = error, 0 = skip, 1 = hit found */
int r_search_binparse_update(struct r_search_binparse_t *t, u8 inchar, u64 where)
//int update_tlist(tokenizer* t, u8 inchar, u64 where )
{
	u8 cmin, cmax, cmask;
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
				if (!t->callback(t, i, (u64)(where-(t->tls[i]->numtok-1))))
					return 1;
			t->tls[i]->stat = 0 ;
		}
	}

	return 0;
}

/* unused .. deprecate ? */

#if 0
void tokenize(int fd, tokenizer* t)
{
	char ch;
	int ret;
	int where = lseek(fd, (off_t)0, SEEK_CUR);

	while(1) {
		if ( read(fd, &ch, 1) <= 0 ) break;
		ret = update_tlist(t, ch, where); 
		if (ret == -1) break;
		where++;
	}
}
#if 0
tokenizer* binparse_new_from_file(char *file)
{
	char buf[2049];
	FILE *fd;
	tokenizer *tok;
	char *str  = NULL;
	char *mask = NULL;
	char *name = NULL;

	tok = binparse_new(0);
	fd = fopen(file, "r");
	if (fd == NULL) {
		eprintf("Cannot open file '%s'\n", file);
		return NULL;
	}
	while(!feof(fd)) {
		/* read line */
		buf[0]='\0';
		fgets(buf, 2048, fd);
		if (buf[0]=='\0') continue;
		buf[strlen(buf)-1]='\0';

		/* find token: */
		if (!memcmp(buf, "token:",6)) {
			if (str != NULL) {
				eprintf("new keyword(%s,%s,%s)\n", name, str, mask);
				binparse_add_name(tok, name, str, mask);
				free(name); name = NULL;
				free(str);  str  = NULL;
				free(mask); mask = NULL;
			}
			free(name);
			name = (const char *)str_get_arg(buf);
		} else
		if (!memcmp(buf, "\tstring:", 8)) {
			str = str_get_arg(buf);
		} else
		if (!memcmp(buf, "\tmask:", 6)) {
			mask = str_get_arg(buf);
		}
	}

	if (str != NULL) {
		eprintf("new keyword(%s,%s,%s)\n", name, str, mask);
		binparse_add_name(tok, name, str, mask);
	}

	free(name);
	free(str);
	free(mask);
	printf("TOKEN ELEMENTS: %d\n", tok->nlists);

	return tok;
}
#if 0
/* not necessary */
static void print_tok_list(tokenlist* toklist) 
{
	int i;

	printf ("TOKLIST %s:\n",toklist->name);
	for (i=0; i<toklist->numtok; i++)
		printf ("TOK : %c , range : %d mask : %x\n",
			toklist->tl[i].mintok,
			toklist->tl[i].range,
			toklist->tl[i].mask);
	NEWLINE;
	printf ("\n");
}

static void print_tokenizer ( tokenizer* ptokenizer )
{
	int i;
	for (i=0 ; i < ptokenizer->nlists; i++ )
		print_tok_list(ptokenizer->tls[i]);
}

static char* fd_readline ( int fd, char* line, int maxsize )
{
	int i,ret ;
	memset(line, 0x00, maxsize); 
	for (i=0; i<maxsize; i++) {
		ret = read (fd, line + i, 1);
		if (ret <1) return NULL;
		if (line[i] =='\n') break;
	}
	line[i+1]=0;
	return line;
}

static int indent_count( int fd )
{
	int ret=0;
	char t;
	read ( fd, &t, 1 );
	while ( t=='\t') {
		read ( fd, &t, 1 );
		ret++;
	}

	// Posiciono a la primera diferent.
	lseek ( fd, (off_t)-1, SEEK_CUR );

	return ret;
}
#if 0
// XXX should be deprecated ?
int binparse_add_search(struct r_search_binparse_t *t, int id)
{
	char *token;
	char *mask;
	char tmp[128];
	
	snprintf(tmp, 127, "SEARCH[%d]", id);
	token = getenv(tmp);
	snprintf(tmp, 127, "MASK[%d]", id);
	mask  = getenv(tmp);

	return binparse_add(t, token, mask);
}
#endif



#endif
#endif
#endif

