/*
    mreplace.c - Experimental PERL alike "search & replace" 
                 functions by Mandingo, Copyleft, 2009-02-20
*/

#include <r_types.h>
#if __UNIX__

#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mmemory.h"
#include "mreplace.h"

#if !defined DEBUG2
	#define DEBUG2 0
#endif

#if defined LIB
	#include "m2c_api20.h"
#else
	#define DBG(func,...) "";
#endif

#define CHECKS_CHUNCK_SIZE  1024
#define CHECKS_CHUNCK_COUNT 6

int matchs(const char *string, char *pattern) {
	int    status;
	regex_t    re;
	if (regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB) != 0) return(0); 
	status = regexec(&re, string, (size_t) 0, NULL, 0);
	regfree(&re);
	return status?0:1;
}

void sreplace(char *s,char *orig,char *rep,char multi,long dsize){
	char *p;
	memChunk *buffer,*string,*result; 
  
  	if(!(p=strstr(s, orig))) return;

	buffer=memReserve(dsize);
	string=memString(s);

	memCopy(buffer, string);
	
  	snprintf(buffer->address+(p-s), buffer->size-(p-s),"%s%s", rep, p+strlen(orig));

	result=memString(buffer->address);

  	strcpy(s,result->address);	//unsafe	

	memFree(string);
	memFree(result);
	memFree(buffer);
}

char *mreplace(char *string, char *se,char *rep) {
    	int    		status,i;
	char		noMatch=0;
    	regex_t    	re;
	size_t     	nmatch = 16;
	regmatch_t 	pm[nmatch];
	unsigned long	offset = 0;
	char		field[16];
	char		*res;
	memChunk	*search,*temp,*found,*ffound;

	if(!string)        	return "";
	if(!strlen(se)) 	return string;
	if(!strcmp(se,rep)) 	return string;

	temp   = memStringReserve(string,INPUTLINE_BUFFER_REPLACE_SIZE);
	search = memStringReserve(se,INPUTLINE_BUFFER_REPLACE_SIZE);

	sreplace(search->address,"\\d","[0-9]",1,INPUTLINE_BUFFER_REPLACE_SIZE);

#if MDEBUG2
	sData=strdup(string);
	DBG("mreplace(string,se,re)","string  : %s",sData);
	DBG("mreplace(string,se,re)","search  : %s",search->address);
	DBG("mreplace(string,se,re)","replace : %s",rep);
#endif

    	if(regcomp(&re, search->address, REG_EXTENDED) != 0) 
		if(regcomp(&re, search->address, REG_EXTENDED<<1)) 	noMatch=1;
    	if((status = regexec(&re, string, nmatch, pm, 0))) 		noMatch=1;

	if(noMatch){
		memFree(temp);
		memFree(search);
		return (char*)string; 
	}

	found  = memReserve(INPUTLINE_BUFFER_REPLACE_SIZE);
	ffound = memReserve(INPUTLINE_BUFFER_REPLACE_SIZE);
	while(!status){
		offset=strlen(temp->address)-strlen(string);
		snprintf(found->address, INPUTLINE_BUFFER_REPLACE_SIZE, "%.*s",
			(int)(size_t)(pm[0].rm_eo - pm[0].rm_so), &string[pm[0].rm_so]);//,&string[pm[0].rm_so]);
#if MDEBUG3
		printf("------->> found \"%s\" length => %d offset[%d]\n",
			found->address, strlen(temp->address),offset);
#endif
		sreplace(temp->address+offset,found->address,rep,0,INPUTLINE_BUFFER_REPLACE_SIZE-offset);
		for(i=1;i<nmatch;i++){
			snprintf(ffound->address,INPUTLINE_BUFFER_REPLACE_SIZE, "%.*s",
				(int)(size_t)(pm[i].rm_eo - pm[i].rm_so), &string[pm[i].rm_so]);//,&string[pm[i].rm_so]);
			snprintf(field,sizeof(field),"\\%d",i);
			if(strlen(ffound->address)) {
				sreplace(temp->address,field,ffound->address,1,INPUTLINE_BUFFER_REPLACE_SIZE);
			}else{
				sreplace(temp->address,field,"",1,INPUTLINE_BUFFER_REPLACE_SIZE);
				continue;
			}
#if MDEBUG3
			printf(">> subfound %2d  '%s' => '%s' length %d\n",
				i,
				ffound->address,
				temp->address,offset);
#endif
		}
	// it is unsigned!	if(offset<0) offset=-offset;
		if(*string && strlen(string+pm[0].rm_eo)) {
			string+=pm[0].rm_eo;
			status = regexec(&re, string, nmatch, pm, 0);
		}else{
			status=-1;
		}
	}
#if MDEBUG2
	DBG("mreplace(string,se,re)","result : %s",temp->address);
#endif
	res=strdup(temp->address);
	memFree(temp);
	memFree(search);
	memFree(found);
	memFree(ffound);
     	return res;
}

char *treplace(char *data,char *search,char *replace){
	char *newline,*p;

	memChunk *result,*line;
	//ulong resultAllocSize;

	if(!strlen(search))  return data;

#if MDEBUG2
	DBG("treplace(string,se,re)","string  : %s",data);
	DBG("treplace(string,se,re)","search  : %s",search);
	DBG("treplace(string,se,re)","replace : %s",replace);
#endif

	result = memReserve(INPUTLINE_BUFFER_REPLACE_SIZE);
	line   = memReserve(INPUTLINE_BUFFER_REPLACE_SIZE);
	
	p=data;
	while (sscanf(p,"%[^\n]",line->address)==1){
		if(p-data>strlen(data)) break;
		newline=mreplace(line->address,search,replace);

		memStrCat(result,newline);
		if (line->address && *(p+strlen(line->address))) memStrCat(result,"\n");
		else break;

		p+=strlen(line->address)+1;
	}
	p=strdup(result->address);
	memFree(result);
	memFree(line);
	return p;
}

//#if ! LIB
#if 0 

void doChecks(){
	char *checkBuffer,*checkresult,*sIn;
	long i,n,total,invalid=0;
	typedef struct {char *in,*s,*r,*out;} sCheck;
	sCheck checks[]={
		{"{{div.cOptions}}go {{tag.tag56}} {{get.link.parent.html}}/ edit {{tag.tag57}} / edit {{tag.tag58}} / rename {{tag.tag59}} / move {{tag.tag60}} / add {{tag.tag61}}{{get.delete.html}} / {{get.link.login.html}}{{enddiv}}", ".*(\\{\\{\\w+\\.\\w+(\\.\\w+)?\\}\\}).*","\\1","{{get.delete.html}}"},
		{"abracadabra",	"a",			"b",				"bbrbcbdbbrb"},
		{"a1a2a3a4a5a",	"\\d",			"_",				"a_a_a_a_a_a"},
		{"z1b4a5a",	"(\\w)",		"[\\1]",			"[z][1][b][4][a][5][a]"},
		{"farooeboar",	"(.)..(..).(.).",	"\\1\\2\\3",			"foobar"},
		{"file.c",	"(([^\\.]+)\\.(.+))",	"[\\1] name=\\2 ext=\\3",	"[file.c] name=file ext=c"},
		{"helloworld",	"([e-o])",			"_\\1_",		"_h__e__l__l__o_w_o_r_l_d"},
		{"I' a {{get.tag}}",".*(\\{\\{\\w+\\.\\w+(\\.\\w+)?\\}\\}).*","found tag  \"\\1\"","found tag  \"{{get.tag}}\""},
		{"get.param","(\\w+?)\\..+","method is  \"\\1\"","method is  \"get\""},
		{"get.param","[^\\.]+\\.([^\\.]+).*","tagname is \"\\1\"","tagname is \"param\""}
	};
	total=sizeof(checks)/sizeof(checks[0])-1;

	if((checkBuffer=(char*)malloc(CHECKS_CHUNCK_COUNT*CHECKS_CHUNCK_SIZE))==NULL){
		perror("malloc");
	}else{
		memset(checkBuffer,0,CHECKS_CHUNCK_COUNT*CHECKS_CHUNCK_SIZE);
	}

	fprintf(stdout,"  [+] Performing several replacements to check consistence ");
	for(n=0;n<100;n++){
		if(!(n%25)){
			printf(".");
			fflush(stdout);
		}
		for(i=0;i<total;i++){
			checkresult=treplace(checks[i].in,checks[i].s,checks[i].r);
			sIn=strdup(checks[i].in);
			if(strlen(sIn)>20) memcpy(sIn+15," ...\0",5);
			if(strcmp(checkresult,checks[i].out)){
				fprintf(stderr,"\r[%d/%d] %-20s s: %-30s r: %-20s  =>  %-25s ",i+1,total,sIn,checks[i].s,checks[i].r,checkresult);
				fprintf(stdout," ERR :(\n");
				exit(0);
			}else{
				if(!n){
					fprintf(stderr,"\r[%d/%d] %-20s s: %-30s r: %-20s  =>  %-25s 	",i+1,total,sIn,checks[i].s,checks[i].r,checkresult);
					fprintf(stdout," OK :)\n");
				}
			}
		}
	}

	for(n=1;n<=CHECKS_CHUNCK_COUNT;n+=1+CHECKS_CHUNCK_COUNT/10){
		fprintf(stdout,"\r[ + ] Checking stability for different input sizes consistence %d bytes, memory allocated: %d bytes",n*CHECKS_CHUNCK_COUNT*CHECKS_CHUNCK_SIZE,memAllocated());
		fflush(stdout);
		memset(checkBuffer,'.',n*CHECKS_CHUNCK_SIZE-1);
		checkBuffer[n*CHECKS_CHUNCK_SIZE]=0;
		mreplace(checkBuffer,"\\.","_");
		treplace(checkBuffer,"_",".");
	}
	fprintf(stdout,"\n");
	fprintf(stdout,"[ m ] Memory allocated final: %d bytes\n",memAllocated());
}

/* 
	builds a binary for command line "search & replace" tests
*/
int main(char argc,char **argv){
	if(argc==4 && strlen(argv[2])){
#if MDEBUG2
		printf("Input string: %s, length %d, search %s, replace %s\n",argv[1],strlen(argv[1]),argv[2],argv[3]);
#endif		
		fprintf(stdout,"%s\n",treplace(argv[1],argv[2],argv[3]));
	}else{
		fprintf(stdout,	"Perl alike \"search & replace\" v1.01 by Mandingo, Copyleft, 2009\n");
		doChecks();
		fprintf(stdout,	"Usage: %s \"<text>\" \"<search>\" \"<replace>\"\n",argv[0]);
		
	}	

	return 1;
}
#endif
#else
#warning NOT SUPPPORTED FOR THIS PLATFORM
#endif
