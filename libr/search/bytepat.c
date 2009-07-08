/* radare - LGPL - Copyright 2006-2009 esteve<eslack.org> */

#include "r_search.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define CTXMINB 5

#define BSIZE (1024*1024)

#define MAX_PATLEN 1024

/* XXX memory leak!!! malloc-ed data not free'd */

typedef struct _fnditem
{
	unsigned char str[MAX_PATLEN];
	void* next;
} fnditem;

#if 0
static fnditem* init_fi()
{
	fnditem* n;
	n = (fnditem*) malloc ( sizeof ( fnditem ) );
	n->next = NULL;
	return n;
}
#endif

static void add_fi ( fnditem* n, unsigned char* blk, int patlen )
{
	fnditem* p;

	for(p=n;p->next!=NULL;p=p->next);

	p->next = (fnditem*) malloc(sizeof(fnditem));
	p = p->next;

	memcpy(p->str, blk, patlen);
	p->next = NULL;
}

static int is_fi_present(fnditem* n, unsigned char* blk , int patlen)
{
	fnditem* p;
	for(p=n;p->next!=NULL; p=p->next) {
		if (!memcmp(blk, p->str, patlen))
			return 1;
	}
	return 0;
}

// XXX needs to be refactored
int do_byte_pat(int patlen) 
{
	unsigned char block[BSIZE+MAX_PATLEN];
	unsigned char sblk[MAX_PATLEN+1];
	static fnditem* root;
	ut64 bproc = 0;
	ut64 rb;
	//const char *str;
	int nr,i, moar;
	int pcnt, cnt=0, k=0;
	ut64 intaddr;
	/* end addr */
	//ut64 bytes =  (config.limit!=0)?(config.limit-config.seek):config.block_size;
//XXX bytes not defined
	ut64 bytes  = 0;
	ut64 bact = 0;
 	/* start addr */
	//ut64 bact = config.seek;
//XXX bact = curseek not defined

#if 0
	if (patlen < 1 || patlen > MAX_PATLEN) {
		eprintf("Invalid pattern length (must be > 1 and < %d)\n", MAX_PATLEN);
		return 0;
	}
	str = config_get("search.from");
	if (str&&str[0]) {
		bact = config_get_i("search.from");
		fprintf(stderr, "Searching from 0x%08llx\n", bact);
	}
	str = config_get("search.to");
	if (str&&str[0]) {
		bytes = config_get_i("search.to");
		fprintf(stderr, "Searching from 0x%08llx\n", bytes);
	}

	bytes += bact;

	root = init_fi();

	radare_controlc();
#endif

	pcnt = -1;
	//while ( !config.interrupted && bact < bytes ) {
	while ( bact < bytes ) {
	//	radare_seek ( bact , SEEK_SET );
		bproc = bact + patlen ;
//		read ( fd, sblk, patlen );
//XXX bytepattern should be used with a read callback
	//XXX	radare_read_at(bact, sblk, patlen);
		sblk[patlen]=0;

		intaddr = bact;
		cnt = 0;
		//while ( !config.interrupted && bproc < bytes ) {
		while ( bproc < bytes ) {
			//radare_controlc();
			nr = ((bytes-bproc) < BSIZE)?(bytes-bproc):BSIZE;
			nr = nr + ( patlen - (nr % patlen) ); // tamany de bloc llegit multiple superior de tamany busqueda
			//rb = read ( fd, block, nr );
			//rb = radare_read_at(bproc, block, nr);
//XXX
			moar = 0;
			for(i=0; i<nr; i++){
				if (!memcmp(&block[i], sblk, patlen) && !is_fi_present(root, sblk, patlen)){
					if (cnt == 0) {
						printf("\n");
						add_fi( root, sblk , patlen);
						pcnt++;
						printf("bytes:%d: ", pcnt);
						for(k = 0; k<patlen; k++)
							printf("%02x", sblk[k]);
						printf("\nfound:%d: 0x%08llx ", pcnt, intaddr);
					}
					moar++;
					cnt++;
					printf("0x%08llx ", bproc+i );
				}
			}
			if (moar>0) {
				printf("\ncount:%d: %d\n", pcnt, moar+1);
				fflush(stdout);
			}
			bproc += rb;
		}

		if (moar > 0) {
			bact += (ut64)patlen;
		} else bact++;
	}
	printf("\n");
	//radare_controlc_end();
	return 0;
}


/* -- */

int r_search_pattern_update(int patlen) 
{
	unsigned char block[BSIZE+MAX_PATLEN];
	unsigned char sblk[MAX_PATLEN+1];
	static fnditem* root;
	ut64 bproc = 0;
	ut64 rb;
	//const char *str;
	int nr,i, moar;
	int pcnt, cnt=0, k=0;
	ut64 intaddr;
	/* end addr */
	//ut64 bytes =  (config.limit!=0)?(config.limit-config.seek):config.block_size;
//XXX bytes not defined
	ut64 bytes  = 0;
	ut64 bact = 0;
 	/* start addr */
	//ut64 bact = config.seek;
//XXX bact = curseek not defined

#if 0
	if (patlen < 1 || patlen > MAX_PATLEN) {
		eprintf("Invalid pattern length (must be > 1 and < %d)\n", MAX_PATLEN);
		return 0;
	}
	str = config_get("search.from");
	if (str&&str[0]) {
		bact = config_get_i("search.from");
		fprintf(stderr, "Searching from 0x%08llx\n", bact);
	}
	str = config_get("search.to");
	if (str&&str[0]) {
		bytes = config_get_i("search.to");
		fprintf(stderr, "Searching from 0x%08llx\n", bytes);
	}

	bytes += bact;

	root = init_fi();

	radare_controlc();
#endif

	pcnt = -1;
	//while ( !config.interrupted && bact < bytes ) {
	while ( bact < bytes ) {
	//	radare_seek ( bact , SEEK_SET );
		bproc = bact + patlen ;
//		read ( fd, sblk, patlen );
//XXX bytepattern should be used with a read callback
	//XXX	radare_read_at(bact, sblk, patlen);
		sblk[patlen]=0;

		intaddr = bact;
		cnt = 0;
		//while ( !config.interrupted && bproc < bytes ) {
		while ( bproc < bytes ) {
			//radare_controlc();
			nr = ((bytes-bproc) < BSIZE)?(bytes-bproc):BSIZE;
			nr = nr + ( patlen - (nr % patlen) ); // tamany de bloc llegit multiple superior de tamany busqueda
			//rb = read ( fd, block, nr );
			//rb = radare_read_at(bproc, block, nr);
//XXX
			moar = 0;
			for(i=0; i<nr; i++){
				if (!memcmp(&block[i], sblk, patlen) && !is_fi_present(root, sblk, patlen)){
					if (cnt == 0) {
						printf("\n");
						add_fi( root, sblk , patlen);
						pcnt++;
						printf("bytes:%d: ", pcnt);
						for(k = 0; k<patlen; k++)
							printf("%02x", sblk[k]);
						printf("\nfound:%d: 0x%08llx ", pcnt, intaddr);
					}
					moar++;
					cnt++;
					printf("0x%08llx ", bproc+i );
				}
			}
			if (moar>0) {
				printf("\ncount:%d: %d\n", pcnt, moar+1);
				fflush(stdout);
			}
			bproc += rb;
		}

		if (moar > 0) {
			bact += (ut64)patlen;
		} else bact++;
	}
	printf("\n");
	//radare_controlc_end();
	return 0;
}
