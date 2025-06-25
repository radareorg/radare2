/* radare - LGPL - Copyright 2006-2024 - esteve, pancake */

#include <r_util.h>
#include <r_util/r_print.h>
#include <r_search.h>

#define CTXMINB 5
#define BSIZE (1024 * 1024)
#define MAX_PATLEN 1024

typedef struct _fnditem {
	unsigned char str[MAX_PATLEN];
	void* next;
} fnditem;

static fnditem* init_fi(void) {
	fnditem* n = R_NEW0 (fnditem);
	n->next = NULL;
	return n;
}

static void fini_fi(fnditem* fi) {
	fnditem *fu;
	fu = fi;
	while (fi->next) {
		fu = fi;
		fi = fi->next;
		free (fu);
		fu = NULL;
	}
	free (fu);
}

static void add_fi(fnditem* n, unsigned char* blk, int patlen) {
	fnditem* p;
	for (p = n; p->next; p = p->next) {
		;
	}
	p->next = R_NEW0 (fnditem);
	p = p->next;
	memcpy (p->str, blk, patlen);
	p->next = NULL;
}

static int is_fi_present(fnditem* n, unsigned char* blk , int patlen) {
	fnditem* p;
	for (p = n; p->next; p = p->next) {
		if (!memcmp (blk, p->str, patlen)) {
			return true;
		}
	}
	return false;
}

R_IPI bool search_pattern(RSearch *s, ut64 from, ut64 to) {
	R_RETURN_VAL_IF_FAIL (s, false);
	ut8 block[BSIZE+MAX_PATLEN], sblk[BSIZE+MAX_PATLEN + 1];
	ut64 addr, bact, bytes, intaddr, rb, bproc = 0;
	int nr,i, moar = 0, pcnt, cnt = 0, k = 0;
	int patlen = s->pattern_size;
	fnditem* root;

	eprintf ("Searching patterns between 0x%08"PFMT64x" and 0x%08"PFMT64x"\n", from, to);
	if (patlen < 1 || patlen > MAX_PATLEN) {
		eprintf ("Invalid pattern length (must be > 1 and < %d)\n", MAX_PATLEN);
		return false;
	}
	bact = from;
	bytes = to;
	// bytes += bact;
	root = init_fi ();
	pcnt = -1;
	// bact = from
	// bytes = to
	// bproc = from2
	while (bact < bytes) {
		addr = bact;
#if 0
		if (r_print_is_interrupted ()) {
			break;
		}
#endif
		bproc = bact + patlen ;
		nr = ((bytes - bproc) < BSIZE)?(bytes - bproc):BSIZE;
		rb = s->iob.read_at (s->iob.io, addr, sblk, nr);
		sblk[patlen] = 0;

		intaddr = bact;
		cnt = 0;
		while (bproc < bytes) {
			// TODO: handle ^C here
			nr = ((bytes - bproc) < BSIZE)?(bytes - bproc):BSIZE;
			nr += (patlen - (nr % patlen)); // tamany de bloc llegit multiple superior de tamany busqueda
			rb = s->iob.read_at (s->iob.io, bproc, block, nr);
			if (rb < 1) {
				break;
			}
			nr = rb;
			addr += nr;
			moar = 0;
			for (i = 0; i < nr; i++) {
				if (!memcmp (&block[i], sblk, patlen) && !is_fi_present (root, sblk, patlen)) {
					if (cnt == 0) {
						add_fi (root, sblk, patlen);
						pcnt++;
						eprintf ("\nbytes: %d: ", pcnt);
						for (k = 0; k < patlen; k++) {
							eprintf ("%02x", sblk[k]);
						}
						eprintf ("\nfound: %d: 0x%08"PFMT64x" ", pcnt, intaddr);
					}
					moar++;
					cnt++;
					eprintf ("0x%08"PFMT64x" ", bproc+i);
				}
			}
			if (moar > 0) {
				eprintf ("\ncount: %d: %d\n", pcnt, moar + 1);
			}
			bproc += rb;
		}
		bact += (moar > 0)? patlen: 1;
	}
	eprintf ("\n");
	fini_fi (root);
	return true;
}
