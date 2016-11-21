/*radare - LGPL - Copyright 2016 - oddcoder */
//dual buffer used as fast way to access large text files

#ifndef DUALBUF_H
#define DUALBUF_H

#define BUF_MAX 5
enum RDualBuf_modes {
	RDualBuf_dual,
	RDualBuf_single
};
typedef struct rdualbuffer {
	ut8 mode;  // 0 = dualbuf 1 = singlebuf
	FILE *file;
	char *buf1;
	char *buf1_end;
	char *buf2;
	char *buf2_end;
	ut64 lsize; // size of buffer of which cp is in it
	char *cp; //current pointer
} RDualBuf;
R_API int r_dualbuf_single_init(RDualBuf *buf, char *s);
R_API int r_dualbuf_init(RDualBuf *buf, FILE *f);
R_API void r_dualbuf_destroy(RDualBuf *b);
R_API char *r_dualbuf_current_charp(RDualBuf *b);
R_API char *r_dualbuf_next_charp(RDualBuf *b);
R_API char *r_dualbuf_retrieve_tok(RDualBuf *b, char *start, char *end);
R_API  char *r_dualbuf_prev_charp(RDualBuf *b);
#endif
