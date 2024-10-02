#ifndef BUFFER_H
#define BUFFER_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*BufferOp)(int, const char *, int);

typedef struct buffer {
	char *x;
	unsigned int p;
	unsigned int n;
	int fd;
	BufferOp op;
} buffer;

#define BUFFER_INIT(op,fd,buf,len) { (buf), 0, (len), (fd), (op) }
#define BUFFER_INSIZE 8192
#define BUFFER_OUTSIZE 8192

#if 0
void buffer_initialize(buffer *,BufferOp,int,char *,unsigned int);

int buffer_flush(buffer *);
int buffer_put(buffer *,const char *,unsigned int);
int buffer_putalign(buffer *,const char *,unsigned int);
int buffer_putflush(buffer *,const char *,unsigned int);
int buffer_get(buffer *,char *,unsigned int);
int buffer_bget(buffer *,char *,unsigned int);
int buffer_feed(buffer *);

char *buffer_peek(buffer *);
void buffer_seek(buffer *,unsigned int);

#endif

#define buffer_PUTC(s,c) \
  ( ((s)->n != (s)->p) \
    ? ( (s)->x[(s)->p++] = (c), 0 ) \
    : buffer_put((s),&(c),1) \
  )

#define buffer_PEEK(s) ( (s)->x + (s)->n )
#define buffer_SEEK(s,len) ( ( (s)->p -= (len) ) , ( (s)->n += (len) ) )

#define buffer_GETC(s,c) \
  ( ((s)->p > 0) \
    ? ( *(c) = (s)->x[(s)->n], buffer_SEEK((s),1), 1 ) \
    : buffer_get((s),(c),1) \
  )

int buffer_copy(buffer *,buffer *);

// WTF GLOBALS
#if 0
extern buffer *buffer_0;
extern buffer *buffer_0small;
extern buffer *buffer_1;
extern buffer *buffer_1small;
extern buffer *buffer_2;
#endif

#ifdef __cplusplus
}
#endif

#endif
