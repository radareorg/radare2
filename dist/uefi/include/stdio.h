#ifndef _STDIO_H
#define _STDIO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int unused;
} FILE;

#define NULL ((void *)0)
#define EOF  (-1)

#ifdef __cplusplus
}
#endif

#endif /* _STDIO_H */