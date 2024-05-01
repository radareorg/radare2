
#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "asm.h"

#define PROG_STAT_OFILE		    0x0004
#define PROG_MODE_VERBOSE	  	0x0001
#define PROG_MODE_REL0  		  0x0002
#define PROG_MODE_IONAME      0x0004

ioreg *ioregtable;
int   ioreg_cnt;

typedef struct {
  uint32_t start_add;
  uint32_t ext_offset;
  uint32_t size;
  uint32_t line_index;
  const unsigned char *data;
} datablock;
