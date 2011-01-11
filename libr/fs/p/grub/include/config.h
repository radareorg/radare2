#ifndef _FOO_
#define _FOO_

#include <config-util.h>
#define GRUB_UTIL
#define SIZEOF_VOID_P 4
#define SIZEOF_LONG 4
#define GRUB_FILE "/tmp/"
#define NESTED_FUNC_ATTR
#undef WORDS_BIGENDIAN
//#define Elf_Sym void
#define grub_cpu_idle() //
#define grub_dl_ref(x) //
#define grub_dl_unref(x) //
#define grub_dl_unload_unneeded(x) //
#define grub_malloc(x) malloc(x)
#define grub_realloc(x,y) realloc(x,y)
#define grub_free(x) free(x)
#define grub_zalloc(x) calloc(1,x)

#include <stdlib.h>
#endif
