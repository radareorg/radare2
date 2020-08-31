#ifndef CONFIG_H
#define CONFIG_H

#define SDB_KEYSIZE 32
/* only available on linux, and some distros require -lrt */
#define USE_MONOTONIC_CLOCK 0

#if SDB_KEYSIZE == 32
#define SDB_KT ut32
#elif SDB_KEYSIZE == 64
#define SDB_KT ut64
#else
#error Invalid key size
#endif

#endif
