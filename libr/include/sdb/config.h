#ifndef CONFIG_H
#define CONFIG_H

#define SDB_KEYSIZE 32

#if SDB_KEYSIZE == 32
#define SDB_KT ut32
#elif SDB_KEYSIZE == 64
#define SDB_KT ut64
#else
#error Invalid key size
#endif

#endif
