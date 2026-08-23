/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _BITS_PTHREADTYPES_H
#define _BITS_PTHREADTYPES_H

#include <stddef.h>

typedef unsigned long pthread_t;
typedef struct { int __v; } pthread_mutex_t;
typedef struct { int __v; } pthread_mutexattr_t;
typedef struct { int __v; } pthread_cond_t;
typedef struct { int __v; } pthread_condattr_t;
typedef struct { int __v; } pthread_rwlock_t;
typedef struct { int __v; } pthread_rwlockattr_t;
typedef struct { size_t stacksize; } pthread_attr_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;

#endif /* _BITS_PTHREADTYPES_H */
