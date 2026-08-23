/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

/* no include guard: assert.h can be included multiple times with different NDEBUG */

#undef assert
#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
#define assert(expr) ((expr)? (void)0: __builtin_trap ())
#endif

#ifndef _ASSERT_H
#define _ASSERT_H
#define static_assert _Static_assert
#endif
