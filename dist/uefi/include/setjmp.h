/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SETJMP_H
#define _SETJMP_H

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long long jmp_buf[8];
typedef jmp_buf sigjmp_buf;

int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val) __attribute__((noreturn));
#define sigsetjmp(env, savesigs) setjmp (env)
#define siglongjmp(env, val) longjmp (env, val)
#define _setjmp setjmp
#define _longjmp longjmp

#ifdef __cplusplus
}
#endif

#endif /* _SETJMP_H */
