/* Hacky way to bypass make(1) and waf(X) build */
#ifndef MKPFX
#define MKPFX ""
#endif
asm(".include \""MKPFX"../src/rasc/syscall.S\"");
