// included from p/debug_native.c
// splitted for better reading/cleaning up

static const char *r_debug_native_reg_profile(RDebug *dbg) {
#if __linux__
/*  __
 -=(o '.
    \.-.\
    /|  \\
    '|  ||
     _\_):,_
*/
#if __arm__
#include "reg/linux-arm.h"
#elif __arm64__ || __aarch64__
#include "reg/linux-arm64.h"
#elif __MIPS__ || __mips__
#include "reg/linux-mips.h"
#elif (__i386__ || __x86_64__)
	if (dbg->bits & R_SYS_BITS_32) {
#	if __x86_64__
#	include "reg/linux-x64-32.h"
#	else
#	include "reg/linux-x86.h"
#	endif
	} else {
#	include "reg/linux-x64.h"
	}
#else
#error "Unsupported Linux CPU"
#endif


#elif __WINDOWS__
/*_______
 |   |   |
 |___|___|
 |   |   |
 |___|___|
*/
	if (dbg->bits & R_SYS_BITS_64) {
#include "reg/windows-x64.h"
	} else {
#include "reg/windows-x86.h"
	}
#elif (__OpenBSD__ || __NetBSD__)
/*                           __.--..__
       \-/-/-/    _ __  _.--'  _.--'
  _  \'       \   \\  ''      `------.__
  \\/      __)_)   \\      ____..---'
  //\       o  o    \\----'
     / <_/      3    \\
      \_,_,__,_/      \\
*/
#if __i386__
#include "reg/netbsd-x86.h"
#elif __x86_64__
#include "reg/netbsd-x64.h"
#else
#error "Unsupported BSD architecture"
#endif

#elif __KFBSD__ || __FreeBSD__
/*
    /(       ).
    \ \__   /|
    /  _ '-/ |
   (/\/ |    \
   / /  | \   )
   O O _/     |
  (__)  __   /
    \___/   /
      `----'
*/
#if __i386__ || __i386
#include "reg/kfbsd-x86.h"
#elif __x86_64__ || __amd64__
#include "reg/kfbsd-x64.h"
#else
#error "Unsupported BSD architecture"
#endif

#else
#warning Unsupported Kernel
	return NULL;
#endif
}
