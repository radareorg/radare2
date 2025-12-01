
#ifndef CLANGD_PREAMBLE
#define CLANGD_PREAMBLE

#include <r_core.h>
#include <r_util/r_json.h>
#include <r_vec.h>
#if R2__UNIX__
#include <sys/utsname.h>
#ifndef __wasi__
#include <pwd.h>
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#if !TARGET_OS_IPHONE
#include <crt_externs.h>
#endif
#endif
#endif

int bb_cmpaddr(const void *_a, const void *_b);

#endif
