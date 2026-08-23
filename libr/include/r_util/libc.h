/* radare2 uefi libc bootstrap - LGPL - Copyright 2026 - pancake */

#ifndef R2_UTIL_LIBC_H
#define R2_UTIL_LIBC_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types_base.h>

#if R2_UEFI

/* The freestanding libc for UEFI targets lives in libr/util/uefi.c and the
 * declarations come from the dist/uefi/include headers used by the cross
 * build. An EFI application must call r_uefi_init() from its efi_main()
 * before using any radare2 api, so the shim can reach the boot services. */

R_API void r_uefi_init(void *image_handle, void *system_table);
R_API bool r_uefi_initialized(void);

#endif

#ifdef __cplusplus
}
#endif

#endif
