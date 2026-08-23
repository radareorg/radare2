/* radare2 efi application entrypoint - LGPL - Copyright 2026 - pancake */

#define GNU_EFI_USE_MS_ABI 1
#include <efi.h>

#include <r_core.h>
#include <r_util/libc.h>

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab) {
	r_uefi_init (image, systab);
	printf ("radare2 " R2_VERSION " on UEFI\n");
	RCore *core = r_core_new ();
	if (!core) {
		return EFI_OUT_OF_RESOURCES;
	}
	r_core_cmd0 (core, "o malloc://4096");
	r_core_prompt_loop (core);
	r_core_free (core);
	return EFI_SUCCESS;
}
