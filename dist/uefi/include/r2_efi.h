/* radare2 - LGPL - gnu-efi headers for the UEFI build */

#ifndef R2_EFI_H
#define R2_EFI_H

#define GNU_EFI_USE_MS_ABI 1

#define wchar_t unsigned short
#include <efi.h>
#undef wchar_t

_Static_assert (sizeof (CHAR16) == 2, "CHAR16 must be 16 bit");
_Static_assert (sizeof (BOOLEAN) == 1, "BOOLEAN must be 8 bit");
_Static_assert (sizeof (UINTN) == sizeof (void *), "UINTN must be pointer sized");
_Static_assert (sizeof (EFI_GUID) == 16, "EFI_GUID must be 16 bytes");
_Static_assert (sizeof (EFI_INPUT_KEY) == 4, "EFI_INPUT_KEY must be 4 bytes");

#endif
