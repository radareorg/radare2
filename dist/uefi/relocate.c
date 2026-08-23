/* radare2 efi self-relocation - LGPL - Copyright 2026 - pancake */

/* The gnu-efi _relocate assumes the linker wrote the implicit addends into
 * the relocated slots, which bfd ld does but lld does not. This replacement
 * applies the R_X86_64_RELATIVE relocations using the explicit RELA addends,
 * so the EFI binary can be linked with clang and lld. It runs before any
 * relocation is applied: it must only touch its own arguments and locals. */

typedef unsigned long long r2efi_u64;
typedef long long r2efi_i64;

typedef struct {
	r2efi_i64 d_tag;
	r2efi_u64 d_val;
} R2EfiDyn;

typedef struct {
	r2efi_u64 r_offset;
	r2efi_u64 r_info;
	r2efi_i64 r_addend;
} R2EfiRela;

#define R2EFI_DT_NULL 0
#define R2EFI_DT_RELA 7
#define R2EFI_DT_RELASZ 8
#define R2EFI_DT_RELAENT 9
#define R2EFI_R_X86_64_RELATIVE 8

r2efi_u64 _relocate(r2efi_u64 ldbase, R2EfiDyn *dyn, void *image, void *systab) {
	(void)image;
	(void)systab;
	R2EfiRela *rela = 0;
	r2efi_u64 relsz = 0;
	r2efi_u64 relent = sizeof (R2EfiRela);
	int i;
	for (i = 0; dyn[i].d_tag != R2EFI_DT_NULL; i++) {
		if (dyn[i].d_tag == R2EFI_DT_RELA) {
			rela = (R2EfiRela *)(dyn[i].d_val + ldbase);
		} else if (dyn[i].d_tag == R2EFI_DT_RELASZ) {
			relsz = dyn[i].d_val;
		} else if (dyn[i].d_tag == R2EFI_DT_RELAENT) {
			relent = dyn[i].d_val;
		}
	}
	if (!rela || !relent) {
		return 0;
	}
	while (relsz >= relent) {
		if ((rela->r_info & 0xffffffff) == R2EFI_R_X86_64_RELATIVE) {
			r2efi_u64 *addr = (r2efi_u64 *)(ldbase + rela->r_offset);
			*addr = ldbase + (r2efi_u64)rela->r_addend;
		}
		rela = (R2EfiRela *)((char *)rela + relent);
		relsz -= relent;
	}
	return 0;
}
