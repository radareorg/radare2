/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#define R_BIN_ELF64 1
#include "bin_elf.c"

static int check(RBinArch *arch) {
	if (!memcmp (arch->buf->buf, "\x7F\x45\x4c\x46\x02", 5))
		return R_TRUE;
	return R_FALSE;
}

extern struct r_bin_meta_t r_bin_meta_elf64;
extern struct r_bin_write_t r_bin_write_elf64;

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 p_ehdrsz, p_phdrsz;
	ut64 filesize, code_va, code_pa, phoff;
	ut16 ehdrsz, phdrsz;
	ut64 baddr = 0x400000LL;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define Q(x) r_buf_append_ut64(buf,x)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)

	/* Ehdr */
	B ("\x7F" "ELF" "\x02\x01\x01\x00", 8); // e_ident (ei_class = ELFCLASS64)
	Z (8);
	H (2); // e_type = ET_EXEC
	H (62); // e_machine = EM_X86_64
	D (1); // e_version = EV_CURRENT
	p_start = buf->length;
	Q (-1); // e_entry = 0xFFFFFFFF
	p_phoff = buf->length;
	Q (-1); // e_phoff = 0xFFFFFFFF
	Q (0);  // e_shoff = 0xFFFFFFFF
	D (0);  // e_flags
	p_ehdrsz = buf->length;
	H (-1); // e_ehsize = 0xFFFFFFFF
	p_phdrsz = buf->length;
	H (-1); // e_phentsize = 0xFFFFFFFF
	H (1);  // e_phnum
	H (0);  // e_shentsize
	H (0);  // e_shnum
	H (0);  // e_shstrndx

	/* Phdr */
	p_phdr = buf->length;
	D (1);  // p_type
	D (5);  // p_flags = PF_R | PF_X
	Q (0);  // p_offset 
	p_vaddr = buf->length;
	Q (-1); // p_vaddr = 0xFFFFFFFF
	p_paddr = buf->length;
	Q (-1); // p_paddr = 0xFFFFFFFF
	p_fs = buf->length;
	Q (-1); // p_filesz
	p_fs2 = buf->length;
	Q (-1); // p_memsz
	Q (0x200000); // p_align

	/* Calc fields */
	ehdrsz = p_phdr;
	phdrsz = buf->length - p_phdr;
	code_pa = buf->length;
	code_va = code_pa + baddr;
	phoff = p_phdr;
	filesize = code_pa + codelen + datalen;

	/* Write fields */
	W (p_start, &code_va, 8);
	W (p_phoff, &phoff, 8);
	W (p_ehdrsz, &ehdrsz, 2);
	W (p_phdrsz, &phdrsz, 2);
	W (p_fs, &filesize, 8);
	W (p_fs2, &filesize, 8);

	W (p_vaddr, &baddr, 8);
	W (p_paddr, &baddr, 8);

	/* Append code */
	B (code, codelen);

	if (data && datalen>0) {
		eprintf ("Warning: DATA section not support for ELF yet\n");
		B (data, datalen);
	}
	return buf;
}

struct r_bin_plugin_t r_bin_plugin_elf64 = {
	.name = "elf64",
	.desc = "elf64 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.libs = &libs,
	.relocs = &relocs,
	.meta = &r_bin_meta_elf64,
	.create = &create,
	.write = &r_bin_write_elf64,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf64
};
#endif
