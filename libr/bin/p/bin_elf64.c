/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

#define R_BIN_ELF64 1
#include "bin_elf.c"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length >= 5)
		if (!memcmp (buf, "\x7F\x45\x4c\x46\x02", 5))
			return R_TRUE;
	return R_FALSE;
}

extern struct r_bin_dbginfo_t r_bin_dbginfo_elf64;
extern struct r_bin_write_t r_bin_write_elf64;

static ut64 get_elf_vaddr64 (RBinFile *arch, ut64 baddr, ut64 paddr, ut64 vaddr) {
	//NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;
	return obj->baddr - obj->boffset + vaddr;

}

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

RBinPlugin r_bin_plugin_elf64 = {
	.name = "elf64",
	.desc = "elf64 bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.minstrlen = 4,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = &r_bin_dbginfo_elf64,
	.create = &create,
	.write = &r_bin_write_elf64,
	.get_vaddr = &get_elf_vaddr64,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf64
};
#endif
