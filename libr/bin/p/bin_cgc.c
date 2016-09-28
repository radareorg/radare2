/* radare - LGPL - Copyright 2009-2015 - ret2libc, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#define R_BIN_CGC 1
#include "bin_elf.c"

extern struct r_bin_dbginfo_t r_bin_dbginfo_elf;
extern struct r_bin_write_t r_bin_write_elf;

static int check_bytes(const ut8 *buf, ut64 length) {
	return buf && length > 4 && memcmp (buf, CGCMAG, SCGCMAG) == 0
		&& buf[4] != 2;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 filesize, code_va, code_pa, phoff;
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_ehdrsz, p_phdrsz;
	ut16 ehdrsz, phdrsz;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 baddr = 0x8048000;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	B ("\x7F" "CGC" "\x01\x01\x01\x43", 8);
	Z (8);
	H (2); // ET_EXEC
	H (3); // e_machne = EM_I386

	D (1);
	p_start = buf->length;
	D (-1); // _start
	p_phoff = buf->length;
	D (-1); // phoff -- program headers offset
	D (0);  // shoff -- section headers offset
	D (0);  // flags
	p_ehdrsz = buf->length;
	H (-1); // ehdrsz
	p_phdrsz = buf->length;
	H (-1); // phdrsz
	H (1);
	H (0);
	H (0);
	H (0);
	// phdr:
	p_phdr = buf->length;
	D (1);
	D (0);
	p_vaddr = buf->length;
	D (-1); // vaddr = $$
	p_paddr = buf->length;
	D (-1); // paddr = $$
	p_fs = buf->length;
	D (-1); // filesize
	p_fs2 = buf->length;
	D (-1); // filesize
	D (5); // flags
	D (0x1000); // align

	ehdrsz = p_phdr;
	phdrsz = buf->length - p_phdr;
	code_pa = buf->length;
	code_va = code_pa + baddr;
	phoff = 0x34;//p_phdr ;
	filesize = code_pa + codelen + datalen;

	W (p_start, &code_va, 4);
	W (p_phoff, &phoff, 4);
	W (p_ehdrsz, &ehdrsz, 2);
	W (p_phdrsz, &phdrsz, 2);

	code_va = baddr; // hack
	W (p_vaddr, &code_va, 4);
	code_pa = baddr; // hack
	W (p_paddr, &code_pa, 4);

	W (p_fs, &filesize, 4);
	W (p_fs2, &filesize, 4);

	B (code, codelen);

	if (data && datalen>0) {
		//ut32 data_section = buf->length;
		eprintf ("Warning: DATA section not support for ELF yet\n");
		B (data, datalen);
	}
	return buf;
}

RBinPlugin r_bin_plugin_cgc = {
	.name = "cgc",
	.desc = "CGC format r_bin plugin",
	.license = "LGPL3",
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
	.minstrlen = 4,
	.imports = &imports,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = &r_bin_dbginfo_elf,
	.create = &create,
	.patch_relocs = &patch_relocs,
	.write = &r_bin_write_elf,
};
