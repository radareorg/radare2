/* radare - LGPL - Copyright 2009-2019 - ret2libc, pancake */

#define R_BIN_CGC 1
#include "bin_elf.inc.c"

extern struct r_bin_dbginfo_t r_bin_dbginfo_elf;
extern struct r_bin_write_t r_bin_write_elf;

static bool check(RBinFile *bf, RBuffer *buf) {
	ut8 tmp[SCGCMAG + 1];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	return r > SCGCMAG && !memcmp (tmp, CGCMAG, SCGCMAG) && tmp[4] != 2;
}

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	ut32 filesize, code_va, code_pa, phoff;
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_ehdrsz, p_phdrsz;
	ut16 ehdrsz, phdrsz;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 baddr = 0x8048000;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)(x),y)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)(y),z)
#define WZ(x,y) p_tmp=r_buf_size (buf);Z(x);W(p_tmp,y,strlen(y))

	B ("\x7F" "CGC" "\x01\x01\x01\x43", 8);
	Z (8);
	H (2); // ET_EXEC
	H (3); // e_machne = EM_I386

	D (1);
	p_start = r_buf_size (buf);
	D (-1); // _start
	p_phoff = r_buf_size (buf);
	D (-1); // phoff -- program headers offset
	D (0);  // shoff -- section headers offset
	D (0);  // flags
	p_ehdrsz = r_buf_size (buf);
	H (-1); // ehdrsz
	p_phdrsz = r_buf_size (buf);
	H (-1); // phdrsz
	H (1);
	H (0);
	H (0);
	H (0);
	// phdr:
	p_phdr = r_buf_size (buf);
	D (1);
	D (0);
	p_vaddr = r_buf_size (buf);
	D (-1); // vaddr = $$
	p_paddr = r_buf_size (buf);
	D (-1); // paddr = $$
	p_fs = r_buf_size (buf);
	D (-1); // filesize
	p_fs2 = r_buf_size (buf);
	D (-1); // filesize
	D (5); // flags
	D (0x1000); // align

	ehdrsz = p_phdr;
	phdrsz = r_buf_size (buf) - p_phdr;
	code_pa = r_buf_size (buf);
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
		R_LOG_WARN ("DATA section not support for ELF yet");
		B (data, datalen);
	}
	return buf;
}

RBinPlugin r_bin_plugin_cgc = {
	.meta = {
		.name = "cgc",
		.desc = "CGC format r_bin plugin",
		.license = "LGPL3",
	},
	.get_sdb = &get_sdb,
	.load = load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols_vec = &symbols_vec,
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
	.regstate = regstate,
	.maps = maps,
};
