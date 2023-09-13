/* radare - LGPL - Copyright 2009-2023 - pancake, nibble */

#define R_BIN_ELF64 1
#include "bin_elf.inc.c"


static bool check(RBinFile *bf, RBuffer *b) {
	ut8 buf[5] = {0};
	if (r_buf_size (b) > 4) {
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "\x7F\x45\x4c\x46\x02", 5)) {
			return true;
		}
	}
	return false;
}

extern struct r_bin_dbginfo_t r_bin_dbginfo_elf64;
extern struct r_bin_write_t r_bin_write_elf64;

static ut64 get_elf_vaddr64(RBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	//NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
	struct Elf_(obj_t)* obj = bf->bo->bin_obj;
	return obj->baddr - obj->boffset + vaddr;
}

static void headers64(RBinFile *bf) {
#define p bf->rbin->cb_printf
	p ("0x00000000  ELF64       0x%08x\n", r_buf_read_le32_at (bf->buf, 0));
	p ("0x00000010  Type        0x%04x\n", r_buf_read_le16_at (bf->buf, 0x10));
	p ("0x00000012  Machine     0x%04x\n", r_buf_read_le16_at (bf->buf, 0x12));
	p ("0x00000014  Version     0x%08x\n", r_buf_read_le32_at (bf->buf, 0x14));
	p ("0x00000018  Entrypoint  0x%08"PFMT64x"\n", r_buf_read_le64_at (bf->buf, 0x18));
	p ("0x00000020  PhOff       0x%08"PFMT64x"\n", r_buf_read_le64_at (bf->buf, 0x20));
	p ("0x00000028  ShOff       0x%08"PFMT64x"\n", r_buf_read_le64_at (bf->buf, 0x28));
	p ("0x00000030  Flags       0x%08x\n", r_buf_read_le32_at (bf->buf, 0x30));
	p ("0x00000034  EhSize      %d\n", r_buf_read_le16_at (bf->buf, 0x34));
	p ("0x00000036  PhentSize   %d\n", r_buf_read_le16_at (bf->buf, 0x36));
	p ("0x00000038  PhNum       %d\n", r_buf_read_le16_at (bf->buf, 0x38));
	p ("0x0000003a  ShentSize   %d\n", r_buf_read_le16_at (bf->buf, 0x3a));
	p ("0x0000003c  ShNum       %d\n", r_buf_read_le16_at (bf->buf, 0x3c));
	p ("0x0000003e  ShrStrndx   %d\n", r_buf_read_le16_at (bf->buf, 0x3e));
}

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 p_ehdrsz, p_phdrsz;
	ut64 filesize, code_va, code_pa, phoff;
	ut16 ehdrsz, phdrsz;
	ut64 baddr = 0x400000LL;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)(x),y)
#define Q(x) r_buf_append_ut64(buf,x)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)(y),z)

	/* Ehdr */
	B ("\x7F" "ELF" "\x02\x01\x01\x00", 8); // e_ident (ei_class = ELFCLASS64)
	Z (8);
	H (2); // e_type = ET_EXEC
	H (62); // e_machine = EM_X86_64
	D (1); // e_version = EV_CURRENT
	p_start = r_buf_size (buf);
	Q (-1); // e_entry = 0xFFFFFFFF
	p_phoff = r_buf_size (buf);
	Q (-1); // e_phoff = 0xFFFFFFFF
	Q (0);  // e_shoff = 0xFFFFFFFF
	D (0);  // e_flags
	p_ehdrsz = r_buf_size (buf);
	H (-1); // e_ehsize = 0xFFFFFFFF
	p_phdrsz = r_buf_size (buf);
	H (-1); // e_phentsize = 0xFFFFFFFF
	H (1);  // e_phnum
	H (0);  // e_shentsize
	H (0);  // e_shnum
	H (0);  // e_shstrndx

	/* Phdr */
	p_phdr = r_buf_size (buf);
	D (1); // p_type
	D (5);  // p_flags = PF_R | PF_X
	Q (0);  // p_offset
	p_vaddr = r_buf_size (buf);
	Q (-1); // p_vaddr = 0xFFFFFFFF
	p_paddr = r_buf_size (buf);
	Q (-1); // p_paddr = 0xFFFFFFFF
	p_fs = r_buf_size (buf);
	Q (-1); // p_filesz
	p_fs2 = r_buf_size (buf);
	Q (-1); // p_memsz
	Q (0x200000); // p_align

	/* Calc fields */
	ehdrsz = p_phdr;
	phdrsz = r_buf_size (buf) - p_phdr;
	code_pa = r_buf_size (buf);
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

	if (data && datalen > 0) {
		R_LOG_WARN ("DATA section not support for ELF yet");
		B (data, datalen);
	}
	return buf;
}

RBinPlugin r_bin_plugin_elf64 = {
	.meta = {
		.name = "elf64",
		.desc = "elf64 bin plugin",
		.license = "LGPL3",
	},
	.get_sdb = &get_sdb,
	.check = &check,
	.load = &load,
	.destroy = &destroy,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
#if R2_590
	.sections_vec = &sections_vec,
#else
	.sections = &sections,
#endif
	.symbols_vec = symbols_vec,
	.imports = &imports,
	.minstrlen = 4,
	.info = &info,
	.fields = &fields,
	.header = &headers64,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.patch_relocs = &patch_relocs,
	.dbginfo = &r_bin_dbginfo_elf64,
	.create = &create,
	.write = &r_bin_write_elf64,
	.get_vaddr = &get_elf_vaddr64,
	.regstate = &regstate,
	.maps = &maps,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf64,
	.version = R2_VERSION
};
#endif
