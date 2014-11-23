/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#define R_BIN_MACH064 1
#include "bin_mach0.c"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {

	if (buf && length > 4)
	if (!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
		!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
		return R_TRUE;
	return R_FALSE;
}

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut64 filesize, codeva, datava;
	ut32 ncmds, magiclen, headerlen;
	ut64 p_codefsz=0, p_codeva=0, p_codesz=0, p_codepa=0;
	ut64 p_datafsz=0, p_datava=0, p_datasz=0, p_datapa=0;
	ut64 p_cmdsize=0, p_entry=0, p_tmp=0;
	ut64 baddr = 0x100001000LL;
// TODO: baddr must be overriden with -b
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
#define Q(x) r_buf_append_ut64(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	/* MACH0 HEADER */
	// 32bit B ("\xce\xfa\xed\xfe", 4); // header
	B ("\xcf\xfa\xed\xfe", 4); // header
	D (7 | 0x01000000); // cpu type (x86) | ABI64
	//D (3); // subtype (i386-all)
	D(0x80000003); // unknown subtype issue
	D (2); // filetype (executable)

	ncmds = (data && datalen>0)? 3: 2;
	
	/* COMMANDS */
	D (ncmds); // ncmds
	p_cmdsize = buf->length;
	D (-1); // headsize // cmdsize?
	D (0);//0x85); // flags
	D (0); // reserved -- only found in x86-64

	magiclen = buf->length;

	/* TEXT SEGMENT */
	D (0x19);   // cmd.LC_SEGMENT_64
	//D (124+16+8); // sizeof (cmd)
	D (124+28); // sizeof (cmd)
	WZ (16, "__TEXT");
	Q (baddr); // vmaddr
	Q (0x1000); // vmsize XXX

	Q (0); // fileoff
	p_codefsz = buf->length;
	Q (-1); // filesize
	D (7); // maxprot
	D (5); // initprot
	D (1); // nsects
	D (0); // flags
	// define section
	WZ (16, "__text");
	WZ (16, "__TEXT");
	p_codeva = buf->length; // virtual address
	Q (-1);
	p_codesz = buf->length; // size of code (end-start)
	Q (-1);
	p_codepa = buf->length; // code - baddr
	D (-1); // offset, _start-0x1000);
	D (2); // align
	D (0); // reloff
	D (0); // nrelocs
	D (0); // flags
	D (0); // reserved1
	D (0); // reserved2
	D (0); // reserved3

	if (data && datalen>0) {
		/* DATA SEGMENT */
		D (0x19);   // cmd.LC_SEGMENT_64
		D (124+28); // sizeof (cmd)
		p_tmp = buf->length;
		Z (16);
		W (p_tmp, "__TEXT", 6); // segment name
//XXX must be vmaddr+baddr
		Q (0x2000); // vmaddr
//XXX must be vmaddr+baddr
		Q (0x1000); // vmsize
		Q (0); // fileoff
		p_datafsz = buf->length;
		Q (-1); // filesize
		D (6); // maxprot
		D (6); // initprot
		D (1); // nsects
		D (0); // flags

		WZ (16, "__data");
		WZ (16, "__DATA");

		p_datava = buf->length;
		Q (-1);
		p_datasz = buf->length;
		Q (-1);
		p_datapa = buf->length;
		D (-1); //_start-0x1000);
		D (2); // align
		D (0); // reloff
		D (0); // nrelocs
		D (0); // flags
		D (0); // reserved1
		D (0); // reserved2
		D (0); // reserved3
	}

#define STATESIZE (21*sizeof (ut64))
	/* THREAD STATE */
	D (5); // LC_UNIXTHREAD
	D (184); // sizeof (cmd)
	
	D (4); // 1=i386, 4=x86_64
	D (42); // thread-state-count
	p_entry = buf->length + (16*sizeof (ut64));
	Z (STATESIZE);

	headerlen = buf->length - magiclen;

	codeva = buf->length + baddr;
	datava = buf->length + codelen + baddr;
	W (p_entry, &codeva, 8); // set PC

	/* fill header variables */
	W (p_cmdsize, &headerlen, 4);
	filesize = magiclen + headerlen + codelen + datalen;
	// TEXT SEGMENT //
	W (p_codefsz, &filesize, 8);
	W (p_codeva, &codeva, 8);
	{
		ut64 clen = codelen;
		W (p_codesz, &clen, 8);
	}
	p_tmp = codeva - baddr;
	W (p_codepa, &p_tmp, 8);

	B (code, codelen);

	if (data && datalen>0) {
		/* append data */
		W (p_datafsz, &filesize, 8);
		W (p_datava, &datava, 8);
		W (p_datasz, &datalen, 8);
		p_tmp = datava - baddr;
		W (p_datapa, &p_tmp, 8);
		B (data, datalen);
	}

	return buf;
}

static RBinAddr* binsym(RBinFile *arch, int sym) {
	ut64 addr;
	RBinAddr *ret = NULL;
	switch (sym) {
	case R_BIN_SYM_MAIN:
		addr = MACH0_(get_main) (arch->o->bin_obj);
		if (!addr || !(ret = R_NEW0 (RBinAddr)))
			return NULL;
		ret->paddr = ret->vaddr = addr;
		break;
	}
	return ret;
}

RBinPlugin r_bin_plugin_mach064 = {
	.name = "mach064",
	.desc = "mach064 bin plugin",
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
	.boffset = NULL,
	.binsym = binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = NULL,
	.write = NULL,
	.create = &create,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach064
};
#endif
