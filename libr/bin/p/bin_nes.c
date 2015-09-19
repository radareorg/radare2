/* radare - LGPL - 2015 - maijin */

#include <r_bin.h>
#include "nes/nes_specs.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (!buf || length < 4) return false;
	return (!memcmp (buf, INES_MAGIC, 4));
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	ines_hdr ihdr;
	memset (&ihdr, 0, INES_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&ihdr, INES_HDR_SIZE);
	if (reat != INES_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Nintendo NES");
	ret->os = strdup ("nes");
	ret->arch = strdup ("6502");
	ret->bits = 8;
	ret->has_va = 1;
	return ret;
}

static RList* create_nes_cpu_memory_map(ines_hdr ihdr) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, "ROM");
	ptr->paddr = INES_HDR_SIZE;
	ptr->size = ihdr.prg_page_count_16k * PRG_PAGE_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	ptr->vsize = ROM_SIZE;
	ptr->srwx = R_BIN_SCN_MAP;
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *arch) {
	ines_hdr ihdr;
	memset (&ihdr, 0, INES_HDR_SIZE);
	int reat = r_buf_read_at (arch->buf, 0, (ut8*)&ihdr, INES_HDR_SIZE);
	if (reat != INES_HDR_SIZE) {
		eprintf ("Truncated Header\n");
		return NULL;
	}
	RList *ret = create_nes_cpu_memory_map(ihdr);
	return ret;
}

static RList* entries(RBinFile *arch) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = INES_HDR_SIZE;
	ptr->vaddr = ROM_START_ADDRESS;
	r_list_append (ret, ptr);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_nes = {
	.name = "nes",
	.desc = "NES",
	.license = "BSD",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = sections,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_nes,
	.version = R2_VERSION
};
#endif
