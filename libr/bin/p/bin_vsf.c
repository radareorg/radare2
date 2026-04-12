/* radare - LGPL3 - 2015-2019 - riq */

/* VICE Snapshot File loader: https://vice-emu.sourceforge.net/ */

#include <r_bin.h>
#include "vsf/vsf_specs.h"

static const char VICE_MAGIC[] = "VICE Snapshot File\032";
static const char VICE_VERSION[] = "VICE Version\032";
#define VICE_MAGIC_LEN sizeof (VICE_MAGIC) - 1
static const char VICE_MAINCPU[] = "MAINCPU";
static const char VICE_C64MEM[] = "C64MEM";
static const char VICE_C64MEMHACKS[] = "C64MEMHACKS";
static const char VICE_C64ROM[] = "C64ROM";
static const char VICE_C128MEM[] = "C128MEM";
static const char VICE_C128ROM[] = "C128ROM";

static const struct {
	const char* name;
	const char* desc;
	const int offset_mem;
	const int ram_size;
} _machines[] = {
	{ "C64", "Commodore 64", r_offsetof(struct vsf_c64mem, ram), 64 * 1024},
	{ "C128", "Commodore 128", r_offsetof(struct vsf_c128mem, ram), 128 * 1024},
};
static const int MACHINES_MAX = sizeof (_machines) / sizeof (_machines[0]);

static Sdb* get_sdb(RBinFile *bf) {
	struct r_bin_vsf_obj *bin = (struct r_bin_vsf_obj *)R_UNWRAP3 (bf, bo, bin_obj);
	return bin ? bin->kv : NULL;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[VICE_MAGIC_LEN];
	if (r_buf_read_at (b, 0, magic, VICE_MAGIC_LEN) == VICE_MAGIC_LEN) {
		return !memcmp (magic, VICE_MAGIC, VICE_MAGIC_LEN);
	}
	return false;
}

// XXX b vs bf->buf
static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	if (!check (bf, bf->buf)) {
		return false;
	}
	struct r_bin_vsf_obj *res = R_NEW0 (struct r_bin_vsf_obj);
	ut64 offset = r_offsetof (struct vsf_hdr, machine);
	if (offset > bf->size) {
		free (res);
		return false;
	}
	char machine[20];
	if (r_buf_read_at (bf->buf, offset, (ut8 *)machine, sizeof (machine)) < 0) {
		free (res);
		return false;
	}
	int i;
	for (i = 0; i < MACHINES_MAX; i++) {
		if (offset + strlen (_machines[i].name) > bf->size) {
			free (res);
			return false;
		}
		if (r_str_startswith (machine, _machines[i].name)) {
			res->machine_idx = i;
			break;
		}
	}
	if (i >= MACHINES_MAX) {
		R_LOG_WARN ("Unsupported machine type");
		free (res);
		return false;
	}
	// read all VSF modules
	offset = sizeof (struct vsf_hdr);
	ut8 vice_version[sizeof (VICE_VERSION)];
	if (r_buf_read_at (bf->buf, offset, vice_version, sizeof (VICE_VERSION)) == sizeof (VICE_VERSION)) {
		if (!memcmp (vice_version, VICE_VERSION, sizeof (VICE_VERSION) - 1)) {
			offset += sizeof (VICE_VERSION) + 7;
		}
	}
	ut64 sz = r_buf_size (bf->buf);
	while (offset < sz) {
		struct vsf_module module;
		int rd = r_buf_fread_at (bf->buf, offset, (ut8 *)&module, "16ccci", 1);
		if (rd != sizeof (module)) {
			R_LOG_ERROR ("Truncated Header");
			free (res);
			return false;
		}
		if (module.length == 0) {
			R_LOG_ERROR ("Malformed VSF module with length 0");
			break;
		}
#define CMP_MODULE(x) memcmp (module.module_name, x, sizeof (x) - 1)
		if (!module.major) {
			if ((!CMP_MODULE (VICE_C64MEM) && CMP_MODULE (VICE_C64MEMHACKS)) || !CMP_MODULE (VICE_C128MEM)) {
				res->mem = offset + rd;
			} else if (!CMP_MODULE (VICE_C64ROM) || !CMP_MODULE (VICE_C128ROM)) {
				res->rom = offset + rd;
			}
		} else if (module.major == 1 && !CMP_MODULE (VICE_MAINCPU)) {
			res->maincpu = R_NEW0 (struct vsf_maincpu);
			r_buf_read_at (bf->buf, offset + rd, (ut8 *)res->maincpu, sizeof (*res->maincpu));
		}
#undef CMP_MODULE
		offset += module.length;
	}
	res->kv = sdb_new0 ();
	sdb_ns_set (bf->sdb, "info", res->kv);
	bf->bo->bin_obj = res;
	return true;
}

static RList *mem(RBinFile *bf) {
	struct r_bin_vsf_obj *vsf_obj = (struct r_bin_vsf_obj *) bf->bo->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	RList *ret = r_list_newf (free);
	RBinMem *m = R_NEW0 (RBinMem);
	m->name = strdup ("RAM");
	m->addr = 0;
	m->size = _machines[vsf_obj->machine_idx].ram_size;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	return ret;
}

static void add_section(RList *list, const char *name, ut64 paddr, int size, ut64 vaddr, int perm) {
	RBinSection *s = R_NEW0 (RBinSection);
	s->name = strdup (name);
	s->paddr = paddr;
	s->size = size;
	s->vaddr = vaddr;
	s->vsize = size;
	s->perm = perm;
	s->add = true;
	r_list_append (list, s);
}

static RList *sections(RBinFile *bf) {
	struct r_bin_vsf_obj *vsf_obj = (struct r_bin_vsf_obj *) bf->bo->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	RList *ret = r_list_new ();
	const int m_idx = vsf_obj->machine_idx;
	// ROM sections first, then RAM, to simulate bank switching
	if (vsf_obj->rom) {
		if (!m_idx) {
			add_section (ret, "BASIC", vsf_obj->rom + r_offsetof (struct vsf_c64rom, basic), 1024 * 8, 0xa000, R_PERM_RX);
			add_section (ret, "KERNAL", vsf_obj->rom + r_offsetof (struct vsf_c64rom, kernal), 1024 * 8, 0xe000, R_PERM_RX);
		} else {
			ut64 basic_off = vsf_obj->rom + r_offsetof (struct vsf_c128rom, basic);
			add_section (ret, "BASIC", basic_off, 1024 * 28, 0x4000, R_PERM_RX);
			add_section (ret, "MONITOR", basic_off + 1024 * 28, 1024 * 4, 0xb000, R_PERM_RX);
			add_section (ret, "EDITOR", vsf_obj->rom + r_offsetof (struct vsf_c128rom, editor), 1024 * 4, 0xc000, R_PERM_RX);
			add_section (ret, "KERNAL", vsf_obj->rom + r_offsetof (struct vsf_c128rom, kernal), 1024 * 8, 0xe000, R_PERM_RX);
		}
	}
	if (vsf_obj->mem) {
		int offset = _machines[m_idx].offset_mem;
		if (!m_idx) {
			add_section (ret, "RAM", vsf_obj->mem + offset, _machines[m_idx].ram_size, 0, R_PERM_RWX);
		} else {
			int bank_size = 1024 * 64;
			add_section (ret, "RAM BANK 0", vsf_obj->mem + offset, bank_size, 0, R_PERM_RWX);
			add_section (ret, "RAM BANK 1", vsf_obj->mem + offset + bank_size, bank_size, 0, R_PERM_RWX);
		}
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	struct r_bin_vsf_obj *vsf_obj = (struct r_bin_vsf_obj *) bf->bo->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	const int m_idx = vsf_obj->machine_idx;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("Snapshot");
	ret->machine = strdup (_machines[m_idx].desc);
	ret->os = strdup (_machines[m_idx].name);
	ret->arch = strdup ("6502");
	ret->bits = 8;
	ret->has_va = true;

	struct vsf_maincpu *cpu = vsf_obj->maincpu;
	if (!cpu) {
		return ret;
	}
	Sdb *kv = vsf_obj->kv;
	sdb_num_set (kv, "vsf.reg_a", cpu->ac, 0);
	sdb_num_set (kv, "vsf.reg_x", cpu->xr, 0);
	sdb_num_set (kv, "vsf.reg_y", cpu->yr, 0);
	sdb_num_set (kv, "vsf.reg_sp", cpu->sp, 0);
	sdb_num_set (kv, "vsf.reg_pc", cpu->pc, 0);
	sdb_num_set (kv, "vsf.reg_st", cpu->st, 0);
	sdb_num_set (kv, "vsf.clock", cpu->clk, 0);
	return ret;
}

static RList* symbols(RBinFile *bf) {

	static const struct {
		const ut16 address;
		const char* symbol_name;
	} _symbols[] = {
//		{0xfffa, "NMI_VECTOR_LSB" },
//		{0xfffb, "NMI_VECTOR_MSB" },
//		{0xfffe, "IRQ_VECTOR_LSB" },
//		{0xffff, "IRQ_VECTOR_MSB" },

		// Defines taken from c64.inc from cc65
		// I/O: VIC
		{0xd000, "VIC_SPR0_X" },
		{0xd001, "VIC_SPR0_Y" },
		{0xd002, "VIC_SPR1_X" },
		{0xd003, "VIC_SPR1_Y" },
		{0xd004, "VIC_SPR2_X" },
		{0xd005, "VIC_SPR2_Y" },
		{0xd006, "VIC_SPR3_X" },
		{0xd007, "VIC_SPR3_Y" },
		{0xd008, "VIC_SPR4_X" },
		{0xd009, "VIC_SPR4_Y" },
		{0xd00a, "VIC_SPR5_X" },
		{0xd00b, "VIC_SPR5_Y" },
		{0xd00c, "VIC_SPR6_X" },
		{0xd00d, "VIC_SPR6_Y" },
		{0xd00e, "VIC_SPR7_X" },
		{0xd00f, "VIC_SPR7_Y" },
		{0xd010, "VIC_SPR_HI_X" },
		{0xd015, "VIC_SPR_ENA" },
		{0xd017, "VIC_SPR_EXP_Y" },
		{0xd01d, "VIC_SPR_EXP_X" },
		{0xd01c, "VIC_SPR_MCOLOR" },
		{0xd01b, "VIC_SPR_BG_PRIO" },

		{0xd025, "VIC_SPR_MCOLOR0" },
		{0xd026, "VIC_SPR_MCOLOR1" },

		{0xd027, "VIC_SPR0_COLOR" },
		{0xd028, "VIC_SPR1_COLOR" },
		{0xd029, "VIC_SPR2_COLOR" },
		{0xd02A, "VIC_SPR3_COLOR" },
		{0xd02B, "VIC_SPR4_COLOR" },
		{0xd02C, "VIC_SPR5_COLOR" },
		{0xd02D, "VIC_SPR6_COLOR" },
		{0xd02E, "VIC_SPR7_COLOR" },

		{0xd011, "VIC_CTRL1" },
		{0xd016, "VIC_CTRL2" },

		{0xd012, "VIC_HLINE" },

		{0xd013, "VIC_LPEN_X" },
		{0xd014, "VIC_LPEN_Y" },

		{0xd018, "VIC_VIDEO_ADR" },

		{0xd019, "VIC_IRR" },
		{0xd01a, "VIC_IMR" },

		{0xd020, "VIC_BORDERCOLOR" },
		{0xd021, "VIC_BG_COLOR0" },
		{0xd022, "VIC_BG_COLOR1" },
		{0xd023, "VIC_BG_COLOR2" },
		{0xd024, "VIC_BG_COLOR3" },

		// 128 stuff
		{0xd02F, "VIC_KBD_128" },
		{0xd030, "VIC_CLK_128" },

		// I/O: SID
		{0xD400, "SID_S1Lo" },
		{0xD401, "SID_S1Hi" },
		{0xD402, "SID_PB1Lo" },
		{0xD403, "SID_PB1Hi" },
		{0xD404, "SID_Ctl1" },
		{0xD405, "SID_AD1" },
		{0xD406, "SID_SUR1" },

		{0xD407, "SID_S2Lo" },
		{0xD408, "SID_S2Hi" },
		{0xD409, "SID_PB2Lo" },
		{0xD40A, "SID_PB2Hi" },
		{0xD40B, "SID_Ctl2" },
		{0xD40C, "SID_AD2" },
		{0xD40D, "SID_SUR2" },

		{0xD40E, "SID_S3Lo" },
		{0xD40F, "SID_S3Hi" },
		{0xD410, "SID_PB3Lo" },
		{0xD411, "SID_PB3Hi" },
		{0xD412, "SID_Ctl3" },
		{0xD413, "SID_AD3" },
		{0xD414, "SID_SUR3" },

		{0xD415, "SID_FltLo" },
		{0xD416, "SID_FltHi" },
		{0xD417, "SID_FltCtl" },
		{0xD418, "SID_Amp" },
		{0xD419, "SID_ADConv1" },
		{0xD41A, "SID_ADConv2" },
		{0xD41B, "SID_Noise" },
		{0xD41C, "SID_Read3" },

		// I/O: VDC (128 only)
		{0xd600, "VDC_INDEX" },
		{0xd601, "VDC_DATA" },

		// I/O: CIAs
		{0xDC00, "CIA1_PRA" },
		{0xDC01, "CIA1_PRB" },
		{0xDC02, "CIA1_DDRA" },
		{0xDC03, "CIA1_DDRB" },
		{0xDC08, "CIA1_TOD10" },
		{0xDC09, "CIA1_TODSEC" },
		{0xDC0A, "CIA1_TODMIN" },
		{0xDC0B, "CIA1_TODHR" },
		{0xDC0D, "CIA1_ICR" },
		{0xDC0E, "CIA1_CRA" },
		{0xDC0F, "CIA1_CRB" },

		{0xDD00, "CIA2_PRA" },
		{0xDD01, "CIA2_PRB" },
		{0xDD02, "CIA2_DDRA" },
		{0xDD03, "CIA2_DDRB" },
		{0xDD08, "CIA2_TOD10" },
		{0xDD09, "CIA2_TODSEC" },
		{0xDD0A, "CIA2_TODMIN" },
		{0xDD0B, "CIA2_TODHR" },
		{0xDD0D, "CIA2_ICR" },
		{0xDD0E, "CIA2_CRA" },
		{0xDD0F, "CIA2_CRB" },
	};
	static const int SYMBOLS_MAX = sizeof (_symbols) / sizeof (_symbols[0]);
	struct r_bin_vsf_obj *vsf_obj = (struct r_bin_vsf_obj *) bf->bo->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	int offset = _machines[vsf_obj->machine_idx].offset_mem;
	RList *ret = r_list_newf (free);
	int i;
	for (i = 0; i < SYMBOLS_MAX; i++) {
		RBinSymbol *ptr = R_NEW0 (RBinSymbol);
		ptr->name = r_bin_name_new_from (r_str_ndup (_symbols[i].symbol_name, R_BIN_SIZEOF_STRINGS));
		ptr->vaddr = _symbols[i].address;
		ptr->size = 2;
		ptr->paddr = vsf_obj->mem + offset + _symbols[i].address;
		ptr->ordinal = i;
		r_list_append (ret, ptr);
	}
	return ret;
}

static void destroy(RBinFile *bf) {
	struct r_bin_vsf_obj *obj = (struct r_bin_vsf_obj *)bf->bo->bin_obj;
	free (obj->maincpu);
	free (obj);
}

static RList *entries(RBinFile *bf) {
	struct r_bin_vsf_obj *vsf_obj = (struct r_bin_vsf_obj *) bf->bo->bin_obj;
	if (!vsf_obj) {
		return NULL;
	}
	RList *ret = r_list_new ();
	int offset = _machines[vsf_obj->machine_idx].offset_mem;
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = vsf_obj->mem + offset;
	ptr->vaddr = vsf_obj->maincpu ? vsf_obj->maincpu->pc : 0;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_vsf = {
	.meta = {
		.name = "vsf",
		.author = "riq",
		.desc = "VICE Snapshot",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.check = &check,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.destroy = &destroy,
	.mem = &mem,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_vsf,
	.version = R2_VERSION
};
#endif
