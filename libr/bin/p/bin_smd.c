/* radare - LGPL3 - 2015-2021 - pancake */

#include <r_bin.h>

typedef struct gen_hdr {
	ut8 CopyRights[32];
	ut8 DomesticName[48];
	ut8 OverseasName[48];
	ut8 ProductCode[14];
	ut16 CheckSum;
	ut8 Peripherals[16];
	ut32 RomStart;
	ut32 RomEnd;
	ut32 RamStart;
	ut32 RamEnd;
	ut8 SramCode[12];
	ut8 ModemCode[12];
	ut8 Reserved[40];
	ut8 CountryCode[16];
} SMD_Header;

typedef struct gen_vect {
	union {
		struct {
			ut32 SSP;
			ut32 Reset;
			ut32 BusErr;
			ut32 AdrErr;
			ut32 InvOpCode;
			ut32 DivBy0;
			ut32 Check;
			ut32 TrapV;
			ut32 GPF;
			ut32 Trace;
			ut32 Reserv0;
			ut32 Reserv1;
			ut32 Reserv2;
			ut32 Reserv3;
			ut32 Reserv4;
			ut32 BadInt;
			ut32 Reserv10;
			ut32 Reserv11;
			ut32 Reserv12;
			ut32 Reserv13;
			ut32 Reserv14;
			ut32 Reserv15;
			ut32 Reserv16;
			ut32 Reserv17;
			ut32 BadIRQ;
			ut32 IRQ1;
			ut32 EXT;
			ut32 IRQ3;
			ut32 HBLANK;
			ut32 IRQ5;
			ut32 VBLANK;
			ut32 IRQ7;
			ut32 Trap0;
			ut32 Trap1;
			ut32 Trap2;
			ut32 Trap3;
			ut32 Trap4;
			ut32 Trap5;
			ut32 Trap6;
			ut32 Trap7;
			ut32 Trap8;
			ut32 Trap9;
			ut32 Trap10;
			ut32 Trap11;
			ut32 Trap12;
			ut32 Trap13;
			ut32 Trap14;
			ut32 Trap15;
			ut32 Reserv30;
			ut32 Reserv31;
			ut32 Reserv32;
			ut32 Reserv33;
			ut32 Reserv34;
			ut32 Reserv35;
			ut32 Reserv36;
			ut32 Reserv37;
			ut32 Reserv38;
			ut32 Reserv39;
			ut32 Reserv3A;
			ut32 Reserv3B;
			ut32 Reserv3C;
			ut32 Reserv3D;
			ut32 Reserv3E;
			ut32 Reserv3F;
		};
		ut32 vectors[64];
	};
} SMD_Vectors;

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 0x190) {
		ut8 buf[4];
		r_buf_read_at (b, 0x100, buf, sizeof (buf));
		return !memcmp (buf, "SEGA", 4);
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Sega Megadrive");
	ut8 tmp[32];
	r_buf_read_at (bf->buf, 0x100, tmp, sizeof (tmp));
	ret->bclass = r_str_ndup ((char *)tmp, 32);
	ret->os = strdup ("smd");
	ret->arch = strdup ("m68k");
	ret->bits = 32;
	ret->has_va = 1;
	ret->big_endian = 1;
	return ret;
}

static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	ptr->name = r_bin_name_new (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static void showstr(const char *str, const ut8 *s, size_t len) {
	char *msg = r_str_ndup ((const char *) s, len);
	R_LOG_INFO ("%s: %s", str, msg);
	free (msg);
}

static const char *smd_vector_names[64] = {
	"SSP", "Reset", "BusErr", "AdrErr", "InvOpCode", "DivBy0", "Check", "TrapV",
	"GPF", "Trace", "Reserv0", "Reserv1", "Reserv2", "Reserv3", "Reserv4", "BadInt",
	"Reserv10", "Reserv11", "Reserv12", "Reserv13", "Reserv14", "Reserv15", "Reserv16", "Reserv17",
	"BadIRQ", "IRQ1", "EXT", "IRQ3", "HBLANK", "IRQ5", "VBLANK", "IRQ7",
	"Trap0", "Trap1", "Trap2", "Trap3", "Trap4", "Trap5", "Trap6", "Trap7",
	"Trap8", "Trap9", "Trap10", "Trap11", "Trap12", "Trap13", "Trap14", "Trap15",
	"Reserv30", "Reserv31", "Reserv32", "Reserv33", "Reserv34", "Reserv35", "Reserv36", "Reserv37",
	"Reserv38", "Reserv39", "Reserv3A", "Reserv3B", "Reserv3C", "Reserv3D", "Reserv3E", "Reserv3F",
};

static RList *symbols(RBinFile *bf) {
	RList *ret = r_list_newf ((RListFree)r_bin_symbol_free);
	if (!ret) {
		return NULL;
	}
	SMD_Header hdr = {{0}};
	int left = r_buf_read_at (bf->buf, 0x100, (ut8*)&hdr, sizeof (hdr));
	if (left < sizeof (SMD_Header)) {
		return NULL;
	}
	addsym (ret, "rom_start", r_read_be32 (&hdr.RomStart));
	addsym (ret, "rom_end", r_read_be32 (&hdr.RomEnd));
	addsym (ret, "ram_start", r_read_be32 (&hdr.RamStart));
	addsym (ret, "ram_end", r_read_be32 (&hdr.RamEnd));
	showstr ("Copyright", hdr.CopyRights, sizeof (hdr.CopyRights));
	showstr ("DomesticName", hdr.DomesticName, sizeof (hdr.DomesticName));
	showstr ("OverseasName", hdr.OverseasName, sizeof (hdr.OverseasName));
	showstr ("ProductCode", hdr.ProductCode, sizeof (hdr.ProductCode));
	R_LOG_INFO ("Checksum: 0x%04x", (ut32) hdr.CheckSum);
	showstr ("Peripherals", hdr.Peripherals, sizeof (hdr.Peripherals));
	showstr ("SramCode", hdr.SramCode, sizeof (hdr.SramCode));
	showstr ("ModemCode", hdr.ModemCode, sizeof (hdr.ModemCode));
	showstr ("CountryCode", hdr.CountryCode, sizeof (hdr.CountryCode));
	ut32 vtable[64];
	r_buf_read_at (bf->buf, 0, (ut8*)&vtable, sizeof (ut32) * 64);
	int i;
	for (i = 0; i < 64; i++) {
		if (vtable[i]) {
			addsym (ret, smd_vector_names[i], r_read_be32 (&vtable[i]));
		}
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}

	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("vtable");
	ptr->paddr = ptr->vaddr = 0;
	ptr->size = ptr->vsize = 0x100;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);

	ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("header");
	ptr->paddr = ptr->vaddr = 0x100;
	ptr->size = ptr->vsize = sizeof (SMD_Header);
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);

	SMD_Header hdr = {{0}};
	r_buf_read_at (bf->buf, 0x100, (ut8*)&hdr, sizeof (hdr));

	ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("text");
	ptr->paddr = 0x100 + sizeof (SMD_Header);
	ptr->vaddr = ptr->paddr + r_read_be32 (&hdr.RomStart);
	ptr->size = ptr->vsize = r_buf_size (bf->buf) - ptr->paddr;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (bf->size < sizeof (SMD_Vectors)) {
		R_LOG_WARN ("binfile too small");
		ptr->paddr = ptr->vaddr = 0x100 + sizeof (SMD_Header);
	} else {
		SMD_Vectors vectors;
		r_buf_read_at (bf->buf, 0, (ut8*)&vectors, sizeof (vectors));
		ptr->paddr = ptr->vaddr = r_read_be32 (&vectors.Reset);
	}
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_smd = {
	.meta = {
		.name = "smd",
		.author = "pancake",
		.desc = "SEGA Genesis/Megadrive",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.minstrlen = 10,
	.strfilter = 'U'
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_smd,
	.version = R2_VERSION
};
#endif
