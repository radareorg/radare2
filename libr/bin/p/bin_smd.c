/* radare - LGPL3 - 2015-2016 - pancake */

#include <r_bin.h>

typedef struct gen_hdr {
	ut8 CopyRights[32];
	ut8 DomesticName[48];
	ut8 OverseasName[48];
	ut8 ProductCode[14];
	ut16 CheckSum;
	ut8 Peripherials[16];
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
	if (length > 0x190) {
		if (!memcmp (buf+0x100, "SEGA", 4))
			return true;
	}
	return false;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Sega Megadrive");
	ret->bclass = r_str_ndup ((char*)arch->buf->buf + 0x100, 32);
	ret->os = strdup ("smd");
	ret->arch = strdup ("m68k");
	ret->bits = 16;
	ret->has_va = 1;
	return ret;
}

static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) return;
	ptr->name = strdup (name? name: "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static void showstr(const char *str, const ut8 *s, int len) {
	char *msg = r_str_ndup ((const char*)s, len);
	eprintf ("%s: %s\n", str, msg);
	free (msg);
}

static RList* symbols(RBinFile *arch) {
	ut32 *vtable = (ut32*)arch->buf->buf;
	RList *ret = NULL;
	const char *name;
	SMD_Header *hdr;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	// TODO: store all this stuff in SDB
	hdr = (SMD_Header*)(arch->buf->buf + 0x100);
	addsym (ret, "rom_start", hdr->RomStart);
	addsym (ret, "rom_end", hdr->RomEnd);
	addsym (ret, "ram_start", hdr->RamStart);
	addsym (ret, "ram_end", hdr->RamEnd);
	showstr ("Copyright", hdr->CopyRights, 32);
	showstr ("DomesticName", hdr->DomesticName, 48);
	showstr ("OverseasName", hdr->OverseasName, 48);
	showstr ("ProductCode", hdr->ProductCode, 14);
	eprintf ("Checksum: 0x%04x\n", (ut32)hdr->CheckSum);
	showstr ("Peripherials", hdr->Peripherials, 16);
	showstr ("SramCode", hdr->CountryCode, 12);
	showstr ("ModemCode", hdr->CountryCode, 12);
	showstr ("CountryCode", hdr->CountryCode, 16);
	/* parse vtable */
	for (i = 0; i<64; i++) {
		switch (i) {
		case 0: name = "SSP"; break;
		case 1: name = "Reset"; break;
		case 2: name = "BusErr"; break;
		case 3: name = "InvOpCode"; break;
		case 4: name = "DivBy0"; break;
		case 5: name = "Check"; break;
		case 6: name = "TrapV"; break;
		case 7: name = "GPF"; break;
		case 8: name = "Trace"; break;
		case 9: name = "Reserv0"; break;
		case 10: name = "Reserv1"; break;
		case 11: name = "Reserv2"; break;
		case 12: name = "Reserv3"; break;
		case 13: name = "Reserv4"; break;
		case 14: name = "BadInt"; break;
		case 15: name = "Reserv10"; break;
		case 16: name = "Reserv11"; break;
		case 17: name = "Reserv12"; break;
		case 18: name = "Reserv13"; break;
		case 19: name = "Reserv14"; break;
		case 20: name = "Reserv15"; break;
		case 21: name = "Reserv16"; break;
		case 22: name = "Reserv17"; break;
		case 23: name = "BadIRQ"; break;
		case 24: name = "IRQ1"; break;
		case 25: name = "EXT"; break;
		case 26: name = "IRQ3"; break;
		case 27: name = "HBLANK"; break;
		case 28: name = "IRQ5"; break;
		case 29: name = "VBLANK"; break;
		case 30: name = "IRQ7"; break;
		case 31: name = "Trap0"; break;
		case 32: name = "Trap1"; break;
		case 33: name = "Trap2"; break;
		case 34: name = "Trap3"; break;
		case 35: name = "Trap4"; break;
		case 36: name = "Trap5"; break;
		case 37: name = "Trap6"; break;
		case 38: name = "Trap7"; break;
		case 39: name = "Trap8"; break;
		case 40: name = "Trap9"; break;
		case 41: name = "Trap10"; break;
		case 42: name = "Trap11"; break;
		case 43: name = "Trap12"; break;
		case 44: name = "Trap13"; break;
		case 45: name = "Trap14"; break;
		case 46: name = "Trap15"; break;
		case 47: name = "Reserv30"; break;
		case 48: name = "Reserv31"; break;
		case 49: name = "Reserv32"; break;
		case 50: name = "Reserv33"; break;
		case 51: name = "Reserv34"; break;
		case 52: name = "Reserv35"; break;
		case 53: name = "Reserv36"; break;
		case 54: name = "Reserv37"; break;
		case 55: name = "Reserv38"; break;
		case 56: name = "Reserv39"; break;
		case 57: name = "Reserv3A"; break;
		case 58: name = "Reserv3B"; break;
		case 59: name = "Reserv3C"; break;
		case 60: name = "Reserv3D"; break;
		case 61: name = "Reserv3E"; break;
		case 62: name = "Reserv3F"; break;
		default: name = NULL;
		}
		if (name && vtable[i]) {
			ut32 addr = 0;
			// XXX don't know if always LE
			addr = r_read_le32 (&vtable[i]);
			addsym (ret, name, addr);
		}
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	RBinSection *ptr;
	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, "vtable");
	ptr->paddr = ptr->vaddr = 0;
	ptr->size = ptr->vsize = 0x100;
	ptr->srwx = R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, "header");
	ptr->paddr = ptr->vaddr = 0x100;
	ptr->size = ptr->vsize = sizeof (SMD_Header);
	ptr->srwx = R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strcpy (ptr->name, "text");
	ptr->paddr = ptr->vaddr = 0x100 + sizeof (SMD_Header);
	{
		SMD_Header * hdr = (SMD_Header*)(arch->buf->buf + 0x100);
		ut64 baddr = hdr->RamStart;
		ptr->vaddr += baddr;
	}
	ptr->size = ptr->vsize = arch->buf->length - ptr->paddr;
	ptr->srwx = R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList* entries(RBinFile *arch) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = ptr->vaddr = 0x100 + sizeof (SMD_Header); //vtable[1];
	r_list_append (ret, ptr);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_smd = {
	.name = "smd",
	.desc = "SEGA Genesis/Megadrive",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.minstrlen = 10,
	.strfilter = 'U'
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_smd,
	.version = R2_VERSION
};
#endif
