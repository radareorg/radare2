/* radare - LGPL3 - 2021 - Jose_Ant_Romero */

#include <r_bin.h>

typedef struct msx_hdr_rom {
	ut8 ROMSignature[2]; // 'AB'
	ut16 InitAddress;
	ut16 RuntimeAddress;
	ut16 DeviceAddress;
	ut16 PointAddress;
	ut8 Reserved[6];
} MSX_Header_ROM;

typedef struct msx_hdr_bin {
	ut8 BINSignature; // 0xFE
	ut16 StartAddress;
	ut16 EndAddress;
	ut16 InitAddress;
} MSX_Header_BIN;

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 buf[2] = {0};
	if (!bf) {
		// not eligible for carving
		return false;
	}
	ut64 b_size = r_buf_size (b);
	// check size
	if (b_size > 0x100000) {
		// 1MB is the limit of the sky
		return false;
	}
	// check extension
	const char *b_file = bf->file;
	if (b_file == NULL) {
		return false;
	}
	if (!r_str_endswith (b_file, ".rom") && !r_str_endswith (b_file, ".mx1")) {
		return false;
	}
	// check magic
	r_buf_read_at (b, 0, buf, sizeof (buf));
	if (!memcmp (buf, "AB", 2)) {
		if (b_size > sizeof (MSX_Header_ROM)) {
			return true;
		}
	} else if (buf[0] == 0xFE) {
		if (b_size > sizeof (MSX_Header_BIN)) {
			return true;
		}
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->machine = strdup ("MSX");
	ut8 tmp[16] = {0};
	r_buf_read_at (bf->buf, 0, tmp, sizeof (tmp));
	if (tmp[0] == 'A') {
		ret->bclass = r_str_newf ("%c%c", tmp[0], tmp[1]);
		ret->type = strdup ("rom");
	} else if (tmp[0] == 0xFE) {
		ret->bclass = r_str_newf ("0x%02x", tmp[0]);
		ret->type = strdup ("bin");
	}
	ret->os = strdup ("msx");
	ret->arch = strdup ("z80");
	ret->bits = 8;
	ret->has_va = 1;
	ret->big_endian = 0;
	return ret;
}

static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = r_bin_name_new (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	ut8 gbuf[16] = {0};
	int left = r_buf_read_at (bf->buf, 0, gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}
	if (!memcmp (gbuf, "AB", 2)) {
		MSX_Header_ROM *hdr = (MSX_Header_ROM*)gbuf;
		addsym (ret, "ROMSignature", r_offsetof (MSX_Header_ROM, ROMSignature));
		addsym (ret, "InitAddress", r_read_le16 (&hdr->InitAddress));
		addsym (ret, "RuntimeAddress", r_read_le16 (&hdr->RuntimeAddress));
		addsym (ret, "DeviceAddress", r_read_le16 (&hdr->DeviceAddress));
		addsym (ret, "PointAddress", r_read_le16 (&hdr->PointAddress));

		eprintf ("InitAddress: 0x%04x\n", (ut16) hdr->InitAddress);
		eprintf ("RuntimeAddress: 0x%04x\n", (ut16) hdr->RuntimeAddress);
		eprintf ("DeviceAddress: 0x%04x\n", (ut16) hdr->DeviceAddress);
		eprintf ("PointAddress: 0x%04x\n", (ut16) hdr->PointAddress);
	} else if (gbuf[0] == 0xFE) {
		MSX_Header_BIN *hdr = (MSX_Header_BIN*)gbuf;
		addsym (ret, "BINSignature", r_read_be8 (&hdr->BINSignature));
		addsym (ret, "StartAddress", r_read_be16 (&hdr->StartAddress));
		addsym (ret, "EndAddress", r_read_be16 (&hdr->EndAddress));
		addsym (ret, "InitAddress", r_read_be16 (&hdr->InitAddress));

		eprintf ("StartAddress: 0x%04x\n", (ut16) hdr->StartAddress);
		eprintf ("EndAddress: 0x%04x\n", (ut16) hdr->EndAddress);
		eprintf ("InitAddress: 0x%04x\n", (ut16) hdr->InitAddress);
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	ut8 gbuf[32];
	int left = r_buf_read_at (bf->buf, 0, (ut8*)&gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}

	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("header");
	ptr->paddr = ptr->vaddr = 0;
	ut64 baddr = 0;
	ut64 hdrsize = 0;
	if (!memcmp (gbuf, "AB", 2)) {
		MSX_Header_ROM *hdr = (MSX_Header_ROM*)gbuf;
		baddr = r_read_le16 (&hdr->InitAddress) & 0xff00;
		hdrsize = ptr->vsize = sizeof (hdr);
	} else if (gbuf[0] == 0xFE) {
		MSX_Header_BIN *hdr = (MSX_Header_BIN*)gbuf;
		baddr = r_read_le16 (&hdr->StartAddress) & 0xff00;
		hdrsize = ptr->vsize = sizeof (hdr);
	}

	ptr->size = hdrsize;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("text");
	ptr->paddr = 0;
	ptr->vaddr = baddr;
	ptr->size = ptr->vsize = r_buf_size (bf->buf) - hdrsize;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_new ();
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (!ret || !ptr) {
		free (ret);
		free (ptr);
		return NULL;
	}
	ut8 gbuf[32];
	int left = r_buf_read_at (bf->buf, 0, (ut8*)&gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		free (ret);
		free (ptr);
		return NULL;
	}
	if (!memcmp (gbuf, "AB", 2)) {
		MSX_Header_ROM *hdr = (MSX_Header_ROM*)gbuf;
		ut16 init = r_read_le16 (&hdr->InitAddress);
		ptr->vaddr = init;
		ptr->paddr = 0;
		r_list_append (ret, ptr);
	} else if (gbuf[0] == 0xFE) {
		MSX_Header_BIN *hdr = (MSX_Header_BIN*)gbuf;
		ut16 init = r_read_le16 (&hdr->InitAddress);
		ptr->vaddr = init;
		ptr->paddr = 0;
		r_list_append (ret, ptr);
	}
	return ret;
}

RBinPlugin r_bin_plugin_msx = {
	.meta = {
		.name = "msx",
		.desc = "MSX ROM images",
		.license = "LGPL-3.0-only",
		.author = "Jose Antonio Romero",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.minstrlen = 3
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_msx,
	.version = R2_VERSION
};
#endif
