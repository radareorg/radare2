/* radare - LGPL3 - 2021 - Jose_Ant_Romero */

#include <r_bin.h>
#include <magic/ascmagic.c>

// CESD Record
typedef struct s390_hdr_cesd {
	ut8 Identification;	// 0x20
	ut8 Flag;
	ut16 Reserved;
	ut16 ESDID;
	ut16 Count;
} S390_Header_CESD;

// CESD Data
typedef struct s390_hdr_cesd_data {
	ut8 Symbol[8];
	ut8 Type;
	ut8 Address[3];
	ut8 Zeros;
	ut8 ID_or_Length[3];
} S390_Header_CESD_DATA;

// CSET Identificacion Record (IDR)
typedef struct s390_hdr_csect_idr {
	ut8 Identification;	// 0x80
	ut8 Count;
	ut8 SubType;
} S390_Header_CSECT_IDR;

// Control Record
typedef struct s390_hdr_contrec {
	ut8 Identificacion; // 0x01, 0x05 (EOS) & 0x0d (EOM)
	ut8 Zeros1[3];
	ut16 Count;
	ut16 Zeros2;
	ut8	CCW[8];
} S390_Header_ControlRecord;

// Control Data (for Control Record)
typedef struct s390_hdr_contrec_data {
	ut16 EntryNumber;
	ut16 Length;
} S390_Header_ControlRecord_Data;

// Relocation Directory Record (RLD)
typedef struct s390_hdr_rld {
	ut8 Identificacion; // 0x02, 0x06 (EOS) & 0x0e (EOM)
	ut8 Zeros[3];
	ut16 Count1;
	ut16 Count2;
	ut64 Reserved;
} S390_Header_RLD;

// RLD Data
typedef struct s390_hdr_rld_data {
	ut16 RelPointer;
	ut16 PosPointer;
} S390_Header_RLD_Data;

// Control & Relocation Directory Record (RLD)
typedef struct s390_hdr_contrld {
	ut8 Identificacion; // 0x03, 0x07 (EOS) & 0x0f (EOM)
	ut8 Zeros[3];
	ut16 Count1;
	ut16 Count2;
	ut8	CCW[8];
} S390_Header_ControlRLD;

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check_buffer(RBinFile *bf, RBuffer *b) {
	ut8 buf[8] = {0};
	r_buf_read_at (b, 0, buf, sizeof (buf));
	if (buf[0] == 0x20) {
		S390_Header_CESD *hdr = (S390_Header_CESD*)buf; 
		if (r_buf_size (b) > sizeof (S390_Header_CESD) + r_read_be16(&hdr->Count)) {
			return true;
		}
	}
	return false; 
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb){
	return check_buffer (bf, b);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->machine = strdup ("s390");
	ret->bclass = strdup("XX");
	ret->type = strdup ("load module");
	ret->os = strdup ("s390");
	ret->arch = strdup ("s390");
	ret->bits = 32;
	ret->has_va = 0;
	ret->big_endian = 1;
	return ret;
}

/* static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
} */

/* static void showstr(const char *str, const ut8 *s, size_t len) {
	char *msg = r_str_ndup ((const char *) s, len);
	eprintf ("%s: %s\n", str, msg);
	free (msg);
} */

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

/*	ut8 gbuf[16] = {0};
	int left = r_buf_read_at (bf->buf, 0, gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}
	if(!memcmp (gbuf, "AB", 2)) {
		S390_Header_ROM *hdr = (S390_Header_ROM*)gbuf;
		addsym (ret, "ROMSignature", r_offsetof (S390_Header_ROM, ROMSignature));
		addsym (ret, "InitAddress", r_read_le16 (&hdr->InitAddress));
		addsym (ret, "RuntimeAddress", r_read_le16 (&hdr->RuntimeAddress));
		addsym (ret, "DeviceAddress", r_read_le16 (&hdr->DeviceAddress));
		addsym (ret, "PointAddress", r_read_le16 (&hdr->PointAddress));

		eprintf ("InitAddress: 0x%04x\n", (ut16) hdr->InitAddress);
		eprintf ("RuntimeAddress: 0x%04x\n", (ut16) hdr->RuntimeAddress);
		eprintf ("DeviceAddress: 0x%04x\n", (ut16) hdr->DeviceAddress);
		eprintf ("PointAddress: 0x%04x\n", (ut16) hdr->PointAddress);
	} else if (gbuf[0] == 0xFE) {
		S390_Header_BIN *hdr = (S390_Header_BIN*)gbuf;
		addsym (ret, "BINSignature", r_read_be8 (&hdr->BINSignature));
		addsym (ret, "StartAddress", r_read_be16 (&hdr->StartAddress));
		addsym (ret, "EndAddress", r_read_be16 (&hdr->EndAddress));
		addsym (ret, "InitAddress", r_read_be16 (&hdr->InitAddress));

		eprintf ("StartAddress: 0x%04x\n", (ut16) hdr->StartAddress);
		eprintf ("EndAddress: 0x%04x\n", (ut16) hdr->EndAddress);
		eprintf ("InitAddress: 0x%04x\n", (ut16) hdr->InitAddress);
	}
*/
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}

	S390_Header_CESD hdr20 = {0};
	S390_Header_CESD_DATA hdr20d = {0};
	S390_Header_CSECT_IDR hdr80 = {0};
	S390_Header_ControlRecord hdrCR = {0};
	S390_Header_ControlRecord_Data hdrCRd = {0};

	ut16 lon;
	ut16 lonCR;
	int left;
	ut16 x = 0;
	bool endw = false;
	int rec = 0;
	int sym = 0;
//	ut8 gidr[255] = {0};

	ut8 gbuf[1] = {0};
	left = r_buf_read_at (bf->buf, 0, gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}

	while (!endw) {
		switch (gbuf[0]) {
			// CESD Record
			case 0x20:
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdr20, sizeof (S390_Header_CESD));
				if (left < sizeof (S390_Header_CESD)) {
					return NULL;
				}

				lon = r_read_be16(&hdr20.Count);
				rec++;
				eprintf("Record %02d Type 0x%02x - Count: 0x%04x - (%03d) 0x%04x - %02ld\n", 
								rec, gbuf[0], x, lon, lon, lon / sizeof(S390_Header_CESD_DATA));
				x += sizeof(S390_Header_CESD);

				// process each symbols with their datas
				sym = 0;
				for (ut16 y = 0 ; y < lon / sizeof(S390_Header_CESD_DATA) ; y++) {
					left = r_buf_read_at (bf->buf, x, (ut8*)&hdr20d, sizeof (S390_Header_CESD_DATA));
					if (left < sizeof (S390_Header_CESD_DATA)) {
						return NULL;
					}

					ut8 cad[8];
					from_ebcdic(hdr20d.Symbol, sizeof(hdr20d.Symbol), cad);
					ut32 a;
					ut32 b;
					a = (hdr20d.Address[0] * 65536) + (hdr20d.Address[1] * 256) + (hdr20d.Address[2]);
					b = (hdr20d.ID_or_Length[0] * 65536) + (hdr20d.ID_or_Length[1] * 256) + (hdr20d.ID_or_Length[2]);
					sym++;
					eprintf ("       %02d   %s   0x%02x   0x%04x   (%5u) 0x%04x\n", 
								sym, r_str_ndup ((char *) cad, 8), hdr20d.Type, a, b, b); 

					x += sizeof(S390_Header_CESD_DATA);
				}

				left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
				if (left < sizeof (gbuf)) {
					return NULL;
				}
				break;
			
			// CSECT IDR
			case 0x80:
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdr80, sizeof(S390_Header_CSECT_IDR));
				if (left < sizeof (S390_Header_CSECT_IDR)) {
					return NULL;
				}
				lon = hdr80.Count - 2;	// Count include Count & SubType fields
				rec++;
				eprintf("Record %02d Type 0x%02x SubType 0x%02x - Count: 0x%04x (%03d) - 0x%02x\n", 
								rec, gbuf[0], hdr80.SubType, x, lon, lon);
				x += sizeof(S390_Header_CSECT_IDR);

				// To Do something with IDR data
				x += lon;

//				Last IDR data has as SubType 1--- ----
//				if (hdr80.SubType & 0x080) {
//					eprintf("End of CSET_IDR\n");
//					endw = true;
//				}

				left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
				if (left < sizeof (gbuf)) {
					return NULL;
				}
				break;
			
			// Control Record             0x0001
			case 0x01:
			// RLD                        0x0010
			case 0x02:
			// Control Record & RLD       0x0011
			case 0x03:
			// Control Record (EOS)       0x0101
			case 0x05:
			// RLD (EOS)                  0x0110
			case 0x06:
			// Control Record & RLD (EOS) 0x0111
			case 0x07:
			// Control Record (EOM)       0x1101
			case 0x0d:
			// RLD (EOM)                  0x1110
			case 0x0e:
			// Control Record & RLD (EOS) 0x1111
			case 0x0f:
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdrCR, sizeof(S390_Header_ControlRecord));
				if (left < sizeof (S390_Header_ControlRecord)) {
					return NULL;
				}
				lon = r_read_be16(&hdrCR.Count);
				rec++;
				eprintf("Record %02d Type 0x%02x - Count: 0x%04x - 0x%04x - %04ld\n", 
								rec, gbuf[0], x, lon, lon / sizeof(S390_Header_ControlRecord_Data));
				x += sizeof(S390_Header_ControlRecord);

				lonCR = 0;
				for (ut16 y = 0 ; y < lon / sizeof(S390_Header_ControlRecord_Data) ; y++) {
					left = r_buf_read_at (bf->buf, x, (ut8*)&hdrCRd, sizeof (S390_Header_ControlRecord_Data));
					if (left < sizeof (S390_Header_ControlRecord_Data)) {
						return NULL;
					}

					eprintf ("    CESD 0x%02x - 0x%04x\n", 
								r_read_be16(&hdrCRd.EntryNumber), r_read_be16(&hdrCRd.Length)); 
					lonCR += r_read_be16(&hdrCRd.Length);
					x += sizeof(S390_Header_ControlRecord_Data);
				}

				// To Do something with IDR data
				eprintf ("Long: 0x%04x\n", lonCR);
				x += lonCR;

				left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
				if (left < sizeof (gbuf)) {
					return NULL;
				}
				eprintf ("Record %02d Type 0x%02x\n", rec, gbuf[0]);
				break;
		}
	}

/*	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = strdup ("header");
	ptr->paddr = ptr->vaddr = 0;
	ut64 baddr = 0;
	ut64 hdrsize = 0;
	if (!memcmp (gbuf, "AB", 2)) {
		S390_Header_ROM *hdr = (S390_Header_ROM*)gbuf;
		baddr = r_read_le16 (&hdr->InitAddress) & 0xff00;
		hdrsize = ptr->vsize = sizeof (hdr);
	} else if (gbuf[0] == 0xFE) {
		S390_Header_BIN *hdr = (S390_Header_BIN*)gbuf;
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
*/
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
/*	ut8 gbuf[32];
	int left = r_buf_read_at (bf->buf, 0, (ut8*)&gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		free (ret);
		free (ptr);
		return NULL;
	}
	if (!memcmp (gbuf, "AB", 2)) {
		S390_Header_ROM *hdr = (S390_Header_ROM*)gbuf;
		ut16 init = r_read_le16 (&hdr->InitAddress);
		ptr->vaddr = init;
		ptr->paddr = 0;
		r_list_append (ret, ptr);
	} else if (gbuf[0] == 0xFE) {
		S390_Header_BIN *hdr = (S390_Header_BIN*)gbuf;
		ut16 init = r_read_le16 (&hdr->InitAddress);
		ptr->vaddr = init;
		ptr->paddr = 0;
		r_list_append (ret, ptr);
	}
*/
	return ret;
}

RBinPlugin r_bin_plugin_s390 = {
	.name = "s390",
	.desc = "s390 Load Module parser",
	.license = "LGPL3",
	.author = "Jose Antonio Romero",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
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
	.data = &r_bin_plugin_s390,
	.version = R2_VERSION
};
#endif
