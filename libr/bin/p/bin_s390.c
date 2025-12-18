/* radare - LGPL3 - 2021-2025 - Jose_Ant_Romero */

#include <r_bin.h>
#include <r_magic.h>

#define S390_BADDR 0xa5000
// #define S390_BADDR 0

static RList *sections(RBinFile *bf);
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

// CSECT Identificacion Record (IDR)
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
	ut8 CCW[8];
} S390_Header_ControlRLD;

typedef struct {
	ut64 text0;
	ut64 entry0;
	RStrBuf *sb;
	RList *symbols;
} s390user;

static ut64 baddr(RBinFile *bf) {
	return S390_BADDR;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 buf[8] = {0};
	if (r_buf_read_at (b, 0, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	if (!memcmp (buf, "\x20\x00\x00\x00\x01\x00", 6)) {
		S390_Header_CESD *hdr = (S390_Header_CESD*)buf;
		if (r_buf_size (b) > sizeof (S390_Header_CESD) + r_read_be16 (&hdr->Count)) {
			return true;
		}
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	bool res = check (bf, b);
	if (res) {
		s390user *su = R_NEW0 (s390user);
		su->sb = r_strbuf_new ("");
		su->symbols = r_list_newf (r_bin_symbol_free);
		bf->bo->bin_obj = (void*)su;
	}
	return res;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->machine = strdup ("s390");
	ret->bclass = strdup ("XX");
	ret->type = strdup ("load module");
	ret->os = strdup ("s390");
	ret->arch = strdup ("s390");
	ret->charset = strdup ("ebcdic37");
	ret->bits = 32;
	ret->has_va = 1;
	ret->big_endian = 1;
	return ret;
}

static void add_symbol(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	ptr->name = r_bin_name_new (name);
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

/* static void showstr(const char *str, const ut8 *s, size_t len) {
	char *msg = r_str_ndup ((const char *) s, len);
	eprintf ("%s: %s\n", str, msg);
	free (msg);
} */

static RList *symbols(RBinFile *bf) {
	s390user *su = bf->bo->bin_obj;
	RList *ret = NULL;
	RListIter *iter;
	RBinSymbol *sym;
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	r_list_free (sections (bf));
	r_list_foreach (su->symbols, iter, sym) {
		char *name = r_str_trim_dup (r_bin_name_tostring (sym->name));
		add_symbol (ret, name, sym->vaddr + su->text0 + S390_BADDR);
	}
	return ret;
}

static void add_section(RList *ret, char *name, ut64 addr, ut64 len) {
	RBinSection *ptr = R_NEW0 (RBinSection);
	ptr->name = name;
	ptr->paddr = addr;
	ptr->vaddr = addr + S390_BADDR;
	ptr->size = len;
	ptr->vsize = len;
	ptr->perm = R_PERM_RX;
	ptr->add = true;
	r_list_append (ret, ptr);
}

static RList *sections(RBinFile *bf) {
	s390user *su = bf->bo->bin_obj;
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}


	r_strbuf_free (su->sb);
	su->sb = r_strbuf_new ("");

	S390_Header_CESD hdr20 = {0};
	S390_Header_CESD_DATA hdr20d = {{0}};
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
	su->entry0 = 0;
//	ut8 gidr[255] = {0};

	ut8 gbuf[1] = {0};
	left = r_buf_read_at (bf->buf, 0, gbuf, sizeof (gbuf));
	if (left < sizeof (gbuf)) {
		return NULL;
	}
	eprintf ("Use the `iH` command to display the headers\n");

	while (!endw) {
		switch (gbuf[0]) {
		// CESD Record
		case 0x20:
			left = r_buf_read_at (bf->buf, x, (ut8*)&hdr20, sizeof (S390_Header_CESD));
			if (left < sizeof (S390_Header_CESD)) {
				return NULL;
			}
			lon = r_read_be16 (&hdr20.Count);
			rec++;
			r_strbuf_appendf (su->sb, "Record %02d Type 0x%02x - Count: 0x%04x - (%03d) 0x%04x - %02d\n",
					rec, gbuf[0], x, lon, lon, (int)(lon / sizeof (S390_Header_CESD_DATA)));
			x += sizeof (S390_Header_CESD);
			// process each symbols with their datas
			sym = 0;
			ut16 y;
			for (y = 0; y < lon / sizeof (S390_Header_CESD_DATA) ; y++) {
				ut8 cad[9];
				ut32 a, b;

				left = r_buf_read_at (bf->buf, x, (ut8*)&hdr20d, sizeof (S390_Header_CESD_DATA));
				if (left < sizeof (S390_Header_CESD_DATA)) {
					return NULL;
				}
				r_magic_from_ebcdic (hdr20d.Symbol, sizeof (hdr20d.Symbol), cad);
				cad[8] = '\0';
				a = (hdr20d.Address[0] * 65536) + (hdr20d.Address[1] * 256) + (hdr20d.Address[2]);
				b = (hdr20d.ID_or_Length[0] * 65536) + (hdr20d.ID_or_Length[1] * 256) + (hdr20d.ID_or_Length[2]);
				sym++;
				r_strbuf_appendf (su->sb, "       %02d   %s   0x%02x   0x%04x   (%5u) 0x%04x\n",
						sym, (char *)cad, hdr20d.Type, a, b, b);
				add_symbol (su->symbols, (char *)cad, a);
				x += sizeof (S390_Header_CESD_DATA);
			}
			left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
			if (left < sizeof (gbuf)) {
				return NULL;
			}
			break;
		// CSECT IDR
		case 0x80:
			left = r_buf_read_at (bf->buf, x, (ut8*)&hdr80, sizeof (S390_Header_CSECT_IDR));
			if (left < sizeof (S390_Header_CSECT_IDR)) {
				return NULL;
			}
			lon = hdr80.Count - 2;	// Count include Count & SubType fields
			rec++;
			r_strbuf_appendf (su->sb, "Record %02d Type 0x%02x SubType 0x%02x - Count: 0x%04x (%03d) - 0x%02x\n",
					rec, gbuf[0], hdr80.SubType, x, lon, lon);
			x += sizeof (S390_Header_CSECT_IDR);
			add_section (ret, r_str_newf ("record%d", rec), x, lon);
			eprintf ("SECTION AT 0x%08x OF LENGTH %d\n", x, lon);

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
			left = r_buf_read_at (bf->buf, x, (ut8*)&hdrCR, sizeof (S390_Header_ControlRecord));
			if (left < sizeof (S390_Header_ControlRecord)) {
				return NULL;
			}
			lon = r_read_be16 (&hdrCR.Count);
			rec++;
			r_strbuf_appendf (su->sb, "Record %02d Type 0x%02x - Count: 0x%04x - 0x%04x - %04d\n",
					rec, gbuf[0], x, lon, (int)(lon / sizeof (S390_Header_ControlRecord_Data)));
			x += sizeof (S390_Header_ControlRecord);

			lonCR = 0;
			{
			ut16 y;
			for (y = 0; y < lon / sizeof (S390_Header_ControlRecord_Data) ; y++) {
				left = r_buf_read_at (bf->buf, x, (ut8*)&hdrCRd, sizeof (S390_Header_ControlRecord_Data));
				if (left < sizeof (S390_Header_ControlRecord_Data)) {
					return NULL;
				}
				r_strbuf_appendf (su->sb, "    CESD 0x%02x - 0x%04x\n",
						r_read_be16 (&hdrCRd.EntryNumber), r_read_be16 (&hdrCRd.Length));
				lonCR += r_read_be16 (&hdrCRd.Length);
				x += sizeof (S390_Header_ControlRecord_Data);
			}
			}
			// To Do something with IDR data
			r_strbuf_appendf (su->sb, "Long: 0x%04x\n", lonCR);
			r_strbuf_appendf (su->sb, "TEXT SECTION AT 0x%08x of %d\n", x, lonCR);
			eprintf ("TEXT 0x%08x %d\n", x, lonCR);
			add_section (ret, r_str_newf ("record%d", rec), x, lonCR);
			if (!su->entry0) {
				su->text0 = x; // XXX this 0xc is hardcoded
				su->entry0 = x + 0xc; // XXX this 0xc is hardcoded
				// add_section (ret, r_str_newf ("whole"), x + 4, 32); // r_buf_size (bf->buf)  - x);
			}
			x += lonCR;
			left = r_buf_read_at (bf->buf, x, gbuf, sizeof (gbuf));
			if (left < sizeof (gbuf)) {
				return NULL;
			}
			r_strbuf_appendf (su->sb, "Record %02d Type 0x%02x\n", rec, gbuf[0]);
			break;
		default:
			r_strbuf_appendf (su->sb, "Unknown record 0x%02x\n", gbuf[0]);
			endw = true;
			break;
		}
	}
	return ret;
}

static RList *entries(RBinFile *bf) {
	s390user *su = bf->bo->bin_obj;
	RList *ret = r_list_new ();
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	r_list_free (sections (bf));
	ptr->vaddr = su->entry0 + S390_BADDR;
	ptr->paddr = su->entry0;
	r_list_append (ret, ptr);
	return ret;
}

static void headers(RBinFile *bf) {
	s390user *su = bf->bo->bin_obj;
	char *s = r_strbuf_get (su->sb);
	bf->rbin->cb_printf ("%s\n", s);
}

static void destroy(RBinFile *bf) {
	if (bf && bf->bo && bf->bo->bin_obj) {
		s390user *su = bf->bo->bin_obj;
		r_strbuf_free (su->sb);
		free (su);
	}
}

RBinPlugin r_bin_plugin_s390 = {
	.meta = {
		.name = "s390",
		.desc = "IBM s390 Load Module",
		.license = "LGPL-3.0-only",
		.author = "Jose Antonio Romero",
	},
	.weak_guess = true,
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.header = &headers,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.destroy = &destroy,
	.minstrlen = 3
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_s390,
	.version = R2_VERSION
};
#endif
