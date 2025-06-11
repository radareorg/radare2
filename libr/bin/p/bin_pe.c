/* radare - LGPL - Copyright 2009-2024 - nibble, pancake, alvarofe */

#include "bin_pe.inc.c"

extern struct r_bin_write_t r_bin_write_pe;

static bool check(RBinFile *bf, RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length <= 0x3d) {
		return false;
	}
	ut16 idx = r_buf_read_le16_at (b, 0x3c);
	if (idx + 26 < length) {
		ut8 buf[2];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "MZ", 2)) {
			r_buf_read_at (b, idx, buf, sizeof (buf));
		 	// PL signature for Phar Lap TNT DOS extender 32bit executables
			if (!memcmp (buf, "PL", 2)) {
				// TODO: Add one more indicator, to prevent false positives
				return true;
			}
			if (!memcmp (buf, "PE", 2)) {
				r_buf_read_at (b, idx + 0x18, buf, sizeof (buf));
				return !memcmp (buf, "\x0b\x01", 2);
			}
		}
	}
	return false;
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	ut32 hdrsize, p_start, p_opthdr, p_sections, p_lsrlc, n;
	ut32 baddr = 0x400000;
	RBuffer *buf = r_buf_new ();

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)(x),y)
#define H(x) r_buf_append_ut16(buf,x)
#define D(x) r_buf_append_ut32(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)(y),z)
#define WZ(x,y) p_tmp=r_buf_size (buf);Z(x);W(p_tmp,y,strlen(y))

	B ("MZ\x00\x00", 4); // MZ Header
	B ("PE\x00\x00", 4); // PE Signature
	H (0x14c); // Machine
	H (1); // Number of sections
	D (0); // Timestamp (Unused)
	D (0); // PointerToSymbolTable (Unused)
	D (0); // NumberOfSymbols (Unused)
	p_lsrlc = r_buf_size (buf);
	H (-1); // SizeOfOptionalHeader
	H (0x103); // Characteristics

	/* Optional Header */
	p_opthdr = r_buf_size (buf);
	H (0x10b); // Magic
	B ("\x08\x00", 2); // (Major/Minor)LinkerVersion (Unused)

	p_sections = r_buf_size (buf);
	n = p_sections - p_opthdr;
	W (p_lsrlc, &n, 2); // Fix SizeOfOptionalHeader

	/* Sections */
	p_start = 0x7c; //HACK: Headersize
	hdrsize = 0x7c;

	D (R_ROUND (codelen, 4)); // SizeOfCode (Unused)
	D (0); // SizeOfInitializedData (Unused)
	D (codelen); // codesize
	D (p_start);
	D (codelen);
	D (p_start);
	D (baddr); // ImageBase
	D (4); // SectionAlignment
	D (4); // FileAlignment
	H (4); // MajorOperatingSystemVersion (Unused)
	H (0); // MinorOperatingSystemVersion (Unused)
	H (0); // MajorImageVersion (Unused)
	H (0); // MinorImageVersion (Unused)
	H (4); // MajorSubsystemVersion
	H (0); // MinorSubsystemVersion (Unused)
	D (0); // Win32VersionValue (Unused)
	D ((R_ROUND (hdrsize, 4)) + (R_ROUND (codelen, 4))); // SizeOfImage
	D (R_ROUND (hdrsize, 4)); // SizeOfHeaders
	D (0); // CheckSum (Unused)
	H (2); // Subsystem (Win32 GUI)
	H (0x400); // DllCharacteristics (Unused)
	D (0x100000); // SizeOfStackReserve (Unused)
	D (0x1000); // SizeOfStackCommit
	D (0x100000); // SizeOfHeapReserve
	D (0x1000); // SizeOfHeapCommit (Unused)
	D (0); // LoaderFlags (Unused)
	D (0); // NumberOfRvaAndSizes (Unused)
	B (code, codelen);

	if (data && datalen > 0) {
		//ut32 data_section = buf->length;
		R_LOG_WARN ("DATA section not support for PE yet");
		B (data, datalen);
	}
	return buf;
}

static char *signature(RBinFile *bf, bool json) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinPEObj *pe = PE_(get)(bf);
	if (json) {
		PJ *pj = r_pkcs7_cms_json (pe->cms);
		if (pj) {
			return pj_drain (pj);
		}
		return strdup ("{}");
	}
	return r_pkcs7_cms_tostring (pe->cms);
}

static RList *fields(RBinFile *bf) {
	RList *ret  = r_list_new ();
	if (!ret) {
		return NULL;
	}

	#define ROWL(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, NULL, fmt, false));

	RBinPEObj *pe = PE_(get)(bf);
	ut64 addr = pe->rich_header_offset ? pe->rich_header_offset : 128;

	RListIter *it;
	Pe_image_rich_entry *rich;
	r_list_foreach (pe->rich_entries, it, rich) {
		r_list_append (ret, r_bin_field_new (addr, addr, 0, 0, "RICH_ENTRY_NAME", rich->productName, "s", false));
		ROWL ("RICH_ENTRY_ID", 2, rich->productId, "x"); addr += 2;
		ROWL ("RICH_ENTRY_VERSION", 2, rich->minVersion, "x"); addr += 2;
		ROWL ("RICH_ENTRY_TIMES", 4, rich->timesUsed, "x"); addr += 4;
	}

	ROWL ("Signature", 4, pe->nt_headers->Signature, "x"); addr += 4;
	ROWL ("Machine", 2, pe->nt_headers->file_header.Machine, "x"); addr += 2;
	ROWL ("NumberOfSections", 2, pe->nt_headers->file_header.NumberOfSections, "x"); addr += 2;
	ROWL ("TimeDateStamp", 4, pe->nt_headers->file_header.TimeDateStamp, "x"); addr += 4;
	ROWL ("PointerToSymbolTable", 4, pe->nt_headers->file_header.PointerToSymbolTable, "x"); addr += 4;
	ROWL ("NumberOfSymbols ", 4, pe->nt_headers->file_header.NumberOfSymbols, "x"); addr += 4;
	ROWL ("SizeOfOptionalHeader", 2, pe->nt_headers->file_header.SizeOfOptionalHeader, "x"); addr += 2;
	ROWL ("Characteristics", 2, pe->nt_headers->file_header.Characteristics, "x"); addr += 2;
	ROWL ("Magic", 2, pe->nt_headers->optional_header.Magic, "x"); addr += 2;
	ROWL ("MajorLinkerVersion", 1, pe->nt_headers->optional_header.MajorLinkerVersion, "x"); addr += 1;
	ROWL ("MinorLinkerVersion", 1, pe->nt_headers->optional_header.MinorLinkerVersion, "x"); addr += 1;
	ROWL ("SizeOfCode", 4, pe->nt_headers->optional_header.SizeOfCode, "x"); addr += 4;
	ROWL ("SizeOfInitializedData", 4, pe->nt_headers->optional_header.SizeOfInitializedData, "x"); addr += 4;
	ROWL ("SizeOfUninitializedData", 4, pe->nt_headers->optional_header.SizeOfUninitializedData, "x"); addr += 4;
	ROWL ("AddressOfEntryPoint", 4, pe->nt_headers->optional_header.AddressOfEntryPoint, "x"); addr += 4;
	ROWL ("BaseOfCode", 4, pe->nt_headers->optional_header.BaseOfCode, "x"); addr += 4;
	ROWL ("BaseOfData", 4, pe->nt_headers->optional_header.BaseOfData, "x"); addr += 4;
	ROWL ("ImageBase", 4, pe->nt_headers->optional_header.ImageBase, "x"); addr += 4;
	ROWL ("SectionAlignment", 4, pe->nt_headers->optional_header.SectionAlignment, "x"); addr += 4;
	ROWL ("FileAlignment", 4, pe->nt_headers->optional_header.FileAlignment, "x"); addr += 4;
	ROWL ("MajorOperatingSystemVersion", 2, pe->nt_headers->optional_header.MajorOperatingSystemVersion, "x"); addr += 2;
	ROWL ("MinorOperatingSystemVersion", 2, pe->nt_headers->optional_header.MinorOperatingSystemVersion, "x"); addr += 2;
	ROWL ("MajorImageVersion", 2, pe->nt_headers->optional_header.MajorImageVersion, "x"); addr += 2;
	ROWL ("MinorImageVersion", 2, pe->nt_headers->optional_header.MinorImageVersion, "x"); addr += 2;
	ROWL ("MajorSubsystemVersion", 2, pe->nt_headers->optional_header.MajorSubsystemVersion, "x"); addr += 2;
	ROWL ("MinorSubsystemVersion", 2, pe->nt_headers->optional_header.MinorSubsystemVersion, "x"); addr += 2;
	ROWL ("Win32VersionValue", 4, pe->nt_headers->optional_header.Win32VersionValue, "x"); addr += 4;
	ROWL ("SizeOfImage", 4, pe->nt_headers->optional_header.SizeOfImage, "x"); addr += 4;
	ROWL ("SizeOfHeaders", 4, pe->nt_headers->optional_header.SizeOfHeaders, "x"); addr += 4;
	ROWL ("CheckSum", 4, pe->nt_headers->optional_header.CheckSum, "x"); addr += 4;
	ROWL ("Subsystem",24, pe->nt_headers->optional_header.Subsystem, "x"); addr += 2;
	ROWL ("DllCharacteristics", 2, pe->nt_headers->optional_header.DllCharacteristics, "x"); addr += 2;
	ROWL ("SizeOfStackReserve", 4, pe->nt_headers->optional_header.SizeOfStackReserve, "x"); addr += 4;
	ROWL ("SizeOfStackCommit", 4, pe->nt_headers->optional_header.SizeOfStackCommit, "x"); addr += 4;
	ROWL ("SizeOfHeapReserve", 4, pe->nt_headers->optional_header.SizeOfHeapReserve, "x"); addr += 4;
	ROWL ("SizeOfHeapCommit", 4, pe->nt_headers->optional_header.SizeOfHeapCommit, "x"); addr += 4;
	ROWL ("LoaderFlags", 4, pe->nt_headers->optional_header.LoaderFlags, "x"); addr += 4;
	ROWL ("NumberOfRvaAndSizes", 4, pe->nt_headers->optional_header.NumberOfRvaAndSizes, "x"); addr += 4;

	int i;
	ut64 tmp = addr;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (pe->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			addr = tmp + i*8;
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_EXPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_EXPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_IMPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_IMPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				ROWL ("IMAGE_DIRECTORY_ENTRY_RESOURCE", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_RESOURCE", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				ROWL ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				ROWL ("IMAGE_DIRECTORY_ENTRY_SECURITY", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_SECURITY", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				ROWL ("IMAGE_DIRECTORY_ENTRY_BASERELOC", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_BASERELOC", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				ROWL ("IMAGE_DIRECTORY_ENTRY_DEBUG", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_DEBUG", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				ROWL ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				ROWL ("IMAGE_DIRECTORY_ENTRY_TLS", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_TLS", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				ROWL ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_IAT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_IAT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				ROWL ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4, \
				pe->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			}
		}
	}
	return ret;
}

static void header(RBinFile *bf) {
	RBinPEObj *pe = PE_(get)(bf);
	PrintfCallback cb_printf = bf->rbin->cb_printf;

	cb_printf ("PE file header:\n");
	cb_printf ("IMAGE_NT_HEADERS\n");
	cb_printf ("  Signature : 0x%x\n", pe->nt_headers->Signature);
	cb_printf ("IMAGE_FILE_HEADERS\n");
	cb_printf ("  Machine : 0x%x\n", pe->nt_headers->file_header.Machine);
	cb_printf ("  NumberOfSections : 0x%x\n", pe->nt_headers->file_header.NumberOfSections);
	cb_printf ("  TimeDateStamp : 0x%x\n", pe->nt_headers->file_header.TimeDateStamp);
	cb_printf ("  PointerToSymbolTable : 0x%x\n", pe->nt_headers->file_header.PointerToSymbolTable);
	cb_printf ("  NumberOfSymbols : 0x%x\n", pe->nt_headers->file_header.NumberOfSymbols);
	cb_printf ("  SizeOfOptionalHeader : 0x%x\n", pe->nt_headers->file_header.SizeOfOptionalHeader);
	cb_printf ("  Characteristics : 0x%x\n", pe->nt_headers->file_header.Characteristics);
	cb_printf ("IMAGE_OPTIONAL_HEADERS\n");
	cb_printf ("  Magic : 0x%x\n", pe->nt_headers->optional_header.Magic);
	cb_printf ("  MajorLinkerVersion : 0x%x\n", pe->nt_headers->optional_header.MajorLinkerVersion);
	cb_printf ("  MinorLinkerVersion : 0x%x\n", pe->nt_headers->optional_header.MinorLinkerVersion);
	cb_printf ("  SizeOfCode : 0x%x\n", pe->nt_headers->optional_header.SizeOfCode);
	cb_printf ("  SizeOfInitializedData : 0x%x\n", pe->nt_headers->optional_header.SizeOfInitializedData);
	cb_printf ("  SizeOfUninitializedData : 0x%x\n", pe->nt_headers->optional_header.SizeOfUninitializedData);
	cb_printf ("  AddressOfEntryPoint : 0x%x\n", pe->nt_headers->optional_header.AddressOfEntryPoint);
	cb_printf ("  BaseOfCode : 0x%x\n", pe->nt_headers->optional_header.BaseOfCode);
	cb_printf ("  BaseOfData : 0x%x\n", pe->nt_headers->optional_header.BaseOfData);
	cb_printf ("  ImageBase : 0x%x\n", pe->nt_headers->optional_header.ImageBase);
	cb_printf ("  SectionAlignment : 0x%x\n", pe->nt_headers->optional_header.SectionAlignment);
	cb_printf ("  FileAlignment : 0x%x\n", pe->nt_headers->optional_header.FileAlignment);
	cb_printf ("  MajorOperatingSystemVersion : 0x%x\n", pe->nt_headers->optional_header.MajorOperatingSystemVersion);
	cb_printf ("  MinorOperatingSystemVersion : 0x%x\n", pe->nt_headers->optional_header.MinorOperatingSystemVersion);
	cb_printf ("  MajorImageVersion : 0x%x\n", pe->nt_headers->optional_header.MajorImageVersion);
	cb_printf ("  MinorImageVersion : 0x%x\n", pe->nt_headers->optional_header.MinorImageVersion);
	cb_printf ("  MajorSubsystemVersion : 0x%x\n", pe->nt_headers->optional_header.MajorSubsystemVersion);
	cb_printf ("  MinorSubsystemVersion : 0x%x\n", pe->nt_headers->optional_header.MinorSubsystemVersion);
	cb_printf ("  Win32VersionValue : 0x%x\n", pe->nt_headers->optional_header.Win32VersionValue);
	cb_printf ("  SizeOfImage : 0x%x\n", pe->nt_headers->optional_header.SizeOfImage);
	cb_printf ("  SizeOfHeaders : 0x%x\n", pe->nt_headers->optional_header.SizeOfHeaders);
	cb_printf ("  CheckSum : 0x%x\n", pe->nt_headers->optional_header.CheckSum);
	cb_printf ("  Subsystem : 0x%x\n", pe->nt_headers->optional_header.Subsystem);
	cb_printf ("  DllCharacteristics : 0x%x\n", pe->nt_headers->optional_header.DllCharacteristics);
	cb_printf ("  SizeOfStackReserve : 0x%x\n", pe->nt_headers->optional_header.SizeOfStackReserve);
	cb_printf ("  SizeOfStackCommit : 0x%x\n", pe->nt_headers->optional_header.SizeOfStackCommit);
	cb_printf ("  SizeOfHeapReserve : 0x%x\n", pe->nt_headers->optional_header.SizeOfHeapReserve);
	cb_printf ("  SizeOfHeapCommit : 0x%x\n", pe->nt_headers->optional_header.SizeOfHeapCommit);
	cb_printf ("  LoaderFlags : 0x%x\n", pe->nt_headers->optional_header.LoaderFlags);
	cb_printf ("  NumberOfRvaAndSizes : 0x%x\n", pe->nt_headers->optional_header.NumberOfRvaAndSizes);
	RListIter *it;
	Pe_image_rich_entry *entry;
	cb_printf ("RICH_FIELDS\n");
	r_list_foreach (pe->rich_entries, it, entry) {
		cb_printf ("  Product: %d Name: %s Version: %d Times: %d\n", entry->productId, entry->productName, entry->minVersion, entry->timesUsed);
	}
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (pe->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_EXPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_RESOURCE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_EXCEPTION\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_SECURITY\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_BASERELOC\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_DEBUG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT\n");
				cb_printf ("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_TLS\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_IAT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				cb_printf ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\n");
				break;
			}
			cb_printf ("  VirtualAddress : 0x%x\n", pe->nt_headers->optional_header.DataDirectory[i].VirtualAddress);
			cb_printf ("  Size : 0x%x\n", pe->nt_headers->optional_header.DataDirectory[i].Size);
		}
	}
	if (pe->metadata_header) {
		PE_(image_metadata_header) *mh = pe->metadata_header;
		cb_printf ("Metadata Header:\n");
		cb_printf ("  Signature: 0x%08"PFMT64x"\n", mh->Signature);
		cb_printf ("  Version: %d.%d\n", mh->MajorVersion, mh->MinorVersion);
		cb_printf ("  VersionString: %s\n", mh->VersionString);
		cb_printf ("  Flags: 0x%x\n", mh->Flags);
		cb_printf ("  Streams: %d\n", mh->NumberOfStreams);
		if (pe->streams) {
			for (i = 0; i < mh->NumberOfStreams; i++) {
				PE_(image_metadata_stream) * stream = pe->streams[i];
				cb_printf ("  Stream %d: %s\n", i, stream->Name);
				cb_printf ("    offset: 0x%08"PFMT64x" size: 0x%x\n", (ut64)stream->Offset, stream->Size);
			}
		}
	}
	if (pe->clr_hdr) {
		PE_(image_clr_header) *clr = pe->clr_hdr;
		cb_printf ("Common Language Runtime Header (CLR):\n");
		cb_printf ("  Header Size: %d\n", clr->HeaderSize);
		cb_printf ("  CLR RuntimeVersion: %d.%d\n", clr->MajorRuntimeVersion, clr->MinorRuntimeVersion);
		cb_printf ("  MetadataDirectory: 0x%08"PFMT64x" (%d)\n", (ut64) clr->MetaDataDirectoryAddress, clr->MetaDataDirectorySize);
		cb_printf ("  Flags: 0x%x\n", clr->Flags);
		cb_printf ("  EntryPointToken: 0x%x\n", clr->EntryPointToken);
		cb_printf ("  ResourceDirectory: 0x%"PFMT64x" (%d)\n", (ut64)clr->ResourcesDirectoryAddress, clr->ResourcesDirectorySize);
		cb_printf ("  StrongNameSignature: 0x%"PFMT64x" (%d)\n", (ut64)clr->StrongNameSignatureAddress, clr->StrongNameSignatureSize);
		cb_printf ("  CodeManagerTable: 0x%"PFMT64x" (%d)\n", (ut64)clr->StrongNameSignatureAddress, clr->StrongNameSignatureSize);
		cb_printf ("  VTableFixups: 0x%"PFMT64x" (%d)\n", (ut64)clr->VTableFixupsAddress, clr->VTableFixupsSize);
		cb_printf ("  ExportAddressTableJumps: 0x%"PFMT64x" (%d)\n", (ut64)clr->ExportAddressTableJumpsAddress, clr->ExportAddressTableJumpsSize);
		cb_printf ("  ManagedNativeHeader: 0x%"PFMT64x" (%d)\n", (ut64)clr->ManagedNativeHeaderAddress, clr->ManagedNativeHeaderSize);
	}
}

RBinPlugin r_bin_plugin_pe = {
	.meta = {
		.name = "pe",
		.desc = "Portable Executable for 32bit",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.signature = &signature,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.header = &header,
	.fields = &fields,
	.libs = &libs,
	.relocs = relocs,
	.minstrlen = 4,
	.create = &create,
	.get_vaddr = &get_vaddr,
	.write = &r_bin_write_pe,
	.hashes = &compute_hashes
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe,
	.version = R2_VERSION
};
#endif
