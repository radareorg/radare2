/* radare - LGPL - Copyright 2009-2025 - nibble, pancake */

#define R_BIN_PE64 1
#include "bin_pe.inc.c"

static bool check(RBinFile *bf, RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length <= 0x3d) {
		return false;
	}
	ut16 idx = r_buf_read_le16_at (b, 0x3c);
	if (idx + 26 < length) {
		/* Here PE signature for usual PE files
		 * and PL signature for Phar Lap TNT DOS extender 32bit executables
		 */
		ut8 buf[2];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "MZ", 2)) {
			r_buf_read_at (b, idx, buf, sizeof (buf));
			// TODO: Add one more indicator, to prevent false positives
			// if (!memcmp (buf, "PL", 2)) { return true; }
			if (!memcmp (buf, "PE", 2)) {
				r_buf_read_at (b, idx + 0x18, buf, sizeof (buf));
				return !memcmp (buf, "\x0b\x02", 2);
			}
		}
	}
	return false;
}

static RList *fields(RBinFile *bf) {
	RList *ret  = r_list_new ();

	#define ROWL(nam,siz,val,fmt) \
		r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, NULL, fmt, false));

	struct PE_(r_bin_pe_obj_t) * bin = bf->bo->bin_obj;
	ut64 addr = bin->rich_header_offset ? bin->rich_header_offset : 128;

	RListIter *it;
	Pe_image_rich_entry *rich;
	r_list_foreach (bin->rich_entries, it, rich) {
		r_list_append (ret, r_bin_field_new (addr, addr, 0, 0, "RICH_ENTRY_NAME", rich->productName, "s", false));
		ROWL ("RICH_ENTRY_ID", 2, rich->productId, "x"); addr += 2;
		ROWL ("RICH_ENTRY_VERSION", 2, rich->minVersion, "x"); addr += 2;
		ROWL ("RICH_ENTRY_TIMES", 4, rich->timesUsed, "x"); addr += 4;
	}

	ROWL ("Signature", 4, bin->nt_headers->Signature, "x"); addr += 4;
	ROWL ("Machine", 2, bin->nt_headers->file_header.Machine, "x"); addr += 2;
	ROWL ("NumberOfSections", 2, bin->nt_headers->file_header.NumberOfSections, "x"); addr += 2;
	ROWL ("TimeDateStamp", 4, bin->nt_headers->file_header.TimeDateStamp, "x"); addr += 4;
	ROWL ("PointerToSymbolTable", 4, bin->nt_headers->file_header.PointerToSymbolTable, "x"); addr += 4;
	ROWL ("NumberOfSymbols ", 4, bin->nt_headers->file_header.NumberOfSymbols, "x"); addr += 4;
	ROWL ("SizeOfOptionalHeader", 2, bin->nt_headers->file_header.SizeOfOptionalHeader, "x"); addr += 2;
	ROWL ("Characteristics", 2, bin->nt_headers->file_header.Characteristics, "x"); addr += 2;
	ROWL ("Magic", 2, bin->nt_headers->optional_header.Magic, "x"); addr += 2;
	ROWL ("MajorLinkerVersion", 1, bin->nt_headers->optional_header.MajorLinkerVersion, "x"); addr += 1;
	ROWL ("MinorLinkerVersion", 1, bin->nt_headers->optional_header.MinorLinkerVersion, "x"); addr += 1;
	ROWL ("SizeOfCode", 4, bin->nt_headers->optional_header.SizeOfCode, "x"); addr += 4;
	ROWL ("SizeOfInitializedData", 4, bin->nt_headers->optional_header.SizeOfInitializedData, "x"); addr += 4;
	ROWL ("SizeOfUninitializedData", 4, bin->nt_headers->optional_header.SizeOfUninitializedData, "x"); addr += 4;
	ROWL ("AddressOfEntryPoint", 4, bin->nt_headers->optional_header.AddressOfEntryPoint, "x"); addr += 4;
	ROWL ("BaseOfCode", 4, bin->nt_headers->optional_header.BaseOfCode, "x"); addr += 4;
	ROWL ("ImageBase", 4, bin->nt_headers->optional_header.ImageBase, "x"); addr += 4;
	ROWL ("SectionAlignment", 4, bin->nt_headers->optional_header.SectionAlignment, "x"); addr += 4;
	ROWL ("FileAlignment", 4, bin->nt_headers->optional_header.FileAlignment, "x"); addr += 4;
	ROWL ("MajorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MajorOperatingSystemVersion, "x"); addr += 2;
	ROWL ("MinorOperatingSystemVersion", 2, bin->nt_headers->optional_header.MinorOperatingSystemVersion, "x"); addr += 2;
	ROWL ("MajorImageVersion", 2, bin->nt_headers->optional_header.MajorImageVersion, "x"); addr += 2;
	ROWL ("MinorImageVersion", 2, bin->nt_headers->optional_header.MinorImageVersion, "x"); addr += 2;
	ROWL ("MajorSubsystemVersion", 2, bin->nt_headers->optional_header.MajorSubsystemVersion, "x"); addr += 2;
	ROWL ("MinorSubsystemVersion", 2, bin->nt_headers->optional_header.MinorSubsystemVersion, "x"); addr += 2;
	ROWL ("Win32VersionValue", 4, bin->nt_headers->optional_header.Win32VersionValue, "x"); addr += 4;
	ROWL ("SizeOfImage", 4, bin->nt_headers->optional_header.SizeOfImage, "x"); addr += 4;
	ROWL ("SizeOfHeaders", 4, bin->nt_headers->optional_header.SizeOfHeaders, "x"); addr += 4;
	ROWL ("CheckSum", 4, bin->nt_headers->optional_header.CheckSum, "x"); addr += 4;
	ROWL ("Subsystem",24, bin->nt_headers->optional_header.Subsystem, "x"); addr += 2;
	ROWL ("DllCharacteristics", 2, bin->nt_headers->optional_header.DllCharacteristics, "x"); addr += 2;
	ROWL ("SizeOfStackReserve", 4, bin->nt_headers->optional_header.SizeOfStackReserve, "x"); addr += 4;
	ROWL ("SizeOfStackCommit", 4, bin->nt_headers->optional_header.SizeOfStackCommit, "x"); addr += 4;
	ROWL ("SizeOfHeapReserve", 4, bin->nt_headers->optional_header.SizeOfHeapReserve, "x"); addr += 4;
	ROWL ("SizeOfHeapCommit", 4, bin->nt_headers->optional_header.SizeOfHeapCommit, "x"); addr += 4;
	ROWL ("LoaderFlags", 4, bin->nt_headers->optional_header.LoaderFlags, "x"); addr += 4;
	ROWL ("NumberOfRvaAndSizes", 4, bin->nt_headers->optional_header.NumberOfRvaAndSizes, "x"); addr += 4;

	int i;
	ut64 tmp = addr;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			addr = tmp + i*8;
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_EXPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_EXPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				ROWL ("IMAGE_DIRECTORY_ENTRY_RESOURCE", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_RESOURCE", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				ROWL ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_EXCEPTION", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				ROWL ("IMAGE_DIRECTORY_ENTRY_SECURITY", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_SECURITY", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				ROWL ("IMAGE_DIRECTORY_ENTRY_BASERELOC", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_BASERELOC", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				ROWL ("IMAGE_DIRECTORY_ENTRY_DEBUG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_DEBUG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				ROWL ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				ROWL ("IMAGE_DIRECTORY_ENTRY_TLS", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_TLS", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				ROWL ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_IAT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_IAT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				ROWL ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				ROWL ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress, "x");
				addr += 4;
				ROWL ("SIZE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 4, \
				bin->nt_headers->optional_header.DataDirectory[i].Size, "x");
				break;
			}
		}
	}

	return ret;
}

static char *header(RBinFile *bf, int mode) {
	struct PE_(r_bin_pe_obj_t) * bin = bf->bo->bin_obj;
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	p ("PE file header:\n");
	p ("IMAGE_NT_HEADERS\n");
	p ("  Signature : 0x%x\n", bin->nt_headers->Signature);
	p ("IMAGE_FILE_HEADERS\n");
	p ("  Machine : 0x%x\n", bin->nt_headers->file_header.Machine);
	p ("  NumberOfSections : 0x%x\n", bin->nt_headers->file_header.NumberOfSections);
	p ("  TimeDateStamp : 0x%x\n", bin->nt_headers->file_header.TimeDateStamp);
	p ("  PointerToSymbolTable : 0x%x\n", bin->nt_headers->file_header.PointerToSymbolTable);
	p ("  NumberOfSymbols : 0x%x\n", bin->nt_headers->file_header.NumberOfSymbols);
	p ("  SizeOfOptionalHeader : 0x%x\n", bin->nt_headers->file_header.SizeOfOptionalHeader);
	p ("  Characteristics : 0x%x\n", bin->nt_headers->file_header.Characteristics);
	p ("IMAGE_OPTIONAL_HEADERS\n");
	p ("  Magic : 0x%x\n", bin->nt_headers->optional_header.Magic);
	p ("  MajorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MajorLinkerVersion);
	p ("  MinorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MinorLinkerVersion);
	p ("  SizeOfCode : 0x%x\n", bin->nt_headers->optional_header.SizeOfCode);
	p ("  SizeOfInitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfInitializedData);
	p ("  SizeOfUninitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfUninitializedData);
	p ("  AddressOfEntryPoint : 0x%x\n", bin->nt_headers->optional_header.AddressOfEntryPoint);
	p ("  BaseOfCode : 0x%x\n", bin->nt_headers->optional_header.BaseOfCode);
	p ("  ImageBase : 0x%"PFMT64x"\n", bin->nt_headers->optional_header.ImageBase);
	p ("  SectionAlignment : 0x%x\n", bin->nt_headers->optional_header.SectionAlignment);
	p ("  FileAlignment : 0x%x\n", bin->nt_headers->optional_header.FileAlignment);
	p ("  MajorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorOperatingSystemVersion);
	p ("  MinorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorOperatingSystemVersion);
	p ("  MajorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MajorImageVersion);
	p ("  MinorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MinorImageVersion);
	p ("  MajorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorSubsystemVersion);
	p ("  MinorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorSubsystemVersion);
	p ("  Win32VersionValue : 0x%x\n", bin->nt_headers->optional_header.Win32VersionValue);
	p ("  SizeOfImage : 0x%x\n", bin->nt_headers->optional_header.SizeOfImage);
	p ("  SizeOfHeaders : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeaders);
	p ("  CheckSum : 0x%x\n", bin->nt_headers->optional_header.CheckSum);
	p ("  Subsystem : 0x%x\n", bin->nt_headers->optional_header.Subsystem);
	p ("  DllCharacteristics : 0x%x\n", bin->nt_headers->optional_header.DllCharacteristics);
	p ("  SizeOfStackReserve : 0x%"PFMT64x"\n", bin->nt_headers->optional_header.SizeOfStackReserve);
	p ("  SizeOfStackCommit : 0x%"PFMT64x"\n", bin->nt_headers->optional_header.SizeOfStackCommit);
	p ("  SizeOfHeapReserve : 0x%"PFMT64x"\n", bin->nt_headers->optional_header.SizeOfHeapReserve);
	p ("  SizeOfHeapCommit : 0x%"PFMT64x"\n", bin->nt_headers->optional_header.SizeOfHeapCommit);
	p ("  LoaderFlags : 0x%x\n", bin->nt_headers->optional_header.LoaderFlags);
	p ("  NumberOfRvaAndSizes : 0x%x\n", bin->nt_headers->optional_header.NumberOfRvaAndSizes);
	RListIter *it;
	Pe_image_rich_entry *entry;
	p ("RICH_FIELDS\n");
	r_list_foreach (bin->rich_entries, it, entry) {
		p ("  Product: %d Name: %s Version: %d Times: %d\n", entry->productId, entry->productName, entry->minVersion, entry->timesUsed);
	}
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				p ("IMAGE_DIRECTORY_ENTRY_EXPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				p ("IMAGE_DIRECTORY_ENTRY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				p ("IMAGE_DIRECTORY_ENTRY_RESOURCE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				p ("IMAGE_DIRECTORY_ENTRY_EXCEPTION\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				p ("IMAGE_DIRECTORY_ENTRY_SECURITY\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				p ("IMAGE_DIRECTORY_ENTRY_BASERELOC\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				p ("IMAGE_DIRECTORY_ENTRY_DEBUG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				p ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT\n");
				p ("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				p ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				p ("IMAGE_DIRECTORY_ENTRY_TLS\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				p ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				p ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				p ("IMAGE_DIRECTORY_ENTRY_IAT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				p ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				p ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\n");
				break;
			}
			p ("  VirtualAddress : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress);
			p ("  Size : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].Size);
		}
	}
#undef p
	return r_strbuf_drain (sb);
}

extern struct r_bin_write_t r_bin_write_pe64;

static bool read_u32_at(RIO *io, ut64 addr, ut32 *out) {
	ut8 buf[sizeof (ut32)];
	if (!r_io_read_at (io, addr, buf, sizeof (buf))) {
		return false;
	}
	*out = r_read_le32 (buf);
	return true;
}

static bool read_runtime_function_at(RIO *io, ut64 addr, PE64_RUNTIME_FUNCTION *rfcn) {
	ut8 buf[sizeof (*rfcn)];
	if (!r_io_read_at (io, addr, buf, sizeof (buf))) {
		return false;
	}
	rfcn->BeginAddress = r_read_le32 (buf);
	rfcn->EndAddress = r_read_le32 (buf + sizeof (ut32));
	rfcn->UnwindData = r_read_le32 (buf + sizeof (ut32) * 2);
	return true;
}

static bool read_unwind_info_at(RIO *io, ut64 addr, PE64_UNWIND_INFO *info) {
	ut8 buf[offsetof (PE64_UNWIND_INFO, UnwindCode)];
	if (!r_io_read_at (io, addr, buf, sizeof (buf))) {
		return false;
	}
	info->Version = buf[0] & 7;
	info->Flags = buf[0] >> 3;
	info->SizeOfProlog = buf[1];
	info->CountOfCodes = buf[2];
	info->FrameRegister = buf[3] & 0xf;
	info->FrameOffset = buf[3] >> 4;
	return true;
}

static bool read_scope_record_at(RIO *io, ut64 addr, PE64_SCOPE_RECORD *scope) {
	ut8 buf[sizeof (*scope)];
	if (!r_io_read_at (io, addr, buf, sizeof (buf))) {
		return false;
	}
	scope->BeginAddress = r_read_le32 (buf);
	scope->EndAddress = r_read_le32 (buf + sizeof (ut32));
	scope->HandlerAddress = r_read_le32 (buf + sizeof (ut32) * 2);
	scope->JumpTarget = r_read_le32 (buf + sizeof (ut32) * 3);
	return true;
}

static RList *trycatch(RBinFile *bf) {
	RIO *io = bf->rbin->iob.io;
	ut64 baseAddr = bf->bo->baddr;
	int i;
	ut64 offset;
	ut32 c_handler = 0;

	struct PE_(r_bin_pe_obj_t) * bin = bf->bo->bin_obj;
	PE_(image_data_directory) *expdir = &bin->optional_header->DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	if (!expdir->Size) {
		return NULL;
	}

	RList *tclist = r_list_newf ((RListFree)r_bin_trycatch_free);
	if (!tclist) {
		return NULL;
	}

	for (offset = expdir->VirtualAddress; offset < (ut64)expdir->VirtualAddress + expdir->Size; offset += sizeof (PE64_RUNTIME_FUNCTION)) {
		PE64_RUNTIME_FUNCTION rfcn;
		bool suc = read_runtime_function_at (io, offset + baseAddr, &rfcn);
		if (!rfcn.BeginAddress) {
			break;
		}
		ut32 savedBeginOff = rfcn.BeginAddress;
		ut32 savedEndOff = rfcn.EndAddress;
		while (suc && rfcn.UnwindData & 1) {
			// XXX this ugly (int) cast is needed for MSVC for not to crash
			int delta = (rfcn.UnwindData & (int)~1);
			ut64 at = baseAddr + delta;
			suc = read_runtime_function_at (io, at, &rfcn);
		}
		rfcn.BeginAddress = savedBeginOff;
		rfcn.EndAddress = savedEndOff;
		if (!suc) {
			continue;
		}
		PE64_UNWIND_INFO info;
		suc = read_unwind_info_at (io, rfcn.UnwindData + baseAddr, &info);
		if (!suc || info.Version != 1 || (!(info.Flags & PE64_UNW_FLAG_EHANDLER) && !(info.Flags & PE64_UNW_FLAG_CHAININFO))) {
			continue;
		}

		ut32 sizeOfCodeEntries = info.CountOfCodes % 2 ? info.CountOfCodes + 1 : info.CountOfCodes;
		sizeOfCodeEntries *= sizeof (PE64_UNWIND_CODE);
		ut64 exceptionDataOff = baseAddr + rfcn.UnwindData + offsetof (PE64_UNWIND_INFO, UnwindCode) + sizeOfCodeEntries;

		if (info.Flags & PE64_UNW_FLAG_CHAININFO) {
			savedBeginOff = rfcn.BeginAddress;
			savedEndOff = rfcn.EndAddress;
			do {
				if (!read_runtime_function_at (io, exceptionDataOff, &rfcn)) {
					break;
				}
				suc = read_unwind_info_at (io, rfcn.UnwindData + baseAddr, &info);
				if (!suc || info.Version != 1) {
					break;
				}
				while (suc && (rfcn.UnwindData & 1)) {
					// XXX this ugly (int) cast is needed for MSVC for not to crash
					suc = read_runtime_function_at (io, baseAddr + ((int)rfcn.UnwindData & (int)~1), &rfcn);
				}
				if (!suc || info.Version != 1) {
					break;
				}
				sizeOfCodeEntries = info.CountOfCodes % 2 ? info.CountOfCodes + 1 : info.CountOfCodes;
				sizeOfCodeEntries *= sizeof (PE64_UNWIND_CODE);
				exceptionDataOff = baseAddr + rfcn.UnwindData + offsetof (PE64_UNWIND_INFO, UnwindCode) + sizeOfCodeEntries;
			} while (info.Flags & PE64_UNW_FLAG_CHAININFO);
			if (!(info.Flags & PE64_UNW_FLAG_EHANDLER)) {
				continue;
			}
			rfcn.BeginAddress = savedBeginOff;
			rfcn.EndAddress = savedEndOff;
		}

		ut32 handler;
		if (!read_u32_at (io, exceptionDataOff, &handler)) {
			continue;
		}
		if (c_handler && c_handler != handler) {
			continue;
		}
		exceptionDataOff += sizeof (ut32);

		if (!c_handler) {
			ut32 magic, rva_to_fcninfo;
			if (read_u32_at (io, exceptionDataOff, &rva_to_fcninfo) &&
				read_u32_at (io, baseAddr + rva_to_fcninfo, &magic)) {
				if (magic >= 0x19930520 && magic <= 0x19930522) {
					// __CxxFrameHandler3 or __GSHandlerCheck_EH
					continue;
				}
			}
		}

		ut32 scope_count;
		if (!read_u32_at (io, exceptionDataOff, &scope_count)) {
			continue;
		}

		PE64_SCOPE_RECORD scope;
		ut64 scopeRecOff = exceptionDataOff + sizeof (ut32);
		for (i = 0; i < scope_count; i++) {
			if (!read_scope_record_at (io, scopeRecOff, &scope)) {
				break;
			}
			if (scope.BeginAddress > scope.EndAddress
				|| scope.BeginAddress == UT32_MAX || scope.EndAddress == UT32_MAX
				|| !scope.BeginAddress || !scope.EndAddress) {
				break;
			}
			if (!(scope.BeginAddress >= rfcn.BeginAddress - 1 && scope.BeginAddress < rfcn.EndAddress
				&& scope.EndAddress <= rfcn.EndAddress + 1 && scope.EndAddress > rfcn.BeginAddress)) {
				continue;
			}
			if (!scope.JumpTarget) {
				// scope.HandlerAddress == __finally block
				continue;
			}
			ut64 handlerAddr = scope.HandlerAddress == 1 ? 0 : scope.HandlerAddress + baseAddr;
			RBinTrycatch *tc = r_bin_trycatch_new (
				rfcn.BeginAddress + baseAddr,
				scope.BeginAddress + baseAddr,
				scope.EndAddress + baseAddr,
				scope.JumpTarget + baseAddr,
				handlerAddr
			);
			c_handler = handler;
			r_list_append (tclist, tc);
			scopeRecOff += sizeof (PE64_SCOPE_RECORD);
		}
	}
	return tclist;
}

RBinPlugin r_bin_plugin_pe64 = {
	.meta = {
		.name = "pe64",
		.desc = "Portable Executable for 64 bit (PE32+)",
		.author = "nibble,pancake",
		.license = "LGPL-3.0-only",
	},
	.get_sdb = &get_sdb,
	.get_cc = &get_cc,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections_vec = &sections_vec,
	.symbols_vec = &symbols_vec,
	.imports_vec = &imports_vec,
	.info = &info,
	.header = &header,
	.fields = &fields,
	.classes = &classes,
	.libs = &libs,
	.relocs = &relocs,
	.get_vaddr = &get_vaddr,
	.trycatch = &trycatch,
	.write = &r_bin_write_pe64,
	.hashes = &compute_hashes
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64,
	.version = R2_VERSION
};
#endif
