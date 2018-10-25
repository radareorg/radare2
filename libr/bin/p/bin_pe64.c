/* radare - LGPL - Copyright 2009-2015 - nibble, pancake */
#define R_BIN_PE64 1
#include "bin_pe.inc"

static bool check_bytes(const ut8 *buf, ut64 length) {
	int idx, ret = false;
	if (!buf || length <= 0x3d) {
		return false;
	}
	idx = buf[0x3c] | (buf[0x3d] << 8);
	if (length >= idx + 0x20) {
		if (!memcmp (buf, "MZ", 2) && !memcmp (buf + idx, "PE", 2) &&
			!memcmp (buf + idx + 0x18, "\x0b\x02", 2)) {
			ret = true;
		}
	}
	return ret;
}

static void header(RBinFile *bf) {
	struct PE_(r_bin_pe_obj_t) * bin = bf->o->bin_obj;
	struct r_bin_t *rbin = bf->rbin;
	rbin->cb_printf ("PE file header:\n");
	rbin->cb_printf ("IMAGE_NT_HEADERS\n");
	rbin->cb_printf ("\tSignature : 0x%x\n", bin->nt_headers->Signature);
	rbin->cb_printf ("IMAGE_FILE_HEADERS\n");
	rbin->cb_printf ("\tMachine : 0x%x\n", bin->nt_headers->file_header.Machine);
	rbin->cb_printf ("\tNumberOfSections : 0x%x\n", bin->nt_headers->file_header.NumberOfSections);
	rbin->cb_printf ("\tTimeDateStamp : 0x%x\n", bin->nt_headers->file_header.TimeDateStamp);
	rbin->cb_printf ("\tPointerToSymbolTable : 0x%x\n", bin->nt_headers->file_header.PointerToSymbolTable);
	rbin->cb_printf ("\tNumberOfSymbols : 0x%x\n", bin->nt_headers->file_header.NumberOfSymbols);
	rbin->cb_printf ("\tSizeOfOptionalHeader : 0x%x\n", bin->nt_headers->file_header.SizeOfOptionalHeader);
	rbin->cb_printf ("\tCharacteristics : 0x%x\n", bin->nt_headers->file_header.Characteristics);
	rbin->cb_printf ("IMAGE_OPTIONAL_HEADERS\n");
	rbin->cb_printf ("\tMagic : 0x%x\n", bin->nt_headers->optional_header.Magic);
	rbin->cb_printf ("\tMajorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MajorLinkerVersion);
	rbin->cb_printf ("\tMinorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MinorLinkerVersion);
	rbin->cb_printf ("\tSizeOfCode : 0x%x\n", bin->nt_headers->optional_header.SizeOfCode);
	rbin->cb_printf ("\tSizeOfInitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfInitializedData);
	rbin->cb_printf ("\tSizeOfUninitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfUninitializedData);
	rbin->cb_printf ("\tAddressOfEntryPoint : 0x%x\n", bin->nt_headers->optional_header.AddressOfEntryPoint);
	rbin->cb_printf ("\tBaseOfCode : 0x%x\n", bin->nt_headers->optional_header.BaseOfCode);
	rbin->cb_printf ("\tImageBase : 0x%x\n", bin->nt_headers->optional_header.ImageBase);
	rbin->cb_printf ("\tSectionAlignment : 0x%x\n", bin->nt_headers->optional_header.SectionAlignment);
	rbin->cb_printf ("\tFileAlignment : 0x%x\n", bin->nt_headers->optional_header.FileAlignment);
	rbin->cb_printf ("\tMajorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorOperatingSystemVersion);
	rbin->cb_printf ("\tMinorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorOperatingSystemVersion);
	rbin->cb_printf ("\tMajorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MajorImageVersion);
	rbin->cb_printf ("\tMinorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MinorImageVersion);
	rbin->cb_printf ("\tMajorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorSubsystemVersion);
	rbin->cb_printf ("\tMinorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorSubsystemVersion);
	rbin->cb_printf ("\tWin32VersionValue : 0x%x\n", bin->nt_headers->optional_header.Win32VersionValue);
	rbin->cb_printf ("\tSizeOfImage : 0x%x\n", bin->nt_headers->optional_header.SizeOfImage);
	rbin->cb_printf ("\tSizeOfHeaders : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeaders);
	rbin->cb_printf ("\tCheckSum : 0x%x\n", bin->nt_headers->optional_header.CheckSum);
	rbin->cb_printf ("\tSubsystem : 0x%x\n", bin->nt_headers->optional_header.Subsystem);
	rbin->cb_printf ("\tDllCharacteristics : 0x%x\n", bin->nt_headers->optional_header.DllCharacteristics);
	rbin->cb_printf ("\tSizeOfStackReserve : 0x%x\n", bin->nt_headers->optional_header.SizeOfStackReserve);
	rbin->cb_printf ("\tSizeOfStackCommit : 0x%x\n", bin->nt_headers->optional_header.SizeOfStackCommit);
	rbin->cb_printf ("\tSizeOfHeapReserve : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeapReserve);
	rbin->cb_printf ("\tSizeOfHeapCommit : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeapCommit);
	rbin->cb_printf ("\tLoaderFlags : 0x%x\n", bin->nt_headers->optional_header.LoaderFlags);
	rbin->cb_printf ("\tNumberOfRvaAndSizes : 0x%x\n", bin->nt_headers->optional_header.NumberOfRvaAndSizes);
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_EXPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_RESOURCE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_EXCEPTION\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_SECURITY\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_BASERELOC\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_DEBUG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT\n");
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_TLS\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_IAT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\n");
				break;
			}
			rbin->cb_printf ("\tVirtualAddress : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress);
			rbin->cb_printf ("\tSize : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].Size);
		}
	}
}

extern struct r_bin_write_t r_bin_write_pe64;

RBinPlugin r_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_buffer = &load_buffer,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.header = &header,
	.libs = &libs,
	.relocs = &relocs,
	.get_vaddr = &get_vaddr,
	.write = &r_bin_write_pe64
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64,
	.version = R2_VERSION
};
#endif
