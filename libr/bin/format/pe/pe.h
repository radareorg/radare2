#include <r_lib.h>
#include <r_bin.h>

#include "pe_specs.h"

#ifndef _INCLUDE_R_BIN_PE_H_
#define _INCLUDE_R_BIN_PE_H_

#define R_BIN_PE_SCN_IS_SHAREABLE(x)       x & PE_IMAGE_SCN_MEM_SHARED
#define R_BIN_PE_SCN_IS_EXECUTABLE(x)      x & PE_IMAGE_SCN_MEM_EXECUTE
#define R_BIN_PE_SCN_IS_READABLE(x)        x & PE_IMAGE_SCN_MEM_READ
#define R_BIN_PE_SCN_IS_WRITABLE(x)        x & PE_IMAGE_SCN_MEM_WRITE

struct r_bin_pe_addr_t {
	ut64 vaddr;
	ut64 paddr;
	ut64 haddr;
};

struct r_bin_pe_section_t {
	ut8 name[PE_IMAGE_SIZEOF_SHORT_NAME * 3];
	ut64 size;
	ut64 vsize;
	ut64 vaddr;
	ut64 paddr;
	ut64 perm;
	int last;
};

struct r_bin_pe_import_t {
	ut8 name[PE_NAME_LENGTH + 1];
	ut8 libname[PE_NAME_LENGTH + 1];
	ut64 vaddr;
	ut64 paddr;
	ut64 hint;
	ut64 ordinal;
	int last;
};

struct r_bin_pe_export_t {
	ut8 name[PE_NAME_LENGTH + 1];
	ut8 libname[PE_NAME_LENGTH + 1];
	ut8 forwarder[PE_NAME_LENGTH + 1];
	ut64 vaddr;
	ut64 paddr;
	ut64 ordinal;
	int last;
};

struct r_bin_pe_string_t {
	char string[PE_STRING_LENGTH];
	ut64 vaddr;
	ut64 paddr;
	ut64 size;
	char type;
	int last;
};

struct r_bin_pe_lib_t {
	char name[PE_STRING_LENGTH];
	int last;
};

typedef struct _PE_RESOURCE {
	char *timestr;
	char *type;
	char *language;
	char *name;
	Pe_image_resource_data_entry *data;
} r_pe_resource;

#define GUIDSTR_LEN 41
#define DBG_FILE_NAME_LEN 255

typedef struct SDebugInfo {
	char guidstr[GUIDSTR_LEN];
	char file_name[DBG_FILE_NAME_LEN];
} SDebugInfo;

// typedef struct PE_(r_bin_pe_obj_t) RBinPEObj;

#endif
struct PE_(r_bin_pe_obj_t) {
	// these pointers contain a copy of the headers and sections!
	PE_(image_dos_header) * dos_header;
	PE_(image_nt_headers) * nt_headers;
	PE_(image_optional_header) * optional_header;       //not free this just pointer into nt_headers
	PE_(image_data_directory) * data_directory;         //not free this just pointer into nt_headers
	PE_(image_section_header) * section_header;
	PE_(image_export_directory) * export_directory;
	PE_(image_import_directory) * import_directory;
	PE_(image_tls_directory) * tls_directory;
	Pe_image_resource_directory* resource_directory;
	PE_(image_delay_import_directory) * delay_import_directory;
	Pe_image_security_directory * security_directory;

	// these pointers pertain to the .net relevant sections
	PE_(image_clr_header) * clr_hdr;
	PE_(image_metadata_header) * metadata_header;
	PE_(image_metadata_stream) * *streams;

	/* store the section information for future use */
	struct r_bin_pe_section_t *sections;

	// these values define the real offset into the untouched binary
	ut64 rich_header_offset;
	ut64 nt_header_offset;
	ut64 section_header_offset;
	ut64 import_directory_offset;
	ut64 export_directory_offset;
	ut64 resource_directory_offset;
	ut64 delay_import_directory_offset;

	int import_directory_size;
	int size;
	int num_sections;
	int endian;
	bool verbose;
	int big_endian;
	RList* rich_entries;
	RList* relocs;
	RList* resources; //RList of r_pe_resources
	const char* file;
	RBuffer* b;
	Sdb *kv;
	RCMS* cms;
	SpcIndirectDataContent *spcinfo;
	char *authentihash;
	bool is_authhash_valid;
	bool is_signed;
};

#undef RBinPEObj
#define RBinPEObj struct PE_(r_bin_pe_obj_t)

// #define RBinPEObj struct PE_(r_bin_pe_obj_t)
R_API PE_DWord PE_(va2pa)(RBinPEObj* bin, PE_DWord rva);
R_API void PE_(r_bin_store_all_resource_version_info)(RBinPEObj* bin);
R_API char* PE_(r_bin_pe_get_arch)(RBinPEObj* bin);
R_API char *PE_(r_bin_pe_get_cc)(RBinPEObj* bin);
R_API struct r_bin_pe_addr_t* PE_(r_bin_pe_get_entrypoint)(RBinPEObj* bin);
R_API struct r_bin_pe_addr_t* PE_(r_bin_pe_get_main_vaddr)(RBinPEObj* bin);
R_API struct r_bin_pe_export_t* PE_(r_bin_pe_get_exports)(RBinPEObj* bin); // TODO
R_API int PE_(r_bin_pe_get_file_alignment)(RBinPEObj* bin);
R_API ut64 PE_(r_bin_pe_get_image_base)(RBinPEObj* bin);
R_API struct r_bin_pe_import_t* PE_(r_bin_pe_get_imports)(RBinPEObj* bin); // TODO
R_API struct r_bin_pe_lib_t* PE_(r_bin_pe_get_libs)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_get_image_size)(RBinPEObj* bin);
R_API char* PE_(r_bin_pe_get_machine)(RBinPEObj* bin);
R_API char* PE_(r_bin_pe_get_os)(RBinPEObj* bin);
R_API char* PE_(r_bin_pe_get_class)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_get_bits)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_get_section_alignment)(RBinPEObj* bin);
R_API char* PE_(r_bin_pe_get_subsystem)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_is_dll)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_is_big_endian)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_is_stripped_relocs)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_is_stripped_line_nums)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_is_stripped_local_syms)(RBinPEObj* bin);
R_API int PE_(r_bin_pe_is_stripped_debug)(RBinPEObj* bin);
R_API void* PE_(r_bin_pe_free)(RBinPEObj* bin);
R_API RBinPEObj* PE_(r_bin_pe_new)(const char* file, bool verbose);
R_API RBinPEObj* PE_(r_bin_pe_new_buf)(RBuffer* buf, bool verbose);
R_API int PE_(r_bin_pe_get_debug_data)(RBinPEObj* bin, struct SDebugInfo* res);
R_API int PE_(bin_pe_get_claimed_checksum)(RBinPEObj* bin);
R_API int PE_(bin_pe_get_actual_checksum)(RBinPEObj* bin);
R_API const char* PE_(bin_pe_compute_authentihash)(RBinPEObj* bin);
R_API int PE_(bin_pe_is_authhash_valid)(RBinPEObj* bin);
R_API int PE_(bin_pe_get_overlay)(RBinPEObj* bin, ut64* size);
R_API void PE_(r_bin_pe_check_sections)(RBinPEObj* bin, struct r_bin_pe_section_t** sects);
R_API struct r_bin_pe_addr_t *PE_(check_unknow)(RBinPEObj *bin);
R_API struct r_bin_pe_addr_t *PE_(check_msvcseh)(RBinPEObj *bin);
R_API struct r_bin_pe_addr_t *PE_(check_mingw)(RBinPEObj *bin);
R_API bool PE_(r_bin_pe_section_perms)(RBinFile *bf, const char *name, int perms);
R_API void PE_(bin_pe_parse_resource)(RBinPEObj *bin);
R_API RBinPEObj* PE_(get)(RBinFile *bf);
