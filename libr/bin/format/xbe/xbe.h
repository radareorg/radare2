
#define XBE_MAGIC 0x48454258

#define XBE_EP_RETAIL 0xA8FC57AB
#define XBE_EP_DEBUG 0x94859D4B

#define XBE_KP_RETAIL 0x5b6d40b6
#define XBE_KP_DEBUG 0xefb1f152

#define XBE_EP_CHIHIRO 0x40B5C16E
#define XBE_KP_CHIHIRO 0x2290059D

#define XBE_MAX_THUNK 378

typedef struct {
	ut32 magic;
	ut8  signature[0x100];
	ut32 base;
	ut32 headers_size;
	ut32 image_size;
	ut32 image_header_size;
	ut32 timestamp;
	ut32 cert_addr;
	ut32 sections;
	ut32 sechdr_addr;
	ut32 init_flags;
	ut32 ep;
	ut32 tls_addr;
	ut32 pe_shit[7];
	ut32 debug_path_addr;
	ut32 debug_name_addr;
	ut32 debug_uname_addr;
	ut32 kernel_thunk_addr;
	ut32 nonkernel_import_dir_addr;
	ut32 lib_versions;
	ut32 lib_versions_addr;
	ut32 kernel_lib_addr;
	ut32 xapi_lib_addr;
	ut32 shit[2];
} __attribute__((packed)) xbe_header;

#define SECT_FLAG_X 0x00000004
#define SECT_FLAG_W 0x00000001

typedef struct {
	ut32 flags;
	ut32 vaddr;
	ut32 vsize;
	ut32 offset;
	ut32 size;
	ut32 name_addr;
	ut32 refcount;
	ut32 shit[2];
	ut8  digest[20];
} __attribute__((packed)) xbe_section;

typedef struct {
	char name[8];
	ut16 major, minor, build;
	ut16 flags;
} __attribute__((packed)) xbe_lib;

typedef struct {
	xbe_header *header;
	int kt_key;
	int ep_key;
} r_bin_xbe_obj_t; 


