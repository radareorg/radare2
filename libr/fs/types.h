typedef struct r_fs_type_t {
	const char *name;
	int bufoff;
	const char *buf;
	int buflen;
	int byteoff;
	ut8 byte;
	int bytelen;
} RFSType;

static RFSType fstypes[] = {
	{ "hfsplus", 0x400, "H+", 2, 0, 0, 0x400 },
	{ "fat", 0x36, "FAT12", 5, 0, 0, 0 },
	{ "fat", 0x52, "FAT32", 5, 0, 0, 0 },
	{ "ext2", 0x438, "\x53\xef", 2, 0, 0, 0 },
	{ "btrfs", 0x10040, "_BHRfS_M", 8, 0, 0, 0x0 },
	{ NULL }
};
