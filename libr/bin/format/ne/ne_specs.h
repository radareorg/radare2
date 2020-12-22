#ifndef NE_SPECS_H
#define NE_SPECS_H

enum {
	LOBYTE = 0,
	SEL_16 = 2,
	POI_32 = 3,
	OFF_16 = 5,
	POI_48 = 11,
	OFF_32 = 13
};

enum {
	INTERNAL_REF = 0,
	IMPORTED_ORD = 1,
	IMPORTED_NAME = 2,
	OSFIXUP = 3,
	ADDITIVE = 4
};

typedef struct _RELOC {
	ut8 type;
	ut8 flags;
	ut16 offset;
	union {
		ut16 index;
		struct { // internal_fixed
			ut8 segnum;
			ut8 zero;
			ut16 segoff;
		};
		struct { // internal_moveable
			ut16 ignore;
			ut16 entry_ordinal;
		};
		struct { // import_ordinal
			ut16 align1;
			ut16 func_ord;
		};
		struct { // import_name
			ut16 align2;
			ut16 name_off;
		};
	};
} NE_image_reloc_item;

enum {
	IS_DATA = 1,
	IS_MOVEABLE = 0x10,
	IS_SHAREABLE = 0x20,
	IS_PRELOAD = 0x40,
	RELOCINFO = 0x100,
	IS_RX = 0x1000
};

enum {
	NOAUTODATA = 0,
	SINGLEDATA = 1,
	LINKERROR = 0x2000,
	LIBRARY = 0x8000
};

typedef struct _SEGMENT {
	ut16 offset; //Specifies the offset, in sectors, to the segment data (relative to the beginning of the file). A value of zero means no data exists.
	ut16 length; //Length of the segment in bytes. A value of zero indicates that the segment length is 64K, unless the selector offset is also zero.
	ut16 flags; // NE_SEGMENT_FLAGS
	ut16 minAllocSz; //A value of zero indicates that the minimum allocation size is 64K
} NE_image_segment_entry;

typedef struct _NAMEINFO {
	ut16 rnOffset;
	ut16 rnLength;
	ut16 rnFlags;
	ut16 rnID;
	ut16 rnHandle;
	ut16 rnUsage;
} NE_image_nameinfo_entry;

typedef struct _TYPEINFO {
	ut16        rtTypeID;
	ut16        rtResourceCount;
	ut32        rtReserved;
	NE_image_nameinfo_entry    rtNameInfo[];
} NE_image_typeinfo_entry;

typedef struct {
	char sig[2];             // "NE"
	ut8 MajLinkerVersion;    // The major linker version
	ut8 MinLinkerVersion;    // The minor linker version
	ut16 EntryTableOffset;   // Offset of entry table
	ut16 EntryTableLength;   // Length of entry table in bytes
	ut32 FileLoadCRC;        // 32-bit CRC of entire contents of file
	ut8 ProgFlags;           // Program flags, bitmapped
	ut8 ApplFlags;           // Application flags, bitmapped
	ut8 AutoDataSegIndex;    // The automatic data segment index
	ut16 InitHeapSize;       // The intial local heap size
	ut16 InitStackSize;      // The inital stack size
	ut16 ipEntryPoint;       // IP entry point offset
	ut16 csEntryPoint;       // CS entrypoint index into segment table (Start at 1)
	ut32 InitStack;          // SS:SP inital stack pointer, SS is index into segment table
	ut16 SegCount;           // Number of segments in segment table
	ut16 ModRefs;            // Number of module references (DLLs)
	ut16 NoResNamesTabSiz;   // Size of non-resident names table, in bytes
	ut16 SegTableOffset;     // Offset of Segment table
	ut16 ResTableOffset;     // Offset of resources table
	ut16 ResidNamTable;      // Offset of resident names table
	ut16 ModRefTable;        // Offset of module reference table
	ut16 ImportNameTable;    // Offset of imported names table (array of counted strings, terminated with string of length 00h)
	ut32 OffStartNonResTab;  // Offset from start of file to non-resident names table
	ut16 MovEntryCount;      // Count of moveable entry point listed in entry table
	ut16 FileAlnSzShftCnt;   // File alligbment size shift count (0=9(default 512 byte pages))
	ut16 nResTabEntries;     // Number of resource table entries
	ut8 targOS;              // Target OS
	ut8 OS2EXEFlags;         // Other OS/2 flags
	ut16 retThunkOffset;     // Offset to return thunks or start of gangload area - what is gangload?
	ut16 segrefthunksoff;    // Offset to segment reference thunks or size of gangload area
	ut16 mincodeswap;        // Minimum code swap area size
	ut8 expctwinver[2];      // Expected windows version (minor first)
} NE_image_header;

#endif