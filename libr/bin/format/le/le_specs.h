#ifndef LE_SPECS_H
#define LE_SPECS_H
#include <r_types.h>

typedef enum {
	UNUSED_ENTRY = 0,
	ENTRY16,
	CALLGATE,
	ENTRY32,
	FORWARDER,
} LE_entry_bundle_type;

typedef enum {
	LE_RT_POINTER = 1, /* mouse pointer shape */
	LE_RT_BITMAP = 2, /* bitmap */
	LE_RT_MENU = 3, /* menu template */
	LE_RT_DIALOG = 4, /* dialog template */
	LE_RT_STRING = 5, /* string tables */
	LE_RT_FONTDIR = 6, /* font directory */
	LE_RT_FONT = 7, /* font */
	LE_RT_ACCELTABLE = 8, /* accelerator tables */
	LE_RT_RCDATA = 9, /* binary data */
	LE_RT_MESSAGE = 10, /* error msg tables */
	LE_RT_DLGINCLUDE = 11, /* dialog include file name */
	LE_RT_VKEYTBL = 12, /* key to vkey tables */
	LE_RT_KEYTBL = 13, /* key to UGL tables */
	LE_RT_CHARTBL = 14, /* glyph to character tables */
	LE_RT_DISPLAYINFO = 15, /* screen display information */
	LE_RT_FKASHORT = 16, /* function key area short form */
	LE_RT_FKALONG = 17, /* function key area long form */
	LE_RT_HELPTABLE = 18, /* Help table for Cary Help manager */
	LE_RT_HELPSUBTABLE = 19, /* Help subtable for Cary Help manager */
	LE_RT_FDDIR = 20, /* DBCS uniq/font driver directory */
	LE_RT_FD = 21, /* DBCS uniq/font driver */
} LE_resource_type;

// This bit signifies that additional information is contained in the linear EXE module 
// and will be used in the future for parameter type checking.
#define ENTRY_PARAMETER_TYPING_PRESENT 0x80

typedef struct LE_entry_bundle_header_s {
	ut8 count;
	ut8 type; /* LE_entry_bundle_type */
	ut16 objnum; // This is the object number for the entries in this bundle.
} LE_entry_bundle_header;

#define ENTRY_EXPORTED         0x01
#define ENTRY_PARAM_COUNT_MASK 0xF8

typedef R_PACKED (union LE_entry_bundle_entry_u {
	R_PACKED (struct {
		ut8 flags;   // First bit set if exported, mask with 0xF8 to get parameters count
		ut16 offset; // This is the offset in the object for the entry point defined at this ordinal number.
	}) entry_16;
	R_PACKED (struct {
		ut8 flags;   // First bit set if exported, mask with 0xF8 to get parameters count
		ut16 offset; // This is the offset in the object for the entry point defined at this ordinal number.
		ut16 callgate_sel; // The callgate selector for references to ring 2 entry points.
	}) callgate;
	R_PACKED (struct {
		ut8 flags;   // First bit set if exported, mask with 0xF8 to get parameters count
		ut32 offset; // This is the offset in the object for the entry point defined at this ordinal number.
	}) entry_32;
	R_PACKED (struct {
		ut8 flags; // First bit set if import by ordinal
		ut16 import_ord; // This is the index into the Import Module Name Table for this forwarder.
		ut32 offset; // If import by ordinal, is the ordinal number into the Entry Table of the target module, else is the offset into the Procedure Names Table of the target module.
	}) forwarder;
}) LE_entry_bundle_entry;


#define F_SOURCE_TYPE_MASK 0xF
#define F_SOURCE_ALIAS 0x10
#define F_SOURCE_LIST 0x20

typedef enum {
	BYTEFIXUP,
	UNDEFINED1,
	SELECTOR16,
	POINTER32, // 16:16
	UNDEFINED2,
	OFFSET16,
	POINTER48, // 16:32
	OFFSET32,
	SELFOFFSET32,
} LE_fixup_source_type;

#define F_TARGET_TYPE_MASK 0x3
#define F_TARGET_ADDITIVE 0x4
#define F_TARGET_CHAIN 0x8
#define F_TARGET_OFF32 0x10 // Else 16
#define F_TARGET_ADD32 0x20 // Else 16
#define F_TARGET_ORD16 0x40 // Else 8
#define F_TARGET_ORD8 0x80 // Else 16

typedef enum {
	INTERNAL,
	IMPORTORD,
	IMPORTNAME,
	INTERNALENTRY
} LE_fixup_record_type;

typedef struct LE_fixup_record_header_s {
	ut8 source;
	ut8 target;
} LE_fixup_record_header;

#define O_READABLE     1
#define O_WRITABLE     1 << 1
#define O_EXECUTABLE   1 << 2
#define O_RESOURCE     1 << 3
#define O_DISCARTABLE  1 << 4
#define O_SHARED       1 << 5
#define O_PRELOAD      1 << 6
#define O_INVALID      1 << 7
#define O_ZEROED       1 << 8
#define O_RESIDENT     1 << 9
#define O_CONTIGUOUS   O_RESIDENT | O_ZEROED
#define O_LOCKABLE     1 << 10
#define O_RESERVED     1 << 11
#define O_ALIASED      1 << 12
#define O_BIG_BIT      1 << 13
#define O_CODE         1 << 14
#define O_IO_PRIV      1 << 15

typedef struct LE_object_entry_s {
	ut32 virtual_size;
	ut32 reloc_base_addr;
	ut32 flags;
	ut32 page_tbl_idx; // This specifies the number of the first object page table entry for this object
	ut32 page_tbl_entries;
	ut32 reserved;
} LE_object_entry;

#define P_LEGAL      0
#define P_ITERATED   1
#define P_INVALID    2
#define P_ZEROED     3
#define P_RANGE      4
#define P_COMPRESSED 5

typedef struct LE_object_page_entry_s {
	ut32 offset; // 0 if zero-filled/invalid page (check flags)
	ut16 size;
	ut16 flags;
} LE_object_page_entry;

#define M_PP_LIB_INIT           1 << 2
#define M_SYS_DLL               1 << 3 // No internal fixups
#define M_INTERNAL_FIXUP        1 << 4
#define M_EXTERNAL_FIXUP        1 << 5
#define M_PM_WINDOWING_INCOMP   1 << 8 // Fullscreen only
#define M_PM_WINDOWING_COMPAT   1 << 9
#define M_USES_PM_WINDOWING     M_PM_WINDOWING_INCOMP | M_PM_WINDOWING_COMPAT
#define M_NOT_LOADABLE          1 << 13
#define M_TYPE_MASK             0x38000
#define M_TYPE_EXE              0
#define M_TYPE_DLL              0x08000
#define M_TYPE_PM_DLL           0x10000
#define M_TYPE_PDD              0x20000 // Physical Device Driver
#define M_TYPE_VDD              0x28000 // Virtual Device Driver
#define M_MP_UNSAFE             1 << 19
#define M_PP_LIB_TERM           1 << 30

typedef struct LE_image_header_s { /* New 32-bit .EXE header */
	ut8 magic[2]; /* Magic number MAGIC */
	ut8 border; /* The byte ordering for the .EXE */
	ut8 worder; /* The word ordering for the .EXE */
	ut32 level; /* The EXE format level for now = 0 */
	ut16 cpu; /* The CPU type */
	ut16 os; /* The OS type */
	ut32 ver; /* Module version */
	ut32 mflags; /* Module flags */
	ut32 mpages; /* Module # pages */
	ut32 startobj; /* Object # for instruction pointer */
	ut32 eip; /* Extended instruction pointer */
	ut32 stackobj; /* Object # for stack pointer */
	ut32 esp; /* Extended stack pointer */
	ut32 pagesize; /* .EXE page size */
	ut32 pageshift; /* Page alignment shift in .EXE or Last Page Size (on LE only)*/
	ut32 fixupsize; /* Fixup section size */
	ut32 fixupsum; /* Fixup section checksum */
	ut32 ldrsize; /* Loader section size */
	ut32 ldrsum; /* Loader section checksum */
	ut32 objtab; /* Object table offset */
	ut32 objcnt; /* Number of objects in module */
	ut32 objmap; /* Object page map offset */
	ut32 itermap; /* Object iterated data map offset (File Relative) */
	ut32 rsrctab; /* Offset of Resource Table */
	ut32 rsrccnt; /* Number of resource entries */
	ut32 restab; /* Offset of resident name table */
	ut32 enttab; /* Offset of Entry Table */
	ut32 dirtab; /* Offset of Module Directive Table */
	ut32 dircnt; /* Number of module directives */
	ut32 fpagetab; /* Offset of Fixup Page Table */
	ut32 frectab; /* Offset of Fixup Record Table */
	ut32 impmod; /* Offset of Import Module Name Table */
	ut32 impmodcnt; /* Number of entries in Import Module Name Table */
	ut32 impproc; /* Offset of Import Procedure Name Table */
	ut32 pagesum; /* Offset of Per-Page Checksum Table */
	ut32 datapage; /* Offset of Enumerated Data Pages (File Relative) */
	ut32 preload; /* Number of preload pages */
	ut32 nrestab; /* Offset of Non-resident Names Table (File Relative) */
	ut32 cbnrestab; /* Size of Non-resident Name Table */
	ut32 nressum; /* Non-resident Name Table Checksum */
	ut32 autodata; /* Object # for automatic data object */
	ut32 debuginfo; /* Offset of the debugging information */
	ut32 debuglen; /* The length of the debugging info. in bytes */
	ut32 instpreload; /* Number of instance pages in preload section of .EXE file */
	ut32 instdemand; /* Number of instance pages in demand load section of EXE file */
	ut32 heapsize; /* Size of heap - for 16-bit apps */
	ut32 stacksize; /* Size of stack */
} LE_image_header;
#endif
