#ifndef TYPES_H
#define TYPES_H

#define _R_LIST_C
#include <r_util.h>

#define READ_PAGE_FAIL 0x01

//TODO: MOVE TO GENERAL MACROSE
///////////////////////////////////////////////////////////////////////////////
#define GET_PAGE(pn, off, pos, page_size)	{ \
	(pn) = (pos) / (page_size); \
	(off) = (pos) % (page_size); \
}

///////////////////////////////////////////////////////////////////////////////
#define READ_PAGES(start_indx, end_indx) { \
	for (i = start_indx; i < end_indx; i++) { \
		fseek(stream_file->fp, stream_file->pages[i] * stream_file->page_size, SEEK_SET); \
		fread(tmp, stream_file->page_size, 1, stream_file->fp); \
		tmp += stream_file->page_size; \
	} \
}

///////////////////////////////////////////////////////////////////////////////
#define SWAP_UINT16(x) (((x) >> 8) | ((x) << 8))

///////////////////////////////////////////////////////////////////////////////
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

///////////////////////////////////////////////////////////////////////////////
#define CAN_READ(curr_read_bytes, bytes_for_read, max_len) { \
	if ((((curr_read_bytes) + (bytes_for_read)) >= (max_len))) { \
		return 0; \
	} \
}

///////////////////////////////////////////////////////////////////////////////
#define UPDATE_DATA(src, curr_read_bytes, bytes_for_read) { \
	(src) += (bytes_for_read); \
	(curr_read_bytes) += (bytes_for_read); \
}

///////////////////////////////////////////////////////////////////////////////
#define PEEK_READ(curr_read_bytes, bytes_for_read, max_len, dst, src, type_name) { \
	CAN_READ((curr_read_bytes), (bytes_for_read), (max_len)); \
	(dst) = *(type_name *) (src); \
}

///////////////////////////////////////////////////////////////////////////////
#define READ(curr_read_bytes, bytes_for_read, max_len, dst, src, type_name) { \
	PEEK_READ((curr_read_bytes), (bytes_for_read), (max_len), (dst), (src), type_name); \
	UPDATE_DATA((src), (curr_read_bytes), (bytes_for_read)); \
}

///////////////////////////////////////////////////////////////////////////////
#define PAD_ALIGN(pad, curr_read_bytes, src, max_len) { \
	int tmp = 0; \
	if ((pad) > 0xF0) { \
		tmp = (pad) & 0x0F; \
		CAN_READ((curr_read_bytes), (tmp), (len)); \
		UPDATE_DATA((src), (curr_read_bytes), (tmp)); \
	} \
}

typedef struct R_STREAM_FILE_{
//	FILE *fp;
	RBuffer *buf;
	int *pages;
	int page_size;
	int pages_amount;
	int end;
	int pos;
	int error;
} R_STREAM_FILE;

typedef void (*free_func)(void *);
typedef void (*get_value_name)(void *type, char **res_name);
typedef void (*get_value)(void *type, int *res);
typedef void (*get_value_name_len)(void *type, int *res);
typedef void (*get_member_list)(void *type, RList **l);
typedef int (*get_arg_type_)(void *type, void **ret_type);
typedef int (*get_val_type)(void *type, void **ret_type);

typedef get_val_type get_element_type_;
typedef get_val_type get_index_type_;
typedef get_val_type get_base_type_;
typedef get_arg_type_ get_derived_;
typedef get_arg_type_ get_vshape_;
typedef get_arg_type_ get_utype_;
typedef get_val_type get_return_type_;
typedef get_val_type get_class_type_;
typedef get_val_type get_this_type_;
typedef get_arg_type_ get_arglist_;
typedef get_arg_type_ get_index_;
typedef get_arg_type_ get_mlist_;
typedef get_arg_type_ get_modified_type_;
typedef get_value get_index_val;
typedef get_value_name get_print_type_;

typedef enum {
	eT_NOTYPE =               0x00000000,
	eT_ABS =                  0x00000001,
	eT_SEGMENT =              0x00000002,
	eT_VOID =                 0x00000003,

	eT_HRESULT =              0x00000008,
	eT_32PHRESULT =           0x00000408,
	eT_64PHRESULT =           0x00000608,

	eT_PVOID =                0x00000103,
	eT_PFVOID =               0x00000203,
	eT_PHVOID =               0x00000303,
	eT_32PVOID =              0x00000403,
	eT_32PFVOID =             0x00000503,
	eT_64PVOID =              0x00000603,

	eT_CURRENCY =             0x00000004,
	eT_NBASICSTR =            0x00000005,
	eT_FBASICSTR =            0x00000006,
	eT_NOTTRANS =             0x00000007,
	eT_BIT =                  0x00000060,
	eT_PASCHAR =              0x00000061,

	eT_CHAR =                 0x00000010,
	eT_PCHAR =                0x00000110,
	eT_PFCHAR =               0x00000210,
	eT_PHCHAR =               0x00000310,
	eT_32PCHAR =              0x00000410,
	eT_32PFCHAR =             0x00000510,
	eT_64PCHAR =              0x00000610,

	eT_UCHAR =                0x00000020,
	eT_PUCHAR =               0x00000120,
	eT_PFUCHAR =              0x00000220,
	eT_PHUCHAR =              0x00000320,
	eT_32PUCHAR =             0x00000420,
	eT_32PFUCHAR =            0x00000520,
	eT_64PUCHAR =             0x00000620,

	eT_RCHAR =                0x00000070,
	eT_PRCHAR =               0x00000170,
	eT_PFRCHAR =              0x00000270,
	eT_PHRCHAR =              0x00000370,
	eT_32PRCHAR =             0x00000470,
	eT_32PFRCHAR =            0x00000570,
	eT_64PRCHAR =             0x00000670,

	eT_WCHAR =                0x00000071,
	eT_PWCHAR =               0x00000171,
	eT_PFWCHAR =              0x00000271,
	eT_PHWCHAR =              0x00000371,
	eT_32PWCHAR =             0x00000471,
	eT_32PFWCHAR =            0x00000571,
	eT_64PWCHAR =             0x00000671,

	eT_INT1 =                 0x00000068,
	eT_PINT1 =                0x00000168,
	eT_PFINT1 =               0x00000268,
	eT_PHINT1 =               0x00000368,
	eT_32PINT1 =              0x00000468,
	eT_32PFINT1 =             0x00000568,
	eT_64PINT1 =              0x00000668,

	eT_UINT1 =                0x00000069,
	eT_PUINT1 =               0x00000169,
	eT_PFUINT1 =              0x00000269,
	eT_PHUINT1 =              0x00000369,
	eT_32PUINT1 =             0x00000469,
	eT_32PFUINT1 =            0x00000569,
	eT_64PUINT1 =             0x00000669,

	eT_SHORT =                0x00000011,
	eT_PSHORT =               0x00000111,
	eT_PFSHORT =              0x00000211,
	eT_PHSHORT =              0x00000311,
	eT_32PSHORT =             0x00000411,
	eT_32PFSHORT =            0x00000511,
	eT_64PSHORT =             0x00000611,

	eT_USHORT =               0x00000021,
	eT_PUSHORT =              0x00000121,
	eT_PFUSHORT =             0x00000221,
	eT_PHUSHORT =             0x00000321,
	eT_32PUSHORT =            0x00000421,
	eT_32PFUSHORT =           0x00000521,
	eT_64PUSHORT =            0x00000621,

	eT_INT2 =                 0x00000072,
	eT_PINT2 =                0x00000172,
	eT_PFINT2 =               0x00000272,
	eT_PHINT2 =               0x00000372,
	eT_32PINT2 =              0x00000472,
	eT_32PFINT2 =             0x00000572,
	eT_64PINT2 =              0x00000672,

	eT_UINT2 =                0x00000073,
	eT_PUINT2 =               0x00000173,
	eT_PFUINT2 =              0x00000273,
	eT_PHUINT2 =              0x00000373,
	eT_32PUINT2 =             0x00000473,
	eT_32PFUINT2 =            0x00000573,
	eT_64PUINT2 =             0x00000673,

	eT_LONG =                 0x00000012,
	eT_PLONG =                0x00000112,
	eT_PFLONG =               0x00000212,
	eT_PHLONG =               0x00000312,
	eT_32PLONG =              0x00000412,
	eT_32PFLONG =             0x00000512,
	eT_64PLONG =              0x00000612,

	eT_ULONG =                0x00000022,
	eT_PULONG =               0x00000122,
	eT_PFULONG =              0x00000222,
	eT_PHULONG =              0x00000322,
	eT_32PULONG =             0x00000422,
	eT_32PFULONG =            0x00000522,
	eT_64PULONG =             0x00000622,

	eT_INT4 =                 0x00000074,
	eT_PINT4 =                0x00000174,
	eT_PFINT4 =               0x00000274,
	eT_PHINT4 =               0x00000374,
	eT_32PINT4 =              0x00000474,
	eT_32PFINT4 =             0x00000574,
	eT_64PINT4 =              0x00000674,

	eT_UINT4 =                0x00000075,
	eT_PUINT4 =               0x00000175,
	eT_PFUINT4 =              0x00000275,
	eT_PHUINT4 =              0x00000375,
	eT_32PUINT4 =             0x00000475,
	eT_32PFUINT4 =            0x00000575,
	eT_64PUINT4 =             0x00000675,

	eT_QUAD =                 0x00000013,
	eT_PQUAD =                0x00000113,
	eT_PFQUAD =               0x00000213,
	eT_PHQUAD =               0x00000313,
	eT_32PQUAD =              0x00000413,
	eT_32PFQUAD =             0x00000513,
	eT_64PQUAD =              0x00000613,

	eT_UQUAD =                0x00000023,
	eT_PUQUAD =               0x00000123,
	eT_PFUQUAD =              0x00000223,
	eT_PHUQUAD =              0x00000323,
	eT_32PUQUAD =             0x00000423,
	eT_32PFUQUAD =            0x00000523,
	eT_64PUQUAD =             0x00000623,

	eT_INT8 =                 0x00000076,
	eT_PINT8 =                0x00000176,
	eT_PFINT8 =               0x00000276,
	eT_PHINT8 =               0x00000376,
	eT_32PINT8 =              0x00000476,
	eT_32PFINT8 =             0x00000576,
	eT_64PINT8 =              0x00000676,

	eT_UINT8 =                0x00000077,
	eT_PUINT8 =               0x00000177,
	eT_PFUINT8 =              0x00000277,
	eT_PHUINT8 =              0x00000377,
	eT_32PUINT8 =             0x00000477,
	eT_32PFUINT8 =            0x00000577,
	eT_64PUINT8 =             0x00000677,

	eT_OCT =                  0x00000014,
	eT_POCT =                 0x00000114,
	eT_PFOCT =                0x00000214,
	eT_PHOCT =                0x00000314,
	eT_32POCT =               0x00000414,
	eT_32PFOCT =              0x00000514,
	eT_64POCT =               0x00000614,

	eT_UOCT =                 0x00000024,
	eT_PUOCT =                0x00000124,
	eT_PFUOCT =               0x00000224,
	eT_PHUOCT =               0x00000324,
	eT_32PUOCT =              0x00000424,
	eT_32PFUOCT =             0x00000524,
	eT_64PUOCT =              0x00000624,

	eT_INT16 =                0x00000078,
	eT_PINT16 =               0x00000178,
	eT_PFINT16 =              0x00000278,
	eT_PHINT16 =              0x00000378,
	eT_32PINT16 =             0x00000478,
	eT_32PFINT16 =            0x00000578,
	eT_64PINT16 =             0x00000678,

	eT_UINT16 =               0x00000079,
	eT_PUINT16 =              0x00000179,
	eT_PFUINT16 =             0x00000279,
	eT_PHUINT16 =             0x00000379,
	eT_32PUINT16 =            0x00000479,
	eT_32PFUINT16 =           0x00000579,
	eT_64PUINT16 =            0x00000679,

	eT_REAL32 =               0x00000040,
	eT_PREAL32 =              0x00000140,
	eT_PFREAL32 =             0x00000240,
	eT_PHREAL32 =             0x00000340,
	eT_32PREAL32 =            0x00000440,
	eT_32PFREAL32 =           0x00000540,
	eT_64PREAL32 =            0x00000640,

	eT_REAL48 =               0x00000044,
	eT_PREAL48 =              0x00000144,
	eT_PFREAL48 =             0x00000244,
	eT_PHREAL48 =             0x00000344,
	eT_32PREAL48 =            0x00000444,
	eT_32PFREAL48 =           0x00000544,
	eT_64PREAL48 =            0x00000644,

	eT_REAL64 =               0x00000041,
	eT_PREAL64 =              0x00000141,
	eT_PFREAL64 =             0x00000241,
	eT_PHREAL64 =             0x00000341,
	eT_32PREAL64 =            0x00000441,
	eT_32PFREAL64 =           0x00000541,
	eT_64PREAL64 =            0x00000641,

	eT_REAL80 =               0x00000042,
	eT_PREAL80 =              0x00000142,
	eT_PFREAL80 =             0x00000242,
	eT_PHREAL80 =             0x00000342,
	eT_32PREAL80 =            0x00000442,
	eT_32PFREAL80 =           0x00000542,
	eT_64PREAL80 =            0x00000642,

	eT_REAL128 =              0x00000043,
	eT_PREAL128 =             0x00000143,
	eT_PFREAL128 =            0x00000243,
	eT_PHREAL128 =            0x00000343,
	eT_32PREAL128 =           0x00000443,
	eT_32PFREAL128 =          0x00000543,
	eT_64PREAL128 =           0x00000643,

	eT_CPLX32 =               0x00000050,
	eT_PCPLX32 =              0x00000150,
	eT_PFCPLX32 =             0x00000250,
	eT_PHCPLX32 =             0x00000350,
	eT_32PCPLX32 =            0x00000450,
	eT_32PFCPLX32 =           0x00000550,
	eT_64PCPLX32 =            0x00000650,

	eT_CPLX64 =               0x00000051,
	eT_PCPLX64 =              0x00000151,
	eT_PFCPLX64 =             0x00000251,
	eT_PHCPLX64 =             0x00000351,
	eT_32PCPLX64 =            0x00000451,
	eT_32PFCPLX64 =           0x00000551,
	eT_64PCPLX64 =            0x00000651,

	eT_CPLX80 =               0x00000052,
	eT_PCPLX80 =              0x00000152,
	eT_PFCPLX80 =             0x00000252,
	eT_PHCPLX80 =             0x00000352,
	eT_32PCPLX80 =            0x00000452,
	eT_32PFCPLX80 =           0x00000552,
	eT_64PCPLX80 =            0x00000652,

	eT_CPLX128 =              0x00000053,
	eT_PCPLX128 =             0x00000153,
	eT_PFCPLX128 =            0x00000253,
	eT_PHCPLX128 =            0x00000353,
	eT_32PCPLX128 =           0x00000453,
	eT_32PFCPLX128 =          0x00000553,
	eT_64PCPLX128 =           0x00000653,

	eT_BOOL08 =               0x00000030,
	eT_PBOOL08 =              0x00000130,
	eT_PFBOOL08 =             0x00000230,
	eT_PHBOOL08 =             0x00000330,
	eT_32PBOOL08 =            0x00000430,
	eT_32PFBOOL08 =           0x00000530,
	eT_64PBOOL08 =            0x00000630,

	eT_BOOL16 =               0x00000031,
	eT_PBOOL16 =              0x00000131,
	eT_PFBOOL16 =             0x00000231,
	eT_PHBOOL16 =             0x00000331,
	eT_32PBOOL16 =            0x00000431,
	eT_32PFBOOL16 =           0x00000531,
	eT_64PBOOL16 =            0x00000631,

	eT_BOOL32 =               0x00000032,
	eT_PBOOL32 =              0x00000132,
	eT_PFBOOL32 =             0x00000232,
	eT_PHBOOL32 =             0x00000332,
	eT_32PBOOL32 =            0x00000432,
	eT_32PFBOOL32 =           0x00000532,
	eT_64PBOOL32 =            0x00000632,

	eT_BOOL64 =               0x00000033,
	eT_PBOOL64 =              0x00000133,
	eT_PFBOOL64 =             0x00000233,
	eT_PHBOOL64 =             0x00000333,
	eT_32PBOOL64 =            0x00000433,
	eT_32PFBOOL64 =           0x00000533,
	eT_64PBOOL64 =            0x00000633,

	eT_NCVPTR =               0x000001F0,
	eT_FCVPTR =               0x000002F0,
	eT_HCVPTR =               0x000003F0,
	eT_32NCVPTR =             0x000004F0,
	eT_32FCVPTR =             0x000005F0,
	eT_64NCVPTR =             0x000006F0,
} EBASE_TYPES;

typedef enum {
	eNEAR_C          = 0x00000000,
	eFAR_C           = 0x00000001,
	eNEAR_PASCAL     = 0x00000002,
	eFAR_PASCAL      = 0x00000003,
	eNEAR_FAST       = 0x00000004,
	eFAR_FAST        = 0x00000005,
	eSKIPPED         = 0x00000006,
	eNEAR_STD        = 0x00000007,
	eFAR_STD         = 0x00000008,
	eNEAR_SYS        = 0x00000009,
	eFAR_SYS         = 0x0000000A,
	eTHISCALL        = 0x0000000B,
	eMIPSCALL        = 0x0000000C,
	eGENERIC         = 0x0000000D,
	eALPHACALL       = 0x0000000E,
	ePPCCALL         = 0x0000000F,
	eSHCALL          = 0x00000010,
	eARMCALL         = 0x00000011,
	eAM33CALL        = 0x00000012,
	eTRICALL         = 0x00000013,
	eSH5CALL         = 0x00000014,
	eM32RCALL        = 0x00000015,
	eRESERVED        = 0x00000016,
	eMAX_CV_CALL
} ECV_CALL;

typedef union {
	struct {
		unsigned char scoped : 1;
		unsigned char reserved : 7; // swapped
		unsigned char packed : 1;
		unsigned char ctor : 1;
		unsigned char ovlops : 1;
		unsigned char isnested : 1;
		unsigned char cnested : 1;
		unsigned char opassign : 1;
		unsigned char opcast : 1;
		unsigned char fwdref : 1;
	} bits;
	unsigned short cv_property;
} UCV_PROPERTY;

enum {
	eMTvanilla   = 0x00,
	eMTvirtual   = 0x01,
	eMTstatic    = 0x02,
	eMTfriend    = 0x03,
	eMTintro     = 0x04,
	eMTpurevirt  = 0x05,
	eMTpureintro = 0x06,
	eMT_MAX
} EMPROP;

enum {
	ePrivate    = 1,
	eProtected  = 2,
	ePublic     = 3,
	eAccessMax
} EACCESS;

//### CodeView bitfields and enums
//# NOTE: Construct assumes big-endian
//# ordering for BitStructs
typedef union {
	struct {
		unsigned char access : 2;
		unsigned char mprop : 3;
		unsigned char pseudo : 1;
		unsigned char noinherit : 1;
		unsigned char noconstruct : 1;
		unsigned char padding : 7;
		unsigned char compgenx : 1;
	} bits;
	unsigned short fldattr;
} UCV_fldattr;

typedef struct {
	unsigned int return_type;
	ECV_CALL call_conv;
	unsigned char reserved;
	unsigned short parm_count;
	unsigned int arg_list;
	unsigned char pad;
} SLF_PROCEDURE;

typedef struct {
	unsigned int return_type;
	unsigned int class_type;
	unsigned int this_type;
	ECV_CALL call_conv; // 1 byte
	unsigned char reserved;
	unsigned short parm_count;
	unsigned int arglist;
	int this_adjust;
	unsigned char pad;
} SLF_MFUNCTION;

typedef struct {
	unsigned int count;
	unsigned int *arg_type;
	unsigned char pad;
} SLF_ARGLIST;

typedef struct {
	unsigned int modified_type;
	union {
		struct {
			unsigned char pad2 : 8;
			unsigned char const_ : 1;
			unsigned char volatile_ : 1;
			unsigned char unaligned : 1;
			unsigned char pad1 : 5;
		} bits;
		unsigned short modifier;
	} umodifier;
	unsigned char pad;
} SLF_MODIFIER;

typedef enum {
	ePTR_MODE_PTR         = 0x00000000,
	ePTR_MODE_REF         = 0x00000001,
	ePTR_MODE_PMEM        = 0x00000002,
	ePTR_MODE_PMFUNC      = 0x00000003,
	ePTR_MODE_RESERVED    = 0x00000004,
	eModeMax
} EMode;

typedef enum {
	ePTR_NEAR             = 0x00000000,
	ePTR_FAR              = 0x00000001,
	ePTR_HUGE             = 0x00000002,
	ePTR_BASE_SEG         = 0x00000003,
	ePTR_BASE_VAL         = 0x00000004,
	ePTR_BASE_SEGVAL      = 0x00000005,
	ePTR_BASE_ADDR        = 0x00000006,
	ePTR_BASE_SEGADDR     = 0x00000007,
	ePTR_BASE_TYPE        = 0x00000008,
	ePTR_BASE_SELF        = 0x00000009,
	ePTR_NEAR32           = 0x0000000A,
	ePTR_FAR32            = 0x0000000B,
	ePTR_64               = 0x0000000C,
	ePTR_UNUSEDPTR        = 0x0000000D,
	eTypeMax
} EType;

typedef union {
	struct {
		unsigned char pad[2];
		unsigned char flat32 : 1;
		unsigned char volatile_ : 1;
		unsigned char const_ : 1;
		unsigned char unaligned : 1;
		unsigned char restrict_ : 1;
		unsigned char pad1 : 3;
		unsigned char type : 5;
		unsigned char mode : 3;
	} bits;
	unsigned int ptr_attr;
} UPTR_ATTR;

typedef struct {
	unsigned int utype;
	UPTR_ATTR ptr_attr;
	unsigned char pad;
} SLF_POINTER;

typedef struct {
	int stream_size;
	int num_pages;
	char *stream_pages;
} SPage;

typedef struct {
//	FILE *fp;
	RBuffer *buf;
	int *pages;
	int pages_amount;
	int indx;
	int page_size;
	int size;
	R_STREAM_FILE stream_file;
	// int fast_load;
	// ... parent;

	free_func free_;
} R_PDB_STREAM;

typedef struct R_PDB7_ROOT_STREAM{
	R_PDB_STREAM pdb_stream;
	int num_streams;
	RList *streams_list;
} R_PDB7_ROOT_STREAM;

typedef enum EStream_{
	ePDB_STREAM_ROOT = 0, // PDB_ROOT_DIRECTORY
	ePDB_STREAM_PDB, // PDB STREAM INFO
	ePDB_STREAM_TPI, // TYPE INFO
	ePDB_STREAM_DBI, // DEBUG INFO

	ePDB_STREAM_GSYM,
	ePDB_STREAM_SECT_HDR,
	ePDB_STREAM_SECT__HDR_ORIG,
	ePDB_STREAM_OMAP_TO_SRC,
	ePDB_STREAM_OMAP_FROM_SRC,
	ePDB_STREAM_FPO,
	ePDB_STREAM_FPO_NEW,
	ePDB_STREAM_XDATA,
	ePDB_STREAM_PDATA,
	ePDB_STREAM_TOKEN_RID_MAP,
	ePDB_STREAM_MAX
} EStream;

typedef void (*f_load)(void *parsed_pdb_stream, R_STREAM_FILE *stream);

typedef struct {
	R_PDB_STREAM *pdb_stream;
	f_load load;
} SParsedPDBStream;

typedef struct {
	unsigned int size;
	char *name;
} SCString;

typedef struct {
	SCString name;
} SNoVal;

typedef struct {
	char value;
	SCString name;
} SVal_LF_CHAR;

typedef struct {
	short value;
	SCString name;
} SVal_LF_SHORT;

typedef struct {
	unsigned short value;
	SCString name;
} SVal_LF_USHORT;

typedef struct {
	long value;
	SCString name;
} SVal_LF_LONG;

typedef struct {
	unsigned long value;
	SCString name;
} SVal_LF_ULONG;

typedef struct {
	unsigned short value_or_type;
	void *name_or_val;
} SVal;

typedef struct {
	unsigned int element_type;
	unsigned int index_type;
	SVal size;
	unsigned char pad;
} SLF_ARRAY;

typedef struct {
	unsigned short count;
	UCV_PROPERTY prop;
	unsigned int field_list;
	unsigned int derived;
	unsigned int vshape;
	SVal size;
	unsigned char pad;
} SLF_STRUCTURE, SLF_CLASS;

typedef struct {
	unsigned short count;
	UCV_PROPERTY prop;
	unsigned int field_list;
	SVal size;
	unsigned pad;
} SLF_UNION;

typedef struct {
	unsigned int base_type;
	unsigned char length;
	unsigned char position;
	unsigned char pad;
} SLF_BITFIELD;

typedef struct {
	unsigned short count;
	char *vt_descriptors;
	unsigned char pad;
} SLF_VTSHAPE;

typedef struct {
	unsigned short count;
	UCV_PROPERTY prop;
	unsigned int utype;
	unsigned int field_list;
	SCString name;
	unsigned char pad;
} SLF_ENUM;

typedef struct {
	UCV_fldattr fldattr;
	SVal enum_value;
	unsigned char pad;

	free_func free_;
} SLF_ENUMERATE;

typedef struct {
	unsigned short pad;
	unsigned int index;
	SCString name;

	free_func free_;
} SLF_NESTTYPE;

typedef struct {
	unsigned short count;
	unsigned int mlist;
	SCString name;
	unsigned char pad;

	free_func free_;
} SLF_METHOD;

typedef struct {
	UCV_fldattr fldattr;
	unsigned int inedex;
	SVal offset;
	unsigned char pad;

	// TODO: remove free_
	free_func free_;
} SLF_MEMBER;

typedef struct {
	unsigned int val;
	SCString str_data;
} SLF_ONEMETHOD_VAL;

typedef struct {
	UCV_fldattr fldattr;
	unsigned int index;
	SLF_ONEMETHOD_VAL val;
	unsigned char pad;
} SLF_ONEMETHOD;

typedef struct {
//	ELeafType leaf_type;
	RList *substructs;
} SLF_FIELDLIST;

typedef struct {
	int off;
	int cb;
} SOffCb;

typedef struct {
	short sn;
	short padding;
	int hash_key;
	int buckets;
	SOffCb hash_vals;
	SOffCb ti_off;
	SOffCb hash_adj;
} STPI;

typedef struct {
	unsigned int version;
	int hdr_size;
	unsigned int ti_min;
	unsigned int ti_max;
	unsigned int follow_size;
	STPI tpi;
} STPIHeader;

typedef enum {
	eLF_MODIFIER_16t         = 0x00000001,
	eLF_POINTER_16t          = 0x00000002,
	eLF_ARRAY_16t            = 0x00000003,
	eLF_CLASS_16t            = 0x00000004,
	eLF_STRUCTURE_16t        = 0x00000005,
	eLF_UNION_16t            = 0x00000006,
	eLF_ENUM_16t             = 0x00000007,
	eLF_PROCEDURE_16t        = 0x00000008,
	eLF_MFUNCTION_16t        = 0x00000009,
	eLF_VTSHAPE              = 0x0000000A,
	eLF_COBOL0_16t           = 0x0000000B,
	eLF_COBOL1               = 0x0000000C,
	eLF_BARRAY_16t           = 0x0000000D,
	eLF_LABEL                = 0x0000000E,
	eLF_NULL                 = 0x0000000F,
	eLF_NOTTRAN              = 0x00000010,
	eLF_DIMARRAY_16t         = 0x00000011,
	eLF_VFTPATH_16t          = 0x00000012,
	eLF_PRECOMP_16t          = 0x00000013,
	eLF_ENDPRECOMP           = 0x00000014,
	eLF_OEM_16t              = 0x00000015,
	eLF_TYPESERVER_ST        = 0x00000016,
	eLF_SKIP_16t             = 0x00000200,
	eLF_ARGLIST_16t          = 0x00000201,
	eLF_DEFARG_16t           = 0x00000202,
	eLF_LIST                 = 0x00000203,
	eLF_FIELDLIST_16t        = 0x00000204,
	eLF_DERIVED_16t          = 0x00000205,
	eLF_BITFIELD_16t         = 0x00000206,
	eLF_METHODLIST_16t       = 0x00000207,
	eLF_DIMCONU_16t          = 0x00000208,
	eLF_DIMCONLU_16t         = 0x00000209,
	eLF_DIMVARU_16t          = 0x0000020A,
	eLF_DIMVARLU_16t         = 0x0000020B,
	eLF_REFSYM               = 0x0000020C,
	eLF_BCLASS_16t           = 0x00000400,
	eLF_VBCLASS_16t          = 0x00000401,
	eLF_IVBCLASS_16t         = 0x00000402,
	eLF_ENUMERATE_ST         = 0x00000403,
	eLF_FRIENDFCN_16t        = 0x00000404,
	eLF_INDEX_16t            = 0x00000405,
	eLF_MEMBER_16t           = 0x00000406,
	eLF_STMEMBER_16t         = 0x00000407,
	eLF_METHOD_16t           = 0x00000408,
	eLF_NESTTYPE_16t         = 0x00000409,
	eLF_VFUNCTAB_16t         = 0x0000040A,
	eLF_FRIENDCLS_16t        = 0x0000040B,
	eLF_ONEMETHOD_16t        = 0x0000040C,
	eLF_VFUNCOFF_16t         = 0x0000040D,
	eLF_TI16_MAX             = 0x00001000,
	eLF_MODIFIER             = 0x00001001,
	eLF_POINTER              = 0x00001002,
	eLF_ARRAY_ST             = 0x00001003,
	eLF_CLASS_ST             = 0x00001004,
	eLF_STRUCTURE_ST         = 0x00001005,
	eLF_UNION_ST             = 0x00001006,
	eLF_ENUM_ST              = 0x00001007,
	eLF_PROCEDURE            = 0x00001008,
	eLF_MFUNCTION            = 0x00001009,
	eLF_COBOL0               = 0x0000100A,
	eLF_BARRAY               = 0x0000100B,
	eLF_DIMARRAY_ST          = 0x0000100C,
	eLF_VFTPATH              = 0x0000100D,
	eLF_PRECOMP_ST           = 0x0000100E,
	eLF_OEM                  = 0x0000100F,
	eLF_ALIAS_ST             = 0x00001010,
	eLF_OEM2                 = 0x00001011,
	eLF_SKIP                 = 0x00001200,
	eLF_ARGLIST              = 0x00001201,
	eLF_DEFARG_ST            = 0x00001202,
	eLF_FIELDLIST            = 0x00001203,
	eLF_DERIVED              = 0x00001204,
	eLF_BITFIELD             = 0x00001205,
	eLF_METHODLIST           = 0x00001206,
	eLF_DIMCONU              = 0x00001207,
	eLF_DIMCONLU             = 0x00001208,
	eLF_DIMVARU              = 0x00001209,
	eLF_DIMVARLU             = 0x0000120A,
	eLF_BCLASS               = 0x00001400,
	eLF_VBCLASS              = 0x00001401,
	eLF_IVBCLASS             = 0x00001402,
	eLF_FRIENDFCN_ST         = 0x00001403,
	eLF_INDEX                = 0x00001404,
	eLF_MEMBER_ST            = 0x00001405,
	eLF_STMEMBER_ST          = 0x00001406,
	eLF_METHOD_ST            = 0x00001407,
	eLF_NESTTYPE_ST          = 0x00001408,
	eLF_VFUNCTAB             = 0x00001409,
	eLF_FRIENDCLS            = 0x0000140A,
	eLF_ONEMETHOD_ST         = 0x0000140B,
	eLF_VFUNCOFF             = 0x0000140C,
	eLF_NESTTYPEEX_ST        = 0x0000140D,
	eLF_MEMBERMODIFY_ST      = 0x0000140E,
	eLF_MANAGED_ST           = 0x0000140F,
	eLF_ST_MAX               = 0x00001500,
	eLF_TYPESERVER           = 0x00001501,
	eLF_ENUMERATE            = 0x00001502,
	eLF_ARRAY                = 0x00001503,
	eLF_CLASS                = 0x00001504,
	eLF_STRUCTURE            = 0x00001505,
	eLF_UNION                = 0x00001506,
	eLF_ENUM                 = 0x00001507,
	eLF_DIMARRAY             = 0x00001508,
	eLF_PRECOMP              = 0x00001509,
	eLF_ALIAS                = 0x0000150A,
	eLF_DEFARG               = 0x0000150B,
	eLF_FRIENDFCN            = 0x0000150C,
	eLF_MEMBER               = 0x0000150D,
	eLF_STMEMBER             = 0x0000150E,
	eLF_METHOD               = 0x0000150F,
	eLF_NESTTYPE             = 0x00001510,
	eLF_ONEMETHOD            = 0x00001511,
	eLF_NESTTYPEEX           = 0x00001512,
	eLF_MEMBERMODIFY         = 0x00001513,
	eLF_MANAGED              = 0x00001514,
	eLF_TYPESERVER2          = 0x00001515,
	eLF_CHAR                 = 0x00008000,
	eLF_SHORT                = 0x00008001,
	eLF_USHORT               = 0x00008002,
	eLF_LONG                 = 0x00008003,
	eLF_ULONG                = 0x00008004,
	eLF_REAL32               = 0x00008005,
	eLF_REAL64               = 0x00008006,
	eLF_REAL80               = 0x00008007,
	eLF_REAL128              = 0x00008008,
	eLF_QUADWORD             = 0x00008009,
	eLF_UQUADWORD            = 0x0000800A,
	eLF_REAL48               = 0x0000800B,
	eLF_COMPLEX32            = 0x0000800C,
	eLF_COMPLEX64            = 0x0000800D,
	eLF_COMPLEX80            = 0x0000800E,
	eLF_COMPLEX128           = 0x0000800F,
	eLF_VARSTRING            = 0x00008010,
	eLF_OCTWORD              = 0x00008017,
	eLF_UOCTWORD             = 0x00008018,
	eLF_DECIMAL              = 0x00008019,
	eLF_DATE                 = 0x0000801A,
	eLF_UTF8STRING           = 0x0000801B,
	eLF_PAD0                 = 0x000000F0,
	eLF_PAD1                 = 0x000000F1,
	eLF_PAD2                 = 0x000000F2,
	eLF_PAD3                 = 0x000000F3,
	eLF_PAD4                 = 0x000000F4,
	eLF_PAD5                 = 0x000000F5,
	eLF_PAD6                 = 0x000000F6,
	eLF_PAD7                 = 0x000000F7,
	eLF_PAD8                 = 0x000000F8,
	eLF_PAD9                 = 0x000000F9,
	eLF_PAD10                = 0x000000FA,
	eLF_PAD11                = 0x000000FB,
	eLF_PAD12                = 0x000000FC,
	eLF_PAD13                = 0x000000FD,
	eLF_PAD14                = 0x000000FE,
	eLF_PAD15                = 0x000000FF,
	eLF_MAX                  = 0xFFFFFFFF
} ELeafType;

typedef struct {
	ELeafType leaf_type;
	void *type_info;

	free_func free_;
	get_value_name get_name;
	get_value get_val;
	get_value_name_len get_name_len;
	get_member_list get_members;
	get_arg_type_ get_arg_type;
	get_element_type_ get_element_type;
	get_index_type_ get_index_type;
	get_base_type_ get_base_type;
	get_derived_ get_derived;
	get_vshape_ get_vshape;
	get_utype_ get_utype;
	get_return_type_ get_return_type;
	get_class_type_ get_class_type;
	get_this_type_ get_this_type;
	get_arglist_ get_arglist;
	get_index_ get_index;
	get_mlist_ get_mlist;
	get_modified_type_ get_modified_type;
	get_value is_fwdref;
	get_print_type_ get_print_type;

} STypeInfo;

typedef struct {
	unsigned short length;
	unsigned int tpi_idx;
	STypeInfo type_data;

//	free_func free_;
} SType;

typedef struct {
	STPIHeader header;
	RList *types;

	free_func free_;
} STpiStream;

typedef struct {
	unsigned int data1;
	unsigned short data2;
	unsigned short data3;
	char data4[8];
} SGUID;

typedef struct {
	unsigned int version;
	unsigned int time_date_stamp;
	unsigned int age;
	SGUID guid;
	unsigned int cb_names;
	char *names;

	free_func free_;
} SPDBInfoStream/*D*/;

// dbi stream structures start here

typedef enum {
	eIMAGE_FILE_MACHINE_UNKNOWN = 0x0,
	eIMAGE_FILE_MACHINE_I386 = 0x014c,
	eIMAGE_FILE_MACHINE_IA64 = 0x0200,
	eIMAGE_FILE_MACHINE_AMD64 = 0x8664,
	eMaxMachine
} EMachine;

#pragma pack(push, 1)
typedef struct {
	short section;
	short padding1;
	int offset;
	int size;
	unsigned int flags;
	int module;
	short padding2;
	unsigned int data_crc;
	unsigned int reloc_crc;
} SSymbolRange;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	unsigned int opened;
	SSymbolRange range;
	unsigned short flags;
	short stream;
	unsigned int symSize;
	unsigned int oldLineSize;
	unsigned int lineSize;
	short nSrcFiles;
	short padding1;
	unsigned int offsets;
	unsigned int niSource;
	unsigned int niCompiler;
	SCString modName;
	SCString objName;
} SDBIExHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	short sn_fpo;
	short sn_exception;
	short sn_fixup;
	short sn_omap_to_src;
	short sn_omap_from_src;
	short sn_section_hdr;
	short sn_token_rid_map;
	short sn_xdata;
	short sn_pdata;
	short sn_new_fpo;
	short sn_section_hdr_orig;
} SDbiDbgHeader;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	unsigned int magic;
	unsigned int version;
	unsigned int age;
	short gssymStream;
	unsigned short vers;
	short pssymStream;
	unsigned short pdbver;
	short symrecStream;
	unsigned short pdbver2;
	unsigned int module_size;
	unsigned int seccon_size;
	unsigned int secmap_size;
	unsigned int filinf_size;
	unsigned int tsmap_size;
	unsigned int mfc_index;
	unsigned int dbghdr_size;
	unsigned int ecinfo_size;
	unsigned short flags;
	EMachine machine; // read just 2 bytes
	unsigned int resvd;
} SDBIHeader;
#pragma pack(pop)

typedef struct {
	SDBIHeader dbi_header;
	SDbiDbgHeader dbg_header;
	RList *dbiexhdrs;

	free_func free_;
} SDbiStream;
// end of dbi stream structures

// start of FPO stream structures
typedef union {
	struct {
		unsigned char cbRegs : 3;
		unsigned char fHashSEH : 1;
		unsigned char fUseBp : 1;
		unsigned char reserved : 1;
		unsigned char cbFrame : 2;
		unsigned char cbProlog : 8;
	} bits;
	unsigned short bit_values;
} UBit_values;

typedef struct {
	unsigned int ul_off_start;
	unsigned int cb_proc_size;
	unsigned int cdw_locals;
	unsigned short cdw_params;
	UBit_values bit_values;
} SFPO_DATA;

typedef struct {
	RList *fpo_data_list;
} SFPOStream;

typedef enum {
	eSEH = 1,
	eCPPEH = 2,
	eFnStart = 4,
	eFPO_DATA_FLAGS_MAX
} EFPO_DATA_FLAGS;

typedef struct {
	unsigned int ul_off_start;
	unsigned int cb_proc_size;
	unsigned int cdw_locals;
	unsigned int cdw_params;
	unsigned int max_stack;
	unsigned int programm_string_offset;
	unsigned short cb_prolog;
	unsigned short cb_save_regs;
	EFPO_DATA_FLAGS flags;
} SFPO_DATA_V2;

typedef struct {
	RList *fpo_data_list;
} SFPONewStream;
// end of FPO stream structures

// GDATA structrens
typedef struct {
	RList *globals_list;
} SGDATAStream;

typedef struct {
	unsigned short leaf_type;
	unsigned int symtype;
	unsigned int offset;
	unsigned short segment;
	SCString name;
} SGlobal;
// end GDATA structures

// PE stream structures
typedef union {
	unsigned int physical_address;
	unsigned int virtual_address;
} UMISC;

typedef struct {
	char name[8];
	UMISC misc;
	unsigned int virtual_address;
	unsigned int size_of_raw_data;
	unsigned int pointer_to_raw_data;
	unsigned int pointer_to_relocations;
	unsigned int pointer_to_line_numbers;
	unsigned short number_of_relocations;
	unsigned short number_of_line_numbers;
	unsigned int charactestics;
} SIMAGE_SECTION_HEADER;

typedef struct {
	RList *sections_hdrs;
} SPEStream;
// end PE stream structures

// omap structures
typedef struct {
	unsigned int from;
	unsigned int to;
} SOmapEntry;

typedef struct {
	RList *omap_entries;
	unsigned int *froms;
} SOmapStream;
// end of omap structures

#endif // TYPES_H
