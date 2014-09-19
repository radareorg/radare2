#include <r_pdb.h>
//#include <tpi.c>
#include <string.h>

#define PDB2_SIGNATURE "Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"
#define PDB7_SIGNATURE_LEN 32
#define PDB2_SIGNATURE_LEN 51

static unsigned int base_idx = 0;
static RList *p_types_list;

typedef void (*free_func)(void *);
typedef void (*get_value_name)(void *type, char **res_name);
typedef void (*get_value)(void *type, int *res);
typedef void (*get_value_name_len)(void *type, int *res);
typedef void (*get_member_list)(void *type, RList *l);
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

//CV_property = BitStruct("prop",
//    Flag("fwdref"),
//    Flag("opcast"),
//    Flag("opassign"),
//    Flag("cnested"),
//    Flag("isnested"),
//    Flag("ovlops"),
//    Flag("ctor"),
//    Flag("packed"),

//    BitField("reserved", 7, swapped=True),
//    Flag("scoped"),
//)
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

//lfProcedure = Struct("lfProcedure",
//    ULInt32("return_type"),
//    CV_call,
//    ULInt8("reserved"),
//    ULInt16("parm_count"),
//    ULInt32("arglist"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned int return_type;
	ECV_CALL call_conv;
	unsigned char reserved;
	unsigned short parm_count;
	unsigned int arg_list;
	unsigned char pad;
} SLF_PROCEDURE;

//lfMFunc = Struct("lfMFunc",
//    ULInt32("return_type"),
//    ULInt32("class_type"),
//    ULInt32("this_type"),
//    CV_call,
//    ULInt8("reserved"),
//    ULInt16("parm_count"),
//    ULInt32("arglist"),
//    SLInt32("thisadjust"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
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

//lfArgList = Struct("lfArgList",
//    ULInt32("count"),
//    Array(lambda ctx: ctx.count, ULInt32("arg_type")),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned int count;
	unsigned int *arg_type;
	unsigned char pad;
} SLF_ARGLIST;

//lfModifier = Struct("lfModifier",
//    ULInt32("modified_type"),
//    BitStruct("modifier",
//        Padding(5),
//        Flag("unaligned"),
//        Flag("volatile"),
//        Flag("const"),
//        Padding(8),
//    ),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
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

//lfPointer = Struct("lfPointer",
//    ULInt32("utype"),
//    BitStruct("ptr_attr",
//        Enum(BitField("mode", 3),
//            PTR_MODE_PTR         = 0x00000000,
//            PTR_MODE_REF         = 0x00000001,
//            PTR_MODE_PMEM        = 0x00000002,
//            PTR_MODE_PMFUNC      = 0x00000003,
//            PTR_MODE_RESERVED    = 0x00000004,
//        ),
//        Enum(BitField("type", 5),
//            PTR_NEAR             = 0x00000000,
//            PTR_FAR              = 0x00000001,
//            PTR_HUGE             = 0x00000002,
//            PTR_BASE_SEG         = 0x00000003,
//            PTR_BASE_VAL         = 0x00000004,
//            PTR_BASE_SEGVAL      = 0x00000005,
//            PTR_BASE_ADDR        = 0x00000006,
//            PTR_BASE_SEGADDR     = 0x00000007,
//            PTR_BASE_TYPE        = 0x00000008,
//            PTR_BASE_SELF        = 0x00000009,
//            PTR_NEAR32           = 0x0000000A,
//            PTR_FAR32            = 0x0000000B,
//            PTR_64               = 0x0000000C,
//            PTR_UNUSEDPTR        = 0x0000000D,
//        ),
//        Padding(3),
//        Flag("restrict"),
//        Flag("unaligned"),
//        Flag("const"),
//        Flag("volatile"),
//        Flag("flat32"),
//        Padding(16),
//    ),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned int utype;
	UPTR_ATTR ptr_attr;
	unsigned char pad;
} SLF_POINTER;

typedef struct {
	int stream_size;
	char *stream_pages;
} SPage;

typedef struct {
	FILE *fp;
	int *pages;
	int page_size;
	int pages_amount;
	int end;
	int pos;
} R_STREAM_FILE;

typedef struct {
	FILE *fp;
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

typedef struct {
	R_PDB_STREAM pdb_stream;
	int num_streams;
	RList *streams_list;
} R_PDB7_ROOT_STREAM;

typedef enum EStream_{
	ePDB_STREAM_ROOT = 0, // PDB_ROOT_DIRECTORY
	ePDB_STREAM_PDB, // PDB STREAM INFO
	ePDB_STREAM_TPI, // TYPE INFO
	ePDB_STREAM_DBI, // DEBUG INFO
	ePDB_STREAM_MAX
} EStream;

typedef void (*f_load)(void *parsed_pdb_stream, R_STREAM_FILE *stream);

typedef struct {
	R_PDB_STREAM *pdb_stream;
	f_load load;
} SParsedPDBStream;

//### Header structures
//def OffCb(name):
//    return Struct(name,
//        SLInt32("off"),
//        SLInt32("cb"),
//    )

//TPI = Struct("TPIHash",
//    ULInt16("sn"),
//    Padding(2),
//    SLInt32("HashKey"),
//    SLInt32("Buckets"),
//    OffCb("HashVals"),
//    OffCb("TiOff"),
//    OffCb("HashAdj"),
//)

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

//lfArray = Struct("lfArray",
//    ULInt32("element_type"),
//    ULInt32("index_type"),
//    val("size"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned int element_type;
	unsigned int index_type;
	SVal size;
	unsigned char pad;
} SLF_ARRAY;

//lfStructure = Struct("lfStructure",
//    ULInt16("count"),
//    CV_property,
//    ULInt32("fieldlist"),
//    ULInt32("derived"),
//    ULInt32("vshape"),
//    val("size"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned short count;
	// TODO: fix displaying of UCV_PROPERTY
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

//lfBitfield = Struct("lfBitfield",
//    ULInt32("base_type"),
//    ULInt8("length"),
//    ULInt8("position"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned int base_type;
	unsigned char length;
	unsigned char position;
	unsigned char pad;
} SLF_BITFIELD;

//lfVTShape = Struct("lfVTShape",
//    ULInt16("count"),
//    BitStruct("vt_descriptors",
//        Array(lambda ctx: ctx._.count,
//            BitField("vt_descriptors", 4)
//        ),
//        # Needed to align to a byte boundary
//        Padding(lambda ctx: (ctx._.count % 2) * 4),
//    ),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//)
typedef struct {
	unsigned short count;
	char *vt_descriptors;
	unsigned char pad;
} SLF_VTSHAPE;

//	lfEnum = Struct("lfEnum",
//ULInt16("count"),
//CV_property,
//ULInt32("utype"),
//ULInt32("fieldlist"),
//CString("name"),
//Peek(ULInt8("_pad")),
//PadAlign,
//)
typedef struct {
	unsigned short count;
	UCV_PROPERTY prop;
	unsigned int utype;
	unsigned int field_list;
	SCString name;
	unsigned char pad;
} SLF_ENUM;

//"LF_ENUMERATE": Struct("lfEnumerate",
//    CV_fldattr,
//    val("enum_value"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//),
typedef struct {
	UCV_fldattr fldattr;
	SVal enum_value;
	unsigned char pad;

	free_func free_;
} SLF_ENUMERATE;

//	"LF_NESTTYPE": Struct("lfNestType",
//        Padding(2),
//        ULInt32("index"),
//        CString("name"),
//    ),
typedef struct {
	unsigned short pad;
	unsigned int index;
	SCString name;

	free_func free_;
} SLF_NESTTYPE;

//"LF_METHOD": Struct("lfMethod",
//    ULInt16("count"),
//    ULInt32("mlist"),
//    CString("name"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//),
typedef struct {
	unsigned short count;
	unsigned int mlist;
	SCString name;
	unsigned char pad;

	free_func free_;
} SLF_METHOD;

//"LF_MEMBER": Struct("lfMember",
//    CV_fldattr,
//    ULInt32("index"),
//    val("offset"),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//),
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

//"LF_ONEMETHOD": Struct("lfOneMethod",
//    CV_fldattr,
//    ULInt32("index"),
//    Switch("intro", lambda ctx: ctx.fldattr.mprop,
//        {
//            "MTintro": Struct("value",
//                ULInt32("val"),
//                CString("str_data"),
//            ),
//            "MTpureintro": Struct("value",
//                ULInt32("val"),
//                CString("str_data"),
//            ),
//        },
//        default = CString("str_data"),
//    ),
//    Peek(ULInt8("_pad")),
//    PadAlign,
//),
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

//Type = Debugger(Struct("type",
//    leaf_type,
//    Switch("type_info", lambda ctx: ctx.leaf_type,
//        {
//            "eLF_ARGLIST": eLFArgList,
//            "eLF_ARRAY": eLFArray,
//            "eLF_ARRAY_ST": eLFArrayST,
//            "eLF_BITFIELD": eLFBitfield,
//            "eLF_CLASS": eLFClass,
//            "eLF_ENUM": eLFEnum,
//            "eLF_FIELDLIST": eLFFieldList,
//            "eLF_MFUNCTION": eLFMFunc,
//            "eLF_MODIFIER": eLFModifier,
//            "eLF_POINTER": eLFPointer,
//            "eLF_PROCEDURE": eLFProcedure,
//            "eLF_STRUCTURE": eLFStructure,
//            "eLF_STRUCTURE_ST": eLFStructureST,
//            "eLF_UNION": eLFUnion,
//            "eLF_UNION_ST": eLFUnionST,
//            "eLF_VTSHAPE": eLFVTShape,
//        },
//        default = Pass,
//    ),
//))

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

///////////////////////////////////////////////////////////////////////////////
static void print_base_type(EBASE_TYPES base_type, char **name)
{
	switch (base_type) {
	case eT_32PINT4:
		*name = "pointer to long";
		break;
	case eT_32PRCHAR:
		*name = "pointer to unsgined char";
		break;
	case eT_32PUCHAR:
		*name = "pointer to unsgined char";
		break;
	case eT_32PULONG:
		*name = "pointer to unsigned long";
		break;
	case eT_32PLONG:
		*name = "pointer to long";
		break;
	case eT_32PUQUAD:
		*name = "pointer to unsigned long long";
		break;
	case eT_32PUSHORT:
		*name = "pointer to unsigned short";
		break;
	case eT_32PVOID:
		*name = "pointer to void";
		break;
	case eT_64PVOID:
		*name = "pointer64 to void";
		break;
	case eT_INT4:
		*name = "long";
		break;
	case eT_INT8:
		*name = "long long";
		break;
	case eT_LONG:
		*name = "long";
		break;
	case eT_QUAD:
		*name = "long long";
		break;
	case eT_RCHAR:
		*name = "unsigned char";
		break;
	case eT_REAL32:
		*name = "float";
		break;
	case eT_REAL64:
		*name = "double";
		break;
	case eT_REAL80:
		*name = "long double";
		break;
	case eT_SHORT:
		*name = "short";
		break;
	case eT_UCHAR:
		*name = "unsigned char";
		break;
	case eT_UINT4:
		*name = "unsigned long";
		break;
	case eT_ULONG:
		*name = "unsigned long";
		break;
	case eT_UQUAD:
		*name = "unsigned long long";
		break;
	case eT_USHORT:
		*name = "unsigned short";
		break;
	case eT_WCHAR:
		*name = "wchar";
		break;
	case eT_VOID:
		*name = "void";
		break;
	default:
		*name = "unsupported base type";
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_name_len(SVal *val, int *res_len)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		*res_len = scstr->size;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			*res_len = lf_ulong->name.size;
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			*res_len = lf_ushort->name.size;
			break;
		}
		default:
			printf("get_sval_name::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_name(SVal *val, char **name)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		*name = scstr->name;
//		strcpy(name, scstr->name);
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			*name = lf_ulong->name.name;
//			strcpy(name, lf_ulong->name.name);
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			*name =lf_ushort->name.name;
//			strcpy(name, lf_ushort->name.name);
			break;
		}
		default:
			*name = 0;
			printf("get_sval_name::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_arglist_type(void *type, void *arglist_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *) t->type_info;
	RList *l = (RList *) arglist_type;
	int i = 0;
	int tmp = 0;

	for (i = 0; i < lf_arglist->count; i++) {
		tmp = lf_arglist->arg_type[i];
		if (tmp < base_idx) {
			// 0 - means NO_TYPE
			r_list_append(l, 0);
		} else {
			r_list_append(l, r_list_get_n(p_types_list, (tmp - base_idx)));
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void is_union_fwdref(void *type, int *is_fwdref)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf = (SLF_UNION *) t->type_info;

	*is_fwdref = lf->prop.bits.fwdref;
}

///////////////////////////////////////////////////////////////////////////////
static void is_struct_class_fwdref(void *type, int *is_fwdref)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;

	*is_fwdref = lf->prop.bits.fwdref;
}

///////////////////////////////////////////////////////////////////////////////
static int get_array_element_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;
	int curr_idx = lf_array->element_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_array_index_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;
	int curr_idx = lf_array->index_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_bitfield_base_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_BITFIELD *lf = (SLF_BITFIELD *) t->type_info;
	int curr_idx = lf->base_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_class_struct_derived(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;
	int curr_idx = lf->derived;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_class_struct_vshape(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;
	int curr_idx = lf->vshape;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_return_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->return_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_class_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->class_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_this_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->this_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_mfunction_arglist(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MFUNCTION *lf = (SLF_MFUNCTION *) t->type_info;
	int curr_idx = lf->arglist;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_modifier_modified_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MODIFIER *lf = (SLF_MODIFIER *) t->type_info;
	int curr_idx = lf->modified_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_pointer_utype(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_POINTER *lf = (SLF_POINTER *) t->type_info;
	int curr_idx = lf->utype;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_procedure_return_type(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_PROCEDURE *lf = (SLF_PROCEDURE *) t->type_info;
	int curr_idx = lf->return_type;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_procedure_arglist(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_PROCEDURE *lf = (SLF_PROCEDURE *) t->type_info;
	int curr_idx = lf->arg_list;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_member_index(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *) t->type_info;
	int curr_idx = lf->inedex;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_nesttype_index(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *) t->type_info;
	int curr_idx = lf->index;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_onemethod_index(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *) t->type_info;
	int curr_idx = lf->index;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_method_mlist(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_METHOD *lf = (SLF_METHOD *) t->type_info;
	int curr_idx = lf->mlist;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static int get_enum_utype(void *type, void **ret_type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf = (SLF_ENUM *) t->type_info;
	int curr_idx = lf->utype;

	if (curr_idx < base_idx) {
		*ret_type = 0;
		return curr_idx;
	}

	curr_idx -= base_idx;
	*ret_type = r_list_get_n(p_types_list, curr_idx);
}

///////////////////////////////////////////////////////////////////////////////
static void get_fieldlist_members(void *type, RList *l)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *) t->type_info;

	l = lf_fieldlist->substructs;
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_members(void *type, RList *l)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;
	unsigned int indx = 0;

	if (lf_union->field_list == 0) {
		l = indx;
	} else {
		SType *tmp = 0;
		indx = lf_union->field_list - base_idx;
		tmp = (SType *)r_list_get_n(p_types_list, indx);
		l = ((SLF_FIELDLIST *) tmp->type_data.type_info)->substructs;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_struct_class_members(void *type, RList **l)
{
	STypeInfo *tt = 0;
	RListIter *iter;
	RList *tmpl;
	SLF_FIELDLIST *lf_fieldlist = 0;
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;
	unsigned int indx = 0;

	if (lf->field_list == 0) {
		*l = 0;
		return;
	} else {
		SType *tmp = 0;
		indx = lf->field_list - base_idx;
		tmp = (SType *)r_list_get_n(p_types_list, indx);
		lf_fieldlist = (SLF_FIELDLIST *) tmp->type_data.type_info;
		*l = lf_fieldlist->substructs;
//		iter = r_list_iterator*l);
//		while (r_list_iter_next(iter)) {
//			tt = (STypeInfo *) r_list_iter_get(iter);
//		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_members(void *type, RList *l)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf = (SLF_ENUM *) t->type_info;
	unsigned int indx = 0;

	if (lf->field_list == 0) {
		l = indx;
	} else {
		SType *tmp = 0;
		indx = lf->field_list - base_idx;
		tmp = (SType *)r_list_get_n(p_types_list, indx);
		l = ((SLF_FIELDLIST *) tmp->type_data.type_info)->substructs;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_sval_val(SVal *val, int *res)
{
	if (val->value_or_type < eLF_CHAR) {
		*res = val->value_or_type;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			*res = lf_ulong->value;
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			*res = lf_ushort->value;
			break;
		}
		default:
			*res = 0;
			printf("get_sval_val::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_indx_val(void *type, int *indx_val)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf_member = (SLF_MEMBER *)t->type_info;

	*indx_val = lf_member->inedex;
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *)t->type_info;

	*res_len = lf_onemethod->val.str_data.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;

	*res_len = lf_enum->name.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;

	get_sval_name_len(&lf->size, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	get_sval_name_len(&lf_array->size, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	get_sval_name_len(&lf_union->size, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_name_len(void *type, int *res_len)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_name_len(&lf->enum_value, res_len);
}

///////////////////////////////////////////////////////////////////////////////
static void get_nesttype_name_len(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;

	*res = lf->name.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_name_len(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;

	*res = lf->name.size;
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_name_len(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_name_len(&lf->offset, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_name(&lf->offset, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *)t->type_info;

	*name = lf->val.str_data.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_METHOD *lf = (SLF_METHOD *)t->type_info;

	*name = lf->name.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_nesttype_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_NESTTYPE *lf = (SLF_NESTTYPE *)t->type_info;

	*name = lf->name.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_name(&lf->enum_value, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *)t->type_info;

	*name = lf_enum->name.name;
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *)t->type_info;

	get_sval_name(&lf->size, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	get_sval_name(&lf_array->size, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_name(void *type, char **name)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	get_sval_name(&lf_union->size, name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf = (SLF_ONEMETHOD *) t->type_info;

	*res = lf->val.val;
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_MEMBER *lf = (SLF_MEMBER *)t->type_info;

	get_sval_val(&lf->offset, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUMERATE *lf = (SLF_ENUMERATE *)t->type_info;

	get_sval_val(&lf->enum_value, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_STRUCTURE *lf = (SLF_STRUCTURE *) t->type_info;

	get_sval_val(&lf->size, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	get_sval_val(&lf_array->size, res);
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_val(void *type, int *res)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	get_sval_val(&lf_union->size, res);
}

///////////////////////////////////////////////////////////////////////////////
static void printf_sval_name(SVal *val)
{
	int len = 0;
	char *name = 0;

	get_sval_name_len(val, &len);
	name = (char *) malloc(len);
	get_sval_name(val, name);
	printf("%s", name);

	free(name);
}

//typedef struct {
//	SParsedPDBStream *parsed_pdb_stream;
//	SPDBInfoStreamD data;
//} SPDBInfoStream;

///////////////////////////////////////////////////////////////////////////////
static void free_sval(SVal *val)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		free(scstr->name);
		free(val->name_or_val);
		scstr->name = 0;
		val->name_or_val = 0;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			free(lf_ulong->name.name);
			free(val->name_or_val);
			lf_ulong->name.name = 0;
			val->name_or_val = 0;
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT *lf_ushort;
			lf_ushort = (SVal_LF_USHORT *) val->name_or_val;
			free(lf_ushort->name.name);
			free(val->name_or_val);
			lf_ushort->name.name = 0;
			val->name_or_val = 0;
			break;
		}
		default:
			printf("free_sval()::oops\n");
			break;
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////
static void free_lf_enumerate(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_ENUMERATE *lf_en = (SLF_ENUMERATE *) typeInfo->type_info;

	free_sval(&(lf_en->enum_value));
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_nesttype(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_NESTTYPE *lf_nest = (SLF_NESTTYPE *) typeInfo->type_info;

	free(lf_nest->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_method(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_METHOD *lf_meth = (SLF_METHOD *) typeInfo->type_info;

	free(lf_meth->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_member(void *type_info)
{
	STypeInfo *typeInfo = (STypeInfo *) type_info;
	SLF_MEMBER *lf_mem = (SLF_MEMBER *) typeInfo->type_info;

	free_sval(&lf_mem->offset);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_fieldlist(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_FIELDLIST *lf_fieldlist = (SLF_FIELDLIST *) t->type_info;
	RListIter *it;
	STypeInfo *type_info = 0;

	it = r_list_iterator(lf_fieldlist->substructs);
	while (r_list_iter_next(it)) {
		type_info = (STypeInfo *) r_list_iter_get(it);
		if (type_info->free_)
			type_info->free_(type_info);
		if (type_info->type_info) {
			free(type_info->type_info);
		}
		if (type_info)
			free(type_info);
	}
	r_list_free(lf_fieldlist->substructs);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_class(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_CLASS *lf_class = (SLF_CLASS *) t->type_info;

	free_sval(&lf_class->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_union(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_info;

	free_sval(&lf_union->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_onemethod(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ONEMETHOD *lf_onemethod = (SLF_ONEMETHOD *) t->type_info;

	free(lf_onemethod->val.str_data.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_enum(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *) t->type_info;

	free(lf_enum->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_array(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_info;

	free_sval(&lf_array->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_arglist(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *) t->type_info;

	free(lf_arglist->arg_type);
	lf_arglist->arg_type = 0;
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_vtshape(void *type)
{
	STypeInfo *t = (STypeInfo *) type;
	SLF_VTSHAPE *lf_vtshape = (SLF_VTSHAPE *) t->type_info;

	free(lf_vtshape->vt_descriptors);
	lf_vtshape->vt_descriptors = 0;
}

///////////////////////////////////////////////////////////////////////////////
static void free_tpi_stream(void *stream)
{
	STpiStream *tpi_stream = (STpiStream *)stream;
	RListIter *it;
	SType *type = 0;

	it = r_list_iterator(tpi_stream->types);
	while (r_list_iter_next(it)) {
		type = (SType *) r_list_iter_get(it);
		if (type) {
			if (type->type_data.free_) {
				type->type_data.free_(&type->type_data);
				type->type_data.free_ = 0;
			}
		}
		if (type->type_data.type_info) {
			free(type->type_data.type_info);
			type->type_data.free_ = 0;
			type->type_data.type_info = 0;
		}
		free(type);
		type = 0;
	}
	r_list_free(tpi_stream->types);
}

///////////////////////////////////////////////////////////////////////////////
static void free_info_stream(void *stream)
{
	SPDBInfoStream *info_stream = (SPDBInfoStream *)stream;

	free(info_stream->names);
}

///////////////////////////////////////////////////////////////////////////////
static void free_pdb_stream(void *stream)
{
	R_PDB_STREAM *pdb_stream = (R_PDB_STREAM *) stream;

	if (pdb_stream) {
		if (pdb_stream->pages) {
			free(pdb_stream->pages);
			pdb_stream->pages = 0;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_array_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_element_type(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("array: ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "array: ");
	strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_pointer_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_utype(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("pointer to ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "pointer to ");
	strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_modifier_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_modified_type(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("modifier ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "modifier ");
	strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_procedure_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("proc ");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "proc ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_bitfield_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_base_type(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("bitfield ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "bitfield ");
	strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_fieldlist_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("fieldlist ");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "fieldlist ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_enum_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_utype(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("enum ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "enum ");
	strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_struct_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	lt = ti->leaf_type;
	ti->get_name(ti, &tmp_name);

	if (lt == eLF_CLASS) {
		tmp1 = "class ";
	} else {
		tmp1 = "struct ";
	}
	name_len = strlen(tmp1);
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	strcat(*name, tmp_name);

//	if (need_to_free) {
//		free(tmp_name);
//		tmp_name = 0;
//	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_arglist_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_arg_type(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("arglist ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "arglist ");
	strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_mfunction_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("mfunction ");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "mfunction ");
}

///////////////////////////////////////////////////////////////////////////////
static void get_union_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	lt = ti->leaf_type;
	ti->get_name(ti, &tmp_name);

	tmp1 = "union ";
	name_len = strlen(tmp1);
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	strcat(*name, tmp_name);

//	if (need_to_free) {
//		free(tmp_name);
//		tmp_name = 0;
//	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_vtshape_print_type(void *type, char **name)
{
	int name_len = 0;

	name_len = strlen("mfunction");
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "mfunction");
}

///////////////////////////////////////////////////////////////////////////////
static void get_enumerate_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	lt = ti->leaf_type;
	ti->get_name(ti, &tmp_name);

	tmp1 = "enumerate ";
	name_len = strlen(tmp1);
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	strcat(*name, tmp_name);

//	if (need_to_free)
//		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_nesttype_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_index(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("arglist ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "arglist ");
	strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	ELeafType lt;
	char *tmp_name = 0, *tmp1 = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	lt = ti->leaf_type;
	ti->get_name(ti, &tmp_name);

	tmp1 = "method ";
	name_len = strlen(tmp1);
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, tmp1);
	strcat(*name, tmp_name);

//	if (need_to_free)
//		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
static void get_member_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_index(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("(member) ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "(member) ");
	strcat(*name, tmp_name);

	if (need_to_free) {
		free(tmp_name);
		tmp_name = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void get_onemethod_print_type(void *type, char **name)
{
	STypeInfo *ti = (STypeInfo *) type;
	SType *t = 0;
	char *tmp_name = 0;
	int name_len = 0;
	int need_to_free = 1;
	int base_type = 0;

	base_type = ti->get_index(ti, &t);
	if (!t) {
		need_to_free = 0;
		print_base_type(base_type, &tmp_name);
	} else {
		ti = &t->type_data;
		ti->get_print_type(ti, &tmp_name);
	}

	name_len = strlen("onemethod ");
	name_len += strlen(tmp_name);
	*name = (char *) malloc(name_len + 1);
	// name[name_len] = '\0';
	strcpy(*name, "onemethod ");
	strcat(*name, tmp_name);

	if (need_to_free)
		free(tmp_name);
}

///////////////////////////////////////////////////////////////////////////////
void init_scstring(SCString *cstr, unsigned int size, char *name)
{
	cstr->size = size;
	cstr->name = (char *) malloc(size);
	strcpy(cstr->name, name);
}

///////////////////////////////////////////////////////////////////////////////
void deinit_scstring(SCString *cstr)
{
	free(cstr->name);
}

///////////////////////////////////////////////////////////////////////////////
/// size = -1 (default value)
/// pages_size = 0x1000 (default value)
////////////////////////////////////////////////////////////////////////////////
static int init_r_stream_file(R_STREAM_FILE *stream_file, FILE *fp, int *pages,
							  int pages_amount, int size, int page_size)
{
	stream_file->fp = fp;
	stream_file->pages = pages;
	stream_file->pages_amount = pages_amount;
	stream_file->page_size = page_size;

	if (size == -1) {
			stream_file->end = pages_amount * page_size;
	} else {
			stream_file->end = size;
	}

	stream_file->pos = 0;

	return 1;
}

#define GET_PAGE(pn, off, pos, page_size)	{ \
	(pn) = (pos) / (page_size); \
	(off) = (pos) % (page_size); \
}

///////////////////////////////////////////////////////////////////////////////
static void stream_file_read_pages(R_STREAM_FILE *stream_file, int start_indx,
								   int end_indx, char *res)
{
	int i;
	int page_offset;
	int curr_pos;
	int tmp;
//	char buffer[1024];

	for (i = start_indx; i < end_indx; i++) {
		tmp = stream_file->pages[i];
		page_offset = stream_file->pages[i] * stream_file->page_size;
		fseek(stream_file->fp, page_offset, SEEK_SET);
//		curr_pos = ftell(stream_file->fp);
		fread(res, stream_file->page_size, 1, stream_file->fp);
		res += stream_file->page_size;
	}
}

#define READ_PAGES(start_indx, end_indx) { \
	for (i = start_indx; i < end_indx; i++) { \
		fseek(stream_file->fp, stream_file->pages[i] * stream_file->page_size, SEEK_SET); \
		fread(tmp, stream_file->page_size, 1, stream_file->fp); \
		tmp += stream_file->page_size; \
	} \
}

// size by default = -1
///////////////////////////////////////////////////////////////////////////////
static void stream_file_read(R_STREAM_FILE *stream_file, int size, char *res)
{
	int pn_start, off_start, pn_end, off_end;
	int i = 0;
	char *pdata = 0;
	char *tmp;
	int len = 0;

	if (size == -1) {
		pdata = (char *) malloc(stream_file->pages_amount * stream_file->page_size);
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		tmp = pdata;
		stream_file_read_pages(stream_file, 0, stream_file->pages_amount, tmp);
		stream_file->pos = stream_file->end;
		memcpy(res, pdata + off_start, stream_file->end - off_start);
		free(pdata);
	} else {
		GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
		GET_PAGE(pn_end, off_end, stream_file->pos + size, stream_file->page_size);

		pdata = (char *) malloc(stream_file->page_size * (pn_end + 1 - pn_start));
		tmp = pdata;
		stream_file_read_pages(stream_file, pn_start, pn_end + 1, tmp);
		stream_file->pos += size;
		memcpy(res, pdata + off_start, size);
		free(pdata);
	}
}

///////////////////////////////////////////////////////////////////////////////
//def seek(seeLF, offset, whence=0):
//    if whence == 0:
//        seeLF.pos = offset
//    elif whence == 1:
//        seeLF.pos += offset
//    elif whence == 2:
//        seeLF.pos = seeLF.end + offset
//if seeLF.pos < 0: seeLF.pos = 0
//if seeLF.pos > seeLF.end: seeLF.pos = seeLF.end
// whence by default = 0
static void stream_file_seek(R_STREAM_FILE *stream_file, int offset, int whence)
{
	switch (whence) {
	case 0:
		stream_file->pos = offset;
		break;
	case 1:
		stream_file->pos += offset;
		break;
	case 2:
		stream_file->pos = stream_file->end + offset;
		break;
	default:
		break;
	}

	if (stream_file->pos < 0) stream_file->pos = 0;
	if (stream_file->pos > stream_file->end) stream_file->pos = stream_file->end;
}

///////////////////////////////////////////////////////////////////////////////
static int stream_file_tell(R_STREAM_FILE *stream_file)
{
	return stream_file->pos;
}

//def _get_data(seeLF):
//    pos = seeLF.stream_file.tell()
//    seeLF.stream_file.seek(0)
//    data = seeLF.stream_file.read()
//    seeLF.stream_file.seek(pos)
//    return data
static void pdb_stream_get_data(R_PDB_STREAM *pdb_stream, char *data)
{
	int pos = stream_file_tell(&pdb_stream->stream_file);
	stream_file_seek(&pdb_stream->stream_file, 0, 0);
	stream_file_read(&pdb_stream->stream_file, -1, data);
	stream_file_seek(&pdb_stream->stream_file, pos, 0);
}

///////////////////////////////////////////////////////////////////////////////
/// size - default value = -1
/// page_size - default value = 0x1000
///////////////////////////////////////////////////////////////////////////////
static int init_r_pdb_stream(R_PDB_STREAM *pdb_stream, FILE *fp, int *pages,
							 int pages_amount, int index, int size, int page_size)
{
//	printf("init_r_pdb_stream()\n");

	pdb_stream->fp = fp;
	pdb_stream->pages = pages;
	pdb_stream->indx = index;
	pdb_stream->page_size = page_size;
	pdb_stream->pages_amount = pages_amount;

	if (size == -1) {
		pdb_stream->size =  pages_amount * page_size;
	} else {
		pdb_stream->size = size;
	}

	init_r_stream_file(&(pdb_stream->stream_file), fp, pages, pages_amount, size, page_size);

	pdb_stream->free_ = free_pdb_stream;

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int read_int_var(char *var_name, int *var, FILE *fp)
{
	int bytes_read = fread(var, 4, 1, fp);
	if (bytes_read != 1) {
		printf("error while reading from file [%s]", var_name);
		return 0;
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int count_pages(int length, int page_size)
{
	int num_pages = 0;
	num_pages = length / page_size;
	if (length % page_size)
		num_pages++;
	return num_pages;
}

///////////////////////////////////////////////////////////////////////////////
static int init_pdb7_root_stream(R_PDB *pdb, int *root_page_list, int pages_amount,
								 EStream indx, int root_size, int page_size)
{
	int num_streams = 0;
	char *data = 0;
	char *tmp_data = 0;
	int *tmp_sizes = 0;
	int num_pages = 0;
	int i = 0;
	int *sizes = 0;
	int stream_size = 0;
	int pos = 0;
	int pn_start, off_start;
	R_PDB_STREAM *pdb_stream = 0;

	char *tmp;
	int some_int;

	R_PDB7_ROOT_STREAM *root_stream7;

	pdb->root_stream = (R_PDB7_ROOT_STREAM *) malloc(sizeof(R_PDB7_ROOT_STREAM));
	init_r_pdb_stream(pdb->root_stream, pdb->fp, root_page_list, pages_amount,
					  indx, root_size, page_size);

	root_stream7 = pdb->root_stream;
	pdb_stream = &(root_stream7->pdb_stream);

	GET_PAGE(pn_start, off_start, pdb_stream->stream_file.pos, pdb_stream->stream_file.page_size);
	data = (char *) malloc(pdb_stream->stream_file.end - off_start);
	pdb_stream_get_data(pdb_stream, data);

	num_streams = *(int *)data;
	tmp_data = data;
	tmp_data += 4;

	root_stream7->num_streams = num_streams;

	sizes = (int *) malloc(num_streams * 4);

	for (i = 0; i < num_streams; i++) {
		stream_size = *(int *)(tmp_data);
		tmp_data += 4;
		if (stream_size == 0xffffffff) {
			stream_size = 0;
		}
		memcpy(sizes + i, &stream_size, 4);
	}

//	char *tmp_file_name = (char *) malloc(strlen("/root/test.pdb.000") + 1);
//	short ii;
//	FILE *tmp_file;
	tmp_data = ((char *)data + num_streams * 4 + 4);
	//FIXME: free list...
	root_stream7->streams_list = r_list_new();
	RList *pList = root_stream7->streams_list;
	SPage *page = 0;
	for (i = 0; i < num_streams; i++) {
		num_pages = count_pages(sizes[i], page_size);

		// FIXME: remove tmp..
		tmp = (char *) malloc(num_pages * 4);
		memset(tmp, 0, num_pages * 4);
		page = (SPage *) malloc(sizeof(SPage));
		if (num_pages != 0) {
			memcpy(tmp, tmp_data + pos, num_pages * 4);
			pos += num_pages * 4;
//			sprintf(tmp_file_name, "%s%d", "/root/test.pdb", i);
//			tmp_file = fopen(tmp_file_name, "wb");
//			fwrite(tmp, num_pages * 4, 1, tmp_file);
//			fclose(tmp_file);
			page->stream_size = sizes[i];
			page->stream_pages = tmp;
		} else {
			page->stream_size = 0;
			page->stream_pages = 0;
			free(tmp);
		}

		r_list_append(pList, page);
	}

	free(sizes);
	free(data);
	printf("init_pdb7_root_stream()\n");
	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static void init_parsed_pdb_stream(SParsedPDBStream *pdb_stream, FILE *fp, int *pages,
								   int pages_amount, int index, int size,
								   int page_size, f_load pLoad)
{
	// FIXME: free memory...
	pdb_stream->pdb_stream = (R_PDB_STREAM *) malloc(sizeof(R_PDB_STREAM));
	init_r_pdb_stream(pdb_stream->pdb_stream, fp, pages, pages_amount, index, size, page_size);
	pdb_stream->load = pLoad;
	if (pLoad != NULL) {
		pLoad(pdb_stream, &(pdb_stream->pdb_stream->stream_file));
	}
}

///////////////////////////////////////////////////////////////////////////////
static void parse_pdb_info_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream)
{
	SPDBInfoStream *tmp = (SPDBInfoStream *)parsed_pdb_stream;

	tmp->names = 0;

	stream_file_read(stream, 4, (char *)&tmp->/*data.*/version);
	stream_file_read(stream, 4, (char *)&tmp->/*data.*/time_date_stamp);
	stream_file_read(stream, 4, (char *)&tmp->/*data.*/age);
	stream_file_read(stream, 4, (char *)&tmp->/*data.*/guid.data1);
	stream_file_read(stream, 2, (char *)&tmp->/*data.*/guid.data2);
	stream_file_read(stream, 2, (char *)&tmp->/*data.*/guid.data3);
	stream_file_read(stream, 8, (char *)&tmp->/*data.*/guid.data4);
	stream_file_read(stream, 4, (char *)&tmp->/*data.*/cb_names);

	tmp->/*data.*/names = (char *) malloc(tmp->/*data.*/cb_names);
	stream_file_read(stream, tmp->/*data.*/cb_names, tmp->/*data.*/names);
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

//if (lf_mfunction.pad > 0xF0) {
//	tmp = lf_mfunction.pad & 0x0F;
//	CAN_READ(*read_bytes, tmp, len);
//	UPDATE_DATA(leaf_data, *read_bytes, tmp);
//}
#define PAD_ALIGN(pad, curr_read_bytes, src, max_len) { \
	int tmp = 0; \
	if ((pad) > 0xF0) { \
		tmp = (pad) & 0x0F; \
		CAN_READ((curr_read_bytes), (tmp), (len)); \
		UPDATE_DATA((src), (curr_read_bytes), (tmp)); \
	} \
}

///////////////////////////////////////////////////////////////////////////////
static void parse_sctring(SCString *sctr, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int c = 0;

	sctr->name = 0;

	while (*leaf_data != 0) {
		CAN_READ((*read_bytes + c), 1, len);
		c++;
		leaf_data++;
	}
	CAN_READ(*read_bytes, 1, len);
	leaf_data += 1;
	(*read_bytes) += (c + 1);

	init_scstring(sctr, c + 1, leaf_data - (c + 1));
}

///////////////////////////////////////////////////////////////////////////////
static void parse_sval(SVal *val, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	val->name_or_val = 0;

	READ(*read_bytes, 2, len, val->value_or_type, leaf_data, unsigned short);

	if (val->value_or_type < eLF_CHAR) {
		SCString *sctr = (SCString *) malloc(sizeof(SCString));
		parse_sctring(sctr, leaf_data, read_bytes, len);
		val->name_or_val = sctr;
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG lf_ulong;
			lf_ulong.value = 0;
			// unsinged long = 4 bytes for Windows, but not in Linux x64,
			// so here is using unsinged int instead of unsigned long when
			// reading ulong value
			READ(*read_bytes, 4, len, lf_ulong.value, leaf_data, unsigned int);
			parse_sctring(&lf_ulong.name, leaf_data, read_bytes, len);
			val->name_or_val = malloc(sizeof(SVal_LF_ULONG));
			memcpy(val->name_or_val, &lf_ulong, sizeof(SVal_LF_ULONG));
			break;
		}
		case eLF_USHORT:
		{
			SVal_LF_USHORT lf_ushort;
			READ(*read_bytes, 2, len, lf_ushort.value, leaf_data, unsigned short);
			parse_sctring(&lf_ushort.name, leaf_data, read_bytes, len);
			val->name_or_val = malloc(sizeof(SVal_LF_USHORT));
			memcpy(val->name_or_val, &lf_ushort, sizeof(SVal_LF_USHORT));
			break;
		}
		default:
			printf("parse_sval()::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_enumerate(SLF_ENUMERATE *lf_enumerate, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = 0, tmp_read_bytes_before = 0;

	lf_enumerate->enum_value.name_or_val = 0;

	read_bytes_before = *read_bytes;
	READ(*read_bytes, 2, len, lf_enumerate->fldattr.fldattr, leaf_data, unsigned short);

	tmp_read_bytes_before = *read_bytes;
	parse_sval(&lf_enumerate->enum_value, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_enumerate->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_enumerate->pad, *read_bytes, leaf_data, len);

//	printf("%s:", "parse_lf_enumerate()");
//	printf_sval_name(&lf_enumerate->enum_value);
//	printf("\n");

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_nesttype(SLF_NESTTYPE *lf_nesttype, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = *read_bytes;

	lf_nesttype->name.name = 0;

	READ(*read_bytes, 2, len, lf_nesttype->pad, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_nesttype->index, leaf_data, unsigned short);

	parse_sctring(&lf_nesttype->name, leaf_data, read_bytes, len);
//	printf("parse_lf_nesttype(): name = %s\n", lf_nesttype->name.name);

	return *read_bytes - read_bytes_before;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_method(SLF_METHOD *lf_method, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;

	lf_method->name.name = 0;

	READ(*read_bytes, 2, len, lf_method->count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_method->mlist, leaf_data, unsigned int);

	tmp_read_bytes_before = *read_bytes;
	parse_sctring(&lf_method->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_method->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_method->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_method(): name = %s\n", lf_method->name.name);

	return *read_bytes - read_bytes_before;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_member(SLF_MEMBER *lf_member, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;

	lf_member->offset.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_member->fldattr.fldattr, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_member->inedex, leaf_data, unsigned int);

	tmp_read_bytes_before = *read_bytes;
	parse_sval(&lf_member->offset, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_member->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_member->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_member(): name = ");
//	printf_sval_name(&lf_member->offset);
//	printf("\n");

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_onemethod(SLF_ONEMETHOD *lf_onemethod, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	int read_bytes_before = *read_bytes, tmp_before_read_bytes = 0;

	lf_onemethod->val.str_data.name = 0;
	lf_onemethod->val.val = 0;

	READ(*read_bytes, 2, len, lf_onemethod->fldattr.fldattr, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_onemethod->index, leaf_data, unsigned int);

	lf_onemethod->fldattr.fldattr = SWAP_UINT16(lf_onemethod->fldattr.fldattr);

	if((lf_onemethod->fldattr.bits.mprop == eMTintro) ||
		(lf_onemethod->fldattr.bits.mprop == eMTpureintro)) {
		READ(*read_bytes, 4, len, lf_onemethod->val.val, leaf_data, unsigned int);
	}

	tmp_before_read_bytes = *read_bytes;
	parse_sctring(&(lf_onemethod->val.str_data), leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_onemethod->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_onemethod->pad, *read_bytes, leaf_data, len);

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static void init_stype_info(STypeInfo *type_info)
{
	type_info->free_ = 0;
	type_info->get_members = 0;
	type_info->get_name = 0;
	type_info->get_val = 0;
	type_info->get_name_len = 0;
	type_info->get_arg_type = 0;
	type_info->get_element_type = 0;
	type_info->get_index_type = 0;
	type_info->get_base_type = 0;
	type_info->get_derived = 0;
	type_info->get_vshape = 0;
	type_info->get_utype = 0;
	type_info->get_return_type = 0;
	type_info->get_class_type = 0;
	type_info->get_this_type = 0;
	type_info->get_arglist = 0;
	type_info->get_index = 0;
	type_info->get_mlist = 0;
	type_info->get_modified_type = 0;
	type_info->is_fwdref = 0;
	type_info->get_print_type = 0;

	switch (type_info->leaf_type) {
	case eLF_FIELDLIST:
		type_info->get_members = get_fieldlist_members;
		type_info->free_ = free_lf_fieldlist;
		type_info->get_print_type = get_fieldlist_print_type;
		break;
	case eLF_ENUM:
		type_info->get_name = get_enum_name;
		type_info->get_name_len = get_enum_name_len;
		type_info->get_members = get_enum_members;
		type_info->get_utype = get_enum_utype;
		type_info->free_ = free_lf_enum;
		type_info->get_print_type = get_enum_print_type;
		break;
	case eLF_CLASS:
	case eLF_STRUCTURE:
		type_info->get_name = get_class_struct_name;
		type_info->get_val = get_class_struct_val; // for structure this is size
		type_info->get_name_len = get_class_struct_name_len;
		type_info->get_members = get_struct_class_members;
		type_info->get_derived = get_class_struct_derived;
		type_info->get_vshape = get_class_struct_vshape;
		type_info->is_fwdref = is_struct_class_fwdref;
		type_info->free_ = free_lf_class;
		type_info->get_print_type = get_class_struct_print_type;
		break;
	case eLF_POINTER:
		type_info->get_utype = get_pointer_utype;
		type_info->get_print_type = get_pointer_print_type;
		break;
	case eLF_ARRAY:
		type_info->get_name = get_array_name;
		type_info->get_val = get_array_val;
		type_info->get_name_len = get_array_name_len;
		type_info->get_element_type = get_array_element_type;
		type_info->get_index_type = get_array_index_type;
		type_info->free_ = free_lf_array;
		type_info->get_print_type = get_array_print_type;
		break;
	case eLF_MODIFIER:
		type_info->get_modified_type = get_modifier_modified_type;
		type_info->get_print_type = get_modifier_print_type;
		break;
	case eLF_ARGLIST:
		type_info->get_arg_type = get_arglist_type;
		type_info->free_ = free_lf_arglist;
		type_info->get_print_type = get_arglist_print_type;
		break;
	case eLF_MFUNCTION:
		type_info->get_return_type = get_mfunction_return_type;
		type_info->get_class_type = get_mfunction_class_type;
		type_info->get_this_type = get_mfunction_this_type;
		type_info->get_arglist = get_mfunction_arglist;
		type_info->get_print_type = get_mfunction_print_type;
		break;
	case eLF_METHODLIST:
		break;
	case eLF_PROCEDURE:
		type_info->get_return_type = get_procedure_return_type;
		type_info->get_arglist = get_procedure_arglist;
		type_info->get_print_type = get_procedure_print_type;
		break;
	case eLF_UNION:
		type_info->get_name = get_union_name;
		type_info->get_val = get_union_val;
		type_info->get_name_len = get_union_name_len;
		type_info->get_members = get_union_members;
		type_info->is_fwdref = is_union_fwdref;
		type_info->free_ = free_lf_union;
		type_info->get_print_type = get_union_print_type;
		break;
	case eLF_BITFIELD:
		type_info->get_base_type = get_bitfield_base_type;
		type_info->get_print_type = get_bitfield_print_type;
		break;
	case eLF_VTSHAPE:
		type_info->free_ = free_lf_vtshape;
		type_info->get_print_type = get_vtshape_print_type;
		break;
	case eLF_ENUMERATE:
		type_info->get_name = get_enumerate_name;
		type_info->get_val = get_enumerate_val;
		type_info->get_name_len = get_enumerate_name_len;
		type_info->free_ = free_lf_enumerate;
		type_info->get_print_type = get_enumerate_print_type;
		break;
	case eLF_NESTTYPE:
		type_info->get_name = get_nesttype_name;
		type_info->get_name_len = get_nesttype_name_len;
		type_info->get_index = get_nesttype_index;
		type_info->free_ = free_lf_nesttype;
		type_info->get_print_type = get_nesttype_print_type;
		break;
	case eLF_METHOD:
		type_info->get_name = get_method_name;
		type_info->get_name_len = get_method_name_len;
		type_info->get_mlist = get_method_mlist;
		type_info->free_ = free_lf_method;
		type_info->get_print_type = get_method_print_type;
		break;
	case eLF_MEMBER:
		type_info->get_name = get_member_name;
		type_info->get_val = get_member_val;
		type_info->get_name_len = get_member_name_len;
		type_info->get_index = get_member_index;
		type_info->free_ = free_lf_member;
		type_info->get_print_type = get_member_print_type;
		break;
	case eLF_ONEMETHOD:
		type_info->get_name = get_onemethod_name;
		type_info->get_name_len = get_onemethod_name_len;
		type_info->get_val = get_onemethod_val;
		type_info->get_index = get_onemethod_index;
		type_info->free_ = free_lf_onemethod;
		type_info->get_print_type = get_onemethod_print_type;
		break;
	default:
//		printf("init_stype_info(): unknown type for init\n");
		type_info->get_name = 0;
		type_info->get_val = 0;
		type_info->get_name_len = 0;
		type_info->get_members = 0;
		type_info->get_arg_type = 0;
		type_info->get_element_type = 0;
		type_info->get_index_type = 0;
		type_info->get_base_type = 0;
		type_info->get_derived = 0;
		type_info->get_vshape = 0;
		type_info->get_utype = 0;
		type_info->get_return_type = 0;
		type_info->get_class_type = 0;
		type_info->get_this_type = 0;
		type_info->get_arglist = 0;
		type_info->get_index = 0;
		type_info->get_mlist = 0;
		type_info->get_print_type = 0;
		break;
	}
}

#define PARSE_LF2(lf_type, lf_func_name, type) { \
	STypeInfo *type_info = (STypeInfo *) malloc(sizeof(STypeInfo)); \
	lf_type *lf = (lf_type *) malloc(sizeof(lf_type)); \
	curr_read_bytes = parse_##lf_func_name(lf, p, read_bytes, len); \
	type_info->type_info = (void *) lf; \
	type_info->leaf_type = type; \
	init_stype_info(type_info); \
	r_list_append(lf_fieldlist->substructs, type_info); \
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_fieldlist(SLF_FIELDLIST *lf_fieldlist,  unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	ELeafType leaf_type;
	int curr_read_bytes = 0;
	unsigned char *p = leaf_data;

	lf_fieldlist->substructs = r_list_new();

	while (*read_bytes <= len) {
		READ(*read_bytes, 2, len, leaf_type, p, unsigned short);
		switch (leaf_type) {
		case eLF_ENUMERATE:
			PARSE_LF2(SLF_ENUMERATE, lf_enumerate, eLF_ENUMERATE);
			break;
		case eLF_NESTTYPE:
			PARSE_LF2(SLF_NESTTYPE, lf_nesttype, eLF_NESTTYPE);
			break;
		case eLF_METHOD:
			PARSE_LF2(SLF_METHOD, lf_method, eLF_METHOD);
			break;
		case eLF_MEMBER:
			PARSE_LF2(SLF_MEMBER, lf_member, eLF_MEMBER);
			break;
		case eLF_ONEMETHOD:
			PARSE_LF2(SLF_ONEMETHOD, lf_onemethod, eLF_ONEMETHOD);
			break;
		default:
//			printf("unsupported leaf type in parse_lf_fieldlist()\n");
			return;
		}

		if (curr_read_bytes != 0) {
			p += curr_read_bytes;
		} else
			return;
	}
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_enum(SLF_ENUM *lf_enum, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int before_read_bytes = 0;

	lf_enum->name.name = 0;

	READ(*read_bytes, 2, len, lf_enum->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_enum->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_enum->utype, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_enum->field_list, leaf_data, unsigned int);

	lf_enum->prop.cv_property = SWAP_UINT16(lf_enum->prop.cv_property);
	before_read_bytes = *read_bytes;
	parse_sctring(&lf_enum->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_enum->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_enum->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_enum(): name = %s\n", lf_enum->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_class(SLF_CLASS *lf_class, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_CLASS lf_class;
	unsigned int before_read_bytes = 0;

	lf_class->size.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_class->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_class->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_class->field_list, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_class->derived, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_class->vshape, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_class->size, leaf_data, read_bytes, len);
	before_read_bytes = *read_bytes - before_read_bytes;
	leaf_data = (unsigned char *)leaf_data + before_read_bytes;

	PEEK_READ(*read_bytes, 1, len, lf_class->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_class->pad, *read_bytes, leaf_data, len);

//	printf("%s:", "parse_lf_class()");
//	printf_sval_name(&lf_class->size);
//	printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_structure(SLF_STRUCTURE *lf_structure, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_STRUCTURE lf_structure;
	unsigned int before_read_bytes = 0;

	lf_structure->size.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_structure->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_structure->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_structure->field_list, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_structure->derived, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_structure->vshape, leaf_data, unsigned int);

	lf_structure->prop.cv_property = SWAP_UINT16(lf_structure->prop.cv_property);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_structure->size, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_structure->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_structure->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_structure(): name = ");
//	printf_sval_name(&lf_structure->size);
//	printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_pointer(SLF_POINTER *lf_pointer, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	READ(*read_bytes, 4, len, lf_pointer->utype, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_pointer->ptr_attr.ptr_attr, leaf_data, unsigned int);

	lf_pointer->ptr_attr.ptr_attr = SWAP_UINT32(lf_pointer->ptr_attr.ptr_attr);

	PEEK_READ(*read_bytes, 1, len, lf_pointer->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_pointer->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_array(SLF_ARRAY *lf_array, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int before_read_bytes = 0;

	lf_array->size.name_or_val = 0;

	READ(*read_bytes, 4, len, lf_array->element_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_array->index_type, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_array->size, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_array->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_array->pad, *read_bytes, leaf_data, len);

//	printf("parse_lf_array(): name = ");
//	printf_sval_name(&lf_array->size);
//	printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_modifier(SLF_MODIFIER *lf_modifier, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	READ(*read_bytes, 4, len, lf_modifier->modified_type, leaf_data, unsigned int);
	READ(*read_bytes, 2, len, lf_modifier->umodifier.modifier, leaf_data, unsigned short);
	lf_modifier->umodifier.modifier = SWAP_UINT16(lf_modifier->umodifier.modifier);

	PEEK_READ(*read_bytes, 1, len, lf_modifier->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_modifier->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_arglist(SLF_ARGLIST *lf_arglist, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	lf_arglist->arg_type = 0;

	READ(*read_bytes, 4, len, lf_arglist->count, leaf_data, unsigned int);

	lf_arglist->arg_type = (unsigned int *) malloc(lf_arglist->count * 4);
	memcpy(lf_arglist->arg_type, leaf_data, lf_arglist->count * 4);
	leaf_data += (lf_arglist->count * 4);

	PEEK_READ(*read_bytes, 1, len, lf_arglist->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_arglist->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_mfunction(SLF_MFUNCTION *lf_mfunction, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	READ(*read_bytes, 4, len, lf_mfunction->return_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_mfunction->class_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_mfunction->this_type, leaf_data, unsigned int);
	READ(*read_bytes, 1, len, lf_mfunction->call_conv, leaf_data, unsigned char);
	READ(*read_bytes, 1, len, lf_mfunction->reserved, leaf_data, unsigned char);
	READ(*read_bytes, 2, len, lf_mfunction->parm_count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_mfunction->arglist, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_mfunction->this_adjust, leaf_data, int);

	PEEK_READ(*read_bytes, 1, len, lf_mfunction->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_mfunction->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_procedure(SLF_PROCEDURE *lf_procedure, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	READ(*read_bytes, 4, len, lf_procedure->return_type, leaf_data, unsigned int);
	READ(*read_bytes, 1, len, lf_procedure->call_conv, leaf_data, unsigned char);
	READ(*read_bytes, 1, len, lf_procedure->reserved, leaf_data, unsigned char);
	READ(*read_bytes, 2, len, lf_procedure->parm_count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_procedure->arg_list, leaf_data, unsigned int);

	PEEK_READ(*read_bytes, 1, len, lf_procedure->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_procedure->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_union(SLF_UNION *lf_union, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int before_read_bytes = 0;

	lf_union->size.name_or_val = 0;

	READ(*read_bytes, 2, len, lf_union->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_union->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_union->field_list, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_union->size, leaf_data, read_bytes, len);
	before_read_bytes = *read_bytes - before_read_bytes;
	leaf_data = (unsigned char *)leaf_data + before_read_bytes;

	PEEK_READ(*read_bytes, 1, len, lf_union->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_union->pad, *read_bytes, leaf_data, len);

//	printf("%s:", "parse_lf_union()");
//	printf_sval_name(&lf_union->size);
//	printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_bitfield(SLF_BITFIELD *lf_bitfield, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	READ(*read_bytes, 4, len, lf_bitfield->base_type, leaf_data, unsigned int);
	READ(*read_bytes, 1, len, lf_bitfield->length, leaf_data, unsigned char);
	READ(*read_bytes, 1, len, lf_bitfield->position, leaf_data, unsigned char);

	PEEK_READ(*read_bytes, 1, len, lf_bitfield->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_bitfield->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_vtshape(SLF_VTSHAPE *lf_vtshape, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int size; // in bytes;

	lf_vtshape->vt_descriptors = 0;

	READ(*read_bytes, 2, len, lf_vtshape->count, leaf_data, unsigned short);

	size = (4 * lf_vtshape->count + (lf_vtshape->count % 2) * 4) / 8;
	lf_vtshape->vt_descriptors = (char *) malloc(size);
	memcpy(lf_vtshape->vt_descriptors, leaf_data, size);
	leaf_data += size;

	PEEK_READ(*read_bytes, 1, len, lf_vtshape->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_vtshape->pad, *read_bytes, leaf_data, len);
}

#define PARSE_LF(lf_type, lf_func) { \
	lf_type *lf = (lf_type *) malloc(sizeof(lf_type)); \
	parse_##lf_func(lf, leaf_data + 2, &read_bytes, type->length); \
	type->type_data.type_info = (void *) lf; \
	init_stype_info(&type->type_data); \
}

//Type = Debugger(Struct("type",
//    leaf_type,
//    Switch("type_info", lambda ctx: ctx.leaf_type,
//        {
//            "LF_ARGLIST": lfArgList,
//            "LF_ARRAY": lfArray,
//            "LF_ARRAY_ST": lfArrayST,
//            "LF_BITFIELD": lfBitfield,
//            "LF_CLASS": lfClass,
//            "LF_ENUM": lfEnum,
//            "LF_FIELDLIST": lfFieldList,
//            "LF_MFUNCTION": lfMFunc,
//            "LF_MODIFIER": lfModifier,
//            "LF_POINTER": lfPointer,
//            "LF_PROCEDURE": lfProcedure,
//            "LF_STRUCTURE": lfStructure,
//            "LF_STRUCTURE_ST": lfStructureST,
//            "LF_UNION": lfUnion,
//            "LF_UNION_ST": lfUnionST,
//            "LF_VTSHAPE": lfVTShape,
//        },
//        default = Pass,
//    ),
//))
///////////////////////////////////////////////////////////////////////////////
static void parse_tpi_stypes(R_STREAM_FILE *stream, SType *type)
{
	unsigned char *leaf_data;
	unsigned int read_bytes = 0;

	stream_file_read(stream, 2, (char *)&type->length);
	leaf_data = (unsigned char *) malloc(type->length);
	stream_file_read(stream, type->length, (char *)leaf_data);
	type->type_data.leaf_type = *(unsigned short *)leaf_data;
	read_bytes += 2;
	switch (type->type_data.leaf_type) {
	case eLF_FIELDLIST:
//		printf("eLF_FIELDLIST\n");
		PARSE_LF(SLF_FIELDLIST, lf_fieldlist);
		break;
	case eLF_ENUM:
//		printf("eLF_ENUM\n");
		PARSE_LF(SLF_STRUCTURE, lf_enum);
		break;
	// TODO: combine with eLF_STRUCTURE
	case eLF_CLASS:
//		printf("eLF_CLASS\n");
		PARSE_LF(SLF_CLASS, lf_class);
		break;
	case eLF_STRUCTURE:
//		printf("eLF_STRUCTURE\n");
		PARSE_LF(SLF_STRUCTURE, lf_structure);
		break;
	case eLF_POINTER:
//		printf("eLF_POINTER\n");
	{
		SLF_POINTER *lf = (SLF_POINTER *) malloc(sizeof(SLF_POINTER)); \
		parse_lf_pointer(lf, leaf_data + 2, &read_bytes, type->length); \
		type->type_data.type_info = (void *) lf; \
		init_stype_info(&type->type_data); \
	}
//		PARSE_LF(SLF_POINTER, lf_pointer);
		break;
	case eLF_ARRAY:
//		printf("eLF_ARRAY\n");
		PARSE_LF(SLF_ARRAY, lf_array);
		break;
	case eLF_MODIFIER:
//		printf("eLF_MODIFIER\n");
		PARSE_LF(SLF_MODIFIER, lf_modifier);
		break;
	case eLF_ARGLIST:
//		printf("eLF_ARGLIST\n");
		PARSE_LF(SLF_ARGLIST, lf_arglist);
		break;
	case eLF_MFUNCTION:
//		printf("eLF_MFUNCTION\n");
		PARSE_LF(SLF_MFUNCTION, lf_mfunction);
		break;
	case eLF_METHODLIST:
//		printf("eLF_METHOD_LIST\n");
		break;
	case eLF_PROCEDURE:
//		printf("eLF_PROCEDURE\n");
		PARSE_LF(SLF_PROCEDURE, lf_mfunction);
		break;
	case eLF_UNION:
//		printf("eLF_UNION\n");
		PARSE_LF(SLF_UNION, lf_union);
		break;
	case eLF_BITFIELD:
//		printf("eLF_BITFIELD\n");
		PARSE_LF(SLF_BITFIELD, lf_bitfield);
		break;
	case eLF_VTSHAPE:
//		printf("eLF_VTSHAPE\n");
		PARSE_LF(SLF_VTSHAPE, lf_vtshape);
		break;
	default:
		printf("parse_tpi_stremas(): unsupported leaf type\n");
		break;
	}

	free(leaf_data);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_tpi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream)
{
	int i;
	SType *type = 0;
	STpiStream *tpi_stream = (STpiStream *) parsed_pdb_stream;
	tpi_stream->types = r_list_new();
	p_types_list = tpi_stream->types;

	stream_file_read(stream, sizeof(STPIHeader), (char *)&tpi_stream->header);

	base_idx = tpi_stream->header.ti_min;

	for (i = tpi_stream->header.ti_min; i < tpi_stream->header.ti_max; i++) {
		type = (SType *) malloc(sizeof(SType));
		type->tpi_idx = i;
		type->type_data.type_info = 0;
		type->type_data.leaf_type = eLF_MAX;
		init_stype_info(&type->type_data);
		parse_tpi_stypes(stream, type);
		r_list_append(tpi_stream->types, type);
	}

	// Postprocessing...
}

//seeLF.streams = []
//for i in range(len(rs.streams)):
//    try:
//        pdb_cls = seeLF._stream_map[i]
//    except KeyError:
//        pdb_cls = PDBStream
//    stream_size, stream_pages = rs.streams[i]
//    seeLF.streams.append(
//        pdb_cls(seeLF.fp, stream_pages, i, size=stream_size,
//            page_size=seeLF.page_size, fast_load=seeLF.fast_load,
//            parent=seeLF))

//# Sets up access to streams by name
//seeLF._update_names()

//# Second stage init. Currently only used for FPO strings
//if not seeLF.fast_load:
//    for s in seeLF.streams:
//        if hasattr(s, 'load2'):
//            s.load2()
///////////////////////////////////////////////////////////////////////////////
static int pdb_read_root(R_PDB *pdb)
{
	int i = 0;

	RList *pList = pdb->pdb_streams;
	R_PDB7_ROOT_STREAM *root_stream = pdb->root_stream;
	R_PDB_STREAM *pdb_stream = 0;
	SParsedPDBStream *parsed_pdb_stream = 0;
	SPDBInfoStream *pdb_info_stream = 0;
	STpiStream *tpi_stream = 0;
	R_STREAM_FILE stream_file;
	RListIter *it;
	SPage *page = 0;

	it = r_list_iterator(root_stream->streams_list);
	while (r_list_iter_next(it)) {
		page = (SPage*) r_list_iter_get(it);
		init_r_stream_file(&stream_file, pdb->fp, page->stream_pages,
						   root_stream->pdb_stream.pages_amount,
						   page->stream_size,
						   root_stream->pdb_stream.page_size);
		switch (i) {
		case ePDB_STREAM_PDB:
			pdb_info_stream = (SPDBInfoStream *) malloc(sizeof(SPDBInfoStream));
			pdb_info_stream->free_ = free_info_stream;
			parse_pdb_info_stream(pdb_info_stream, &stream_file);
			r_list_append(pList, pdb_info_stream);
			break;
		case ePDB_STREAM_TPI:
			tpi_stream = (STpiStream *) malloc(sizeof(STpiStream));
			tpi_stream->free_ = free_tpi_stream;
			parse_tpi_stream(tpi_stream, &stream_file);
			r_list_append(pList, tpi_stream);
			break;
		case ePDB_STREAM_DBI:
			//TODO: free memory
//			parsed_pdb_stream = (SParsedPDBStream *) malloc(sizeof(SParsedPDBStream));
//			init_parsed_pdb_stream(parsed_pdb_stream, pdb->fp, page->stream_pages,
//								   root_stream->pdb_stream.pages_amount, i,
//								   page->stream_size,
//								   root_stream->pdb_stream.page_size, 0);
//			r_list_append(pList, parsed_pdb_stream);
			break;
		default:
			pdb_stream = (R_PDB_STREAM *)malloc(sizeof(R_PDB_STREAM));
			init_r_pdb_stream(pdb_stream, pdb->fp, page->stream_pages,
							  root_stream->pdb_stream.pages_amount, i,
							  page->stream_size,
							  root_stream->pdb_stream.page_size);
			r_list_append(pList, pdb_stream);
			break;
		}
		i++;
	}

	return 1;
}

///////////////////////////////////////////////////////////////////////////////
static int pdb7_parse(R_PDB *pdb)
{
	printf("pdb7_parse()\n");

	char signature[PDB7_SIGNATURE_LEN + 1];
	int page_size = 0;
	int alloc_tbl_ptr = 0;
	int num_file_pages = 0;
	int root_size = 0;
	int reserved = 0;

	int num_root_pages = 0;
	int num_root_index_pages = 0;
	int *root_index_pages = 0;
	void *root_page_data = 0;
	int *root_page_list = 0;

	int i = 0;
	void *p_tmp;

	int bytes_read = 0;

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("error while reading PDB7_SIGNATURE\n");
		goto error;
	}

	if (read_int_var("page_size", &page_size, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("alloc_tbl_ptr", &alloc_tbl_ptr, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("num_file_pages", &num_file_pages, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("root_size", &root_size, pdb->fp) == 0) {
		goto error;
	}

	if (read_int_var("reserved", &reserved, pdb->fp) == 0) {
		goto error;
	}

	// FIXME: why they is not equal ????
//	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN) != 0) {
//		printf("Invalid signature for PDB7 format\n");
//		//goto error;
//	}

	// TODO:
	// create stream of maps and names
	// ...

	num_root_pages = count_pages(root_size, page_size);
	num_root_index_pages = count_pages((num_root_pages * 4), page_size);

	root_index_pages = (int *)malloc(sizeof(int) * num_root_index_pages);
	if (!root_index_pages) {
		printf("error memory allocation\n");
		goto error;
	}

	bytes_read = fread(root_index_pages, 4, num_root_index_pages, pdb->fp);
	if (bytes_read != num_root_index_pages) {
		printf("error while reading root_index_pages\n");
		goto error;
	}

	root_page_data = (int *)malloc(page_size * num_root_index_pages);
	if (!root_page_data) {
		printf("error memory allocation of root_page_data\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_index_pages; i++) {
		fseek(pdb->fp, root_index_pages[i] * page_size, SEEK_SET);
		fread(p_tmp, page_size, 1, pdb->fp);
		p_tmp = (char *)p_tmp + page_size;
	}

	root_page_list = (int *)malloc(sizeof(int) * num_root_pages);
	if (!root_page_list) {
		printf("error: memory allocation of root page\n");
		goto error;
	}

	p_tmp = root_page_data;
	for (i = 0; i < num_root_pages; i++) {
		root_page_list[i] = *((int *)p_tmp);
		p_tmp = (int *)p_tmp + 1;
	}

	init_pdb7_root_stream(pdb, root_page_list, num_root_pages, ePDB_STREAM_ROOT, root_size, page_size);
	pdb_read_root(pdb);

	if (root_page_list) {
		free(root_page_list);
		root_page_list = 0;
	}

	if (root_page_data) {
		free(root_page_data);
		root_page_data = 0;
	}

	if (root_index_pages) {
		free(root_index_pages);
		root_index_pages = 0;
	}

	return 1;

error:
	if (root_page_list) {
		free(root_page_list);
		root_page_list = 0;
	}

	if (root_page_data) {
		free(root_page_data);
		root_page_data = 0;
	}

	if (root_index_pages) {
		free(root_index_pages);
		root_index_pages = 0;
	}

	return 0;
}

///////////////////////////////////////////////////////////////////////////////
static void finish_pdb_parse(R_PDB *pdb)
{
	R_PDB7_ROOT_STREAM *p = pdb->root_stream;

	// TODO: maybe create some kind of destructor?
	// free of R_PDB7_ROOT_STREAM
	RListIter *it;
	SPage *page = 0;

	it = r_list_iterator(p->streams_list);
	while (r_list_iter_next(it)) {
		page = (SPage *) r_list_iter_get(it);
		free(page->stream_pages);
		page->stream_pages = 0;
		free(page);
		page = 0;
	}
	r_list_free(p->streams_list);
	p->streams_list = 0;
	free(p);
	p = 0;
	// end of free of R_PDB7_ROOT_STREAM

	// TODO: maybe create some kind of destructor?
	// free of pdb->pdb_streams
//	SParsedPDBStream *parsed_pdb_stream = 0;
	SPDBInfoStream *pdb_info_stream = 0;
	STpiStream *tpi_stream = 0;
	R_PDB_STREAM *pdb_stream = 0;
	int i = 0;
	it = r_list_iterator(pdb->pdb_streams);
	while (r_list_iter_next(it)) {
		switch (i) {
		case 1:
			pdb_info_stream = (SPDBInfoStream *) r_list_iter_get(it);
			pdb_info_stream->free_(pdb_info_stream);
			free(pdb_info_stream);
			break;
		case 2:
			tpi_stream = (STpiStream *) r_list_iter_get(it);
			tpi_stream->free_(tpi_stream);
			free(tpi_stream);
			break;
		case 3:
			break;
		default:
			pdb_stream = (R_PDB_STREAM *) r_list_iter_get(it);
			pdb_stream->free_(pdb_stream);
			free(pdb_stream);
		}

		i++;
	}
	r_list_free(pdb->pdb_streams);
	// enf of free of pdb->pdb_streams

	if (pdb->stream_map)
		free(pdb->stream_map);

	fclose(pdb->fp);
	printf("finish_pdb_parse()\n");
}

///////////////////////////////////////////////////////////////////////////////
static void print_types(R_PDB *pdb)
{
	printf("print_types()\n");
	char *name;
	int val = 0;
	int offset = 0;
	SType *t = 0;
	STypeInfo *tf = 0;
	RListIter *it = 0, *it2 = 0;
	RList *plist = pdb->pdb_streams, *ptmp;
	STpiStream *tpi_stream = r_list_get_n(plist, ePDB_STREAM_TPI);

	it = r_list_iterator(tpi_stream->types);
	while (r_list_iter_next(it)) {
		t = (SType *) r_list_iter_get(it);
		tf = &t->type_data;
		if ((tf->leaf_type == eLF_STRUCTURE) || (tf->leaf_type == eLF_UNION)) {
			tf->is_fwdref(tf, &val);
			if (val == 1) {
				continue;
			}
			tf->get_name(tf, &name);
			// val for STRUCT or UNION mean size
			tf->get_val(tf, &val);
			printf("%s: size 0x%x\n", name, val);

			tf->get_members(tf, &ptmp);
			it2 = r_list_iterator(ptmp);
			while (r_list_iter_next(it2)) {
				tf = (STypeInfo *) r_list_iter_get(it2);
				tf->get_name(tf, &name);
				if (tf->get_val)
					tf->get_val(tf, &offset);
				else
					offset = 0;
				printf("\t0x%x: %s ", offset, name);
				tf->get_print_type(tf, &name);
				printf("%s\n", name);
				free(name);
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
int init_pdb_parser(R_PDB *pdb)
{
	char *signature = 0;
	int bytes_read = 0;

	if (!pdb) {
		printf("struct R_PDB is not correct\n");
		goto error;
	}

	pdb->fp = fopen(pdb->file_name, "rb");
	if (!pdb->fp) {
		printf("file %s can not be open\n", pdb->file_name);
		goto error;
	}

	signature = (char *)malloc(sizeof(char) * PDB7_SIGNATURE_LEN);
	if (!signature) {
		printf("memory allocation error\n");
		goto error;
	}

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("file reading error\n");
		goto error;
	}

	fseek(pdb->fp, 0, SEEK_SET);

	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN)) {
		pdb->pdb_parse =pdb7_parse;
	} else {
		printf("unsupported pdb format\n");
		goto error;
	}

	if (signature) {
		free(signature);
		signature = 0;
	}

	pdb->pdb_streams = r_list_new();
	pdb->stream_map = 0;
	pdb->finish_pdb_parse = finish_pdb_parse;
	pdb->print_types = print_types;
	printf("init_pdb_parser() finish with success\n");
	return 1;

error:
	if (signature) {
		free(signature);
		signature = 0;
	}

	return 0;
}
