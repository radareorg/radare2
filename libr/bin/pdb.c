#include <r_pdb.h>
//#include <tpi.c>
#include <string.h>
#include <byteswap.h>

#define PDB2_SIGNATURE "Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"
#define PDB7_SIGNATURE_LEN 32
#define PDB2_SIGNATURE_LEN 51

typedef void (*free_func)(void *);

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
		unsigned char fwdref : 1;
		unsigned char opcast : 1;
		unsigned char opassign : 1;
		unsigned char cnested : 1;
		unsigned char isnested : 1;
		unsigned char ovlops : 1;
		unsigned char ctor : 1;
		unsigned char packed : 1;
		unsigned char reserved : 7; // swapped
		unsigned char scoped : 1;
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
	// TODO: need to be free
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

typedef enum {
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
} SLF_MEMBER;

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
} STypeInfo;

typedef struct {
	unsigned short length;
	STypeInfo type_data;

	free_func free_;
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
		default:
			printf("free_sval()::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_class(void *type)
{
	SType *t = (SType *) type;
	SLF_CLASS *lf_class = (SLF_CLASS *) t->type_data.type_info;

	free_sval(&lf_class->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_union(void *type)
{
	SType *t = (SType *) type;
	SLF_UNION *lf_union = (SLF_UNION *) t->type_data.type_info;

	free_sval(&lf_union->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_enum(void *type)
{
	SType *t = (SType *) type;
	SLF_ENUM *lf_enum = (SLF_ENUM *) t->type_data.type_info;

	free(lf_enum->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_array(void *type)
{
	SType *t = (SType *) type;
	SLF_ARRAY *lf_array = (SLF_ARRAY *) t->type_data.type_info;

	free_sval(&lf_array->size);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_arglist(void *type)
{
	SType *t = (SType *) type;
	SLF_ARGLIST *lf_arglist = (SLF_ARGLIST *) t->type_data.type_info;

	free(lf_arglist->arg_type);
}

///////////////////////////////////////////////////////////////////////////////
static void free_lf_vtshape(void *type)
{
	SType *t = (SType *) type;
	SLF_VTSHAPE *lf_vtshape = (SLF_VTSHAPE *) t->type_data.type_info;

	free(lf_vtshape->vt_descriptors);
}

///////////////////////////////////////////////////////////////////////////////
static void free_tpi_stream(void *stream)
{
//	STpiStream *tpi_stream = (STpiStream *)stream;
//	RListIter *it;
//	SType *type = 0;

//	it = r_list_iterator(tpi_stream->types);
//	while (r_list_iter_next(it)) {
//		type = (SType *) r_list_iter_get(it);
//		if (type->free_)
//			type->free_(type);
//		if (type->type_data.type_info)
//			free(type->type_data.type_info);
//		free(type);
//	}
//	r_list_free(tpi_stream->types);
}

///////////////////////////////////////////////////////////////////////////////
static void free_info_stream(void *stream)
{
	SPDBInfoStream *info_stream = (SPDBInfoStream *)stream;

	free(info_stream->names);
//	free(info_stream);
}

///////////////////////////////////////////////////////////////////////////////
static void free_pdb_stream(void *stream)
{
	R_PDB_STREAM *pdb_stream = (R_PDB_STREAM *) stream;

	free(pdb_stream->pages);
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

	// TODO: free in appropriate place
//	free(tmp->/*data.*/names);
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
	READ(*read_bytes, 2, len, val->value_or_type, leaf_data, unsigned short);

	if (val->value_or_type < eLF_CHAR) {
		SCString sctr;
		parse_sctring(&sctr, leaf_data, read_bytes, len);
		val->name_or_val = malloc(sizeof(SCString));
		memcpy(val->name_or_val, &sctr, sizeof(SCString));
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
		default:
			printf("parse_sval()::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static void printf_sval_name(SVal *val)
{
	if (val->value_or_type < eLF_CHAR) {
		SCString *scstr;
		scstr = (SCString *) val->name_or_val;
		printf("%s", scstr->name);
	} else {
		switch (val->value_or_type) {
		case eLF_ULONG:
		{
			SVal_LF_ULONG *lf_ulong;
			lf_ulong = (SVal_LF_ULONG *) val->name_or_val;
			printf("%s", lf_ulong->name.name);
			break;
		}
		default:
			printf("printf_sval_name()::oops\n");
			break;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_enumerate(unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	SLF_ENUMERATE lf_enumerate;
	unsigned int read_bytes_before = 0, tmp_read_bytes_before = 0;

	read_bytes_before = *read_bytes;
	READ(*read_bytes, 2, len, lf_enumerate.fldattr.fldattr, leaf_data, unsigned short);

	tmp_read_bytes_before = *read_bytes;
	parse_sval(&lf_enumerate.enum_value, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_enumerate.pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_enumerate.pad, *read_bytes, leaf_data, len);

	printf("%s:", "parse_lf_enumerate()");
	printf_sval_name(&lf_enumerate.enum_value);
	printf("\n");

	free_sval(&lf_enumerate.enum_value);

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_nesttype(unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	unsigned int read_bytes_before = *read_bytes;
	SLF_NESTTYPE lf_nesttype;

	READ(*read_bytes, 2, len, lf_nesttype.pad, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_nesttype.index, leaf_data, unsigned short);

	parse_sctring(&lf_nesttype.name, leaf_data, read_bytes, len);
	printf("parse_lf_nesttype(): name = %s\n", lf_nesttype.name.name);

	// TODO: free in appropriate place
	free(lf_nesttype.name.name);

	return *read_bytes - read_bytes_before;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_method(unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{

	unsigned int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;
	SLF_METHOD lf_method;

	READ(*read_bytes, 2, len, lf_method.count, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_method.mlist, leaf_data, unsigned int);

	tmp_read_bytes_before = *read_bytes;
	parse_sctring(&lf_method.name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_method.pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_method.pad, *read_bytes, leaf_data, len);

	printf("parse_lf_method(): name = %s\n", lf_method.name.name);

	// TODO: free in appropriate place
	free(lf_method.name.name);

	return *read_bytes - read_bytes_before;
}

///////////////////////////////////////////////////////////////////////////////
static int parse_lf_member(unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	int read_bytes_before = *read_bytes, tmp_read_bytes_before = 0;
	SLF_MEMBER lf_member;

	READ(*read_bytes, 2, len, lf_member.fldattr.fldattr, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_member.inedex, leaf_data, unsigned int);

	tmp_read_bytes_before = *read_bytes;
	parse_sval(&lf_member.offset, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - tmp_read_bytes_before);

	PEEK_READ(*read_bytes, 1, len, lf_member.pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_member.pad, *read_bytes, leaf_data, len);

	printf("parse_lf_member(): name = ");
	printf_sval_name(&lf_member.offset);
	printf("\n");

	free_sval(&lf_member.offset);

	return (*read_bytes - read_bytes_before);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_fieldlist(unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
	ELeafType leaf_type;
	int curr_read_bytes = 0;
	unsigned char *p = leaf_data;

	while (*read_bytes <= len) {
		READ(*read_bytes, 2, len, leaf_type, p, unsigned short);
		switch (leaf_type) {
		case eLF_ENUMERATE:
			curr_read_bytes = parse_lf_enumerate(p, read_bytes, len);
			break;
		case eLF_NESTTYPE:
			curr_read_bytes = parse_lf_nesttype(p, read_bytes, len);
			break;
		case eLF_METHOD:
			curr_read_bytes = parse_lf_method(p, read_bytes, len);
			break;
		case eLF_MEMBER:
			curr_read_bytes = parse_lf_member(p, read_bytes, len);
			break;
		default:
			printf("unsupported leaf type in parse_lf_fieldlist()\n");
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

	READ(*read_bytes, 2, len, lf_enum->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_enum->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_enum->utype, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_enum->field_list, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sctring(&lf_enum->name, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_enum->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_enum->pad, *read_bytes, leaf_data, len);

	printf("parse_lf_enum(): name = %s\n", lf_enum->name.name);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_class(SLF_CLASS *lf_class, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_CLASS lf_class;
	unsigned int before_read_bytes = 0;

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

	printf("%s:", "parse_lf_class()");
	printf_sval_name(&lf_class->size);
	printf("\n");

	free_sval(&lf_class->size);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_structure(SLF_STRUCTURE *lf_structure, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_STRUCTURE lf_structure;
	unsigned int before_read_bytes = 0;

	READ(*read_bytes, 2, len, lf_structure->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_structure->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_structure->field_list, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_structure->derived, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_structure->vshape, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_structure->size, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_structure->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_structure->pad, *read_bytes, leaf_data, len);

	printf("parse_lf_structure(): name = ");
	printf_sval_name(&lf_structure->size);
	printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_pointer(SLF_POINTER *lf_pointer, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_POINTER lf_pointer;

	READ(*read_bytes, 4, len, lf_pointer->utype, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_pointer->ptr_attr.ptr_attr, leaf_data, unsigned int);
	lf_pointer->ptr_attr.ptr_attr = SWAP_UINT32(lf_pointer->ptr_attr.ptr_attr);

	PEEK_READ(*read_bytes, 1, len, lf_pointer->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_pointer->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_array(SLF_ARRAY *lf_array, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_ARRAY lf_array;
	unsigned int before_read_bytes = 0;

	READ(*read_bytes, 4, len, lf_array->element_type, leaf_data, unsigned int);
	READ(*read_bytes, 4, len, lf_array->index_type, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_array->size, leaf_data, read_bytes, len);
	leaf_data += (*read_bytes - before_read_bytes);

	PEEK_READ(*read_bytes, 1, len, lf_array->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_array->pad, *read_bytes, leaf_data, len);

	printf("parse_lf_array(): name = ");
	printf_sval_name(&lf_array->size);
	printf("\n");

//	free_sval(&lf_array.size);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_modifier(SLF_MODIFIER *lf_modifier, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
//	SLF_MODIFIER lf_modifier;

	READ(*read_bytes, 4, len, lf_modifier->modified_type, leaf_data, unsigned int);
	READ(*read_bytes, 2, len, lf_modifier->umodifier.modifier, leaf_data, unsigned short);
	lf_modifier->umodifier.modifier = SWAP_UINT16(lf_modifier->umodifier.modifier);

	PEEK_READ(*read_bytes, 1, len, lf_modifier->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_modifier->pad, *read_bytes, leaf_data, len);
}

///////////////////////////////////////////////////////////////////////////////
static void parse_lf_arglist(SLF_ARGLIST *lf_arglist, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len)
{
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

	READ(*read_bytes, 2, len, lf_union->count, leaf_data, unsigned short);
	READ(*read_bytes, 2, len, lf_union->prop.cv_property, leaf_data, unsigned short);
	READ(*read_bytes, 4, len, lf_union->field_list, leaf_data, unsigned int);

	before_read_bytes = *read_bytes;
	parse_sval(&lf_union->size, leaf_data, read_bytes, len);
	before_read_bytes = *read_bytes - before_read_bytes;
	leaf_data = (unsigned char *)leaf_data + before_read_bytes;

	PEEK_READ(*read_bytes, 1, len, lf_union->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_union->pad, *read_bytes, leaf_data, len);

	printf("%s:", "parse_lf_union()");
	printf_sval_name(&lf_union->size);
	printf("\n");
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

	READ(*read_bytes, 2, len, lf_vtshape->count, leaf_data, unsigned short);

	size = (4 * lf_vtshape->count + (lf_vtshape->count % 2) * 4) / 8;
	lf_vtshape->vt_descriptors = (char *) malloc(size);
	memcpy(lf_vtshape->vt_descriptors, leaf_data, size);
	leaf_data += size;

	PEEK_READ(*read_bytes, 1, len, lf_vtshape->pad, leaf_data, unsigned char);
	PAD_ALIGN(lf_vtshape->pad, *read_bytes, leaf_data, len);
}

#define PARSE_LF(lf_type, lf_func, lf_free_func_name) { \
	lf_type *lf = (lf_type *) malloc(sizeof(lf_type)); \
	parse_##lf_func(lf, leaf_data + 2, &read_bytes, type->length); \
	type->type_data.type_info = (void *) lf; \
	type->free_ = lf_free_func_name; \
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
//	case eLF_FIELDLIST:
//		printf("eLF_FIELDLIST\n");
//		parse_lf_fieldlist(leaf_data + 2, &read_bytes, type->length);
//		break;
	case eLF_ENUM:
	{
		printf("eLF_ENUM\n");
		PARSE_LF(SLF_STRUCTURE, lf_enum, free_lf_enum);
		break;
	}
	// TODO: combine with eLF_STRUCTURE
	case eLF_CLASS:
	{
		printf("eLF_CLASS\n");
		PARSE_LF(SLF_CLASS, lf_class, free_lf_class);
		break;
	}
	case eLF_STRUCTURE:
	{
		printf("eLF_STRUCTURE\n");
		PARSE_LF(SLF_STRUCTURE, lf_structure, free_lf_class);
		break;
	}
	case eLF_POINTER:
	{
		printf("eLF_POINTER\n");
		PARSE_LF(SLF_POINTER, lf_pointer, 0);
		break;
	}
	case eLF_ARRAY:
	{
		printf("eLF_ARRAY\n");
		PARSE_LF(SLF_ARRAY, lf_array, free_lf_array);
		break;
	}
	case eLF_MODIFIER:
		printf("eLF_MODIFIER\n");
		PARSE_LF(SLF_MODIFIER, lf_modifier, 0);
		break;
	case eLF_ARGLIST:
		printf("eLF_ARGLIST\n");
		PARSE_LF(SLF_ARGLIST, lf_arglist, free_lf_arglist);
		break;
	case eLF_MFUNCTION:
		printf("eLF_MFUNCTION\n");
		PARSE_LF(SLF_MFUNCTION, lf_mfunction, 0);
		break;
	case eLF_METHODLIST:
		printf("eLF_METHOD_LIST\n");
		break;
	case eLF_PROCEDURE:
		printf("eLF_PROCEDURE\n");
		PARSE_LF(SLF_PROCEDURE, lf_mfunction, 0);
		break;
	case eLF_UNION:
		printf("eLF_UNION\n");
		PARSE_LF(SLF_UNION, lf_union, free_lf_union);
		break;
	case eLF_BITFIELD:
		printf("eLF_BITFIELD\n");
		PARSE_LF(SLF_BITFIELD, lf_bitfield, 0);
		break;
	case eLF_VTSHAPE:
		printf("eLF_VTSHAPE\n");
		PARSE_LF(SLF_VTSHAPE, lf_vtshape, free_lf_vtshape);
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

	stream_file_read(stream, sizeof(STPIHeader), (char *)&tpi_stream->header);

	for (i = 0; i < (tpi_stream->header.ti_max - tpi_stream->header.ti_min); i++) {
		type = (SType *) malloc(sizeof(SType));
		type->free_ = 0;
		type->type_data.type_info = 0;
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
		case 1:
			pdb_info_stream = (SPDBInfoStream *) malloc(sizeof(SPDBInfoStream));
			pdb_info_stream->free_ = free_info_stream;
			parse_pdb_info_stream(pdb_info_stream, &stream_file);
			r_list_append(pList, pdb_info_stream);
			break;
		case 2:
			tpi_stream = (STpiStream *) malloc(sizeof(STpiStream));
			tpi_stream->free_ = free_tpi_stream;
			parse_tpi_stream(tpi_stream, &stream_file);
			r_list_append(pList, tpi_stream);
			break;
		case 3:
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
	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN) != 0) {
		printf("Invalid signature for PDB7 format\n");
		//goto error;
	}

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
	printf("init_pdb_parser() finish with success\n");
	return 1;

error:
	if (signature) {
		free(signature);
		signature = 0;
	}

	return 0;
}
