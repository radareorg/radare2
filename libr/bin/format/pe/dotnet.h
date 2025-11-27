#ifndef YR_DOTNET_H
#define YR_DOTNET_H

#include <r_types.h>
#include <r_list.h>

#pragma pack(push, 1)


#define fits_in_pe(pe, pointer, size) \
    ((size_t) size <= pe->data_size && \
     (uint8_t*) (pointer) >= pe->data && \
     (uint8_t*) (pointer) <= pe->data + pe->data_size - size)

#define struct_fits_in_pe(pe, pointer, struct_type) \
    fits_in_pe(pe, pointer, sizeof (struct_type))

// Simple data directory structure
typedef struct {
	ut32 VirtualAddress;
	ut32 Size;
} DATA_DIRECTORY;

//
// CLI header.
// ECMA-335 Section II.25.3.3
//
typedef struct _CLI_HEADER {
    ut32 Size; // Called "Cb" in documentation.
    ut16 MajorRuntimeVersion;
    ut16 MinorRuntimeVersion;
    DATA_DIRECTORY MetaData;
    ut32 Flags;
    ut32 EntryPointToken;
    DATA_DIRECTORY Resources;
    DATA_DIRECTORY StrongNameSignature;
    ut64 CodeManagerTable;
    DATA_DIRECTORY VTableFixups;
    ut64 ExportAddressTableJumps;
    ut64 ManagedNativeHeader;
} CLI_HEADER, *PCLI_HEADER;

#define NET_METADATA_MAGIC 0x424a5342

//
// CLI MetaData
// ECMA-335 Section II.24.2.1
//
// Note: This is only part of the struct, as the rest of it is variable length.
//
typedef struct _NET_METADATA {
    ut32 Magic;
    ut16 MajorVersion;
    ut16 MinorVersion;
    ut32 Reserved;
    ut32 Length;
    char Version[0];
} NET_METADATA, *PNET_METADATA;

#define DOTNET_STREAM_NAME_SIZE 32

//
// CLI Stream Header
// ECMA-335 Section II.24.2.2
//
typedef struct _STREAM_HEADER {
    ut32 Offset;
    ut32 Size;
    char Name[0];
} STREAM_HEADER, *PSTREAM_HEADER;


//
// CLI #~ Stream Header
// ECMA-335 Section II.24.2.6
//
typedef struct _TILDE_HEADER {
    ut32 Reserved1;
    ut8 MajorVersion;
    ut8 MinorVersion;
    ut8 HeapSizes;
    ut8 Reserved2;
    ut64 Valid;
    ut64 Sorted;
} TILDE_HEADER, *PTILDE_HEADER;

// These are the bit positions in Valid which will be set if the table
// exists.
#define BIT_MODULE                   0x00
#define BIT_TYPEREF                  0x01
#define BIT_TYPEDEF                  0x02
#define BIT_FIELDPTR                 0x03 // Not documented in ECMA-335
#define BIT_FIELD                    0x04
#define BIT_METHODDEFPTR             0x05 // Not documented in ECMA-335
#define BIT_METHODDEF                0x06
#define BIT_PARAMPTR                 0x07 // Not documented in ECMA-335
#define BIT_PARAM                    0x08
#define BIT_INTERFACEIMPL            0x09
#define BIT_MEMBERREF                0x0A
#define BIT_CONSTANT                 0x0B
#define BIT_CUSTOMATTRIBUTE          0x0C
#define BIT_FIELDMARSHAL             0x0D
#define BIT_DECLSECURITY             0x0E
#define BIT_CLASSLAYOUT              0x0F
#define BIT_FIELDLAYOUT              0x10
#define BIT_STANDALONESIG            0x11
#define BIT_EVENTMAP                 0x12
#define BIT_EVENTPTR                 0x13 // Not documented in ECMA-335
#define BIT_EVENT                    0x14
#define BIT_PROPERTYMAP              0x15
#define BIT_PROPERTYPTR              0x16 // Not documented in ECMA-335
#define BIT_PROPERTY                 0x17
#define BIT_METHODSEMANTICS          0x18
#define BIT_METHODIMPL               0x19
#define BIT_MODULEREF                0x1A
#define BIT_TYPESPEC                 0x1B
#define BIT_IMPLMAP                  0x1C
#define BIT_FIELDRVA                 0x1D
#define BIT_ENCLOG                   0x1E // Not documented in ECMA-335
#define BIT_ENCMAP                   0x1F // Not documented in ECMA-335
#define BIT_ASSEMBLY                 0x20
#define BIT_ASSEMBLYPROCESSOR        0x21
#define BIT_ASSEMBLYOS               0x22
#define BIT_ASSEMBLYREF              0x23
#define BIT_ASSEMBLYREFPROCESSOR     0x24
#define BIT_ASSEMBLYREFOS            0x25
#define BIT_FILE                     0x26
#define BIT_EXPORTEDTYPE             0x27
#define BIT_MANIFESTRESOURCE         0x28
#define BIT_NESTEDCLASS              0x29
#define BIT_GENERICPARAM             0x2A
#define BIT_METHODSPEC               0x2B
#define BIT_GENERICPARAMCONSTRAINT   0x2C
// These are not documented in ECMA-335 nor is it clear what the format is.
// They are for debugging information as far as I can tell.
//#define BIT_DOCUMENT               0x30
//#define BIT_METHODDEBUGINFORMATION 0x31
//#define BIT_LOCALSCOPE             0x32
//#define BIT_LOCALVARIABLE          0x33
//#define BIT_LOCALCONSTANT          0x34
//#define BIT_IMPORTSCOPE            0x35
//#define BIT_STATEMACHINEMETHOD     0x36


//
// Element types. Note this is not a complete list as we aren't parsing all of
// them. This only includes the ones we care about.
// ECMA-335 Section II.23.1.16
//
#define ELEMENT_TYPE_STRING 0x0E


// The string length of a typelib attribute is at most 0xFF.
#define MAX_TYPELIB_SIZE 0xFF

//
// Module table
// ECMA-335 Section II.22.30
//
typedef struct _MODULE_TABLE {
    ut16 Generation;
    union {
        ut16 Name_Short;
        ut32 Name_Long;
    } Name;
    union {
        ut16 Mvid_Short;
        ut32 Mvid_Long;
    } Mvid;
    union {
        ut16 EncId_Short;
        ut32 EncId_Long;
    } EncId;
    union {
        ut16 EncBaseId_Short;
        ut32 EncBaseId_Long;
    } EncBaseId;
} MODULE_TABLE, *PMODULE_TABLE;

//
// Assembly Table
// ECMA-335 Section II.22.2
//
typedef struct _ASSEMBLY_TABLE {
    ut32 HashAlgId;
    ut16 MajorVersion;
    ut16 MinorVersion;
    ut16 BuildNumber;
    ut16 RevisionNumber;
    ut32 Flags;
    union {
        ut16 PublicKey_Short;
        ut32 PublicKey_Long;
    } PublicKey;
    union {
        ut16 Name_Short;
        ut32 Name_Long;
    } Name;
} ASSEMBLY_TABLE, *PASSEMBLY_TABLE;


//
// Assembly Reference Table
// ECMA-335 Section II.22.5
//
typedef struct _ASSEMBLYREF_TABLE {
    ut16 MajorVersion;
    ut16 MinorVersion;
    ut16 BuildNumber;
    ut16 RevisionNumber;
    ut32 Flags;
    union {
        ut16 PublicKeyOrToken_Short;
        ut32 PublicKeyOrToken_Long;
    } PublicKeyOrToken;
    union {
        ut16 Name_Short;
        ut32 Name_Long;
    } Name;
} ASSEMBLYREF_TABLE, *PASSEMBLYREF_TABLE;


//
// Manifest Resource Table
// ECMA-335 Section II.22.24
//
typedef struct _MANIFESTRESOURCE_TABLE {
    ut32 Offset;
    ut32 Flags;
    union {
        ut16 Name_Short;
        ut32 Name_Long;
    } Name;
    union {
        ut16 Implementation_Short;
        ut32 Implementation_Long;
    } Implementation;
} MANIFESTRESOURCE_TABLE, *PMANIFESTRESOURCE_TABLE;

//
// ModuleRef Table
// ECMA-335 Section II.22.31
//
// This is a short table, but necessary because the field size can change.
//
typedef struct _MODULEREF_TABLE {
  union {
      ut16 Name_Short;
      ut32 Name_Long;
  } Name;
} MODULEREF_TABLE, *PMODULEREF_TABLE;


//
// CustomAttribute Table
// ECMA-335 Section II.22.10
//
typedef struct _CUSTOMATTRIBUTE_TABLE {
  union {
    ut16 Parent_Short;
    ut32 Parent_Long;
  } Parent;
  union {
    ut16 Type_Short;
    ut32 Type_Long;
  } Type;
  union {
    ut16 Value_Short;
    ut32 Value_Long;
  } Value;
} CUSTOMATTRIBUTE_TABLE, *PCUSTOMATTRIBUTE_TABLE;


//
// Constant TAble
// ECMA-335 Section II.22.9
//
typedef struct _CONSTANT_TABLE {
  ut16 Type;
  union {
    ut16 Parent_Short;
    ut32 Parent_Long;
  } Parent;
  union {
    ut16 Value_Short;
    ut32 Value_Long;
  } Value;
} CONSTANT_TABLE, *PCONSTANT_TABLE;


// Used to return offsets to the various headers.
typedef struct _STREAMS {
    PSTREAM_HEADER guid;
    PSTREAM_HEADER tilde;
    PSTREAM_HEADER string;
    PSTREAM_HEADER blob;
    PSTREAM_HEADER us;
} STREAMS, *PSTREAMS;


// Used to return the value of parsing a #US or #Blob entry.
// ECMA-335 Section II.24.2.4
typedef struct _BLOB_PARSE_RESULT {
    uint8_t size; // Number of bytes parsed. This is the new offset.
    ut32 length; // Value of the bytes parsed. This is the blob length.
} BLOB_PARSE_RESULT, *PBLOB_PARSE_RESULT;


// Used to store the number of rows of each table.
typedef struct _ROWS {
    ut32 module;
    ut32 moduleref;
    ut32 assemblyref;
    ut32 typeref;
    ut32 methoddef;
    ut32 memberref;
    ut32 typedef_;
    ut32 typespec;
    ut32 field;
    ut32 param;
    ut32 property;
    ut32 interfaceimpl;
    ut32 event;
    ut32 standalonesig;
    ut32 assembly;
    ut32 file;
    ut32 exportedtype;
    ut32 manifestresource;
    ut32 genericparam;
    ut32 genericparamconstraint;
    ut32 methodspec;
    ut32 assemblyrefprocessor;
} ROWS, *PROWS;


// Used to store the index sizes for the various tables.
typedef struct _INDEX_SIZES {
    uint8_t string;
    uint8_t guid;
    uint8_t blob;
    uint8_t field;
    uint8_t methoddef;
    uint8_t memberref;
    uint8_t param;
    uint8_t event;
    uint8_t typedef_;
    uint8_t property;
    uint8_t moduleref;
    uint8_t assemblyrefprocessor;
    uint8_t assemblyref;
    uint8_t genericparam;
} INDEX_SIZES, *PINDEX_SIZES;

typedef struct {
	char *name;
	ut64 vaddr;
	ut32 size;
	char *namespace;  // For types
	char *type;       // "typedef", "methoddef", "memberref", "typeref", etc.
	ut32 flags;       // access flags, etc.
	ut32 token;       // Token value for symbolication
	RList *methods;   // List of DotNetMethod pointers
	RList *fields;    // List of DotNetField pointers
} DotNetSymbol;

typedef struct {
	char *name;
	ut64 vaddr;
	ut32 flags;
} DotNetMethod;

typedef struct {
	char *name;
	ut32 flags;
	ut32 offset;
} DotNetField;

typedef struct {
	char *name;
	char *version;
	ut16 major_version;
	ut16 minor_version;
	ut16 build_number;
	ut16 revision_number;
} DotNetLibrary;

typedef struct {
	char *name;
	char *library;  // Native library name for P/Invoke
	int ordinal;
} DotNetImport;

typedef struct {
	ut16 cli_major;
	ut16 cli_minor;
	ut16 asm_major;
	ut16 asm_minor;
	ut16 asm_build;
	ut16 asm_revision;
	char *asm_name;
} DotNetVersionInfo;

#pragma pack(pop)

#ifdef __cplusplus
extern "C" {
#endif

RList* dotnet_parse(const ut8 *buf, int size, ut64 baddr);
RList* dotnet_parse_libs(const ut8 *buf, int size);
RList* dotnet_parse_imports(const ut8 *buf, int size);
DotNetVersionInfo* dotnet_parse_version_info(const ut8 *buf, int size);

#ifdef __cplusplus
}
#endif

#endif
