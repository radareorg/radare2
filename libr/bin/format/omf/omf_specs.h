#ifndef OMF_SPECS_H_
#define OMF_SPECS_H_

// additionnal informations : http://pierrelib.pagesperso-orange.fr/exec_formats/OMF_v1.1.pdf

// record type
#define OMF_THEADR	0x80  // Translator Header Record
#define OMF_LHEADR	0x82  // Library Module Header Record
#define OMF_COMENT	0x88  // Comment Record (Including all comment class extensions)
#define OMF_MODEND	0x8A  // Module End Record 16 bits
#define OMF_MODEND32	0x8B  // Module End Record 32 bits
#define OMF_EXTDEF	0x8C  // External Names Definition Record
#define OMF_PUBDEF	0x90  // Public Names Definition Record 16 bits
#define OMF_PUBDEF32	0x91  // Public Names Definition Record 32 bits
#define OMF_LINNUM	0x94  // Line Numbers Record 16 bits
#define OMF_LINNUM32	0x95  // Line Numbers Record 32 bits
#define OMF_LNAMES	0x96  // List of Names Record
#define OMF_SEGDEF	0x98  // Segment Definition Record bits 16
#define OMF_SEGDEF32	0x99  // Segment Definition Record bits 32
#define OMF_GRPDEF	0x9A  // Group Definition Record
#define OMF_FIXUPP	0x9C  // Fixup Record 16 bits
#define OMF_FIXUPP32	0x9D  // Fixup Record 32 bits
#define OMF_LEDATA	0xA0  // Logical Enumerated Data Record 16 bits
#define OMF_LEDATA32	0xA1  // Logical Enumerated Data Record 32 bits
#define OMF_LIDATA	0xA2  // Logical Iterated Data Record 16 bits
#define OMF_LIDATA32	0xA3  // Logical Iterated Data Record 32 bits
#define OMF_COMDEF	0xB0  // Communal Names Definition Record
#define OMF_BAKPAT	0xB2  // Backpatch Record 16 bits
#define OMF_BAKPAT32	0xB3  // Backpatch Record 32 bits
#define OMF_LEXTDEF	0xB4  // Local External Names Definition Record
#define OMF_LPUBDEF	0xB6  // Local Public Names Definition Record 16 bits
#define OMF_LPUBDEF32	0xB7  // Local Public Names Definition Record 32 bits
#define OMF_LCOMDEF	0xB8  // Local Communal Names Definition Record
#define OMF_CEXTDEF	0xBC  // COMDAT External Names Definition Record
#define OMF_COMDAT	0xC2  // Initialized Communal Data Record 16 bits
#define OMF_COMDAT32	0xC3  // Initialized Communal Data Record 32 bits
#define OMF_LINSYM	0xC4  // Symbol Line Numbers Record 16 bits
#define OMF_LINSYM32	0xC5  // Symbol Line Numbers Record 32 bits
#define OMF_ALIAS	0xC6  // Alias Definition Record
#define OMF_NBKPAT	0xC8  // Named Backpatch Record 16 bits
#define OMF_NBKPAT32	0xC9  // Named Backpatch Record 32 bits
#define OMF_LLNAMES	0xCA  // Local Logical Names Definition Record
#define OMF_VERNUM	0xCC  // OMF Version Number Record
#define OMF_VENDEXT	0xCE  // Vendor-specific OMF Extension Record

// comment type
#define OMF_COMENT_EXT		0xA0 // OMF extensions
#define OMF_COMENT_NEW_EXT	0xA1 // OMF new extensions
#define OMF_COMENT_LINK_SEP	0xA2 // Link Pass Separator
#define OMF_COMENT_LIBMOD	0xA3 // Library module comment record
#define OMF_COMENT_EXESTR	0xA4 // executable string
#define OMF_COMENT_INCERR	0xA6 // Incremental compilation error
#define OMF_COMENT_NOPAD	0xA7 // No segment padding
#define OMF_COMENT_WKEXT	0xA8 // Weak Extern record
#define OMF_COMENT_LZEXT	0xA9 // Lazy Extern record
#define OMF_COMENT_COMMENT	0xDA // random comment
#define OMF_COMENT_COMPIL	0xDB // compiler comment (version number)
#define OMF_COMENT_DATE		0xDC // date
#define OMF_COMENT_TIMESTAMP	0xDD // timestamp
#define OMF_COMENT_USER		0xDF // user's comment
#define OMF_COMENT_DEP_FILE	0xE9 // Borland : Show include file needed for building
#define OMF_COMENT_CMD_LINE	0xFF // Microsoft QuickC : Shows the compiler options chosen

// comment extensions subtype
#define OMF_COMENT_EXT_IMPDEF	0x01 // Import definition record
#define OMF_COMENT_EXT_EXPDEF	0x02 // Export definition record
#define OMF_COMENT_EXT_INCDEF	0x03 // Incremental compilation record
#define OMF_COMENT_EXT_PMEM_LIB	0x04 // Protect loading for 32 bits library
#define OMF_COMENT_EXT_LNKDIR	0x05 // Microsoft C++ linker directives record
#define OMF_COMENT_EXT_BIG_E	0x06 // Target machine is big endian

typedef struct {
	ut8 type;
	ut16 size;
	void *content;
	ut8 checksum;
} OMF_record;

#endif
