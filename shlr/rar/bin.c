#if 0
entry0 = 0x9a
header:
526172211a0700f94e7300000e0000000000000000a197740000260003010000000000000210415221000000001d000600000000207374646f75742021550ccd10cd981181c8301d6be017692bf82af42bd4afe87a32f4e665e65e6c30e6d124f2003d93c9e689ec9ec9eb30b8e47a731ebd6b61ddeb3430bb76a83030f0304b30003000303e0ff77f30f9dc9da110700adc00000003000000a4


-- offset -  0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000000  5261 7221 1a07 00f9 4e73 0000 0e00 0000  Rar!....Ns......
0x00000010  0000 0000 008b 0074 0000 2600 0901 0000  .......t..&.....
0x00000020  0000 0000 0210 4152 2100 0000 001d 0006  ......AR!.......
0x00000030  0000 0000 2073 7464 6f75 7420 2155 0ccd  .... stdout !U..
0x00000040  10cd 9811 81c8 301d 6be0 1769 2bf8 2af4  ......0.k..i+.*.
0x00000050  2bd4 afe8 7a32 f4e6 65e6 5e6c 30e6 d124  +...z2..e.^l0..$
0x00000060  f200 3d93 c9e6 89ec 9ec9 eb30 b8e4 7a73  ..=........0..zs
0x00000070  1ebd 6b61 ddeb 3430 bb76 a830 30f0 304b  ..ka..40.v.00.0K
0x00000080  3000 3000 303e 0ff7 7f30 f9dc 9da1 1070  0.0.0>...0.....p
0x00000090  0b3c 0000 0003 0000 00aa                 .<........     

-- offset -  0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000000  5261 7221 1a07 00f9 4e73 0000 0e00 0000  Rar!....Ns......
0x00000010  0000 0000 00a1 9774 0000 2600 0301 0000  .......t..&..... <--------
0x00000020  0000 0000 0210 4152 2100 0000 001d 0006  ......AR!.......
0x00000030  0000 0000 2073 7464 6f75 7420 2155 0ccd  .... stdout !U..
0x00000040  10cd 9811 81c8 301d 6be0 1769 2bf8 2af4  ......0.k..i+.*.
0x00000050  2bd4 afe8 7a32 f4e6 65e6 5e6c 30e6 d124  +...z2..e.^l0..$
0x00000060  f200 3d93 c9e6 89ec 9ec9 eb30 b8e4 7a73  ..=........0..zs
0x00000070  1ebd 6b61 ddeb 3430 bb76 a830 30f0 304b  ..ka..40.v.00.0K
0x00000080  3000 3000 303e 0ff7 7f30 f9dc 9da1 1070  0.0.0>...0.....p
0x00000090  0adc 0000 0003 0000 00a4                 ..........       <--------


0x15 : 0x8b00 -> 0xa197
0x1c : 0x09 -> 0x03
0x90 : 0x0b3c -> 0x0adc
0x99 : 0xaa -> 0xa4
#endif

#include <stdio.h>
#include <stdlib.h>
// crc32
#include "../../libr/hash/crc32.c"

#define eprintf(x,y...) fprintf(stderr,x,##y)

#pragma pack(1)
typedef struct rar_block_t {
	unsigned short crc;
	unsigned char type;
	unsigned short flags;
	unsigned short size;
	unsigned int add_size;
} __attribute((__packed__)) RarBlock;

typedef struct rar_block_archive_t {
	unsigned int pack_size;
	unsigned int unpack_size;
	unsigned char os; // [msdos,os2,w32,unix,osx,beos]
	unsigned int crc;
	unsigned int ftime; // datetime (dos format)
	unsigned char rarversion; // datetime
	unsigned char packmethod;
#if 0
	0x30 - storing
	0x31 - fastest compression
	0x32 - fast compression
	0x33 - normal compression
	0x34 - good compression
	0x35 - best compression
#endif
	unsigned short filenamesize;
	unsigned int file_attr;
	unsigned int high_pack_size;
	unsigned int high_unpack_size;
	char *filename;
	// unsigned long long salt;
	// ext_time: present if flags &0x1000) variable size
} __attribute((__packed__)) RarBlockArchive;
typedef struct {
	unsigned short    crc;
	unsigned char     type;
	unsigned short    flags;
	unsigned short    size;
} hdr_t;
struct filehdr {
	hdr_t       hdr;
	unsigned int    PackSize;
	unsigned int    UnpSize;
	unsigned char     HostOS;
	unsigned int    FileCRC;
	unsigned int    FileTime;
	unsigned char     UnpVer;
	unsigned char     Method;
	unsigned short    NameSize;
	union {
		unsigned int    FileAttr;
		unsigned int    SubFlags;
	};
	unsigned char     FileName[6];
};
#if 0
HIGH_PACK_SIZE  High 4 bytes of 64 bit value of compressed file size.
4 bytes         Optional value, presents only if bit 0x100 in HEAD_FLAGS
is set.

HIGH_UNP_SIZE   High 4 bytes of 64 bit value of uncompressed file size.
4 bytes         Optional value, presents only if bit 0x100 in HEAD_FLAGS
is set.

FILE_NAME       File name - string of NAME_SIZE bytes size

SALT            present if (HEAD_FLAGS & 0x400) != 0
8 bytes

EXT_TIME        present if (HEAD_FLAGS & 0x1000) != 0
variable size
#endif

static inline unsigned short shortswap(unsigned short s) {
	unsigned char c, *b = (unsigned char *)&s;
	c = b[1]; b[1] = b[0]; b[0] = c;
	return s;
}

static int israr(unsigned char *b, int sz) {
	return (sz>4 && b[0]==0x52 && b[1]==0x61);
}

static int parseBlock(unsigned char *b, int sz) {
#if 0
HEAD_CRC       2 bytes     CRC of total block or block part
HEAD_TYPE      1 byte      Block type
HEAD_FLAGS     2 bytes     Block flags
HEAD_SIZE      2 bytes     Block size
ADD_SIZE       4 bytes     Optional field - added block size
Field ADD_SIZE present only if (HEAD_FLAGS & 0x8000) != 0
#endif
struct filehdr *fhdr;
	RarBlockArchive *rba;
	RarBlock *rb = (RarBlock*) b;
	int i, n, blocksize; // = headsize
	// TODO: check size of rarblockstruct and sz
	//printf ("Flags : %x\n", rb->flags);
	printf ("Type: 0x%x\n", rb->type);
	//rb->flags = shortswap (rb->flags);
	printf ("   Flags: 0x%x\n", rb->flags);
	printf ("   Size: 0x%x\n", rb->size);
#if 0
	// flags
0x4000 : ignored block on old rars
		 0x8000 : add size
#endif
	 switch (rb->type) {
	 case 0x72:
		 //sequence: 0x52 0x61 0x72 0x21 0x1a 0x07 0x00
		 eprintf ("   + marker block\n");
		 break;
	 case 0x73:
		eprintf ("   + archive header (flags=%x)\n", rb->flags);
		rba = b+7;
		for (i=0;i<rb->size&&i<sz; i++) 
			printf ("%02x ", b[7+i]);
		printf("\n");
		fhdr = b;
		printf ("~~~~~(0x%x)~~~~~\n",
				 fhdr->FileAttr);
printf ("SZ %x %x %x\n", fhdr->PackSize, fhdr->UnpSize , fhdr->FileCRC);
		 if (fhdr->FileAttr & 0x20000000) {
			 printf ("IS CODE!\n");
		 }
		 //rba->file_attr);
		 printf ("FILENAME (");
		{
			int i;
			char mark = b[rb->size+31];
			for (i=0; b[rb->size+32+i] != mark; i++) {
				printf ("%c", b[rb->size+32+i]);
			}
		}
		printf (")\n");
//printf ("FILENAME (%s)\n", b+rb->size +32);//rba->filename);
		if (rb->flags & 0x400) {
			printf ("~~~~bonus 8\n");
		}
		if (rb->flags & 0x200) {
			printf ("utf8\n");
		}
		//sequence: 0x52 0x61 0x72 0x21 0x1a 0x07 0x00
#if 0
HEAD_FLAGS      Bit flags:
2 bytes
0x0001  - Volume attribute (archive volume)
0x0002  - Archive comment present
RAR 3.x uses the separate comment block
and does not set this flag.

0x0004  - Archive lock attribute
0x0008  - Solid attribute (solid archive)
0x0010  - New volume naming scheme (‘volname.partN.rar’)
0x0020  - Authenticity information present
RAR 3.x does not set this flag.

0x0040  - Recovery record present
0x0080  - Block headers are encrypted
0x0100  - First volume (set only by RAR 3.0 and later)
#endif
		break;
	case 0x74:
// File header full size including file name and comments
		eprintf ("   + file header\n");
for(i=0;i<32;i++) {
printf ("%02x ", b[i+38]);
}
printf ("\n");
return 32;
		break;
	case 0x7a:
		eprintf ("   + old block is old\n");
		break;
	default:
		eprintf ("   + Unknown block type 0x%x\n", rb->type);
		break;
	}
#if 0
HEAD_TYPE=0x72          marker block
HEAD_TYPE=0x73          archive header
HEAD_TYPE=0x74          file header
HEAD_TYPE=0x75          old style comment header
HEAD_TYPE=0x76          old style authenticity information
HEAD_TYPE=0x77          old style subblock
HEAD_TYPE=0x78          old style recovery record
HEAD_TYPE=0x79          old style authenticity information
HEAD_TYPE=0x7a          subblock
#endif
	if (rb->flags & 0x8000) {
		n = rb->size + rb->add_size;
	} else {
		n = rb->size;
	}
	printf ("   + SIZE: %d\n", n);
	return n;
}

static int parse_rar(unsigned char *b, int sz) {
	int idx = 0;
	if (!israr (b, sz)) {
		eprintf ("File is not rar\n");
		return 0;
	}
	while (idx<sz) {
		idx += parseBlock (b+idx, sz-idx);
	}
}

int main() {
	const char *rarfile = "helloworld.rar";
	FILE *fd = fopen (rarfile, "r");
	unsigned char buf[4096];
	if (fd) {
		int size = fread (buf, 1, sizeof (buf), fd);
		parse_rar (buf, size);
		fclose (fd);
	} else eprintf ("Cannot open rarfile\n");
	return 0;
}
