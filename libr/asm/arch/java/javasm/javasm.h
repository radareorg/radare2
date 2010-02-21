#include <r_types.h>


#define USHORT(x,y) (unsigned short)(x[y+1]|(x[y]<<8))
#define UINT(x,y) (unsigned int) ((x[y]<<24)|(x[y+1]<<16)|(x[y+2]<<8)|x[y+3])

struct classfile {
	unsigned char cafebabe[4];
	unsigned char minor[2];
	unsigned char major[2];
	unsigned short cp_count;
};

struct classfile2 {
	unsigned short access_flags;
	unsigned short this_class;
	unsigned short super_class;
};

struct cp_item {
	int tag;
	char name[255];
	char *value;
	unsigned char bytes[5];
	ut64 off;
};

//extern struct cp_item *cp_items;
//extern struct cp_item cp_null_item; // NOTE: must be initialized for safe use

int java_print_opcode(int idx, const ut8 *bytes, char *output);
int java_disasm(const ut8 *bytes, char *output);
int java_assemble(unsigned char *bytes, const char *string);
unsigned short read_short(FILE *fd);
int javasm_init();
int java_classdump(const char *file);
