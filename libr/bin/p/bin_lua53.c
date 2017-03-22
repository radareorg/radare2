
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check_bytes(const ut8 *buf, ut64 length);

int lua53_intSize;
int lua53_sizeSize;
int lua53_instructionSize;
int lua53_luaIntSize;
int lua53_luaNumberSize;

static int init(void *user) {
	fprintf( stderr, "Init\n");
	return 0;
}
static int finit(void *user) {
	fprintf( stderr, "FInit\n");
	return 0;
}
int load(RBinFile *arch){
	fprintf( stderr, "Load\n");
	const ut8 *bytes = arch? r_buf_buffer (arch->buf): NULL;
	ut64 sz = arch? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check(RBinFile *arch) {
	fprintf( stderr, "Check\n");
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

typedef void (*OnFunction) (ut8* data, ut64 size);
typedef void (*OnConst) (ut8* data, ut64 size);
typedef void (*OnUpvalue) (ut8* data, ut64 size);
typedef void (*OnString) (ut8* data, ut64 size);
typedef void (*OnCode) (ut8* data, ut64 size);

ut64 parseFunction(ut8* data, ut64 size, OnFunction onFunc, OnConst onConst, OnUpvalue onUpValue, OnString onString, OnCode onCode);
ut64 parseCode(ut8* data, ut64 size, OnFunction onFunc, OnConst onConst, OnUpvalue onUpValue, OnString onString, OnCode onCode);
	
ut64 parseFunction(ut8* data, ut64 size, OnFunction onFunc, OnConst onConst, OnUpvalue onUpValue, OnString onString, OnCode onCode){
	ut8 functionNameSize = data[0];
	if(functionNameSize != 0 && onString != 0){
		onString(data + 1, functionNameSize);
	}
	ut64 offset = 1 + functionNameSize + lua53_intSize*2 + 3;
	offset += parseCode(data + offset,size - offset, onFunc, onConst, onUpValue, onString, onCode);
	offset += parseConstants(data + offset,size - offset, onFunc, onConst, onUpValue, onString, onCode);
	offset += parseUpvalues(data + offset,size - offset, onFunc, onConst, onUpValue, onString, onCode);
	offset += parseProtos(data + offset,size - offset, onFunc, onConst, onUpValue, onString, onCode);
	offset += parseDebug(data + offset,size - offset, onFunc, onConst, onUpValue, onString, onCode);
	
	return offset;
}
ut64 parseCode(ut8* data, ut64 size, OnFunction onFunc, OnConst onConst, OnUpvalue onUpValue, OnString onString, OnCode onCode){
	
}


static int check_bytes(const ut8 *buf, ut64 length) {
	bool ret = false;
	/**
		Part of the luac implementation:
		DumpLiteral(LUA_SIGNATURE, D);
		DumpByte(LUAC_VERSION, D);
		DumpByte(LUAC_FORMAT, D);
		DumpLiteral(LUAC_DATA, D);
		DumpByte(sizeof(int), D);
		DumpByte(sizeof(size_t), D);
		DumpByte(sizeof(Instruction), D);
		DumpByte(sizeof(lua_Integer), D);
		DumpByte(sizeof(lua_Number), D);
		DumpInteger(LUAC_INT, D);
		DumpNumber(LUAC_NUM, D);
	*/
	if (buf && length>16 && !memcmp (buf, "\x1bLua", 4)) {//check the header
		if(buf[4] != '\x53')//check version
			return false;
		if(memcmp (buf + 6, "\x19\x93\r\n\x1a\n", 6))//for version 5.3
			return false;
		lua53_intSize = buf[12];
		lua53_sizeSize = buf[13];
		lua53_instructionSize = buf[14];
		lua53_luaIntSize = buf[15];
		lua53_luaNumberSize = buf[16];
		if(length <= 16 + lua53_luaIntSize + lua53_luaNumberSize)//check again the length because an int and number is appended
			return false;
		if(memcmp (buf + 17, "\x78\x56\0\0\0\0\0\0", lua53_luaIntSize))//check the appended integer
			return false;
		if(memcmp (buf + 17 + lua53_luaIntSize, "\0\0\0\0\0\x28\x77\x40" + 8 - lua53_luaNumberSize, lua53_luaNumberSize))//check the appended number
			return false;
		ret = true;
	}
	return ret;
}

static RList* sections(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	
	fprintf( stderr, "Sections\n");
	RList *result_list = NULL;
	
	result_list = r_list_newf ((RListFree)free);
	if(!result_list)
		return NULL;
	
	
	RBinSection *headerSection = R_NEW0 (RBinSection);
	if(!headerSection)
		return result_list;
	
	strcpy (headerSection->name, "lua-header");
	headerSection->size = 4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;//header + version + format + stringterminators + sizes + integer + number + upvalues
	headerSection->vaddr = headerSection->paddr = 0;
	headerSection->srwx = R_BIN_SCN_READABLE;
	
	headerSection->bits = 8;
	
	r_list_append (result_list, headerSection);
	
	RBinSection * functionSection = R_NEW0 (RBinSection);
	if(!functionSection)
		return result_list;
	
	strcpy (functionSection->name, "main-function");
	functionSection->size = sz - headerSection->size;//size - headersize
	functionSection->vaddr = functionSection->paddr = 0;
	functionSection->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE;
	
	functionSection->bits = 8;
	functionSection->has_strings = true;
	
	r_list_append (result_list, functionSection);
	
	fprintf( stderr, "End Section\n");
	return result_list;
}

RBinPlugin r_bin_plugin_lua53 = {
	.name = "lua53",
	.desc = "LUA 5.3 bin plugin",
	.license = "MIT",
	.init = &init,
	.fini = &finit,
	.load = &load,
	.size = 0,
	.entries = 0,
	.sections = &sections,
	.check = &check,
	.check_bytes = &check_bytes,
	//.signature = &signature,
	.symbols = 0,
	//.write = &r_bin_write_mach0,
};
	//int (*load)(RBinFile *arch);
	//void *(*load_bytes)(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb);
	//int (*destroy)(RBinFile *arch);
	//int (*check)(RBinFile *arch);
	//int (*check_bytes)(const ut8 *buf, ut64 length);
	//ut64 (*baddr)(RBinFile *arch);	
	//ut64 (*boffset)(RBinFile *arch);
	//RBinAddr* (*binsym)(RBinFile *arch, int num);
	//RList/*<RBinDwarfRow>*/* (*lines)(RBinFile *arch);
	//RList/*<RBinImport>*/* (*imports)(RBinFile *arch);
	//RList/*<RBinString>*/* (*strings)(RBinFile *arch);
	//RBinInfo/*<RBinInfo>*/* (*info)(RBinFile *arch);
	//RList/*<RBinField>*/* (*fields)(RBinFile *arch);
	//RList/*<char *>*/* (*libs)(RBinFile *arch);
	//RList/*<RBinMem>*/* (*mem)(RBinFile *arch);
	//void (*header)(RBinFile *arch);
	/*char* (*signature)(RBinFile *arch);
	int (*demangle_type)(const char *str);
	struct r_bin_dbginfo_t *dbginfo;
	struct r_bin_write_t *write;
	int (*get_offset)(RBinFile *arch, int type, int idx);
	char* (*get_name)(RBinFile *arch, int type, int idx);
	ut64 (*get_vaddr)(RBinFile *arch, ut64 baddr, ut64 paddr, ut64 vaddr);
	RBuffer* (*create)(RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen);
	char* (*demangle)(const char *str);
	int minstrlen;
	char strfilter;
	void *user;*/

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_lua53,
	.version = R2_VERSION
};
#endif