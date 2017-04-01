
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "../../anal/arch/lua53/lua53_parser.c"


static int check_bytes(const ut8 *buf, ut64 length);

static int init(void *user) {
	Dprintf ("Init\n");
	return 0;
}
static int finit(void *user) {
	Dprintf ("FInit\n");
	if(lua53_data.functionList){
		r_list_free (lua53_data.functionList);
		lua53_data.functionList = 0;
	}
	return 0;
}
int load(RBinFile *arch){
	Dprintf ("Load\n");
	const ut8 *bytes = arch? r_buf_buffer (arch->buf): NULL;
	ut64 sz = arch? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static int check(RBinFile *arch) {
	Dprintf ("Check\n");
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}



static int check_bytes(const ut8 *buf, ut64 length) {
	ParseStruct parseStruct;
	ut64 parsedbytes = parseHeader (buf,0,length,&parseStruct);
	if(parsedbytes)
		Dprintf ( "It is a Lua Binary!!!\n");
	return parsedbytes != 0;
}

static void addSection (RList *list, const char *name, ut64 addr, ut32 size, bool isFunc) {
	RBinSection *binSection = R_NEW0 (RBinSection);
	if (!binSection) return;
	
	strcpy (binSection->name, name);
	
	binSection->vaddr = binSection->paddr = addr;
	binSection->size = binSection->vsize = size;
	binSection->add = true;
	binSection->is_data = false;
	binSection->bits = isFunc ? 8*lua53_data.instructionSize : 8;
	binSection->has_strings = !isFunc;
	binSection->arch = strdup("lua53");
	if(isFunc){
		binSection->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	}else
		binSection->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
	
	r_list_append (list, binSection);
}

void addSections (LuaFunction* func, ParseStruct* parseStruct){
	
	char* string;
	if(func->name_size == 0 || func->name_ptr == 0){
		string = malloc (11);
		sprintf (string,"0x%"PFMT64x,func->offset);
	}else{
		string = malloc (func->name_size + 1);
		memcpy(string,func->name_ptr,func->name_size);
		string[func->name_size] = '\0';
	}
	
	char string_buffer[R_BIN_SIZEOF_STRINGS + 1];
	
	sprintf (string_buffer,"header.%s",string);
	addSection (parseStruct->data,string_buffer,func->offset,func->code_offset - func->offset, false);
	
	sprintf (string_buffer,"code.%s",string);
	addSection (parseStruct->data,string_buffer,func->code_offset,func->const_offset - func->code_offset, true);//code section also holds codesize
	
	sprintf (string_buffer,"consts.%s",string);
	addSection (parseStruct->data,string_buffer,func->const_offset,func->upvalue_offset - func->const_offset, false);
	
	sprintf (string_buffer,"upvalues.%s",string);
	addSection (parseStruct->data,string_buffer,func->upvalue_offset,func->protos_offset - func->upvalue_offset, false);
	
	sprintf (string_buffer,"debuginfo.%s",string);
	addSection (parseStruct->data,string_buffer,func->debug_offset,func->offset + func->size - func->debug_offset, false);
	
	r_str_free (string);
}
static RList* sections (RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	
	Dprintf ("Sections\n");
	
	ParseStruct parseStruct;
	memset (&parseStruct,0,sizeof(parseStruct));
	parseStruct.onFunction = addSections;
	
	parseStruct.data = r_list_newf ((RListFree)free);
	if(!parseStruct.data)
		return NULL;
	
	ut64 headersize =  4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;//header + version + format + stringterminators + sizes + integer + number + upvalues
	addSection (parseStruct.data,"lua-header",0,headersize, false);
	
	//parse functions
	parseFunction (bytes,headersize,sz,0,&parseStruct);
	
	Dprintf ("End Section\n");
	return parseStruct.data;
}

void addString(const ut8 *buf, ut64 offset, ut64 length,ParseStruct* parseStruct){
	RBinString* binstring = R_NEW0 (RBinString);
	
	if(binstring == NULL)
		return;
	
	binstring->string = r_str_newlen ((char*)buf + offset,length);
	binstring->vaddr = binstring->paddr = offset;
	binstring->ordinal = 0;
	binstring->size = length;
	binstring->length = length;
	r_list_append (parseStruct->data, binstring);
}

void addSymbol (RList *list, char *name, ut64 addr, ut32 size, const char* type) {
	
	RBinSymbol* binSymbol = R_NEW0 (RBinSymbol);
	if(binSymbol == NULL)
		return;
	
	binSymbol->name = strdup (name);
	
	binSymbol->vaddr = binSymbol->paddr = addr;
	binSymbol->size = size;
	binSymbol->ordinal = 0;
	binSymbol->type = type;
	r_list_append (list, binSymbol);
}
void handleFuncSymbol (LuaFunction* func, ParseStruct* parseStruct){
	
	RBinSymbol* binSymbol = R_NEW0 (RBinSymbol);
	
	if(binSymbol == NULL)
		return;
	
	char* string;
	if(!func->name_ptr || !func->name_size){
		string = malloc (11);
		sprintf (string,"0x%"PFMT64x,func->offset);
	}else{
		string = malloc (func->name_size + 1);
		memcpy(string,func->name_ptr,func->name_size);
		int i;
		for(i = 0; i < func->name_size;i++)
			if(string[i] == '@')
				string[i] = '_';
		string[func->name_size] = '\0';
	}
	char string_buffer[R_BIN_SIZEOF_STRINGS + 1];
	
	
	
	sprintf (string_buffer,"lineDefined.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset - 3 - 2*lua53_data.intSize,lua53_data.intSize,"NUM");
	sprintf (string_buffer,"lastLineDefined.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset - 3 - lua53_data.intSize,lua53_data.intSize,"NUM");
	sprintf (string_buffer,"numParams.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset - 3,1,"NUM");
	sprintf (string_buffer,"isVarArg.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset - 2,1,"BOOL");
	sprintf (string_buffer,"maxStackSize.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset - 1,1,"BOOL");
	
	sprintf (string_buffer,"codesize.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset,lua53_data.intSize,"NUM");
	
	sprintf (string_buffer,"func.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->code_offset + lua53_data.intSize,lua53_data.instructionSize*func->code_size,"FUNC");
	
	sprintf (string_buffer,"constsize.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->const_offset,lua53_data.intSize,"NUM");
	
	sprintf (string_buffer,"upvaluesize.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->upvalue_offset,lua53_data.intSize,"NUM");
	
	sprintf (string_buffer,"prototypesize.%s",string);
	addSymbol (parseStruct->data,string_buffer,func->protos_offset,lua53_data.intSize,"NUM");
	
	r_str_free (string);
}


static RList* strings(RBinFile *arch) {
	
	Dprintf ("Strings\n");
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	ut64 headersize =  4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;//header + version + format + stringterminators + sizes + integer + number + upvalues
	
	ParseStruct parseStruct;
	memset (&parseStruct,0,sizeof (parseStruct));
	parseStruct.onString = addString;
	
	parseStruct.data = r_list_new ();
	if(!parseStruct.data)
		return NULL;
	
	parseFunction (bytes,headersize,sz,0,&parseStruct);
	
	Dprintf ("End Strings\n");
	return parseStruct.data;
}
static RList* symbols(RBinFile *arch) {
	
	Dprintf ("Symbols\n");
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	ut64 headersize =  4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;//header + version + format + stringterminators + sizes + integer + number + upvalues
	
	ParseStruct parseStruct;
	memset (&parseStruct,0,sizeof(parseStruct));
	parseStruct.onFunction = handleFuncSymbol;
	parseStruct.data = NULL;
	
	parseStruct.data = r_list_new ();
	if(!parseStruct.data)
		return NULL;
	
	addSymbol (parseStruct.data,"lua-header",0,4,"NOTYPE");
	addSymbol (parseStruct.data,"lua-version",4,1,"NOTYPE");
	addSymbol (parseStruct.data,"lua-format",5,1,"NOTYPE");
	addSymbol (parseStruct.data,"stringterminators",6,6,"NOTYPE");
	addSymbol (parseStruct.data,"int-size",12,1,"NUM");
	addSymbol (parseStruct.data,"size-size",13,1,"NUM");
	addSymbol (parseStruct.data,"instruction-size",14,1,"NUM");
	addSymbol (parseStruct.data,"lua-int-size",15,1,"NUM");
	addSymbol (parseStruct.data,"lua-number-size",16,1,"NUM");
	addSymbol (parseStruct.data,"check-int",17,bytes[15],"NUM");
	addSymbol (parseStruct.data,"check-number",17 + bytes[15],bytes[16],"FLOAT");
	addSymbol (parseStruct.data,"upvalues",17 + bytes[15] + bytes[16],1,"NUM");
	
	parseFunction (bytes,headersize,sz,0,&parseStruct);
	
	Dprintf ("End Symbols\n");
	return parseStruct.data;
}
static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->file = strdup (arch->file);
	ret->type = strdup ("lua53");
	ret->os = strdup ("any");
	ret->machine = strdup ("LUA 5.3 VM");
	ret->arch = strdup ("lua53");
	ret->bits = lua53_data.instructionSize * 8;
	ret->has_va = 1;
	ret->big_endian = 0;
	return ret;
}
void addEntry (LuaFunction* func, ParseStruct* parseStruct){
	
	if(func->parent_func == NULL){
		RBinAddr *ptr = NULL;
		if ((ptr = R_NEW0 (RBinAddr))) {
			ptr->paddr = func->code_offset + lua53_data.intSize;
			ptr->vaddr = func->code_offset + lua53_data.intSize;
			r_list_append (parseStruct->data, ptr);
		}
	}
}
static RList* entries(RBinFile *arch) {
	Dprintf ("Entries\n");
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	ut64 headersize =  4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;//header + version + format + stringterminators + sizes + integer + number + upvalues
	
	ParseStruct parseStruct;
	memset (&parseStruct,0,sizeof(parseStruct));
	parseStruct.onFunction = addEntry;
	parseStruct.data = NULL;
	
	parseStruct.data = r_list_new ();
	if(!parseStruct.data)
		return NULL;
	
	parseFunction (bytes,headersize,sz,0,&parseStruct);
	
	Dprintf ("End Entries\n");
	return parseStruct.data;
}

RBinPlugin r_bin_plugin_lua53 = {
	.name = "lua53",
	.desc = "LUA 5.3 bin plugin",
	.license = "MIT",
	.init = &init,
	.fini = &finit,
	.load = &load,
	.sections = &sections,
	.check = &check,
	.check_bytes = &check_bytes,
	.symbols = &symbols,
	.strings = &strings,
	.info = &info,
	.entries = &entries,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_lua53,
	.version = R2_VERSION
};
#endif