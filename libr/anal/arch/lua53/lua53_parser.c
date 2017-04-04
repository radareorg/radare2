#include <r_types.h>

#ifdef LUA_DEBUG
	#define Dprintf(...) eprintf(__VA_ARGS__)
#else
	#define Dprintf(...)
#endif


struct{
	int intSize;
	int sizeSize;
	int instructionSize;
	int luaIntSize;
	int luaNumberSize;
	RList* functionList;
} lua53_data;


static ut64 parseNumber(const ut8* data, ut64 bytesize){
	int i;
	ut64 res = 0;
	for(i = 0; i < bytesize;i++){
		res |= ((ut64)data[i]) << (8*i);
	}
	return res;
}

#define parseInt(data) parseNumber(data, lua53_data.intSize)
#define parseSize(data) parseNumber(data, lua53_data.sizeSize)
#define parseInstruction(data) parseNumber(data, lua53_data.instructionSize)
#define parseLuaInt(data) parseNumber(data, lua53_data.luaIntSize)
#define parseLuaNumber(data) parseNumber(data, lua53_data.luaNumberSize)


typedef struct lua_function{
	ut64 offset;

	char* name_ptr;//only valid in onFunction methon
	ut64 name_size;

	ut64 lineDefined;
	ut64 lastLineDefined;
	ut8 numParams;
	ut8 isVarArg;
	ut8 maxStackSize;

	struct lua_function* parent_func;//if != NULL, should always be valid

	ut64 const_size;
	ut64 code_size;
	ut64 upvalue_size;
	ut64 protos_size;

	ut64 const_offset;
	ut64 code_offset;
	ut64 upvalue_offset;
	ut64 protos_offset;
	ut64 debug_offset;

	ut64 size;
} LuaFunction;

RList *lua53_function_list;

struct lua_parse_struct;

typedef void (*OnFunction) (LuaFunction* function, struct lua_parse_struct* parseStruct);
typedef void (*OnString) (const ut8* data, ut64 offset, ut64 size, struct lua_parse_struct* parseStruct);
typedef void (*OnConst) (const ut8* data, ut64 offset, ut64 size, struct lua_parse_struct* parseStruct);

typedef struct lua_parse_struct{
	OnString onString;
	OnFunction onFunction;
	OnConst onConst;
	void* data;
} ParseStruct;

LuaFunction* lua53findLuaFunctionByCodeAddr(ut64 addr){
	if(!lua53_data.functionList)
		return NULL;
	LuaFunction *function = NULL;
	RListIter *iter = NULL;
	r_list_foreach (lua53_data.functionList, iter, function) {
		if(function->code_offset +  lua53_data.intSize <= addr && addr < function->const_offset)
			return function;
	}
	return NULL;
}

static int storeLuaFunction(LuaFunction* function){
	if(!lua53_data.functionList){
		lua53_data.functionList = r_list_new ();
		if(!lua53_data.functionList){
			return 0;
		}
	}
	r_list_append (lua53_data.functionList,function);
	return 1;
}

static LuaFunction* findLuaFunction(ut64 addr){
	if(!lua53_data.functionList)
		return NULL;
	LuaFunction *function = NULL;
	RListIter *iter = NULL;
	r_list_foreach (lua53_data.functionList, iter, function) {
		Dprintf ("Search 0x%"PFMT64x"\n",function->offset);
		if(function->offset == addr)
			return function;
	}
	return NULL;
}

ut64 lua53parseHeader (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
ut64 lua53parseFunction (const ut8* data, ut64 offset, const ut64 size, LuaFunction* parent_func, ParseStruct* parseStruct);

static ut64 parseString (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
static ut64 parseStringR (const ut8* data, ut64 offset, const ut64 size, char** str_ptr, ut64* str_len, ParseStruct* parseStruct);
static ut64 parseCode (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
static ut64 parseConstants (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
static ut64 parseUpvalues (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
static ut64 parseProtos (const ut8* data, ut64 offset, const ut64 size, LuaFunction* func, ParseStruct* parseStruct);
static ut64 parseDebug (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);

ut64 lua53parseHeader(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){

	if (data && offset + 16 <= size && !memcmp (data + offset, "\x1bLua", 4)) {//check the header
		offset += 4;
		if(data[offset + 0] != '\x53')//check version
			return 0;
		//skip format byte
		offset += 2;
		if(memcmp (data + offset, "\x19\x93\r\n\x1a\n", 6))//for version 5.3
			return 0;
		offset += 6;
		lua53_data.intSize = data[offset + 0];
		lua53_data.sizeSize = data[offset + 1];
		lua53_data.instructionSize = data[offset + 2];
		lua53_data.luaIntSize = data[offset + 3];
		lua53_data.luaNumberSize = data[offset + 4];

		Dprintf ("Int Size: %i\n",lua53_data.intSize);
		Dprintf ("Size Size: %i\n",lua53_data.sizeSize);
		Dprintf ("Instruction Size: %i\n",lua53_data.instructionSize);
		Dprintf ("Lua Int Size: %i\n",lua53_data.luaIntSize);
		Dprintf ("Lua Number Size: %i\n",lua53_data.luaNumberSize);

		offset += 5;
		if(offset + lua53_data.luaIntSize + lua53_data.luaNumberSize >= size)//check again the remainingsize because an int and number is appended to the header
			return 0;
		if(parseLuaInt (data + offset) != 0x5678)//check the appended integer
			return 0;
		offset += lua53_data.luaIntSize;
		ut64 num = parseLuaNumber (data + offset);
		if(*((double*)&num) != 370.5)//check the appended number
			return 0;
		offset += lua53_data.luaNumberSize;
		Dprintf ("Is a Lua Binary\n");
		return offset;
	}
	return 0;
}

ut64 lua53parseFunction (const ut8* data, ut64 offset, const ut64 size, LuaFunction* parent_func, ParseStruct* parseStruct){
	Dprintf ("Function 0x%"PFMT64x"\n",offset);
	LuaFunction* function = findLuaFunction (offset);
	if(function){//if a function object was cached
		Dprintf ("Found cached Functione: 0x%"PFMT64x"\n",function->offset);

		if(parseStruct != NULL && parseStruct->onString != NULL)
			parseConstants (data, function->const_offset, size, parseStruct);

		parseProtos (data, function->protos_offset, size, function, parseStruct);

		if(parseStruct != NULL && parseStruct->onString != NULL)
			parseDebug (data, function->debug_offset, size, parseStruct);

		if(parseStruct != NULL && parseStruct->onFunction != NULL)
			parseStruct->onFunction (function, parseStruct);
		return offset + function->size;
	}else{
		ut64 baseoffset = offset;

		function = R_NEW0 (LuaFunction);
		function->parent_func = parent_func;
		function->offset = offset;
		offset = parseStringR (data, offset, size, &function->name_ptr, &function->name_size, parseStruct);
		if(offset == 0) return 0;

		function->lineDefined = parseInt (data + offset);
		Dprintf ("Line Defined: %"PFMT64x"\n",function->lineDefined);
		function->lastLineDefined = parseInt (data + offset + lua53_data.intSize);
		Dprintf ("Last Line Defined: %"PFMT64x"\n",function->lastLineDefined);
		offset += lua53_data.intSize*2;
		function->numParams = data[offset + 0];
		Dprintf ("Param Count: %d\n",function->numParams);
		function->isVarArg = data[offset + 1];
		Dprintf ("Is VarArgs: %d\n",function->isVarArg);
		function->maxStackSize = data[offset + 2];
		Dprintf ("Max Stack Size: %d\n",function->maxStackSize);
		offset += 3;

		function->code_offset = offset;
		function->code_size = parseInt (data + offset);
		offset = parseCode (data, offset, size, parseStruct);
		if(offset == 0) return 0;
		function->const_offset = offset;
		function->const_size = parseInt (data + offset);
		offset = parseConstants (data, offset, size, parseStruct);
		if(offset == 0) return 0;
		function->upvalue_offset = offset;
		function->upvalue_size = parseInt (data + offset);
		offset = parseUpvalues (data, offset, size, parseStruct);
		if(offset == 0) return 0;
		function->protos_offset = offset;
		function->protos_size = parseInt (data + offset);
		offset = parseProtos (data, offset, size, function, parseStruct);
		if(offset == 0) return 0;
		function->debug_offset = offset;
		offset = parseDebug (data, offset, size, parseStruct);
		if(offset == 0) return 0;

		function->size = offset - baseoffset;
		if(parseStruct && parseStruct->onFunction)
			parseStruct->onFunction (function, parseStruct);
		if(!storeLuaFunction (function)){
			free (function);
		}
		return offset;
	}
}
static ut64 parseCode(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	if(offset + lua53_data.intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;

	if(offset + length*lua53_data.instructionSize >= size)
		return 0;
	Dprintf ("Function has %"PFMT64x" Instructions\n",length);

	return offset + length*lua53_data.instructionSize;
}
static ut64 parseConstants(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	if(offset + lua53_data.intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;
	Dprintf ("Function has %"PFMT64x" Constants\n",length);

	int i;
	for(i = 0;i < length; i++){
		Dprintf ("%d: ",i);
		ut8 type = data[offset + 0];
		offset += 1;
		switch(type){
			case 0://Nil
				Dprintf ("Nil\n");
			break;
			case 1://Boolean
				Dprintf ("Boolean %d\n",data[offset + 0]);
				offset += 1;
			break;
			case (3 | (0 << 4))://Number
			{
#ifdef LUA_DEBUG
				ut64 num = parseLuaNumber (data + offset);
				Dprintf ("Number %f\n",*((double*)&num));
#endif
				offset += lua53_data.luaNumberSize;
			}
			break;
			case (3 | (1 << 4))://Integer
				Dprintf ("Integer %"PFMT64x"\n",parseLuaInt (data + offset));
				offset += lua53_data.luaIntSize;
			break;
			case (4 | (0 << 4))://Short String
			case (4 | (1 << 4))://Long String
				offset = parseString (data,offset,size,parseStruct);
			break;
			default:
				Dprintf ("Invalid\n");
				return 0;
		}
	}
	return offset;
}
static ut64 parseUpvalues(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	if(offset + lua53_data.intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;

	Dprintf ("Function has %"PFMT64x" Upvalues\n",length);

	int i;
	for(i = 0;i < length; i++){
		Dprintf ("%d: inStack: %d id: %d\n",i,data[offset + 0],data[offset + 1]);
		offset += 2;
	}
	return offset;
}
static ut64 parseProtos(const ut8* data, ut64 offset, const ut64 size, LuaFunction* func, ParseStruct* parseStruct){
	if(offset + lua53_data.intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;
	Dprintf ("Function has %"PFMT64x" Prototypes\n",length);

	int i;
	for(i = 0;i < length; i++){
		offset = lua53parseFunction (data,offset,size,func,parseStruct);
		if(offset == 0)
			return 0;
	}
	return offset;
}
static ut64 parseDebug(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	if(offset + lua53_data.intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;

	if(length != 0){
		Dprintf ("Instruction-Line Mappings %"PFMT64x"\n",length);
		if(offset + lua53_data.intSize * length >= size)
			return 0;
		int i;
		for(i = 0;i < length; i++){
			Dprintf ("Instruction %d Line %"PFMT64x"\n",i,parseInt (data + offset));
			offset += lua53_data.intSize;
		}
	}
	if(offset + lua53_data.intSize >= size)
		return 0;
	length = parseInt (data + offset);
	offset += lua53_data.intSize;
	if(length != 0){
		Dprintf ("LiveRanges: %"PFMT64x"\n",length);
		int i;
		for(i = 0;i < length; i++){
			Dprintf ("LiveRange %d:\n",i);
			offset = parseString (data,offset,size,parseStruct);
			if(offset == 0) return 0;
#ifdef LUA_DEBUG
			ut64 num1 = parseInt (data + offset);
#endif
			offset += lua53_data.intSize;
#ifdef LUA_DEBUG
			ut64 num2 = parseInt (data + offset);
#endif
			offset += lua53_data.intSize;
		}
	}
	if(offset + lua53_data.intSize >= size)
		return 0;
	length = parseInt (data + offset);
	offset += lua53_data.intSize;
	if(length != 0){
		Dprintf ("Up-Values: %"PFMT64x"\n",length);
		int i;
		for(i = 0;i < length; i++){
			Dprintf ("Up-Value %d:\n",i);
			offset = parseString (data,offset,size,parseStruct);
			if(offset == 0) return 0;
		}
	}
	return offset;
}
static ut64 parseString (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	return parseStringR (data,offset,size,0,0,parseStruct);
}
static ut64 parseStringR (const ut8* data, ut64 offset, const ut64 size, char** str_ptr, ut64* str_len, ParseStruct* parseStruct){
	ut64 functionNameSize = data[offset + 0];
	offset += 1;
	if(functionNameSize == 0xFF){
		functionNameSize = parseSize(data + offset);
		offset += lua53_data.sizeSize;
	}
	if(functionNameSize != 0){
		if(str_ptr)
			*str_ptr = (char*)data + offset;
		if(str_len)
			*str_len = functionNameSize - 1;
		if(parseStruct && parseStruct->onString)
			parseStruct->onString (data, offset, functionNameSize - 1, parseStruct);
		Dprintf ("String %.*s\n",(int)(functionNameSize - 1),data + offset);
		offset += functionNameSize - 1;
	}
	return offset;
}