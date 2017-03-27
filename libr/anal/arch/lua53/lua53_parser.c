

#include <r_types.h>

#ifdef DEBUG
	#define Dprintf(...) fprintf(stderr,__VA_ARGS__)
#else
	#define Dprintf(...) 
#endif


int lua53_intSize;
int lua53_sizeSize;
int lua53_instructionSize;
int lua53_luaIntSize;
int lua53_luaNumberSize;

ut64 parseNumber(const ut8* data, ut64 bytesize){
	int i;
	ut64 res = 0;
	for(i = 0; i < bytesize;i++){
		res |= ((ut64)data[i]) << (8*i);
	}
	return res;
}

#define parseInt(data) parseNumber(data, lua53_intSize) 
#define parseSize(data) parseNumber(data, lua53_sizeSize) 
#define parseInstruction(data) parseNumber(data, lua53_instructionSize) 
#define parseLuaInt(data) parseNumber(data, lua53_luaIntSize) 
#define parseLuaNumber(data) parseNumber(data, lua53_luaNumberSize) 


typedef struct lua_function{
	const ut8* data;
	ut64 offset;
	
	char* name_ptr;
	ut64 name_size;
	
	ut64 lineDefined;
	ut64 lastLineDefined;
	ut8 numParams;
	ut8 isVarArg;
	ut8 maxStackSize;
	
	struct lua_function* parent_func;
	
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

struct lua_parse_struct;

typedef void (*OnFunction) (LuaFunction* function, struct lua_parse_struct* parseStruct);
typedef void (*OnString) (const ut8* data, ut64 offset, ut64 size, struct lua_parse_struct* parseStruct);

typedef struct lua_parse_struct{
	OnString onString;
	OnFunction onFunction;
	void* data;
} ParseStruct;



ut64 parseString (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
ut64 parseStringR (const ut8* data, ut64 offset, const ut64 size, char** str_ptr, ut64* str_len, ParseStruct* parseStruct);
ut64 parseHeader (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
ut64 parseFunction (const ut8* data, ut64 offset, const ut64 size, LuaFunction* parent_func, ParseStruct* parseStruct);
ut64 parseCode (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
ut64 parseConstants (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
ut64 parseUpvalues (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);
ut64 parseProtos (const ut8* data, ut64 offset, const ut64 size, LuaFunction* func, ParseStruct* parseStruct);
ut64 parseDebug (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct);


ut64 parseHeader(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	
	if (data && offset + 16 <= size && !memcmp (data + offset, "\x1bLua", 4)) {//check the header
		offset += 4;
		if(data[offset + 0] != '\x53')//check version
			return 0;
		//skip format byte
		offset += 2;
		if(memcmp (data + offset, "\x19\x93\r\n\x1a\n", 6))//for version 5.3
			return 0;
		offset += 6;
		lua53_intSize = data[offset + 0];
		lua53_sizeSize = data[offset + 1];
		lua53_instructionSize = data[offset + 2];
		lua53_luaIntSize = data[offset + 3];
		lua53_luaNumberSize = data[offset + 4];
		
		Dprintf ("Int Size: %i\n",lua53_intSize);
		Dprintf ("Size Size: %i\n",lua53_sizeSize);
		Dprintf ("Instruction Size: %i\n",lua53_instructionSize);
		Dprintf ("Lua Int Size: %i\n",lua53_luaIntSize);
		Dprintf ("Lua Number Size: %i\n",lua53_luaNumberSize);
		
		offset += 5;
		if(offset + lua53_luaIntSize + lua53_luaNumberSize >= size)//check again the remainingsize because an int and number is appended to the header
			return 0;
		if(parseLuaInt (data + offset) != 0x5678)//check the appended integer
			return 0;
		offset += lua53_luaIntSize;
		ut64 num = parseLuaNumber (data + offset);
		if(*((double*)&num) != 370.5)//check the appended number
			return 0;
		offset += lua53_luaNumberSize;
		Dprintf ("Is a Lua Binary\n");
		return offset;
	}
	return 0;
}
ut64 parseFunction (const ut8* data, ut64 offset, const ut64 size, LuaFunction* parent_func, ParseStruct* parseStruct){
	
	ut64 baseoffset = offset;
	
	Dprintf ("Function\n");
	LuaFunction function;
	ZERO_FILL (function);
	function.parent_func = parent_func;
	function.data = data;
	function.offset = offset;
	offset = parseStringR (data, offset, size, &function.name_ptr, &function.name_size, parseStruct);
	if(offset == 0) return 0;
	
	
	function.lineDefined = parseInt (data + offset);
	Dprintf ("Line Defined: %llu\n",function.lineDefined);
	function.lastLineDefined = parseInt (data + offset + lua53_intSize);
	Dprintf ("Last Line Defined: %llu\n",function.lastLineDefined);
	offset += lua53_intSize*2;
	function.numParams = data[offset + 0];
	Dprintf ("Param Count: %d\n",function.numParams);
	function.isVarArg = data[offset + 1];
	Dprintf ("Is VarArgs: %d\n",function.isVarArg);
	function.maxStackSize = data[offset + 2];
	Dprintf ("Max Stack Size: %d\n",function.maxStackSize);
	offset += 3;
	
	function.code_offset = offset;
	function.code_size = parseInt (data + offset);
	offset = parseCode (data, offset, size, parseStruct);
	if(offset == 0) return 0;
	function.const_offset = offset;
	function.const_size = parseInt (data + offset);
	offset = parseConstants (data, offset, size, parseStruct);
	if(offset == 0) return 0;
	function.upvalue_offset = offset;
	function.upvalue_size = parseInt (data + offset);
	offset = parseUpvalues (data, offset, size, parseStruct);
	if(offset == 0) return 0;
	function.protos_offset = offset;
	function.protos_size = parseInt (data + offset);
	offset = parseProtos (data, offset, size, &function, parseStruct);
	if(offset == 0) return 0;
	function.debug_offset = offset;
	offset = parseDebug (data, offset, size, parseStruct);
	if(offset == 0) return 0;
	
	function.size = offset - baseoffset;
	if(parseStruct && parseStruct->onFunction)
		parseStruct->onFunction (&function, parseStruct);
	return offset;
}
ut64 parseCode(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	if(offset + lua53_intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_intSize;
	
	if(offset + length*lua53_instructionSize >= size)
		return 0;
	Dprintf ("Function has %llu Instructions\n",length);
	
	return offset + length*lua53_instructionSize;
}
ut64 parseConstants(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	
	if(offset + lua53_intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_intSize;
	
	Dprintf ("Function has %llu Constants\n",length);
	
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
#ifdef DEBUG
				ut64 num = parseLuaNumber (data + offset);
				Dprintf ("Number %f\n",*((double*)&num));
#endif
				offset += lua53_luaNumberSize;
			}
			break;
			case (3 | (1 << 4))://Integer
				Dprintf ("Integer %llu\n",parseLuaInt (data + offset));
				offset += lua53_luaIntSize;
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
ut64 parseUpvalues(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	
	if(offset + lua53_intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_intSize;
	
	Dprintf ("Function has %llu Upvalues\n",length);
	
	int i;
	for(i = 0;i < length; i++){
		Dprintf ("%d: inStack: %d id: %d\n",i,data[offset + 0],data[offset + 1]);
		offset += 2;
	}
	
	return offset;
}
ut64 parseProtos(const ut8* data, ut64 offset, const ut64 size, LuaFunction* func, ParseStruct* parseStruct){
	
	if(offset + lua53_intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_intSize;
	
	Dprintf ("Function has %llu Prototypes\n",length);
	
	int i;
	for(i = 0;i < length; i++){
		offset = parseFunction (data,offset,size,func,parseStruct);
	}
	
	return offset;
}
ut64 parseDebug(const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	
	if(offset + lua53_intSize >= size)
		return 0;
	ut64 length = parseInt (data + offset);
	offset += lua53_intSize;
	
	if(length != 0){
		Dprintf ("Instruction-Line Mappings %llu\n",length);
		if(offset + lua53_intSize * length >= size)
			return 0;
		int i;
		for(i = 0;i < length; i++){
			Dprintf ("Instruction %d Line %llu\n",i,parseInt (data + offset));
			offset += lua53_intSize;
		}
	}
	
	if(offset + lua53_intSize >= size)
		return 0;
	length = parseInt (data + offset);
	offset += lua53_intSize;
	
	if(length != 0){
		Dprintf ("LiveRanges: %llu\n",length);
		int i;
		for(i = 0;i < length; i++){
			Dprintf ("LiveRange %d:\n",i);
			offset = parseString (data,offset,size,parseStruct);
			if(offset == 0) return 0;
#ifdef DEBUG
			ut64 num1 = parseInt (data + offset);
#endif
			offset += lua53_intSize;
#ifdef DEBUG
			ut64 num2 = parseInt (data + offset);
#endif
			offset += lua53_intSize;
			Dprintf ("%llu - %llu\n",num1, num2);
		}
	}
	
	if(offset + lua53_intSize >= size)
		return 0;
	length = parseInt (data + offset);
	offset += lua53_intSize;
	
	if(length != 0){
		Dprintf ("Up-Values: %llu\n",length);
		int i;
		for(i = 0;i < length; i++){
			Dprintf ("Up-Value %d:\n",i);
			offset = parseString (data,offset,size,parseStruct);
			if(offset == 0) return 0;
		}
	}
	
	return offset;
}
ut64 parseString (const ut8* data, ut64 offset, const ut64 size, ParseStruct* parseStruct){
	return parseStringR (data,offset,size,0,0,parseStruct);
}
ut64 parseStringR (const ut8* data, ut64 offset, const ut64 size, char** str_ptr, ut64* str_len, ParseStruct* parseStruct){
	
	ut64 functionNameSize = data[offset + 0];
	offset += 1;
	if(functionNameSize == 0xFF){
		functionNameSize = parseSize(data + offset);
		offset += lua53_sizeSize;
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