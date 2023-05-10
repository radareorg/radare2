/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_types.h>

// XXX global
// R_UNUSED static RList *lua53_function_list = NULL;

struct {
	int intSize;
	int sizeSize;
	int instructionSize;
	int luaIntSize;
	int luaNumberSize;
	RList *functionList;
} lua53_data;

static ut64 parseNumber(const ut8 *data, ut64 bytesize){
	int i;
	ut64 res = 0;
	for (i = 0; i < bytesize; i++) {
		res |= ((ut64) data[i]) << (8 * i);
	}
	return res;
}

#define parseInt(data) parseNumber (data, lua53_data.intSize)
#define parseSize(data) parseNumber (data, lua53_data.sizeSize)
#define parseInstruction(data) parseNumber (data, lua53_data.instructionSize)
#define parseLuaInt(data) parseNumber (data, lua53_data.luaIntSize)
#define parseLuaNumber(data) parseNumber (data, lua53_data.luaNumberSize)

typedef struct lua_function {
	ut64 offset;

	char *name_ptr;	// only valid in onFunction methon
	ut64 name_size;

	ut64 lineDefined;
	ut64 lastLineDefined;
	ut8 numParams;
	ut8 isVarArg;
	ut8 maxStackSize;

	struct lua_function *parent_func; // if != NULL, should always be valid

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

typedef struct lua_parse_struct ParseStruct;
typedef void (*OnFunction) (LuaFunction *function, struct lua_parse_struct *parseStruct);
typedef void (*OnString) (const ut8 *data, ut64 offset, ut64 size, struct lua_parse_struct *parseStruct);
typedef void (*OnConst) (const ut8 *data, ut64 offset, ut64 size, struct lua_parse_struct *parseStruct);

typedef struct lua_parse_struct {
	OnString onString;
	OnFunction onFunction;
	OnConst onConst;
	void *data;
} ParseStruct;

LuaFunction *lua53findLuaFunctionByCodeAddr(ut64 addr){
	if (!lua53_data.functionList) {
		return NULL;
	}
	LuaFunction *function = NULL;
	RListIter *iter = NULL;
	r_list_foreach (lua53_data.functionList, iter, function) {
		if (function->code_offset + lua53_data.intSize <= addr && addr < function->const_offset) {
			return function;
		}
	}
	return NULL;
}

static int storeLuaFunction(LuaFunction *function){
	if (!lua53_data.functionList) {
		lua53_data.functionList = r_list_new ();
		if (!lua53_data.functionList) {
			return 0;
		}
	}
	r_list_append (lua53_data.functionList, function);
	return 1;
}

static LuaFunction *findLuaFunction(ut64 addr){
	if (!lua53_data.functionList) {
		return NULL;
	}
	LuaFunction *function = NULL;
	RListIter *iter = NULL;
	r_list_foreach (lua53_data.functionList, iter, function) {
		R_LOG_DEBUG ("Search 0x%"PFMT64x, function->offset);
		if (function->offset == addr) {
			return function;
		}
	}
	return NULL;
}

ut64 lua53parseHeader(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
ut64 lua53parseFunction(const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *parseStruct);

static ut64 parseString(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseStringR(const ut8 *data, ut64 offset, const ut64 size, char **str_ptr, ut64 *str_len, ParseStruct *parseStruct);
static ut64 parseCode(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseConstants(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseUpvalues(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseProtos(const ut8 *data, ut64 offset, const ut64 size, LuaFunction *func, ParseStruct *parseStruct);
static ut64 parseDebug(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);

ut64 lua53parseHeader(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (data && offset + 16 <= size && !memcmp (data + offset, "\x1bLua", 4)) {	// check the header
		offset += 4;
		if (data[offset + 0] != '\x53') {// check version
			return 0;
		}
		// skip format byte
		offset += 2;
		if (memcmp (data + offset, "\x19\x93\r\n\x1a\n", 6)) {	// for version 5.3
			return 0;
		}
		offset += 6;
		lua53_data.intSize = data[offset + 0];
		lua53_data.sizeSize = data[offset + 1];
		lua53_data.instructionSize = data[offset + 2];
		lua53_data.luaIntSize = data[offset + 3];
		lua53_data.luaNumberSize = data[offset + 4];

		R_LOG_DEBUG ("Int Size: %i", lua53_data.intSize);
		R_LOG_DEBUG ("Size Size: %i", lua53_data.sizeSize);
		R_LOG_DEBUG ("Instruction Size: %i", lua53_data.instructionSize);
		R_LOG_DEBUG ("Lua Int Size: %i", lua53_data.luaIntSize);
		R_LOG_DEBUG ("Lua Number Size: %i", lua53_data.luaNumberSize);

		offset += 5;
		if (offset + lua53_data.luaIntSize + lua53_data.luaNumberSize >= size) {// check again the remainingsize because an int and number is appended to the header
			return 0;
		}
		if (parseLuaInt (data + offset) != 0x5678) {	// check the appended integer
			return 0;
		}
		offset += lua53_data.luaIntSize;
		ut64 num = parseLuaNumber (data + offset);
		double d = 0;
		memcpy (&d, &num, sizeof (double));
		// if (*((double *) &num) != 370.5) {	// check the appended number
		if (d != 370.5) {	// check the appended number
			return 0;
		}
		offset += lua53_data.luaNumberSize;
		R_LOG_DEBUG ("Is a Lua Binary");
		return offset;
	}
	return 0;
}

ut64 lua53parseFunction(const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *parseStruct){
	R_LOG_DEBUG ("Function 0x%"PFMT64x, offset);
	LuaFunction *function = findLuaFunction (offset);
	if (function) {	// if a function object was cached
		R_LOG_DEBUG ("Found cached Functione: 0x%"PFMT64x, function->offset);

		if (parseStruct != NULL && parseStruct->onString != NULL) {
			parseConstants (data, function->const_offset, size, parseStruct);
		}

		parseProtos (data, function->protos_offset, size, function, parseStruct);

		if (parseStruct != NULL && parseStruct->onString != NULL) {
			parseDebug (data, function->debug_offset, size, parseStruct);
		}

		if (parseStruct != NULL && parseStruct->onFunction != NULL) {
			parseStruct->onFunction (function, parseStruct);
		}
		return offset + function->size;
	} else {
		ut64 baseoffset = offset;

		function = R_NEW0 (LuaFunction);
		function->parent_func = parent_func;
		function->offset = offset;
		offset = parseStringR (data, offset, size, &function->name_ptr, &function->name_size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}

		function->lineDefined = parseInt (data + offset);
		R_LOG_DEBUG ("Line Defined: %"PFMT64x, function->lineDefined);
		function->lastLineDefined = parseInt (data + offset + lua53_data.intSize);
		R_LOG_DEBUG ("Last Line Defined: %"PFMT64x, function->lastLineDefined);
		offset += lua53_data.intSize * 2;
		function->numParams = data[offset + 0];
		R_LOG_DEBUG ("Param Count: %d", function->numParams);
		function->isVarArg = data[offset + 1];
		R_LOG_DEBUG ("Is VarArgs: %d", function->isVarArg);
		function->maxStackSize = data[offset + 2];
		R_LOG_DEBUG ("Max Stack Size: %d", function->maxStackSize);
		offset += 3;

		function->code_offset = offset;
		function->code_size = parseInt (data + offset);
		offset = parseCode (data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->const_offset = offset;
		function->const_size = parseInt (data + offset);
		offset = parseConstants (data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->upvalue_offset = offset;
		function->upvalue_size = parseInt (data + offset);
		offset = parseUpvalues (data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->protos_offset = offset;
		function->protos_size = parseInt (data + offset);
		offset = parseProtos (data, offset, size, function, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->debug_offset = offset;
		offset = parseDebug (data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}

		function->size = offset - baseoffset;
		if (parseStruct && parseStruct->onFunction) {
			parseStruct->onFunction (function, parseStruct);
		}
		if (!storeLuaFunction (function)) {
			free (function);
		}
		return offset;
	}
}

static ut64 parseCode(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct){
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;

	if (offset + length * lua53_data.instructionSize >= size) {
		return 0;
	}
	R_LOG_DEBUG ("Function has %"PFMT64x " Instructions", length);

	return offset + length * lua53_data.instructionSize;
}

static ut64 parseConstants(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct){
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;
	R_LOG_DEBUG ("Function has %"PFMT64x " Constants", length);

	int i;
	for (i = 0; i < length; i++) {
		R_LOG_DEBUG ("%d: ", i);
		ut8 type = data[offset + 0];
		offset += 1;
		switch (type) {
		case 0:		// Nil
			R_LOG_DEBUG ("Nil");
			break;
		case 1:		// Boolean
			R_LOG_DEBUG ("Boolean %d", data[offset + 0]);
			offset += 1;
			break;
		case (3 | (0 << 4)):		// Number
		{
#ifdef LUA_DEBUG
			ut64 num = parseLuaNumber (data + offset);
			R_LOG_DEBUG ("Number %f", *((double *) &num));
#endif
			offset += lua53_data.luaNumberSize;
		}
		break;
		case (3 | (1 << 4)):		// Integer
			R_LOG_DEBUG ("Integer %"PFMT64x, parseLuaInt (data + offset));
			offset += lua53_data.luaIntSize;
			break;
		case (4 | (0 << 4)):		// Short String
		case (4 | (1 << 4)):		// Long String
			offset = parseString (data, offset, size, parseStruct);
			break;
		default:
			R_LOG_DEBUG ("Invalid");
			return 0;
		}
	}
	return offset;
}

static ut64 parseUpvalues(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct){
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;

	R_LOG_DEBUG ("Function has %"PFMT64x " Upvalues", length);

	int i;
	for (i = 0; i < length; i++) {
		R_LOG_DEBUG ("%d: inStack: %d id: %d", i, data[offset + 0], data[offset + 1]);
		offset += 2;
	}
	return offset;
}

static ut64 parseProtos(const ut8 *data, ut64 offset, const ut64 size, LuaFunction *func, ParseStruct *parseStruct){
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;
	R_LOG_DEBUG ("Function has %"PFMT64x " Prototypes", length);

	int i;
	for (i = 0; i < length; i++) {
		offset = lua53parseFunction (data, offset, size, func, parseStruct);
		if (offset == 0) {
			return 0;
		}
	}
	return offset;
}
static ut64 parseDebug(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct){
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lua53_data.intSize;

	if (length != 0) {
		R_LOG_DEBUG ("Instruction-Line Mappings %"PFMT64x, length);
		if (offset + lua53_data.intSize * length >= size) {
			return 0;
		}
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("Instruction %d Line %"PFMT64x, i, parseInt (data + offset));
			offset += lua53_data.intSize;
		}
	}
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	length = parseInt (data + offset);
	offset += lua53_data.intSize;
	if (length != 0) {
		R_LOG_DEBUG ("LiveRanges: %"PFMT64x, length);
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("LiveRange %d:", i);
			offset = parseString (data, offset, size, parseStruct);
			if (offset == 0) {
				return 0;
			}
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
	if (offset + lua53_data.intSize >= size) {
		return 0;
	}
	length = parseInt (data + offset);
	offset += lua53_data.intSize;
	if (length != 0) {
		R_LOG_DEBUG ("Up-Values: %"PFMT64x, length);
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("Up-Value %d:", i);
			offset = parseString (data, offset, size, parseStruct);
			if (offset == 0) {
				return 0;
			}
		}
	}
	return offset;
}

static ut64 parseString(const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct){
	return parseStringR (data, offset, size, 0, 0, parseStruct);
}

static ut64 parseStringR(const ut8 *data, ut64 offset, const ut64 size, char **str_ptr, ut64 *str_len, ParseStruct *parseStruct){
	if (offset + 8 > size) {
		R_LOG_DEBUG ("Prevented oobread");
		return 0;
	}
	ut64 functionNameSize = data[offset];
	offset += 1;
	if (functionNameSize == 0xFF) {
		functionNameSize = parseSize (data + offset);
		offset += lua53_data.sizeSize;
	}
	if (functionNameSize != 0) {
		if (str_ptr) {
			*str_ptr = r_str_ndup ((char *) (data + offset), functionNameSize - 1);
		}
		if (str_len) {
			*str_len = functionNameSize - 1;
		}
		if (parseStruct && parseStruct->onString) {
			parseStruct->onString (data, offset, functionNameSize - 1, parseStruct);
		}
		R_LOG_DEBUG ("String %.*s", (int) (functionNameSize - 1), data + offset);
		offset += functionNameSize - 1;
	}
	return offset;
}
