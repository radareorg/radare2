/* radare - LGPL - Copyright 2009-2024 - pancake, dennis */

#include <r_types.h>
#include "../../bin/format/lua/lua_spec.h"

static ut64 parseNumber(const ut8 *data, ut64 bytesize) {
	int i;
	ut64 res = 0;
	for (i = 0; i < bytesize; i++) {
		res |= ((ut64) data[i]) << (8 * i);
	}
	return res;
}

#define parseInt(data) parseNumber (data, lh->intSize)
#define parseSize(data) parseNumber (data, lh->sizeSize)
#define parseInstruction(data) parseNumber (data, lh->instructionSize)
#define parseLuaInt(data) parseNumber (data, lh->luaIntSize)
#define parseLuaNumber(data) parseNumber (data, lh->luaNumberSize)

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
typedef void (*OnFunction) (RLuaHeader *lh, LuaFunction *function, struct lua_parse_struct *parseStruct);
typedef void (*OnString) (const ut8 *data, ut64 offset, ut64 size, struct lua_parse_struct *parseStruct);
typedef void (*OnConst) (const ut8 *data, ut64 offset, ut64 size, struct lua_parse_struct *parseStruct);

typedef struct lua_parse_struct {
	OnString onString;
	OnFunction onFunction;
	OnConst onConst;
	void *data;
} ParseStruct;

#if 0
LuaFunction *lua53findLuaFunctionByCodeAddr(ut64 addr) {
	if (!lua53_data->functionList) {
		return NULL;
	}
	LuaFunction *function = NULL;
	RListIter *iter = NULL;
	r_list_foreach (lua53_data->functionList, iter, function) {
		if (function->code_offset + lua53_data->intSize <= addr && addr < function->const_offset) {
			return function;
		}
	}
	return NULL;
}
#endif

static int storeLuaFunction(RLuaHeader *lh, LuaFunction *function) {
	if (!lh->functionList) {
		lh->functionList = r_list_new ();
		if (!lh->functionList) {
			return 0;
		}
	}
	r_list_append (lh->functionList, function);
	return 1;
}

static LuaFunction *findLuaFunction(RLuaHeader *lh, ut64 addr) {
	if (!lh->functionList) {
		return NULL;
	}
	LuaFunction *function = NULL;
	RListIter *iter = NULL;
	r_list_foreach (lh->functionList, iter, function) {
		R_LOG_DEBUG ("Search 0x%" PFMT64x, function->offset);
		if (function->offset == addr) {
			return function;
		}
	}
	return NULL;
}

bool check_header(RBuffer *b);
ut64 lua53parseFunction(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *parseStruct);

static ut64 parseString(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseStringR(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, char **str_ptr, ut64 *str_len, ParseStruct *parseStruct);
static ut64 parseCode(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseConstants(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseUpvalues(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);
static ut64 parseProtos(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *func, ParseStruct *parseStruct);
static ut64 parseDebug(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct);

ut64 lua53parseFunction(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *parseStruct) {
	R_LOG_DEBUG ("Function 0x%"PFMT64x, offset);
	LuaFunction *function = findLuaFunction (lh, offset);
	if (function) {	// if a function object was cached
		R_LOG_DEBUG ("Found cached Functione: 0x%"PFMT64x, function->offset);

		if (parseStruct != NULL && parseStruct->onString != NULL) {
			parseConstants (lh, data, function->const_offset, size, parseStruct);
		}

		parseProtos (lh, data, function->protos_offset, size, function, parseStruct);

		if (parseStruct != NULL && parseStruct->onString != NULL) {
			parseDebug (lh, data, function->debug_offset, size, parseStruct);
		}

		if (parseStruct != NULL && parseStruct->onFunction != NULL) {
			parseStruct->onFunction (lh, function, parseStruct);
		}
		return offset + function->size;
	} else {
		ut64 baseoffset = offset;

		function = R_NEW0 (LuaFunction);
		function->parent_func = parent_func;
		function->offset = offset;
		offset = parseStringR (lh, data, offset, size, &function->name_ptr, &function->name_size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}

		function->lineDefined = parseInt (data + offset);
		R_LOG_DEBUG ("Line Defined: %"PFMT64x, function->lineDefined);
		function->lastLineDefined = parseInt (data + offset + lh->intSize);
		R_LOG_DEBUG ("Last Line Defined: %"PFMT64x, function->lastLineDefined);
		offset += lh->intSize * 2;
		function->numParams = data[offset + 0];
		R_LOG_DEBUG ("Param Count: %d", function->numParams);
		function->isVarArg = data[offset + 1];
		R_LOG_DEBUG ("Is VarArgs: %d", function->isVarArg);
		function->maxStackSize = data[offset + 2];
		R_LOG_DEBUG ("Max Stack Size: %d", function->maxStackSize);
		offset += 3;

		function->code_offset = offset;
		function->code_size = parseInt (data + offset);
		offset = parseCode (lh, data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->const_offset = offset;
		function->const_size = parseInt (data + offset);
		offset = parseConstants (lh, data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->upvalue_offset = offset;
		function->upvalue_size = parseInt (data + offset);
		offset = parseUpvalues (lh, data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->protos_offset = offset;
		function->protos_size = parseInt (data + offset);
		offset = parseProtos (lh, data, offset, size, function, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}
		function->debug_offset = offset;
		offset = parseDebug (lh, data, offset, size, parseStruct);
		if (offset == 0) {
			free (function);
			return 0;
		}

		function->size = offset - baseoffset;
		if (parseStruct && parseStruct->onFunction) {
			parseStruct->onFunction (lh, function, parseStruct);
		}
		if (!storeLuaFunction (lh, function)) {
			free (function);
		}
		return offset;
	}
}

static ut64 parseCode(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;

	if (offset + length * lh->instructionSize >= size) {
		return 0;
	}
	R_LOG_DEBUG ("Function has %"PFMT64x " Instructions", length);

	return offset + length * lh->instructionSize;
}

static ut64 parseConstants(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;
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
			offset += lh->luaNumberSize;
		}
		break;
		case (3 | (1 << 4)):		// Integer
			R_LOG_DEBUG ("Integer %"PFMT64x, parseLuaInt (data + offset));
			offset += lh->luaIntSize;
			break;
		case (4 | (0 << 4)):		// Short String
		case (4 | (1 << 4)):		// Long String
			offset = parseString (lh, data, offset, size, parseStruct);
			break;
		default:
			R_LOG_DEBUG ("Invalid");
			return 0;
		}
	}
	return offset;
}

static ut64 parseUpvalues(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;

	R_LOG_DEBUG ("Function has %"PFMT64x " Upvalues", length);

	int i;
	for (i = 0; i < length; i++) {
		R_LOG_DEBUG ("%d: inStack: %d id: %d", i, data[offset + 0], data[offset + 1]);
		offset += 2;
	}
	return offset;
}

static ut64 parseProtos(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *func, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;
	R_LOG_DEBUG ("Function has %"PFMT64x " Prototypes", length);

	int i;
	for (i = 0; i < length; i++) {
		offset = lua53parseFunction (lh, data, offset, size, func, parseStruct);
		if (offset == 0) {
			return 0;
		}
	}
	return offset;
}
static ut64 parseDebug(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;

	if (length != 0) {
		R_LOG_DEBUG ("Instruction-Line Mappings %"PFMT64x, length);
		if (offset + lh->intSize * length >= size) {
			return 0;
		}
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("Instruction %d Line %"PFMT64x, i, parseInt (data + offset));
			offset += lh->intSize;
		}
	}
	if (offset + lh->intSize >= size) {
		return 0;
	}
	length = parseInt (data + offset);
	offset += lh->intSize;
	if (length != 0) {
		R_LOG_DEBUG ("LiveRanges: %"PFMT64x, length);
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("LiveRange %d:", i);
			offset = parseString (lh, data, offset, size, parseStruct);
			if (offset == 0) {
				return 0;
			}
#ifdef LUA_DEBUG
			ut64 num1 = parseInt (data + offset);
#endif
			offset += lh->intSize;
#ifdef LUA_DEBUG
			ut64 num2 = parseInt (data + offset);
#endif
			offset += lh->intSize;
		}
	}
	if (offset + lh->intSize >= size) {
		return 0;
	}
	length = parseInt (data + offset);
	offset += lh->intSize;
	if (length != 0) {
		R_LOG_DEBUG ("Up-Values: %"PFMT64x, length);
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("Up-Value %d:", i);
			offset = parseString (lh, data, offset, size, parseStruct);
			if (offset == 0) {
				return 0;
			}
		}
	}
	return offset;
}

static ut64 parseString(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	return parseStringR (lh, data, offset, size, 0, 0, parseStruct);
}

static ut64 parseStringR(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, char **str_ptr, ut64 *str_len, ParseStruct *parseStruct) {
	if (offset + 8 > size) {
		R_LOG_DEBUG ("Prevented oobread");
		return 0;
	}
	ut64 functionNameSize = data[offset];
	offset += 1;
	if (functionNameSize == 0xFF) {
		functionNameSize = parseSize (data + offset);
		offset += lh->sizeSize;
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
