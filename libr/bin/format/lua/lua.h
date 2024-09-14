/* radare - LGPL - Copyright 2024-2024 - bemodtwz */
#include "lua_spec.h"
#include <r_bin.h>

typedef struct lua_function {
	ut64 offset;

	char *name_ptr; // only valid in onFunction methon
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

static inline ut64 parseNumber(const ut8 *data, ut64 bytesize) {
	int i;
	ut64 res = 0;
	for (i = 0; i < bytesize; i++) {
		res |= ((ut64)data[i]) << (8 * i);
	}
	return res;
}

#define parseInt(data) parseNumber (data, lh->intSize)
#define parseSize(data) parseNumber (data, lh->sizeSize)
#define parseInstruction(data) parseNumber (data, lh->instructionSize)
#define parseLuaInt(data) parseNumber (data, lh->luaIntSize)
#define parseLuaNumber(data) parseNumber (data, lh->luaNumberSize)

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

bool check_header(RBuffer *b);
void lua_header_free(RLuaHeader *lhead);
RLuaHeader *r_lua_load_header(RBuffer *b);
ut64 lua53parseFunction(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *parseStruct);
