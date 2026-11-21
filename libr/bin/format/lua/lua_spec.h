/* radare - LGPL - Copyright 2009-2024 - pancake, dennis */

#ifndef LUASPEC
#define LUASPEC 1

#include <r_util.h>
#include <r_bin.h>

typedef struct {
	ut64 offset, length;
} LuaString;

R_VEC_TYPE (RVecLuaString, LuaString);

typedef struct lua_data_struct {
	ut8 ver;
	bool isLe;
	ut8 format;
	int intSize;
	int sizeSize;
	int instructionSize;
	int luaIntSize;
	int luaNumberSize;
	int upValues;
	ut64 headerSize;
	RVecLuaString strings;
	bool strings_ready;
	int depth; // prototype nesting level while parsing
	RList *functionList;
	RVecRBinSymbol symbols;
} RLuaHeader;

#endif
