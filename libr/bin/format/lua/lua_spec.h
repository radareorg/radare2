/* radare - LGPL - Copyright 2009-2024 - pancake, dennis */

#ifndef LUASPEC
#define LUASPEC 1

#include <r_util.h>

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
	RList *functionList;
	RList *symbols;
} RLuaHeader;

#endif
