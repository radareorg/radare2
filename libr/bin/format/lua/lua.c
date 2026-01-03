/* radare - LGPL - Copyright 2009-2024 - pancake, dennis */

#include "lua.h"

void lua_header_free(RLuaHeader *lhead) {
	if (lhead) {
		r_list_free (lhead->functionList);
		r_list_free (lhead->symbols);
		free (lhead);
	}
}

static void lua_func_free(void *f) {
	free (f);
}

static inline RLuaHeader *lua_header_new(void) {
	RLuaHeader *lh = R_NEW0 (RLuaHeader);
	if (lh) {
		lh->functionList = r_list_newf ((RListFree)lua_func_free);
		lh->symbols = r_list_newf ((RListFree)r_bin_symbol_free);
	}
	return lh;
}

static ut64 parseProtos(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *func, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;
	R_LOG_DEBUG ("Function has %" PFMT64x " Prototypes", length);

	int i;
	for (i = 0; i < length; i++) {
		offset = lua53parseFunction (lh, data, offset, size, func, parseStruct);
		if (offset == 0) {
			return 0;
		}
	}
	return offset;
}

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

static ut64 parseCode(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;

	if (offset + length * lh->instructionSize >= size) {
		return 0;
	}
	R_LOG_DEBUG ("Function has %" PFMT64x " Instructions", length);

	return offset + length * lh->instructionSize;
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
			*str_ptr = r_str_ndup ((char *)(data + offset), functionNameSize - 1);
		}
		if (str_len) {
			*str_len = functionNameSize - 1;
		}
		if (parseStruct && parseStruct->onString) {
			parseStruct->onString (data, offset, functionNameSize - 1, parseStruct);
		}
		R_LOG_DEBUG ("String %.*s", (int)(functionNameSize - 1), data + offset);
		offset += functionNameSize - 1;
	}
	return offset;
}

static ut64 parseString(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	return parseStringR (lh, data, offset, size, 0, 0, parseStruct);
}

static ut64 parseConstants(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;
	R_LOG_DEBUG ("Function has %" PFMT64x " Constants", length);

	int i;
	for (i = 0; i < length; i++) {
		R_LOG_DEBUG ("%d: ", i);
		ut8 type = data[offset + 0];
		offset += 1;
		switch (type) {
		case 0: // Nil
			R_LOG_DEBUG ("Nil");
			break;
		case 1: // Boolean
			R_LOG_DEBUG ("Boolean %d", data[offset + 0]);
			offset += 1;
			break;
		case (3 | (0 << 4)): // Number
		{
#ifdef LUA_DEBUG
			ut64 num = parseLuaNumber (data + offset);
			R_LOG_DEBUG ("Number %f", *((double *)&num));
#endif
			offset += lh->luaNumberSize;
		}
		break;
		case (3 | (1 << 4)): // Integer
			R_LOG_DEBUG ("Integer %" PFMT64x, parseLuaInt (data + offset));
			offset += lh->luaIntSize;
			break;
		case (4 | (0 << 4)): // Short String
		case (4 | (1 << 4)): // Long String
			offset = parseString (lh, data, offset, size, parseStruct);
			break;
		default:
			R_LOG_DEBUG ("Invalid");
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
		R_LOG_DEBUG ("Instruction-Line Mappings %" PFMT64x, length);
		if (offset + lh->intSize * length >= size) {
			return 0;
		}
		int i;
		for (i = 0; i < length; i++) {
			R_LOG_DEBUG ("Instruction %d Line %" PFMT64x, i, parseInt (data + offset));
			offset += lh->intSize;
		}
	}
	if (offset + lh->intSize >= size) {
		return 0;
	}
	length = parseInt (data + offset);
	offset += lh->intSize;
	if (length != 0) {
		R_LOG_DEBUG ("LiveRanges: %" PFMT64x, length);
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
		R_LOG_DEBUG ("Up-Values: %" PFMT64x, length);
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

static inline ut64 buf_parse_int(RBuffer *buf, int size, bool le) {
	switch (size) {
	case 2:
		return le? r_buf_read_le16 (buf): r_buf_read_be16 (buf);
	case 4:
		return le? r_buf_read_le32 (buf): r_buf_read_be32 (buf);
	case 8:
		return le? r_buf_read_le64 (buf): r_buf_read_be64 (buf);
	default:
		return UT64_MAX;
	}
}

static ut64 parseUpvalues(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, ParseStruct *parseStruct) {
	if (offset + lh->intSize >= size) {
		return 0;
	}
	ut64 length = parseInt (data + offset);
	offset += lh->intSize;

	R_LOG_DEBUG ("Function has %" PFMT64x " Upvalues", length);

	int i;
	for (i = 0; i < length; i++) {
		R_LOG_DEBUG ("%d: inStack: %d id: %d", i, data[offset + 0], data[offset + 1]);
		offset += 2;
	}
	return offset;
}

static inline double buf_parse_num(RLuaHeader *lh, RBuffer *buf) {
	double ret = 0;
	ut64 num = buf_parse_int (buf, lh->luaNumberSize, lh->isLe);
	memcpy (&ret, &num, R_MIN (64, R_MIN (sizeof (double), lh->luaNumberSize)));
	return ret;
}

static ut64 add_symbol(RLuaHeader *lh, RBuffer *buf, char *name, ut64 start, const char *type) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	ut64 end = r_buf_tell (buf); // end of field that was just parsed from bf
	if (sym && end > start) {
		sym->name = r_bin_name_new (name);
		sym->vaddr = sym->paddr = start;
		sym->size = end - start;
		sym->ordinal = 0;
		sym->type = type;
		if (sym->name && r_list_append (lh->symbols, sym)) {
			return end;
		}
	}
	r_bin_symbol_free (sym);
	// Caller shouldn't stop parsing lua just for a missing symbol. But we return location to save a r_buf_tell
	return end;
}

static inline bool lua53_check_header_data(RBuffer *buf) {
	ut8 lua_data[] = "\x19\x93\r\n\x1a\n";
	const size_t size = R_ARRAY_SIZE (lua_data) - 1;
	ut8 tmp[size];
	r_buf_read (buf, tmp, size);
	return memcmp (tmp, lua_data, size) == 0;
}

static inline bool is_valid_num_size(int size) {
	switch (size) {
	case 2:
	case 4:
	case 8:
		return true;
	}
	return false;
}

bool check_header(RBuffer *b) {
	return r_buf_read_be32 (b) == 0x1b4c7561? true: false; // "\x1bLua"
}

#define GETVALIDSIZE(x, symname) { \
	lh->x = r_buf_read8 (buf); \
	if (!is_valid_num_size (lh->x)) { \
		R_LOG_WARN ("Invalid size 0x%x for " #x " at offset: 0x%lx", lh->x, where); \
		goto bad_header_ret; \
	} \
	where = add_symbol (lh, buf, symname, where, "NUM"); \
}

// this function expects buf to be pointing to correct location
RLuaHeader *r_lua_load_header(RBuffer *buf) {
	ut64 start = r_buf_tell (buf);
	RLuaHeader *lh = lua_header_new (); // TODO use this when removing global
	if (!lh || !check_header (buf)) {
		R_LOG_DEBUG ("Bad lua magic at offset 0x" PFMT64x, start);
		goto bad_header_ret;
	}
	ut64 where = add_symbol (lh, buf, "lua-header", start, "NOTYPE");

	// version
	lh->ver = r_buf_read8 (buf);
	if (lh->ver != 0x53) {
#if 0
		int mj = lh->ver >> 4;
		int mn = lh->ver & 0xf;
		R_LOG_DEBUG ("[0x%08" PFMT64x "] Reported lua version  %d.%d (0x%x) not supported", where, mj, mn, lh->ver);
#endif
		goto bad_header_ret; // TODO support more versions
	}
	where = add_symbol (lh, buf, "lua-version", where, "NOTYPE");

	// format
	lh->format = r_buf_read8 (buf);
	if (lh->format != 0) {
		R_LOG_WARN ("[0x%08" PFMT64x "]Unexpected Lua format 0x%x", where, lh->format);
	}
	where = add_symbol (lh, buf, "lua-format", where, "NOTYPE");

	// header data check
	if (!lua53_check_header_data (buf)) {
		R_LOG_DEBUG ("[0x%08" PFMT64x "] Bad Lua Data", where);
		goto bad_header_ret;
	}
	where = add_symbol (lh, buf, "stringterminators", where, "NOTYPE");

	GETVALIDSIZE (intSize, "int-size");
	GETVALIDSIZE (sizeSize, "size-size");
	GETVALIDSIZE (instructionSize, "instruction-size");
	GETVALIDSIZE (luaIntSize, "lua-int-size");
	GETVALIDSIZE (luaNumberSize, "lua-number-size");

	// check-int
	ut64 first_try = buf_parse_int (buf, lh->luaIntSize, lh->isLe);
	if (first_try != 0x5678) {
		lh->isLe = !lh->isLe;
		r_buf_seek (buf, where, R_BUF_SET);
		ut64 second_try = buf_parse_int (buf, lh->luaIntSize, lh->isLe);
		if (second_try != 0x5678) {
			R_LOG_DEBUG ("[0x%08" PFMT64x "] Can't parse lua num of size %u ([0x%" PFMT64x ", 0x%" PFMT64x " != 0x5678])", where, lh->intSize, first_try, second_try);
			goto bad_header_ret;
		}
	}
	where = add_symbol (lh, buf, "check-int", where, "NUM");

	// check numbers
	double num = buf_parse_num (lh, buf);
	if (num != 370.5) {
		R_LOG_DEBUG ("[0x%08" PFMT64x "] Lua test number failed (%lf != 370.5)", where, num);
		goto bad_header_ret;
	}
	where = add_symbol (lh, buf, "check-number", where, "NUM");

	// upvalues
	lh->upValues = r_buf_read8 (buf);
	where = add_symbol (lh, buf, "upvalues", where, "NUM");

	lh->headerSize = where - start;
	return lh;

bad_header_ret:
	lua_header_free (lh);
	return 0;
}

ut64 lua53parseFunction(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *parseStruct) {
	R_LOG_DEBUG ("Function 0x%" PFMT64x, offset);
	LuaFunction *function = findLuaFunction (lh, offset);
	if (function) { // if a function object was cached
		R_LOG_DEBUG ("Found cached Functione: 0x%" PFMT64x, function->offset);

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
		R_LOG_DEBUG ("Line Defined: %" PFMT64x, function->lineDefined);
		function->lastLineDefined = parseInt (data + offset + lh->intSize);
		R_LOG_DEBUG ("Last Line Defined: %" PFMT64x, function->lastLineDefined);
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
