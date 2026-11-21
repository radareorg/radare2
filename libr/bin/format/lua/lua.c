/* radare - LGPL - Copyright 2009-2026 - pancake, dennis */

#include "lua.h"

// luac can not nest functions deeper than its LUAI_MAXCCALLS parser limit
#define LUA_MAX_PROTO_DEPTH 200

void lua_header_free(RLuaHeader *lhead) {
	if (lhead) {
		r_list_free (lhead->functionList);
		RVecRBinSymbol_fini (&lhead->symbols);
		free (lhead);
	}
}

static void lua_func_free(void *f) {
	LuaFunction *func = f;
	free (func->name_ptr);
	free (f);
}

static inline RLuaHeader *lua_header_new(void) {
	RLuaHeader *lh = R_NEW0 (RLuaHeader);
	lh->functionList = r_list_newf ((RListFree)lua_func_free);
	RVecRBinSymbol_init (&lh->symbols);
	return lh;
}

static inline bool has_bytes(const ut64 size, const ut64 offset, const ut64 len) {
	return offset <= size && len <= size - offset;
}

static int storeLuaFunction(RLuaHeader *lh, LuaFunction *function) {
	if (!lh->functionList) {
		lh->functionList = r_list_newf ((RListFree)lua_func_free);
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

static bool readCount(RLuaHeader *lh, const ut8 *data, ut64 *offset, ut64 size, ut64 *value, ut8 *width) {
	const ut64 start = *offset;
	ut64 n = 0;
	if (lh->ver == 0x54) {
		ut8 b;
		do {
			if (!has_bytes (size, *offset, 1) || *offset - start >= 10) {
				return false;
			}
			b = data[(*offset)++];
			if (n > (UT64_MAX - (b & 0x7f)) / 128) {
				return false;
			}
			n = (n << 7) | (b & 0x7f);
		} while (!(b & 0x80));
	} else {
		if (!has_bytes (size, *offset, lh->intSize)) {
			return false;
		}
		int i;
		for (i = 0; i < lh->intSize; i++) {
			n |= (ut64)data[*offset + i] << (8 * (lh->isLe? i: lh->intSize - 1 - i));
		}
		*offset += lh->intSize;
	}
	*value = n;
	if (width) {
		*width = *offset - start;
	}
	return true;
}

static ut64 parseStringR(RLuaHeader *lh, const ut8 *data, ut64 offset, ut64 size, char **str, ut64 *length, ParseStruct *ps) {
	ut64 n;
	if (lh->ver == 0x54) {
		if (!readCount (lh, data, &offset, size, &n, NULL)) {
			return 0;
		}
	} else {
		if (!has_bytes (size, offset, 1)) {
			return 0;
		}
		n = data[offset++];
		if (n == 0xff) {
			if (!has_bytes (size, offset, lh->sizeSize)) {
				return 0;
			}
			n = parseSize (data + offset);
			offset += lh->sizeSize;
		}
	}
	if (!n) {
		return offset;
	}
	n--;
	if (!has_bytes (size, offset, n)) {
		return 0;
	}
	if (str) {
		*str = r_str_ndup ((const char *)data + offset, n);
	}
	if (length) {
		*length = n;
	}
	if (ps && ps->onString) {
		ps->onString (data, offset, n, ps);
	}
	return offset + n;
}

static ut64 parseConstants(RLuaHeader *lh, const ut8 *data, ut64 offset, ut64 size, ut8 *width, ParseStruct *ps) {
	ut64 count;
	if (!readCount (lh, data, &offset, size, &count, width) || count > size - offset) {
		return 0;
	}
	ut64 i;
	for (i = 0; i < count; i++) {
		if (!has_bytes (size, offset, 1)) {
			return 0;
		}
		ut8 type = data[offset++];
		if (lh->ver == 0x54) {
			if (type == 1 || type == 17) {
				continue;
			}
			if (type == 3 || type == 19) {
				type ^= 16;
			}
		}
		ut64 n = 0;
		switch (type) {
		case 0:
			break;
		case 1:
			n = 1;
			break;
		case 3:
			n = lh->luaNumberSize;
			break;
		case 19:
			n = lh->luaIntSize;
			break;
		case 4:
		case 20:
			offset = parseStringR (lh, data, offset, size, NULL, NULL, ps);
			if (!offset) {
				return 0;
			}
			break;
		default:
			return 0;
		}
		if (!has_bytes (size, offset, n)) {
			return 0;
		}
		offset += n;
	}
	return offset;
}

static ut64 parseProtos(RLuaHeader *lh, const ut8 *data, ut64 offset, ut64 size, LuaFunction *func, ParseStruct *ps) {
	ut64 count;
	if (!readCount (lh, data, &offset, size, &count, &func->protos_count_size) || count > size - offset) {
		return 0;
	}
	if (lh->depth >= LUA_MAX_PROTO_DEPTH) {
		R_LOG_WARN ("Function prototypes nested deeper than %d levels", LUA_MAX_PROTO_DEPTH);
		return 0;
	}
	lh->depth++;
	ut64 i;
	for (i = 0; i < count; i++) {
		offset = r_lua_parse_function (lh, data, offset, size, func, ps);
		if (!offset) {
			break;
		}
	}
	lh->depth--;
	return offset;
}

static ut64 parseDebug(RLuaHeader *lh, const ut8 *data, ut64 offset, ut64 size, ParseStruct *ps) {
	ut64 count, bytes, ignored;
	if (!readCount (lh, data, &offset, size, &count, NULL)
			|| r_mul_overflow (count, (ut64)(lh->ver == 0x54? 1: lh->intSize), &bytes)
			|| !has_bytes (size, offset, bytes)) {
		return 0;
	}
	offset += bytes;
	ut64 i;
	if (lh->ver == 0x54) {
		if (!readCount (lh, data, &offset, size, &count, NULL) || count > (size - offset) / 2) {
			return 0;
		}
		for (i = 0; i < count; i++) {
			if (!readCount (lh, data, &offset, size, &ignored, NULL) || !readCount (lh, data, &offset, size, &ignored, NULL)) {
				return 0;
			}
		}
	}
	if (!readCount (lh, data, &offset, size, &count, NULL) || count > size - offset) {
		return 0;
	}
	for (i = 0; i < count; i++) {
		offset = parseStringR (lh, data, offset, size, NULL, NULL, ps);
		if (!offset || !readCount (lh, data, &offset, size, &ignored, NULL) || !readCount (lh, data, &offset, size, &ignored, NULL)) {
			return 0;
		}
	}
	if (!readCount (lh, data, &offset, size, &count, NULL) || count > size - offset) {
		return 0;
	}
	for (i = 0; i < count; i++) {
		offset = parseStringR (lh, data, offset, size, NULL, NULL, ps);
		if (!offset) {
			return 0;
		}
	}
	return offset;
}

static ut64 parseUpvalues(RLuaHeader *lh, const ut8 *data, ut64 offset, ut64 size, ut8 *width) {
	ut64 count, bytes;
	if (!readCount (lh, data, &offset, size, &count, width)
			|| r_mul_overflow (count, (ut64)(lh->ver == 0x54? 3: 2), &bytes)
			|| !has_bytes (size, offset, bytes)) {
		return 0;
	}
	return offset + bytes;
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

static inline double buf_parse_num(RLuaHeader *lh, RBuffer *buf) {
	double ret = 0;
	ut64 num = buf_parse_int (buf, lh->luaNumberSize, lh->isLe);
	memcpy (&ret, &num, R_MIN (64, R_MIN (sizeof (double), lh->luaNumberSize)));
	return ret;
}

static ut64 add_symbol(RLuaHeader *lh, RBuffer *buf, char *name, ut64 start, const char *type) {
	ut64 end = r_buf_tell (buf); // end of field that was just parsed from bf
	if (end > start) {
		RBinSymbol *sym = RVecRBinSymbol_emplace_back (&lh->symbols);
		memset (sym, 0, sizeof (*sym));
		sym->name = r_bin_name_new (name);
		if (sym->name) {
			sym->vaddr = sym->paddr = start;
			sym->attr.size = end - start;
			sym->type = type;
			return end;
		}
		RVecRBinSymbol_pop_back (&lh->symbols);
	}
	// Caller shouldn't stop parsing lua just for a missing symbol. But we return location to save a r_buf_tell
	return end;
}

static inline bool lua53_check_header_data(RBuffer *buf) {
	const ut8 lua_data[] = "\x19\x93\r\n\x1a\n";
	ut8 tmp[6];
	r_buf_read (buf, tmp, sizeof (tmp));
	return memcmp (tmp, lua_data, sizeof (tmp)) == 0;
}

static inline bool is_valid_num_size(int size) {
	if (size == 2 || size == 4 || size == 8) {
		return true;
	}
	return false;
}

bool check_header(RBuffer *b) {
	return r_buf_read_be32 (b) == 0x1b4c7561? true: false; // "\x1bLua"
}

#define GETVALIDSIZE(x, symname) \
	{ \
		lh->x = r_buf_read8 (buf); \
		if (!is_valid_num_size (lh->x)) { \
			R_LOG_WARN ("Invalid size 0x%x for " #x " at offset: 0x%" PFMT64x, lh->x, where); \
			goto bad_header_ret; \
		} \
		where = add_symbol (lh, buf, symname, where, "NUM"); \
	}

// this function expects buf to be pointing to correct location
RLuaHeader *r_lua_load_header(RBuffer *buf) {
	ut64 start = r_buf_tell (buf);
	RLuaHeader *lh = lua_header_new (); // TODO use this when removing global
	if (!lh || !check_header (buf)) {
		R_LOG_DEBUG ("Bad lua magic at offset 0x%" PFMT64x, start);
		goto bad_header_ret;
	}
	ut64 where = add_symbol (lh, buf, "lua-header", start, "NOTYPE");

	// version
	lh->ver = r_buf_read8 (buf);
	if (lh->ver != 0x53 && lh->ver != 0x54) {
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

	if (lh->ver == 0x53) {
		GETVALIDSIZE (intSize, "int-size");
		GETVALIDSIZE (sizeSize, "size-size");
	}
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

ut64 r_lua_parse_function(RLuaHeader *lh, const ut8 *data, ut64 offset, const ut64 size, LuaFunction *parent_func, ParseStruct *ps) {
	LuaFunction *function = findLuaFunction (lh, offset);
	if (function) {
		if (ps && ps->onString) {
			if (!parseConstants (lh, data, function->const_offset, size, NULL, ps)) {
				return 0;
			}
		}
		if (!parseProtos (lh, data, function->protos_offset, size, function, ps)) {
			return 0;
		}
		if (ps && ps->onString && !parseDebug (lh, data, function->debug_offset, size, ps)) {
			return 0;
		}
		if (ps && ps->onFunction) {
			ps->onFunction (lh, function, ps);
		}
		return offset + function->size;
	}
	function = R_NEW0 (LuaFunction);
	function->parent_func = parent_func;
	function->offset = offset;
	offset = parseStringR (lh, data, offset, size, &function->name_ptr, &function->name_size, ps);
	if (!offset) {
		goto beach;
	}
	function->line_offset = offset;
	if (!readCount (lh, data, &offset, size, &function->lineDefined, NULL)) {
		goto beach;
	}
	function->lastline_offset = offset;
	if (!readCount (lh, data, &offset, size, &function->lastLineDefined, NULL) || !has_bytes (size, offset, 3)) {
		goto beach;
	}
	function->numParams = data[offset++];
	function->isVarArg = data[offset++];
	function->maxStackSize = data[offset++];
	function->code_offset = offset;
	ut64 bytes;
	if (!readCount (lh, data, &offset, size, &function->code_size, &function->code_count_size)
			|| r_mul_overflow (function->code_size, (ut64)lh->instructionSize, &bytes)
			|| !has_bytes (size, offset, bytes)) {
		goto beach;
	}
	offset += bytes;
	function->const_offset = offset;
	offset = parseConstants (lh, data, offset, size, &function->const_count_size, ps);
	if (!offset) {
		goto beach;
	}
	function->upvalue_offset = offset;
	offset = parseUpvalues (lh, data, offset, size, &function->upvalue_count_size);
	if (!offset) {
		goto beach;
	}
	function->protos_offset = offset;
	offset = parseProtos (lh, data, offset, size, function, ps);
	if (!offset) {
		goto beach;
	}
	function->debug_offset = offset;
	offset = parseDebug (lh, data, offset, size, ps);
	if (!offset) {
		goto beach;
	}
	function->size = offset - function->offset;
	if (ps && ps->onFunction) {
		ps->onFunction (lh, function, ps);
	}
	if (!storeLuaFunction (lh, function)) {
		lua_func_free (function);
	}
	return offset;
beach:
	lua_func_free (function);
	return 0;
}
