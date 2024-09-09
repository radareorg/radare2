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

bool check_header(RBuffer *b) {
	return r_buf_read_be32 (b) == 0x1b4c7561? true: false; // "\x1bLua"
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
		int mj = lh->ver >> 4;
		int mn = lh->ver & 0xf;
		R_LOG_DEBUG ("[0x%08" PFMT64x "] Reported lua version  %d.%d (0x%x) not supported", where, mj, mn, lh->ver);
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
