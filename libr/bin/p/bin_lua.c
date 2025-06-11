/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_bin.h>
#include <r_lib.h>

#include "../format/lua/lua.h"

static inline RLuaHeader *get_lua_header(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	if (!bf->bo->bin_obj && b) {
		r_buf_seek (b, loadaddr, R_BUF_SET);
		bf->bo->bin_obj = r_lua_load_header (b);
	}
	return bf->bo->bin_obj;
}

static bool check(RBinFile *bf, RBuffer *b) {
	return check_header (b);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return get_lua_header (bf, b, loadaddr) != NULL;
}

static void addSection(RLuaHeader *lh, RList *list, const char *name, ut64 addr, ut32 size, bool isFunc) {
	RBinSection *bs = R_NEW0 (RBinSection);
	bs->name = strdup (name);
	bs->vaddr = bs->paddr = addr;
	bs->size = bs->vsize = size;
	bs->add = true;
	bs->is_data = false;
	bs->bits = isFunc? 8 * lh->instructionSize: 8;
	if (bs->bits == 0) {
		bs->bits = 32;
	}
	bs->has_strings = !isFunc;
	bs->arch = strdup ("lua"); // maybe add bs->cpu or use : to separate arch:cpu
	// bs->cpu = strdup ("5.4"); // maybe add bs->cpu or use : to separate arch:cpu
	if (isFunc) {
		bs->perm = R_PERM_RX;
	} else {
		bs->perm = R_PERM_R;
	}
	bs->is_segment = true;
	r_list_append (list, bs);
}

static void addSections(RLuaHeader *lh, LuaFunction *func, ParseStruct *parseStruct) {
	char *string = (func->name_size == 0 || func->name_ptr == 0)
		? r_str_newf ("0x%"PFMT64x, func->offset) : func->name_ptr;

	r_strf_buffer (R_BIN_SIZEOF_STRINGS);

	RList *data = parseStruct->data;
	addSection (lh, data, r_strf ("header.%s", string),
		func->offset, func->code_offset - func->offset, false);
	// code section also holds codesize
	addSection (lh, data, r_strf ("code.%s", string),
		func->code_offset, func->const_offset - func->code_offset, true);
	addSection (lh, data, r_strf ("consts.%s", string),
		func->const_offset, func->upvalue_offset - func->const_offset, false);
	addSection (lh, data, r_strf ("upvalues.%s", string),
		func->upvalue_offset, func->protos_offset - func->upvalue_offset, false);
	addSection (lh, data, r_strf ("debuginfo.%s", string),
		func->debug_offset, func->offset + func->size - func->debug_offset, false);

	free (string);
}

static RList *sections(RBinFile *bf) {

	ParseStruct parseStruct = {0};
	if (!bf) {
		return NULL;
	}
#if 1
	ut8 *bytes = malloc (bf->size);
	if (!bytes) {
		return NULL;
	}
	r_buf_read_at (bf->buf, 0, bytes, bf->size);
	ut64 sz = bf? r_buf_size (bf->buf): 0;

	memset (&parseStruct, 0, sizeof (parseStruct));
	parseStruct.onFunction = addSections;

	parseStruct.data = r_list_newf ((RListFree) free);
	if (!parseStruct.data) {
		return NULL;
	}

	RLuaHeader *lh = get_lua_header (bf, NULL, 0);
	if (lh) {
		addSection (lh, parseStruct.data, "lua-header", 0, lh->headerSize, false);
		lua53parseFunction (lh, bytes, lh->headerSize, sz, 0, &parseStruct);
	}
	free (bytes);
#endif
	return parseStruct.data;
}

static void addString(const ut8 *buf, ut64 offset, ut64 length, ParseStruct *parseStruct) {
	RBinString *binstring = R_NEW0 (RBinString);
	binstring->string = r_str_ndup ((char *) buf + offset, length);
	binstring->vaddr = binstring->paddr = offset;
	binstring->ordinal = 0;
	binstring->size = length;
	binstring->length = length;
	r_list_append (parseStruct->data, binstring);
}

static void addSymbol(RList *list, char *name, ut64 addr, ut32 size, const char *type) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	sym->name = r_bin_name_new (name);
	if (!sym->name) {
		free (sym);
		return;
	}
	sym->vaddr = sym->paddr = addr;
	sym->size = size;
	sym->ordinal = 0;
	sym->type = type;
	r_list_append (list, sym);
}

static void handleFuncSymbol(RLuaHeader *lh, LuaFunction *func, ParseStruct *parseStruct) {
	char *string;
	if (!func->name_ptr || !func->name_size) {
		string = r_str_newf ("0x%"PFMT64x, func->offset);
	} else {
		string = r_str_ndup (func->name_ptr, func->name_size);
		// XXX use RName.filter() or nothing
		r_str_replace_char (string, '@', '_');
	}
	char sb[R_BIN_SIZEOF_STRINGS + 1];
	snprintf (sb, sizeof (sb), "lineDefined.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 3 - 2 * lh->intSize, lh->intSize, "NUM");
	snprintf (sb, sizeof (sb), "lastLineDefined.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 3 - lh->intSize, lh->intSize, "NUM");
	snprintf (sb, sizeof (sb), "numParams.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 3, 1, "NUM");
	snprintf (sb, sizeof (sb), "isVarArg.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 2, 1, "BOOL");
	snprintf (sb, sizeof (sb), "maxStackSize.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 1, 1, "BOOL");

	snprintf (sb, sizeof (sb), "codesize.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset, lh->intSize, "NUM");

	snprintf (sb, sizeof (sb), "func.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset + lh->intSize, lh->instructionSize * func->code_size, "FUNC");

	snprintf (sb, sizeof (sb), "constsize.%s", string);
	addSymbol (parseStruct->data, sb, func->const_offset, lh->intSize, "NUM");

	snprintf (sb, sizeof (sb), "upvaluesize.%s", string);
	addSymbol (parseStruct->data, sb, func->upvalue_offset, lh->intSize, "NUM");

	snprintf (sb, sizeof (sb), "prototypesize.%s", string);
	addSymbol (parseStruct->data, sb, func->protos_offset, lh->intSize, "NUM");

	free (string);
}

static RList *strings(RBinFile *bf) {
	ut8 *bytes = malloc (bf->size);
	if (bytes) {
		r_buf_read_at (bf->buf, 0, bytes, bf->size);
	}

	ParseStruct parseStruct;
	memset (&parseStruct, 0, sizeof (parseStruct));
	parseStruct.onString = addString;

	parseStruct.data = r_list_new ();
	if (!parseStruct.data) {
		free (bytes);
		return NULL;
	}
	RLuaHeader *lh = get_lua_header (bf, NULL, 0);
	if (lh) {
		lua53parseFunction (lh, bytes, lh->headerSize, bf->size, 0, &parseStruct);
	}

	free (bytes);
	return parseStruct.data;
}

static RList *symbols(RBinFile *bf) {
	RLuaHeader *lh = get_lua_header (bf, NULL, 0);
	if (!lh) {
		return NULL;
	}

	ParseStruct parseStruct = {0};
	parseStruct.onFunction = handleFuncSymbol;
	parseStruct.data = NULL;
	parseStruct.data = r_list_clone (lh->symbols, (RListClone)r_bin_symbol_clone);
	if (!parseStruct.data) {
		return NULL;
	}

	ut8 *bytes = malloc (bf->size);
	if (bytes) {
		st64 sz = r_buf_read_at (bf->buf, 0, bytes, bf->size);
		if (sz > 0) {
			lua53parseFunction (lh, bytes, lh->headerSize, sz, 0, &parseStruct);
		}
		free (bytes);
	}

	return parseStruct.data;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("lua");
	ret->os = strdup ("any");
	ret->machine = strdup ("LUA 5.3 VM");
	ret->arch = strdup ("lua");
	RLuaHeader *lh = get_lua_header (bf, NULL, 0);
	ret->bits = lh? lh->instructionSize * 8: 32;
	if (ret->bits < 1) {
		ret->bits = 32;
	} else if (ret->bits != 32) {
		R_LOG_WARN ("lua vm using %d bits registers is not well tested", ret->bits);
	}
	ret->has_va = true;
	ret->big_endian = false;
	return ret;
}

static void addEntry(RLuaHeader *lh, LuaFunction *func, ParseStruct *parseStruct) {
	if (!func->parent_func) {
		RBinAddr *ptr = R_NEW0 (RBinAddr);
		ptr->paddr = ptr->vaddr = func->code_offset + lh->intSize;
		r_list_append (parseStruct->data, ptr);
	}
}

static RList *entries(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf, NULL);
	if (bf->size < 20) {
		return NULL;
	}
	ut8 *buf = malloc (bf->size);
	if (!buf) {
		R_LOG_ERROR ("cannot malloc filesize");
		return false;
	}
	r_buf_read_at (bf->buf, 0, buf, bf->size);

	ParseStruct parseStruct;
	memset (&parseStruct, 0, sizeof (parseStruct));
	parseStruct.onFunction = addEntry;
	parseStruct.data = NULL;

	parseStruct.data = r_list_new ();
	RLuaHeader *lh = get_lua_header (bf, NULL, 0);
	if (parseStruct.data && lh) {
		lua53parseFunction (lh, buf, lh->headerSize, bf->size, 0, &parseStruct);
	}
	free (buf);
	return parseStruct.data;
}

static void destroy(RBinFile *bf) {
	lua_header_free (bf->bo->bin_obj);
	bf->bo->bin_obj = NULL;
}

RBinPlugin r_bin_plugin_lua = {
	.meta = {
		.name = "lua",
		.desc = "Compiled LUA (lua 5.3)",
		.license = "MIT",
		.author = "pancake",
	},
	.sections = &sections,
	.load = &load,
	.check = &check,
	.symbols = &symbols,
	.strings = &strings,
	.info = &info,
	.entries = &entries,
	.destroy = &destroy,
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_lua,
	.version = R2_VERSION
};
#endif
