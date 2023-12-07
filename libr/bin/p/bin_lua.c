/* radare - LGPL - Copyright 2009-2023 - pancake */

#include <r_bin.h>
#include <r_lib.h>

#include "../arch/p/lua/lua53_parser.c"

#if 0
static int finit(void *user) {
	if (lua53_data.functionList) {
		r_list_free (lua53_data.functionList);
		lua53_data.functionList = 0;
	}
	return 0;
}

static bool check_bytes(const ut8 *buf, ut64 length);

static bool check(RBinFile *bf) {
	Dprintf ("Check\n");
	const ut8 *bytes = bf? r_buf_buffer (bf->buf): NULL;
	ut64 sz = bf? r_buf_size (bf->buf): 0;
	return check_bytes (bytes, sz);
}
#endif

static bool check(RBinFile *bf, RBuffer *b) {
	if (r_buf_size (b) > 4) {
		ut8 buf[4];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "\x1b\x4c\x75\x61", 4)) {
			return true;
		}
#if 0
		ParseStruct parseStruct;
		ut64 parsedbytes = lua53parseHeader (buf, 0, sizeof (buf), &parseStruct);
		return parsedbytes != 0;
#endif
	}
	return false;
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	ut8 *buf = malloc (bf->size);
	if (!buf) {
		R_LOG_ERROR ("cannot malloc filesize");
		return false;
	}
	r_buf_read_at (b, 0, buf, bf->size);
	ParseStruct parseStruct;
	ut64 parsedbytes = lua53parseHeader (buf, 0, sizeof (buf), &parseStruct);
	free (buf);
	// eprintf ("PAr %"PFMT64d"\n", parsedbytes);
	return true;
	return parsedbytes != 0;
#if 0
	const ut8 *bytes = bf? r_buf_buffer (bf->buf): NULL;
	ut64 sz = bf? r_buf_size (bf->buf): 0;
	return check_bytes (bytes, sz);
#endif
}

static void addSection(RList *list, const char *name, ut64 addr, ut32 size, bool isFunc) {
	RBinSection *bs = R_NEW0 (RBinSection);
	if (bs) {
		bs->name = strdup (name);
		bs->vaddr = bs->paddr = addr;
		bs->size = bs->vsize = size;
		bs->add = true;
		bs->is_data = false;
		bs->bits = isFunc? 8 * lua53_data.instructionSize: 8;
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
}

static void addSections(LuaFunction *func, ParseStruct *parseStruct){
	char *string = (func->name_size == 0 || func->name_ptr == 0)
		? r_str_newf ("0x%"PFMT64x, func->offset) : func->name_ptr;

	r_strf_buffer (R_BIN_SIZEOF_STRINGS);

	addSection (parseStruct->data, r_strf ("header.%s", string),
		func->offset, func->code_offset - func->offset, false);
	// code section also holds codesize
	addSection (parseStruct->data, r_strf ("code.%s", string),
		func->code_offset, func->const_offset - func->code_offset, true);
	addSection (parseStruct->data, r_strf ("consts.%s", string),
		func->const_offset, func->upvalue_offset - func->const_offset, false);
	addSection (parseStruct->data, r_strf ("upvalues.%s", string),
		func->upvalue_offset, func->protos_offset - func->upvalue_offset, false);
	addSection (parseStruct->data, r_strf ("debuginfo.%s", string),
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
	// header + version + format + stringterminators + sizes + integer + number + upvalues
	ut64 headersize = 4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;
	addSection (parseStruct.data, "lua-header", 0, headersize, false);

	// parse functions
	lua53parseFunction (bytes, headersize, sz, 0, &parseStruct);
	free (bytes);
#endif
	return parseStruct.data;
}

static void addString(const ut8 *buf, ut64 offset, ut64 length, ParseStruct *parseStruct){
	RBinString *binstring = R_NEW0 (RBinString);

	if (binstring == NULL) {
		return;
	}

	binstring->string = r_str_newlen ((char *) buf + offset, length);
	binstring->vaddr = binstring->paddr = offset;
	binstring->ordinal = 0;
	binstring->size = length;
	binstring->length = length;
	r_list_append (parseStruct->data, binstring);
}

static void addSymbol(RList *list, char *name, ut64 addr, ut32 size, const char *type) {
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (sym) {
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
}

static void handleFuncSymbol(LuaFunction *func, ParseStruct *parseStruct){
	RBinSymbol *binSymbol = R_NEW0 (RBinSymbol);
	if (!binSymbol) {
		return;
	}
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
	addSymbol (parseStruct->data, sb, func->code_offset - 3 - 2 * lua53_data.intSize, lua53_data.intSize, "NUM");
	snprintf (sb, sizeof (sb), "lastLineDefined.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 3 - lua53_data.intSize, lua53_data.intSize, "NUM");
	snprintf (sb, sizeof (sb), "numParams.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 3, 1, "NUM");
	snprintf (sb, sizeof (sb), "isVarArg.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 2, 1, "BOOL");
	snprintf (sb, sizeof (sb), "maxStackSize.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset - 1, 1, "BOOL");

	snprintf (sb, sizeof (sb), "codesize.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset, lua53_data.intSize, "NUM");

	snprintf (sb, sizeof (sb), "func.%s", string);
	addSymbol (parseStruct->data, sb, func->code_offset + lua53_data.intSize, lua53_data.instructionSize * func->code_size, "FUNC");

	snprintf (sb, sizeof (sb), "constsize.%s", string);
	addSymbol (parseStruct->data, sb, func->const_offset, lua53_data.intSize, "NUM");

	snprintf (sb, sizeof (sb), "upvaluesize.%s", string);
	addSymbol (parseStruct->data, sb, func->upvalue_offset, lua53_data.intSize, "NUM");

	snprintf (sb, sizeof (sb), "prototypesize.%s", string);
	addSymbol (parseStruct->data, sb, func->protos_offset, lua53_data.intSize, "NUM");

	free (string);
}

static RList *strings(RBinFile *bf) {
	ut8 *bytes = malloc (bf->size);
	if (bytes) {
		r_buf_read_at (bf->buf, 0, bytes, bf->size);
	}

	ut64 headersize = 4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;// header + version + format + stringterminators + sizes + integer + number + upvalues

	ParseStruct parseStruct;
	memset (&parseStruct, 0, sizeof (parseStruct));
	parseStruct.onString = addString;

	parseStruct.data = r_list_new ();
	if (!parseStruct.data) {
		free (bytes);
		return NULL;
	}
	lua53parseFunction (bytes, headersize, bf->size, 0, &parseStruct);

	free (bytes);
	return parseStruct.data;
}

static RList *symbols(RBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	ut8 *bytes = malloc (bf->size);
	if (bytes) {
		r_buf_read_at (bf->buf, 0, bytes, bf->size);
	}
	ut64 sz = bf? r_buf_size (bf->buf): 0;
	ut64 headersize = 4 + 1 + 1 + 6 + 5 + bytes[15] + bytes[16] + 1;
	// header + version + format + stringterminators + sizes + integer + number + upvalues

	ParseStruct parseStruct = {0};
	parseStruct.onFunction = handleFuncSymbol;
	parseStruct.data = NULL;

	RList *list = r_list_new ();
	parseStruct.data = list;
	if (!parseStruct.data) {
		return NULL;
	}

	addSymbol (list, "lua-header", 0, 4, "NOTYPE");
	addSymbol (list, "lua-version", 4, 1, "NOTYPE");
	addSymbol (list, "lua-format", 5, 1, "NOTYPE");
	addSymbol (list, "stringterminators", 6, 6, "NOTYPE");
	addSymbol (list, "int-size", 12, 1, "NUM");
	addSymbol (list, "size-size", 13, 1, "NUM");
	addSymbol (list, "instruction-size", 14, 1, "NUM");
	addSymbol (list, "lua-int-size", 15, 1, "NUM");
	addSymbol (list, "lua-number-size", 16, 1, "NUM");
	addSymbol (list, "check-int", 17, bytes[15], "NUM");
	addSymbol (list, "check-number", 17 + bytes[15], bytes[16], "FLOAT");
	addSymbol (list, "upvalues", 17 + bytes[15] + bytes[16], 1, "NUM");

	lua53parseFunction (bytes, headersize, sz, 0, &parseStruct);
	free (bytes);
	return list;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("lua");
	ret->os = strdup ("any");
	ret->machine = strdup ("LUA 5.3 VM");
	ret->arch = strdup ("lua");
	ret->bits = lua53_data.instructionSize * 8;
	if (ret->bits < 1) {
		ret->bits = 32;
	} else if (ret->bits != 32) {
		R_LOG_WARN ("lua vm using %d bits registers is not well tested", ret->bits);
	}
	ret->has_va = true;
	ret->big_endian = false;
	return ret;
}

static void addEntry(LuaFunction *func, ParseStruct *parseStruct){
	if (!func->parent_func) {
		RBinAddr *ptr = NULL;
		if ((ptr = R_NEW0 (RBinAddr))) {
			ptr->paddr = ptr->vaddr = func->code_offset + lua53_data.intSize;
			r_list_append (parseStruct->data, ptr);
		}
	}
}

static RList *entries(RBinFile *bf) {
	r_return_val_if_fail (bf, NULL);
	if (bf->size < 20) {
		return NULL;
	}
	ut8 *buf = malloc (bf->size);
	if (!buf) {
		R_LOG_ERROR ("cannot malloc filesize");
		return false;
	}
	r_buf_read_at (bf->buf, 0, buf, bf->size);

	// header + version + format + stringterminators + sizes + integer + number + upvalues
	ut64 headersize = 4 + 1 + 1 + 6 + 5 + buf[15] + buf[16] + 1;

	ParseStruct parseStruct;
	memset (&parseStruct, 0, sizeof (parseStruct));
	parseStruct.onFunction = addEntry;
	parseStruct.data = NULL;

	parseStruct.data = r_list_new ();
	if (parseStruct.data) {
		lua53parseFunction (buf, headersize, bf->size, 0, &parseStruct);
	}
	free (buf);
	return parseStruct.data;
}

RBinPlugin r_bin_plugin_lua = {
	.meta = {
		.name = "lua",
		.desc = "Compiled LUA bin plugin (lua 5.3)",
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
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_lua,
	.version = R2_VERSION
};
#endif
