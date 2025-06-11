/* radare - LGPL - Copyright 2011-2025 - pancake, h4ng3r */

#include <r_bin.h>
#include "../i/private.h"
#include "dex/dex.h"
// XXX use rhash/crytpo/trans api instead
#define r_hash_adler32 __adler32
// TODO rename muta/hash to muta/p/algo
#include "../../muta/hash/adler32.c"

#define DBG_END_SEQUENCE          0x00
#define DBG_ADVANCE_PC            0x01
#define DBG_ADVANCE_LINE          0x02
#define DBG_START_LOCAL           0x03
#define DBG_START_LOCAL_EXTENDED  0x04
#define DBG_END_LOCAL             0x05
#define DBG_RESTART_LOCAL         0x06
#define DBG_SET_PROLOGUE_END      0x07
#define DBG_SET_EPILOGUE_BEGIN    0x08
#define DBG_SET_FILE              0x09
#define DBG_FIRST_SPECIAL         0x0A

#define DBG_LINE_BASE             -4
#define DBG_LINE_RANGE            15

extern struct r_bin_dbginfo_t r_bin_dbginfo_dex;

static ut64 get_method_attr(ut64 MA) {
	ut64 flags = 0;
	if (MA & R_DEX_METH_PUBLIC) {
		flags |= R_BIN_ATTR_PUBLIC;
	}
	if (MA & R_DEX_METH_PRIVATE) {
		flags |= R_BIN_ATTR_PRIVATE;
	}
	if (MA & R_DEX_METH_PROTECTED) {
		flags |= R_BIN_ATTR_PROTECTED;
	}
	if (MA & R_DEX_METH_STATIC) {
		flags |= R_BIN_ATTR_STATIC;
	}
	if (MA & R_DEX_METH_FINAL) {
		flags |= R_BIN_ATTR_FINAL;
	}
	if (MA & R_DEX_METH_SYNCHRONIZED) {
		flags |= R_BIN_ATTR_SYNCHRONIZED;
	}
	if (MA & R_DEX_METH_BRIDGE) {
		flags |= R_BIN_ATTR_BRIDGE;
	}
	if (MA & R_DEX_METH_VARARGS) {
		flags |= R_BIN_ATTR_VARARGS;
	}
	if (MA & R_DEX_METH_NATIVE) {
		flags |= R_BIN_ATTR_NATIVE;
	}
	if (MA & R_DEX_METH_ABSTRACT) {
		flags |= R_BIN_ATTR_ABSTRACT;
	}
	if (MA & R_DEX_METH_STRICT) {
		flags |= R_BIN_ATTR_STRICT;
	}
	if (MA & R_DEX_METH_SYNTHETIC) {
		flags |= R_BIN_ATTR_SYNTHETIC;
	}
	if (MA & R_DEX_METH_MIRANDA) {
		flags |= R_BIN_ATTR_MIRANDA;
	}
	if (MA & R_DEX_METH_CONSTRUCTOR) {
		flags |= R_BIN_ATTR_CONSTRUCTOR;
	}
	if (MA & R_DEX_METH_DECLARED_SYNCHRONIZED) {
		flags |= R_BIN_ATTR_SYNCHRONIZED;
	}
	return flags;
}

static ut64 offset_of_method_idx(RBinFile *bf, int idx) {
	RBinDexObj *dex = bf->bo->bin_obj;
	// ut64 off = dex->header.method_offset + idx;
	r_strf_var (key, 64, "method.%d", idx);
	return sdb_num_get (dex->mdb, key, 0);
}

static ut64 dex_field_offset(RBinDexObj *bin, int fid) {
	return bin->header.fields_offset + (fid * 8); // (sizeof (DexField) * fid);
}

static const char *getstr(RBinDexObj *dex, int idx) {
	ut8 buf[LEB_MAX_SIZE];
	if (idx < 0 || idx >= dex->header.strings_size || !dex->strings) {
		return NULL;
	}
	if (dex->cal_strings) {
		const char *p = dex->cal_strings[idx];
		if (!R_STR_ISEMPTY (p)) {
			return p;
		}
	} else {
		dex->cal_strings = R_NEWS0 (char *, dex->header.strings_size);
	}
	const ut32 string_index = dex->strings[idx];
	if (string_index >= dex->size) {
		return NULL;
	}
	if (r_buf_read_at (dex->b, string_index, buf, sizeof (buf)) != sizeof (buf)) {
		return NULL;
	}
	ut64 len;
	int uleblen = r_uleb128 (buf, sizeof (buf), &len, NULL) - buf;
	if (!uleblen || uleblen >= dex->size || uleblen >= dex->header.strings_size) {
		return NULL;
	}
	if (!len || len >= dex->size) {
		return NULL;
	}
	ut8 *ptr = malloc (len + 1);
	if (ptr) {
		r_buf_read_at (dex->b, string_index + uleblen, ptr, len);
		ptr[len] = 0;
		dex->cal_strings[idx] = (char *)ptr;
		return (const char *)ptr;
	}
	return NULL;
}

typedef enum {
	kAccessForClass = 0,
	kAccessForMethod = 1,
	kAccessForField = 2,
	kAccessForMAX
} AccessFor;

static char *createAccessFlagStr(ut32 flags, AccessFor forWhat) {
	#define NUM_FLAGS 18
	static const char *kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
		{
			/* class, inner class */
			"public", /* 0x0001 */
			"private", /* 0x0002 */
			"protected", /* 0x0004 */
			"static", /* 0x0008 */
			"final", /* 0x0010 */
			"?", /* 0x0020 */
			"?", /* 0x0040 */
			"?", /* 0x0080 */
			"?", /* 0x0100 */
			"interface", /* 0x0200 */
			"abstract", /* 0x0400 */
			"?", /* 0x0800 */
			"synthetic", /* 0x1000 */
			"annotation", /* 0x2000 */
			"enum", /* 0x4000 */
			"?", /* 0x8000 */
			"verified", /* 0x10000 */
			"optimized", /* 0x20000 */
		},
		{
			/* method */
			"public", /* 0x0001 */
			"private", /* 0x0002 */
			"protected", /* 0x0004 */
			"static", /* 0x0008 */
			"final", /* 0x0010 */
			"synchronized", /* 0x0020 */
			"bridge", /* 0x0040 */
			"varargs", /* 0x0080 */
			"native", /* 0x0100 */
			"?", /* 0x0200 */
			"abstract", /* 0x0400 */
			"strict", /* 0x0800 */
			"synthetic", /* 0x1000 */
			"?", /* 0x2000 */
			"?", /* 0x4000 */
			"miranda", /* 0x8000 */
			"constructor", /* 0x10000 */
			"declared_synchronized", /* 0x20000 */
		},
		{
			/* field */
			"public", /* 0x0001 */
			"private", /* 0x0002 */
			"protected", /* 0x0004 */
			"static", /* 0x0008 */
			"final", /* 0x0010 */
			"?", /* 0x0020 */
			"volatile", /* 0x0040 */
			"transient", /* 0x0080 */
			"?", /* 0x0100 */
			"?", /* 0x0200 */
			"?", /* 0x0400 */
			"?", /* 0x0800 */
			"synthetic", /* 0x1000 */
			"?", /* 0x2000 */
			"enum", /* 0x4000 */
			"?", /* 0x8000 */
			"?", /* 0x10000 */
			"?", /* 0x20000 */
		},
	};
	size_t i, count = r_num_bit_count (flags);
	// produces a huge number????
	if (count < 1) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 1) {
			const char *accessStr = kAccessStrings[forWhat][i];
			if (!r_strbuf_is_empty (sb)) {
				r_strbuf_append (sb, " ");
			}
			r_strbuf_append (sb, accessStr);
		}
		flags >>= 1;
	}
	return r_strbuf_drain (sb);
}

static const char *dex_type_descriptor(RBinDexObj *dex, int type_idx) {
	if (type_idx < 0 || type_idx >= dex->header.types_size) {
		return NULL;
	}
	return getstr (dex, dex->types[type_idx].descriptor_id);
}

static ut16 type_desc(RBinDexObj *bin, ut16 type_idx) {
	if (type_idx >= bin->header.types_size || type_idx >= bin->size) {
		return UT16_MAX;
	}
	return bin->types[type_idx].descriptor_id;
}

static char *dex_get_proto(RBinDexObj *bin, int proto_id) {
	if (proto_id >= bin->header.prototypes_size) {
		return NULL;
	}
	ut32 params_off = bin->protos[proto_id].parameters_off;
	if (params_off >= bin->size) {
		return NULL;
	}
	ut32 type_id = bin->protos[proto_id].return_type_id;
	if (type_id >= bin->header.types_size ) {
		return NULL;
	}
	const char *return_type = getstr (bin, bin->types[type_id].descriptor_id);
	if (!return_type) {
		return NULL;
	}
	if (!params_off) {
		return r_str_newf ("()%s", return_type);
	}
	ut8 params_buf[sizeof (ut32)];
	if (!r_buf_read_at (bin->b, params_off, params_buf, sizeof (params_buf))) {
		return NULL;
	}
	// size of the list, in 16 bit entries
	ut32 list_size = r_read_le32 (params_buf);
	if (list_size >= ST32_MAX) {
		R_LOG_WARN ("function prototype contains too many parameters (> 2 million)");
		list_size = ST32_MAX;
	}
	size_t typeidx_bufsize = (list_size * sizeof (ut16));
	if (params_off + typeidx_bufsize > bin->size) {
		R_LOG_WARN ("truncated typeidx buffer from %d to %d",
			(int)(params_off + typeidx_bufsize), (int)(bin->size - params_off));
		typeidx_bufsize = bin->size - params_off;
		// early return as this may result on so many trashy symbols that take too much time to load
		// this is only happening when there's a corrupted dex.
		return NULL;
	}
	RStrBuf *sig = r_strbuf_new ("(");
	if (typeidx_bufsize > 0) {
		ut8 *typeidx_buf = malloc (typeidx_bufsize);
		if (!typeidx_buf || !r_buf_read_at (bin->b, params_off + 4, typeidx_buf, typeidx_bufsize)) {
			r_strbuf_free (sig);
			return NULL;
		}
		size_t off;
		for (off = 0; off + 1 < typeidx_bufsize; off += 2) {
			ut16 type_idx = r_read_le16 (typeidx_buf + off);
			ut16 type_desc_id = type_desc (bin, type_idx);
			if (type_desc_id == UT16_MAX) {
				r_strbuf_append (sig, "?;");
			} else {
				const char *buff = getstr (bin, type_desc_id);
				r_strbuf_append (sig, r_str_get_fail (buff, "?;"));
			}
		}
		free (typeidx_buf);
	}
	r_strbuf_appendf (sig, ")%s", return_type);
	return r_strbuf_drain (sig);
}

static char *dex_method_signature(RBinDexObj *bin, int method_idx) {
	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		return NULL;
	}
	return dex_get_proto (bin, bin->methods[method_idx].proto_id);
}

static ut32 read32(RBuffer* b, ut64 addr) {
	ut32 n = 0;
	r_buf_read_at (b, addr, (ut8*)&n, sizeof (n));
	return r_read_le32 (&n);
}

static ut16 read16(RBuffer* b, ut64 addr) {
	ut16 n = 0;
	r_buf_read_at (b, addr, (ut8*)&n, sizeof (n));
	return r_read_le16 (&n);
}

static RList *dex_method_signature2(RBinDexObj *bin, int method_idx) {
	ut32 proto_id, params_off, list_size;
	ut16 type_idx;
	size_t i;

	RList *params = r_list_new ();
	if (!params) {
		return NULL;
	}
	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		goto out_error;
	}
	proto_id = bin->methods[method_idx].proto_id;
	if (proto_id >= bin->header.prototypes_size) {
		goto out_error;
	}
	params_off = bin->protos[proto_id].parameters_off;
	if (params_off  >= bin->size) {
		goto out_error;
	}
	if (!params_off) {
		return params;
	}
	list_size = read32 (bin->b, params_off);
	for (i = 0; i < list_size; i++) {
		ut64 of = params_off + 4 + (i * 2);
		if (of >= bin->size || of < params_off) {
			break;
		}
		type_idx = read16 (bin->b, of);
		if (type_idx >= bin->header.types_size || type_idx > bin->size) {
			break;
		}
		const char *buff = getstr (bin, bin->types[type_idx].descriptor_id);
		if (!buff) {
			break;
		}
		r_list_append (params, (void *)buff);
	}
	return params;
out_error:
	r_list_free (params);
	return NULL;
}

// TODO: fix this, now has more registers that it should
// XXX. this is using binfile->buf directly :(
// https://github.com/android/platform_dalvik/blob/0641c2b4836fae3ee8daf6c0af45c316c84d5aeb/libdex/DexDebugInfo.cpp#L312
// https://github.com/android/platform_dalvik/blob/0641c2b4836fae3ee8daf6c0af45c316c84d5aeb/libdex/DexDebugInfo.cpp#L141
static void dex_parse_debug_item(RBinFile *bf, RBinDexClass *c, int MI, int MA, int paddr, int ins_size, int insns_size, const char *class_name, int regsz, int debug_info_off) {
	RBin *rbin = bf->rbin;
	RBinDexObj *dex = bf->bo->bin_obj; //  bin .. unnecessary arg
	// runtime error: pointer index expression with base 0x000000004402 overflowed to 0xffffffffff0043fc
	if (debug_info_off >= r_buf_size (bf->buf)) {
		return;
	}
	ut64 line_start;
	ut64 parameters_size;
	ut64 param_type_idx;
	ut16 argReg = regsz - ins_size;
	ut64 source_file_idx = c->source_file;
	bool keep = true;
	if (argReg > regsz) {
		return; // this return breaks tests
	}
	r_buf_seek (bf->buf, debug_info_off, R_BUF_SET);
	ut64 res;
	if (r_buf_uleb128 (bf->buf, &res) < 1) {
		return;
	}
	line_start = res;
	if (r_buf_uleb128 (bf->buf, &res) < 1) {
		return;
	}
	parameters_size = res;

	// TODO: check when we should use source_file
	// The state machine consists of five registers
	ut32 address = 0;
	ut32 line = line_start;
	RList *debug_positions = r_list_newf ((RListFree)free);
	RList *emitted_debug_locals = r_list_newf ((RListFree)free);

	struct dex_debug_local_t *debug_locals = calloc (sizeof (struct dex_debug_local_t), regsz + 1);
	if (!(MA & 0x0008)) {
		debug_locals[argReg].name = "this";
		debug_locals[argReg].descriptor = r_str_newf ("%s;", class_name);
		debug_locals[argReg].startAddress = 0;
		debug_locals[argReg].signature = NULL;
		debug_locals[argReg].live = true;
		argReg++;
	}
	RList *params = dex_method_signature2 (dex, MI);

	RListIter *iter;
	const char *name;
	char *type;
	int reg;

	r_list_foreach (params, iter, type) {
		if ((argReg >= regsz) || !type || parameters_size <= 0) {
			goto beach;
		}
		if (r_buf_uleb128 (bf->buf, &res) < 1) {
			goto beach;
		}
		param_type_idx = res - 1;
		name = getstr (dex, param_type_idx);
		reg = argReg;
		switch (type[0]) {
		case 'D':
		case 'J':
			argReg += 2;
			break;
		default:
			argReg += 1;
			break;
		}
		if (R_STR_ISEMPTY (name)) {
			debug_locals[reg].name = name;
			debug_locals[reg].descriptor = type;
			debug_locals[reg].signature = NULL;
			debug_locals[reg].startAddress = address;
			debug_locals[reg].live = true;
		}
		parameters_size--;
	}
	ut8 opcode = 0;
	if (r_buf_read (bf->buf, &opcode, 1) != 1) {
		goto beach;
	}
	while (keep) {
		switch (opcode) {
		case DBG_END_SEQUENCE:
			keep = false;
			break;
		case DBG_ADVANCE_PC:
			{
			ut64 addr_diff;
			if (r_buf_uleb128 (bf->buf, &addr_diff) < 1) {
				goto beach;
			}
			address += addr_diff;
			}
			break;
		case DBG_ADVANCE_LINE:
			{
			st64 line_diff;
			r_buf_sleb128 (bf->buf, &line_diff);
			line += line_diff;
			}
			break;
		case DBG_START_LOCAL:
			{
			ut64 register_num, name_idx, type_idx;
			r_buf_uleb128 (bf->buf, &register_num);
			r_buf_uleb128 (bf->buf, &name_idx);
			r_buf_uleb128 (bf->buf, &type_idx);
			name_idx--;
			type_idx--;
			if (register_num >= regsz) {
				goto beach;
			}
			// Emit what was previously there, if anything
			// emitLocalCbIfLive
			if (debug_locals[register_num].live) {
				struct dex_debug_local_t *local = malloc (
					sizeof (struct dex_debug_local_t));
				if (!local) {
					keep = false;
					break;
				}
				local->name = debug_locals[register_num].name;
				local->descriptor = debug_locals[register_num].descriptor;
				local->startAddress = debug_locals[register_num].startAddress;
				local->signature = debug_locals[register_num].signature;
				local->live = true;
				local->reg = register_num;
				local->endAddress = address;
				r_list_append (emitted_debug_locals, local);
			}
			debug_locals[register_num].name = getstr (dex, name_idx);
			debug_locals[register_num].descriptor = dex_type_descriptor (dex, type_idx);
			debug_locals[register_num].startAddress = address;
			debug_locals[register_num].signature = NULL;
			debug_locals[register_num].live = true;
			//eprintf("DBG_START_LOCAL %x %x %x\n", register_num, name_idx, type_idx);
			}
			break;
		case DBG_START_LOCAL_EXTENDED:
			{
			ut64 register_num, name_idx, type_idx, sig_idx;
			r_buf_uleb128 (bf->buf, &register_num);
			r_buf_uleb128 (bf->buf, &name_idx);
			r_buf_uleb128 (bf->buf, &type_idx);
			r_buf_uleb128 (bf->buf, &sig_idx);
			sig_idx--;
			type_idx--;
			name_idx--;
			if (register_num >= regsz) {
				goto beach;
			}

			// Emit what was previously there, if anything
			// emitLocalCbIfLive
			if (debug_locals[register_num].live) {
				struct dex_debug_local_t *local = malloc (
					sizeof (struct dex_debug_local_t));
				if (!local) {
					keep = false;
					break;
				}
				local->name = debug_locals[register_num].name;
				local->descriptor = debug_locals[register_num].descriptor;
				local->startAddress = debug_locals[register_num].startAddress;
				local->signature = debug_locals[register_num].signature;
				local->live = true;
				local->reg = register_num;
				local->endAddress = address;
				r_list_append (emitted_debug_locals, local);
			}
			debug_locals[register_num].name = getstr (dex, name_idx);
			debug_locals[register_num].descriptor = dex_type_descriptor (dex, type_idx);
			debug_locals[register_num].startAddress = address;
			debug_locals[register_num].signature = getstr (dex, sig_idx);
			debug_locals[register_num].live = true;
			}
			break;
		case DBG_END_LOCAL:
			{
			ut64 register_num;
			if (r_buf_uleb128 (bf->buf, &register_num) < 1) {
				goto beach;
			}
			// emitLocalCbIfLive
			if (register_num >= regsz) {
				goto beach;
			}
			if (debug_locals[register_num].live) {
				struct dex_debug_local_t *local = malloc (
					sizeof (struct dex_debug_local_t));
				if (!local) {
					keep = false;
					break;
				}
				local->name = debug_locals[register_num].name;
				local->descriptor = debug_locals[register_num].descriptor;
				local->startAddress = debug_locals[register_num].startAddress;
				local->signature = debug_locals[register_num].signature;
				local->live = true;
				local->reg = register_num;
				local->endAddress = address;
				r_list_append (emitted_debug_locals, local);
			}
			debug_locals[register_num].live = false;
			}
			break;
		case DBG_RESTART_LOCAL:
			{
			ut64 register_num;
			if (r_buf_uleb128 (bf->buf, &register_num) < 1) {
				goto beach;
			}
			if (register_num >= regsz) {
				goto beach;
			}
			if (!debug_locals[register_num].live) {
				debug_locals[register_num].startAddress = address;
				debug_locals[register_num].live = true;
			}
			}
			break;
		case DBG_SET_PROLOGUE_END:
			// ignored
			break;
		case DBG_SET_EPILOGUE_BEGIN:
			// ignored
			break;
		case DBG_SET_FILE:
			{
				ut64 res;
				if (r_buf_uleb128 (bf->buf, &res) < 1) {
					goto beach;
				}
				source_file_idx = res - 1;
			}
			break;
		default:
			if (opcode >= DBG_FIRST_SPECIAL) {
				int adjusted_opcode = opcode - DBG_FIRST_SPECIAL;
				int addr_delta = adjusted_opcode / DBG_LINE_RANGE;
				int line_delta = DBG_LINE_BASE + (adjusted_opcode % DBG_LINE_RANGE);
				address += addr_delta;
				line += line_delta;
				if (dex->dexdump) {
					struct dex_debug_position_t *position =
						R_NEW0 (struct dex_debug_position_t);
					position->source_file_idx = source_file_idx;
					position->address = address;
					position->line = line;
					r_list_append (debug_positions, position);
				}
				RBinAddrline item = {
					.addr = address + paddr,
					.file = getstr (dex, source_file_idx),
					.line = line,
				};
				bf->addrline.al_add (&bf->addrline, item);
			} else {
				R_LOG_ERROR ("unknown dex debug opcode: 0x%02x", opcode);
			}
			break;
		}
		if (r_buf_read (bf->buf, &opcode, 1) != 1) {
			break;
		}
	}

	if (!dex->dexdump) {
		goto beach;
	}

	RListIter *iter2;
	struct dex_debug_position_t *position;

	rbin->cb_printf ("      positions     :\n");
	r_list_foreach (debug_positions, iter2, position) {
		rbin->cb_printf ("        0x%04"PFMT64x" line=%"PFMT64u"\n",
				 position->address, position->line);
	}

	rbin->cb_printf ("      locals        :\n");

	RListIter *iter3;
	struct dex_debug_local_t *local;
	r_list_foreach (emitted_debug_locals, iter3, local) {
		if (local->signature) {
			rbin->cb_printf (
				"        0x%04x - 0x%04x reg=%d %s %s %s\n",
				local->startAddress, local->endAddress,
				local->reg, local->name, local->descriptor,
				local->signature);
		} else {
			rbin->cb_printf (
				"        0x%04x - 0x%04x reg=%d %s %s\n",
				local->startAddress, local->endAddress,
				local->reg, local->name, local->descriptor);
		}
	}

	for (reg = 0; reg < regsz; reg++) {
		if (!debug_locals[reg].name) {
			continue;
		}
		if (debug_locals[reg].live) {
			if (debug_locals[reg].signature) {
				rbin->cb_printf (
					"        0x%04x - 0x%04x reg=%d %s %s %s\n",
					debug_locals[reg].startAddress,
					insns_size, reg, debug_locals[reg].name,
					debug_locals[reg].descriptor,
					debug_locals[reg].signature);
			} else {
				rbin->cb_printf (
					"        0x%04x - 0x%04x reg=%d %s %s\n",
					debug_locals[reg].startAddress,
					insns_size, reg, debug_locals[reg].name,
					debug_locals[reg].descriptor);
			}
		}
	}
beach:
	r_list_free (debug_positions);
	r_list_free (emitted_debug_locals);
	r_list_free (params);
	free (debug_locals);
}

static Sdb *get_sdb(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinObject *o = bf->bo;
	R_RETURN_VAL_IF_FAIL (o && o->bin_obj, NULL);
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) o->bin_obj;
	return bin->kv;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	bf->bo->bin_obj = r_bin_dex_new_buf (buf, bf->rbin->options.verbose);
	return bf->bo->bin_obj != NULL;
}

static bool check(RBinFile *bf, RBuffer *buf) {
	ut8 tmp[8];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	if (r < sizeof (tmp)) {
		return false;
	}
	// Non-extended opcode dex file
	if (!memcmp (tmp, "dex\n035\0", 8)) {
		return true;
	}
	// Extended (jumnbo) opcode dex file, ICS+ only (sdk level 14+)
	if (!memcmp (tmp, "dex\n036\0", 8)) {
		return true;
	}
	// Two new opcodes: invoke-polymorphic and invoke-custom (sdk level 26+)
	if (!memcmp (tmp, "dex\n038\0", 8)) {
		return true;
	}
	// M3 (Nov-Dec 07)
	if (!memcmp (tmp, "dex\n009\0", 8)) {
		return true;
	}
	// M5 (Feb-Mar 08)
	if (!memcmp (tmp, "dex\n009\0", 8)) {
		return true;
	}
	// Default fall through, should still be a dex file
	if (!memcmp (tmp, "dex\n", 4)) {
		return true;
	}
	return false;
}

static RBinInfo *info(RBinFile *bf) {
	RBinHash *h;
	RBinInfo *ret = R_NEW0 (RBinInfo);
	RBinDexObj *dex = bf->bo->bin_obj;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("DEX CLASS");
	ret->has_va = true;
	ret->has_lit = true;
	ret->bclass = r_bin_dex_get_version (dex);
	ret->rclass = strdup ("class");
	ret->os = strdup ("linux");
	ret->subsystem = strdup (r_str_get_fail (dex->dexSubsystem, "java"));
	ret->machine = strdup ("Dalvik VM");
	h = &ret->sum[0];
	h->type = "sha1";
	h->len = 20;
	h->addr = 12;
	h->from = 12;
	h->to = r_buf_size (bf->buf) - 32;
	r_buf_read_at (bf->buf, 12, h->buf, 20);
	h = &ret->sum[1];
	h->type = "adler32";
	h->len = 4;
	h->addr = 8;
	h->from = 12;
	h->to = r_buf_size (bf->buf) - h->from;
	r_buf_read_at (bf->buf, 8, h->buf, 12);
	h = &ret->sum[2];
	h->type = 0;
	r_buf_read_at (bf->buf, 8, h->buf, 4);
	// this is slow but computed once, so we can use r_buf_data or just do r_buf_read()
	// not sure if we want to expose the computed checksum everytime we open the file
	// also the checksum is computed by other methods in RBin, so maybe good to generalize
	{
		ut32 fc = r_buf_read_le32_at (bf->buf, 8);
		ut64 tmpsz;
		const ut8 *tmp = r_buf_data (bf->buf, &tmpsz);
		ut32 cc = __adler32 (tmp + 12, tmpsz - 12);
		if (fc != cc) {
			eprintf ("# adler32 checksum doesn't match. Type this to fix it:\n");
			eprintf ("wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8\n");
		}
	}
	ret->arch = strdup ("dalvik");
	ret->lang = "dalvik";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; //1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

static RList *strings(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinString *ptr = NULL;
	RList *ret = NULL;
	int i;
	ut64 len;
	ut8 buf[LEB_MAX_SIZE];
	ut64 off;
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *)bf->bo->bin_obj;
	if (!bin || !bin->strings) {
		return NULL;
	}
	if (bin->header.strings_size > bin->size) {
		bin->strings = NULL;
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	for (i = 0; i < bin->header.strings_size; i++) {
		ptr = R_NEW0 (RBinString);
		if (bin->strings[i] > bin->size || bin->strings[i] + 6 > bin->size) {
			goto out_error;
		}
		r_buf_read_at (bin->b, bin->strings[i], buf, sizeof (buf));
		r_uleb128 (buf, sizeof (buf), &len, NULL);

		if (len > 5 && len < R_BIN_SIZEOF_STRINGS) {
			ptr->string = malloc (len + 1);
			if (!ptr->string) {
				goto out_error;
			}
			off = bin->strings[i] + r_uleb128_len (buf, sizeof (buf));
			if (off + len >= bin->size || off + len < len) {
				free (ptr->string);
				goto out_error;
			}
			r_buf_read_at (bin->b, off, (ut8*)ptr->string, len);
			ptr->string[len] = 0;
			if ((ptr->string[0] == 'L' && strchr (ptr->string, '/')) || !strncmp (ptr->string, "[L", 2)) {
				free (ptr->string);
				free (ptr);
				continue;
			}
			ptr->paddr = bin->strings[i];
			ptr->vaddr = ptr->paddr + bf->bo->baddr;
			ptr->size = len;
			ptr->length = len;
			ptr->ordinal = i + 1;
			r_list_append (ret, ptr);
		} else {
			free (ptr);
		}
	}
	return ret;
out_error:
	r_list_free (ret);
	free (ptr);
	return NULL;
}

static const char *dex_method_name(RBinDexObj *bin, int idx) {
	if (idx < 0 || idx >= bin->header.method_size) {
		return NULL;
	}
	ut16 cid = bin->methods[idx].class_id;
	if (cid >= bin->header.strings_size) {
		return NULL;
	}
	int tid = bin->methods[idx].name_id;
	if (tid < 0 || tid >= bin->header.strings_size) {
		return NULL;
	}
	return getstr (bin, tid);
}

static char *simplify(char *s) {
	char *p = (char *)r_str_rchr (s, NULL, '/');
	if (p) {
		r_str_cpy (s, p + 1);
	}
	r_str_replace_char (s, '/', '.');
	return s;
}

static char *dex_class_name_byid(RBinDexObj *dex, int cid) {
	R_RETURN_VAL_IF_FAIL (dex && dex->types, NULL);
	if (cid < 0 || cid >= dex->header.types_size) {
		return NULL;
	}
	int tid = dex->types[cid].descriptor_id;
	const char *s = getstr (dex, tid);
	if (s) {
		char *r = strdup (s);
		if (dex->simplifiedDemangling) {
			simplify (r);
		}
		return r;
	}
	return NULL;
}

static char *dex_class_name(RBinDexObj *dex, RBinDexClass *c) {
	char *s = dex_class_name_byid (dex, c->class_id);
	if (dex->simplifiedDemangling) {
		simplify (s);
		if (*s == 'L') {
			r_str_cpy (s, s + 1);
		}
	}
	return s;
}

static char *dex_field_name(RBinDexObj *dex, int fid) {
	int tid;
	ut16 cid, type_id;
	R_RETURN_VAL_IF_FAIL (dex&& dex->fields, NULL);

	if (fid < 0 || fid >= dex->header.fields_size) {
		return NULL;
	}
	cid = dex->fields[fid].class_id;
	if (cid >= dex->header.types_size) {
		return NULL;
	}
	type_id = dex->fields[fid].type_id;
	if (type_id >= dex->header.types_size) {
		return NULL;
	}
	tid = dex->fields[fid].name_id;
	const char *a = getstr (dex, dex->types[cid].descriptor_id);
	const char *b = getstr (dex, tid);
	const char *c = getstr (dex, dex->types[type_id].descriptor_id);
	if (dex->simplifiedDemangling) {
		if (a && b && c) {
			char *_a = simplify (strdup (a));
			char *_b = simplify (strdup (b));
			char *_c = simplify (strdup (c));
			char *str =  r_str_newf ("(%s) %s.%s", _c, _a, _b);
			free (_a);
			free (_b);
			free (_c);
			return str;
		}
		return r_str_newf ("(%d) %d.%d",
				dex->types[type_id].descriptor_id,
				tid,
				dex->types[cid].descriptor_id);
	}
	return (a && b && c)
		? r_str_newf ("%s->%s %s", a, b, c)
		: r_str_newf ("%d->%d %d", dex->types[cid].descriptor_id, tid, dex->types[type_id].descriptor_id);
}

static char *dex_method_fullname(RBinDexObj *dex, int method_idx) {
	R_RETURN_VAL_IF_FAIL (dex && dex->types, NULL);
	if (method_idx < 0 || method_idx >= dex->header.method_size) {
		return NULL;
	}
	ut16 cid = dex->methods[method_idx].class_id;
	if (cid >= dex->header.types_size) {
		return NULL;
	}
	const char *name = dex_method_name (dex, method_idx);
	if (!name) {
		return NULL;
	}
	char *flagname = NULL;

	char *class_name = dex_class_name_byid (dex, cid);
	if (!class_name) {
		class_name = strdup ("???");
	}
	r_str_replace_char (class_name, ';', 0);
	char *signature = dex_method_signature (dex, method_idx);
	if (signature) {
		flagname = r_str_newf ("%s.%s%s", class_name, name, signature);
		free (signature);
	} else {
		flagname = r_str_newf ("%s.%s%s", class_name, name, "???");
	}
	free (class_name);
	if (flagname && dex->simplifiedDemangling) {
		char *p = strchr (flagname, '(');
		if (p) {
			*p = 0;
			char *q = strchr (p + 1, ')');
			if (q) {
				simplify (q + 1);
				r_str_cpy (p, q + 1);
			}
			simplify (flagname);
		}
	}
	return flagname;
}

static ut64 dex_get_type_offset(RBinFile *bf, int type_idx) {
	RBinDexObj *bin = (RBinDexObj*) bf->bo->bin_obj;
	if (!bin || !bin->types) {
		return 0;
	}
	if (type_idx < 0 || type_idx >= bin->header.types_size) {
		return 0;
	}
	return bin->header.types_offset + type_idx * 0x04; //&bin->types[type_idx];
}

static const char *dex_class_super_name(RBinDexObj *bin, RBinDexClass *c) {
	R_RETURN_VAL_IF_FAIL (bin && bin->types && c, NULL);
	int cid = c->super_class;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	int tid = bin->types[cid].descriptor_id;
	return getstr (bin, tid);
}

static ut64 peek_uleb(RBuffer *b, bool *err, size_t *nn) {
	ut64 n = UT64_MAX;
	int len = r_buf_uleb128 (b, &n);
	if (len < 1) {
		if (err) {
			*err |= true;
		}
	} else {
		*nn += len;
	}
	return n;
}

static void parse_dex_class_fields(RBinFile *bf, RBinDexClass *c, RBinClass *cls, int *sym_count, ut64 fields_count, bool is_sfield) {
	RBinDexObj *dex = bf->bo->bin_obj;
	RBin *bin = bf->rbin;
	ut64 lastIndex = 0;
	ut8 ff[sizeof (DexField)] = {0};
	int total, tid;
	DexField field;
	size_t i, skip = 0;

	for (i = 0; i < fields_count; i++) {
		bool err = false;
		ut64 fieldIndex = peek_uleb (bf->buf, &err, &skip);
		ut64 accessFlags = peek_uleb (bf->buf, &err, &skip);
		if (err) {
			break;
		}
		fieldIndex += lastIndex;
		total = dex->header.fields_offset + (sizeof (DexField) * fieldIndex);
		if (total >= dex->size || total < dex->header.fields_offset) {
			break;
		}
		if (r_buf_read_at (bf->buf, total, ff, sizeof (DexField)) != sizeof (DexField)) {
			break;
		}
		field.class_id = r_read_le16 (ff);
		field.type_id = r_read_le16 (ff + 2);
		field.name_id = r_read_le32 (ff + 4);
		const char *fieldName = getstr (dex, field.name_id);
		if (field.type_id >= dex->header.types_size) {
			break;
		}
		tid = dex->types[field.type_id].descriptor_id;
		const char *type_str = getstr (dex, tid);
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		const char *cls_name = r_bin_name_tostring (cls->name);
		const char *ftype = is_sfield ? "sfield": "ifield";
		char *s = r_str_newf ("%s.%s_%s:%s", cls_name, ftype, fieldName, type_str);
		sym->name = r_bin_name_new (s);
		if (is_sfield) {
			sym->type = "STATIC";
		} else {
			sym->type = "FIELD";
		}
		s = r_str_replace (s, "method.", "", 0);
		r_str_replace_char (s, ';', 0);
		r_bin_name_filtered (sym->name, s);
		free (s);
		sym->paddr = total;
		sym->vaddr = sym->paddr; //  + baddr;
		sym->lang = R_BIN_LANG_JAVA;
		sym->ordinal = (*sym_count)++;

		if (dex->dexdump) {
			char *accessStr = createAccessFlagStr (accessFlags, kAccessForField);
			bin->cb_printf ("    #%u              : (in %s;)\n", (unsigned int)i, cls_name);
			bin->cb_printf ("      name          : '%s'\n", fieldName);
			bin->cb_printf ("      type          : '%s'\n", type_str);
			bin->cb_printf ("      access        : 0x%04x (%s)\n",
					 (ut32)accessFlags, r_str_get (accessStr));
			free (accessStr);
		}
		r_list_append (dex->methods_list, sym);

		RBinField *field = R_NEW0 (RBinField);
		field->vaddr = field->paddr = sym->paddr;
		field->name = r_bin_name_clone (sym->name);
		field->attr = get_method_attr (accessFlags);
		r_list_append (cls->fields, field);
		lastIndex = fieldIndex;
	}
}

// TODO: refactor this method
static void parse_dex_class_method(RBinFile *bf, RBinDexClass *c, RBinClass *cls, int *sym_count, ut64 DM, int *methods, bool is_direct) {
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	RBinDexObj *dex = bf->bo->bin_obj;
	bool bin_dbginfo = bf->rbin->want_dbginfo;
	ut64 omi = 0;
	bool catchAll;
	ut16 regsz = 0, ins_size = 0, outs_size = 0, tries_size = 0;
	ut16 start_addr, insn_count = 0;
	ut32 debug_info_off = 0, insns_size = 0;

	if (!dex->trycatch_list) {
		dex->trycatch_list = r_list_newf ((RListFree)r_bin_trycatch_free);
	}
	const ut64 baddr = bf->bo->baddr;
	size_t skip = 0;
	ut64 bufsz = r_buf_size (bf->buf);
	ut64 encoded_method_addr;
	bool err = false;
	ut64 MI, MA, MC;
	const char *cls_name = r_bin_name_tostring (cls->name);
	ut64 i;
	for (i = 0; i < DM; i++) {
		err = false;
		skip = 0;
		// Needed because theres another rbufseek call inside this loop. must be fixed
		encoded_method_addr = r_buf_tell (bf->buf);
		MI = peek_uleb (bf->buf, &err, &skip);
		if (err) {
			R_LOG_ERROR ("peek-uleb0");
			break;
		}
		MI += omi;
		omi = MI;
		MA = peek_uleb (bf->buf, &err, &skip);
		if (err) {
			R_LOG_ERROR ("peek-uleb1");
			break;
		}
		MC = peek_uleb (bf->buf, &err, &skip);
		if (err) {
			R_LOG_ERROR ("peek-uleb2");
			break;
		}
		// TODO: MOVE CHECKS OUTSIDE!
		if (MI < dex->header.method_size) {
			if (methods) {
				methods[MI] = 1;
			}
		}
		const char *method_name = dex_method_name (dex, MI);
		if (!method_name) {
			// method_name = strdup ("unknown");
			continue;
		}
		char *signature = dex_method_signature (dex, MI);
		char *flag_name = r_str_newf ("%s.method.%s%s", cls_name, method_name, signature);
		if (!flag_name || !*flag_name) {
			R_FREE (flag_name);
			R_FREE (signature);
			continue;
		}
		// TODO: check size
		// ut64 prolog_size = 2 + 2 + 2 + 2 + 4 + 4;
		ut64 v2, handler_type, handler_addr;
		int t = 0;
		if (MC > 0) {
			// TODO: parse debug info
			// XXX why bf->buf->base???
			if (MC + 16 >= dex->size || MC + 16 < MC) {
				R_FREE (flag_name);
				R_FREE (signature);
				continue;
			}
			if (bufsz < MC || bufsz < MC + 16) {
				R_FREE (flag_name);
				R_FREE (signature);
				continue;
			}
			regsz = r_buf_read_le16_at (bf->buf, MC);
			if (regsz == UT16_MAX) {
				R_FREE (flag_name);
				R_FREE (signature);
				break;
			}
			ins_size = r_buf_read_le16_at (bf->buf, MC + 2);
			if (ins_size == UT16_MAX) {
				R_FREE (flag_name);
				R_FREE (signature);
				break;
			}
			outs_size = r_buf_read_le16_at (bf->buf, MC + 4);
			tries_size = r_buf_read_le16_at (bf->buf, MC + 6);
			if (tries_size == UT16_MAX) {
				R_FREE (flag_name);
				R_FREE (signature);
				break;
			}
			debug_info_off = r_buf_read_le32_at (bf->buf, MC + 8);
			insns_size = r_buf_read_le32_at (bf->buf, MC + 12);
			int padd = 0;
			if (tries_size > 0 && insns_size % 2) {
				padd = 2;
			}
			t = 16 + 2 * insns_size + padd;
		}
		if (dex->dexdump) {
			char* accessStr = createAccessFlagStr (MA, kAccessForMethod);
			cb_printf ("    #%" PFMT64d "              : (in %s;)\n", i, cls_name);
			cb_printf ("      name          : '%s'\n", method_name);
			cb_printf ("      type          : '%s'\n", signature);
			cb_printf ("      access        : 0x%04x (%s)\n", (ut32)MA, accessStr);
			free (accessStr);
		}

		if (MC > 0) {
			if (dex->dexdump) {
				cb_printf ("      code          -\n");
				cb_printf ("      registers     : %d\n", regsz);
				cb_printf ("      ins           : %d\n", ins_size);
				cb_printf ("      outs          : %d\n", outs_size);
				cb_printf (
					"      insns size    : %d 16-bit code "
					"units\n",
					insns_size);
			}
			if (tries_size > 0) {
				if (dex->dexdump) {
					cb_printf ("      catches       : %d\n", tries_size);
				}
				int j, m = 0;
				//XXX bucle controlled by tainted variable it could produces huge loop
				ut64 offorig = r_buf_tell (bf->buf);
				for (j = 0; j < tries_size; j++) {
					ut64 offset = MC + t + j * 8;
					if (offset >= dex->size || offset < MC) {
						R_FREE (signature);
						break;
					}
					if (bufsz < offset || bufsz < offset + 8) {
						R_FREE (signature);
						break;
					}
					// start address of the block of code covered by this entry.
					// The address is a count of 16-bit code units to the start of the first covered instruction.
					start_addr = r_buf_read_le32_at (bf->buf, offset);
					// number of 16-bit code units covered by this entry.
					// The last code unit covered (inclusive) is start_addr + insn_count - 1.
					insn_count = r_buf_read_le16_at (bf->buf, offset + 4);
					// offset in bytes from the start of the associated encoded_catch_hander_list
					// to the encoded_catch_handler for this entry.
					// This must be an offset to the start of an encoded_catch_handler.
					ut64 handler_off = r_buf_read_le16_at (bf->buf, offset + 6);

					ut64 method_offset = MC + 16;
					ut64 try_from = (start_addr * 2) + method_offset;
					ut64 try_to = (start_addr * 2) + (insn_count * 2) + method_offset + 2;
					ut64 try_catch = try_to + handler_off - 1;
					if (dex->dexdump) {
						cb_printf ("        0x%04x - 0x%04x\n", start_addr, (start_addr + insn_count));
					}
					RBinTrycatch *tc = r_bin_trycatch_new (method_offset, try_from, try_to, try_catch, 0);
					r_list_append (dex->trycatch_list, tc);

					//XXX tries_size is tainted and oob here
					int off = MC + t + tries_size * 8 + handler_off;
					if (off >= dex->size || off < tries_size) {
						R_FREE (signature);
						break;
					}
					// TODO: catch left instead of null
					st64 size;
					if (r_buf_seek (bf->buf, off, R_BUF_SET) == -1) {
						break;
					}
					int r = r_buf_sleb128 (bf->buf, &size);
					if (r <= 0) {
						break;
					}
					if (size <= 0) {
						catchAll = true;
						size = -size;
						// XXX this is probably wrong
					} else {
						catchAll = false;
					}

					for (m = 0; m < size; m++) {
						r = r_buf_uleb128 (bf->buf, &handler_type);
						if (r <= 0) {
							break;
						}
						r = r_buf_uleb128 (bf->buf, &handler_addr);
						if (r <= 0) {
							break;
						}
						if (handler_type > 0 && handler_type < dex->header.types_size) {
							const char *s = getstr (dex, dex->types[handler_type].descriptor_id);
							if (dex->dexdump) {
								cb_printf (
									"          %s "
									"-> 0x%04"PFMT64x"\n",
									s,
									handler_addr);
							}
						} else {
							if (dex->dexdump) {
								cb_printf ("          (error) -> 0x%04"PFMT64x"\n", handler_addr);
							}
						}
					}
					if (catchAll) {
						r = r_buf_uleb128 (bf->buf, &v2);
						if (r <= 0) {
							break;
						}
						if (dex->dexdump) {
							cb_printf ("          <any> -> 0x%04"PFMT64x"\n", v2);
						}
					}
				}
				r_buf_seek (bf->buf, offorig, R_BUF_SET);
			} else {
				if (dex->dexdump) {
					cb_printf (
						"      catches       : "
						"(none)\n");
				}
			}
		} else {
			if (dex->dexdump) {
				cb_printf ("      code          : (none)\n");
			}
		}
		if (*flag_name) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			sym->name = r_bin_name_new (flag_name);
			R_FREE (flag_name);
			// is_direct is no longer used
			// if method has code *addr points to code
			// otherwise it points to the encoded method
			if (MC > 0) {
				sym->type = R_BIN_TYPE_FUNC_STR;
				sym->paddr = MC;// + 0x10;
			} else {
				sym->type = R_BIN_TYPE_METH_STR;
				sym->paddr = encoded_method_addr;
			}
			sym->vaddr = sym->paddr + bf->bo->baddr;
			// sym->vaddr += bf->bo->baddr;
			dex->code_from = R_MIN (dex->code_from, sym->paddr);
			sym->lang = R_BIN_LANG_JAVA;
			sym->bind = ((MA & 1) == 1) ? R_BIN_BIND_GLOBAL_STR : R_BIN_BIND_LOCAL_STR;
			sym->attr = get_method_attr (MA);
			sym->ordinal = (*sym_count)++;
			if (MC > 0) {
				if (bufsz < MC || bufsz < MC + 16) {
					R_FREE (sym);
					R_FREE (signature);
					continue;
				}
				ut16 tries_size = r_buf_read_le16_at (bf->buf, MC + 6);
				ut32 insns_size = r_buf_read_le32_at (bf->buf, MC + 12);
				ut64 prolog_size = 2 + 2 + 2 + 2 + 4 + 4;
				if (tries_size > 0) {
					//prolog_size += 2 + 8*tries_size; // we need to parse all so the catch info...
				}
				// TODO: prolog_size
				sym->paddr = MC + prolog_size;// + 0x10;
				sym->vaddr = sym->paddr; //  + baddr;
				//if (is_direct) {
				sym->size = insns_size * 2;
				//}
				//eprintf("%s (0x%x-0x%x) size=%d\nregsz=%d\ninsns_size=%d\nouts_size=%d\ntries_size=%d\ninsns_size=%d\n", flag_name, sym->vaddr, sym->vaddr+sym->size, prolog_size, regsz, ins_size, outs_size, tries_size, insns_size);
				r_list_append (dex->methods_list, sym);
				// XXX this is necessary because class methods and symbols obey baddr in a inconsistent way in cbin.c .. so better get this to work and fix later with more tests
				RBinSymbol *method = r_bin_symbol_clone (sym);
				method->vaddr += baddr;
				r_list_append (cls->methods, method);

				if (dex->code_from == UT64_MAX || dex->code_from > sym->paddr) {
					dex->code_from = sym->paddr;
				}
				if (dex->code_to < sym->paddr) {
					dex->code_to = sym->paddr + sym->size;
				}

				if (!dex->mdb) {
					dex->mdb = sdb_new0 ();
				}
				r_strf_var (methvar, 64, "method.%"PFMT64d, MI);
				sdb_num_set (dex->mdb, methvar, sym->paddr, 0);
				// -----------------
				// WORK IN PROGRESS
				// -----------------
#if 0
				if (0) {
					if (MA & 0x10000) { //ACC_CONSTRUCTOR
						if (!cdb) {
							cdb = sdb_new0 ();
						}
						sdb_num_set (cdb, r_strf ("%d", c->class_id), sym->paddr, 0);
					}
				}
#endif
			} else {
				sym->size = 0;
				r_list_append (dex->methods_list, sym);
				sym->lang = R_BIN_LANG_JAVA;
				RBinSymbol *method = r_bin_symbol_clone (sym);
				// method->vaddr += baddr;
				r_list_append (cls->methods, method);
			}
			if (MC > 0 && debug_info_off > 0 && dex->header.data_offset < debug_info_off &&
				debug_info_off < dex->header.data_offset + dex->header.data_size) {
				if (bin_dbginfo) {
					ut64 addr = r_buf_tell (bf->buf);
					dex_parse_debug_item (bf, c, MI, MA, sym->paddr, ins_size,
							insns_size, cls_name, regsz, debug_info_off);
					r_buf_seek (bf->buf, addr, R_BUF_SET);
				}
			} else if (MC > 0) {
				if (dex->dexdump) {
					cb_printf ("      positions     :\n");
					cb_printf ("      locals        :\n");
				}
			}
		} else {
			R_FREE (flag_name);
		}
		R_FREE (signature);
	}
}

static void parse_class(RBinFile *bf, RBinDexClass *c, int class_index, int *methods, int *sym_count) {
	R_RETURN_IF_FAIL (bf && bf->bo && c);

	RBinDexObj *dex = bf->bo->bin_obj;
	RBin *rbin = bf->rbin;
	int z;
	RBinClass *cls = R_NEW0 (RBinClass);
	cls->lang = R_BIN_LANG_JAVA;
	char *cls_name = dex_class_name (dex, c);
	if (!cls_name) {
		goto beach;
	}
	r_str_replace_char (cls_name, ';', 0);
	cls->name = r_bin_name_new (cls_name);
	cls->index = class_index;
	cls->addr = dex->header.class_offset + (class_index * DEX_CLASS_SIZE);
	cls->methods = r_list_newf ((RListFree)r_bin_symbol_free);
	const char *super = dex_class_super_name (dex, c);
	if (super) {
		cls->super = r_list_newf ((void*)r_bin_name_free);
		r_list_append (cls->super, r_bin_name_new (super));
	}
	if (!cls->methods) {
		free (cls);
		goto beach;
	}
	cls->fields = r_list_new ();
	if (!cls->fields) {
		r_list_free (cls->methods);
		free (cls);
		goto beach;
	}
	cls->visibility_str = createAccessFlagStr (c->access_flags, kAccessForClass);
	r_list_append (dex->classes_list, cls);
	if (dex->dexdump) {
		rbin->cb_printf ("  Class descriptor  : '%s;'\n", cls_name);
		rbin->cb_printf ("  Access flags      : 0x%04x (%s)\n", c->access_flags,
				r_str_get (cls->visibility_str));
		if (cls->super) {
			RBinName *bn;
			RListIter *iter;
			rbin->cb_printf ("  Superclass        : '");
			r_list_foreach (cls->super, iter, bn) {
				rbin->cb_printf ("%s%s", iter->n? ",": "", r_bin_name_tostring (bn));
			}
			rbin->cb_printf ("'\n");
		}
		rbin->cb_printf ("  Interfaces        -\n");
	}

	if (c->interfaces_offset > 0 &&
	    dex->header.data_offset < c->interfaces_offset &&
	    c->interfaces_offset < dex->header.data_offset + dex->header.data_size) {
		int types_list_size = r_buf_read_le32_at (bf->buf, c->interfaces_offset);
		if (types_list_size < 0 || types_list_size >= dex->header.types_size ) {
			goto beach;
		}
		for (z = 0; z < types_list_size; z++) {
			ut16 le16;
			ut32 off = c->interfaces_offset + 4 + (z * 2);
			r_buf_read_at (bf->buf, off, (ut8*)&le16, sizeof (le16));
			int t = r_read_le16 (&le16);
			if (t > 0 && t < dex->header.types_size ) {
				int tid = dex->types[t].descriptor_id;
				if (dex->dexdump) {
					const char *cn = getstr (dex, tid);
					rbin->cb_printf ("    #%d              : '%s'\n", z, cn);
				}
			}
		}
	}
	// TODO: this is quite ugly
	if (!c || !c->class_data_offset) {
		if (dex->dexdump) {
			rbin->cb_printf (
				"  Static fields     -\n"
				"  Instance fields   -\n"
				"  Direct methods    -\n"
				"  Virtual methods   -\n");
		}
	} else {
		// TODO: move to func, def or inline
		// class_data_offset => [class_offset, class_defs_off+class_defs_size*32]
		if (dex->header.class_offset > c->class_data_offset ||
		    c->class_data_offset <
			    dex->header.class_offset +
				    dex->header.class_size * DEX_CLASS_SIZE) {
			goto beach;
		}

		RBinDexClassData *dc = R_NEW0 (RBinDexClassData);
		if (!dc) {
			goto beach;
		}

		bool err = false;
		size_t skip = 0;
		r_buf_seek (bf->buf, c->class_data_offset, R_BUF_SET);
		dc->static_fields_size   = peek_uleb (bf->buf, &err, &skip);
		dc->instance_fields_size = peek_uleb (bf->buf, &err, &skip);
		dc->direct_methods_size  = peek_uleb (bf->buf, &err, &skip);
		dc->virtual_methods_size = peek_uleb (bf->buf, &err, &skip);
		if (err) {
			free (dc);
			goto beach;
		}
		c->class_data = dc;

		if (dex->dexdump) { rbin->cb_printf ("  Static fields     -\n"); }
		parse_dex_class_fields (bf, c, cls, sym_count, dc->static_fields_size, true);

		if (dex->dexdump) { rbin->cb_printf ("  Instance fields   -\n"); }
		parse_dex_class_fields (bf, c, cls, sym_count, dc->instance_fields_size, false);

		if (dex->dexdump) { rbin->cb_printf ("  Direct methods    -\n"); }
		parse_dex_class_method (bf, c, cls, sym_count,
			c->class_data->direct_methods_size, methods, true);

		if (dex->dexdump) { rbin->cb_printf ("  Virtual methods   -\n"); }
		parse_dex_class_method (bf, c, cls, sym_count,
			c->class_data->virtual_methods_size, methods, false);
	}

	if (dex->dexdump) {
		const char *source_file = getstr (dex, c->source_file);
		if (source_file) {
			rbin->cb_printf ("  source_file_idx   : %d (%s)\n\n",
					c->source_file, source_file);
		} else {
			rbin->cb_printf ("  source_file_idx   : %d (unknown)\n\n",
					c->source_file);
		}
	}
	cls = NULL;
beach:
	R_FREE (cls_name);
}

static bool is_class_idx_in_code_classes(RBinDexObj *dex, int class_idx) {
	int i;
	for (i = 0; i < dex->header.class_size; i++) {
		if (class_idx == dex->classes[i].class_id) {
			return true;
		}
	}
	return false;
}

static bool dex_loadcode(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, false);
	RBinDexObj *dex = (RBinDexObj*)bf->bo->bin_obj;
	dex->verbose = true;
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	size_t i;
	int *methods = NULL;
	size_t methods_size = 0;
	int sym_count = 0;
	// doublecheck??
	if (dex->methods_list) {
		return false;
	}
	dex->version = r_bin_dex_get_version (dex);
	dex->code_from = UT64_MAX;
	dex->code_to = 0;
	dex->methods_list = r_list_newf ((RListFree)free);
	if (!dex->methods_list) {
		return false;
	}
	dex->imports_list = r_list_newf ((RListFree)r_bin_import_free);
	if (!dex->imports_list) {
		r_list_free (dex->methods_list);
		return false;
	}
	dex->lines_list = r_list_newf ((RListFree)free);
	if (!dex->lines_list) {
		return false;
	}
	dex->classes_list = r_list_newf ((RListFree)r_bin_class_free);
	if (!dex->classes_list) {
		r_list_free (dex->methods_list);
		r_list_free (dex->lines_list);
		r_list_free (dex->imports_list);
		return false;
	}

	if (dex->header.method_size > dex->size) {
		dex->header.method_size = 0;
		return false;
	}

	/* WrapDown the header sizes to avoid huge allocations */
	dex->header.method_size = R_MIN (dex->header.method_size, dex->size);
	dex->header.class_size = R_MIN (dex->header.class_size, dex->size);
	dex->header.strings_size = R_MIN (dex->header.strings_size, dex->size);

	// TODO: is this posible after R_MIN ??
	if (dex->header.strings_size > dex->size) {
		R_LOG_WARN ("Invalid strings size");
		return false;
	}
	dex->dexSubsystem = NULL;

	if (dex->classes) {
		ut64 amount = sizeof (int) * dex->header.method_size;
		if (amount > UT32_MAX || amount < dex->header.method_size) {
			return false;
		}
		methods_size = amount + 1;
		methods = calloc (1, methods_size);
		for (i = 0; i < dex->header.class_size; i++) {
			struct dex_class_t *c = &dex->classes[i];
			if (dex->dexdump) {
				cb_printf ("Class #%u            -\n", (unsigned int)i);
			}
			parse_class (bf, c, i, methods, &sym_count);
		}
	}
	if (methods) {
		int import_count = 0;
		int sym_count = dex->methods_list->length;
		int last = (methods_size / sizeof (int)); // sym_count
		for (i = 0; i < last; i++) {
			int len = 0;
			if (methods[i]) {
				continue;
			}
			if (dex->methods[i].class_id >= dex->header.types_size) {
				continue;
			}
			if (is_class_idx_in_code_classes (dex, dex->methods[i].class_id)) {
				continue;
			}
			const char *className = getstr (dex, dex->types[dex->methods[i].class_id].descriptor_id);
			if (!className) {
				continue;
			}
			char *class_name = strdup (className);
			if (!class_name) {
				free (class_name);
				continue;
			}
			if (!dex->dexSubsystem) {
				if (strstr (class_name, "wearable/view")) {
					dex->dexSubsystem = "android-wear";
				} else if (strstr (class_name, "android/view/View")) {
					dex->dexSubsystem = "android";
				}
			}
			len = strlen (class_name);
			if (len < 1) {
				free (class_name);
				continue;
			}
			r_str_replace_char (class_name, ';', 0);
			const char *method_name = dex_method_name (dex, i);
			char *signature = dex_method_signature (dex, i);
			if (!R_STR_ISEMPTY (method_name)) {
				RBinImport *imp = R_NEW0 (RBinImport);
				if (!imp) {
					free (methods);
					free (signature);
					free (class_name);
					return false;
				}
				char *s = r_str_newf ("%s.method.%s%s", class_name, method_name, signature);
				imp->name = r_bin_name_new (s);
				free (s);
				imp->type = "FUNC";
				imp->bind = "NONE";
				imp->ordinal = import_count++;
				r_list_append (dex->imports_list, imp);

				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				if (!sym) {
					free (methods);
					free ((void *)signature);
					free (class_name);
					return false;
				}
				sym->name = r_bin_name_clone (imp->name);
				sym->is_imported = true;
				sym->type = R_BIN_TYPE_FUNC_STR;
				sym->bind = "NONE";
				//XXX so damn unsafe check buffer boundaries!!!!
				//XXX use r_buf API!!
				sym->paddr = dex->header.method_offset + (sizeof (struct dex_method_t) * i);
				sym->vaddr = sym->paddr; //  + bf->bo->baddr;
				sym->ordinal = sym_count++;
				sym->lang = R_BIN_LANG_JAVA;
				r_list_append (dex->methods_list, sym);
				r_strf_var (mname, 64, "method.%"PFMT64d, (ut64)i);
				sdb_num_set (dex->mdb, mname, sym->paddr, 0);
			}
			free ((void *)signature);
			free (class_name);
		}
		free (methods);
	}
	return true;
}

static RList* imports(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinDexObj *dex = (RBinDexObj*) bf->bo->bin_obj;
	if (!dex->imports_list) {
		dex_loadcode (bf);
	}
	return dex->imports_list;
}

static RList *trycatch(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinDexObj *bin = (RBinDexObj*) bf->bo->bin_obj;
	if (!bin->trycatch_list) {
		dex_loadcode (bf);
	}
	return bin->trycatch_list;
}

static RList *methods(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinDexObj *bin = (RBinDexObj*) bf->bo->bin_obj;
	if (!bin->methods_list) {
		dex_loadcode (bf);
	}
	return bin->methods_list;
}

static RList *classes(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	RBinDexObj *bin = (RBinDexObj*) bf->bo->bin_obj;
	if (!bin->classes_list) {
		dex_loadcode (bf);
	}
	return bin->classes_list;
}

static bool already_entry(RList *entries, ut64 vaddr) {
	RBinAddr *e;
	RListIter *iter;
	r_list_foreach (entries, iter, e) {
		if (e->vaddr == vaddr) {
			return true;
		}
	}
	return false;
}

static RList *entries(RBinFile *bf) {
	RListIter *iter;
	RBinSymbol *m;
	RBinAddr *ptr;

	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);

	RBinDexObj *bin = (RBinDexObj*) bf->bo->bin_obj;
	RList *ret = r_list_newf ((RListFree)free);

	if (!bin->methods_list) {
		dex_loadcode (bf);
	}

	// STEP 1. ".onCreate(Landroid/os/Bundle;)V"
	r_list_foreach (bin->methods_list, iter, m) {
		const char *oname = r_bin_name_tostring2 (m->name, 'o');
		if (strlen (oname) > 30 && m->bind \
				&& (!strcmp (m->bind, R_BIN_BIND_LOCAL_STR) || !strcmp (m->bind, R_BIN_BIND_GLOBAL_STR)) \
				&& !strcmp (oname + strlen (oname) - 31, ".onCreate(Landroid/os/Bundle;)V")) {
			if (!already_entry (ret, m->paddr)) {
				if ((ptr = R_NEW0 (RBinAddr))) {
					ptr->paddr = ptr->vaddr = m->paddr;
					r_list_append (ret, ptr);
				}
			}
		}
	}

	// STEP 2. ".main([Ljava/lang/String;)V"
	if (r_list_empty (ret)) {
		r_list_foreach (bin->methods_list, iter, m) {
			const char *oname = r_bin_name_tostring2 (m->name, 'o');
			if (strlen (oname) > 26 && !strcmp (oname + strlen (oname) - 27, ".main([Ljava/lang/String;)V")) {
				if (!already_entry (ret, m->paddr)) {
					if ((ptr = R_NEW0 (RBinAddr))) {
						ptr->paddr = m->paddr;
						ptr->vaddr = ptr->paddr + bf->bo->baddr;
						r_list_append (ret, ptr);
					}
				}
			}
		}
	}
#if 0
	// this is now done by r2 in a generic way
	// STEP 3. NOTHING FOUND POINT TO CODE_INIT
	if (r_list_empty (ret)) {
		if (!already_entry (ret, bin->code_from)) {
			ptr = R_NEW0 (RBinAddr);
			if (ptr) {
				ptr->paddr = ptr->vaddr = bin->code_from;
				r_list_append (ret, ptr);
			}
		}
	}
#endif
	return ret;
}

static ut64 getoffset(RBinFile *bf, int type, int idx) {
	struct r_bin_dex_obj_t *dex = bf->bo->bin_obj;
	switch (type) {
	case 'm': // methods
		// TODO: ADD CHECK
		return offset_of_method_idx (bf, idx);
	case 'f':
		return dex_field_offset (dex, idx);
	case 'o': // objects
		R_LOG_TODO ("getoffset object");
		return 0; // //chdex_object_offset (dex, idx);
	case 's': // strings
		if (dex->header.strings_size > idx) {
			if (dex->strings) {
				return dex->strings[idx];
			}
		}
		break;
	case 't': // type
		return dex_get_type_offset (bf, idx);
	case 'c': // class
		return dex_get_type_offset (bf, idx);
	}
	return UT64_MAX;
}

static const char *getname(RBinFile *bf, int type, int idx, bool sd) {
	RBinDexObj *dex = bf->bo->bin_obj;
	dex->simplifiedDemangling = sd; // XXX kill globals
	switch (type) {
	case 'm': // methods
		return dex_method_fullname (dex, idx);
	case 'c': // classes
		return dex_class_name_byid (dex, idx);
	case 'f': // fields
		return dex_field_name (dex, idx);
	case 'p': // proto
		return dex_get_proto (dex, idx);
	}
	return NULL;
}

typedef struct {
	ut64 addr;
	ut64 size;
} Section;

static RBinSection *add_section(RList *ret, ut64 baddr, const char *name, Section s, int perm, char *format) {
	R_RETURN_VAL_IF_FAIL (ret && name, NULL);
	R_RETURN_VAL_IF_FAIL (s.addr < UT32_MAX, NULL);
	R_RETURN_VAL_IF_FAIL (s.size > 0 && s.size < UT32_MAX, NULL);
	RBinSection *ptr = R_NEW0 (RBinSection);
	if (ptr) {
		ptr->name = strdup (name);
		ptr->size = ptr->vsize = s.size;
		ptr->paddr = s.addr;
		ptr->vaddr = s.addr;
		ptr->perm = perm;
		ptr->add = false;
		if (format) {
			ptr->format = format;
		}
		r_list_append (ret, ptr);
	}
	return ptr;
}

static void add_segment(RList *ret, ut64 baddr, const char *name, Section s, int perm) {
	RBinSection *bs = add_section (ret, baddr, name, s, perm, NULL);
	if (bs) {
		bs->is_segment = true;
		bs->add = true;
	}
}

static bool validate_section(const char *name, Section *pre, Section *cur, Section *nex, Section *all) {
	R_RETURN_VAL_IF_FAIL (cur && all, false);
	if (pre && cur->addr < (pre->addr + pre->size)) {
		R_LOG_WARN ("%s Section starts before the previous", name);
	}
	if (cur->addr >= all->size) {
		R_LOG_WARN ("%s section starts beyond the end of the file", name);
		return false;
	}
	if (cur->addr == UT64_MAX) {
		R_LOG_WARN ("%s invalid region size", name);
		return false;
	}
	if ((cur->addr + cur->size) > all->size) {
		R_LOG_WARN ("%s truncated section because of file size", name);
		cur->size = all->size - cur->addr;
	}
	if (nex) {
		if (cur->addr >= nex->addr) {
			R_LOG_WARN ("invalid %s section address", name);
			return false;
		}
		if ((cur->addr + cur->size) > nex->addr) {
			R_LOG_WARN ("truncated %s with next section size", name);
			cur->size = nex->addr - cur->addr;
		}
	}
	return cur->size > 0;
}

static void fast_code_size(RBinFile *bf) {
	const size_t bs = r_buf_size (bf->buf);
	ut64 ns;
	ut64 fsym = 0LL;
	ut64 fsymsz = 0LL;
	RListIter *iter;
	RBinSymbol *m;
	RList *ml = methods (bf);
	r_list_foreach (ml, iter, m) {
		if (!fsym || m->paddr < fsym) {
			fsym = m->paddr;
		}
		ns = m->paddr + m->size;
		if (ns > bs || m->paddr > bs || m->size > bs) {
			continue;
		}
		if (ns > fsymsz) {
			fsymsz = ns;
		}
	}
	struct r_bin_dex_obj_t *bin = bf->bo->bin_obj;
	bin->code_from = fsym;
	bin->code_to = fsymsz;
}

static RList *sections(RBinFile *bf) {
	struct r_bin_dex_obj_t *bin = bf->bo->bin_obj;
	RList *ret = NULL;

	/* find the last method */
	const size_t bs = r_buf_size (bf->buf);
	if (!bin->code_from || !bin->code_to) {
		fast_code_size (bf);
	}
	if (!(ret = r_list_newf ((RListFree)r_bin_section_free))) {
		return NULL;
	}

	/* initial section boundary assumptions */
	Section s_head = { 0, sizeof (struct dex_header_t) };
	Section s_pool = { s_head.size, bin->code_from - sizeof (struct dex_header_t)};
	Section s_code = { bin->code_from, bin->code_to - bin->code_from };
	Section s_data = { bin->code_to, bs - bin->code_to};
	Section s_file = { 0, bs };

	const ut64 baddr = bf->bo->baddr;
	/* sanity bound checks and section registrations */
	if (validate_section ("header", NULL, &s_head, NULL, &s_file)) {
		add_section (ret, baddr, "header", s_head, R_PERM_R, NULL);
	}
	if (validate_section ("constpool", &s_head, &s_pool, &s_code, &s_file)) {
		char *s_pool_format = r_str_newf ("Cd %d[%"PFMT64d"]", 4, (ut64) s_pool.size / 4);
		add_section (ret, baddr, "constpool", s_pool, R_PERM_R, s_pool_format);
	}
	if (validate_section ("code", &s_pool, &s_code, &s_data, &s_file)) {
		add_section (ret, baddr, "code", s_code, R_PERM_RX, NULL);
	}
	if (validate_section ("data", &s_code, &s_data, NULL, &s_file)) {
		add_section (ret, baddr, "data", s_data, R_PERM_RX, NULL);
	}
	add_section (ret, baddr, "file", s_file, R_PERM_R, NULL);

	/* add segments */
	if (s_code.size > 0) {
		add_segment (ret, baddr, "code", s_code, R_PERM_RX);
	}
	add_segment (ret, baddr, "file", s_file, R_PERM_R);
	return ret;
}

// iH
static void dex_header(RBinFile *bf) {
	RBinDexObj *dex = bf->bo->bin_obj;
	DexHeader *hdr = &dex->header;
	PrintfCallback cb_printf = bf->rbin->cb_printf;

	cb_printf ("DEX file header:\n");
	cb_printf ("magic               : 'dex\\n035\\0'\n");
	cb_printf ("checksum            : %x\n", hdr->checksum);
	cb_printf ("signature           : %02x%02x...%02x%02x\n",
		hdr->signature[0], hdr->signature[1], hdr->signature[18], hdr->signature[19]);
	cb_printf ("file_size           : %d\n", hdr->size);
	cb_printf ("header_size         : %d\n", hdr->header_size);
	cb_printf ("link_size           : %d\n", hdr->linksection_size);
	cb_printf ("link_off            : %d (0x%06x)\n", hdr->linksection_offset, hdr->linksection_offset);
	cb_printf ("string_ids_size     : %d\n", hdr->strings_size);
	cb_printf ("string_ids_off      : %d (0x%06x)\n", hdr->strings_offset, hdr->strings_offset);
	cb_printf ("type_ids_size       : %d\n", hdr->types_size);
	cb_printf ("type_ids_off        : %d (0x%06x)\n", hdr->types_offset, hdr->types_offset);
	cb_printf ("proto_ids_size      : %d\n", hdr->prototypes_size);
	cb_printf ("proto_ids_off       : %d (0x%06x)\n", hdr->prototypes_offset, hdr->prototypes_offset);
	cb_printf ("field_ids_size      : %d\n", hdr->fields_size);
	cb_printf ("field_ids_off       : %d (0x%06x)\n", hdr->fields_offset, hdr->fields_offset);
	cb_printf ("method_ids_size     : %d\n", hdr->method_size);
	cb_printf ("method_ids_off      : %d (0x%06x)\n", hdr->method_offset, hdr->method_offset);
	cb_printf ("class_defs_size     : %d\n", hdr->class_size);
	cb_printf ("class_defs_off      : %d (0x%06x)\n", hdr->class_offset, hdr->class_offset);
	cb_printf ("data_size           : %d\n", hdr->data_size);
	cb_printf ("data_off            : %d (0x%06x)\n\n", hdr->data_offset, hdr->data_offset);

	// TODO: print information stored in the RBIN not this ugly fix
	dex->methods_list = NULL;
	dex->dexdump = true; /// XXX convert this global into an argument or field in RBinFile or so
	dex_loadcode (bf);
	dex->dexdump = false;
}

static ut64 size(RBinFile *bf) {
	ut8 u32s[sizeof (ut32)] = {0};

	int ret = r_buf_read_at (bf->buf, 108, u32s, 4);
	if (ret != 4) {
		return 0;
	}
	ut32 off = r_read_le32 (u32s);
	ret = r_buf_read_at (bf->buf, 104, u32s, 4);
	if (ret != 4) {
		return 0;
	}
	return off + r_read_le32 (u32s);
}

#if 0
static R_BORROW RList *lines(RBinFile *bf) {
	struct r_bin_dex_obj_t *dex = bf->bo->bin_obj;
	return dex->lines_list;
}
#endif

// iH*
static RList *dex_fields(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	ut64 addr = 0;

#define ROW(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, val, siz, nam, NULL, fmt, false)); \
	addr += siz;

	r_buf_seek (bf->buf, 0, R_BUF_SET);
	ut64 magic = r_buf_read_le64 (bf->buf);
	ROW ("dex_magic", 8, magic, "[8]c");
	ut32 checksum = r_buf_read_le32 (bf->buf);
	ROW ("dex_checksum", 4, checksum, "x");
	ut8 signature[20];
	ROW ("dex_signature", 8, (size_t)signature, "[20]c");
	ut32 size = r_buf_read_le32 (bf->buf);
	ROW ("dex_size", 4, size, "x");
	ut32 header_size = r_buf_read_le32 (bf->buf);
	ROW ("dex_header_size", 4, header_size, "x");
	ut32 endian = r_buf_read_le32 (bf->buf);
	ROW ("dex_endian", 4, endian, "x");
/*
	ROW ("hdr.cputype", 4, mh->cputype, "x");
	ROW ("hdr.cpusubtype", 4, mh->cpusubtype, "x");
	ROW ("hdr.filetype", 4, mh->filetype, "x");
	ROW ("hdr.nbcmds", 4, mh->ncmds, "x");
	ROW ("hdr.sizeofcmds", 4, mh->sizeofcmds, "x");
*/
	return ret;
}

static int cmp_path(const void *a, const void *b) {
	if (!a || !b) {
		return 0;
	}
	return strcmp ((const char*)a, (const char*)b);
}

static bool is_classes_dex(const char *filename) {
	return r_str_startswith (filename, "classes") \
		&& r_str_endswith (filename, ".dex");
}

static RList* libs(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->bo->bin_obj, NULL);
	char *path = r_file_dirname (bf->file);
	if (r_str_startswith (path, "./")) {
		// avoids stuff like .//.//.//.//.//
		free (path);
		return NULL;
	}
	RList *files = r_sys_dir (path);
	if (!files) {
		free (path);
		return NULL;
	}
	RList *ret = r_list_newf (free);
	if (!ret) {
		free (path);
		r_list_free (files);
		return NULL;
	}
	/* opening dex files in order. */
	r_list_sort (files, cmp_path);
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		if (is_classes_dex (file)) {
			char *n = r_str_newf ("%s%s%s", path, R_SYS_DIR, file);
			if (strcmp (n, bf->file)) {
				r_list_append (ret, n);
			} else {
				free (n);
			}
		}
	}
	r_list_free (files);
	free (path);
	return ret;
}

static void destroy(RBinFile *bf) {
	R_RETURN_IF_FAIL (bf && bf->bo);
	RBinDexObj *obj = bf->bo->bin_obj;
	r_bin_dex_free (obj);
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

RBinPlugin r_bin_plugin_dex = {
	.meta = {
		.name = "dex",
		.desc = "Dalvik Executable format",
		.license = "LGPL-3.0-only",
	},
	.destroy = &destroy,
	.get_sdb = &get_sdb,
	.load = &load,
	.check = check,
	.entries = entries,
	.classes = classes,
	.sections = sections,
	.symbols = methods,
	.baddr = baddr,
	.trycatch = trycatch,
	.imports = imports,
	.strings = strings,
	.info = &info,
	.header = dex_header,
	.fields = dex_fields,
	.libs = &libs,
	.size = &size,
	.get_offset = &getoffset,
	.get_name = &getname,
//	.dbginfo = &r_bin_dbginfo_dex,
	// .lines = &lines,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dex,
	.version = R2_VERSION
};
#endif
