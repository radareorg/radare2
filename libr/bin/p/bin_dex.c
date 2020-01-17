/* radare - LGPL - Copyright 2011-2019 - pancake, h4ng3r */

#include <r_cons.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"
#include "dex/dex.h"
#define r_hash_adler32 __adler32
#include "../../hash/adler32.c"

// globals to kill
extern struct r_bin_dbginfo_t r_bin_dbginfo_dex;
static bool dexdump = false;
static Sdb *mdb = NULL;
static const char *dexSubsystem = NULL;
static bool simplifiedDemangling = false; // depends on asm.pseudo

static ut64 get_method_flags(ut64 MA) {
	ut64 flags = 0;
	if (MA & R_DEX_METH_PUBLIC) {
		flags |= R_BIN_METH_PUBLIC;
	}
	if (MA & R_DEX_METH_PRIVATE) {
		flags |= R_BIN_METH_PRIVATE;
	}
	if (MA & R_DEX_METH_PROTECTED) {
		flags |= R_BIN_METH_PROTECTED;
	}
	if (MA & R_DEX_METH_STATIC) {
		flags |= R_BIN_METH_STATIC;
	}
	if (MA & R_DEX_METH_FINAL) {
		flags |= R_BIN_METH_FINAL;
	}
	if (MA & R_DEX_METH_SYNCHRONIZED) {
		flags |= R_BIN_METH_SYNCHRONIZED;
	}
	if (MA & R_DEX_METH_BRIDGE) {
		flags |= R_BIN_METH_BRIDGE;
	}
	if (MA & R_DEX_METH_VARARGS) {
		flags |= R_BIN_METH_VARARGS;
	}
	if (MA & R_DEX_METH_NATIVE) {
		flags |= R_BIN_METH_NATIVE;
	}
	if (MA & R_DEX_METH_ABSTRACT) {
		flags |= R_BIN_METH_ABSTRACT;
	}
	if (MA & R_DEX_METH_STRICT) {
		flags |= R_BIN_METH_STRICT;
	}
	if (MA & R_DEX_METH_SYNTHETIC) {
		flags |= R_BIN_METH_SYNTHETIC;
	}
	if (MA & R_DEX_METH_MIRANDA) {
		flags |= R_BIN_METH_MIRANDA;
	}
	if (MA & R_DEX_METH_CONSTRUCTOR) {
		flags |= R_BIN_METH_CONSTRUCTOR;
	}
	if (MA & R_DEX_METH_DECLARED_SYNCHRONIZED) {
		flags |= R_BIN_METH_DECLARED_SYNCHRONIZED;
	}
	return flags;
}

static ut64 offset_of_method_idx(RBinFile *bf, struct r_bin_dex_obj_t *dex, int idx) {
	// ut64 off = dex->header.method_offset + idx;
	return sdb_num_get (mdb, sdb_fmt ("method.%d", idx), 0);
}

static ut64 dex_field_offset(RBinDexObj *bin, int fid) {
	return bin->header.fields_offset + (fid * 8); // (sizeof (DexField) * fid);
}

static char *getstr(RBinDexObj *dex, int idx) {
	ut8 buf[6];
	ut64 len;
	int uleblen;
	// null terminate the buf wtf
	if (!dex || idx < 0 || idx >= dex->header.strings_size || !dex->strings) {
		return NULL;
	}
	if (dex->strings[idx] >= dex->size) {
		return NULL;
	}
	if (r_buf_read_at (dex->b, dex->strings[idx], buf, sizeof (buf)) < 1) {
		return NULL;
	}
	r_buf_write_at (dex->b, r_buf_size (dex->b) - 1, (ut8 *)"\x00", 1);
	uleblen = r_uleb128 (buf, sizeof (buf), &len) - buf;
	if (!uleblen || uleblen >= dex->size) {
		return NULL;
	}
	if (!len || len >= dex->size) {
		return NULL;
	}
	if (dex->strings[idx] + uleblen >= dex->strings[idx] + dex->header.strings_size) {
		return NULL;
	}
	ut8 *ptr = R_NEWS (ut8, len + 1);
	if (!ptr) {
		return NULL;
	}
	r_buf_read_at (dex->b, dex->strings[idx] + uleblen, ptr, len + 1);
	ptr[len] = 0;
	if (len != r_utf8_strlen (ptr)) {
		// eprintf ("WARNING: Invalid string for index %d\n", idx);
		return NULL;
	}
	return (char *)ptr;
}

static int countOnes(ut32 val) {
	if (!val) {
		return 0;
	}
	/* visual studio doesnt supports __buitin_clz */
#ifdef _MSC_VER
	int count = 0;
	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
	return count;
#else
	return __builtin_clz (val);
#endif
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
			"PUBLIC", /* 0x0001 */
			"PRIVATE", /* 0x0002 */
			"PROTECTED", /* 0x0004 */
			"STATIC", /* 0x0008 */
			"FINAL", /* 0x0010 */
			"?", /* 0x0020 */
			"?", /* 0x0040 */
			"?", /* 0x0080 */
			"?", /* 0x0100 */
			"INTERFACE", /* 0x0200 */
			"ABSTRACT", /* 0x0400 */
			"?", /* 0x0800 */
			"SYNTHETIC", /* 0x1000 */
			"ANNOTATION", /* 0x2000 */
			"ENUM", /* 0x4000 */
			"?", /* 0x8000 */
			"VERIFIED", /* 0x10000 */
			"OPTIMIZED", /* 0x20000 */
		},
		{
			/* method */
			"PUBLIC", /* 0x0001 */
			"PRIVATE", /* 0x0002 */
			"PROTECTED", /* 0x0004 */
			"STATIC", /* 0x0008 */
			"FINAL", /* 0x0010 */
			"SYNCHRONIZED", /* 0x0020 */
			"BRIDGE", /* 0x0040 */
			"VARARGS", /* 0x0080 */
			"NATIVE", /* 0x0100 */
			"?", /* 0x0200 */
			"ABSTRACT", /* 0x0400 */
			"STRICT", /* 0x0800 */
			"SYNTHETIC", /* 0x1000 */
			"?", /* 0x2000 */
			"?", /* 0x4000 */
			"MIRANDA", /* 0x8000 */
			"CONSTRUCTOR", /* 0x10000 */
			"DECLARED_SYNCHRONIZED", /* 0x20000 */
		},
		{
			/* field */
			"PUBLIC", /* 0x0001 */
			"PRIVATE", /* 0x0002 */
			"PROTECTED", /* 0x0004 */
			"STATIC", /* 0x0008 */
			"FINAL", /* 0x0010 */
			"?", /* 0x0020 */
			"VOLATILE", /* 0x0040 */
			"TRANSIENT", /* 0x0080 */
			"?", /* 0x0100 */
			"?", /* 0x0200 */
			"?", /* 0x0400 */
			"?", /* 0x0800 */
			"SYNTHETIC", /* 0x1000 */
			"?", /* 0x2000 */
			"ENUM", /* 0x4000 */
			"?", /* 0x8000 */
			"?", /* 0x10000 */
			"?", /* 0x20000 */
		},
	};
	int i, count = countOnes (flags);
	const int kLongest = 21;
	const int maxSize = (count + 1) * (kLongest + 1);
	char* str, *cp;
	// produces a huge number????
	if (count < 1 || (count * (kLongest+1)) < 1) {
		return NULL;
	}
	cp = str = (char*) calloc (count + 1, (kLongest + 1));
	if (!str) {
		return NULL;
	}
	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 0x01) {
			const char *accessStr = kAccessStrings[forWhat][i];
			int len = strlen (accessStr);
			if (cp != str) {
				*cp++ = ' ';
			}
			if (((cp - str) + len) >= maxSize) {
				free (str);
				return NULL;
			}
			memcpy (cp, accessStr, len);
			cp += len;
		}
		flags >>= 1;
	}
	*cp = '\0';
	return str;
}

static char *dex_type_descriptor(RBinDexObj *bin, int type_idx) {
	if (type_idx < 0 || type_idx >= bin->header.types_size) {
		return NULL;
	}
	return getstr (bin, bin->types[type_idx].descriptor_id);
}

static char *dex_get_proto(RBinDexObj *bin, int proto_id) {
	ut32 params_off, type_id, list_size;
	char *r = NULL, *return_type = NULL, *signature = NULL, *buff = NULL;
	ut16 type_idx;
	int pos = 0, i, size = 1;

	if (proto_id >= bin->header.prototypes_size) {
		return NULL;
	}
	params_off = bin->protos[proto_id].parameters_off;
	if (params_off >= bin->size) {
		return NULL;
	}
	type_id = bin->protos[proto_id].return_type_id;
	if (type_id >= bin->header.types_size ) {
		return NULL;
	}
	return_type = getstr (bin, bin->types[type_id].descriptor_id);
	if (!return_type) {
		return NULL;
	}
	if (!params_off) {
		return r_str_newf ("()%s", return_type);;
	}
	ut8 params_buf[sizeof (ut32)];
	if (!r_buf_read_at (bin->b, params_off, params_buf, sizeof (params_buf))) {
		return NULL;
	}
	// size of the list, in entries
	list_size = r_read_le32 (params_buf);
	if (list_size * sizeof (ut16) >= bin->size) {
		return NULL;
	}

	for (i = 0; i < list_size; i++) {
		int buff_len = 0;
		int off = params_off + 4 + (i * 2);
		if (off >= bin->size) {
			break;
		}
		ut8 typeidx_buf[sizeof (ut16)];
		if (!r_buf_read_at (bin->b, off, typeidx_buf, sizeof (typeidx_buf))) {
			break;
		}
		type_idx = r_read_le16 (typeidx_buf);
		if (type_idx >= bin->header.types_size || type_idx >= bin->size) {
			break;
		}
		buff = getstr (bin, bin->types[type_idx].descriptor_id);
		if (!buff) {
			break;
		}
		buff_len = strlen (buff);
		size += buff_len + 1;
		char *newsig = realloc (signature, size);
		if (!newsig) {
			eprintf ("Cannot realloc to %d\n", size);
			break;
		}
		signature = newsig;
		strcpy (signature + pos, buff);
		pos += buff_len;
		signature[pos] = '\0';
	}
	if (signature) {
		r = r_str_newf ("(%s)%s", signature, return_type);
		free (signature);
	}
	return r;
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
	int i;

	RList *params = r_list_newf (free);
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
		char *buff = getstr (bin, bin->types[type_idx].descriptor_id);
		if (!buff) {
			break;
		}
		r_list_append (params, buff);
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
static void dex_parse_debug_item(RBinFile *bf, RBinDexObj *bin,
				  RBinDexClass *c, int MI, int MA, int paddr, int ins_size,
				  int insns_size, char *class_name, int regsz,
				  int debug_info_off) {
	struct r_bin_t *rbin = bf->rbin;
	struct r_bin_dex_obj_t *dex = bf->o->bin_obj;
	// runtime error: pointer index expression with base 0x000000004402 overflowed to 0xffffffffff0043fc
	if (debug_info_off >= r_buf_size (bf->buf)) {
		return;
	}
	int buf_size = r_buf_size (bf->buf) - debug_info_off;
	ut8 *buf = malloc (buf_size);
	if (!buf) {
		return;
	}
	r_buf_read_at (bf->buf, debug_info_off, buf, buf_size);
	const ut8 *p4 = buf;
	const ut8 *p4_end = buf + buf_size;
	ut64 line_start;
	ut64 parameters_size;
	ut64 param_type_idx;
	ut16 argReg = regsz - ins_size;
	ut64 source_file_idx = c->source_file;
	RList *params, *debug_positions, *emitted_debug_locals = NULL;
	bool keep = true;
	if (argReg > regsz) {
		free (buf);
		return; // this return breaks tests
	}
	p4 = r_uleb128 (p4, p4_end - p4, &line_start);
	p4 = r_uleb128 (p4, p4_end - p4, &parameters_size);
	// TODO: check when we should use source_file
	// The state machine consists of five registers
	ut32 address = 0;
	ut32 line = line_start;
	if (!(debug_positions = r_list_newf ((RListFree)free))) {
		free (buf);
		return;
	}
	if (!(emitted_debug_locals = r_list_newf ((RListFree)free))) {
		free (debug_positions);
		free (buf);
		return;
	}

	struct dex_debug_local_t *debug_locals = calloc (sizeof (struct dex_debug_local_t), regsz + 1);
	if (!(MA & 0x0008)) {
		debug_locals[argReg].name = "this";
		debug_locals[argReg].descriptor = r_str_newf ("%s;", class_name);
		debug_locals[argReg].startAddress = 0;
		debug_locals[argReg].signature = NULL;
		debug_locals[argReg].live = true;
		argReg++;
	}
	if (!(params = dex_method_signature2 (bin, MI))) {
		free (debug_positions);
		free (emitted_debug_locals);
		free (debug_locals);
		free (buf);
		return;
	}

	RListIter *iter;
	char *name;
	char *type;
	int reg;

	r_list_foreach (params, iter, type) {
		if ((argReg >= regsz) || !type || parameters_size <= 0) {
			free (debug_positions);
			free (params);
			free (debug_locals);
			free (emitted_debug_locals);
			free (buf);
			return;
		}
		p4 = r_uleb128 (p4, p4_end - p4, &param_type_idx); // read uleb128p1
		param_type_idx -= 1;
		name = getstr (bin, param_type_idx);
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
		if (!name || !*name) {
			debug_locals[reg].name = name;
			debug_locals[reg].descriptor = type;
			debug_locals[reg].signature = NULL;
			debug_locals[reg].startAddress = address;
			debug_locals[reg].live = true;
		}
		parameters_size--;
	}

	if (!p4 || p4 >= p4_end) {
		free (debug_positions);
		free (params);
		free (debug_locals);
		free (emitted_debug_locals);
		free (buf);
		return;
	}
	ut8 opcode = *(p4++) & 0xff;
	while (keep && p4 + 1 < p4_end) {
		switch (opcode) {
		case 0x0: // DBG_END_SEQUENCE
			keep = false;
			break;
		case 0x1: // DBG_ADVANCE_PC
			{
			ut64 addr_diff;
			p4 = r_uleb128 (p4, p4_end - p4, &addr_diff);
			address += addr_diff;
			}
			break;
		case 0x2: // DBG_ADVANCE_LINE
			{
			st64 line_diff = r_sleb128 (&p4, p4_end);
			line += line_diff;
			}
			break;
		case 0x3: // DBG_START_LOCAL
			{
			ut64 register_num;
			ut64 name_idx;
			ut64 type_idx;
			p4 = r_uleb128 (p4, p4_end - p4, &register_num);
			p4 = r_uleb128 (p4, p4_end - p4, &name_idx);
			name_idx -= 1;
			p4 = r_uleb128 (p4, p4_end - p4, &type_idx);
			type_idx -= 1;
			if (register_num >= regsz) {
				r_list_free (debug_positions);
				free (params);
				free (debug_locals);
				free (emitted_debug_locals);
				return;
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
			debug_locals[register_num].name = getstr (bin, name_idx);
			debug_locals[register_num].descriptor = dex_type_descriptor (bin, type_idx);
			debug_locals[register_num].startAddress = address;
			debug_locals[register_num].signature = NULL;
			debug_locals[register_num].live = true;
			//eprintf("DBG_START_LOCAL %x %x %x\n", register_num, name_idx, type_idx);
			}
			break;
		case 0x4: //DBG_START_LOCAL_EXTENDED
			{
			ut64 register_num, name_idx, type_idx, sig_idx;
			p4 = r_uleb128 (p4, p4_end - p4, &register_num);
			p4 = r_uleb128 (p4, p4_end - p4, &name_idx);
			name_idx -= 1;
			p4 = r_uleb128 (p4, p4_end - p4, &type_idx);
			type_idx -= 1;
			p4 = r_uleb128 (p4, p4_end - p4, &sig_idx);
			sig_idx -= 1;
			if (register_num >= regsz) {
				r_list_free (debug_positions);
				free (params);
				free (debug_locals);
				return;
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

			debug_locals[register_num].name = getstr (bin, name_idx);
			debug_locals[register_num].descriptor = dex_type_descriptor (bin, type_idx);
			debug_locals[register_num].startAddress = address;
			debug_locals[register_num].signature = getstr (bin, sig_idx);
			debug_locals[register_num].live = true;
			}
			break;
		case 0x5: // DBG_END_LOCAL
			{
			ut64 register_num;
			p4 = r_uleb128 (p4, p4_end - p4, &register_num);
			// emitLocalCbIfLive
			if (register_num >= regsz) {
				r_list_free (debug_positions);
				free (params);
				free (debug_locals);
				return;
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
		case 0x6: // DBG_RESTART_LOCAL
			{
			ut64 register_num;
			p4 = r_uleb128 (p4, p4_end - p4, &register_num);
			if (register_num >= regsz) {
				r_list_free (debug_positions);
				free (buf);
				free (params);
				free (debug_locals);
				return;
			}
			if (!debug_locals[register_num].live) {
				debug_locals[register_num].startAddress = address;
				debug_locals[register_num].live = true;
			}
			}
			break;
		case 0x7: //DBG_SET_PROLOGUE_END
			break;
		case 0x8: //DBG_SET_PROLOGUE_BEGIN
			break;
		case 0x9:
			{
			p4 = r_uleb128 (p4, p4_end - p4, &source_file_idx);
			source_file_idx--;
			}
			break;
		default:
			{
			int adjusted_opcode = opcode - 10;
			address += (adjusted_opcode / 15);
			line += -4 + (adjusted_opcode % 15);
			struct dex_debug_position_t *position =
				R_NEW0 (struct dex_debug_position_t);
			if (!position) {
				keep = false;
				break;
			}
			position->source_file_idx = source_file_idx;
			position->address = address;
			position->line = line;
			r_list_append (debug_positions, position);
			}
			break;
		}
		if (p4 + 1 >= p4_end) {
			break;
		}
		opcode = *(p4++) & 0xff;
	}

	if (!bf->sdb_addrinfo) {
		bf->sdb_addrinfo = sdb_new0 ();
	}

	RListIter *iter1;
	struct dex_debug_position_t *pos;
// Loading the debug info takes too much time and nobody uses this afaik
#if 1
	r_list_foreach (debug_positions, iter1, pos) {
		const char *line = getstr (bin, pos->source_file_idx);
#if 1
		char offset[64] = {0};
		if (!line || !*line) {
			continue;
		}
		char *fileline = r_str_newf ("%s|%"PFMT64d, line, pos->line);
		char *offset_ptr = sdb_itoa (pos->address + paddr, offset, 16);
		sdb_set (bf->sdb_addrinfo, offset_ptr, fileline, 0);
		sdb_set (bf->sdb_addrinfo, fileline, offset_ptr, 0);
		free (fileline);
#endif
		RBinDwarfRow *rbindwardrow = R_NEW0 (RBinDwarfRow);
		if (!rbindwardrow) {
			dexdump = false;
			break;
		}
		if (line) {
			rbindwardrow->file = strdup (line);
			rbindwardrow->address = pos->address;
			rbindwardrow->line = pos->line;
			r_list_append (dex->lines_list, rbindwardrow);
		} else {
			free (rbindwardrow);
		}
	}
#endif

	if (!dexdump) {
		free (debug_positions);
		free (emitted_debug_locals);
		free (debug_locals);
		free (params);
		free (buf);
		return;
	}

	RListIter *iter2;
	struct dex_debug_position_t *position;

	rbin->cb_printf ("      positions     :\n");
	r_list_foreach (debug_positions, iter2, position) {
		rbin->cb_printf ("        0x%04"PFMT64x" line=%llu\n",
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
					"        0x%04x - 0x%04x reg=%d %s %s "
					"%s\n",
					debug_locals[reg].startAddress,
					insns_size, reg, debug_locals[reg].name,
					debug_locals[reg].descriptor,
					debug_locals[reg].signature);
			} else {
				rbin->cb_printf (
					"        0x%04x - 0x%04x reg=%d %s %s"
					"\n",
					debug_locals[reg].startAddress,
					insns_size, reg, debug_locals[reg].name,
					debug_locals[reg].descriptor);
			}
		}
	}
	free (debug_positions);
	free (debug_locals);
	free (emitted_debug_locals);
	free (params);
	free (buf);
}

static Sdb *get_sdb (RBinFile *bf) {
	RBinObject *o = bf->o;
	if (!o || !o->bin_obj) {
		return NULL;
	}
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *) o->bin_obj;
	return bin->kv;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	*bin_obj = r_bin_dex_new_buf (buf);
	return *bin_obj != NULL;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static bool check_buffer(RBuffer *buf) {
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
	if (!ret) {
		return NULL;
	}
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("DEX CLASS");
	ret->has_va = true;
	ret->has_lit = true;
	ret->bclass = r_bin_dex_get_version (bf->o->bin_obj);
	ret->rclass = strdup ("class");
	ret->os = strdup ("linux");
	ret->subsystem = strdup (dexSubsystem? dexSubsystem: "java");
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
	r_return_val_if_fail (bf && bf->o, NULL);
	RBinString *ptr = NULL;
	RList *ret = NULL;
	int i, len;
	ut8 buf[6];
	ut64 off;
	struct r_bin_dex_obj_t *bin = (struct r_bin_dex_obj_t *)bf->o->bin_obj;
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
		if (!(ptr = R_NEW0 (RBinString))) {
			break;
		}
		if (bin->strings[i] > bin->size || bin->strings[i] + 6 > bin->size) {
			goto out_error;
		}
		r_buf_read_at (bin->b, bin->strings[i], (ut8*)&buf, 6);
		len = dex_read_uleb128 (buf, sizeof (buf));

		if (len > 5 && len < R_BIN_SIZEOF_STRINGS) {
			ptr->string = malloc (len + 1);
			if (!ptr->string) {
				goto out_error;
			}
			off = bin->strings[i] + dex_uleb128_len (buf, sizeof (buf));
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
			ptr->vaddr = ptr->paddr = bin->strings[i];
			ptr->size = len;
			ptr->length = len;
			ptr->ordinal = i+1;
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

static char *dex_method_name(RBinDexObj *bin, int idx) {
	if (idx < 0 || idx >= bin->header.method_size) {
		return NULL;
	}
	int cid = bin->methods[idx].class_id;
	if (cid < 0 || cid >= bin->header.strings_size) {
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

static char *dex_class_name_byid(RBinDexObj *bin, int cid) {
	int tid;
	if (!bin || !bin->types) {
		return NULL;
	}
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	tid = bin->types[cid].descriptor_id;
	char *s = getstr (bin, tid);
	if (simplifiedDemangling) {
		simplify (s);
	}
	return s;
}

static char *dex_class_name(RBinDexObj *bin, RBinDexClass *c) {
	char *s = dex_class_name_byid (bin, c->class_id);
	if (simplifiedDemangling) {
		simplify (s);
		if (*s == 'L') {
			r_str_cpy (s, s + 1);
		}
	}
	return s;
}

static char *dex_field_name(RBinDexObj *bin, int fid) {
	int cid, tid, type_id;
	r_return_val_if_fail (bin && bin->fields, NULL);

	if (fid < 0 || fid >= bin->header.fields_size) {
		return NULL;
	}
	cid = bin->fields[fid].class_id;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	type_id = bin->fields[fid].type_id;
	if (type_id < 0 || type_id >= bin->header.types_size) {
		return NULL;
	}
	tid = bin->fields[fid].name_id;
	const char *a = getstr (bin, bin->types[cid].descriptor_id);
	const char *b = getstr (bin, tid);
	const char *c = getstr (bin, bin->types[type_id].descriptor_id);
	if (simplifiedDemangling) {
		if (a && b && c) {
			char *_a = simplify(strdup (a));
			char *_b = simplify(strdup (b));
			char *_c = simplify(strdup (c));
			char *str =  r_str_newf ("(%s) %s.%s", _c, _a, _b);
			free (_a);
			free (_b);
			free (_c);
			return str;
		}
		return r_str_newf ("(%d) %d.%d",
				bin->types[type_id].descriptor_id,
				tid,
				bin->types[cid].descriptor_id
			     );
	}
	return (a && b && c)
		? r_str_newf ("%s->%s %s", a, b, c)
		: r_str_newf ("%d->%d %d", bin->types[cid].descriptor_id, tid, bin->types[type_id].descriptor_id);
}

static char *dex_method_fullname(RBinDexObj *bin, int method_idx) {
	r_return_val_if_fail (bin && bin->types, NULL);
	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		return NULL;
	}
	int cid = bin->methods[method_idx].class_id;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	const char *name = dex_method_name (bin, method_idx);
	if (!name) {
		return NULL;
	}
	const char *className = dex_class_name_byid (bin, cid);
	char *flagname = NULL;
	if (className) {
		char *class_name = strdup (className);
		r_str_replace_char (class_name, ';', 0);
		char *signature = dex_method_signature (bin, method_idx);
		if (signature) {
			flagname = r_str_newf ("%s.%s%s", class_name, name, signature);
			free (signature);
		} else {
			flagname = r_str_newf ("%s.%s%s", class_name, name, "???");
		}
		free (class_name);
	} else {
		char *signature = dex_method_signature (bin, method_idx);
		if (signature) {
			flagname = r_str_newf ("%s.%s%s", "???", name, signature);
			free (signature);
		} else {
			flagname = r_str_newf ("%s.%s%s", "???", name, "???");
			free (signature);
		}
	}
	if (flagname && simplifiedDemangling) {
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
	RBinDexObj *bin = (RBinDexObj*) bf->o->bin_obj;
	if (!bin || !bin->types) {
		return 0;
	}
	if (type_idx < 0 || type_idx >= bin->header.types_size) {
		return 0;
	}
	return bin->header.types_offset + type_idx * 0x04; //&bin->types[type_idx];
}

static const char *dex_class_super_name(RBinDexObj *bin, RBinDexClass *c) {
	r_return_val_if_fail (bin && bin->types && c, NULL);

	int cid = c->super_class;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	int tid = bin->types[cid].descriptor_id;
	return getstr (bin, tid);
}

static const ut8 *parse_dex_class_fields(RBinFile *bf, RBinDexClass *c, RBinClass *cls,
		const ut8 *p, const ut8 *p_end, int *sym_count, ut64 fields_count, bool is_sfield) {
	RBinDexObj *dex = bf->o->bin_obj;
	RBin *bin = bf->rbin;
	ut64 lastIndex = 0;
	ut8 ff[sizeof (DexField)] = {0};
	int total, i, tid;
	DexField field;
	const char* type_str;
	for (i = 0; i < fields_count; i++) {
		ut64 fieldIndex, accessFlags;

		p = r_uleb128 (p, p_end - p, &fieldIndex); // fieldIndex
		p = r_uleb128 (p, p_end - p, &accessFlags); // accessFlags
		fieldIndex += lastIndex;
		total = dex->header.fields_offset + (sizeof (DexField) * fieldIndex);
		if (total >= dex->size || total < dex->header.fields_offset) {
			break;
		}
		if (r_buf_read_at (bf->buf, total, ff,
				sizeof (DexField)) != sizeof (DexField)) {
			break;
		}
		field.class_id = r_read_le16 (ff);
		field.type_id = r_read_le16 (ff + 2);
		field.name_id = r_read_le32 (ff + 4);
		char *fieldName = getstr (dex, field.name_id);
		if (field.type_id >= dex->header.types_size) {
			break;
		}
		tid = dex->types[field.type_id].descriptor_id;
		type_str = getstr (dex, tid);
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			break;
		}
		if (is_sfield) {
			sym->name = r_str_newf ("%s.sfield_%s:%s", cls->name, fieldName, type_str);
			sym->type = "STATIC";
		} else {
			sym->name = r_str_newf ("%s.ifield_%s:%s", cls->name, fieldName, type_str);
			sym->type = "FIELD";
		}
		sym->name = r_str_replace (sym->name, "method.", "", 0);
		r_str_replace_char (sym->name, ';', 0);
		sym->paddr = sym->vaddr = total;
		sym->ordinal = (*sym_count)++;

		if (dexdump) {
			const char *accessStr = createAccessFlagStr (
				accessFlags, kAccessForField);
			bin->cb_printf ("    #%d              : (in %s;)\n", i,
					 cls->name);
			bin->cb_printf ("      name          : '%s'\n", fieldName);
			bin->cb_printf ("      type          : '%s'\n", type_str);
			bin->cb_printf ("      access        : 0x%04x (%s)\n",
					 (unsigned int)accessFlags, accessStr? accessStr: "");
		}
		r_list_append (dex->methods_list, sym);

		RBinField *field = R_NEW0 (RBinField);
		if (field) {
			field->vaddr = field->paddr = sym->paddr;
			field->name = strdup (sym->name);
			field->flags = get_method_flags (accessFlags);
			r_list_append (cls->fields, field);
		}
		lastIndex = fieldIndex;
	}
	return p;
}

// TODO: refactor this method
// XXX it needs a lot of love!!!
static const ut8 *parse_dex_class_method(RBinFile *bf, RBinDexClass *c, RBinClass *cls, const ut8 *p, const ut8 *p_end,
		int *sym_count, ut64 DM, int *methods, bool is_direct, const ut8 *bufbuf) {
	RBin *rbin = bf->rbin;
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	RBinDexObj *bin = bf->o->bin_obj;
	bool bin_dbginfo = rbin->want_dbginfo;
	int i;
	ut64 omi = 0;
	bool catchAll;
	ut16 regsz = 0, ins_size = 0, outs_size = 0, tries_size = 0;
	ut16 start_addr, insn_count = 0;
	ut32 debug_info_off = 0, insns_size = 0;
	const ut8 *encoded_method_addr = NULL;

	if (!bin->trycatch_list) {
		bin->trycatch_list = r_list_newf ((RListFree)r_bin_trycatch_free);
	}
	if (DM > 4096) {
		eprintf ("This DEX is probably corrupted. Chopping DM from %d to 4KB\n", (int)DM);
		DM = 4096;
	}
	for (i = 0; i < DM; i++) {
		encoded_method_addr = p;
		ut64 MI, MA, MC;
		p = r_uleb128 (p, p_end - p, &MI);
		MI += omi;
		omi = MI;
		p = r_uleb128 (p, p_end - p, &MA);
		p = r_uleb128 (p, p_end - p, &MC);
		// TODO: MOVE CHECKS OUTSIDE!
		if (MI < bin->header.method_size) {
			if (methods) {
				methods[MI] = 1;
			}
		}
		char *method_name = dex_method_name (bin, MI);
		char *signature = dex_method_signature (bin, MI);
		if (!method_name) {
			method_name = "unknown";
		}
		char *flag_name = r_str_newf ("%s.method.%s%s", cls->name, method_name, signature);
		if (!flag_name || !*flag_name) {
			//R_FREE (method_name);
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
			if (MC + 16 >= bin->size || MC + 16 < MC) {
				//R_FREE (method_name);
				R_FREE (flag_name);
				R_FREE (signature);
				continue;
			}
			ut64 bufsz = r_buf_size (bf->buf);
			if (bufsz < MC || bufsz < MC + 16) {
				//R_FREE (method_name);
				R_FREE (flag_name);
				R_FREE (signature);
				continue;
			}
			regsz = r_buf_read_le16_at (bf->buf, MC);
			ins_size = r_buf_read_le16_at (bf->buf, MC + 2);
			outs_size = r_buf_read_le16_at (bf->buf, MC + 4);
			tries_size = r_buf_read_le16_at (bf->buf, MC + 6);
			debug_info_off = r_buf_read_le32_at (bf->buf, MC + 8);
			insns_size = r_buf_read_le32_at (bf->buf, MC + 12);
			int padd = 0;
			if (tries_size > 0 && insns_size % 2) {
				padd = 2;
			}
			t = 16 + 2 * insns_size + padd;
		}
		if (dexdump) {
			const char* accessStr = createAccessFlagStr (MA, kAccessForMethod);
			cb_printf ("    #%d              : (in %s;)\n", i, cls->name);
			cb_printf ("      name          : '%s'\n", method_name);
			cb_printf ("      type          : '%s'\n", signature);
			cb_printf ("      access        : 0x%04x (%s)\n", (ut32)MA, accessStr);
		}

		if (MC > 0) {
			if (dexdump) {
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
				if (dexdump) {
					cb_printf ("      catches       : %d\n", tries_size);
				}
				int j, m = 0;
				//XXX bucle controlled by tainted variable it could produces huge loop
				for (j = 0; j < tries_size; j++) {
					ut64 offset = MC + t + j * 8;
					if (offset >= bin->size || offset < MC) {
						R_FREE (signature);
						break;
					}
					ut64 bufsz = r_buf_size (bf->buf);
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
					char* s = NULL;
					if (dexdump) {
						cb_printf ("        0x%04x - 0x%04x\n", start_addr, (start_addr + insn_count));
					}
					RBinTrycatch *tc = r_bin_trycatch_new (method_offset, try_from, try_to, try_catch, 0);
					r_list_append (bin->trycatch_list, tc);

					//XXX tries_size is tainted and oob here
					int off = MC + t + tries_size * 8 + handler_off;
					if (off >= bin->size || off < tries_size) {
						R_FREE (signature);
						break;
					}
					// TODO: catch left instead of null
					st64 size;
					r_buf_seek (bf->buf, off, R_BUF_SET);
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

						if (handler_type > 0 && handler_type < bin->header.types_size) {
							s = getstr (bin, bin->types[handler_type].descriptor_id);
							if (dexdump) {
								cb_printf (
									"          %s "
									"-> 0x%04"PFMT64x"\n",
									s,
									handler_addr);
							}
							free (s);
						} else {
							if (dexdump) {
								cb_printf ("          (error) -> 0x%04"PFMT64x"\n", handler_addr);
							}
						}
					}
					if (catchAll) {
						r = r_buf_uleb128 (bf->buf, &v2);
						if (r <= 0) {
							break;
						}
						if (dexdump) {
							cb_printf ("          <any> -> 0x%04"PFMT64x"\n", v2);
						}
					}
				}
			} else {
				if (dexdump) {
					cb_printf (
						"      catches       : "
						"(none)\n");
				}
			}
		} else {
			if (dexdump) {
				cb_printf (
					"      code          : (none)\n");
			}
		}
		if (*flag_name) {
			RBinSymbol *sym = R_NEW0 (RBinSymbol);
			if (!sym) {
				R_FREE (flag_name);
				return NULL;
			}
			sym->name = flag_name;
			// is_direct is no longer used
			// if method has code *addr points to code
			// otherwise it points to the encoded method
			if (MC > 0) {
				sym->type = R_BIN_TYPE_FUNC_STR;
				sym->paddr = MC;// + 0x10;
				sym->vaddr = MC;// + 0x10;
			} else {
				sym->type = R_BIN_TYPE_METH_STR;
				sym->paddr = encoded_method_addr - bufbuf;
				sym->vaddr = encoded_method_addr - bufbuf;
			}
			bin->code_from = R_MIN (bin->code_from, sym->paddr);
			if ((MA & 1) == 1) {
				sym->bind = R_BIN_BIND_GLOBAL_STR;
			} else {
				sym->bind = R_BIN_BIND_LOCAL_STR;
			}

			sym->method_flags = get_method_flags (MA);

			sym->ordinal = (*sym_count)++;
			if (MC > 0) {
				ut64 bufsz = r_buf_size (bf->buf);
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
				sym->vaddr = MC + prolog_size;// + 0x10;
				//if (is_direct) {
				sym->size = insns_size * 2;
				//}
				//eprintf("%s (0x%x-0x%x) size=%d\nregsz=%d\ninsns_size=%d\nouts_size=%d\ntries_size=%d\ninsns_size=%d\n", flag_name, sym->vaddr, sym->vaddr+sym->size, prolog_size, regsz, ins_size, outs_size, tries_size, insns_size);
				r_list_append (bin->methods_list, sym);
				r_list_append (cls->methods, sym);

				if (bin->code_from == UT64_MAX || bin->code_from > sym->paddr) {
					bin->code_from = sym->paddr;
				}
				if (bin->code_to < sym->paddr) {
					bin->code_to = sym->paddr + sym->size;
				}

				if (!mdb) {
					mdb = sdb_new0 ();
				}
				sdb_num_set (mdb, sdb_fmt ("method.%"PFMT64d, MI), sym->paddr, 0);
				// -----------------
				// WORK IN PROGRESS
				// -----------------
#if 0
				if (0) {
					if (MA & 0x10000) { //ACC_CONSTRUCTOR
						if (!cdb) {
							cdb = sdb_new0 ();
						}
						sdb_num_set (cdb, sdb_fmt ("%d", c->class_id), sym->paddr, 0);
					}
				}
#endif
			} else {
				sym->size = 0;
				r_list_append (bin->methods_list, sym);
				r_list_append (cls->methods, sym);
			}
			if (MC > 0 && debug_info_off > 0 && bin->header.data_offset < debug_info_off &&
				debug_info_off < bin->header.data_offset + bin->header.data_size) {
				if (bin_dbginfo) {
					dex_parse_debug_item (bf, bin, c, MI, MA, sym->paddr, ins_size,
							insns_size, cls->name, regsz, debug_info_off);
				}
			} else if (MC > 0) {
				if (dexdump) {
					cb_printf ("      positions     :\n");
					cb_printf ("      locals        :\n");
				}
			}
		} else {
			R_FREE (flag_name);
		}
		R_FREE (signature);
		//R_FREE (method_name);
	}
	return p;
}

static void parse_class(RBinFile *bf, RBinDexClass *c, int class_index, int *methods, int *sym_count) {
	struct r_bin_dex_obj_t *dex = bf->o->bin_obj;
	RBin *rbin = bf->rbin;
	int z;
	const ut8 *p, *p_end;

	r_return_if_fail (bf && c);
	if (!c) {
		return;
	}
	char *class_name = dex_class_name (dex, c);
	if (!class_name || !*class_name) {
		return;
	}
	const char *superClass = dex_class_super_name (dex, c);
	if (!superClass) {
		return;
	}
	class_name = strdup (class_name);
	r_str_replace_char (class_name, ';', 0);

	if (!class_name || !*class_name) {
		return;
	}
	RBinClass *cls = R_NEW0 (RBinClass);
	if (!cls) {
		free (class_name);
		return;
	}
	cls->name = class_name;
	cls->index = class_index;
	cls->addr = dex->header.class_offset + class_index * DEX_CLASS_SIZE;
	cls->methods = r_list_new ();
	cls->super = strdup (superClass);
	if (!cls->methods) {
		free (cls);
		free (class_name);
		return;
	}
	cls->fields = r_list_new ();
	if (!cls->fields) {
		r_list_free (cls->methods);
		free (class_name);
		free (cls);
		return;
	}
	const char *str = createAccessFlagStr (c->access_flags, kAccessForClass);
	cls->visibility_str = strdup (str? str: "");
	r_list_append (dex->classes_list, cls);
	if (dexdump) {
		rbin->cb_printf ("  Class descriptor  : '%s;'\n", class_name);
		rbin->cb_printf ("  Access flags      : 0x%04x (%s)\n", c->access_flags,
			createAccessFlagStr (c->access_flags, kAccessForClass));
		rbin->cb_printf ("  Superclass        : '%s'\n", dex_class_super_name (dex, c));
		rbin->cb_printf ("  Interfaces        -\n");
	}

	if (c->interfaces_offset > 0 &&
	    dex->header.data_offset < c->interfaces_offset &&
	    c->interfaces_offset <
		    dex->header.data_offset + dex->header.data_size) {
		int types_list_size = r_buf_read_le32_at (bf->buf, c->interfaces_offset);
		if (types_list_size < 0 || types_list_size >= dex->header.types_size ) {
			return;
		}
		for (z = 0; z < types_list_size; z++) {
			ut16 le16;
			ut32 off = c->interfaces_offset + 4 + (z * 2);
			r_buf_read_at (bf->buf, off, (ut8*)&le16, sizeof (le16));
			int t = r_read_le16 (&le16);
			if (t > 0 && t < dex->header.types_size ) {
				int tid = dex->types[t].descriptor_id;
				if (dexdump) {
					rbin->cb_printf (
						"    #%d              : '%s'\n",
						z, getstr (dex, tid));
				}
			}
		}
	}
	// TODO: this is quite ugly
	if (!c || !c->class_data_offset) {
		if (dexdump) {
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
			return;
		}

		ut64 bufbufsz;
		const ut8 *bufbuf = r_buf_data (bf->buf, &bufbufsz);
		p = bufbuf + c->class_data_offset;
		// XXX may overflow
		if (bufbufsz < c->class_data_offset) {
			return;
		}
		ut32 p_size = (bufbufsz - c->class_data_offset);
		p_end = p + p_size;
		//XXX check for NULL!!
		c->class_data = (struct dex_class_data_item_t *)malloc (
			sizeof (struct dex_class_data_item_t));
		if (!c->class_data) {
			return;
		}
		if (p >= p_end) {
			free (c->class_data);
			return;
		}
		ut64 eof;

		p = r_uleb128 (p, p_end - p, &eof);
		if (p >= p_end) {
			free (c->class_data);
			return;
		}
		c->class_data->static_fields_size = eof;

		p = r_uleb128 (p, p_end - p, &eof);
		if (p >= p_end) {
			free (c->class_data);
			return;
		}
		c->class_data->instance_fields_size = eof;

		p = r_uleb128 (p, p_end - p, &eof);
		if (p >= p_end) {
			free (c->class_data);
			return;
		}
		c->class_data->direct_methods_size = eof;

		p = r_uleb128 (p, p_end - p, &eof);
		if (p >= p_end) {
			free (c->class_data);
			return;
		}
		c->class_data->virtual_methods_size = eof;

		if (dexdump) {
			rbin->cb_printf ("  Static fields     -\n");
		}
		p = parse_dex_class_fields (
			bf, c, cls, p, p_end, sym_count,
			c->class_data->static_fields_size, true);

		if (dexdump) {
			rbin->cb_printf ("  Instance fields   -\n");
		}
		p = parse_dex_class_fields (
			bf, c, cls, p, p_end, sym_count,
			c->class_data->instance_fields_size, false);

		if (dexdump) {
			rbin->cb_printf ("  Direct methods    -\n");
		}
		p = parse_dex_class_method (
			bf, c, cls, p, p_end, sym_count,
			c->class_data->direct_methods_size, methods, true, bufbuf);

		if (dexdump) {
			rbin->cb_printf ("  Virtual methods   -\n");
		}
		parse_dex_class_method (
			bf, c, cls, p, p_end, sym_count,
			c->class_data->virtual_methods_size, methods, false, bufbuf);
	}

	if (dexdump) {
		char *source_file = getstr (dex, c->source_file);
		if (!source_file) {
			rbin->cb_printf (
				"  source_file_idx   : %d (unknown)\n\n",
				c->source_file);
		} else {
			rbin->cb_printf ("  source_file_idx   : %d (%s)\n\n",
					 c->source_file, source_file);
		}
	}
	// TODO: fix memleaks
	//free (class_name);
}

static bool is_class_idx_in_code_classes(RBinDexObj *bin, int class_idx) {
	int i;
	for (i = 0; i < bin->header.class_size; i++) {
		if (class_idx == bin->classes[i].class_id) {
			return true;
		}
	}
	return false;
}

// XXX remove this second argument, must be implicit by the rbinfile
static bool dex_loadcode(RBinFile *bf) {
	RBin *rbin = bf->rbin;
	RBinDexObj *bin = bf->o->bin_obj;
	int i;
	int *methods = NULL;
	int sym_count = 0;

	r_return_val_if_fail (bf && bin, false);

	// doublecheck??
	if (bin->methods_list) {
		return false;
	}
	bin->version = r_bin_dex_get_version (bin);
	bin->code_from = UT64_MAX;
	bin->code_to = 0;
	bin->methods_list = r_list_newf ((RListFree)free);
	if (!bin->methods_list) {
		return false;
	}
	bin->imports_list = r_list_newf ((RListFree)free);
	if (!bin->imports_list) {
		r_list_free (bin->methods_list);
		return false;
	}
	bin->lines_list = r_list_newf ((RListFree)free);
	if (!bin->lines_list) {
		r_list_free (bin->methods_list);
		r_list_free (bin->imports_list);
		return false;
	}
	bin->classes_list = r_list_newf ((RListFree)r_bin_class_free);
	if (!bin->classes_list) {
		r_list_free (bin->methods_list);
		r_list_free (bin->imports_list);
		r_list_free (bin->lines_list);
		return false;
	}

	if (bin->header.method_size>bin->size) {
		bin->header.method_size = 0;
		return false;
	}

	/* WrapDown the header sizes to avoid huge allocations */
	bin->header.method_size = R_MIN (bin->header.method_size, bin->size);
	bin->header.class_size = R_MIN (bin->header.class_size, bin->size);
	bin->header.strings_size = R_MIN (bin->header.strings_size, bin->size);

	// TODO: is this posible after R_MIN ??
	if (bin->header.strings_size > bin->size) {
		eprintf ("Invalid strings size\n");
		return false;
	}
	dexSubsystem = NULL;

	if (bin->classes) {
		ut64 amount = sizeof (int) * bin->header.method_size;
		if (amount > UT32_MAX || amount < bin->header.method_size) {
			return false;
		}
		methods = calloc (1, amount + 1);
		for (i = 0; i < bin->header.class_size; i++) {
			struct dex_class_t *c = &bin->classes[i];
			if (dexdump) {
				rbin->cb_printf ("Class #%d            -\n", i);
			}
			parse_class (bf, c, i, methods, &sym_count);
		}
	}
	if (methods) {
		int import_count = 0;
		int sym_count = bin->methods_list->length;

		for (i = 0; i < bin->header.method_size; i++) {
			int len = 0;
			if (methods[i]) {
				continue;
			}
			if (bin->methods[i].class_id >= bin->header.types_size) {
				continue;
			}
			if (is_class_idx_in_code_classes (bin, bin->methods[i].class_id)) {
				continue;
			}
			const char *className = getstr (bin, bin->types[bin->methods[i].class_id].descriptor_id);
			if (!className) {
				continue;
			}
			char *class_name = strdup (className);
			if (!class_name) {
				free (class_name);
				continue;
			}
			if (!dexSubsystem) {
				if (strstr (class_name, "wearable/view")) {
					dexSubsystem = "android-wear";
				} else if (strstr (class_name, "android/view/View")) {
					dexSubsystem = "android";
				}
			}
			len = strlen (class_name);
			if (len < 1) {
				free (class_name);
				continue;
			}
			r_str_replace_char (class_name, ';', 0);
			char *method_name = dex_method_name (bin, i);
			char *signature = dex_method_signature (bin, i);
			if (method_name && *method_name) {
				RBinImport *imp = R_NEW0 (RBinImport);
				if (!imp) {
					free (methods);
					free (signature);
					free (class_name);
					return false;
				}
				imp->name  = r_str_newf ("%s.method.%s%s", class_name, method_name, signature);
				imp->type = "FUNC";
				imp->bind = "NONE";
				imp->ordinal = import_count++;
				r_list_append (bin->imports_list, imp);

				RBinSymbol *sym = R_NEW0 (RBinSymbol);
				if (!sym) {
					free (methods);
					free (signature);
					free (class_name);
					return false;
				}
				sym->name = strdup (imp->name);
				sym->is_imported = true;
				sym->type = R_BIN_TYPE_FUNC_STR;
				sym->bind = "NONE";
				//XXX so damn unsafe check buffer boundaries!!!!
				//XXX use r_buf API!!
				sym->paddr = sym->vaddr = bin->header.method_offset + (sizeof (struct dex_method_t) * i) ;
				sym->ordinal = sym_count++;
				r_list_append (bin->methods_list, sym);
				sdb_num_set (mdb, sdb_fmt ("method.%d", i), sym->paddr, 0);
			}
			free (signature);
			free (class_name);
		}
		free (methods);
	}
	return true;
}

static RList* imports(RBinFile *bf) {
	RBinDexObj *bin = (RBinDexObj*) bf->o->bin_obj;
	if (!bin) {
		return NULL;
	}
	if (bin && bin->imports_list) {
		return bin->imports_list;
	}
	dex_loadcode (bf);
	return bin->imports_list;
}

static RList *trycatch(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
	RBinDexObj *bin = (RBinDexObj*) bf->o->bin_obj;
	if (!bin->trycatch_list) {
		dex_loadcode (bf);
	}
	return bin->trycatch_list;
}

static RList *methods(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
	RBinDexObj *bin = (RBinDexObj*) bf->o->bin_obj;
	if (!bin->methods_list) {
		dex_loadcode (bf);
	}
	return bin->methods_list;
}

static RList *classes(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
	RBinDexObj *bin = (RBinDexObj*) bf->o->bin_obj;
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

	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);

	RBinDexObj *bin = (RBinDexObj*) bf->o->bin_obj;
	RList *ret = r_list_newf ((RListFree)free);

	if (!bin->methods_list) {
		dex_loadcode (bf);
	}

	// STEP 1. ".onCreate(Landroid/os/Bundle;)V"
	r_list_foreach (bin->methods_list, iter, m) {
		if (strlen (m->name) > 30 && m->bind &&
			(!strcmp (m->bind, R_BIN_BIND_LOCAL_STR) || !strcmp (m->bind, R_BIN_BIND_GLOBAL_STR)) &&
		    !strcmp (m->name + strlen (m->name) - 31,
			     ".onCreate(Landroid/os/Bundle;)V")) {
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
			if (strlen (m->name) > 26 &&
			    !strcmp (m->name + strlen (m->name) - 27,
				     ".main([Ljava/lang/String;)V")) {
				if (!already_entry (ret, m->paddr)) {
					if ((ptr = R_NEW0 (RBinAddr))) {
						ptr->paddr = ptr->vaddr = m->paddr;
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

static int getoffset(RBinFile *bf, int type, int idx) {
	struct r_bin_dex_obj_t *dex = bf->o->bin_obj;
	switch (type) {
	case 'm': // methods
		// TODO: ADD CHECK
		return offset_of_method_idx (bf, dex, idx);
	case 'f':
		return dex_field_offset (dex, idx);
	case 'o': // objects
		eprintf ("TODO: getoffset object\n");
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
	return -1;
}

static char *getname(RBinFile *bf, int type, int idx, bool sd) {
	simplifiedDemangling = sd; // XXX kill globals
	struct r_bin_dex_obj_t *dex = bf->o->bin_obj;
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

static RList *sections(RBinFile *bf) {
	struct r_bin_dex_obj_t *bin = bf->o->bin_obj;
	RList *ml = methods (bf);
	RBinSection *ptr = NULL;
	int ns, fsymsz = 0;
	RList *ret = NULL;
	RListIter *iter;
	RBinSymbol *m;
	int fsym = 0;

	r_list_foreach (ml, iter, m) {
		if (!fsym || m->paddr < fsym) {
			fsym = m->paddr;
		}
		ns = m->paddr + m->size;
		if (ns > r_buf_size (bf->buf)) {
			continue;
		}
		if (ns > fsymsz) {
			fsymsz = ns;
		}
	}
	if (!fsym) {
		return NULL;
	}
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	if ((ptr = R_NEW0 (RBinSection))) {
		ptr->name = strdup ("header");
		ptr->size = ptr->vsize = sizeof (struct dex_header_t);
		ptr->paddr= ptr->vaddr = 0;
		ptr->perm = R_PERM_R;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		ptr->name = strdup ("constpool");
		//ptr->size = ptr->vsize = fsym;
		ptr->paddr = ptr->vaddr = sizeof (struct dex_header_t);
		if (bin->code_from != UT64_MAX) {
			ptr->size = bin->code_from - ptr->vaddr; // fix size
		} else {
			eprintf ("Warning: Invalid code size\n");
			ptr->size = ptr->vaddr; // fix size
		}
		ptr->vsize = ptr->size;
		ptr->format = r_str_newf ("Cd %d[%d]", 4, ptr->vsize / 4);
		ptr->perm = R_PERM_R;
		ptr->add = true;
		r_list_append (ret, ptr);
		// Define as dwords!
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		ptr->name = strdup ("code");
		ptr->vaddr = ptr->paddr = bin->code_from; //ptr->vaddr = fsym;
		ptr->size = bin->code_to - ptr->paddr;
		ptr->vsize = ptr->size;
		ptr->perm = R_PERM_RX;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		//ut64 sz = bf ? r_buf_size (bf->buf): 0;
		ptr->name = strdup ("data");
		ptr->paddr = ptr->vaddr = fsymsz+fsym;
		if (ptr->vaddr > r_buf_size (bf->buf)) {
			ptr->paddr = ptr->vaddr = bin->code_to;
			ptr->size = ptr->vsize = r_buf_size (bf->buf) - ptr->vaddr;
		} else {
			ptr->size = ptr->vsize = r_buf_size (bf->buf) - ptr->vaddr;
			// hacky workaround
			//ptr->size = ptr->vsize = 1024;
		}
		ptr->perm = R_PERM_R; //|2;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	if ((ptr = R_NEW0 (RBinSection))) {
		ptr->name = strdup ("file");
		ptr->vaddr = ptr->paddr = 0;
		ptr->size = r_buf_size (bf->buf);
		ptr->vsize = ptr->size;
		ptr->perm = R_PERM_R;
		// ptr->format = strdup ("Cs 4");
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

// iH
static void dex_header(RBinFile *bf) {
	RBinDexObj *dex = bf->o->bin_obj;
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
	dexdump = true; /// XXX convert this global into an argument or field in RBinFile or so
	dex_loadcode (bf);
	dexdump = false;
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

static R_BORROW RList *lines(RBinFile *bf) {
	struct r_bin_dex_obj_t *dex = bf->o->bin_obj;
	/// XXX this is called more than once
	// r_sys_backtrace();
	return dex->lines_list;
	// return r_list_clone (dex->lines_list);
}

// iH*
static RList *dex_fields(RBinFile *bf) {
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	ut64 addr = 0;

#define ROW(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, siz, nam, sdb_fmt ("0x%08"PFMT64x, (ut64)val), fmt, false)); \
	addr += siz;

	r_buf_seek (bf->buf, 0, R_BUF_SET);
	ut64 magic = r_buf_read_le64 (bf->buf);
	ROW ("dex_magic", 8, magic, "[8]c");
	ut32 checksum = r_buf_read_le32 (bf->buf);
	ROW ("dex_checksum", 4, checksum, "x");
	ut8 signature[20];
	ROW ("dex_signature", 8, signature, "[20]c");
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

static RList* libs(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o && bf->o->bin_obj, NULL);
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
	r_list_sort(files, cmp_path);
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		if (!r_str_startswith (file, "classes")) {
			continue;
		}
		if (r_str_endswith (file, ".dex")) {
			char *n = r_str_newf ("%s%s%s", path, R_SYS_DIR, file);
			if (strcmp (n, bf->file)) {
				r_list_append (ret, n);
			}
			free (n);
		}
	}
	r_list_free (files);
	free (path);
	return ret;
}

RBinPlugin r_bin_plugin_dex = {
	.name = "dex",
	.desc = "dex format bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.check_buffer = check_buffer,
	.baddr = baddr,
	.entries = entries,
	.classes = classes,
	.sections = sections,
	.symbols = methods,
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
	.dbginfo = &r_bin_dbginfo_dex,
	.lines = &lines,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dex,
	.version = R2_VERSION
};
#endif
