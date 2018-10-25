/* radare - LGPL - Copyright 2016-2017 - pancake */

#include <r_bin.h>

#define CHECK4INSTR(b, instr, size) \
	if (!instr (b) ||\
		!instr ((b) + (size)) ||\
		!instr ((b) + (size) * 2) ||\
		!instr ((b) + (size) * 3)) {\
		return false;\
	}

#define CHECK3INSTR(b, instr, size) \
	if (!instr ((b) + (size)) ||\
		!instr ((b) + (size) * 2) ||\
		!instr ((b) + (size) * 3)) {\
		return false;\
	}

static ut64 tmp_entry = UT64_MAX;

static bool rjmp(const ut8* b) {
	return b && ((b[1] & 0xf0) == 0xc0);
}

static bool jmp(const ut8* b) {
	return b && (b[0] == 0x0c) && (b[1] == 0x94);
}

static ut64 rjmp_dest(ut64 addr, const ut8* b) {
	ut64 dst = 2 + addr + b[0] * 2;
	dst += ((b[1] & 0xf) * 2) << 8;
	return dst;
}

static ut64 jmp_dest(const ut8* b) {
	return (b[2] + (b[3] << 8)) * 2;
}

static bool check_bytes_rjmp(const ut8 *b, ut64 length) {
	CHECK3INSTR (b, rjmp, 4);
	ut64 dst = rjmp_dest (0, b);
	if (dst < 1 || dst > length) {
		return false;
	}
	tmp_entry = dst;
	return true;
}


static bool check_bytes_jmp(const ut8 *b, ut64 length) {
	CHECK4INSTR (b, jmp, 4);
	ut64 dst = jmp_dest (b);
	if (dst < 1 || dst > length) {
		return false;
	}
	tmp_entry = dst;
	return true;
}

static bool check_bytes(const ut8 *b, ut64 length) {
	if (length < 32) {
		return false;
	}
	if (!rjmp (b)) {
		return check_bytes_jmp (b, length);
	}
	return check_bytes_rjmp (b, length);
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return check_bytes (buf, sz);
}

static RBinInfo* info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !bf || !bf->buf) {
		free (ret);
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("ATmel");
	ret->os = strdup ("avr");
	ret->has_va = 0; // 1;
	ret->has_lit = false;
	ret->arch = strdup ("avr");
	ret->bits = 8;
	// bs = (const char*)bf->buf->buf;
	return ret;
}

static RList* entries(RBinFile *bf) {
        RList* ret;
        RBinAddr *ptr = NULL;
	if (tmp_entry == UT64_MAX) {
		return false;
	}
        if (!(ret = r_list_new ())) {
                return NULL;
	}
        ret->free = free;
        if ((ptr = R_NEW0 (RBinAddr))) {
		ut64 addr = tmp_entry;
                ptr->vaddr = ptr->paddr = addr;
                r_list_append (ret, ptr);
        }
        return ret;
}

static void addsym(RList *ret, const char *name, ut64 addr) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (name? name: "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static void addptr(RList *ret, const char *name, ut64 addr, const ut8 *b, int len) {
	if (b && rjmp (b)) {
		addsym (ret, sdb_fmt ("vector.%s", name), addr);
		ut64 ptr_addr = rjmp_dest (addr, b + addr);
		addsym (ret, sdb_fmt ("syscall.%s", name), ptr_addr);
	}
}

static RList* symbols(RBinFile *bf) {
	RList *ret = NULL;
	const ut8 *b = bf ? r_buf_buffer (bf->buf) : NULL;
	ut64 sz = bf ? r_buf_size (bf->buf): 0;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (false) { // TODO bf->cpu && !strcmp (bf->cpu, "atmega8")) {
		/* ... */
	} else {
		/* atmega8 */
		addptr (ret, "int0", 2, b, sz);
		addptr (ret, "int1", 4, b, sz);
		addptr (ret, "timer2cmp", 6, b, sz);
		addptr (ret, "timer2ovf", 8, b, sz);
		addptr (ret, "timer1capt", 10, b, sz);
		addptr (ret, "timer1cmpa", 12, b, sz);
		/* ... */
	}
	return ret;
}

static RList* strings (RBinFile *bf) {
	return NULL;
}

RBinPlugin r_bin_plugin_avr = {
	.name = "avr",
	.desc = "ATmel AVR MCUs",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.entries = &entries,
	.symbols = &symbols,
	.check_bytes = &check_bytes,
	.info = &info,
	.strings = &strings,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_avr,
	.version = R2_VERSION
};
#endif
