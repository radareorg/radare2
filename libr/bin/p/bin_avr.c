/* radare - LGPL - Copyright 2016-2017 - pancake */

#include <r_bin.h>
#include <r_lib.h>

#define CHECK4INSTR(b, instr, size)       \
	if (!instr (b, 0) ||              \
		!instr ((b), (size)) ||   \
		!instr ((b), (size)*2) || \
		!instr ((b), (size)*3)) { \
		return false;             \
	}

#define CHECK3INSTR(b, instr, size)       \
	if (!instr ((b), (size)) ||       \
		!instr ((b), (size)*2) || \
		!instr ((b), (size)*3)) { \
		return false;             \
	}

static ut64 tmp_entry = UT64_MAX;

static bool rjmp(RBuffer* b, ut64 addr) {
	return (r_buf_read8_at (b, addr + 1) & 0xf0) == 0xc0;
}

static bool jmp(RBuffer* b, ut64 addr) {
	return (r_buf_read8_at (b, addr) == 0x0c) && (r_buf_read8_at (b, addr + 1) == 0x94);
}

static ut64 rjmp_dest(ut64 addr, RBuffer* b) {
	ut64 dst = 2 + addr + r_buf_read8_at (b, addr) * 2;
	dst += ((r_buf_read8_at (b, addr + 1) & 0xf) * 2) << 8;
	return dst;
}

static ut64 jmp_dest(RBuffer* b, ut64 addr) {
	return (r_buf_read8_at (b, addr + 2) + (r_buf_read8_at (b, addr + 3) << 8)) * 2;
}

static bool check_buffer_rjmp(RBuffer *b) {
	CHECK3INSTR (b, rjmp, 4);
	ut64 dst = rjmp_dest (0, b);
	if (dst < 1 || dst > r_buf_size (b)) {
		return false;
	}
	tmp_entry = dst;
	return true;
}


static bool check_buffer_jmp(RBuffer *b) {
	CHECK4INSTR (b, jmp, 4);
	ut64 dst = jmp_dest (b, 0);
	if (dst < 1 || dst > r_buf_size (b)) {
		return false;
	}
	tmp_entry = dst;
	return true;
}

static bool check_buffer(RBuffer *buf) {
	if (r_buf_size (buf) < 32) {
		return false;
	}
	if (!rjmp (buf, 0)) {
		return check_buffer_jmp (buf);
	}
	return check_buffer_rjmp (buf);
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static void destroy(RBinFile *bf) {
	r_buf_free (bf->o->bin_obj);
}

static RBinInfo* info(RBinFile *bf) {
	r_return_val_if_fail (bf, NULL);
	RBinInfo *bi = R_NEW0 (RBinInfo);
	if (bi) {
		bi->file = strdup (bf->file);
		bi->type = strdup ("ROM");
		bi->machine = strdup ("ATmel");
		bi->os = strdup ("avr");
		bi->has_va = 0; // 1;
		bi->has_lit = false;
		bi->arch = strdup ("avr");
		bi->bits = 8;
	}
	return bi;
}

static RList* entries(RBinFile *bf) {
	RList *ret;
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
	if (ptr) {
		ptr->name = strdup (r_str_get (name));
		ptr->paddr = ptr->vaddr = addr;
		ptr->size = 0;
		ptr->ordinal = 0;
		r_list_append (ret, ptr);
	}
}

static void addptr(RList *ret, const char *name, ut64 addr, RBuffer *b) {
	if (b && rjmp (b, 0)) {
		addsym (ret, sdb_fmt ("vector.%s", name), addr);
		ut64 ptr_addr = rjmp_dest (addr, b);
		addsym (ret, sdb_fmt ("syscall.%s", name), ptr_addr);
	}
}

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;
	RBuffer *obj = bf->o->bin_obj;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	/* atmega8 */
	addptr (ret, "int0", 2, obj);
	addptr (ret, "int1", 4, obj);
	addptr (ret, "timer2cmp", 6, obj);
	addptr (ret, "timer2ovf", 8, obj);
	addptr (ret, "timer1capt", 10, obj);
	addptr (ret, "timer1cmpa", 12, obj);
	return ret;
}

static RList *strings(RBinFile *bf) {
	// we dont want to find strings in avr bins because there are lot of false positives
	return NULL;
}

RBinPlugin r_bin_plugin_avr = {
	.name = "avr",
	.desc = "ATmel AVR MCUs",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.entries = &entries,
	.symbols = &symbols,
	.check_buffer = &check_buffer,
	.info = &info,
	.strings = &strings,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_avr,
	.version = R2_VERSION
};
#endif
