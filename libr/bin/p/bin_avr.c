/* radare - LGPL - Copyright 2016 - pancake */

#include <r_bin.h>

static ut64 tmp_entry = UT64_MAX;

static bool rjmp(const ut8* b) {
	return b && ((b[1] & 0xf0) == 0xc0);
}

static ut64 rjmp_dest(ut64 addr, const ut8* b) {
	ut64 dst = 2 + addr + b[0] * 2;
	dst += ((b[1] & 0xf) * 2) << 8;
	return dst;
}

static int check_bytes(const ut8 *b, ut64 length) {
	if (length < 32) {
		return false;
	}
	if (!rjmp (b)) return false;
	if (!rjmp (b + 2)) return false;
	if (!rjmp (b + 4)) return false;
	if (!rjmp (b + 8)) return false;
	ut64 dst = rjmp_dest (0, b);
	if (dst < 1 || dst > length) {
		return false;
	}
	if (!rjmp (b + dst - 2)) {
		return false;
	}
	tmp_entry = dst;
	return true;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !arch || !arch->buf) {
		free (ret);
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("ATmel");
	ret->os = strdup ("avr");
	ret->has_va = 0; // 1;
	ret->arch = strdup ("avr");
	ret->bits = 8;
	// bs = (const char*)arch->buf->buf;
	return ret;
}

static RList* entries(RBinFile *arch) {
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
	if (!ptr) return;
	ptr->name = strdup (name? name: "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = 0;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static void addptr(RList *ret, const char *name, ut64 addr, const ut8 *b, int len) {
	if (b && rjmp (b)) {
		addsym (ret, sdb_fmt (0, "vector.%s", name), addr);
		ut64 ptr_addr = rjmp_dest (addr, b + addr);
		addsym (ret, sdb_fmt (0, "syscall.%s", name), ptr_addr);
	}
}

static RList* symbols(RBinFile *arch) {
	RList *ret = NULL;
	const ut8 *b = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (false) { // TODO arch->cpu && !strcmp (arch->cpu, "atmega8")) {
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

static RList* strings (RBinFile *arch) {
	return NULL;
}

RBinPlugin r_bin_plugin_avr = {
	.name = "avr",
	.desc = "ATmel AVR MCUs",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.entries = &entries,
	.symbols = &symbols,
	.check_bytes = &check_bytes,
	.info = &info,
	.strings = &strings,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_avr,
	.version = R2_VERSION
};
#endif

