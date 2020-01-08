/* radare - LGPL - Copyright 2018 - rkx1209 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "nxo.h"

ut32 readLE32(RBuffer *buf, int off) {
	//int left = 0;
	ut32 num = 0;
	(void)r_buf_read_at (buf, off, (ut8 *)&num, 4);
	return num;
}

ut64 readLE64(RBuffer *buf, int off) {
	return r_buf_size (buf) >= off + 8? r_buf_read_le64_at (buf, off): 0;
}

static char *readString(RBuffer *buf, int off) {
	char symbol[128]; // assume 128 as max symbol name length
	int left = r_buf_read_at (buf, off, (ut8*)symbol, sizeof (symbol));
	if (left < 1) {
		return NULL;
	}
	symbol[sizeof (symbol) - 1] = 0;
	return strdup (symbol);
}

const char *fileType(const ut8 *buf) {
	if (!memcmp (buf, "NRO0", 4)) {
		return "nro0";
	}
	if (!memcmp (buf, "NRR0", 4)) {
		return "nrr0";
	}
	if (!memcmp (buf, "MOD0", 4)) {
		return "mod0";
	}
	if (!memcmp (buf, "NSO0", 4)) {
		return "nso0";
	}
	return NULL;
}

static void walkSymbols (RBuffer *buf, RBinNXOObj *bin, ut64 symtab, ut64 strtab, ut64 strtab_size, ut64 relplt, ut64 baddr) {
	int i, import = 0;
	RBinSymbol *sym;
	RBinImport *imp;
	for (i = 8; i < 99999; i++) {
		ut64 addr = readLE64 (buf, symtab + i);
		ut64 size = readLE64 (buf, symtab + i + 8);
		i += 16; // NULL, NULL
		ut64 name = readLE32 (buf, symtab + i);
		//ut64 type = readLE32 (buf, symtab + i + 4);
		char *symName = readString (buf, strtab + name);
		if (!symName) {
			break;
		}
		sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			free (symName);
			break;
		}
		sym->type = R_BIN_TYPE_FUNC_STR;
		sym->bind = "NONE";
		sym->size = size;

		if (addr == 0) {
			import ++;
			ut64 pltSym = readLE64 (buf, relplt + (import * 24));
			imp = R_NEW0 (RBinImport);
			if (!imp) {
				R_FREE (sym);
				free (symName);
				break;
			}
			imp->name  = symName;
			if (!imp->name) {
				goto out_walk_symbol;
			}
			imp->type = "FUNC";
			if (!imp->type) {
				goto out_walk_symbol;
			}
			imp->bind = "NONE";
			if (!imp->bind) {
				goto out_walk_symbol;
			}
			imp->ordinal = bin->imports_list->length;
			r_list_append (bin->imports_list, imp);
			sym->is_imported = true;
			sym->name = strdup (symName);
			if (!sym->name) {
				goto out_walk_symbol;
			}
			sym->paddr = pltSym - 8;
			sym->vaddr = sym->paddr + baddr;
			eprintf ("f sym.imp.%s = 0x%"PFMT64x"\n", symName, pltSym - 8);
		} else {
			sym->name = symName;
			if (!sym->name) {
				R_FREE (sym);
				break;
			}
			sym->paddr = addr;
			sym->vaddr = sym->paddr + baddr;
			eprintf ("f sym.%s %"PFMT64u "0x%"PFMT64x"\n", symName, size, addr);
		}
		r_list_append (bin->methods_list, sym);
		i += 8 - 1;
	}
    return;

out_walk_symbol:
	R_FREE (sym);
	R_FREE (imp);
	return;
}

void parseMod(RBuffer *buf, RBinNXOObj *bin, ut32 mod0, ut64 baddr) {
	ut32 ptr = readLE32 (buf, mod0);
	eprintf ("magic %x at 0x%x\n", ptr, mod0);
	if (ptr == 0x30444f4d) { // MOD0
		eprintf ("is mode0\n");
		MODHeader mh = {
			.magic = readLE32 (buf, mod0),
			.dynamic = readLE32 (buf, mod0 + 4),
			.bss_start = readLE32 (buf, mod0 + 8),
			.bss_end = readLE32 (buf, mod0 + 12),
			.unwind_start = readLE32 (buf, mod0 + 16),
			.unwind_end = readLE32 (buf, mod0 + 20),
			.mod_object = readLE32 (buf, mod0 + 24),
		};
		mh.mod_object += mod0;
		eprintf ("magic 0x%x\n", mh.magic);
		eprintf ("dynamic 0x%x\n", mh.dynamic);
		eprintf ("bss 0x%x 0x%x\n", mh.bss_start, mh.bss_end);
		eprintf ("unwind 0x%x 0x%x\n", mh.unwind_start, mh.unwind_end);
		eprintf ("-------------\n");
		eprintf ("mod 0x%x\n", mh.mod_object);
#define MO_(x) readLE64(buf, mh.mod_object + r_offsetof(MODObject, x))
		MODObject mo = {
			.next = MO_(next),
			.prev = MO_(prev),
			.relplt = MO_(relplt),
			.reldyn = MO_(reldyn),
			.base = MO_(base),
			.dynamic = MO_(dynamic),
			.is_rela = MO_(is_rela),
			.relplt_size = MO_(relplt_size),
			.init = MO_(init),
			.fini = MO_(fini),
			.bucket = MO_(bucket),
			.chain = MO_(chain),
			.strtab = MO_(strtab),
			.symtab = MO_(symtab),
			.strtab_size = MO_(strtab_size)
		};
		eprintf ("next 0x%"PFMT64x"\n", mo.next);
		eprintf ("prev 0x%"PFMT64x"\n", mo.prev);
		eprintf ("base 0x%"PFMT64x"\n", mo.base);
		eprintf ("init 0x%"PFMT64x"\n", mo.init);
		eprintf ("fini 0x%"PFMT64x"\n", mo.fini);
		eprintf ("relplt 0x%"PFMT64x"\n", mo.relplt - mo.base);
		eprintf ("symtab = 0x%"PFMT64x"\n", mo.symtab - mo.base);
		eprintf ("strtab = 0x%"PFMT64x"\n", mo.strtab - mo.base);
		eprintf ("strtabsz = 0x%"PFMT64x"\n", mo.strtab_size);
		//ut32 modo = mh.mod_object;
		ut64 strtab = mo.strtab - mo.base;
		ut64 symtab = mo.symtab - mo.base;
		walkSymbols (buf, bin, symtab, strtab, mo.strtab_size, mo.relplt - mo.base, baddr);
	}
}
