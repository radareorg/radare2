/* radare2 - LGPL - Copyright 2019 - pancake */

/* This code has been written by pancake which has been based on Alvaro's
 * r2pipe-python script which was based on FireEye script for IDA Pro.
 *
 * https://www.fireeye.com/blog/threat-research/2017/03/introduction_to_reve.html
 */

#include <r_core.h>


typedef struct {
	RCore *core;
	Sdb *db;
	int word_size;
	RBinSection *_selrefs;
	RBinSection *_msgrefs;
	RBinSection *_const;
	RBinSection *_data;
} RCoreObjc;

static bool isInvalid (ut64 addr) {
	return (!addr || addr == UT64_MAX);
}

static const char *addr_key (ut64 va) {
	return sdb_fmt ("refs.0x%08"PFMT64x, va);
}

static bool inBetween(RBinSection *s, ut64 addr) {
	if (!s || addr == UT64_MAX) {
		return false;
	}
	ut64 from = s->vaddr;
	ut64 to = from + s->vsize;
	return R_BETWEEN (from, addr, to);
}

static ut32 readDword (RCoreObjc *objc, ut64 addr) {
	ut8 buf[4];
	(void)r_io_read_at (objc->core->io, addr, buf, sizeof (buf));
	return r_read_le32 (buf);
}

static ut64 readQword (RCoreObjc *objc, ut64 addr) {
	ut8 buf[8];
	(void)r_io_read_at (objc->core->io, addr, buf, sizeof (buf));
	return r_read_le64 (buf);
}

static void objc_analyze(RCore *core) {
	static const char *oldstr = NULL;
	oldstr = r_print_rowlog (core->print, "Analyzing searching references to selref");
	r_core_cmd0 (core, "aar");
	if (!strcmp ("arm", r_config_get (core->config, "asm.arch"))) {
		bool emu_lazy = r_config_get_i (core->config, "emu.lazy");
		r_config_set_i (core->config, "emu.lazy", true);
		r_core_cmd0 (core, "aae");
		r_config_set_i (core->config, "emu.lazy", emu_lazy);
	}
	r_print_rowlog_done (core->print, oldstr);
}

static ut64 getRefPtr(RCoreObjc *objc, ut64 classMethodsVA, bool *res) {
	ut64 namePtr = readQword (objc, classMethodsVA);
	int i, cnt = 0;
	ut64 res_at = 0LL;
	const char *k = addr_key (namePtr);

	*res = false;
	for (i = 0; ; i++) {
		ut64 at = sdb_array_get_num (objc->db, k, i, NULL);
		if (!at) {
			break;
		}
		if (inBetween (objc->_selrefs, at)) {
			*res = false;
			res_at = at;
		} else if (inBetween (objc->_msgrefs, at)) {
			*res = true;
			res_at = at;
		} else if (inBetween (objc->_const, at)) {
			cnt++;
		}
	}
	if (cnt > 1) {
		return 0LL;
	}
	return res_at;
}

static bool objc_build_refs(RCoreObjc *objc) {
	ut64 off;
	if (!objc->_const || !objc->_selrefs) {
		return false;
	}
	
	ut8 *buf = calloc (1, objc->_const->vsize);
	if (!buf) {
		return false;
	}
	(void)r_io_read_at (objc->core->io, objc->_const->vaddr, buf, objc->_const->vsize);
	for (off = 0; off + 8 < objc->_const->vsize; off += objc->word_size) {
		ut64 va = objc->_const->vaddr + off;
		ut64 xrefs_to = r_read_le64 (buf + off);
		if (!xrefs_to) {
			continue;
		}
		sdb_array_add_num (objc->db, addr_key (va), xrefs_to, 0);
	}
	free (buf);

	buf = calloc (1, objc->_selrefs->vsize);
	if (!buf) {
		return false;
	}
	r_io_read_at (objc->core->io, objc->_selrefs->vaddr, buf, objc->_selrefs->vsize);
	for (off = 0; off + 8 < objc->_selrefs->vsize; off += objc->word_size) {
		ut64 va = objc->_selrefs->vaddr + off;
		ut64 xrefs_to = r_read_le64 (buf + off);
		if (!xrefs_to) {
			continue;
		}
		sdb_array_add_num (objc->db, addr_key (xrefs_to), va, 0);
	}
	free (buf);
	return true;
}

static bool objc_find_refs(RCore *core) {
	static const char *oldstr = NULL;

	RCoreObjc objc = {0};

	const int objc2ClassSize = 0x28;
	const int objc2ClassInfoOffs = 0x20;
	const int objc2ClassMethSize = 0x18;
	const int objc2ClassBaseMethsOffs = 0x20;
	const int objc2ClassMethImpOffs = 0x10;

	objc.core = core;
	objc.word_size = (core->assembler->bits == 64)? 8: 4;

	RList *sections = r_bin_get_sections (core->bin);
	if (!sections) {
		return false;
	}
	
	RBinSection *s;
	RListIter *iter;
	r_list_foreach (sections, iter, s) {
		const char *name = s->name;
		if (strstr (name, "__objc_data")) {
			objc._data = s;
		} else if (strstr (name, "__objc_selrefs")) {
			objc._selrefs = s;
		} else if (strstr (name, "__objc_msgrefs")) {
			objc._msgrefs = s;
		} else if (strstr (name, "__objc_const")) {
			objc._const = s;
		}
	}
	if (!objc._const) {
		if (core->anal->verbose) {
			eprintf ("Could not find necessary objc_const section\n");
		}
		return false;
	}
	if ((objc._selrefs || objc._msgrefs) && !(objc._data && objc._const)) {
		if (core->anal->verbose) {
			eprintf ("Could not find necessary Objective-C sections...\n");
		}
		return false;
	}

	objc.db = sdb_new0 ();
	if (!objc_build_refs (&objc)) {
		return false;
	}
	oldstr = r_print_rowlog (core->print, "Parsing metadata in ObjC to find hidden xrefs");
	r_print_rowlog_done (core->print, oldstr);

	int total = 0;
	ut64 off;
	for (off = 0; off < objc._data->vsize ; off += objc2ClassSize) {
		ut64 va = objc._data->vaddr + off;
		ut64 classRoVA = readQword (&objc, va + objc2ClassInfoOffs);
		if (isInvalid (classRoVA)) {
			continue;
		}
		ut64 classMethodsVA = readQword (&objc, classRoVA + objc2ClassBaseMethsOffs);
		if (isInvalid (classMethodsVA)) {
			continue;
		}

		int count = readDword (&objc, classMethodsVA + 4);
		classMethodsVA += 8; // advance to start of class methods array
		ut64 from = classMethodsVA;
		ut64 to = from + (objc2ClassMethSize * count);
		ut64 va2;
		for (va2 = from; va2 < to; va2 += objc2ClassMethSize) {
			bool isMsgRef = false;
			ut64 selRefVA = getRefPtr (&objc, va2, &isMsgRef);
			if (!selRefVA) {
				continue;
			}
			// # adjust pointer to beginning of message_ref struct to get xrefs
			if (isMsgRef) {
				selRefVA -= 8;
			}
			ut64 funcVA = readQword (&objc, va2 + objc2ClassMethImpOffs);
			RList *list = r_anal_xrefs_get (core->anal, selRefVA);
			RListIter *iter;
			RAnalRef *ref;
			r_list_foreach (list, iter, ref) {
				r_anal_xrefs_set (core->anal, ref->addr, funcVA, R_META_TYPE_CODE);
				total++;
			}
		}

	}
	sdb_free (objc.db);
	oldstr = r_print_rowlog (core->print, sdb_fmt ("A total of %d xref were found", total));
	r_print_rowlog_done (core->print, oldstr);

	ut64 from = objc._selrefs->vaddr;
	ut64 to = from + objc._selrefs->vsize;
	total = 0;
	ut64 a;
	for (a = from; a < to; a += objc.word_size) {
		r_meta_set (core->anal, R_META_TYPE_DATA, a, 8, NULL);
		total ++;
	}
	oldstr = r_print_rowlog (core->print, sdb_fmt ("Set %d dwords at 0x%08"PFMT64x, total, from));
	r_print_rowlog_done (core->print, oldstr);
	return true;
}

R_API int cmd_anal_objc (RCore *core, const char *input, bool auto_anal) {
	if (!auto_anal) {
		objc_analyze (core);
	}
	objc_find_refs (core);
	return 0;
}
