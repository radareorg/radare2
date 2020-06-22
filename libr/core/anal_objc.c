/* radare2 - LGPL - Copyright 2019-2020 - pancake */

/* This code has been written by pancake which has been based on Alvaro's
 * r2pipe-python script which was based on FireEye script for IDA Pro.
 *
 * https://www.fireeye.com/blog/threat-research/2017/03/introduction_to_reve.html
 */

#include <r_core.h>


typedef struct {
	RCore *core;
	HtUP *up;
	size_t word_size;
	RBinSection *_selrefs;
	RBinSection *_msgrefs;
	RBinSection *_const;
	RBinSection *_data;
} RCoreObjc;

static void array_add(RCoreObjc *o, ut64 va, ut64 xrefs_to) {
	bool found = false;
	RVector *vec = ht_up_find (o->up, va, &found);
	if (!found || !vec) {
		vec = r_vector_new (sizeof (ut64), NULL, NULL);
		ht_up_insert (o->up, va, vec);
	}
	ut64 *addr;
	r_vector_foreach (vec, addr) {
		if (xrefs_to == *addr) {
			return;
		}
	}
	// extend vector and insert new element
	r_vector_push (vec, &xrefs_to);
}

static void kv_array_free(HtUPKv *kv) {
	r_vector_free (kv->value);
}

static void array_new(RCoreObjc *o) {
	o->up = ht_up_new (NULL, kv_array_free, NULL);
}

static void array_free(RCoreObjc *o) {
	ht_up_free (o->up);
}

static inline bool isValid(ut64 addr) {
	return (addr != 0LL && addr != UT64_MAX);
}

static inline bool isInvalid(ut64 addr) {
	return (addr == 0LL || addr == UT64_MAX);
}

static inline bool inBetween(RBinSection *s, ut64 addr) {
	if (!s || isInvalid (addr)) {
		return false;
	}
	const ut64 from = s->vaddr;
	const ut64 to = from + s->vsize;
	return R_BETWEEN (from, addr, to);
}

static ut32 readDword(RCoreObjc *objc, ut64 addr, bool *success) {
	ut8 buf[4];
	*success = r_io_read_at (objc->core->io, addr, buf, sizeof (buf));
	return r_read_le32 (buf);
}

static ut64 readQword(RCoreObjc *objc, ut64 addr, bool *success) {
	ut8 buf[8] = {0};
	*success = r_io_read_at (objc->core->io, addr, buf, sizeof (buf));
	return r_read_le64 (buf);
}

static void objc_analyze(RCore *core) {
	const char *oldstr = r_print_rowlog (core->print,
		"Analyzing searching references to selref");
	r_core_cmd0 (core, "aar");
	if (!strcmp ("arm", r_config_get (core->config, "asm.arch"))) {
		const bool emu_lazy = r_config_get_i (core->config, "emu.lazy");
		r_config_set_i (core->config, "emu.lazy", true);
		r_core_cmd0 (core, "aae");
		r_config_set_i (core->config, "emu.lazy", emu_lazy);
	}
	r_print_rowlog_done (core->print, oldstr);
}

static ut64 getRefPtr(RCoreObjc *o, ut64 classMethodsVA, bool *rfound) {
	*rfound = false;

	bool readSuccess;
	ut64 namePtr = readQword (o, classMethodsVA, &readSuccess);
	if (!readSuccess) {
		return UT64_MAX;
	}

	size_t cnt = 0;
	ut64 ref = 0LL;

	bool found = false;
	bool isMsgRef = false;
	RVector *vec = ht_up_find (o->up, namePtr, &found);
	if (found && vec) {
		ut64 *addr;
		r_vector_foreach (vec, addr) {
			const ut64 at = *addr;
			if (inBetween (o->_selrefs, at)) {
				isMsgRef = false;
				ref = at;
			} else if (inBetween (o->_msgrefs, at)) {
				isMsgRef = true;
				ref = at;
			} else if (inBetween (o->_const, at)) {
				cnt++;
			}
		}
	}
	
	*rfound = (cnt > 1 && ref != 0);
	return isMsgRef? ref - 8: ref;
}

static bool objc_build_refs(RCoreObjc *objc) {
	ut64 off;
	if (!objc->_const || !objc->_selrefs) {
		return false;
	}

	size_t maxsize = R_MAX (objc->_const->vsize, objc->_selrefs->vsize);
	ut8 *buf = calloc (1, maxsize);
	if (!buf) {
		return false;
	}
	const size_t word_size = objc->word_size;
	(void)r_io_read_at (objc->core->io, objc->_const->vaddr, buf, objc->_const->vsize);
	for (off = 0; off + 8 < objc->_const->vsize; off += word_size) {
		ut64 va = objc->_const->vaddr + off;
		ut64 xrefs_to = r_read_le64 (buf + off);
		if (!xrefs_to) {
			continue;
		}
		array_add (objc, va, xrefs_to);
	}
	r_io_read_at (objc->core->io, objc->_selrefs->vaddr, buf, objc->_selrefs->vsize);
	for (off = 0; off + 8 < objc->_selrefs->vsize; off += word_size) {
		ut64 va = objc->_selrefs->vaddr + off;
		ut64 xrefs_to = r_read_le64 (buf + off);
		if (isValid (xrefs_to)) {
			array_add (objc, xrefs_to, va);
		}
	}
	free (buf);
	return true;
}

static bool objc_find_refs(RCore *core) {
	RCoreObjc objc = {0};

	const size_t objc2ClassSize = 0x28;
	const size_t objc2ClassInfoOffs = 0x20;
	const size_t objc2ClassMethSize = 0x18;
	const size_t objc2ClassBaseMethsOffs = 0x20;
	const size_t objc2ClassMethImpOffs = 0x10;

	objc.core = core;
	objc.word_size = (core->rasm->bits == 64)? 8: 4;

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

	array_new (&objc);
	if (!objc_build_refs (&objc)) {
		return false;
	}
	const char *oldstr = r_print_rowlog (core->print, "Parsing metadata in ObjC to find hidden xrefs");
	r_print_rowlog_done (core->print, oldstr);

	ut64 off;
	size_t total_xrefs = 0;
	bool readSuccess = true;
	for (off = 0; off < objc._data->vsize && readSuccess; off += objc2ClassSize) {
		if (!readSuccess || r_cons_is_breaked ()) {
			break;
		}

		ut64 va = objc._data->vaddr + off;
		ut64 classRoVA = readQword (&objc, va + objc2ClassInfoOffs, &readSuccess);
		if (!readSuccess || isInvalid (classRoVA)) {
			continue;
		}
		ut64 classMethodsVA = readQword (&objc, classRoVA + objc2ClassBaseMethsOffs, &readSuccess);
		if (!readSuccess || isInvalid (classMethodsVA)) {
			continue;
		}

		ut32 count = readDword (&objc, classMethodsVA + 4, &readSuccess);
		if (!readSuccess || ((ut32)count == UT32_MAX)) {
			continue;
		}

		classMethodsVA += 8; // advance to start of class methods array
		ut64 from = classMethodsVA;
		ut64 to = classMethodsVA + (objc2ClassMethSize * count);
		ut64 va2;
		for (va2 = from; va2 < to; va2 += objc2ClassMethSize) {
			if (r_cons_is_breaked ()) {
				break;
			}

			bool found = false;
			ut64 selRefVA = getRefPtr (&objc, va2, &found);
			if (!found) {
				continue;
			}
			ut64 funcVA = readQword (&objc, va2 + objc2ClassMethImpOffs, &readSuccess);
			if (!readSuccess) {
				break;
			}

			RList *list = r_anal_xrefs_get (core->anal, selRefVA);
			if (list) {
				RListIter *iter;
				RAnalRef *ref;
				r_list_foreach (list, iter, ref) {
					r_anal_xrefs_set (core->anal, ref->addr, funcVA, R_ANAL_REF_TYPE_CODE);
					total_xrefs++;
				}
			}
		}
	}
	array_free (&objc);

	char rs[128];

	const ut64 from = objc._selrefs->vaddr;
	const ut64 to = from + objc._selrefs->vsize;

	snprintf (rs, sizeof (rs), "Found %zu objc xrefs...", total_xrefs);
	r_print_rowlog (core->print, rs);
	size_t total_words = 0;
	ut64 a;
	const size_t word_size = objc.word_size;
	for (a = from; a < to; a += word_size) {
		r_meta_set (core->anal, R_META_TYPE_DATA, a, word_size, NULL);
		total_words++;
	}
	snprintf (rs, sizeof (rs), "Found %zu objc xrefs in %zu dwords.", total_xrefs, total_words);
	r_print_rowlog_done (core->print, rs);
	return true;
}

R_API bool cmd_anal_objc(RCore *core, const char *input, bool auto_anal) {
	r_return_val_if_fail (core && input, 0);
	if (!auto_anal) {
		objc_analyze (core);
	}
	return objc_find_refs (core);
}
