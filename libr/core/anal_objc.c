/* radare2 - LGPL - Copyright 2019-2021 - pancake */

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
	size_t file_size;
	RBinSection *_selrefs;
	RBinSection *_msgrefs;
	RBinSection *_const;
	RBinSection *_data;
} RCoreObjc;


const size_t objc2ClassSize = 0x28;
const size_t objc2ClassInfoOffs = 0x20;
const size_t objc2ClassMethSize = 0x18;
const size_t objc2ClassBaseMethsOffs = 0x20;
const size_t objc2ClassMethImpOffs = 0x10;

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

static inline bool isValid(ut64 addr) {
	return (addr != 0LL && addr != UT64_MAX);
}

static inline bool isInvalid(ut64 addr) {
	return !isValid (addr);
}

static inline bool inBetween(RBinSection *s, ut64 addr) {
	if (!s || isInvalid (addr)) {
		return false;
	}
	const ut64 from = s->vaddr;
	const ut64 to = from + s->vsize;
	return R_BETWEEN (from, addr, to);
}

static inline ut32 readDword(RCoreObjc *objc, ut64 addr, bool *success) {
	ut8 buf[4];
	*success = r_io_read_at (objc->core->io, addr, buf, sizeof (buf));
	return r_read_le32 (buf);
}

static inline ut64 readQword(RCoreObjc *objc, ut64 addr, bool *success) {
	ut8 buf[8] = {0};
	*success = r_io_read_at (objc->core->io, addr, buf, sizeof (buf));
	return r_read_le64 (buf);
}

static void objc_analyze(RCore *core) {
	const char *oldstr = r_print_rowlog (core->print, "Analyzing code to find selref references");
	r_core_cmd0 (core, "aar");
	if (!strcmp ("arm", r_config_get (core->config, "asm.arch"))) {
		const bool emu_lazy = r_config_get_i (core->config, "emu.lazy");
		r_config_set_b (core->config, "emu.lazy", true);
		r_core_cmd0 (core, "aae");
		r_config_set_b (core->config, "emu.lazy", emu_lazy);
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
	ut64 ref = UT64_MAX;
	bool isMsgRef = false;

	RVector *vec = ht_up_find (o->up, namePtr, rfound);
	if (!*rfound || !vec) {
		*rfound = false;
		return false;
	}
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
	if (cnt > 1 || ref == 0 || ref == UT64_MAX) {
		*rfound = false;
		return UT64_MAX;
	}
	return isMsgRef? ref - 8: ref;
}

static bool objc_build_refs(RCoreObjc *objc) {
	ut64 off;
	if (!objc->_const || !objc->_selrefs) {
		return false;
	}

	const ut64 va_const = objc->_const->vaddr;
	size_t ss_const = objc->_const->vsize;
	const ut64 va_selrefs = objc->_selrefs->vaddr;
	size_t ss_selrefs = objc->_selrefs->vsize;
	// TODO: check if ss_const or ss_selrefs are too big before going further
	size_t maxsize = R_MAX (ss_const, ss_selrefs);
	maxsize = R_MIN (maxsize, objc->file_size);
	if (ss_const > maxsize) {
		if (objc->core->bin->verbose) {
			eprintf ("aao: Truncating ss_const from %u to %u\n", (int)ss_const, (int)maxsize);
		}
		ss_const = maxsize;
	}
	if (ss_selrefs > maxsize) {
		if (objc->core->bin->verbose) {
			eprintf ("aao: Truncating ss_selrefs from %u to %u\n", (int)ss_selrefs, (int)maxsize);
		}
		ss_selrefs = maxsize;
	}
	ut8 *buf = calloc (1, maxsize);
	if (!buf) {
		return false;
	}
	const size_t word_size = objc->word_size; // assuming 8 because of the read_le64
	if (!r_io_read_at (objc->core->io, objc->_const->vaddr, buf, ss_const)) {
		eprintf ("aao: Cannot read the whole const section %u\n", (unsigned int)ss_const);
		return false;
	}
	for (off = 0; off + word_size < ss_const && off + word_size < maxsize; off += word_size) {
		ut64 va = va_const + off;
		ut64 xrefs_to = r_read_le64 (buf + off);
		if (isValid (xrefs_to)) {
			array_add (objc, va, xrefs_to);
		}
	}
	if (!r_io_read_at (objc->core->io, va_selrefs, buf, ss_selrefs)) {
		eprintf ("aao: Cannot read the whole selrefs section\n");
		return false;
	}
	for (off = 0; off + word_size < ss_selrefs && off + word_size < maxsize; off += word_size) {
		ut64 va = va_selrefs + off;
		ut64 xrefs_to = r_read_le64 (buf + off);
		if (isValid (xrefs_to)) {
			array_add (objc, xrefs_to, va);
		}
	}
	free (buf);
	return true;
}

static RCoreObjc *core_objc_new(RCore *core) {
	RList *sections = r_bin_get_sections (core->bin);
	if (!sections) {
		return false;
	}
	RCoreObjc *o = R_NEW0 (RCoreObjc);
	o->core = core;
	o->file_size = r_bin_get_size (core->bin);
	if (!o->file_size) {
		o->file_size = 512*1024*1024;
	}
	o->word_size = (core->rasm->config->bits == 64)? 8: 4;
	if (o->word_size != 8) {
		eprintf ("Warning: aao experimental on 32bit binaries\n");
	}

	RBinSection *s;
	RListIter *iter;
	r_list_foreach (sections, iter, s) {
		const char *name = s->name;
		if (strstr (name, "__objc_data")) {
			o->_data = s;
		} else if (strstr (name, "__objc_selrefs")) {
			o->_selrefs = s;
		} else if (strstr (name, "__objc_msgrefs")) {
			o->_msgrefs = s;
		} else if (strstr (name, "__objc_const")) {
			o->_const = s;
		}
	}
	if (!o->_const || ((o->_selrefs || o->_msgrefs) && !(o->_data && o->_const))) {
		free (o);
		return NULL;
	}
	o->up = ht_up_new (NULL, kv_array_free, NULL);

	return o;
}

static void core_objc_free(RCoreObjc *o) {
	if (o) {
		ht_up_free (o->up);
		free (o);
	}
}

static bool objc_find_refs(RCore *core) {
	RCoreObjc *objc = core_objc_new (core);
	if (!objc) {
		if (core->anal->verbose) {
			eprintf ("Could not find necessary Objective-C sections...\n");
		}
		return false;
	}

	if (!objc_build_refs (objc)) {
		core_objc_free (objc);
		return false;
	}
	const char *oldstr = r_print_rowlog (core->print, "Parsing metadata in ObjC to find hidden xrefs");
	r_print_rowlog_done (core->print, oldstr);

	ut64 off;
	size_t total_xrefs = 0;
	bool readSuccess = true;
	for (off = 0; off < objc->_data->vsize && readSuccess; off += objc2ClassSize) {
		if (!readSuccess || r_cons_is_breaked ()) {
			break;
		}

		ut64 va = objc->_data->vaddr + off;
		// XXX do a single r_io_read_at() and just r_read_le64() here
		ut64 classRoVA = readQword (objc, va + objc2ClassInfoOffs, &readSuccess);
		if (!readSuccess || isInvalid (classRoVA)) {
			continue;
		}
		ut64 classMethodsVA = readQword (objc, classRoVA + objc2ClassBaseMethsOffs, &readSuccess);
		if (!readSuccess || isInvalid (classMethodsVA)) {
			continue;
		}

		ut32 count = readDword (objc, classMethodsVA + 4, &readSuccess);
		if (!readSuccess || ((ut32)count == UT32_MAX)) {
			continue;
		}

		classMethodsVA += 8; // advance to start of class methods array
		ut64 delta = (objc2ClassMethSize * count);
		ut64 to = classMethodsVA + delta - 8;
		if (delta > objc->file_size) {
			eprintf ("Workaround: Corrupted objc data? checking next %"PFMT64x" !< %"PFMT64x"\n", classMethodsVA, to);
			count = (objc->_data->vsize / objc2ClassMethSize) - 1;
			delta = objc2ClassMethSize * count;
			to = classMethodsVA + delta;

		}
		if (classMethodsVA > to) {
			eprintf ("Warning: Fuzzed binary or bug in here, checking next %"PFMT64x" !< %"PFMT64x"\n", classMethodsVA, to);
			break;
		}
		for (va = classMethodsVA; va < to; va += objc2ClassMethSize) {
			if (r_cons_is_breaked ()) {
				break;
			}
			bool found = false;
			ut64 selRefVA = getRefPtr (objc, va, &found);
			if (!found) {
				continue;
			}
			bool succ = false;
			ut64 funcVA = readQword (objc, va + objc2ClassMethImpOffs, &succ);
			if (!succ) {
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

	const ut64 pa_selrefs = objc->_selrefs->paddr;
	const ut64 va_selrefs = objc->_selrefs->vaddr;
	const ut64 ss_selrefs = va_selrefs + objc->_selrefs->vsize;

	char rs[128];
	snprintf (rs, sizeof (rs), "Found %u objc xrefs...", (unsigned int)total_xrefs);
	r_print_rowlog (core->print, rs);
	size_t total_words = 0;
	ut64 a;
	const size_t word_size = objc->word_size;
	const size_t maxsize = objc->file_size - pa_selrefs;
	for (a = va_selrefs; a < ss_selrefs && a < maxsize; a += word_size) {
		r_meta_set (core->anal, R_META_TYPE_DATA, a, word_size, NULL);
		total_words++;
	}
	snprintf (rs, sizeof (rs), "Found %u objc xrefs in %u dwords.", (unsigned int)total_xrefs, (unsigned int)total_words);
	r_print_rowlog_done (core->print, rs);
	core_objc_free (objc);
	return true;
}

R_API bool cmd_anal_objc(RCore *core, const char *input, bool auto_anal) {
	r_return_val_if_fail (core && input, 0);
	if (!auto_anal) {
		objc_analyze (core);
	}
	return objc_find_refs (core);
}
