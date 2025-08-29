/* radare2 - LGPL - Copyright 2019-2025 - pancake */

/* This code has been written by pancake which has been based on Alvaro's
 * r2pipe-python script which was based on FireEye script for IDA Pro.
 *
 * https://www.fireeye.com/blog/threat-research/2017/03/introduction_to_reve.html
 */

#define R_LOG_ORIGIN "anal.objc"

#include <r_core.h>
#include <r_vec.h>

R_VEC_TYPE(RVecAnalRef, RAnalRef);

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
	R_LOG_INFO ("Analyzing code to find selref references");
	r_core_cmd_call (core, "aar");
	if (!strcmp ("arm", r_config_get (core->config, "asm.arch"))) {
		const bool emu_lazy = r_config_get_b (core->config, "emu.lazy");
		r_config_set_b (core->config, "emu.lazy", true);
		r_core_cmd_call (core, "aae");
		r_config_set_b (core->config, "emu.lazy", emu_lazy);
	}
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
		return UT64_MAX;
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
	return isMsgRef? ref - o->word_size: ref;
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
		if (objc->core->bin->options.verbose) {
			R_LOG_WARN ("aao: Truncating ss_const from %u to %u", (int)ss_const, (int)maxsize);
		}
		ss_const = maxsize;
	}
	if (ss_selrefs > maxsize) {
		if (objc->core->bin->options.verbose) {
			R_LOG_WARN ("aao: Truncating ss_selrefs from %u to %u", (int)ss_selrefs, (int)maxsize);
		}
		ss_selrefs = maxsize;
	}
	ut8 *buf = calloc (1, maxsize);
	if (!buf) {
		return false;
	}
	const size_t word_size = objc->word_size; // assuming 8 because of the read_le64
	if (!r_io_read_at (objc->core->io, objc->_const->vaddr, buf, ss_const)) {
		R_LOG_WARN ("aao: Cannot read the whole const section %u", (unsigned int)ss_const);
		return false;
	}
	for (off = 0; off + word_size < ss_const && off + word_size < maxsize; off += word_size) {
		ut64 va = va_const + off;
		ut64 xrefs_to = (word_size == 8)? r_read_le64 (buf + off): r_read_le32 (buf + off);
		if (isValid (xrefs_to)) {
			array_add (objc, va, xrefs_to);
		}
	}
	if (!r_io_read_at (objc->core->io, va_selrefs, buf, ss_selrefs)) {
		R_LOG_WARN ("aao: Cannot read the whole selrefs section");
		return false;
	}
	for (off = 0; off + word_size < ss_selrefs && off + word_size < maxsize; off += word_size) {
		ut64 va = va_selrefs + off;
		ut64 xrefs_to = (word_size == 8)? r_read_le64 (buf + off): r_read_le32 (buf + off);
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
		R_LOG_WARN ("aao experimental on 32bit binaries");
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
	// if (!o->_const || ((o->_selrefs || o->_msgrefs) && !(o->_data && o->_const))) {
	// reduce expectations, we dont need that much from objc
	if (!o->_const || !o->_data) {
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
			R_LOG_ERROR ("Could not find necessary Objective-C sections");
		}
		return false;
	}

	if (!objc_build_refs (objc)) {
		core_objc_free (objc);
		return false;
	}
	R_LOG_INFO ("Parsing metadata in ObjC to find hidden xrefs");

	ut64 off;
	size_t total_xrefs = 0;
	bool readSuccess = true;
	for (off = 0; off < objc->_data->vsize && readSuccess; off += objc2ClassSize) {
		if (!readSuccess || r_cons_is_breaked (core->cons)) {
			break;
		}

		ut64 va = objc->_data->vaddr + off;
		// XXX do a single r_io_read_at() and just r_read_le64() here
		ut64 classRoVA = readQword (objc, va + objc2ClassInfoOffs, &readSuccess);
		if (!readSuccess || isInvalid (classRoVA)) {
			continue;
		}
		if (objc->word_size == 8) {
			classRoVA &= ~(ut64)0x7;
		} else {
			classRoVA &= ~(ut64)0x3;
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
			R_LOG_WARN ("Workarounding malformed objc data. checking next %"PFMT64x" !< %"PFMT64x, classMethodsVA, to);
			count = (objc->_data->vsize / objc2ClassMethSize) - 1;
			delta = objc2ClassMethSize * count;
			to = classMethodsVA + delta;

		}
		if (classMethodsVA > to) {
			R_LOG_WARN ("Fuzzed binary or bug in here, checking next %"PFMT64x" !< %"PFMT64x, classMethodsVA, to);
			break;
		}
		for (va = classMethodsVA; va < to; va += objc2ClassMethSize) {
			if (r_cons_is_breaked (core->cons)) {
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

			RVecAnalRef *xrefs = r_anal_xrefs_get (core->anal, selRefVA);
			if (xrefs) {
				RAnalRef *ref;
				R_VEC_FOREACH (xrefs, ref) {
					// maybe ICOD?
					r_anal_xrefs_set (core->anal, ref->addr, funcVA, R_ANAL_REF_TYPE_CODE);
					total_xrefs++;
				}
			}
			RVecAnalRef_free (xrefs);
		}
	}
	// R_LOG_INFO ("Found %u objc xrefs", (unsigned int)total_xrefs);

	const ut64 va_selrefs = objc->_selrefs->vaddr;
	const ut64 ss_selrefs = va_selrefs + objc->_selrefs->vsize;

	size_t total_words = 0;
	ut64 a;
	const size_t word_size = objc->word_size;
	for (a = va_selrefs; a < ss_selrefs; a += word_size) {
		r_meta_set (core->anal, R_META_TYPE_DATA, a, word_size, NULL);
		total_words++;
	}
	R_LOG_INFO ("Found %u objc xrefs in %u dwords", (unsigned int)total_xrefs, (unsigned int)total_words);
	core_objc_free (objc);
	return true;
}

R_API bool cmd_anal_objc(RCore *core, const char *input, bool auto_anal) {
	R_RETURN_VAL_IF_FAIL (core && input, 0);
	if (!auto_anal) {
		objc_analyze (core);
	}
	return objc_find_refs (core);
}
