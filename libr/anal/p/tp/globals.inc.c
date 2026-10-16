/* radare - LGPL - Copyright 2026 - pancake */

// R2R db/anal/globals
static bool tp_global_is_memory(const TypeTraceAccess *access, void *user) {
	return !access->is_reg && access->mem.size > 0;
}

static bool tp_global_is_store(const TypeTraceAccess *access, void *user) {
	return tp_global_is_memory (access, user) && access->is_write;
}

static bool tp_global_data(TPState *tps, ut64 addr, ut64 size) {
	RAnal *anal = tps->anal;
	if (addr < 0x100 || !size || !anal->flb.f || !anal->iob.map_get_at) {
		return false;
	}
	RIOMap *map = anal->iob.map_get_at (anal->iob.io, addr);
	if (!map || !(map->sperm & R_PERM_R) || (map->sperm & R_PERM_X)
		|| map->id == tps->stack_map
		|| (map->name && (r_str_startswith (map->name, "stack")
			|| r_str_startswith (map->name, "heap") || r_str_startswith (map->name, "mem.")
			|| !strcmp (map->name, ".got.r2")))
		|| size > map->itv.size - (addr - map->itv.addr)
		|| r_flag_get_by_spaces (anal->flb.f, false, addr, "imports", NULL)) {
		return false;
	}
	if (r_flag_get_by_spaces (anal->flb.f, false, addr, "relocs", NULL)) {
		RBinReloc *reloc = anal->binb.get_reloc_at? anal->binb.get_reloc_at (anal->binb.bin, addr): NULL;
		if (!reloc || reloc->import || reloc->is_ifunc || (reloc->symbol && reloc->symbol->is_imported)) {
			return false;
		}
	}
	return true;
}

static bool tp_global_inferred(RAnal *anal, RFlagItem *global) {
	const char *type = r_anal_global_get_type (anal, global->addr);
	const char *inferred = sdb_const_getf (anal->sdb, NULL, "global.inferred.0x%" PFMT64x, global->addr);
	return type && inferred && !strcmp (type, inferred);
}

static RFlagItem *tp_global_container(RAnal *anal, ut64 addr) {
	r_flag_space_push (anal->flb.f, "globals");
	RFlagItem *global = r_flag_get_at (anal->flb.f, addr, true);
	r_flag_space_pop (anal->flb.f);
	return global && addr - global->addr < global->size? global: NULL;
}

static char *tp_global_type_merge(RAnal *anal, const char *current, const char *type, bool semantic, bool conflict) {
	if (!current || !strcmp (current, type)) {
		return strdup (type);
	}
	const ut64 width = r_anal_type_bitsize (anal, type);
	const ut64 previous_width = r_anal_type_bitsize (anal, current);
	if (conflict) {
		return strdup (current);
	}
	if (strchr (current, '*') && strchr (type, '*')) {
		if (!strcmp (current, "void *")) {
			return strdup (type);
		}
		return strdup (!strcmp (type, "void *")? current: "void *");
	}
	if (!semantic) {
		const bool refine = width == previous_width && r_str_startswith (current, "uint")
			&& (r_str_startswith (type, "int") || !strcmp (type, "float") || !strcmp (type, "double"));
		return strdup (width > previous_width || refine? type: current);
	}
	return strdup (type);
}

typedef struct {
	RAnal *anal;
	ut64 base;
	bool remove;
	bool explicit_global;
} TPGlobalRange;

static bool tp_global_range_cb(RFlagItem *global, void *user) {
	TPGlobalRange *range = user;
	if (!global->space || strcmp (global->space->name, "globals")) {
		return true;
	}
	if (!tp_global_inferred (range->anal, global)) {
		range->explicit_global = true;
		return false;
	}
	if (range->remove && global->addr != range->base) {
		r_anal_global_del (range->anal, global->addr);
	}
	return true;
}

static bool tp_global_set(TPState *tps, ut64 addr, const char *type, const char *name, const char *layout) {
	RAnal *anal = tps->anal;
	RFlagItem *container = tp_global_container (anal, addr);
	if (container && container->addr != addr) {
		return false;
	}
	ut64 size = r_anal_type_bitsize (anal, type) / 8;
	ut64 end;
	if (size > UT32_MAX || r_add_overflow (addr, size, &end) || !tp_global_data (tps, addr, size)) {
		return false;
	}
	RFlagItem *global = r_anal_global_get (anal, addr);
	const char *current = global? r_anal_global_get_type (anal, addr): NULL;
	if (global && ((current && !tp_global_inferred (anal, global)) || (!current && global->size && global->size != size))) {
		return false;
	}
	TPGlobalRange range = { .anal = anal, .base = addr };
	r_flag_foreach_range (anal->flb.f, addr + 1, end, tp_global_range_cb, &range);
	if (range.explicit_global) {
		return false;
	}
	char *global_name = global? strdup (global->name): r_str_newf ("global.0x%" PFMT64x, addr);
	if (!global_name) {
		return false;
	}
	if (R_STR_ISNOTEMPTY (name) && r_str_startswith (global_name, "global.0x")) {
		char *new_name = r_str_newf ("global.%s.0x%" PFMT64x, name, addr);
		if (!new_name) {
			free (global_name);
			return false;
		}
		r_name_filter (new_name, 0);
		if (!global || r_anal_global_rename (anal, addr, new_name)) {
			free (global_name);
			global_name = new_name;
		} else {
			free (new_name);
		}
	}
	range.remove = true;
	r_flag_foreach_range (anal->flb.f, addr + 1, end, tp_global_range_cb, &range);
	bool ok = r_anal_global_add (anal, addr, type, global_name);
	if (ok) {
		sdb_setf (anal->sdb, type, 0, "global.inferred.0x%" PFMT64x, addr);
		if (layout) {
			sdb_setf (anal->sdb, layout, 0, "global.layout.0x%" PFMT64x, addr);
		}
	}
	free (global_name);
	return ok;
}

static int tp_global_member_cmp(const RAnalTypeMember *a, const RAnalTypeMember *b) {
	return (a->offset > b->offset) - (a->offset < b->offset);
}

static bool tp_global_field(TPState *tps, ut64 base, ut64 addr, const char *type, const char *name, bool semantic) {
	RAnal *anal = tps->anal;
	const ut64 width = r_anal_type_bitsize (anal, type) / 8;
	if (!width || width > 0x1000 || addr < base || addr - base >= 0x1000
		|| !tp_global_data (tps, base, addr - base + width)) {
		return false;
	}
	RFlagItem *global = tp_global_container (anal, base);
	if (global && r_anal_global_get_type (anal, global->addr) && !tp_global_inferred (anal, global)) {
		return false;
	}
	char *layout = r_str_newf ("global_0x%" PFMT64x, base);
	if (!layout) {
		return false;
	}
	const char *owned = sdb_const_getf (anal->sdb, NULL, "global.layout.0x%" PFMT64x, base);
	RAnalBaseType *bt = r_anal_get_base_type (anal, layout);
	if (bt && (!owned || strcmp (owned, layout) || bt->kind != R_ANAL_BASE_TYPE_KIND_STRUCT)) {
		r_anal_base_type_free (bt);
		free (layout);
		return false;
	}
	if (!bt) {
		bt = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
		bt->name = strdup (layout);
		if (!bt->name) {
			r_anal_base_type_free (bt);
			free (layout);
			return false;
		}
	}
	RVecAnalTypeMember *members = r_anal_base_type_members (bt);
	RAnalTypeMember *member, *existing = NULL;
	ut64 offset = addr - base;
	R_VEC_FOREACH (members, member) {
		const ut64 end = member->offset + r_anal_type_bitsize (anal, member->type) / 8;
		if (member->offset == offset) {
			existing = member;
		} else if (offset < end && member->offset < offset + width) {
			r_anal_base_type_free (bt);
			free (layout);
			return false;
		}
	}
	bool changed = false;
	if (existing) {
		const bool conflict = sdb_const_getf (anal->sdb, NULL, "global.field.conflict.0x%" PFMT64x ".0x%" PFMT64x, base, offset) != NULL;
		char *merged = tp_global_type_merge (anal, existing->type, type, semantic, conflict);
		if (!merged) {
			r_anal_base_type_free (bt);
			free (layout);
			return false;
		}
		if (strcmp (merged, existing->type)) {
			if (semantic && strchr (existing->type, '*') && strchr (type, '*')
				&& strcmp (existing->type, "void *") && strcmp (type, "void *")) {
				sdb_setf (anal->sdb, "true", 0, "global.field.conflict.0x%" PFMT64x ".0x%" PFMT64x, base, offset);
			}
			free (existing->type);
			existing->type = merged;
			changed = true;
		} else {
			free (merged);
		}
		if (semantic && R_STR_ISNOTEMPTY (name) && r_str_startswith (existing->name, "field_0x")) {
			char *field_name = r_str_newf ("%s_0x%" PFMT64x, name, offset);
			if (field_name) {
				free (existing->name);
				existing->name = field_name;
				r_name_filter (existing->name, 0);
				changed = true;
			}
		}
	} else if (RVecAnalTypeMember_length (members) < 32) {
		RAnalTypeMember field = {
			.name = R_STR_ISNOTEMPTY (name)? r_str_newf ("%s_0x%" PFMT64x, name, offset): r_str_newf ("field_0x%" PFMT64x, offset),
			.type = strdup (type), .offset = offset
		};
		if (!field.name || !field.type) {
			anal_type_member_fini (&field);
			r_anal_base_type_free (bt);
			free (layout);
			return false;
		}
		r_name_filter (field.name, 0);
		RAnalTypeMember *added = RVecAnalTypeMember_emplace_back (members);
		if (!added) {
			anal_type_member_fini (&field);
			r_anal_base_type_free (bt);
			free (layout);
			return false;
		}
		*added = field;
		changed = true;
	}
	if (changed) {
		RVecAnalTypeMember_sort (members, tp_global_member_cmp);
		bt->size = 0;
		R_VEC_FOREACH (members, member) {
			bt->size = R_MAX (bt->size, member->offset * 8 + r_anal_type_bitsize (anal, member->type));
		}
		r_anal_save_base_type (anal, bt);
		sdb_setf (anal->sdb, layout, 0, "global.layout.0x%" PFMT64x, base);
	}
	bool attached = false;
	if (RVecAnalTypeMember_length (members) > 1) {
		const char *current = r_anal_global_get_type (anal, base);
		attached = !changed && current && !strcmp (current, layout);
		if (!attached) {
			attached = tp_global_set (tps, base, layout, NULL, layout);
		}
	}
	bool resolved = attached || (semantic && (existing || changed));
	r_anal_base_type_free (bt);
	free (layout);
	return resolved;
}

static bool tp_global_root(TPState *tps, const char *reg, int idx, ut64 *base) {
	int depth;
	for (depth = 0; reg && depth < 8; depth++) {
		idx = etrace_last_regwrite (&tps->tt, reg, idx - 1);
		if (idx < tps->bb_trace_start) {
			return false;
		}
		RAnalOp *op = tp_op_at (tps, etrace_addrof (&tps->tt, idx), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
		if (!op || etrace_have_memread (&tps->tt, idx)) {
			return false;
		}
		const ut32 kind = op->type & R_ANAL_OP_TYPE_MASK;
		const RArchValue *src = RVecRArchValue_at (&op->srcs, 0);
		const bool arm64 = tps->anal->config->bits == 64 && !strcmp (tps->anal->config->arch, "arm");
		if (arm64 && kind == R_ANAL_OP_TYPE_ADD && src && src->reg && !src->memref) {
			const RArchValue *offset = RVecRArchValue_at (&op->srcs, 1);
			const int page_idx = etrace_last_regwrite (&tps->tt, src->reg, idx - 1);
			if (!offset || offset->reg || offset->imm < 0 || offset->imm >= 0x1000 || page_idx < tps->bb_trace_start) {
				return false;
			}
			RAnalOp *page = tp_op_at (tps, etrace_addrof (&tps->tt, page_idx), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
			const TypeTraceAccess *written = etrace_find_access (&tps->tt, idx, etrace_is_regwrite_name, (void *)reg);
			if (!page || (page->type & R_ANAL_OP_TYPE_MASK) != R_ANAL_OP_TYPE_LEA
				|| page->ptr == UT64_MAX || (page->ptr & 0xfff) || !written
				|| etrace_regread_value (&tps->tt, idx, src->reg) != page->ptr
				|| r_add_overflow (page->ptr, (ut64)offset->imm, base) || *base != written->reg.value) {
				return false;
			}
			return tp_global_data (tps, *base, 1);
		}
		if (kind == R_ANAL_OP_TYPE_LEA && op->ptr != UT64_MAX) {
			const TypeTraceAccess *written = etrace_find_access (&tps->tt, idx, etrace_is_regwrite_name, (void *)reg);
			if (!written || written->reg.value != op->ptr) {
				return false;
			}
			// A page alone from ADRP is not proof of an object's base.
			if (arm64 && !(op->ptr & 0xfff)) {
				return false;
			}
			*base = op->ptr;
			return tp_global_data (tps, *base, 1);
		}
		if (kind != R_ANAL_OP_TYPE_MOV || !src || src->memref || src->regdelta) {
			return false;
		}
		if (!src->reg) {
			*base = src->imm;
			return tp_global_data (tps, *base, 1);
		}
		reg = src->reg;
	}
	return false;
}

static void tp_global_access(TPState *tps, RAnalOp *op, int idx) {
	if (op->tlocal || etrace_addrof (&tps->tt, idx) != op->addr) {
		return;
	}
	const TypeTraceAccess *access = etrace_find_access (&tps->tt, idx, tp_global_is_memory, NULL);
	if (!access || !tp_global_data (tps, access->mem.addr, access->mem.size)) {
		return;
	}
	if (access->mem.size != 1 && access->mem.size != 2 && access->mem.size != 4 && access->mem.size != 8) {
		return;
	}
	op = tp_op_at (tps, op->addr, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
	if (!op) {
		return;
	}
	const RArchValue *value = RVecRArchValue_at (access->is_write? &op->dsts: &op->srcs, 0);
	if (!value || !value->reg || value->regdelta || op->ireg) {
		return;
	}
	ut64 base;
	if (!tp_global_root (tps, value->reg, idx, &base)) {
		return;
	}
	r_strf_var (type, 16, "%s%d_t", op->sign? "int": "uint", access->mem.size * 8);
	const char *current = r_anal_global_get_type (tps->anal, access->mem.addr);
	const char *layout = sdb_const_getf (tps->anal->sdb, NULL, "global.layout.0x%" PFMT64x, base);
	if (current && layout && !strcmp (current, layout)) {
		current = NULL;
	}
	const char *inferred = current;
	if (!current) {
		inferred = ((op->family == R_ANAL_OP_FAMILY_FPU && !op->sign) || op->datatype == R_ANAL_DATATYPE_FLOAT)
			? (access->mem.size == 4? "float": "double"): type;
	}
	tp_global_field (tps, base, access->mem.addr, inferred, NULL, false);
}

static bool tp_global_semantic(TPState *tps, ut64 addr, const char *type, const char *name, int width) {
	RAnal *anal = tps->anal;
	if (R_STR_ISEMPTY (type) || (width && r_anal_type_bitsize (anal, type) != (ut64)width * 8)) {
		return false;
	}
	RFlagItem *global = tp_global_container (anal, addr);
	const char *current = global? r_anal_global_get_type (anal, global->addr): NULL;
	if (current && !tp_global_inferred (anal, global)) {
		return false;
	}
	if (global) {
		const char *layout = sdb_const_getf (anal->sdb, NULL, "global.layout.0x%" PFMT64x, global->addr);
		if ((width || global->addr != addr) && layout && (!current || !strcmp (layout, current))) {
			return tp_global_field (tps, global->addr, addr, type, name, true);
		}
		if (global->addr != addr) {
			return false;
		}
	}
	const char *semantic = sdb_const_getf (anal->sdb, NULL, "global.semantic.0x%" PFMT64x, addr);
	bool conflict = semantic && !strcmp (semantic, "conflict");
	char *merged = tp_global_type_merge (anal, current, type, true, conflict);
	if (!merged) {
		return false;
	}
	if (semantic && current && strchr (current, '*') && strchr (type, '*')
		&& strcmp (current, "void *") && strcmp (type, "void *") && strcmp (current, type)) {
		conflict = true;
	}
	const bool same = current && !strcmp (current, merged)
		&& (R_STR_ISEMPTY (name) || !r_str_startswith (global->name, "global.0x"));
	const char *pending = width? sdb_const_getf (anal->sdb, NULL, "global.layout.0x%" PFMT64x, addr): NULL;
	char *layout = pending? strdup (pending): NULL;
	if (pending && !layout) {
		free (merged);
		return false;
	}
	bool ok = same || tp_global_set (tps, addr, merged, name, layout);
	if (ok) {
		sdb_setf (anal->sdb, conflict? "conflict": merged, 0, "global.semantic.0x%" PFMT64x, addr);
		if (layout) {
			tp_global_field (tps, addr, addr, merged, name, true);
		}
	}
	free (layout);
	free (merged);
	return ok;
}

static bool tp_global_from_arg(TPState *tps, RAnalOp *op, int idx, const TPFieldChain *chain, const char *type, const char *name) {
	if (R_STR_ISEMPTY (type) || chain->len || op->tlocal) {
		return false;
	}
	const TypeTraceAccess *access = etrace_find_access (&tps->tt, idx, etrace_is_memread, NULL);
	if (access && tp_global_data (tps, access->mem.addr, access->mem.size)) {
		return tp_global_semantic (tps, access->mem.addr, type, name, access->mem.size);
	}
	if ((op->type & R_ANAL_OP_TYPE_MASK) != R_ANAL_OP_TYPE_LEA) {
		return false;
	}
	char *pointee = r_type_resolve_typedef (tps->anal->sdb_types, type);
	if (!pointee) {
		pointee = strdup (type);
	}
	if (!pointee) {
		return false;
	}
	char *star = strrchr (pointee, '*');
	if (!star) {
		free (pointee);
		return false;
	}
	char *close = strchr (star, ')');
	if (close && *r_str_trim_head_ro (close + 1) == '[') {
		char *open = star;
		while (open > pointee && open[-1] != '(') {
			open--;
		}
		if (open > pointee && r_str_trim_head_ro (open) == star) {
			memmove (open - 1, close + 1, strlen (close + 1) + 1);
		} else {
			memmove (star, star + 1, strlen (star + 1) + 1);
		}
	} else {
		*star = 0;
	}
	r_str_trim (pointee);
	ut64 addr = op->ptr;
	if (addr == UT64_MAX) {
		const RArchValue *dst = RVecRArchValue_at (&op->dsts, 0);
		const TypeTraceAccess *written = dst && dst->reg
			? etrace_find_access (&tps->tt, idx, etrace_is_regwrite_name, (void *)dst->reg): NULL;
		addr = written? written->reg.value: UT64_MAX;
	}
	// A char pointer does not establish the extent of a string or buffer.
	bool sized = r_anal_type_bitsize (tps->anal, pointee) > 8 || r_anal_global_get (tps->anal, addr);
	bool ok = sized && tp_global_semantic (tps, addr, pointee, name, 0);
	free (pointee);
	return ok;
}

static bool tp_global_from_ret(TPState *tps, int idx, const char *type) {
	const TypeTraceAccess *access = etrace_find_access (&tps->tt, idx, tp_global_is_store, NULL);
	return access && tp_global_data (tps, access->mem.addr, access->mem.size)
		&& tp_global_semantic (tps, access->mem.addr, type, NULL, access->mem.size);
}
