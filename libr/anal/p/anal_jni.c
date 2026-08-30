/* radare - LGPL - Copyright 2026 - pancake */

#include <r_anal.h>
#include <r_anal_priv.h>
#include "../../../shlr/java/descriptor.h"

#define JNI_MIN_TABLE_METHODS 2
#define JNI_MAX_DATA_SECTION (64 * 1024 * 1024)
#define JNI_MAX_METHOD_NAME 256
#define JNI_MAX_DESCRIPTOR 2048

typedef struct {
	ut64 record_addr;
	ut64 name_addr;
	ut64 descriptor_addr;
	ut64 function_addr;
	char *name;
	char *descriptor;
	RJavaMember *member;
} JniMethod;

typedef struct {
	ut64 addr;
	RList /*<JniMethod *>*/ *methods;
} JniTable;

typedef struct {
	RAnal *anal;
	RBinObject *bo;
	Sdb *db;
	int pointer_size;
	bool big_endian;
	int tables_count;
} JniScanContext;

static void jni_function_param_free(void *ptr) {
	RAnalFunctionParam *param = ptr;
	if (param) {
		free (param->name);
		free (param->type);
		free (param);
	}
}

static bool jni_comment_contains_line(const char *comment, const char *line) {
	if (!comment || !line) {
		return false;
	}
	const size_t line_length = strlen (line);
	const char *p = comment;
	while ((p = strstr (p, line))) {
		const bool start_ok = p == comment || p[-1] == '\n';
		const char after = p[line_length];
		if (start_ok && (!after || after == '\n')) {
			return true;
		}
		p++;
	}
	return false;
}

static void jni_append_unique_comment(RAnal *anal, ut64 addr, const char *line) {
	const char *comment = r_meta_get_string (anal, R_META_TYPE_COMMENT, addr);
	if (jni_comment_contains_line (comment, line)) {
		return;
	}
	char *next = comment && *comment
		? r_str_newf ("%s\n%s", comment, line)
		: strdup (line);
	if (next) {
		r_meta_set_string (anal, R_META_TYPE_COMMENT, addr, next);
		free (next);
	}
}

static bool jni_function_name_is_generic(const char *name) {
	return r_str_startswith (name, "fcn.")
		|| r_str_startswith (name, "fcn_")
		|| r_str_startswith (name, "loc.")
		|| r_str_startswith (name, "loc_")
		|| r_str_startswith (name, "sub.")
		|| r_str_startswith (name, "sub_");
}

static char *jni_function_name(JniScanContext *ctx, JniMethod *method) {
	char *method_name = r_name_filter_dup (method->name);
	char *name = r_str_newf ("jni.%s.%08"PFMT32x,
		method_name, r_str_hash (method->descriptor));
	free (method_name);
	RAnalFunction *other = r_anal_get_function_byname (ctx->anal, name);
	if (!other || other->addr == method->function_addr) {
		return name;
	}
	char *unique_name = r_str_newf ("%s.%08"PFMT64x,
		name, method->function_addr);
	free (name);
	return unique_name;
}

static void jni_function_rename(RAnal *anal, RAnalFunction *fcn, const char *name) {
	char *old_name = strdup (fcn->name);
	if (!r_anal_function_rename (fcn, name)) {
		free (old_name);
		return;
	}
	if (anal->flb.f) {
		RFlagItem *flag = r_flag_get_by_spaces (anal->flb.f, false,
			fcn->addr, "functions", NULL);
		if (flag && flag->space && !strcmp (flag->space->name, "functions")
				&& !strcmp (flag->name, old_name)) {
			r_flag_rename (anal->flb.f, flag, name);
		}
	}
	free (old_name);
}

static bool jni_function_has_prototype(RAnal *anal, RAnalFunction *fcn) {
	r_anal_types_ensure_loaded (anal);
	char *linked_name = r_type_link_at (anal->sdb_types, fcn->addr);
	if (linked_name) {
		const bool is_function = r_type_kind (anal->sdb_types, linked_name)
			== R_TYPE_FUNCTION;
		free (linked_name);
		if (is_function) {
			return true;
		}
	}
	const char *dwarf_name = sdb_const_getf (anal->sdb_types, NULL,
		"fcnlink.%08"PFMT64x, fcn->addr);
	if (dwarf_name && r_type_kind (anal->sdb_types, dwarf_name)
			== R_TYPE_FUNCTION) {
		return true;
	}
	if (r_type_func_exist (anal->sdb_types, fcn->name)) {
		r_type_set_link (anal->sdb_types, fcn->name, fcn->addr);
		return true;
	}
	const char *basename = r_str_rchr (fcn->name, NULL, '.');
	if (basename && basename[1]
			&& r_type_func_exist (anal->sdb_types, basename + 1)) {
		r_type_set_link (anal->sdb_types, basename + 1, fcn->addr);
		return true;
	}
	return false;
}

static void jni_function_add_param(RList *params, const char *type, char *name) {
	RAnalFunctionParam *param = R_NEW (RAnalFunctionParam);
	param->name = name;
	param->type = strdup (type);
	r_list_append (params, param);
}

static void jni_function_set_signature(JniScanContext *ctx,
		RAnalFunction *fcn, JniMethod *method) {
	Sdb *types = ctx->anal->sdb_types;
	sdb_set (types, fcn->name, "func", 0);
	r_type_set_link (types, fcn->name, fcn->addr);
	RList *params = r_list_newf (jni_function_param_free);
	jni_function_add_param (params, "JNIEnv *", strdup ("env"));
	// A native table alone cannot tell instance and static receivers apart.
	jni_function_add_param (params, "jobject", strdup ("receiver"));
	RListIter *iter;
	RJavaType *argument;
	int argument_index = 0;
	r_list_foreach (method->member->arguments, iter, argument) {
		char *name = r_str_newf ("arg%d", argument_index++);
		jni_function_add_param (params, argument->jni_name, name);
	}
	RAnalFunctionSignature signature = {
		.ret_type = method->member->type->jni_name,
		.params = params,
	};
	const bool result = r_anal_function_set_signature (ctx->anal, fcn,
		&signature);
	if (!result) {
		r_type_unlink (types, fcn->addr);
		r_type_del (types, fcn->name);
	}
	r_list_free (params);
}

static RAnalFunction *jni_materialize_method(JniScanContext *ctx,
		JniMethod *method) {
	RAnalFunction *fcn = r_anal_get_function_at (ctx->anal,
		method->function_addr);
	const bool has_prototype = fcn
		&& jni_function_has_prototype (ctx->anal, fcn);
	char *name = jni_function_name (ctx, method);
	if (!fcn) {
		fcn = r_anal_create_function (ctx->anal, name,
			method->function_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	} else if (jni_function_name_is_generic (fcn->name)) {
		jni_function_rename (ctx->anal, fcn, name);
	}
	free (name);
	if (!fcn) {
		return NULL;
	}
	if (!has_prototype) {
		jni_function_set_signature (ctx, fcn, method);
	}
	if (r_list_empty (fcn->bbs)) {
		r_anal_function (ctx->anal, fcn, fcn->addr, R_ANAL_REF_TYPE_CALL);
	}
	const ut64 pointer_addr = method->record_addr + ctx->pointer_size * 2;
	r_anal_xrefs_set (ctx->anal, pointer_addr, fcn->addr,
		R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_EXEC);
	char *comment = r_str_newf ("JNI: %s%s receiver=jobject|jclass",
		method->name, method->descriptor);
	jni_append_unique_comment (ctx->anal, fcn->addr, comment);
	free (comment);
	return fcn;
}

static void jni_method_free(void *ptr) {
	JniMethod *method = ptr;
	if (method) {
		free (method->name);
		free (method->descriptor);
		r_java_member_free (method->member);
		free (method);
	}
}

static void jni_table_free(JniTable *table) {
	if (table) {
		r_list_free (table->methods);
		free (table);
	}
}

static bool jni_add_shift(ut64 addr, st64 shift, ut64 *result) {
	if (shift >= 0) {
		ut64 delta = (ut64)shift;
		if (addr > UT64_MAX - delta) {
			return false;
		}
		*result = addr + delta;
		return true;
	}
	ut64 delta = (ut64)(-(shift + 1)) + 1;
	if (addr < delta) {
		return false;
	}
	*result = addr - delta;
	return true;
}

static bool jni_addr_has_perm(JniScanContext *ctx, ut64 addr, int perm) {
	RIORegion region;
	return ctx->anal->iob.get_region_at (ctx->anal->iob.io, &region, addr)
		&& (region.perm & perm) == perm;
}

static bool jni_resolve_addr(JniScanContext *ctx, ut64 addr, int perm, ut64 *result) {
	if (!addr) {
		return false;
	}
	ut64 shifted;
	bool has_shifted = ctx->bo->baddr_shift
		&& jni_add_shift (addr, ctx->bo->baddr_shift, &shifted);
	if (!ctx->bo->is_reloc_patched && has_shifted
			&& jni_addr_has_perm (ctx, shifted, perm)) {
		*result = shifted;
		return true;
	}
	if (jni_addr_has_perm (ctx, addr, perm)) {
		*result = addr;
		return true;
	}
	if (has_shifted && jni_addr_has_perm (ctx, shifted, perm)) {
		*result = shifted;
		return true;
	}
	return false;
}

static char *jni_read_string(JniScanContext *ctx, ut64 addr, size_t maxlen) {
	RIORegion region;
	if (!ctx->anal->iob.get_region_at (ctx->anal->iob.io, &region, addr)
			|| !(region.perm & R_PERM_R)) {
		return NULL;
	}
	ut64 end = r_itv_end (region.itv);
	if (end <= addr) {
		return NULL;
	}
	size_t available = R_MIN ((ut64)maxlen, end - addr);
	char *str = R_NEWS (char, available + 1);
	if (ctx->anal->iob.read_at (ctx->anal->iob.io, addr, (ut8 *)str, available) != available) {
		free (str);
		return NULL;
	}
	str[available] = 0;
	char *nul = memchr (str, 0, available);
	if (!nul) {
		free (str);
		return NULL;
	}
	*nul = 0;
	return str;
}

static bool jni_method_name_is_valid(const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	const ut8 first = (ut8)*name;
	if (first < 0x80 && !isalpha (first) && first != '_' && first != '$') {
		return false;
	}
	const ut8 *p = (const ut8 *)name + 1;
	for (; *p; p++) {
		if (*p < 0x80 && !isalnum (*p) && *p != '_' && *p != '$') {
			return false;
		}
	}
	return true;
}

static ut64 jni_read_pointer(JniScanContext *ctx, const ut8 *buf) {
	return ctx->pointer_size == 8
		? r_read_ble64 (buf, ctx->big_endian)
		: r_read_ble32 (buf, ctx->big_endian);
}

static bool jni_resolve_function(JniScanContext *ctx, ut64 addr, ut64 *result) {
	const char *arch = ctx->anal->config->arch;
	if ((addr & 1) && arch && r_str_startswith (arch, "arm")) {
		if (jni_resolve_addr (ctx, addr & ~1ULL, R_PERM_X, result)) {
			return true;
		}
	}
	return jni_resolve_addr (ctx, addr, R_PERM_X, result);
}

static JniMethod *jni_parse_method(JniScanContext *ctx, const ut8 *buf, ut64 record_addr) {
	ut64 name_addr;
	ut64 descriptor_addr;
	ut64 function_addr;
	const int pointer_size = ctx->pointer_size;
	if (!jni_resolve_function (ctx, jni_read_pointer (ctx, buf + pointer_size * 2),
			&function_addr)) {
		return NULL;
	}
	if (!jni_resolve_addr (ctx, jni_read_pointer (ctx, buf), R_PERM_R, &name_addr)
			|| !jni_resolve_addr (ctx, jni_read_pointer (ctx, buf + pointer_size),
				R_PERM_R, &descriptor_addr)) {
		return NULL;
	}
	char *name = jni_read_string (ctx, name_addr, JNI_MAX_METHOD_NAME);
	if (!jni_method_name_is_valid (name)) {
		free (name);
		return NULL;
	}
	char *descriptor = jni_read_string (ctx, descriptor_addr, JNI_MAX_DESCRIPTOR);
	if (!descriptor || *descriptor != '(') {
		free (name);
		free (descriptor);
		return NULL;
	}
	RJavaMember *member = r_java_member_parse (NULL, name, descriptor,
		R_JAVA_MEMBER_METHOD, 0);
	if (!member) {
		free (name);
		free (descriptor);
		return NULL;
	}
	JniMethod *method = R_NEW (JniMethod);
	method->record_addr = record_addr;
	method->name_addr = name_addr;
	method->descriptor_addr = descriptor_addr;
	method->function_addr = function_addr;
	method->name = name;
	method->descriptor = descriptor;
	method->member = member;
	return method;
}

static JniTable *jni_table_at(JniScanContext *ctx, const ut8 *b, size_t sz, size_t off, ut64 va) {
	const size_t record_size = ctx->pointer_size * 3;
	JniTable *table = R_NEW (JniTable);
	table->addr = va + off;
	table->methods = r_list_newf (jni_method_free);
	while (off <= sz - record_size) {
		JniMethod *method = jni_parse_method (ctx, b + off, va + off);
		if (!method) {
			break;
		}
		r_list_append (table->methods, method);
		off += record_size;
	}
	if (r_list_length (table->methods) < JNI_MIN_TABLE_METHODS) {
		jni_table_free (table);
		return NULL;
	}
	return table;
}

static void jni_store_table(JniScanContext *ctx, JniTable *table) {
	const int table_index = ctx->tables_count++;
	sdb_num_setf (ctx->db, table->addr, 0, "table.%d.addr", table_index);
	sdb_num_setf (ctx->db, r_list_length (table->methods), 0,
		"table.%d.count", table_index);
	RListIter *iter;
	JniMethod *method;
	int method_index = 0;
	r_list_foreach (table->methods, iter, method) {
		RAnalFunction *fcn = jni_materialize_method (ctx, method);
		sdb_num_setf (ctx->db, method->record_addr, 0,
			"table.%d.method.%d.record", table_index, method_index);
		sdb_num_setf (ctx->db, method->name_addr, 0,
			"table.%d.method.%d.name_addr", table_index, method_index);
		sdb_num_setf (ctx->db, method->descriptor_addr, 0,
			"table.%d.method.%d.descriptor_addr", table_index, method_index);
		sdb_num_setf (ctx->db, method->function_addr, 0,
			"table.%d.method.%d.function", table_index, method_index);
		sdb_setf (ctx->db, method->name, 0,
			"table.%d.method.%d.name", table_index, method_index);
		sdb_setf (ctx->db, method->descriptor, 0,
			"table.%d.method.%d.descriptor", table_index, method_index);
		sdb_setf (ctx->db, method->member->definition, 0,
			"table.%d.method.%d.definition", table_index, method_index);
		sdb_setf (ctx->db, method->member->jni_definition, 0,
			"table.%d.method.%d.jni_definition", table_index, method_index);
		sdb_setf (ctx->db, "jobject|jclass", 0,
			"table.%d.method.%d.receiver_type", table_index, method_index);
		if (fcn) {
			sdb_setf (ctx->db, fcn->name, 0,
				"table.%d.method.%d.analysis_name", table_index, method_index);
		}
		method_index++;
	}
}

static bool jni_section_is_scannable(const RBinSection *section, size_t min_size) {
	return section && !section->is_segment
		&& (section->perm & R_PERM_R) && !(section->perm & R_PERM_X)
		&& section->size >= min_size && section->size <= JNI_MAX_DATA_SECTION
		&& section->vaddr != UT64_MAX && section->name
		&& strstr (section->name, "data");
}

static void jni_scan_section(JniScanContext *ctx, const RBinSection *section) {
	const size_t record_size = ctx->pointer_size * 3;
	const size_t min_size = record_size * JNI_MIN_TABLE_METHODS;
	if (!jni_section_is_scannable (section, min_size)) {
		return;
	}
	ut64 section_addr;
	if (!jni_resolve_addr (ctx, section->vaddr, R_PERM_R, &section_addr)) {
		return;
	}
	size_t size = (size_t)section->size;
	if (section_addr > UT64_MAX - size) {
		return;
	}
	ut8 *buf = R_NEWS (ut8, size);
	if (ctx->anal->iob.read_at (ctx->anal->iob.io, section_addr, buf, (int)size) != (int)size) {
		free (buf);
		return;
	}
	size_t offset = (ctx->pointer_size - (section_addr % ctx->pointer_size))
		% ctx->pointer_size;
	while (offset <= size - min_size) {
		JniTable *table = jni_table_at (ctx, buf, size, offset, section_addr);
		if (!table) {
			offset += ctx->pointer_size;
			continue;
		}
		jni_store_table (ctx, table);
		offset += r_list_length (table->methods) * record_size;
		jni_table_free (table);
	}
	free (buf);
}

static int jni_scan(RAnal *anal) {
	if (!anal->iob.read_at || !anal->iob.get_region_at
			|| !anal->binb.bin || !anal->binb.bin->cur
			|| !anal->binb.bin->cur->bo || !anal->binb.get_sections_vec) {
		return 0;
	}
	const int pointer_size = anal->config->bits / 8;
	if (pointer_size != 4 && pointer_size != 8) {
		return 0;
	}
	Sdb *db = sdb_ns (anal->sdb, "jni", 1);
	sdb_reset (db);
	JniScanContext ctx = {
		.anal = anal,
		.bo = anal->binb.bin->cur->bo,
		.db = db,
		.pointer_size = pointer_size,
		.big_endian = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config),
	};
	RVecRBinSection *sections = anal->binb.get_sections_vec (anal->binb.bin);
	RBinSection *section;
	R_VEC_FOREACH (sections, section) {
		jni_scan_section (&ctx, section);
	}
	sdb_num_set (db, "tables", ctx.tables_count, 0);
	return ctx.tables_count;
}

static bool jni_pre_analysis(RAnal *anal) {
	return jni_scan (anal) > 0;
}

static int jni_eligible(RAnal *anal) {
	if (!anal || !anal->binb.bin || !anal->binb.bin->cur
			|| !anal->binb.bin->cur->bo) {
		return -1;
	}
	return R_VPACK_HAS (anal->binb.bin->cur->bo->langs, R_BIN_LANG_JNI)? 0: -1;
}

RAnalPlugin r_anal_plugin_jni = {
	.meta = {
		.name = "jni",
		.desc = "JNI native method table discovery",
		.author = "pancake",
		.license = "LGPL3",
	},
	.eligible = jni_eligible,
	.pre_analysis = jni_pre_analysis,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_jni,
	.version = R2_VERSION,
	.abiversion = R2_ABIVERSION
};
#endif
