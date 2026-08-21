/* radare - LGPL - Copyright 2026 - pancake */

#include <r_anal.h>

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
	RBinJavaMember *member;
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

static void jni_method_free(void *ptr) {
	JniMethod *method = ptr;
	if (method) {
		free (method->name);
		free (method->descriptor);
		r_bin_java_member_free (method->member);
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
	if (!ctx->anal->iob.read_at (ctx->anal->iob.io, addr, (ut8 *)str, available)) {
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
	RBinJavaMember *member = r_bin_java_member_parse (NULL, name, descriptor,
		R_BIN_JAVA_MEMBER_METHOD, 0);
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

static JniTable *jni_parse_table(JniScanContext *ctx, const ut8 *buf, size_t size, size_t offset, ut64 section_addr) {
	const size_t record_size = ctx->pointer_size * 3;
	JniTable *table = R_NEW (JniTable);
	table->addr = section_addr + offset;
	table->methods = r_list_newf (jni_method_free);
	while (offset <= size - record_size) {
		JniMethod *method = jni_parse_method (ctx, buf + offset,
			section_addr + offset);
		if (!method) {
			break;
		}
		r_list_append (table->methods, method);
		offset += record_size;
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
	if (!ctx->anal->iob.read_at (ctx->anal->iob.io, section_addr, buf, (int)size)) {
		free (buf);
		return;
	}
	size_t offset = (ctx->pointer_size - (section_addr % ctx->pointer_size))
		% ctx->pointer_size;
	while (offset <= size - min_size) {
		JniTable *table = jni_parse_table (ctx, buf, size, offset, section_addr);
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
