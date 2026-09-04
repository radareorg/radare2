#include <r_anal.h>
#include <r_anal_priv.h>
#include <r_bin.h>
#include "minunit.h"

#define MODE 2

// Global test context to prevent leaks on early returns
static RBin *bin = NULL;
static RIO *io = NULL;
static RAnal *anal = NULL;
static RFlag *flags = NULL;

static bool setup(void) {
	bin = r_bin_new ();
	io = r_io_new ();
	anal = r_anal_new ();
	flags = r_flag_new ();
	if (!bin || !io || !anal || !flags) {
		r_bin_free (bin);
		r_io_free (io);
		r_anal_free (anal);
		r_flag_free (flags);
		return false;
	}
	anal->binb.demangle = r_bin_demangle;

	r_io_bind (io, &bin->iob);
	return true;
}

static bool teardown(void) {
	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	r_flag_free (flags);
	anal = NULL;
	bin = NULL;
	io = NULL;
	flags = NULL;
	return true;
}

static RBinDwarfAttrValue *test_find_attr(RBinDwarfDie *die, ut64 attr_name) {
	if (!die || !die->attr_values) {
		return NULL;
	}
	RBinDwarfAttrValue *value;
	R_VEC_FOREACH (die->attr_values, value) {
		if (value->attr_name == attr_name) {
			return value;
		}
	}
	return NULL;
}

static RBinDwarfDie *test_find_named_die(RBinDwarfCompUnit *unit, ut64 tag, const char *name) {
	if (!unit || !unit->dies) {
		return NULL;
	}
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		if (die->tag != tag) {
			continue;
		}
		RBinDwarfAttrValue *value = test_find_attr (die, DW_AT_name);
		if (value && value->kind == DW_AT_KIND_STRING
			&& value->string.content && !strcmp (value->string.content, name)) {
			return die;
		}
	}
	return NULL;
}

static RBinDwarfDie *test_find_die_at(RBinDwarfCompUnit *unit, ut64 offset) {
	if (!unit || !unit->dies) {
		return NULL;
	}
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		if (die->offset == offset) {
			return die;
		}
	}
	return NULL;
}

static RBinDwarfDie *test_find_subtree_terminator(RBinDwarfCompUnit *unit, RBinDwarfDie *parent) {
	if (!unit || !unit->dies || !parent || !parent->has_children) {
		return NULL;
	}
	bool found = false;
	size_t depth = 1;
	RBinDwarfDie *die;
	R_VEC_FOREACH (unit->dies, die) {
		if (!found) {
			found = die == parent;
			continue;
		}
		if (die->has_children) {
			depth++;
		}
		if (!die->abbrev_code && --depth == 0) {
			return die;
		}
	}
	return NULL;
}

static char *test_function_type_link_at(Sdb *types, ut64 addr) {
	const char *link = sdb_const_getf (types, NULL, "fcnlink.%08" PFMT64x, addr);
	return link? strdup (link): NULL;
}

static bool test_set_function_type_link(RAnal *anal, const char *type_name, ut64 addr) {
	if (!anal->sdb_types || R_STR_ISEMPTY (type_name)) {
		return false;
	}
	if (r_type_func_exist (anal->sdb_types, type_name)) {
		return r_anal_function_type_link_set (anal, type_name, addr);
	}
	return r_anal_types_set_link (anal, type_name, addr)
		|| r_anal_types_set_link_offset (anal, type_name, addr);
}

static RAnalDwarfFramePointerProof *test_current_frame_pointer_proof(RAnal *anal, ut64 addr) {
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	RAnalDwarfFramePointerProof *proof = priv->dwarf_frame_pointer_proofs
		? ht_up_find (priv->dwarf_frame_pointer_proofs, addr, NULL): NULL;
	RAnalDwarfFunctionLinkAuthority *authority = priv->dwarf_function_link_authority
		? ht_up_find (priv->dwarf_function_link_authority, addr, NULL): NULL;
	const char *linked = sdb_const_getf (
		anal->sdb_types, NULL, "fcnlink.%08" PFMT64x, addr);
	if (!proof || !authority || !linked || !anal->config || !anal->reg
		|| proof->generation != priv->dwarf_function_link_generation
		|| authority->generation != priv->dwarf_function_link_generation
		|| authority->state != R_ANAL_DWARF_FUNCTION_LINK_OWNED
		|| strcmp (proof->type_name, authority->type_name)
		|| strcmp (proof->type_name, linked)
		|| strcmp (proof->arch, anal->config->arch)
		|| proof->bits != anal->config->bits) {
		return NULL;
	}
	RRegItem *reg = r_reg_get (anal->reg, proof->reg_name, -1);
	const bool current = reg && reg->offset >= 0 && !(reg->offset % 8)
		&& reg->size > 0 && !(reg->size % 8)
		&& (ut64)(reg->offset / 8) == proof->offset
		&& reg->size / 8 == proof->size
		&& reg->size == proof->bits;
	r_unref (reg);
	return current? proof: NULL;
}

static bool test_dwarf5_exact_stack_homes(const RAnalFunctionSnapshot *snapshot) {
	const RAnalFunctionInterfaceSnapshot *interface = &snapshot->function_interface;
	if (interface->num_parameters != 2 || !interface->stack_slot_roles_complete
		|| !interface->complete
		|| !(snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES)
		|| !(snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE)) {
		return false;
	}
	const char *expected[] = { "rdi", "rsi" };
	bool seen[] = { false, false };
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (snapshot->context.fcn_slots, iter, slot) {
		if (slot->role != R_ANAL_FCN_SLOT_HOME || slot->arg_index < 0
			|| slot->arg_index >= 2) {
			continue;
		}
		const RAnalSnapshotParameter *parameter =
			&interface->parameters[slot->arg_index];
		if (!slot->home_reg || strcmp (slot->home_reg, expected[slot->arg_index])
			|| strcmp (slot->home_reg, r_str_get (parameter->storage.name))
			|| slot->home_reg_offset != parameter->storage.offset
			|| slot->home_reg_size != parameter->storage.size) {
			return false;
		}
		seen[slot->arg_index] = true;
	}
	return seen[0] && seen[1];
}

static bool test_dwarf5_inexact_stack_homes(const RAnalFunctionSnapshot *snapshot) {
	const RAnalFunctionInterfaceSnapshot *interface = &snapshot->function_interface;
	if (interface->stack_slot_roles_complete || interface->complete
		|| (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES)
		|| (snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE)) {
		return false;
	}
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (snapshot->context.fcn_slots, iter, slot) {
		if (slot->role == R_ANAL_FCN_SLOT_ARG) {
			return true;
		}
	}
	return false;
}

// The snapshot outlives the capture now, so a probe is a take, a read and a
// free rather than a callback run while the analysis is still locked.
static bool snapshot_probe(RAnal *a, ut64 addr, bool (*predicate)(const RAnalFunctionSnapshot *)) {
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_take (a, addr, NULL);
	if (!snapshot) {
		return false;
	}
	const bool result = predicate (snapshot);
	r_anal_function_snapshot_free (snapshot);
	return result;
}

#define check_kv(k, v) \
	do { \
		value = sdb_const_get (sdb, k, NULL); \
		mu_assert_nullable_streq (value, v, "Wrong key - value pair"); \
	} while (0)

static bool test_parse_dwarf_types(void) {
	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/pe/vista-glass.exe", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 32;
	mu_assert ("pe/vista-glass.exe binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}

	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 4);
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	const char *value = NULL;
	Sdb *sdb = anal->sdb_types;
	check_kv ("_cairo_status", "enum");
	check_kv ("enum._cairo_status.0x0", "CAIRO_STATUS_SUCCESS");
	check_kv ("enum._cairo_status.CAIRO_STATUS_SUCCESS", "0x0");
	check_kv ("enum._cairo_status.0x9", "CAIRO_STATUS_INVALID_PATH_DATA");
	check_kv ("enum._cairo_status.CAIRO_STATUS_INVALID_PATH_DATA", "0x9");
	check_kv ("enum._cairo_status.0x1f", "CAIRO_STATUS_INVALID_WEIGHT");
	check_kv ("enum._cairo_status.CAIRO_STATUS_INVALID_WEIGHT", "0x1f");
	check_kv ("enum._cairo_status.0x20", NULL);
	check_kv ("enum._cairo_status", "CAIRO_STATUS_SUCCESS,CAIRO_STATUS_NO_MEMORY" 
	",CAIRO_STATUS_INVALID_RESTORE,CAIRO_STATUS_INVALID_POP_GROUP,CAIRO_STATUS_NO_CURRENT_POINT"
	",CAIRO_STATUS_INVALID_MATRIX,CAIRO_STATUS_INVALID_STATUS,CAIRO_STATUS_NULL_POINTER,"
	"CAIRO_STATUS_INVALID_STRING,CAIRO_STATUS_INVALID_PATH_DATA,CAIRO_STATUS_READ_ERROR,"
	"CAIRO_STATUS_WRITE_ERROR,CAIRO_STATUS_SURFACE_FINISHED,CAIRO_STATUS_SURFACE_TYPE_MISMATCH,"
	"CAIRO_STATUS_PATTERN_TYPE_MISMATCH,CAIRO_STATUS_INVALID_CONTENT,CAIRO_STATUS_INVALID_FORMAT,"
	"CAIRO_STATUS_INVALID_VISUAL,CAIRO_STATUS_FILE_NOT_FOUND,CAIRO_STATUS_INVALID_DASH,"
	"CAIRO_STATUS_INVALID_DSC_COMMENT,CAIRO_STATUS_INVALID_INDEX,CAIRO_STATUS_CLIP_NOT_REPRESENTABLE,"
	"CAIRO_STATUS_TEMP_FILE_ERROR,CAIRO_STATUS_INVALID_STRIDE,"
	"CAIRO_STATUS_FONT_TYPE_MISMATCH,CAIRO_STATUS_USER_FONT_IMMUTABLE,CAIRO_STATUS_USER_FONT_ERROR,"
	"CAIRO_STATUS_NEGATIVE_COUNT,CAIRO_STATUS_INVALID_CLUSTERS,"
	"CAIRO_STATUS_INVALID_SLANT,CAIRO_STATUS_INVALID_WEIGHT");

	check_kv ("_MARGINS", "struct");
	// TODO evaluate member_location operations in DWARF to get offset and test it
	check_kv ("struct._MARGINS", "cxLeftWidth,cxRightWidth,cyTopHeight,cyBottomHeight");

	check_kv ("unaligned", "union");
	check_kv ("union.unaligned", "ptr,u2,u4,u8,s2,s4,s8");
	check_kv ("union.unaligned.u2", "short unsigned int,0,0");
	check_kv ("union.unaligned.s8", "long long int,0,0");
	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_loc (loc_table);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

static bool test_dwarf_function_parsing_cpp(void) {
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert ("elf/dwarf4_many_comp_units.elf binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	const char *value = NULL;
	check_kv ("Mammal", "fcn");
	check_kv ("fcn.Mammal.addr", "0x401300");
	check_kv ("fcn.Mammal.sig", "void Mammal(Mammal * this);");
	check_kv ("fcn.Dog::walk__.addr", "0x401380");
	check_kv ("fcn.Dog::walk__.sig", "int Dog::walk()(Dog * this);");
	check_kv ("fcn.Dog::walk__.name", "Dog::walk()");
	check_kv ("fcn.Mammal::walk__.args", "this");
	check_kv ("fcn.Mammal::walk__.arg.0", "this,b,-8,Mammal *");
	check_kv ("fcn.Mammal::walk__.vars", NULL);

	check_kv ("main", "fcn");
	check_kv ("fcn.main.addr", "0x401160");
	check_kv ("fcn.main.sig", "int main();");
	check_kv ("fcn.main.vars", "b,m,output");
	check_kv ("fcn.main.var.output", "b,-40,int");
	const char *typed_main = sdb_const_get (sdb, "fcn.main.typed_name", NULL);
	mu_assert_notnull ("Missing typed name for main", typed_main);
	sdb = anal->sdb_types;
	char *typed_main_kind = strdup (typed_main);
	check_kv (typed_main_kind, "func");
	free (typed_main_kind);
	char *typed_main_ret = r_str_newf ("func.%s.ret", typed_main);
	check_kv (typed_main_ret, "int");
	free (typed_main_ret);

	Sdb *dwarf_sdb2 = sdb_ns (anal->sdb, "dwarf", 0);
	const char *typed_walk = sdb_const_get (dwarf_sdb2, "fcn.Dog::walk__.typed_name", NULL);
	mu_assert_notnull ("Missing typed name for Dog::walk()", typed_walk);
	char *typed_walk_kind = strdup (typed_walk);
	check_kv (typed_walk_kind, "func");
	free (typed_walk_kind);
	char *typed_walk_ret = r_str_newf ("func.%s.ret", typed_walk);
	check_kv (typed_walk_ret, "int");
	free (typed_walk_ret);
	char *typed_walk_args = r_str_newf ("func.%s.args", typed_walk);
	check_kv (typed_walk_args, "1");
	free (typed_walk_args);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	mu_end;
}

static bool test_dwarf_function_parsing_go(void) {
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/elf/dwarf_go_tree", &opt);
	mu_assert ("bins/elf/dwarf_go_tree", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	if (!sdb) {
		r_bin_dwarf_free_debug_info (info);
		RVecDwarfAbbrevDecl_free (abbrevs);
		r_bin_dwarf_free_loc (loc_table);
		mu_assert ("No dwarf function information in db", false);
		return MU_ERR;
	}
	const char *value = NULL;

	check_kv ("main_main", "fcn");
	check_kv ("fcn.main_main.name", "main.main");
	check_kv ("fcn.main_main.addr", "0x491980");

	check_kv ("main_tree_iterInorder", "fcn");
	check_kv ("fcn.main_tree_iterInorder.name", "main.tree.iterInorder");
	check_kv ("fcn.main_tree_iterInorder.addr", "0x491d90");
	check_kv ("fcn.main_tree_iterInorder.sig", "void main.tree.iterInorder(main.tree t,func(int) visit);");
	char *cache_line_type = r_type_link_at (anal->sdb_types, 0x5500e0);
	mu_assert_streq (cache_line_type, "uintptr",
		"exact fixed-address DWARF data object type is linked by address");
	free (cache_line_type);
	char *static_bytes_type = r_type_link_at (anal->sdb_types, 0x553da0);
	mu_assert_streq (static_bytes_type, "uint8[256]",
		"exact composite DWARF data object type is linked by address");
	free (static_bytes_type);

	/* We do not parse variable information from .debug_frame that is this Go binary using, so
	don't check variable information and add it in the future */

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	mu_end;
}

static bool test_dwarf_function_parsing_rust(void) {
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;

	RBinFileOptions opt;
	r_bin_file_options_init (&opt, -1, UT64_MAX, 0, 0);
	bool res = r_bin_open (bin, "bins/elf/dwarf_rust_bubble", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	free (anal->config->cpu);
	mu_assert ("bins/elf/dwarf_rust_bubble", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	if (!abbrevs) {
		mu_assert ("Couldn't parse Abbreviations", false);
		return MU_ERR;
	}
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	if (!info) {
		RVecDwarfAbbrevDecl_free (abbrevs);
		mu_assert ("Couldn't parse debug_info section", false);
		return MU_ERR;
	}
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bf, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	const char *value = NULL;

	check_kv ("fcn.main.addr", "0x5750");
	check_kv ("fcn.main.name", "main");
	check_kv ("fcn.main.var.numbers", "s,128,i32[10]");
	check_kv ("fcn.main.var.strings", "s,312,&str[5]");
	// check_kv ("fcn.main.vars", "numbers,arg0,arg0,strings,arg0,arg0"); Fix these collision by unique renaming in future
	check_kv ("fcn.lang_start_internal.sig", "isize lang_start_internal(&Fn<()> main,isize argc,u8 ** argv);");

	check_kv ("bubble_sort__str_", "fcn");
	check_kv ("bubble_sort_i32_", "fcn");
	check_kv ("fcn.bubble_sort_i32_.args", "values");
	check_kv ("fcn.bubble_sort_i32_.vars", "n,swapped,iter,__next,val,i");
	check_kv ("fcn.bubble_sort_i32_.var.iter", "s,112,Range<usize>");
	check_kv ("fcn.bubble_sort_i32_.var.i", "s,176,usize");
	check_kv ("fcn.bubble_sort_i32_.name", "bubble_sort<i32>");
	check_kv ("fcn.bubble_sort_i32_.addr", "0x5270");
	char *into_iter = r_str_sanitize_sdb_key ("into_iter<core::ops::range::Range<usize>>");
	char *into_iter_addr = r_str_newf ("fcn.%s.addr", into_iter);
	check_kv (into_iter_addr, "0x6710");
	free (into_iter_addr);
	free (into_iter);
	const char *typed_bubble = sdb_const_get (sdb, "fcn.bubble_sort_i32_.typed_name", NULL);
	mu_assert_notnull ("Missing typed name for bubble_sort_i32_", typed_bubble);
	sdb = anal->sdb_types;
	char *typed_bubble_kind = strdup (typed_bubble);
	check_kv (typed_bubble_kind, "func");
	free (typed_bubble_kind);
	char *typed_bubble_ret = r_str_newf ("func.%s.ret", typed_bubble);
	check_kv (typed_bubble_ret, "void");
	free (typed_bubble_ret);
	char *typed_bubble_args = r_str_newf ("func.%s.args", typed_bubble);
	check_kv (typed_bubble_args, "1");
	free (typed_bubble_args);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	mu_end;
}

static bool test_dwarf5_function_type_links(void) {
	mu_assert_true (r_anal_use (anal, "x86"), "Couldn't load x86 analysis profile");
	mu_assert_true (r_anal_set_bits (anal, 64), "Couldn't select x86-64 analysis");
	mu_assert_true (r_anal_cc_set (anal, "rax amd64(rdi,rsi,rdx,rcx,r8,r9)"),
		"Couldn't seed the fixture calling convention");
	sdb_reset (anal->sdb_types);

	RBinFileOptions opt = {
		.baseaddr = 0x400000,
	};
	bool res = r_bin_open (bin, "bins/elf/dwarf5_line_cl", &opt);
	mu_assert ("dwarf5_line_cl binary could not be opened", res);
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	mu_assert_true (bf->bo->baddr_shift > 0, "DWARF5 fixture was not relocated");
	ut64 shift = (ut64)bf->bo->baddr_shift;
	ut64 foo_addr = 0x1140 + shift;
	ut64 main_addr = 0x11c0 + shift;

	sdb_set (anal->sdb_types, "reserved_type", "func", 0);
	sdb_set (anal->sdb_types, "func.reserved_type.ret", "void", 0);
	sdb_set (anal->sdb_types, "func.reserved_type.args", "0", 0);
	mu_assert_true (sdb_setf (anal->sdb_types, "reserved_type", 0,
		"fcnlink.%08" PFMT64x, foo_addr), "preexisting conflicting function link");

	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse DWARF5 abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_notnull (info, "Couldn't parse DWARF5 indexed info");
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = NULL,
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *dwarf_sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (dwarf_sdb, "No dwarf function information in db");
	const char *typed_main = sdb_const_get (dwarf_sdb, "fcn.main.typed_name", NULL);
	mu_assert_notnull (typed_main, "Missing typed name for DWARF5 main");
	const char *first_record = sdb_const_get (dwarf_sdb, "fcn.main.arg.0", NULL);
	const char *second_record = sdb_const_get (dwarf_sdb, "fcn.main.arg.1", NULL);
	mu_assert_true (first_record && r_str_startswith (first_record, "dwarf-stack-home-v1,0,b,"),
		"First formal stores one exact versioned home record");
	mu_assert_true (second_record && r_str_startswith (second_record, "dwarf-stack-home-v1,1,b,"),
		"Second formal stores one exact versioned home record");
	mu_assert_null (sdb_const_get (dwarf_sdb, "fcn.main.arg.0.exact", NULL),
		"Exact authority has no independent side key");
	mu_assert_null (sdb_const_get (dwarf_sdb, "fcn.main.arg.0.ordinal", NULL),
		"Formal ordinal has no independent side key");
	char *saved_first_record = strdup (first_record);
	mu_assert_notnull (saved_first_record, "Copy exact formal record for refusal tests");
	char *main_link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_notnull (main_link, "Missing exact link for complete DWARF5 main prototype");
	mu_assert_streq (main_link, typed_main, "complete prototype linked at relocated low_pc");
	free (main_link);
	mu_assert_null (r_type_link_at (anal->sdb_types, main_addr),
		"Function signature must not occupy the data type link namespace");
	char *foo_link = test_function_type_link_at (anal->sdb_types, foo_addr);
	mu_assert_streq (foo_link, "reserved_type", "conflicting address link is preserved");
	free (foo_link);

	sdb_set (anal->sdb_types, "wrong_name", "func", 0);
	sdb_set (anal->sdb_types, "func.wrong_name.ret", "uint8_t", 0);
	sdb_set (anal->sdb_types, "func.wrong_name.args", "0", 0);
	RAnalFunction *fcn = r_anal_create_function (anal, "wrong_name", main_addr, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "Couldn't create analysis function for linked signature lookup");
	fcn->callconv = r_str_constpool_get (&anal->constpool, "amd64");
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "Couldn't resolve address-linked function signature");
	mu_assert_streq (signature->ret_type, "int", "address-linked signature wins over function name");
	mu_assert_eq (r_list_length (signature->params), 2, "DWARF5 main parameter count");
	r_anal_function_signature_free (signature);

	RAnalBlock *block = r_anal_create_block (anal, main_addr, 1);
	mu_assert_notnull (block, "Couldn't create DWARF5 main snapshot block");
	r_anal_function_add_block (fcn, block);
	r_unref (block);
	io->va = true;
	r_io_bind (io, &anal->iob);
	mu_assert_notnull (r_io_open_at (io, "malloc://1", R_PERM_R, 0, main_addr),
		"Couldn't map exact snapshot bytes at DWARF5 main");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	RAnalVar *first = r_anal_function_get_var_byname (fcn, "a");
	RAnalVar *second = r_anal_function_get_var_byname (fcn, "v");
	mu_assert_notnull (first, "Couldn't integrate first DWARF5 formal");
	mu_assert_notnull (second, "Couldn't integrate second DWARF5 formal");
	mu_assert_eq (first->argnum, 0, "First exact formal keeps its DWARF ordinal");
	mu_assert_eq (second->argnum, 1, "Second exact formal keeps its DWARF ordinal");
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_exact_stack_homes),
		"Exact DWARF formals become complete ABI stack homes");
	const st64 saved_bp_off = fcn->bp_off;
	const int saved_maxstack = fcn->maxstack;
	fcn->bp_off++;
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Changed BP basis invalidates exact DWARF stack homes");
	fcn->bp_off = saved_bp_off;
	fcn->maxstack++;
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Changed maximum-stack basis invalidates exact DWARF stack homes");
	fcn->maxstack = saved_maxstack;
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_exact_stack_homes),
		"Restored exact frame state restores source-offset validation");

	mu_assert_true (r_anal_function_rename (fcn, "renamed_dwarf_entry"),
		"Couldn't rename DWARF-backed function");
	mu_assert_true (r_anal_var_rename (anal, first, "renamed_first"),
		"Couldn't rename first DWARF-backed formal");
	mu_assert_true (r_anal_var_rename (anal, second, "renamed_second"),
		"Couldn't rename second DWARF-backed formal");
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_exact_stack_homes),
		"Names do not supply stack-home authority");

	mu_assert_true (sdb_set (dwarf_sdb, "fcn.main.arg.0",
		"dwarf-stack-home-v1,0,b,-8,YQ==,aW50,extra", 0),
		"Install malformed marked formal record");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Malformed marked records revoke prior exact formal proof");
	mu_assert_true (sdb_set (dwarf_sdb, "fcn.main.arg.0",
		"dwarf-stack-home-v1,0,b,-16,YQ==,aW50", 0),
		"Install canonical forged marked formal record");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Canonical marked records without parser provenance cannot mint homes");
	mu_assert_true (sdb_set (dwarf_sdb, "fcn.main.arg.0", saved_first_record, 0),
		"Restore exact formal after malformed-record refusal");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	first = r_anal_function_get_var_byname (fcn, "a");
	second = r_anal_function_get_var_byname (fcn, "v");
	mu_assert_notnull (first, "Couldn't restore first exact formal");
	mu_assert_notnull (second, "Couldn't restore second exact formal");
	r_anal_var_set_type (anal, first, first->type);
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Absent private formal proof refuses exact stack-slot roles");
	char *legacy_record = r_str_newf ("%s,%c,%" PFMT64d ",%s",
		first->name, first->kind, (st64)first->delta + fcn->bp_off, first->type);
	mu_assert_notnull (legacy_record, "Build advisory legacy formal record");
	mu_assert_true (sdb_set (dwarf_sdb, "fcn.main.arg.0", legacy_record, 0),
		"Install advisory legacy formal record");
	free (legacy_record);
	mu_assert_true (sdb_num_set (dwarf_sdb, "fcn.main.arg.0.exact", 1, 0),
		"Install forged legacy exact side key");
	mu_assert_true (sdb_num_set (dwarf_sdb, "fcn.main.arg.0.ordinal", 0, 0),
		"Install forged legacy ordinal side key");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Legacy records and forged side keys cannot mint exact homes");
	mu_assert_true (sdb_set (dwarf_sdb, "fcn.main.arg.0", saved_first_record, 0),
		"Restore exact formal record");
	sdb_unset (dwarf_sdb, "fcn.main.arg.0.exact", 0);
	sdb_unset (dwarf_sdb, "fcn.main.arg.0.ordinal", 0);
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	first = r_anal_function_get_var_byname (fcn, "a");
	second = r_anal_function_get_var_byname (fcn, "v");
	mu_assert_notnull (first, "Couldn't reintegrate first exact formal");
	mu_assert_notnull (second, "Couldn't reintegrate second exact formal");
	first->argnum = 2;
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Out-of-range formal ordinal refuses exact stack-slot roles");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	first = r_anal_function_get_var_byname (fcn, "a");
	mu_assert_notnull (first, "Couldn't restore exact formal before type mutation");
	r_anal_var_set_type (anal, first, "char *");
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_inexact_stack_homes),
		"Mismatched formal type refuses exact stack-slot roles");

	const char first_kind = first->kind;
	const int first_delta = first->delta;
	const char second_kind = second->kind;
	const int second_delta = second->delta;
	mu_assert_true (r_anal_var_delete (anal, first),
		"Remove first source home before name-collision regression");
	mu_assert_true (r_anal_var_delete (anal, second),
		"Remove second source home before name-collision regression");
	RRegItem *rdi = r_reg_get (anal->reg, "rdi", -1);
	RRegItem *rsi = r_reg_get (anal->reg, "rsi", -1);
	mu_assert_notnull (rdi, "Resolve first ABI register");
	mu_assert_notnull (rsi, "Resolve second ABI register");
	mu_assert_notnull (r_anal_function_set_var (fcn, rdi->index,
		R_ANAL_VAR_KIND_REG, "int", 8, true, "a"),
		"Create first register formal with the source name");
	mu_assert_notnull (r_anal_function_set_var (fcn, rsi->index,
		R_ANAL_VAR_KIND_REG, "char **", 8, true, "v"),
		"Create second register formal with the source name");
	r_unref (rdi);
	r_unref (rsi);
	RAnalVar *first_home = r_anal_function_set_var (fcn, first_delta,
		first_kind, "uint64_t", 8, false, "var_first_home");
	RAnalVar *second_home = r_anal_function_set_var (fcn, second_delta,
		second_kind, "uint64_t", 8, false, "var_second_home");
	mu_assert_notnull (first_home, "Create first heuristic stack resource");
	mu_assert_notnull (second_home, "Create second heuristic stack resource");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_streq (first_home->type, "int",
		"Exact first formal replaces the heuristic home type");
	mu_assert_streq (second_home->type, "char const **",
		"Exact second formal replaces the heuristic home type");
	mu_assert_true (first_home->isarg && second_home->isarg,
		"Exact formal records promote existing resources to argument homes");
	mu_assert_true (snapshot_probe (
		anal, main_addr, test_dwarf5_exact_stack_homes),
		"Exact stack homes survive source-name collisions with ABI register formals");
	free (saved_first_record);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

static bool test_dwarf5_named_typedef_to_anonymous_aggregate(void) {
	mu_assert_true (r_anal_use (anal, "x86"), "Couldn't load x86 analysis profile");
	mu_assert_true (r_anal_set_bits (anal, 64), "Couldn't select x86-64 analysis");
	mu_assert_true (r_anal_cc_set (anal, "rax amd64(rdi,rsi,rdx,rcx,r8,r9)"),
		"Couldn't seed the fixture calling convention");
	sdb_reset (anal->sdb_types);

	RBinFileOptions opt = {
		.baseaddr = 0x400000,
	};
	mu_assert_true (r_bin_open (bin, "bins/elf/dwarf5_line_cl", &opt),
		"dwarf5_line_cl binary could not be opened");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse DWARF5 abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_notnull (info, "Couldn't parse DWARF5 indexed info");
	mu_assert_eq (RVecDwarfCompUnit_length (info->comp_units), 1,
		"Expected one DWARF5 compilation unit");
	RBinDwarfCompUnit *unit = RVecDwarfCompUnit_at (info->comp_units, 0);
	RBinDwarfDie *foo_pointer = test_find_die_at (unit, 0xc9);
	RBinDwarfDie *typedef_die = test_find_die_at (unit, 0xd3);
	RBinDwarfDie *anonymous_struct = test_find_die_at (unit, 0xd8);
	mu_assert_notnull (foo_pointer, "Missing Foo pointer DIE");
	mu_assert_notnull (typedef_die, "Missing typedef candidate DIE");
	mu_assert_notnull (anonymous_struct, "Missing anonymous-struct candidate DIE");
	RBinDwarfAttrValue *foo_type = test_find_attr (foo_pointer, DW_AT_type);
	RBinDwarfAttrValue *struct_name = test_find_attr (anonymous_struct, DW_AT_name);
	mu_assert_notnull (foo_type, "Missing Foo pointee type");
	mu_assert_notnull (struct_name, "Missing aggregate name to anonymize");
	foo_type->reference = typedef_die->offset;
	typedef_die->tag = DW_TAG_typedef;
	RBinDwarfAttrValue typedef_name = {
		.attr_name = DW_AT_name,
		.kind = DW_AT_KIND_STRING,
		.string.content = "DemoStruct",
	};
	const size_t old_attr_count = RVecDwarfAttrValue_length (
		typedef_die->attr_values);
	RVecDwarfAttrValue_push_back (typedef_die->attr_values, &typedef_name);
	mu_assert_eq (RVecDwarfAttrValue_length (typedef_die->attr_values),
		old_attr_count + 1, "Couldn't name synthetic typedef");
	struct_name->attr_name = DW_AT_linkage_name;

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = NULL,
	};
	r_anal_dwarf_process_info (anal, &ctx);
	const ut64 new_foo_addr = 0x1170 + (ut64)bf->bo->baddr_shift;
	char *link = test_function_type_link_at (anal->sdb_types, new_foo_addr);
	mu_assert_notnull (link,
		"Named typedef to anonymous aggregate keeps exact function authority");
	const char *ret_type = r_type_func_ret (anal->sdb_types, link);
	mu_assert_streq (ret_type, "DemoStruct *",
		"Exact linked prototype retains the canonical typedef name");
	free (link);

	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

static bool test_dwarf3_abstract_origin_prototype_join(void) {
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;
	sdb_reset (anal->sdb_types);
	RBinFileOptions opt = { 0 };
	mu_assert_true (r_bin_open (bin, "bins/elf/dwarf3_cpp.elf", &opt),
		"dwarf3_cpp.elf binary could not be opened");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current dwarf3_cpp.elf bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse DWARF3 abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_notnull (info, "Couldn't parse DWARF3 debug info");
	mu_assert_eq (RVecDwarfCompUnit_length (info->comp_units), 1,
		"Expected one DWARF3 compilation unit");
	RBinDwarfCompUnit *unit = RVecDwarfCompUnit_at (info->comp_units, 0);
	RBinDwarfDie *concrete = test_find_die_at (unit, 0x39c);
	RBinDwarfDie *concrete_formal = test_find_die_at (unit, 0x3c0);
	RBinDwarfDie *origin_decl = test_find_die_at (unit, 0x6d);
	RBinDwarfDie *foreign_formal = test_find_die_at (unit, 0x314);
	RBinDwarfDie *missing_concrete = test_find_die_at (unit, 0x329);
	RBinDwarfDie *missing_origin_decl = test_find_die_at (unit, 0x8a);
	RBinDwarfDie *dog_origin_decl = test_find_die_at (unit, 0x14c);
	mu_assert_notnull (concrete, "Missing concrete constructor DIE");
	mu_assert_notnull (concrete_formal, "Missing concrete constructor formal");
	mu_assert_notnull (origin_decl, "Missing constructor origin declaration");
	mu_assert_notnull (foreign_formal, "Missing foreign abstract formal");
	mu_assert_notnull (missing_concrete, "Missing concrete destructor DIE");
	mu_assert_notnull (missing_origin_decl, "Missing destructor origin declaration");
	mu_assert_notnull (dog_origin_decl, "Missing Dog constructor origin declaration");
	RBinDwarfAttrValue *origin = test_find_attr (concrete, DW_AT_abstract_origin);
	RBinDwarfAttrValue *formal_origin = test_find_attr (
		concrete_formal, DW_AT_abstract_origin);
	RBinDwarfAttrValue *high_pc = test_find_attr (concrete, DW_AT_high_pc);
	RBinDwarfAttrValue *concrete_linkage = test_find_attr (
		concrete, DW_AT_MIPS_linkage_name);
	RBinDwarfAttrValue *abstract_linkage = test_find_attr (
		origin_decl, DW_AT_MIPS_linkage_name);
	RBinDwarfAttrValue *origin_mutable = test_find_attr (
		origin_decl, DW_AT_decl_line);
	RBinDwarfAttrValue *prototyped = test_find_attr (
		origin_decl, DW_AT_decl_column);
	RBinDwarfAttrValue *missing_prototyped = test_find_attr (
		missing_origin_decl, DW_AT_decl_column);
	RBinDwarfAttrValue *dog_prototyped = test_find_attr (
		dog_origin_decl, DW_AT_decl_column);
	mu_assert_notnull (origin, "Missing concrete abstract origin");
	mu_assert_notnull (formal_origin, "Missing formal abstract origin");
	mu_assert_notnull (high_pc, "Missing concrete high_pc");
	mu_assert_notnull (concrete_linkage, "Missing concrete linkage identity");
	mu_assert_notnull (abstract_linkage, "Missing abstract linkage identity");
	mu_assert_streq (concrete_linkage->string.content, "_ZN4BirdC2Ev",
		"Fixture uses an Itanium base-constructor instance");
	mu_assert_streq (abstract_linkage->string.content, "_ZN4BirdC4Ev",
		"Fixture origin uses an Itanium unified-constructor identity");
	mu_assert_notnull (origin_mutable, "Missing mutable origin declaration attribute");
	mu_assert_notnull (prototyped, "Missing mutable constructor declaration attribute");
	mu_assert_notnull (missing_prototyped,
		"Missing mutable destructor declaration attribute");
	mu_assert_notnull (dog_prototyped,
		"Missing mutable Dog constructor declaration attribute");
	RBinDwarfAttrValue saved_prototyped = *prototyped;
	prototyped->attr_name = DW_AT_prototyped;
	prototyped->attr_form = DW_FORM_flag;
	prototyped->kind = DW_AT_KIND_FLAG;
	prototyped->flag = true;
	RBinDwarfAttrValue saved_dog_prototyped = *dog_prototyped;
	dog_prototyped->attr_name = DW_AT_prototyped;
	dog_prototyped->attr_form = DW_FORM_flag;
	dog_prototyped->kind = DW_AT_KIND_FLAG;
	dog_prototyped->flag = true;
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = NULL,
	};
	const ut64 concrete_addr = 0x130e;
	const ut64 dog_concrete_addr = 0x126e;

	const ut64 saved_origin_ref = origin->reference;
	origin->reference = concrete->offset;
	r_anal_dwarf_process_info (anal, &ctx);
	char *link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link, "Cyclic abstract origin must not create an exact link");
	free (link);
	origin->reference = UT64_MAX;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link, "Unresolved abstract origin must not create an exact link");
	free (link);
	origin->reference = concrete_formal->offset;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link, "Wrong-tag abstract origin must not create an exact link");
	free (link);
	origin->reference = saved_origin_ref;

	const ut64 saved_formal_origin_ref = formal_origin->reference;
	formal_origin->reference = foreign_formal->offset;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link, "Foreign formal origin must not create an exact link");
	free (link);
	formal_origin->reference = saved_formal_origin_ref;

	RBinDwarfAttrValue saved_high_pc = *high_pc;
	high_pc->attr_name = DW_AT_MIPS_linkage_name;
	high_pc->attr_form = DW_FORM_string;
	high_pc->kind = DW_AT_KIND_STRING;
	high_pc->string.content = concrete_linkage->string.content;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Duplicate concrete identities must not create an exact link");
	free (link);
	*high_pc = saved_high_pc;
	const char *saved_concrete_linkage = concrete_linkage->string.content;
	concrete_linkage->string.content = "_ZN3DogC2Ev";
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Unrelated concrete and abstract linkage identities must be refused");
	free (link);
	concrete_linkage->string.content = saved_concrete_linkage;
	high_pc->attr_name = DW_AT_name;
	high_pc->attr_form = DW_FORM_string;
	high_pc->kind = DW_AT_KIND_STRING;
	high_pc->string.content = "ConflictingConcreteName";
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Conflicting concrete and abstract source names must be refused");
	free (link);
	*high_pc = saved_high_pc;

	const ut64 saved_foreign_offset = foreign_formal->offset;
	foreign_formal->offset = origin_decl->offset;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Duplicate CU DIE offsets must refuse exact membership authority");
	free (link);
	foreign_formal->offset = saved_foreign_offset;

	RBinDwarfAttrValue saved_origin_mutable = *origin_mutable;
	origin_mutable->attr_name = DW_AT_high_pc;
	origin_mutable->attr_form = DW_FORM_data4;
	origin_mutable->kind = DW_AT_KIND_CONSTANT;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Address-bearing abstract origins must not create an exact link");
	free (link);
	*origin_mutable = saved_origin_mutable;

	origin_mutable->attr_name = DW_AT_declaration;
	origin_mutable->attr_form = DW_FORM_data1;
	origin_mutable->kind = DW_AT_KIND_CONSTANT;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Malformed abstract declaration flags must not create an exact link");
	free (link);
	*origin_mutable = saved_origin_mutable;

	RBinDwarfDie *concrete_terminator = test_find_subtree_terminator (unit, concrete);
	mu_assert_notnull (concrete_terminator, "Missing concrete subtree terminator");
	const ut64 saved_terminator_abbrev = concrete_terminator->abbrev_code;
	concrete_terminator->abbrev_code = 1;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"A later CU terminator cannot close an unterminated concrete subtree");
	free (link);
	concrete_terminator->abbrev_code = saved_terminator_abbrev;

	const ut64 saved_high_pc_name = high_pc->attr_name;
	high_pc->attr_name = DW_AT_ranges;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link, "Ranges-based concrete authority must be refused");
	free (link);
	high_pc->attr_name = saved_high_pc_name;

	RBinDwarfAttrValue saved_missing_prototyped = *missing_prototyped;
	missing_prototyped->attr_name = DW_AT_prototyped;
	missing_prototyped->attr_form = DW_FORM_flag;
	missing_prototyped->kind = DW_AT_KIND_FLAG;
	missing_prototyped->flag = true;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, 0x134a);
	mu_assert_null (link,
		"Concrete formals missing from the abstract prototype must be refused");
	free (link);
	*missing_prototyped = saved_missing_prototyped;

	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_notnull (link,
		"Exact concrete-to-abstract formal bijection must create an address link");
	char *first_link = strdup (link);
	mu_assert_notnull (first_link, "Copy exact abstract-origin link");
	free (link);
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_streq (link, first_link,
		"Repeated abstract-origin import keeps the exact address link stable");
	free (link);
	mu_assert_true (test_set_function_type_link (
		anal, first_link, concrete_addr),
		"Repeat the exact link through the ordinary mutation path");
	origin->reference = UT64_MAX;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_streq (link, first_link,
		"An identical ordinary write clears parser ownership");
	free (link);
	char link_key[SDB_MAX_KEY];
	snprintf (link_key, sizeof (link_key),
		"fcnlink.%08" PFMT64x, concrete_addr);
	mu_assert_true (sdb_unset (anal->sdb_types, link_key, 0),
		"Remove the ordinary link before restoring parser ownership");
	origin->reference = saved_origin_ref;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_notnull (link, "Restore parser-owned address link");
	free (link);

	origin->reference = UT64_MAX;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"A refused generation revokes its prior parser-owned address link");
	free (link);
	mu_assert_true (sdb_set (anal->sdb_types, "foreign_dwarf_signature", "func", 0),
		"Seed foreign function type");
	mu_assert_true (sdb_setf (anal->sdb_types, "foreign_dwarf_signature", 0,
		"fcnlink.%08" PFMT64x, concrete_addr),
		"Seed foreign address link");
	Sdb *dwarf_sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (dwarf_sdb, "Missing DWARF namespace for forged marker test");
	mu_assert_true (sdb_setf (dwarf_sdb, "foreign_dwarf_signature", 0,
		"exact.fcnlink.%08" PFMT64x, concrete_addr),
		"Forge the retired public ownership marker");
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_streq (link, "foreign_dwarf_signature",
		"A forged public marker cannot delete a foreign address link");
	free (link);
	origin->reference = saved_origin_ref;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, dog_concrete_addr);
	mu_assert_null (link,
		"A conflicting desired link rolls back every certifying sibling link");
	free (link);
	free (first_link);
	*prototyped = saved_prototyped;
	*dog_prototyped = saved_dog_prototyped;
	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

static bool test_dwarf3_exact_frame_pointer_authority(void) {
	mu_assert_true (r_anal_use (anal, "x86"), "Load x86 analysis profile");
	mu_assert_true (r_anal_set_bits (anal, 64), "Select x86-64 analysis");
	sdb_reset (anal->sdb_types);
	RBinFileOptions opt = { 0 };
	mu_assert_true (r_bin_open (bin, "bins/elf/dwarf3_cpp.elf", &opt),
		"dwarf3_cpp.elf binary could not be opened");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current dwarf3_cpp.elf bin file");
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse DWARF3 abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_notnull (info, "Couldn't parse DWARF3 debug info");
	RBinDwarfCompUnit *unit = RVecDwarfCompUnit_at (info->comp_units, 0);
	mu_assert_notnull (unit, "Missing DWARF3 compilation unit");
	RBinDwarfDie *concrete = test_find_die_at (unit, 0x39c);
	RBinDwarfDie *origin_decl = test_find_die_at (unit, 0x6d);
	RBinDwarfDie *dog_concrete = test_find_die_at (unit, 0x48d);
	RBinDwarfDie *dog_origin_decl = test_find_die_at (unit, 0x14c);
	mu_assert_notnull (concrete, "Missing concrete constructor DIE");
	mu_assert_notnull (origin_decl, "Missing abstract constructor declaration");
	mu_assert_notnull (dog_concrete, "Missing second concrete constructor DIE");
	mu_assert_notnull (dog_origin_decl, "Missing second abstract constructor declaration");
	RBinDwarfAttrValue *origin = test_find_attr (concrete, DW_AT_abstract_origin);
	RBinDwarfAttrValue *frame_base = test_find_attr (concrete, DW_AT_frame_base);
	RBinDwarfAttrValue *high_pc = test_find_attr (concrete, DW_AT_high_pc);
	RBinDwarfAttrValue *prototyped = test_find_attr (origin_decl, DW_AT_decl_column);
	RBinDwarfAttrValue *origin_mutable = test_find_attr (origin_decl, DW_AT_decl_line);
	RBinDwarfAttrValue *dog_low_pc = test_find_attr (dog_concrete, DW_AT_low_pc);
	RBinDwarfAttrValue *dog_frame_base = test_find_attr (dog_concrete, DW_AT_frame_base);
	RBinDwarfAttrValue *dog_prototyped = test_find_attr (dog_origin_decl, DW_AT_decl_column);
	mu_assert_notnull (origin, "Missing concrete abstract origin");
	mu_assert_notnull (frame_base, "Missing concrete frame base");
	mu_assert_notnull (high_pc, "Missing concrete high_pc");
	mu_assert_notnull (prototyped, "Missing mutable abstract declaration attribute");
	mu_assert_notnull (origin_mutable, "Missing second mutable abstract attribute");
	mu_assert_notnull (dog_low_pc, "Missing second concrete low_pc");
	mu_assert_notnull (dog_frame_base, "Missing second concrete frame base");
	mu_assert_notnull (dog_prototyped, "Missing second mutable declaration attribute");
	RBinDwarfAttrValue saved_prototyped = *prototyped;
	prototyped->attr_name = DW_AT_prototyped;
	prototyped->attr_form = DW_FORM_flag;
	prototyped->kind = DW_AT_KIND_FLAG;
	prototyped->flag = true;
	RBinDwarfAttrValue saved_dog_prototyped = *dog_prototyped;
	dog_prototyped->attr_name = DW_AT_prototyped;
	dog_prototyped->attr_form = DW_FORM_flag;
	dog_prototyped->kind = DW_AT_KIND_FLAG;
	dog_prototyped->flag = true;
	RBinDwarfAttrValue saved_frame_base = *frame_base;
	RBinDwarfAttrValue saved_origin_mutable = *origin_mutable;
	RBinDwarfAttrValue saved_high_pc = *high_pc;
	RBinDwarfAttrValue saved_dog_low_pc = *dog_low_pc;
	RBinDwarfAttrValue saved_dog_frame_base = *dog_frame_base;
	ut8 direct_bp[] = { DW_OP_reg6 };
	ut8 direct_sp[] = { DW_OP_reg7 };
	ut8 compound[] = { DW_OP_reg6, DW_OP_reg7 };
	frame_base->kind = DW_AT_KIND_BLOCK;
	frame_base->block.data = direct_bp;
	frame_base->block.length = sizeof (direct_bp);
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = NULL,
	};
	const ut64 concrete_addr = 0x130e;
	r_anal_dwarf_process_info (anal, &ctx);
	RAnalDwarfFramePointerProof *proof = test_current_frame_pointer_proof (
		anal, concrete_addr);
	mu_assert_notnull (proof,
		"Direct concrete RBP frame base publishes exact private authority");
	mu_assert_streq (proof->reg_name, "rbp", "Exact frame pointer uses canonical RBP identity");
	mu_assert_eq (proof->size, 8, "Exact frame pointer carries full register width");
	mu_assert_eq (proof->dwarf_reg_num, 6,
		"Exact frame pointer retains the direct DWARF register ordinal");
	const ut64 exact_offset = proof->offset;
	proof->offset = UT64_MAX;
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Stale profile geometry invalidates the private proof");
	Sdb *dwarf_sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (dwarf_sdb, "Missing parsed DWARF namespace for rebind tests");
	ut64 type_epoch = r_anal_types_dirty_epoch (anal);
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_eq (r_anal_types_dirty_epoch (anal), type_epoch + 1,
		"Geometry rebind bumps the type epoch exactly once");
	proof = test_current_frame_pointer_proof (anal, concrete_addr);
	mu_assert_notnull (proof, "Rebound frame-pointer proof is current");
	mu_assert_eq (proof->offset, exact_offset,
		"Rebind restores canonical register coordinates");

	proof->offset = UT64_MAX;
	proof->dwarf_reg_num = 7;
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_eq (proof->offset, UT64_MAX,
		"A raw stack-pointer ordinal cannot partially rebind geometry");
	proof->dwarf_reg_num = 6;
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Restored raw frame-pointer ordinal rebinds exactly");

	proof->offset = UT64_MAX;
	anal->config->bits = 32;
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_eq (proof->offset, UT64_MAX,
		"A mismatched profile leaves stale geometry unchanged");
	anal->config->bits = 64;
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Restored analysis profile rebinds frame authority");

	char *owned_link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_notnull (owned_link, "Missing owned link for rebind mutations");
	proof->offset = UT64_MAX;
	mu_assert_true (sdb_setf (anal->sdb_types, "foreign_frame_link", 0,
		"fcnlink.%08" PFMT64x, concrete_addr),
		"Mutate the live function link without changing private ownership");
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_eq (proof->offset, UT64_MAX,
		"A mismatched live link leaves stale geometry unchanged");
	mu_assert_true (sdb_setf (anal->sdb_types, owned_link, 0,
		"fcnlink.%08" PFMT64x, concrete_addr), "Restore the exact owned link");
	free (owned_link);
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Restored owned link rebinds frame authority");

	proof->offset = UT64_MAX;
	proof->generation--;
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_eq (proof->offset, UT64_MAX,
		"A stale proof generation leaves geometry unchanged");
	proof->generation = R_ANAL_PRIV (anal)->dwarf_function_link_generation;
	r_anal_dwarf_integrate_functions (anal, flags, dwarf_sdb);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Restored proof generation rebinds frame authority");

	frame_base->attr_name = DW_AT_decl_line;
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Absent direct frame base publishes no proof");
	origin_mutable->attr_name = DW_AT_frame_base;
	origin_mutable->attr_form = DW_FORM_block1;
	origin_mutable->kind = DW_AT_KIND_BLOCK;
	origin_mutable->block.data = direct_bp;
	origin_mutable->block.length = sizeof (direct_bp);
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Abstract-only frame base publishes no proof");
	*origin_mutable = saved_origin_mutable;
	*frame_base = saved_frame_base;
	frame_base->kind = DW_AT_KIND_BLOCK;
	frame_base->block.data = compound;
	frame_base->block.length = sizeof (compound);
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Compound frame base publishes no proof");
	frame_base->block.data = direct_sp;
	frame_base->block.length = sizeof (direct_sp);
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Direct stack-pointer frame base publishes no proof");
	frame_base->block.data = direct_bp;
	frame_base->block.length = sizeof (direct_bp);
	high_pc->attr_name = DW_AT_frame_base;
	high_pc->attr_form = DW_FORM_block1;
	high_pc->kind = DW_AT_KIND_BLOCK;
	high_pc->block.data = direct_bp;
	high_pc->block.length = sizeof (direct_bp);
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Duplicate direct frame-base attributes publish no proof");
	*high_pc = saved_high_pc;
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Restored direct frame base republishes proof");
	anal->config->bits = 32;
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Changed analysis profile invalidates proof");
	anal->config->bits = 64;
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Restored analysis profile revalidates proof");

	char *link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_notnull (link, "Missing parser-owned frame-pointer function link");
	mu_assert_true (test_set_function_type_link (anal, link, concrete_addr),
		"Ordinary identical write replaces parser ownership");
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Ordinary replacement invalidates parser proof");
	char link_key[SDB_MAX_KEY];
	snprintf (link_key, sizeof (link_key),
		"fcnlink.%08" PFMT64x, concrete_addr);
	mu_assert_true (sdb_unset (anal->sdb_types, link_key, 0),
		"Remove ordinary link before parser reimport");
	free (link);
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Parser reimport restores owned proof");
	const ut64 saved_origin_ref = origin->reference;
	origin->reference = UT64_MAX;
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Failed reparse cannot retain stale proof");
	origin->reference = saved_origin_ref;
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Valid reparse restores exact proof");

	dog_low_pc->address = concrete_addr;
	dog_frame_base->kind = DW_AT_KIND_BLOCK;
	dog_frame_base->block.data = direct_bp;
	dog_frame_base->block.length = sizeof (direct_bp);
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Duplicate function address fails frame authority closed");
	*dog_low_pc = saved_dog_low_pc;
	*dog_frame_base = saved_dog_frame_base;
	r_anal_dwarf_process_info (anal, &ctx);
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Unique function address restores frame proof");

	RAnalPriv *priv = R_ANAL_PRIV (anal);
	RAnalDwarfFunctionLinkAuthority *authority = ht_up_find (
		priv->dwarf_function_link_authority, concrete_addr, NULL);
	proof = ht_up_find (
		priv->dwarf_frame_pointer_proofs, concrete_addr, NULL);
	mu_assert_notnull (authority, "Missing private function-link authority");
	mu_assert_notnull (proof, "Missing private frame-pointer proof");
	priv->dwarf_function_link_generation = UT64_MAX;
	authority->generation = UT64_MAX;
	proof->generation = UT64_MAX;
	mu_assert_notnull (test_current_frame_pointer_proof (anal, concrete_addr),
		"Wrap-adjacent generation starts current");
	RAnalDwarfContext failed_ctx = { 0 };
	r_anal_dwarf_process_info (anal, &failed_ctx);
	mu_assert_null (test_current_frame_pointer_proof (anal, concrete_addr),
		"Generation saturation poisons frame authority");
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link,
		"Failed parse revokes saturated owned link instead of laundering it");
	free (link);

	*frame_base = saved_frame_base;
	*prototyped = saved_prototyped;
	*dog_prototyped = saved_dog_prototyped;
	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

static bool test_dwarf5_malformed_prototypes_do_not_link(void) {
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;
	sdb_reset (anal->sdb_types);
	RBinFileOptions opt = {
		.baseaddr = 0x400000,
	};
	mu_assert_true (r_bin_open (bin, "bins/elf/dwarf5_line_cl", &opt),
		"dwarf5_line_cl binary could not be opened");
	RBinFile *bf = r_bin_cur (bin);
	mu_assert_notnull (bf, "Couldn't get current bin file");
	ut64 main_addr = 0x11c0 + (ut64)bf->bo->baddr_shift;
	RVecDwarfAbbrevDecl *abbrevs = r_bin_dwarf_parse_abbrev (bf, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse DWARF5 abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (bf, abbrevs, MODE);
	mu_assert_notnull (info, "Couldn't parse DWARF5 indexed info");
	mu_assert_eq (RVecDwarfCompUnit_length (info->comp_units), 1,
		"Expected one DWARF5 compilation unit");
	RBinDwarfCompUnit *unit = RVecDwarfCompUnit_at (info->comp_units, 0);
	RBinDwarfDie *main_die = test_find_named_die (unit, DW_TAG_subprogram, "main");
	mu_assert_notnull (main_die, "Couldn't find DWARF5 main DIE");
	RBinDwarfAttrValue *low_pc = test_find_attr (main_die, DW_AT_low_pc);
	mu_assert_notnull (low_pc, "Couldn't find main low_pc");
	RBinDwarfAttrKind low_pc_kind = low_pc->kind;
	low_pc->kind = DW_AT_KIND_CONSTANT;
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = NULL,
	};
	r_anal_dwarf_process_info (anal, &ctx);
	char *link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_null (link, "Malformed address kind must not create an exact link");
	free (link);
	low_pc->kind = low_pc_kind;

	RBinDwarfDie *formal = NULL;
	RBinDwarfDie *die;
	bool after_main = false;
	R_VEC_FOREACH (unit->dies, die) {
		if (die == main_die) {
			after_main = true;
			continue;
		}
		if (after_main && die->tag == DW_TAG_formal_parameter) {
			formal = die;
			break;
		}
	}
	mu_assert_notnull (formal, "Couldn't find main formal parameter");
	RBinDwarfAttrValue *formal_type = test_find_attr (formal, DW_AT_type);
	mu_assert_notnull (formal_type, "Couldn't find formal parameter type");
	RBinDwarfAttrKind formal_type_kind = formal_type->kind;
	formal_type->kind = DW_AT_KIND_CONSTANT;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_null (link, "Malformed formal type kind must not create an exact link");
	free (link);
	formal_type->kind = formal_type_kind;
	ut64 formal_type_ref = formal_type->reference;
	formal_type->reference = UT64_MAX;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_null (link, "Unresolved formal type must not create an exact link");
	free (link);
	formal_type->reference = formal_type_ref;
	RBinDwarfAttrValue *main_name = test_find_attr (main_die, DW_AT_name);
	mu_assert_notnull (main_name, "Couldn't find main name");
	RBinDwarfAttrValue saved_main_name = *main_name;
	main_name->attr_name = DW_AT_specification;
	main_name->attr_form = DW_FORM_ref4;
	main_name->kind = DW_AT_KIND_REFERENCE;
	main_name->reference = main_die->offset;
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_null (link, "Cyclic specification must not create an exact link");
	free (link);
	*main_name = saved_main_name;

	after_main = false;
	R_VEC_FOREACH (unit->dies, die) {
		if (die == main_die) {
			after_main = true;
			continue;
		}
		if (after_main && die->abbrev_code == 0) {
			die->abbrev_code = 1;
		}
	}
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_null (link, "Unclosed formal subtree must not create an exact link");
	free (link);
	R_VEC_FOREACH (unit->dies, die) {
		if (die->tag == 0 && die->abbrev_code == 1) {
			die->abbrev_code = 0;
		}
	}
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_notnull (link, "Restored complete prototype must create an exact link");
	char *first_link = strdup (link);
	free (link);
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, main_addr);
	mu_assert_streq (link, first_link, "Repeated DWARF import keeps the exact address link stable");
	free (first_link);
	free (link);

	RBinDwarfAttrValue *formal_location = test_find_attr (formal, DW_AT_location);
	RBinDwarfAttrValue *frame_base = test_find_attr (main_die, DW_AT_frame_base);
	mu_assert_notnull (formal_location, "Couldn't find formal parameter location");
	mu_assert_notnull (frame_base, "Couldn't find function frame base");
	RBinDwarfAttrValue saved_formal_location = *formal_location;
	RBinDwarfAttrValue saved_frame_base = *frame_base;
	ut8 direct_register[] = { DW_OP_reg6 };
	formal_location->kind = DW_AT_KIND_BLOCK;
	formal_location->block.data = direct_register;
	formal_location->block.length = sizeof (direct_register);
	r_anal_dwarf_process_info (anal, &ctx);
	const char *arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"A direct register value cannot certify a stack home");

	ut8 direct_breg[] = { DW_OP_breg6, 0 };
	formal_location->block.data = direct_breg;
	formal_location->block.length = sizeof (direct_breg);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"A direct breg expression remains advisory");

	ut8 direct_bregx[] = { DW_OP_bregx, 6, 0 };
	formal_location->block.data = direct_bregx;
	formal_location->block.length = sizeof (direct_bregx);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"A direct bregx expression remains advisory");

	ut8 operand_opcode_alias[] = { DW_OP_bregx, 6, 0, DW_OP_fbreg, 0 };
	formal_location->block.data = operand_opcode_alias;
	formal_location->block.length = sizeof (operand_opcode_alias);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"Operand bytes cannot be reinterpreted as exact location opcodes");

	ut8 oversized_bregx[] = {
		DW_OP_bregx, 0x86, 0x80, 0x80, 0x80, 0x10, 0
	};
	formal_location->block.data = oversized_bregx;
	formal_location->block.length = sizeof (oversized_bregx);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !strstr (arg_record, ",YQ==,"),
		"An oversized bregx register cannot alias a supported register");

	ut8 overflowing_bregx[] = {
		DW_OP_bregx, 0x86, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x02, 0
	};
	formal_location->block.data = overflowing_bregx;
	formal_location->block.length = sizeof (overflowing_bregx);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !strstr (arg_record, ",YQ==,"),
		"An overflowing bregx ULEB refuses exact authority");

	ut8 noncanonical_bregx[] = { DW_OP_bregx, 0x86, 0, 0 };
	formal_location->block.data = noncanonical_bregx;
	formal_location->block.length = sizeof (noncanonical_bregx);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !strstr (arg_record, ",YQ==,"),
		"A noncanonical bregx ULEB refuses exact authority");

	ut8 trailing_expression[] = { DW_OP_fbreg, 0, DW_OP_reg6 };
	formal_location->block.data = trailing_expression;
	formal_location->block.length = sizeof (trailing_expression);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"A trailing location opcode refuses exact authority");

	ut8 noncanonical_sleb[] = { DW_OP_fbreg, 0x80, 0 };
	formal_location->block.data = noncanonical_sleb;
	formal_location->block.length = sizeof (noncanonical_sleb);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"A noncanonical stack offset refuses exact authority");

	ut8 exact_fbreg[] = { DW_OP_fbreg, 0 };
	ut8 compound_frame_base[] = { DW_OP_reg6, DW_OP_reg7 };
	formal_location->block.data = exact_fbreg;
	formal_location->block.length = sizeof (exact_fbreg);
	frame_base->kind = DW_AT_KIND_BLOCK;
	frame_base->block.data = compound_frame_base;
	frame_base->block.length = sizeof (compound_frame_base);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (!arg_record || !r_str_startswith (arg_record, "dwarf-stack-home-v1,"),
		"A compound frame-base expression refuses exact authority");

	r_str_ncpy (anal->config->arch, "arm", sizeof (anal->config->arch));
	anal->config->bits = 64;
	ut8 arm64_sp_frame_base[] = { DW_OP_reg31 };
	frame_base->block.data = arm64_sp_frame_base;
	frame_base->block.length = sizeof (arm64_sp_frame_base);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (arg_record && r_str_startswith (
		arg_record, "dwarf-stack-home-v1,0,s,"),
		"An exact AArch64 SP frame base certifies an SP-relative formal home");

	ut8 arm64_fp_frame_base[] = { DW_OP_reg29 };
	frame_base->block.data = arm64_fp_frame_base;
	frame_base->block.length = sizeof (arm64_fp_frame_base);
	r_anal_dwarf_process_info (anal, &ctx);
	arg_record = sdb_const_get (
		sdb_ns (anal->sdb, "dwarf", 0), "fcn.main.arg.0", NULL);
	mu_assert_true (arg_record && r_str_startswith (
		arg_record, "dwarf-stack-home-v1,0,b,"),
		"An exact AArch64 FP frame base certifies a BP-relative formal home");
	*formal_location = saved_formal_location;
	*frame_base = saved_frame_base;
	r_bin_dwarf_free_debug_info (info);
	RVecDwarfAbbrevDecl_free (abbrevs);
	mu_end;
}

#define run_test_with_setup(test_func) \
	do { \
		if (!setup ()) { \
			fprintf (stderr, "Setup failed for " #test_func "\n"); \
			return 1; \
		} \
		mu_run_test (test_func); \
		teardown (); \
	} while (0)

int all_tests(void) {
	run_test_with_setup (test_parse_dwarf_types);
	run_test_with_setup (test_dwarf_function_parsing_cpp);
	run_test_with_setup (test_dwarf_function_parsing_rust);
	run_test_with_setup (test_dwarf_function_parsing_go);
	run_test_with_setup (test_dwarf5_function_type_links);
	run_test_with_setup (test_dwarf5_named_typedef_to_anonymous_aggregate);
	run_test_with_setup (test_dwarf3_abstract_origin_prototype_join);
	run_test_with_setup (test_dwarf3_exact_frame_pointer_authority);
	run_test_with_setup (test_dwarf5_malformed_prototypes_do_not_link);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
