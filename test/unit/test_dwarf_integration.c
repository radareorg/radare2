#include <r_anal.h>
#include <r_bin.h>
#include "minunit.h"

#define MODE 2

// Global test context to prevent leaks on early returns
static RBin *bin = NULL;
static RIO *io = NULL;
static RAnal *anal = NULL;

static bool setup(void) {
	bin = r_bin_new ();
	io = r_io_new ();
	anal = r_anal_new ();
	if (!bin || !io || !anal) {
		r_bin_free (bin);
		r_io_free (io);
		r_anal_free (anal);
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
	anal = NULL;
	bin = NULL;
	io = NULL;
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
	check_kv ("fcn.main.var.numbers", "s,128,i32[11]");
	check_kv ("fcn.main.var.strings", "s,312,&str[6]");
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

#define run_test_with_setup(test_func) \
	do { \
		if (!setup ()) { \
			fprintf (stderr, "Setup failed for " #test_func "\n"); \
			return 1; \
		} \
		mu_run_test (test_func); \
		teardown (); \
	} while (0)

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

	high_pc->attr_form = DW_FORM_string;
	high_pc->kind = DW_AT_KIND_STRING;
	high_pc->string.content = "malformed";
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (link, "Malformed concrete high_pc must be refused");
	free (link);
	*high_pc = saved_high_pc;

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
	char *data_link = r_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_null (data_link,
		"DWARF function links must not become generic data type links");
	free (data_link);
	mu_assert_eq (r_type_kind (anal->sdb_types, link), R_TYPE_FUNCTION,
		"Exact address link must target a function type");
	mu_assert_streq (r_type_func_ret (anal->sdb_types, link), "void",
		"Exact constructor return type");
	mu_assert_eq (r_type_func_args_count (anal->sdb_types, link), 1,
		"Exact constructor formal count");
	char *this_type = r_type_func_args_type (anal->sdb_types, link, 0);
	mu_assert_streq (this_type, "Bird * const", "Exact constructor formal type");
	free (this_type);
	char *first_link = strdup (link);
	mu_assert_notnull (first_link, "Copy exact abstract-origin link");
	free (link);
	r_anal_dwarf_process_info (anal, &ctx);
	link = test_function_type_link_at (anal->sdb_types, concrete_addr);
	mu_assert_streq (link, first_link,
		"Repeated abstract-origin import keeps the exact address link stable");
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


int all_tests(void) {
	run_test_with_setup (test_parse_dwarf_types);
	run_test_with_setup (test_dwarf_function_parsing_cpp);
	run_test_with_setup (test_dwarf_function_parsing_rust);
	run_test_with_setup (test_dwarf_function_parsing_go);
	run_test_with_setup (test_dwarf3_abstract_origin_prototype_join);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
