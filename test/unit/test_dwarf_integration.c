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
	RBinFileOptions opt = { 0 };
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

	RBinFileOptions opt = { 0 };
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

	RBinFileOptions opt = { 0 };
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

	RBinFileOptions opt = { 0 };
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
	r_str_ncpy (anal->config->arch, "x86", sizeof (anal->config->arch));
	anal->config->bits = 64;
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
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	mu_assert_notnull (signature, "Couldn't resolve address-linked function signature");
	mu_assert_streq (signature->ret_type, "int", "address-linked signature wins over function name");
	mu_assert_eq (r_list_length (signature->params), 2, "DWARF5 main parameter count");
	r_anal_function_signature_free (signature);

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
	run_test_with_setup (test_dwarf5_malformed_prototypes_do_not_link);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
