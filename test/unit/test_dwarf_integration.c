#include <r_anal.h>
#include <r_bin.h>
#include <r_flag.h>
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

static bool test_dwarf_argument_register_reuse(void) {
	mu_assert ("set register profile", r_reg_set_profile_string (anal->reg,
		"=PC pc\n"
		"=SP sp\n"
		"=BP x29\n"
		"gpr x0 .64 0 0\n"
		"gpr x1 .64 8 0\n"
		"gpr x29 .64 16 0\n"
		"gpr sp .64 24 0\n"
		"gpr pc .64 32 0\n"));
	RAnalFunction *fcn = r_anal_create_function (anal, "collision", 0x100, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (fcn, "create function");
	RRegItem *x1 = r_reg_get (anal->reg, "x1", -1);
	mu_assert_notnull (x1, "get x1");
	const int x1_index = x1->index;
	mu_assert_notnull (r_anal_function_set_var (fcn, x1->index, R_ANAL_VAR_KIND_REG,
		"int64_t", 8, true, "arg2"), "create generic register argument");
	r_unref (x1);
	mu_assert_notnull (r_anal_function_set_var (fcn, 32, R_ANAL_VAR_KIND_BPV,
		"int64_t", 8, true, "arg_20h"), "create generic stack argument");
	mu_assert_notnull (r_anal_function_set_var (fcn, 40, R_ANAL_VAR_KIND_SPV,
		"int64_t", 8, false, "arg0"), "create generic alternate entry");
	mu_assert_notnull (r_anal_function_set_var (fcn, 48, R_ANAL_VAR_KIND_BPV,
		"int64_t", 8, true, "arg_nameh"), "create source argument");
	RAnalFunction *partial = r_anal_create_function (anal, "partial", 0x200, R_ANAL_FCN_TYPE_FCN, NULL);
	mu_assert_notnull (partial, "create partial function");
	mu_assert_notnull (r_anal_function_set_var (partial, x1_index, R_ANAL_VAR_KIND_REG,
		"int64_t", 8, true, "arg2"), "create partial generic argument");
	RRegItem *x0 = r_reg_get (anal->reg, "x0", -1);
	mu_assert_notnull (x0, "get x0");
	const int x0_index = x0->index;
	r_unref (x0);
	RFlag *flags = r_flag_new ();
	mu_assert_notnull (flags, "create flags");
	Sdb *dwarf = sdb_new0 ();
	mu_assert_notnull (dwarf, "create dwarf database");
	sdb_set (dwarf, "collision", "fcn", 0);
	sdb_set (dwarf, "fcn.collision.addr", "0x100", 0);
	sdb_set (dwarf, "fcn.collision.arg.0", "first,r,x0,Swift.Int", 0);
	sdb_set (dwarf, "fcn.collision.args", "first", 0);
	sdb_set (dwarf, "fcn.collision.args.complete", "1", 0);
	sdb_set (dwarf, "fcn.collision.var.result", "r,x0,Swift.Int", 0);
	sdb_set (dwarf, "fcn.collision.vars", "result", 0);
	sdb_set (dwarf, "partial", "fcn", 0);
	sdb_set (dwarf, "fcn.partial.addr", "0x200", 0);
	sdb_set (dwarf, "fcn.partial.arg.0", "first,r,x0,Swift.Int", 0);
	sdb_set (dwarf, "fcn.partial.args", "first", 0);
	r_anal_dwarf_integrate_functions (anal, flags, dwarf);
	RAnalVar *location = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, x0_index);
	mu_assert_notnull (location, "register variable integrated");
	mu_assert_streq (location->name, "first", "formal owns reused register");
	RAnalVar *first = r_anal_function_get_var_byname (fcn, "first");
	mu_assert_notnull (first, "formal argument survived register reuse");
	mu_assert ("formal remains an argument", first->isarg);
	mu_assert_null (r_anal_function_get_var_byname (fcn, "result"), "later local did not replace formal");
	mu_assert_null (r_anal_function_get_var_byname (fcn, "arg2"), "generic register argument removed");
	mu_assert_null (r_anal_function_get_var_byname (fcn, "arg_20h"), "generic stack argument removed");
	mu_assert_notnull (r_anal_function_get_var_byname (fcn, "arg0"), "non-argument local preserved");
	mu_assert_notnull (r_anal_function_get_var_byname (fcn, "arg_nameh"), "source argument preserved");
	mu_assert_notnull (r_anal_function_get_var_byname (partial, "arg2"), "partial arguments preserved");
	sdb_free (dwarf);
	r_flag_free (flags);
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
	run_test_with_setup (test_dwarf_argument_register_reuse);
	run_test_with_setup (test_parse_dwarf_types);
	run_test_with_setup (test_dwarf_function_parsing_cpp);
	run_test_with_setup (test_dwarf_function_parsing_rust);
	run_test_with_setup (test_dwarf_function_parsing_go);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
