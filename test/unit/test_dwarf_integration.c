#include <r_anal.h>
#include <r_bin.h>
#include "minunit.h"

#define MODE 2

#define check_kv(k, v)                                                         \
	do {                                                                   \
		value = sdb_get (sdb, k, NULL);                    \
		mu_assert_nullable_streq (value, v, "Wrong key - value pair"); \
	} while (0)

static bool test_parse_dwarf_types(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RBin");
	RIO *io = r_io_new ();
	mu_assert_notnull (io, "Couldn't create new RIO");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_io_bind (io, &bin->iob);
	anal->binb.demangle = r_bin_demangle;
	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/pe/vista-glass.exe", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	anal->cpu = strdup ("x86");
	anal->bits = 32;
	mu_assert ("pe/vista-glass.exe binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinDwarfDebugAbbrev *abbrevs = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");

	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bin, 4);
	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	char * value = NULL;
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
	r_bin_dwarf_free_debug_abbrev (abbrevs);
	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

static bool test_dwarf_function_parsing_cpp(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RBin");
	RIO *io = r_io_new ();
	mu_assert_notnull (io, "Couldn't create new RIO");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_io_bind (io, &bin->iob);
	anal->binb.demangle = r_bin_demangle;

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	anal->cpu = strdup ("x86");
	anal->bits = 64;
	mu_assert ("elf/dwarf4_many_comp_units.elf binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinDwarfDebugAbbrev *abbrevs = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bin, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	char *value = NULL;
	check_kv ("Mammal", "fcn");
	check_kv ("fcn.Mammal.addr", "0x401300");
	check_kv ("fcn.Mammal.sig", "void Mammal(Mammal * this);");
	check_kv ("fcn.Dog::walk__.addr", "0x401380");
	check_kv ("fcn.Dog::walk__.sig", "int Dog::walk()(Dog * this);");
	check_kv ("fcn.Dog::walk__.name", "Dog::walk()");
	check_kv ("fcn.Mammal::walk__.vars", "this");
	check_kv ("fcn.Mammal::walk__.var.this", "b,-8,Mammal *");

	check_kv ("main", "fcn");
	check_kv ("fcn.main.addr", "0x401160");
	check_kv ("fcn.main.sig", "int main();");
	check_kv ("fcn.main.vars", "b,m,output");
	check_kv ("fcn.main.var.output", "b,-40,int");

	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

static bool test_dwarf_function_parsing_go(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RBin");
	RIO *io = r_io_new ();
	mu_assert_notnull (io, "Couldn't create new RIO");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_io_bind (io, &bin->iob);
	anal->binb.demangle = r_bin_demangle;

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf_go_tree", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	anal->cpu = strdup ("x86");
	anal->bits = 64;
	mu_assert ("bins/elf/dwarf_go_tree", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinDwarfDebugAbbrev *abbrevs = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bin, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	char *value = NULL;

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
	r_bin_dwarf_free_debug_abbrev (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

static bool test_dwarf_function_parsing_rust(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RBin");
	RIO *io = r_io_new ();
	mu_assert_notnull (io, "Couldn't create new RIO");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_io_bind (io, &bin->iob);
	anal->binb.demangle = r_bin_demangle;

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/elf/dwarf_rust_bubble", &opt);
	// TODO fix, how to correctly promote binary info to the RAnal in unit tests?
	anal->cpu = strdup ("x86");
	anal->bits = 64;
	mu_assert ("bins/elf/dwarf_rust_bubble", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinDwarfDebugAbbrev *abbrevs = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = r_bin_dwarf_parse_loc (bin, 8);

	RAnalDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	r_anal_dwarf_process_info (anal, &ctx);

	Sdb *sdb = sdb_ns (anal->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	char *value = NULL;

	check_kv ("fcn.main.addr", "0x5750");
	check_kv ("fcn.main.name", "main");
	check_kv ("fcn.main.var.numbers", "s,128,i32[11]");
	check_kv ("fcn.main.var.strings", "s,312,&str[6]");
	// check_kv ("fcn.main.vars", "numbers,arg0,arg0,strings,arg0,arg0"); Fix these collision by unique renaming in future
	check_kv ("fcn.lang_start_internal.sig", "isize lang_start_internal(&Fn<()> main,isize argc,u8 ** argv);");

	check_kv ("bubble_sort__str_", "fcn");
	check_kv ("bubble_sort_i32_", "fcn");
	check_kv ("fcn.bubble_sort_i32_.vars", "values,n,swapped,iter,__next,val,i");
	check_kv ("fcn.bubble_sort_i32_.var.iter", "s,112,Range<usize>");
	check_kv ("fcn.bubble_sort_i32_.var.i", "s,176,usize");
	check_kv ("fcn.bubble_sort_i32_.name", "bubble_sort<i32>");
	check_kv ("fcn.bubble_sort_i32_.addr", "0x5270");

	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (abbrevs);
	r_bin_dwarf_free_loc (loc_table);
	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_parse_dwarf_types);
	mu_run_test (test_dwarf_function_parsing_cpp);
	mu_run_test (test_dwarf_function_parsing_go);
	mu_run_test (test_dwarf_function_parsing_rust);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
