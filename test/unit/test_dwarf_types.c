#include <r_anal.h>
#include <r_bin_dwarf.h>
#include "minunit.h"

#define MODE 2

#define check_kv(k, v)                                                         \
	do {                                                                   \
		value = sdb_get (anal->sdb_types, k, NULL);                    \
		mu_assert_nullable_streq (value, v, "Wrong key - value pair"); \
	} while (0)

static bool test_parse_dwarf_types_version2(void) {
	RBin *bin = r_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RBin");
	RIO *io = r_io_new ();
	mu_assert_notnull (io, "Couldn't create new RIO");
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	r_io_bind (io, &bin->iob);

	RBinOptions opt = { 0 };
	bool res = r_bin_open (bin, "bins/pe/vista-glass.exe", &opt);
	mu_assert ("pe/vista-glass.exe binary could not be opened", res);
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	RBinDwarfDebugAbbrev *abbrevs = r_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RBinDwarfDebugInfo *info = r_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	// black box
	r_anal_parse_dwarf_types (anal, info);
	// Now we expect certain information to be set in the sdb
	char * value = NULL;
	char *object_name = "_cairo_status";
	
	check_kv ("_cairo_status", "enum");
	check_kv ("enum._cairo_status.!size", "32");
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
	check_kv ("struct._MARGINS.!size", "128");
	// TODO evaluate member_location operations in DWARF to get offset and test it
	check_kv ("struct._MARGINS", "cxLeftWidth,cxRightWidth,cyTopHeight,cyBottomHeight");

	check_kv ("unaligned", "union");
	check_kv ("union.unaligned.!size", "64");
	check_kv ("union.unaligned", "ptr,u2,u4,u8,s2,s4,s8");
	check_kv ("union.unaligned.u2", "short unsigned int,0,0");
	check_kv ("union.unaligned.s8", "long long int,0,0");

	r_anal_free (anal);
	r_bin_free (bin);
	r_io_free (io);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_parse_dwarf_types_version2);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}