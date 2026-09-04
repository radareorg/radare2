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



// The snapshot outlives the capture now, so a probe is a take, a read and a
// free rather than a callback run while the analysis is still locked.

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
	run_test_with_setup (test_dwarf5_named_typedef_to_anonymous_aggregate);
	run_test_with_setup (test_dwarf5_malformed_prototypes_do_not_link);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
