#include <r_asm.h>

#include "minunit.h"
#include "test_sdb.h"

static void setup_sdb_for_struct(Sdb *res) {
	// "td struct kappa {int bar;int cow;};"
	sdb_set (res, "kappa", "struct", 0);
	sdb_set (res, "struct.kappa", "bar,cow", 0);
	sdb_set (res, "struct.kappa.bar", "int32_t,0,0", 0);
	sdb_set (res, "struct.kappa.cow", "int32_t,4,0", 0);
}

static void setup_sdb_for_union(Sdb *res) {
	// "td union kappa {int bar;int cow;};"
	sdb_set (res, "kappa", "union", 0);
	sdb_set (res, "union.kappa", "bar,cow", 0);
	sdb_set (res, "union.kappa.bar", "int32_t,0,0", 0);
	sdb_set (res, "union.kappa.cow", "int32_t,0,0", 0);
}

static void setup_sdb_for_enum(Sdb *res) {
	// "td enum foo { firstCase=1, secondCase=2,};"
	sdb_set (res, "foo", "enum", 0);
	sdb_set (res, "enum.foo", "firstCase,secondCase", 0);
	sdb_set (res, "enum.foo.firstCase", "0x1", 0);
	sdb_set (res, "enum.foo.secondCase", "0x2", 0);
	sdb_set (res, "enum.foo.0x1", "firstCase", 0);
	sdb_set (res, "enum.foo.0x2", "secondCase", 0);
}

static void setup_sdb_for_typedef(Sdb *res) {
	// td typedef char *string;
	sdb_set (res, "string", "typedef", 0);
	sdb_set (res, "typedef.string", "char *", 0);
}

static void setup_sdb_for_atomic(Sdb *res) {
	sdb_set (res, "char", "type", 0);
	sdb_set (res, "type.char.size", "8", 0);
	sdb_set (res, "type.char", "c", 0);
}

static void setup_sdb_for_not_found(Sdb *res) {
	// malformed type states
	sdb_set (res, "foo", "enum", 0);
	sdb_set (res, "bar", "struct", 0);
	sdb_set (res, "quax", "union", 0);
	sdb_set (res, "enum.foo", "aa,bb", 0);
	sdb_set (res, "struct.bar", "cc,dd", 0);
	sdb_set (res, "union.quax", "ee,ff", 0);

	sdb_set (res, "omega", "struct", 0);
	sdb_set (res, "struct.omega", "ee,ff,gg", 0);
	sdb_set (res, "struct.omega.ee", "0,1", 0);
	sdb_set (res, "struct.omega.ff", "", 0);
}

static bool test_anal_get_base_type_struct(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_struct (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "kappa");
	mu_assert_notnull (base, "Couldn't create get base type of struct \"kappa\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_STRUCT, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "kappa", "type name");

	RAnalStructMember *member;

	member = RVecAnalTypeMember_at (&base->struct_data.members, 0);
	mu_assert_eq (member->offset, 0, "Incorrect offset for struct member");
	mu_assert_streq (member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq (member->name, "bar", "Incorrect name for struct member");

	member = RVecAnalTypeMember_at (&base->struct_data.members, 1);
	mu_assert_eq (member->offset, 4, "Incorrect offset for struct member");
	mu_assert_streq (member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq (member->name, "cow", "Incorrect name for struct member");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_struct(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_struct (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save struct type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_struct_member_needing_sanitization_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	// A member name that sdb keys cannot hold verbatim. DWARF produces these
	// for C++ vtable pointers, e.g. "_vptr.Bird".
	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("Bird");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int (**)()"),
		.name = strdup ("_vptr.Bird")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	// The member list has to name the member by the key that addresses it,
	// otherwise the reader looks up a key that was never written and the whole
	// type becomes unreadable.
	mu_assert_streq (sdb_const_get (anal->sdb_types, "struct.Bird", 0), "_vptr_Bird",
		"member list names the sanitized key");
	mu_assert_notnull (sdb_const_get (anal->sdb_types, "struct.Bird._vptr_Bird", 0),
		"member is stored under the sanitized key");

	RAnalBaseType *got = r_anal_get_base_type (anal, "Bird");
	mu_assert_notnull (got, "reload struct whose member name needed sanitization");
	mu_assert_eq (RVecAnalTypeMember_length (&got->struct_data.members), 1,
		"member survives the round trip");
	RAnalStructMember *m = RVecAnalTypeMember_at (&got->struct_data.members, 0);
	mu_assert_streq (m->name, "_vptr_Bird", "member is named by its key");
	mu_assert_streq (m->type, "int (**)()", "member type survives");
	r_anal_base_type_free (got);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_enum_case_needing_sanitization_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	base->name = strdup ("Mode");

	RAnalEnumCase cas = {
		.name = strdup ("Mode.One"),
		.val = 1
	};
	RVecAnalEnumCase_push_back (&base->enum_data.cases, &cas);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	mu_assert_streq (sdb_const_get (anal->sdb_types, "enum.Mode", 0), "Mode_One",
		"case list names the sanitized key");

	// get_enum_type treats a missing case key as fatal, so a single case name
	// needing sanitization made the whole enum unreadable.
	RAnalBaseType *got = r_anal_get_base_type (anal, "Mode");
	mu_assert_notnull (got, "reload enum whose case name needed sanitization");
	mu_assert_eq (RVecAnalEnumCase_length (&got->enum_data.cases), 1,
		"case survives the round trip");
	RAnalEnumCase *c = RVecAnalEnumCase_at (&got->enum_data.cases, 0);
	mu_assert_streq (c->name, "Mode_One", "case is named by its key");
	mu_assert_eq (c->val, 1, "case value survives");
	r_anal_base_type_free (got);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_union(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_union (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "kappa");
	mu_assert_notnull (base, "Couldn't create get base type of union \"kappa\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_UNION, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "kappa", "type name");

	RAnalUnionMember *member;

	member = RVecAnalTypeMember_at (&base->union_data.members, 0);
	mu_assert_streq (member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq (member->name, "bar", "Incorrect name for union member");

	member = RVecAnalTypeMember_at (&base->union_data.members, 1);
	mu_assert_streq (member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq (member->name, "cow", "Incorrect name for union member");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_union(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("kappa");

	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_union (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save union type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_enum(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_enum (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "foo");
	mu_assert_notnull (base, "Couldn't create get base type of enum \"foo\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_ENUM, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "foo", "type name");

	RAnalEnumCase *cas = RVecAnalEnumCase_at (&base->enum_data.cases, 0);
	mu_assert_eq (cas->val, 1, "Incorrect value for enum case");
	mu_assert_streq (cas->name, "firstCase", "Incorrect name for enum case");

	cas = RVecAnalEnumCase_at (&base->enum_data.cases, 1);
	mu_assert_eq (cas->val, 2, "Incorrect value for enum case");
	mu_assert_streq (cas->name, "secondCase", "Incorrect name for enum case");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_enum(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	base->name = strdup ("foo");

	RAnalEnumCase cas = {
		.name = strdup ("firstCase"),
		.val = 1
	};
	RVecAnalEnumCase_push_back (&base->enum_data.cases, &cas);

	cas.name = strdup ("secondCase");
	cas.val = 2;
	RVecAnalEnumCase_push_back (&base->enum_data.cases, &cas);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_enum (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save enum type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_typedef(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_typedef (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "string");
	mu_assert_notnull (base, "Couldn't create get base type of typedef \"string\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_TYPEDEF, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "string", "type name");
	mu_assert_streq (base->type, "char *", "typedefd type");
	anal->config->bits = 64;
	mu_assert_eq (r_anal_type_bitsize (anal, "string"), 64,
		"Pointer typedef uses the current architecture width");
	sdb_set (anal->sdb_types, "word", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.word", "unsigned long", 0);
	sdb_num_set (anal->sdb_types, "type.word.size", 64, 0);
	mu_assert_eq (r_anal_type_bitsize (anal, "word"), 64,
		"Scalar typedef uses its exact declared width");
	sdb_set (anal->sdb_types, "cycle_a", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_a", "cycle_b", 0);
	sdb_set (anal->sdb_types, "cycle_b", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_b", "cycle_a", 0);
	sdb_set (anal->sdb_types, "u64", "type", 0);
	sdb_num_set (anal->sdb_types, "type.u64.size", 64, 0);
	sdb_set (anal->sdb_types, "myword", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.myword", "u64", 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "myword"), 64,
		"Typedef without a declared width measures what it aliases");
	mu_assert_eq (r_anal_type_bitsize (anal, "cycle_a"), 0,
		"Cyclic typedefs fail closed");

	sdb_set (anal->sdb_types, "word", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.word", "unsigned long", 0);
	sdb_num_set (anal->sdb_types, "type.word.size", 64, 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "word"), 64,
		"Typedef with a declared width measures that width");

	sdb_set (anal->sdb_types, "u64", "type", 0);
	sdb_num_set (anal->sdb_types, "type.u64.size", 64, 0);
	sdb_set (anal->sdb_types, "myword", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.myword", "u64", 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "myword"), 64,
		"Typedef without a declared width measures what it aliases");

	sdb_set (anal->sdb_types, "cycle_a", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_a", "cycle_b", 0);
	sdb_set (anal->sdb_types, "cycle_b", "typedef", 0);
	sdb_set (anal->sdb_types, "typedef.cycle_b", "cycle_a", 0);
	mu_assert_eq (r_type_get_bitsize (anal->sdb_types, "cycle_a"), 0,
		"Cyclic typedefs fail closed");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_typedef(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	base->name = strdup ("string");
	base->type = strdup ("char *");

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_typedef (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save typedef type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_atomic(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	setup_sdb_for_atomic (anal->sdb_types);

	RAnalBaseType *base = r_anal_get_base_type (anal, "char");
	mu_assert_notnull (base, "Couldn't create get base type of atomic type \"char\"");

	mu_assert_eq (R_ANAL_BASE_TYPE_KIND_ATOMIC, base->kind, "Wrong base type");
	mu_assert_streq (base->name, "char", "type name");
	mu_assert_streq (base->type, "c", "atomic type type");
	mu_assert_eq (base->size, 8, "atomic type size");

	r_anal_base_type_free (base);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_atomic(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	base->name = strdup ("char");
	base->type = strdup ("c");
	base->size = 8;

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_atomic (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save atomic type");
	sdb_free (reg);

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_get_base_type_not_found(void) {
	RAnal *anal = r_anal_new ();
	setup_sdb_for_not_found (anal->sdb_types);

	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");

	RAnalBaseType *base = r_anal_get_base_type (anal, "non_existant23321312___");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "foo");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "bar");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "quax");
	mu_assert_null (base, "Should find nothing");
	base = r_anal_get_base_type (anal, "omega");
	mu_assert_null (base, "Should find nothing");

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_struct_array_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("arr");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("scalar"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("char");
	member.name = strdup ("buf");
	member.count = 16;
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "arr");
	mu_assert_notnull (got, "reload struct with array member");

	RAnalStructMember *m = RVecAnalTypeMember_at (&got->struct_data.members, 0);
	mu_assert_eq (m->count, 0, "scalar member count survives as 0");
	m = RVecAnalTypeMember_at (&got->struct_data.members, 1);
	mu_assert_eq (m->offset, 4, "array member offset survives");
	mu_assert_eq (m->count, 16, "array member count survives the roundtrip");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_types_snapshot_epoch_and_context_hash(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	ut64 epoch0 = r_anal_types_dirty_epoch (anal);
	ut64 hash0 = r_anal_types_context_hash (anal);
	mu_assert_neq (hash0, 0, "initial type context hash");

	RList *snapshot0 = r_anal_types_snapshot (anal);
	mu_assert_notnull (snapshot0, "initial type snapshot");
	r_anal_types_snapshot_free (snapshot0);

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	base->name = strdup ("codex_u8");
	base->type = strdup ("u");
	base->size = 8;
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	ut64 epoch1 = r_anal_types_dirty_epoch (anal);
	ut64 hash1 = r_anal_types_context_hash (anal);
	mu_assert_neq (epoch1, epoch0, "saving a base type bumps the dirty epoch");
	mu_assert_neq (hash1, hash0, "saving a base type changes the type context hash");
	mu_assert_eq (r_anal_types_context_hash (anal), hash1, "type context hash is cached until the next epoch");

	bool found = false;
	RList *snapshot1 = r_anal_types_snapshot (anal);
	mu_assert_notnull (snapshot1, "updated type snapshot");
	RAnalBaseType *type;
	RListIter *iter;
	r_list_foreach (snapshot1, iter, type) {
		if (type && type->name && !strcmp (type->name, "codex_u8")) {
			found = true;
			break;
		}
	}
	r_anal_types_snapshot_free (snapshot1);
	mu_assert_true (found, "updated type snapshot contains saved base type");

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_function_type_mutations_bump_type_revision(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "create function-type revision analysis");
	mu_assert_true (r_anal_import_c_decls (anal, "int epoch_one(void);", NULL),
		"seed first function type");
	ut64 epoch = r_anal_types_dirty_epoch (anal);
	ut64 hash = r_anal_types_context_hash (anal);
	mu_assert_true (r_anal_import_c_decls (
		anal, "long epoch_two(int value);", NULL),
		"import second function type");
	mu_assert_neq (r_anal_types_dirty_epoch (anal), epoch,
		"function-type import bumps the type revision epoch");
	mu_assert_neq (r_anal_types_context_hash (anal), hash,
		"function-type import invalidates the type context hash");
	epoch = r_anal_types_dirty_epoch (anal);
	hash = r_anal_types_context_hash (anal);
	mu_assert_true (r_anal_function_del_signature (anal, "epoch_two"),
		"delete imported function type");
	mu_assert_neq (r_anal_types_dirty_epoch (anal), epoch,
		"function-type deletion bumps the type revision epoch");
	mu_assert_neq (r_anal_types_context_hash (anal), hash,
		"function-type deletion invalidates the type context hash");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_struct_redefine(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");
	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	member.offset = 4;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	// a redefinition replaces the member list and drops the stale member keys
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");
	member.offset = 0;
	member.type = strdup ("int64_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	sdb_set (reg, "kappa", "struct", 0);
	sdb_set (reg, "struct.kappa", "cow", 0);
	sdb_set (reg, "struct.kappa.cow", "int64_t,0,0", 0);
	assert_sdb_eq (anal->sdb_types, reg, "redefined struct type");

	// an empty declaration must not clobber the full definition
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kappa");
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	assert_sdb_eq (anal->sdb_types, reg, "empty declaration kept the definition");
	sdb_free (reg);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_types_link_epoch_and_context_hash(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	mu_assert_notnull (anal->sdb_types, "Couldn't create new RAnal.sdb_types");
	sdb_set (anal->sdb_types, "codex_link_type", "type", 0);

	ut64 epoch0 = r_anal_types_dirty_epoch (anal);
	ut64 hash0 = r_anal_types_context_hash (anal);
	mu_assert_true (r_anal_types_set_link (anal, "codex_link_type", 0x401000), "type link applies through typed API");
	ut64 epoch1 = r_anal_types_dirty_epoch (anal);
	ut64 hash1 = r_anal_types_context_hash (anal);
	mu_assert_neq (epoch1, epoch0, "type link bumps dirty epoch");
	mu_assert_neq (hash1, hash0, "type link changes context hash");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "link.00401000", 0), "codex_link_type", "type link stored in sdb");

	mu_assert_true (r_anal_types_set_link_offset (anal, "codex_link_type", 0x401008), "type offset link applies through typed API");
	ut64 epoch2 = r_anal_types_dirty_epoch (anal);
	ut64 hash2 = r_anal_types_context_hash (anal);
	mu_assert_neq (epoch2, epoch1, "type offset link bumps dirty epoch");
	mu_assert_neq (hash2, hash1, "type offset link changes context hash");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "offset.00401008", 0), "codex_link_type", "type offset link stored in sdb");

	mu_assert_true (r_anal_types_unlink (anal, 0x401000), "type link removal applies through typed API");
	ut64 epoch3 = r_anal_types_dirty_epoch (anal);
	ut64 hash3 = r_anal_types_context_hash (anal);
	mu_assert_neq (epoch3, epoch2, "type unlink bumps dirty epoch");
	mu_assert_neq (hash3, hash2, "type unlink changes context hash");
	mu_assert_null (sdb_const_get (anal->sdb_types, "link.00401000", 0), "type link removed from sdb");

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_struct_comma_type_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("tpl");

	RAnalStructMember member = {
		.offset = 8,
		.type = strdup ("pair<int, char>"),
		.name = strdup ("p"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "tpl");
	mu_assert_notnull (got, "reload struct with comma in member type");

	RAnalStructMember *m = RVecAnalTypeMember_at (&got->struct_data.members, 0);
	mu_assert_streq (m->type, "pair<int, char>", "member type with comma survives the roundtrip");
	mu_assert_eq (m->offset, 8, "offset not shifted by the comma in the type");
	mu_assert_eq (m->count, 0, "no count fabricated from comma-shifted fields");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_types_link_context_hash_is_order_independent(void) {
	RAnal *left = r_anal_new ();
	RAnal *right = r_anal_new ();
	mu_assert_notnull (left, "Couldn't create left RAnal");
	mu_assert_notnull (right, "Couldn't create right RAnal");
	sdb_set (left->sdb_types, "codex_link_type", "type", 0);
	sdb_set (right->sdb_types, "codex_link_type", "type", 0);

	mu_assert_true (r_anal_types_set_link (left, "codex_link_type", 0x401000), "left first link");
	mu_assert_true (r_anal_types_set_link_offset (left, "codex_link_type", 0x401008), "left second link");
	mu_assert_true (r_anal_types_set_link_offset (right, "codex_link_type", 0x401008), "right first link");
	mu_assert_true (r_anal_types_set_link (right, "codex_link_type", 0x401000), "right second link");

	mu_assert_eq (r_anal_types_dirty_epoch (left), r_anal_types_dirty_epoch (right), "same mutation count produces same type epoch");
	mu_assert_eq (r_anal_types_context_hash (left), r_anal_types_context_hash (right), "type context hash is independent of link insertion order");

	r_anal_free (left);
	r_anal_free (right);
	mu_end;
}

static bool test_anal_mutation_type_link_bumps_type_context(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	sdb_set (anal->sdb_types, "codex_mut_type", "type", 0);
	ut64 epoch0 = r_anal_types_dirty_epoch (anal);
	ut64 hash0 = r_anal_types_context_hash (anal);
	RAnalMutation mutation = {
		.kind = R_ANAL_MUTATION_TYPE_LINK,
		.type = "codex_mut_type",
		.addr = 0x402000,
	};
	RAnalMutationResult result = {0};
	mu_assert_true (r_anal_apply_mutations (anal, &mutation, 1, &result), "type link mutation batch succeeds");
	mu_assert_eq (result.attempted, 1, "one mutation attempted");
	mu_assert_eq (result.applied, 1, "one mutation applied");
	mu_assert_eq (result.failed, 0, "no mutation failed");
	mu_assert_neq (r_anal_types_dirty_epoch (anal), epoch0, "type link mutation bumps dirty epoch");
	mu_assert_neq (r_anal_types_context_hash (anal), hash0, "type link mutation changes context hash");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "link.00402000", 0), "codex_mut_type", "type link mutation stored in sdb");

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_union_comma_type_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("utpl");

	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("pair<int, char>"),
		.name = strdup ("p"),
		.count = 4
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "utpl");
	mu_assert_notnull (got, "reload union with comma in member type");

	RAnalUnionMember *m = RVecAnalTypeMember_at (&got->union_data.members, 0);
	mu_assert_streq (m->type, "pair<int, char>", "member type with comma survives the roundtrip");
	mu_assert_eq (m->count, 4, "count not shifted by the comma in the type");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_mutation_type_link_accepts_zero_addr(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");
	sdb_set (anal->sdb_types, "codex_zero_type", "type", 0);
	RAnalMutation mutation = {
		.kind = R_ANAL_MUTATION_TYPE_LINK,
		.type = "codex_zero_type",
		.addr = 0,
	};
	RAnalMutationResult result = {0};
	mu_assert_true (r_anal_apply_mutations (anal, &mutation, 1, &result), "zero-address type link mutation succeeds");
	mu_assert_eq (result.applied, 1, "zero-address type link mutation applied");
	mu_assert_streq (sdb_const_get (anal->sdb_types, "link.00000000", 0), "codex_zero_type", "zero-address type link stored in sdb");

	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_union_array_roundtrip(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("uarr");

	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("scalar"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup ("char");
	member.name = strdup ("buf");
	member.count = 16;
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	RAnalBaseType *got = r_anal_get_base_type (anal, "uarr");
	mu_assert_notnull (got, "reload union with array member");

	RAnalUnionMember *m = RVecAnalTypeMember_at (&got->union_data.members, 0);
	mu_assert_eq (m->count, 0, "scalar member count survives as 0");
	m = RVecAnalTypeMember_at (&got->union_data.members, 1);
	mu_assert_eq (m->count, 16, "array member count survives the roundtrip");

	r_anal_base_type_free (got);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_save_base_type_union_redefine(void) {
	RAnal *anal = r_anal_new ();
	mu_assert_notnull (anal, "Couldn't create new RAnal");

	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("omega");
	RAnalUnionMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("bar")
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);
	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	// a redefinition replaces the member list and drops the stale member keys
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("omega");
	member.offset = 0;
	member.type = strdup ("int64_t");
	member.name = strdup ("cow");
	RVecAnalTypeMember_push_back (&base->union_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	sdb_set (reg, "omega", "union", 0);
	sdb_set (reg, "union.omega", "cow", 0);
	sdb_set (reg, "union.omega.cow", "int64_t,0,0", 0);
	assert_sdb_eq (anal->sdb_types, reg, "redefined union type");

	// an empty declaration must not clobber the full definition
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("omega");
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	assert_sdb_eq (anal->sdb_types, reg, "empty declaration kept the definition");
	sdb_free (reg);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_base_type_to_kv(void) {
	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("kv");

	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("scalar"),
		.count = 0
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("char");
	member.name = strdup ("buf");
	member.count = 16;
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);

	char *kv = r_anal_base_type_to_kv (base);
	mu_assert_streq (kv,
		"kv=struct\n"
		"struct.kv.scalar=int32_t,0,0\n"
		"struct.kv.buf=char,4,16\n"
		"struct.kv=scalar,buf\n",
		"canonical struct kv serialization");
	free (kv);
	r_anal_base_type_free (base);

	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	base->name = strdup ("ukv");
	RAnalUnionMember umember = {
		.offset = 0,
		.type = strdup ("char"),
		.name = strdup ("buf"),
		.count = 8
	};
	RVecAnalTypeMember_push_back (&base->union_data.members, &umember);

	kv = r_anal_base_type_to_kv (base);
	mu_assert_streq (kv,
		"ukv=union\n"
		"union.ukv.buf=char,0,8\n"
		"union.ukv=buf\n",
		"canonical union kv serialization");
	free (kv);
	r_anal_base_type_free (base);
	mu_end;
}

static bool test_anal_cparse_multiline_fnptr(void) {
	RAnal *anal = r_anal_new ();
	char *error = NULL;
	char *kv = r_anal_cparse (anal, "void once(void (*cb)(\n\tint\n));", &error);
	mu_assert_null (error, "parse multiline function pointer parameter");
	mu_assert_notnull (kv, "serialize multiline function pointer parameter");
	mu_assert_notnull (strstr (kv, "func.once.arg.0=void (*)( int ),cb\n"),
		"function pointer type stays within one SDB row");
	free (kv);
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_type_bitsize_struct_recorded(void) {
	RAnal *anal = r_anal_new ();
	Sdb *TDB = anal->sdb_types;
	sdb_set (TDB, "int32_t", "type", 0);
	sdb_num_set (TDB, "type.int32_t.size", 32, 0);
	// an importer that knows the real width, padding included, saves it with the members
	RAnalBaseType *base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("padded");
	base->size = 128;
	RAnalStructMember member = {
		.offset = 0,
		.type = strdup ("int32_t"),
		.name = strdup ("a")
	};
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	member.offset = 8;
	member.type = strdup ("int32_t");
	member.name = strdup ("b");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);
	mu_assert_eq (sdb_num_get (TDB, "type.padded.size", NULL), 128, "The struct width is saved beside its members");
	mu_assert_eq (r_type_get_bitsize (TDB, "padded"), 128, "A recorded width wins over the member sum");
	mu_assert_eq (r_type_get_bitsize (TDB, "struct padded"), 128, "The keyword spelling reads the same record");
	// a re-save of what was read back keeps the width
	base = r_anal_get_base_type (anal, "padded");
	mu_assert_notnull (base, "The saved struct reads back");
	mu_assert_eq (base->size, 128, "The width reads back with the members");
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);
	mu_assert_eq (r_type_get_bitsize (TDB, "padded"), 128, "A re-save keeps the recorded width");
	// a struct that names itself still measures when the importer recorded its width
	sdb_set (TDB, "self", "struct", 0);
	sdb_set (TDB, "struct.self", "inner", 0);
	sdb_set (TDB, "struct.self.inner", "self,0,0", 0);
	sdb_num_set (TDB, "type.self.size", 8, 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "self"), 8, "A recorded width answers for a self-naming struct");
	// a definition without a width drops a stale record and walks the members again
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	base->name = strdup ("padded");
	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("a");
	RVecAnalTypeMember_push_back (&base->struct_data.members, &member);
	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);
	mu_assert_null (sdb_const_get (TDB, "type.padded.size", NULL), "A save without a width drops the stale record");
	mu_assert_eq (r_type_get_bitsize (TDB, "padded"), 32, "Without a record the members are measured");
	// deleting the type drops its width too
	sdb_num_set (TDB, "type.padded.size", 64, 0);
	r_type_del (TDB, "padded");
	mu_assert_null (sdb_const_get (TDB, "type.padded.size", NULL), "Deleting the struct drops its width");
	r_anal_free (anal);
	mu_end;
}

static bool test_anal_type_bitsize_struct_cycle(void) {
	RAnal *anal = r_anal_new ();
	Sdb *TDB = anal->sdb_types;
	sdb_set (TDB, "int32_t", "type", 0);
	sdb_num_set (TDB, "type.int32_t.size", 32, 0);
	sdb_set (TDB, "self", "struct", 0);
	sdb_set (TDB, "struct.self", "n,inner", 0);
	sdb_set (TDB, "struct.self.n", "int32_t,0,0", 0);
	sdb_set (TDB, "struct.self.inner", "self,4,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "self"), 0, "A struct containing itself fails closed");
	sdb_set (TDB, "ping", "struct", 0);
	sdb_set (TDB, "struct.ping", "pong", 0);
	sdb_set (TDB, "struct.ping.pong", "pong_t,0,0", 0);
	sdb_set (TDB, "pong_t", "typedef", 0);
	sdb_set (TDB, "typedef.pong_t", "pong", 0);
	sdb_set (TDB, "pong", "struct", 0);
	sdb_set (TDB, "struct.pong", "ping", 0);
	sdb_set (TDB, "struct.pong.ping", "ping,0,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "ping"), 0, "A struct cycle through a typedef fails closed");
	sdb_set (TDB, "pair", "struct", 0);
	sdb_set (TDB, "struct.pair", "a,b", 0);
	sdb_set (TDB, "struct.pair.a", "int32_t,0,0", 0);
	sdb_set (TDB, "struct.pair.b", "int32_t,4,0", 0);
	mu_assert_eq (r_type_get_bitsize (TDB, "pair"), 64, "An acyclic struct still measures its members");
	r_anal_free (anal);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_anal_get_base_type_struct);
	mu_run_test (test_anal_save_base_type_struct);
	mu_run_test (test_anal_base_type_struct_array_roundtrip);
	mu_run_test (test_anal_base_type_struct_member_needing_sanitization_roundtrip);
	mu_run_test (test_anal_base_type_enum_case_needing_sanitization_roundtrip);
	mu_run_test (test_anal_save_base_type_struct_redefine);
	mu_run_test (test_anal_base_type_struct_comma_type_roundtrip);
	mu_run_test (test_anal_base_type_union_comma_type_roundtrip);
	mu_run_test (test_anal_base_type_union_array_roundtrip);
	mu_run_test (test_anal_save_base_type_union_redefine);
	mu_run_test (test_anal_base_type_to_kv);
	mu_run_test (test_anal_cparse_multiline_fnptr);
	mu_run_test (test_anal_get_base_type_union);
	mu_run_test (test_anal_save_base_type_union);
	mu_run_test (test_anal_get_base_type_enum);
	mu_run_test (test_anal_save_base_type_enum);
	mu_run_test (test_anal_get_base_type_typedef);
	mu_run_test (test_anal_type_bitsize_struct_cycle);
	mu_run_test (test_anal_type_bitsize_struct_recorded);
	mu_run_test (test_anal_save_base_type_typedef);
	mu_run_test (test_anal_get_base_type_atomic);
	mu_run_test (test_anal_save_base_type_atomic);
	mu_run_test (test_anal_get_base_type_not_found);
	mu_run_test (test_anal_types_snapshot_epoch_and_context_hash);
	mu_run_test (test_anal_function_type_mutations_bump_type_revision);
	mu_run_test (test_anal_types_link_epoch_and_context_hash);
	mu_run_test (test_anal_types_link_context_hash_is_order_independent);
	mu_run_test (test_anal_mutation_type_link_bumps_type_context);
	mu_run_test (test_anal_mutation_type_link_accepts_zero_addr);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
