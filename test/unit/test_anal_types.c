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

	member = RVecAnalStructMember_at (&base->struct_data.members, 0);
	mu_assert_eq (member->offset, 0, "Incorrect offset for struct member");
	mu_assert_streq (member->type, "int32_t", "Incorrect type for struct member");
	mu_assert_streq (member->name, "bar", "Incorrect name for struct member");

	member = RVecAnalStructMember_at (&base->struct_data.members, 1);
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
	RVecAnalStructMember_push_back (&base->struct_data.members, &member);

	member.offset = 4;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalStructMember_push_back (&base->struct_data.members, &member);

	r_anal_save_base_type (anal, base);
	r_anal_base_type_free (base);

	Sdb *reg = sdb_new0 ();
	setup_sdb_for_struct (reg);
	assert_sdb_eq (anal->sdb_types, reg, "save struct type");
	sdb_free (reg);

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

	member = RVecAnalUnionMember_at (&base->union_data.members, 0);
	mu_assert_streq (member->type, "int32_t", "Incorrect type for union member");
	mu_assert_streq (member->name, "bar", "Incorrect name for union member");

	member = RVecAnalUnionMember_at (&base->union_data.members, 1);
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
	RVecAnalUnionMember_push_back (&base->union_data.members, &member);

	member.offset = 0;
	member.type = strdup ("int32_t");
	member.name = strdup ("cow");
	RVecAnalUnionMember_push_back (&base->union_data.members, &member);

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

int all_tests(void) {
	mu_run_test (test_anal_get_base_type_struct);
	mu_run_test (test_anal_save_base_type_struct);
	mu_run_test (test_anal_get_base_type_union);
	mu_run_test (test_anal_save_base_type_union);
	mu_run_test (test_anal_get_base_type_enum);
	mu_run_test (test_anal_save_base_type_enum);
	mu_run_test (test_anal_get_base_type_typedef);
	mu_run_test (test_anal_save_base_type_typedef);
	mu_run_test (test_anal_get_base_type_atomic);
	mu_run_test (test_anal_save_base_type_atomic);
	mu_run_test (test_anal_get_base_type_not_found);
	mu_run_test (test_anal_types_snapshot_epoch_and_context_hash);
	mu_run_test (test_anal_types_link_epoch_and_context_hash);
	mu_run_test (test_anal_types_link_context_hash_is_order_independent);
	mu_run_test (test_anal_mutation_type_link_bumps_type_context);
	mu_run_test (test_anal_mutation_type_link_accepts_zero_addr);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
