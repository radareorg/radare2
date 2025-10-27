/* radare - LGPL - Copyright 2020 - thestr4ng3r, Yaroslav Stavnichiy */
/* r_json based on nxjson by Yaroslav Stavnichiy */

#include <r_util/pj.h>
#include <r_util/r_json.h>
#include <r_util/r_strbuf.h>
#include "minunit.h"

typedef struct json_test_t {
	const char *json;
	int (*check)(RJson *j);
} JsonTest;

static int check_expected_0(RJson *j) {
	RJson *child_0, *child_1, *child_2;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 16, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "some-int", "object child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 195, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "array1", "object child key");
	mu_assert_eq (child_0->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_0->children.count, 7, "array size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_1->num.u_value, 3, "integer value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_1->num.dbl_value < (5.1 + 1.0e-13)
		&& child_1->num.dbl_value > (5.1 - 1.0e-13));
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_1->num.u_value, -7, "integer value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "nine", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_1->num.u_value, 1, "boolean value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_1->num.u_value, 0, "boolean value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "last", "string value");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "array2", "object child key");
	mu_assert_eq (child_0->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_0->children.count, 2, "array size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "/*", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "*/", "string value");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "some-bool", "object child key");
	mu_assert_eq (child_0->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_0->num.u_value, 1, "boolean value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "other-bool", "object child key");
	mu_assert_eq (child_0->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_0->num.u_value, 0, "boolean value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "some-dbl", "object child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (-1.0e-4 + 1.0e-13)
		&& child_0->num.dbl_value > (-1.0e-4 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "some-null", "object child key");
	mu_assert_eq (child_0->type, R_JSON_NULL, "null type");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "hello", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "world!", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str1", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "//", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str2", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\\", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str3", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "text /*text*/ text", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str4", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\\text\\", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str5", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "?text?", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str\t6\\", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "text\ntext\ttext", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "str7", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "text\xe1\x88\xb4text\xe5\x99\xb8", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "obj", "object child key");
	mu_assert_eq (child_0->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_0->children.count, 2, "object size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "KEY", "object child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "VAL", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "obj", "object child key");
	mu_assert_eq (child_1->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_1->children.count, 1, "object size");
	child_2 = child_1->children.first;
	mu_assert_notnull (child_2, "object child");
	mu_assert_notnull (child_2->key, "object child key not null");
	mu_assert_streq (child_2->key, "KEY", "object child key");
	mu_assert_eq (child_2->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_2->str_value, "VAL", "string value");
	child_2 = child_2->next;
	mu_assert_null (child_2, "last child null");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_4(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 4, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 1, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 2, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 3, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "last", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_5(RJson *j) {
	mu_assert_eq (j->type, R_JSON_STRING, "string type");
	mu_assert_streq (j->str_value, "string value", "string value");
	return MU_PASSED;
}

static int check_expected_6(RJson *j) {
	mu_assert_eq (j->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (j->num.u_value, 1, "boolean value");
	return MU_PASSED;
}

static int check_expected_7(RJson *j) {
	mu_assert_eq (j->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		j->num.dbl_value < (-1.0e-2 + 1.0e-13)
		&& j->num.dbl_value > (-1.0e-2 - 1.0e-13));
	return MU_PASSED;
}

static int check_expected_8(RJson *j) {
	mu_assert_eq (j->type, R_JSON_NULL, "null type");
	return MU_PASSED;
}

static int check_expected_9(RJson *j) {
	RJson *child_0, *child_1, *child_2, *child_3, *child_4, *child_5;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 1, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "glossary", "object child key");
	mu_assert_eq (child_0->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_0->children.count, 2, "object size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "title", "object child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "example glossary", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "GlossDiv", "object child key");
	mu_assert_eq (child_1->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_1->children.count, 2, "object size");
	child_2 = child_1->children.first;
	mu_assert_notnull (child_2, "object child");
	mu_assert_notnull (child_2->key, "object child key not null");
	mu_assert_streq (child_2->key, "title", "object child key");
	mu_assert_eq (child_2->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_2->str_value, "S", "string value");
	child_2 = child_2->next;
	mu_assert_notnull (child_2, "object child");
	mu_assert_notnull (child_2->key, "object child key not null");
	mu_assert_streq (child_2->key, "GlossList", "object child key");
	mu_assert_eq (child_2->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_2->children.count, 1, "array size");
	child_3 = child_2->children.first;
	mu_assert_notnull (child_3, "array child");
	mu_assert_null (child_3->key, "array child key");
	mu_assert_eq (child_3->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_3->children.count, 7, "object size");
	child_4 = child_3->children.first;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "ID", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "SGML", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "SortAs", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "SGML", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "GlossTerm", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "Standard Generalized Markup Language", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "Acronym", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "SGML", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "Abbrev", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "ISO 8879:1986", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "GlossDef", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "A meta-markup language, used to create markup languages such as DocBoo"
		"k.", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "GlossSeeAlso", "object child key");
	mu_assert_eq (child_4->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_4->children.count, 3, "array size");
	child_5 = child_4->children.first;
	mu_assert_notnull (child_5, "array child");
	mu_assert_null (child_5->key, "array child key");
	mu_assert_eq (child_5->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_5->str_value, "GML", "string value");
	child_5 = child_5->next;
	mu_assert_notnull (child_5, "array child");
	mu_assert_null (child_5->key, "array child key");
	mu_assert_eq (child_5->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_5->str_value, "XML", "string value");
	child_5 = child_5->next;
	mu_assert_notnull (child_5, "array child");
	mu_assert_null (child_5->key, "array child key");
	mu_assert_eq (child_5->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_5->str_value, "markup", "string value");
	child_5 = child_5->next;
	mu_assert_null (child_5, "last child null");
	child_4 = child_4->next;
	mu_assert_null (child_4, "last child null");
	child_3 = child_3->next;
	mu_assert_null (child_3, "last child null");
	child_2 = child_2->next;
	mu_assert_null (child_2, "last child null");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_10(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 3, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "this", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "is", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "really", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "simple", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "json", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "right?", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_11(RJson *j) {
	mu_assert_eq (j->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (j->num.u_value, 0, "boolean value");
	return MU_PASSED;
}

static int check_expected_13(RJson *j) {
	mu_assert_eq (j->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (j->num.u_value, 1221, "integer value");
	return MU_PASSED;
}

static int check_expected_14(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 0, "object size");
	child_0 = j->children.first;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_19(RJson *j) {
	RJson *child_0, *child_1, *child_2;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 9, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "foo", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "bar", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "baz", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_0->num.u_value, 1, "boolean value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_0->num.u_value, 0, "boolean value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_NULL, "null type");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_0->children.count, 1, "object size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "key", "object child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "value", "string value");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_0->children.count, 4, "array size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_NULL, "null type");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_NULL, "null type");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_NULL, "null type");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_1->children.count, 0, "array size");
	child_2 = child_1->children.first;
	mu_assert_null (child_2, "last child null");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\n\x0d\\", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_22(RJson *j) {
	mu_assert_eq (j->type, R_JSON_STRING, "string type");
	mu_assert_streq (j->str_value, "\xf0\x90\x8c\x82M\xd0\xb0\xe4\xba\x8c\xf0\x90\x8c\x82", "string value");
	return MU_PASSED;
}

static int check_expected_23(RJson *j) {
	RJson *child_0, *child_1, *child_2, *child_3, *child_4, *child_5;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 1, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "glossary", "object child key");
	mu_assert_eq (child_0->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_0->children.count, 2, "object size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "title", "object child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "example glossary", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "object child");
	mu_assert_notnull (child_1->key, "object child key not null");
	mu_assert_streq (child_1->key, "GlossDiv", "object child key");
	mu_assert_eq (child_1->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_1->children.count, 2, "object size");
	child_2 = child_1->children.first;
	mu_assert_notnull (child_2, "object child");
	mu_assert_notnull (child_2->key, "object child key not null");
	mu_assert_streq (child_2->key, "title", "object child key");
	mu_assert_eq (child_2->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_2->str_value, "S", "string value");
	child_2 = child_2->next;
	mu_assert_notnull (child_2, "object child");
	mu_assert_notnull (child_2->key, "object child key not null");
	mu_assert_streq (child_2->key, "GlossList", "object child key");
	mu_assert_eq (child_2->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_2->children.count, 1, "array size");
	child_3 = child_2->children.first;
	mu_assert_notnull (child_3, "array child");
	mu_assert_null (child_3->key, "array child key");
	mu_assert_eq (child_3->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (child_3->children.count, 7, "object size");
	child_4 = child_3->children.first;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "ID", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "SGML", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "SortAs", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "SGML", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "GlossTerm", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "Standard Generalized Markup Language", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "Acronym", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "SGML", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "Abbrev", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "ISO 8879:1986", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "GlossDef", "object child key");
	mu_assert_eq (child_4->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_4->str_value, "A meta-markup language, used to create markup languages such as DocBoo"
		"k.", "string value");
	child_4 = child_4->next;
	mu_assert_notnull (child_4, "object child");
	mu_assert_notnull (child_4->key, "object child key not null");
	mu_assert_streq (child_4->key, "GlossSeeAlso", "object child key");
	mu_assert_eq (child_4->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_4->children.count, 3, "array size");
	child_5 = child_4->children.first;
	mu_assert_notnull (child_5, "array child");
	mu_assert_null (child_5->key, "array child key");
	mu_assert_eq (child_5->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_5->str_value, "GML", "string value");
	child_5 = child_5->next;
	mu_assert_notnull (child_5, "array child");
	mu_assert_null (child_5->key, "array child key");
	mu_assert_eq (child_5->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_5->str_value, "XML", "string value");
	child_5 = child_5->next;
	mu_assert_notnull (child_5, "array child");
	mu_assert_null (child_5->key, "array child key");
	mu_assert_eq (child_5->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_5->str_value, "markup", "string value");
	child_5 = child_5->next;
	mu_assert_null (child_5, "last child null");
	child_4 = child_4->next;
	mu_assert_null (child_4, "last child null");
	child_3 = child_3->next;
	mu_assert_null (child_3, "last child null");
	child_2 = child_2->next;
	mu_assert_null (child_2, "last child null");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_24(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 5, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (1.1999999999999999e-4 + 1.0e-13)
		&& child_0->num.dbl_value > (1.1999999999999999e-4 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (6.0e-6 + 1.0e-13)
		&& child_0->num.dbl_value > (6.0e-6 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (6.0e-6 + 1.0e-13)
		&& child_0->num.dbl_value > (6.0e-6 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (1.0e-6 + 1.0e-13)
		&& child_0->num.dbl_value > (1.0e-6 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (1.0e-6 + 1.0e-13)
		&& child_0->num.dbl_value > (1.0e-6 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_25(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 4, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (10.0 + 1.0e-13)
		&& child_0->num.dbl_value > (10.0 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (10.0 + 1.0e-13)
		&& child_0->num.dbl_value > (10.0 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (3.141569 + 1.0e-13)
		&& child_0->num.dbl_value > (3.141569 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		child_0->num.dbl_value < (1000.0 + 1.0e-13)
		&& child_0->num.dbl_value > (1000.0 - 1.0e-13));
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_26(RJson *j) {
	mu_assert_eq (j->type, R_JSON_STRING, "string type");
	mu_assert_streq (j->str_value, "", "string value");
	return MU_PASSED;
}

static int check_expected_27(RJson *j) {
	RJson *child_0, *child_1;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 2, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "some", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "utf-8", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "strings", "object child key");
	mu_assert_eq (child_0->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (child_0->children.count, 3, "array size");
	child_1 = child_0->children.first;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "\xd0\xad\xd1\x82\xd0\xbe", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "\xd1\x80\xd1\x83\xd1\x81\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9", "string value");
	child_1 = child_1->next;
	mu_assert_notnull (child_1, "array child");
	mu_assert_null (child_1->key, "array child key");
	mu_assert_eq (child_1->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_1->str_value, "\xd1\x82\xd0\xb5\xd0\xba\xd1\x81\xd1\x82", "string value");
	child_1 = child_1->next;
	mu_assert_null (child_1, "last child null");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_28(RJson *j) {
	mu_assert_eq (j->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (j->num.u_value, 2009, "integer value");
	return MU_PASSED;
}

static int check_expected_29(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 1, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "U+10ABCD", "object child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\xf4\x8a\xaf\x8d", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_30(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 11, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 1, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 2, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 3, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 4, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 5, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 6, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 7, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 123456789, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, -123456789, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 2147483647, "integer value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, -2147483647, "integer value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_31(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 1, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\xd0\x94\xd0\xb0 \xd0\x9c\xd1 \xd0\x95\xd0\xb1\xd0\xb0 \xd0\x9c\xd0\xb0\xd0\xb9\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_32(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 1, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "bad thing", "object child key");
	mu_assert_eq (child_0->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (child_0->num.u_value, 10, "integer value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_35(RJson *j) {
	mu_assert_eq (j->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		j->num.dbl_value < (1000.0 + 1.0e-13)
		&& j->num.dbl_value > (1000.0 - 1.0e-13));
	return MU_PASSED;
}

static int check_expected_36(RJson *j) {
	mu_assert_eq (j->type, R_JSON_DOUBLE, "double type");
	mu_assert ("double value",
		j->num.dbl_value < (10.0 + 1.0e-13)
		&& j->num.dbl_value > (10.0 - 1.0e-13));
	return MU_PASSED;
}

static int check_expected_37(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_OBJECT, "object type");
	mu_assert_eq (j->children.count, 3, "object size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "boolean, true", "object child key");
	mu_assert_eq (child_0->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_0->num.u_value, 1, "boolean value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "boolean, false", "object child key");
	mu_assert_eq (child_0->type, R_JSON_BOOLEAN, "boolean type");
	mu_assert_eq (child_0->num.u_value, 0, "boolean value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "object child");
	mu_assert_notnull (child_0->key, "object child key not null");
	mu_assert_streq (child_0->key, "null", "object child key");
	mu_assert_eq (child_0->type, R_JSON_NULL, "null type");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_38(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 1, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\n foo / bar \x0d\x0c\\\xef\xbf\xbf\t\x08\"\\ and you can't escape thi"
		"\\s", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_39(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 3, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\n foo / bar \x0d\x0c\\\xef\xbf\xbf\t\x08\"\\", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\"and this string has an escape at the beginning", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "and this string has no escapes", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_40(RJson *j) {
	mu_assert_eq (j->type, R_JSON_STRING, "string type");
	mu_assert_streq (j->str_value, "la di dah.  this is a string, and I can do this, \n, but not this\n", "string value");
	return MU_PASSED;
}

static int check_expected_43(RJson *j) {
	mu_assert_eq (j->type, R_JSON_INTEGER, "integer type");
	mu_assert_eq (j->num.u_value, 123, "integer value");
	return MU_PASSED;
}

static int check_expected_45(RJson *j) {
	RJson *child_0;
	mu_assert_eq (j->type, R_JSON_ARRAY, "array type");
	mu_assert_eq (j->children.count, 4, "array size");
	child_0 = j->children.first;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\xd0\x94\xd0\xb0", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\xd0\x9c\xd1\x83", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\xd0\x95\xd0\xb1\xd0\xb0", "string value");
	child_0 = child_0->next;
	mu_assert_notnull (child_0, "array child");
	mu_assert_null (child_0->key, "array child key");
	mu_assert_eq (child_0->type, R_JSON_STRING, "string type");
	mu_assert_streq (child_0->str_value, "\xd0\x9c\xd0\xb0\xd0\xb9\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0", "string value");
	child_0 = child_0->next;
	mu_assert_null (child_0, "last child null");
	return MU_PASSED;
}

static int check_expected_46(RJson *j) {
	mu_assert_eq (j->type, R_JSON_STRING, "string type");
	mu_assert_streq (j->str_value, "foobar", "string value");
	return MU_PASSED;
}

static int check_expected_48(RJson *j) {
	mu_assert_eq (j->type, R_JSON_STRING, "string type");
	mu_assert_streq (j->str_value, "\xd0\x9f\xd1\x80\xd0\xbe\xd0\xb2\xd0\xb5\xd1\x80\xd0\xba\xd0\xb0", "string value");
	return MU_PASSED;
}

static int test_pj_param_raw(void) {
	PJ *pj = pj_new ();
	mu_assert_notnull (pj, "pj_new");

	pj_a (pj);
	pj_o (pj);
	pj_ks (pj, "key1", "value1");
	pj_ko (pj, "fu");
	pj_ks (pj, "key2", "value2");
	pj_k (pj, "param");
	pj_raw (pj, "{}");
	pj_end (pj);
	pj_end (pj);
	pj_o (pj);
	pj_ks (pj, "key3", "value3");
	pj_k (pj, "key4");
	pj_raw (pj, "123");
	pj_end (pj);
	pj_end (pj);

	const char *json = pj_string (pj);
	mu_assert_notnull (json, "pj_string");
	char *copy = strdup (json);
	mu_assert_notnull (copy, "json copy");
	pj_free (pj);

	RJson *parsed = r_json_parse (copy);
	mu_assert_notnull (parsed, "parse failed");
	mu_assert_eq (parsed->type, R_JSON_ARRAY, "root type");
	mu_assert_eq (parsed->children.count, 2, "root size");

	RJson *first = parsed->children.first;
	mu_assert_notnull (first, "first element");
	mu_assert_null (first->key, "first element key");
	mu_assert_eq (first->type, R_JSON_OBJECT, "first element type");
	mu_assert_eq (first->children.count, 2, "first element size");

	RJson *entry = first->children.first;
	mu_assert_notnull (entry, "key1 entry");
	mu_assert_notnull (entry->key, "key1 name");
	mu_assert_streq (entry->key, "key1", "key1 name");
	mu_assert_eq (entry->type, R_JSON_STRING, "key1 type");
	mu_assert_streq (entry->str_value, "value1", "key1 value");

	entry = entry->next;
	mu_assert_notnull (entry, "fu entry");
	mu_assert_notnull (entry->key, "fu name");
	mu_assert_streq (entry->key, "fu", "fu name");
	mu_assert_eq (entry->type, R_JSON_OBJECT, "fu type");
	mu_assert_eq (entry->children.count, 2, "fu size");

	RJson *fu_child = entry->children.first;
	mu_assert_notnull (fu_child, "key2 entry");
	mu_assert_notnull (fu_child->key, "key2 name");
	mu_assert_streq (fu_child->key, "key2", "key2 name");
	mu_assert_eq (fu_child->type, R_JSON_STRING, "key2 type");
	mu_assert_streq (fu_child->str_value, "value2", "key2 value");

	fu_child = fu_child->next;
	mu_assert_notnull (fu_child, "param entry");
	mu_assert_notnull (fu_child->key, "param name");
	mu_assert_streq (fu_child->key, "param", "param name");
	mu_assert_eq (fu_child->type, R_JSON_OBJECT, "param type");
	mu_assert_eq (fu_child->children.count, 0, "param size");
	mu_assert_null (fu_child->children.first, "param children");

	fu_child = fu_child->next;
	mu_assert_null (fu_child, "fu tail");

	RJson *second = first->next;
	mu_assert_notnull (second, "second element");
	mu_assert_null (second->key, "second element key");
	mu_assert_eq (second->type, R_JSON_OBJECT, "second element type");
	mu_assert_eq (second->children.count, 2, "second element size");

	RJson *second_entry = second->children.first;
	mu_assert_notnull (second_entry, "key3 entry");
	mu_assert_notnull (second_entry->key, "key3 name");
	mu_assert_streq (second_entry->key, "key3", "key3 name");
	mu_assert_eq (second_entry->type, R_JSON_STRING, "key3 type");
	mu_assert_streq (second_entry->str_value, "value3", "key3 value");

	second_entry = second_entry->next;
	mu_assert_notnull (second_entry, "key4 entry");
	mu_assert_notnull (second_entry->key, "key4 name");
	mu_assert_streq (second_entry->key, "key4", "key4 name");
	mu_assert_eq (second_entry->type, R_JSON_INTEGER, "key4 type");
	mu_assert_eq (second_entry->num.u_value, 123, "key4 value");

	second_entry = second_entry->next;
	mu_assert_null (second_entry, "second tail");

	second = second->next;
	mu_assert_null (second, "array tail");

	r_json_free (parsed);
	free (copy);
	mu_end;
}

JsonTest tests[] = {
	{ // 0
		"    {\n      \"some-int\": 195,\n      \"array1\": [ 3, 5.1, -7, \"nin"
		"e\", /*11,*/ true, false, \"last\" ],\n      \"array2\":[\"/*\",\"*/\""
		"],\n      \"some-bool\": true,\n      \"other-bool\": false,\n      \""
		"some-dbl\": -1e-4,\n      \"some-null\": null,\n      \"hello\": \"wor"
		"ld!\",\n      \"str1\": \"//\",\n      \"str2\": \"\\\\\",\n      \"st"
		"r3\": \"text /*text*/ text\",\n      \"str4\": \"\\\\text\\\\\",\n    "
		"  \"str5\": \"\\?text\\?\",\n      \"str\\t6\\\\\": \"text\\ntext\\tte"
		"xt\",\n      \"str7\": \"text\\u1234text\\u5678\",\n      //\"other\":"
		" \"/OTHER/\",\n      \"obj\": {\"KEY\":\"VAL\", \"obj\":{\"KEY\":\"VAL"
		"\"}}\n    }\n",
		check_expected_0
	}, { // 1
		"\"unterminated string",
		NULL
	}, { // 2
		"{\"key\":\"val\"",
		NULL
	}, { // 3
		"[ \"unterminated \\string\\\" ]\n",
		NULL
	}, { // 4
		"// array\n[1,2,3,\"last\"]",
		check_expected_4
	}, { // 5
		"\"string value\"\n",
		check_expected_5
	}, { // 6
		"true",
		check_expected_6
	}, { // 7
		"-1e-2",
		check_expected_7
	}, { // 8
		"null",
		check_expected_8
	}, { // 9
		"{ \"glossary\": { /* you */ \"title\": /**/ \"example glossary\", /*sh"
		"ould*/\"GlossDiv\": { \"title\": /*never*/\"S\", /*ever*/\"GlossList\""
		": [ { \"ID\": \"SGML\", \"SortAs\": \"SGML\", \"GlossTerm\": \"Standar"
		"d Generalized Markup Language\", \"Acronym\": \"SGML\", \"Abbrev\": \""
		"ISO 8879:1986\", \"GlossDef\": \"A meta-markup language, used to creat"
		"e markup languages such as DocBook.\", /*see*/\"GlossSeeAlso\":/*comin"
		"g*/[/*out*/\"GML\"/*of*/,/*the*/\"XML\"/*parser!*/, \"markup\"] /*hey*"
		"/}/*ho*/]/*hey*/}/*ho*/} }  // and the parser won't even get this far,"
		" so chill.  /* hah!\n",
		check_expected_9
	}, { // 10
		"{\n  \"this\": \"is\", // ignore this\n  \"really\": \"simple\",\n  /*"
		" ignore\nthis\ntoo * / \n** //\n(/\n******/\n  \"json\": \"right?\"\n}"
		"\n",
		check_expected_10
	}, { // 11
		"falsex\n",
		check_expected_11
	}, { // 12
		"{ \"123\":\n",
		NULL
	}, { // 13
		"1221 21\n",
		check_expected_13
	}, { // 14
		"\n{}\n{}\n",
		check_expected_14
	}, { // 15
		"[",
		NULL
	}, { // 16
		"{\n",
		NULL
	}, { // 17
		"[ \"foo\", \"bar\"\n",
		NULL
	}, { // 18
		"]\n",
		NULL
	}, { // 19
		"[\"foo\",\n \"bar\", \"baz\",\n true,false,null,{\"key\":\"value\"},\n"
		" [null,null,null,[]],\n \"\\n\\r\\\\\"\n]\n",
		check_expected_19
	}, { // 20
		"[ 100000000000000000000000000000, -100000000000000000000000000000, \"e"
		"nd\" ]\n",
		NULL
	}, { // 21
		"[\"this\",\"is\",\"what\",\"should\",\"be\",\n \"a happy bit of json\""
		",\n \"but someone, misspelled \\\"true\\\"\", ture,\n \"who says JSON "
		"is easy for humans to generate?\"]\n",
		NULL
	}, { // 22
		"/* This string contains Unicode surrogate \xf0\x90\x8c\x82 both in UTF"
		"-8 and escaped */ \"\xf0\x90\x8c\x82\\u004d\\u0430\\u4e8c\\ud800\\udf0"
		"2\"\n",
		check_expected_22
	}, { // 23
		"{ \"glossary\": { \"title\": \"example glossary\", \"GlossDiv\": { \"t"
		"itle\": \"S\", \"GlossList\": [ { \"ID\": \"SGML\", \"SortAs\": \"SGML"
		"\", \"GlossTerm\": \"Standard Generalized Markup Language\", \"Acronym"
		"\": \"SGML\", \"Abbrev\": \"ISO 8879:1986\", \"GlossDef\": \"A meta-ma"
		"rkup language, used to create markup languages such as DocBook.\", \"G"
		"lossSeeAlso\": [\"GML\", \"XML\", \"markup\"] } ] } } }\n",
		check_expected_23
	}, { // 24
		"[0.00011999999999999999, 6E-06, 6E-06, 1E-06, 1E-06]\n",
		check_expected_24
	}, { // 25
		"[ 0.1e2, 1e1, 3.141569, 10000000000000e-10]\n",
		check_expected_25
	}, { // 26
		"\"\"\n",
		check_expected_26
	}, { // 27
		"{\"some\":\"utf-8\", \"strings\":[\"\xd0\xad\xd1\x82\xd0\xbe\",\"\xd1"
		"\x80\xd1\x83\xd1\x81\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9\",\"\xd1\x82\xd0"
		"\xb5\xd0\xba\xd1\x81\xd1\x82\"]}",
		check_expected_27
	}, { // 28
		"2009-10-20@20:38:21.539575\n",
		check_expected_28
	}, { // 29
		"{ \"U+10ABCD\": \"\xf4\x8a\xaf\x8d\" }\n\n",
		check_expected_29
	}, { // 30
		"[ 1,2,3,4,5,6,7,\n  123456789 , -123456789,\n  2147483647, -2147483647"
		" ]\n",
		check_expected_30
	}, { // 31
		"/* invalid utf-8 */ [\"\xd0\x94\xd0\xb0 \xd0\x9c\xd1 \xd0\x95\xd0\xb1"
		"\xd0\xb0 \xd0\x9c\xd0\xb0\xd0\xb9\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0\"]\n",
		check_expected_31
	}, { // 32
		"{ \"bad thing\": 010 }\n",
		check_expected_32
	}, { // 33
		"[\n\t\t\"foo\", true,\n\t\ttrue, \"blue\",\n\t\t\"baby where are you?"
		"\", \"oh boo hoo!\",\n        - \n]\n\n",
		NULL
	}, { // 34
		"}\n",
		NULL
	}, { // 35
		"10.e2\n",
		check_expected_35
	}, { // 36
		"10e\n",
		check_expected_36
	}, { // 37
		"{\n\t\"boolean, true\": true,\n\t\"boolean, false\": false,\n\t\"null"
		"\": null\n}\n",
		check_expected_37
	}, { // 38
		"[\"\\n foo \\/ bar \\r\\f\\\\\\uffff\\t\\b\\\"\\\\ and you can't escap"
		"e thi\\s\"]\n",
		check_expected_38
	}, { // 39
		"[\"\\n foo \\/ bar \\r\\f\\\\\\uffff\\t\\b\\\"\\\\\",\n \"\\\"and this"
		" string has an escape at the beginning\",\n \"and this string has no e"
		"scapes\" ]\n",
		check_expected_39
	}, { // 40
		"\"la di dah.  this is a string, and I can do this, \\n, but not this\n"
		"\"\n",
		check_expected_40
	}, { // 41
		"/*",
		NULL
	}, { // 42
		"/*abc /",
		NULL
	}, { // 43
		"/*/\\*/ 123",
		check_expected_43
	}, { // 44
		"/*/ 123",
		NULL
	}, { // 45
		"[\"\\u0414\\u0430\",\n \"\\u041c\\u0443\",\n \"\\u0415\\u0431\\u0430\""
		",\n \"\\u041c\\u0430\\u0439\\u043a\\u0430\\u0442\\u0430\"]\n",
		check_expected_45
	}, { // 46
		"\"\\u0066\\u006f\\u006f\\u0062\\u0061\\u0072\"\n",
		check_expected_46
	}, { // 47
		"/* invalid unicode surrogate */ \"\\ud800\"\n",
		NULL
	}, { // 48
		"\"\\u041F\\u0440\\u043E\\u0432\\u0435\\u0440\\u043a\\u0430\"",
		check_expected_48
	}, { // 49
		"\"\\u04FG\"",
		NULL
	}, { // 50
		"\"\\u0",
		NULL
	}, { // 51
		"\"\\u04\"",
		NULL
	}, { // 52
		"{,}\n",
		NULL
	}, { // 53
		"[,]\n",
		NULL
	}, { // 54
		"[{}{}]\n",
		NULL
	}, { // 55
		"[42,/*nope*/,1337]\n",
		NULL
	}, { // 56
		"{\"hello\":42,/*stuff*/,\"invalid\":123}\n",
		NULL
	}
};

static int test_json(int test_number, char *input, int(*check)(RJson *j)) {
	RJson *json = r_json_parse (input);
	if (!check) {
		mu_assert_null (json, "parse failure expected");
	} else {
		mu_assert_notnull (json, "parse failed");
		if (!check (json)) {
			return MU_ERR;
		}
		r_json_free (json);
	}
	mu_end;
}

static int all_tests(void) {
	size_t i;

	mu_run_test_named (test_pj_param_raw, "test_pj_param_raw");
	for (i = 1; i < sizeof (tests) / sizeof (tests[0]); i++) {
		char *input = strdup (tests[i].json);
		char testname[256];
		snprintf (testname, sizeof(testname), "test_json (%u)", (unsigned int)i);
		mu_run_test_named (test_json, testname, i, input, tests[i].check);
		free (input);
	}
	return tests_passed != tests_run;
}

int main(void) {
	return all_tests ();
}
