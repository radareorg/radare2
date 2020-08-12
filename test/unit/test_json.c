/* radare - LGPL - Copyright 2020 - thestr4ng3r, Yaroslav Stavnichiy */
/* r_json based on nxjson by Yaroslav Stavnichiy */

#include <r_util/r_json.h>
#include <r_util/r_strbuf.h>
#include "minunit.h"

typedef struct json_test_t {
	const char *json;
	const char *expected;
} JsonTest;

JsonTest tests[] = {
	{ // 0
		"    {\n      \"some-int\": 195,\n      \"array1\": [ 3, 5.1, -7, \"nin"
		"e\", /*11*/, true, false, \"last\" ],\n      \"array2\":[\"/*\",\"*/\""
		"],\n      \"some-bool\": true,\n      \"other-bool\": false,\n      \""
		"some-dbl\": -1e-4,\n      \"some-null\": null,\n      \"hello\": \"wor"
		"ld!\",\n      \"str1\": \"//\",\n      \"str2\": \"\\\\\",\n      \"st"
		"r3\": \"text /*text*/ text\",\n      \"str4\": \"\\\\text\\\\\",\n    "
		"  \"str5\": \"\\?text\\?\",\n      \"str\\t6\\\\\": \"text\\ntext\\tte"
		"xt\",\n      \"str7\": \"text\\u1234text\\u5678\",\n      //\"other\":"
		" \"/OTHER/\",\n      \"obj\": {\"KEY\":\"VAL\", \"obj\":{\"KEY\":\"VAL"
		"\"}}\n    }\n",
		"{\n  some-int:195\n  array1:[\n    3\n    5.100000e+00\n    -7\n    \""
		"nine\"\n    T\n    F\n    \"last\"\n  ]\n  array2:[\n    \"/*\"\n    "
		"\"*/\"\n  ]\n  some-bool:T\n  other-bool:F\n  some-dbl:-1.000000e-04\n"
		"  some-null:null\n  hello:\"world!\"\n  str1:\"//\"\n  str2:\"\\\"\n  "
		"str3:\"text /*text*/ text\"\n  str4:\"\\text\\\"\n  str5:\"\\?text\\?"
		"\"\n  str\t6\\:\"text\ntext\ttext\"\n  str7:\"text\xe1\x88\xb4text\xe5"
		"\x99\xb8\"\n  obj:{\n    KEY:\"VAL\"\n    obj:{\n      KEY:\"VAL\"\n  "
		"  }\n  }\n}\n"
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
		"[\n  1\n  2\n  3\n  \"last\"\n]\n"
	}, { // 5
		"\"string value\"\n",
		"\"string value\"\n"
	}, { // 6
		"true",
		"T\n"
	}, { // 7
		"-1e-2",
		"-1.000000e-02\n"
	}, { // 8
		"null",
		"null\n"
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
		"{\n  glossary:{\n    title:\"example glossary\"\n    GlossDiv:{\n     "
		" title:\"S\"\n      GlossList:[\n        {\n          ID:\"SGML\"\n   "
		"       SortAs:\"SGML\"\n          GlossTerm:\"Standard Generalized Mar"
		"kup Language\"\n          Acronym:\"SGML\"\n          Abbrev:\"ISO 887"
		"9:1986\"\n          GlossDef:\"A meta-markup language, used to create "
		"markup languages such as DocBook.\"\n          GlossSeeAlso:[\n       "
		"     \"GML\"\n            \"XML\"\n            \"markup\"\n          ]"
		"\n        }\n      ]\n    }\n  }\n}\n"
	}, { // 10
		"{\n  \"this\": \"is\", // ignore this\n  \"really\": \"simple\",\n  /*"
		" ignore\nthis\ntoo * / \n** //\n(/\n******/\n  \"json\": \"right?\"\n}"
		"\n",
		"{\n  this:\"is\"\n  really:\"simple\"\n  json:\"right?\"\n}\n"
	}, { // 11
		"falsex",
		"F\n"
	}, { // 12
		"{ \"123\":\n",
		NULL
	}, { // 13
		"1221 21\n",
		"1221\n"
	}, { // 14
		"\n{}\n{}\n",
		"{\n}\n"
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
		"[\n  \"foo\"\n  \"bar\"\n  \"baz\"\n  T\n  F\n  null\n  {\n    key:\"v"
		"alue\"\n  }\n  [\n    null\n    null\n    null\n    [\n    ]\n  ]\n  "
		"\"\n\x0d\\\"\n]\n"
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
		"\"\xf0\x90\x8c\x82M\xd0\xb0\xe4\xba\x8c\xf0\x90\x8c\x82\"\n"
	}, { // 23
		"{ \"glossary\": { \"title\": \"example glossary\", \"GlossDiv\": { \"t"
		"itle\": \"S\", \"GlossList\": [ { \"ID\": \"SGML\", \"SortAs\": \"SGML"
		"\", \"GlossTerm\": \"Standard Generalized Markup Language\", \"Acronym"
		"\": \"SGML\", \"Abbrev\": \"ISO 8879:1986\", \"GlossDef\": \"A meta-ma"
		"rkup language, used to create markup languages such as DocBook.\", \"G"
		"lossSeeAlso\": [\"GML\", \"XML\", \"markup\"] } ] } } }\n",
		"{\n  glossary:{\n    title:\"example glossary\"\n    GlossDiv:{\n     "
		" title:\"S\"\n      GlossList:[\n        {\n          ID:\"SGML\"\n   "
		"       SortAs:\"SGML\"\n          GlossTerm:\"Standard Generalized Mar"
		"kup Language\"\n          Acronym:\"SGML\"\n          Abbrev:\"ISO 887"
		"9:1986\"\n          GlossDef:\"A meta-markup language, used to create "
		"markup languages such as DocBook.\"\n          GlossSeeAlso:[\n       "
		"     \"GML\"\n            \"XML\"\n            \"markup\"\n          ]"
		"\n        }\n      ]\n    }\n  }\n}\n"
	}, { // 24
		"[0.00011999999999999999, 6E-06, 6E-06, 1E-06, 1E-06]\n",
		"[\n  1.200000e-04\n  6.000000e-06\n  6.000000e-06\n  1.000000e-06\n  1"
		".000000e-06\n]\n"
	}, { // 25
		"[ 0.1e2, 1e1, 3.141569, 10000000000000e-10]\n",
		"[\n  1.000000e+01\n  1.000000e+01\n  3.141569e+00\n  1.000000e+03\n]\n"
	}, { // 26
		"\"\"\n",
		"\"\"\n"
	}, { // 27
		"{\"some\":\"utf-8\", \"strings\":[\"\xd0\xad\xd1\x82\xd0\xbe\",\"\xd1"
		"\x80\xd1\x83\xd1\x81\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9\",\"\xd1\x82\xd0"
		"\xb5\xd0\xba\xd1\x81\xd1\x82\"]}",
		"{\n  some:\"utf-8\"\n  strings:[\n    \"\xd0\xad\xd1\x82\xd0\xbe\"\n  "
		"  \"\xd1\x80\xd1\x83\xd1\x81\xd1\x81\xd0\xba\xd0\xb8\xd0\xb9\"\n    \""
		"\xd1\x82\xd0\xb5\xd0\xba\xd1\x81\xd1\x82\"\n  ]\n}\n"
	}, { // 28
		"2009-10-20@20:38:21.539575\n",
		"2009\n"
	}, { // 29
		"{ \"U+10ABCD\": \"\xf4\x8a\xaf\x8d\" }\n\n",
		"{\n  U+10ABCD:\"\xf4\x8a\xaf\x8d\"\n}\n"
	}, { // 30
		"[ 1,2,3,4,5,6,7,\n  123456789 , -123456789,\n  2147483647, -2147483647"
		" ]\n",
		"[\n  1\n  2\n  3\n  4\n  5\n  6\n  7\n  123456789\n  -123456789\n  214"
		"7483647\n  -2147483647\n]\n"
	}, { // 31
		"/* invalid utf-8 */ [\"\xd0\x94\xd0\xb0 \xd0\x9c\xd1 \xd0\x95\xd0\xb1"
		"\xd0\xb0 \xd0\x9c\xd0\xb0\xd0\xb9\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0\"]\n",
		"[\n  \"\xd0\x94\xd0\xb0 \xd0\x9c\xd1 \xd0\x95\xd0\xb1\xd0\xb0 \xd0\x9c"
		"\xd0\xb0\xd0\xb9\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0\"\n]\n"
	}, { // 32
		"{ \"bad thing\": 010 }\n",
		"{\n  bad thing:8\n}\n"
	}, { // 33
		"[\n\t\t\"foo\", true,\n\t\ttrue, \"blue\",\n\t\t\"baby where are you?"
		"\", \"oh boo hoo!\",\n        - \n]\n\n",
		NULL
	}, { // 34
		"}\n",
		NULL
	}, { // 35
		"10.e2\n",
		"1.000000e+03\n"
	}, { // 36
		"10e\n",
		"1.000000e+01\n"
	}, { // 37
		"{\n\t\"boolean, true\": true,\n\t\"boolean, false\": false,\n\t\"null"
		"\": null\n}\n",
		"{\n  boolean, true:T\n  boolean, false:F\n  null:null\n}\n"
	}, { // 38
		"[\"\\n foo \\/ bar \\r\\f\\\\\\uffff\\t\\b\\\"\\\\ and you can't escap"
		"e thi\\s\"]\n",
		"[\n  \"\n foo / bar \x0d\x0c\\\xef\xbf\xbf\t\x08\"\\ and you can't esc"
		"ape thi\\s\"\n]\n"
	}, { // 39
		"[\"\\n foo \\/ bar \\r\\f\\\\\\uffff\\t\\b\\\"\\\\\",\n \"\\\"and this"
		" string has an escape at the beginning\",\n \"and this string has no e"
		"scapes\" ]\n",
		"[\n  \"\n foo / bar \x0d\x0c\\\xef\xbf\xbf\t\x08\"\\\"\n  \"\"and this"
		" string has an escape at the beginning\"\n  \"and this string has no e"
		"scapes\"\n]\n"
	}, { // 40
		"\"la di dah.  this is a string, and I can do this, \\n, but not this\n"
		"\"\n",
		"\"la di dah.  this is a string, and I can do this, \n, but not this\n"
		"\"\n"
	}, { // 41
		"/*",
		NULL
	}, { // 42
		"/*abc /",
		NULL
	}, { // 43
		"/*/\\*/ 123",
		"123\n"
	}, { // 44
		"/*/ 123",
		NULL
	}, { // 45
		"[\"\\u0414\\u0430\",\n \"\\u041c\\u0443\",\n \"\\u0415\\u0431\\u0430\""
		",\n \"\\u041c\\u0430\\u0439\\u043a\\u0430\\u0442\\u0430\"]\n",
		"[\n  \"\xd0\x94\xd0\xb0\"\n  \"\xd0\x9c\xd1\x83\"\n  \"\xd0\x95\xd0"
		"\xb1\xd0\xb0\"\n  \"\xd0\x9c\xd0\xb0\xd0\xb9\xd0\xba\xd0\xb0\xd1\x82"
		"\xd0\xb0\"\n]\n"
	}, { // 46
		"\"\\u0066\\u006f\\u006f\\u0062\\u0061\\u0072\"\n",
		"\"foobar\"\n"
	}, { // 47
		"/* invalid unicode surrogate */ \"\\ud800\"\n",
		NULL
	}, { // 48
		"\"\\u041F\\u0440\\u043E\\u0432\\u0435\\u0440\\u043a\\u0430\"",
		"\"\xd0\x9f\xd1\x80\xd0\xbe\xd0\xb2\xd0\xb5\xd1\x80\xd0\xba\xd0\xb0\"\n"
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
		"{,}",
		NULL
	}, { // 53
		"[,]",
		NULL
	}, { // 54
		"[{}{}]",
		NULL
	}
};

static void dump(const RJson *json, RStrBuf *out, int indent) {
	if (!json) {
		return;
	}
	size_t i;
	for (i = 0; i < indent; i++) {
		r_strbuf_append (out, " ");
	}
	if (json->key) {
		r_strbuf_appendf (out, "%s:", json->key);
	}
	switch (json->type) {
	case R_JSON_NULL:
		r_strbuf_append (out, "null");
		break;
	case R_JSON_OBJECT:
		r_strbuf_append (out, "{\n");
		{
			RJson *js = json->children.first;
			for (js = json->children.first; js; js = js->next) {
				dump (js, out, indent + 2);
			}
		}
		for (i = 0; i < indent; i++) {
			r_strbuf_append (out, " ");
		}
		r_strbuf_append (out, "}");
		break;
	case R_JSON_ARRAY:
		r_strbuf_append (out, "[\n");
		{
			RJson *js = json->children.first;
			for (js = json->children.first; js; js = js->next) {
				dump (js, out, indent + 2);
			}
		}
		for (i = 0; i < indent; i++) {
			r_strbuf_append (out, " ");
		}
		r_strbuf_append (out, "]");
		break;
	case R_JSON_STRING:
		r_strbuf_appendf (out, "\"%s\"", json->str_value);
		break;
	case R_JSON_INTEGER:
		r_strbuf_appendf (out, "%"PFMT64d, json->num.s_value);
		break;
	case R_JSON_DOUBLE:
		r_strbuf_appendf (out, "%le", json->num.dbl_value);
		break;
	case R_JSON_BOOLEAN:
		r_strbuf_append (out, json->num.s_value ? "T" : "F");
		break;
	default:
		r_strbuf_append (out, "????");
		break;
	}
	r_strbuf_append (out, "\n");
}

static int test_json(int test_number, char *input, const char *expected_output) {
	RJson *json = r_json_parse (input);
	if (!expected_output) {
		mu_assert_null (json, "parse failure expected");
	} else {
		mu_assert_notnull (json, "parse failed");
		RStrBuf buf;
		r_strbuf_init (&buf);
		dump (json, &buf, 0);
		r_json_free (json);
		mu_assert_streq (r_strbuf_get (&buf), expected_output, "dump");
		r_strbuf_fini (&buf);
	}
	mu_end;
}

static int all_tests(void) {
	size_t i;
	for (i = 1; i < sizeof (tests) / sizeof (tests[0]); i++) {
		char *input = strdup (tests[i].json);
		char testname[256];
		snprintf (testname, sizeof(testname), "test_json (%u)", (unsigned int)i);
		mu_run_test_named (test_json, testname, i, input, tests[i].expected);
		free (input);
	}
	return tests_passed != tests_run;
}

int main(void) {
	return all_tests ();
}
