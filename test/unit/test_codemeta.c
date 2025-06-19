#include <r_util.h>
#include <r_vector.h>
#include <r_core.h>
#include <r_cons.h>

#include "minunit.h"

static char *r_codemeta_print_json(RCodeMeta *code) {
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_o (pj);
	pj_ks (pj, "code", code->code);

	pj_k (pj, "annotations");
	pj_a (pj);

	char *type_str;
	RCodeMetaItem *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		pj_o (pj);
		pj_kn (pj, "start", (ut64)annotation->start);
		pj_kn (pj, "end", (ut64)annotation->end);
		switch (annotation->type) {
		case R_CODEMETA_TYPE_OFFSET:
			pj_ks (pj, "type", "offset");
			pj_kn (pj, "offset", annotation->offset.offset);
			break;
		case R_CODEMETA_TYPE_FUNCTION_NAME:
			pj_ks (pj, "type", "function_name");
			pj_ks (pj, "name", annotation->reference.name);
			pj_kn (pj, "offset", annotation->reference.offset);
			break;
		case R_CODEMETA_TYPE_GLOBAL_VARIABLE:
			pj_ks (pj, "type", "global_variable");
			pj_kn (pj, "offset", annotation->reference.offset);
			break;
		case R_CODEMETA_TYPE_CONSTANT_VARIABLE:
			pj_ks (pj, "type", "constant_variable");
			pj_kn (pj, "offset", annotation->reference.offset);
			break;
		case R_CODEMETA_TYPE_LOCAL_VARIABLE:
			pj_ks (pj, "type", "local_variable");
			pj_ks (pj, "name", annotation->variable.name);
			break;
		case R_CODEMETA_TYPE_FUNCTION_PARAMETER:
			pj_ks (pj, "type", "function_parameter");
			pj_ks (pj, "name", annotation->variable.name);
			break;
		case R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT:
			pj_ks (pj, "type", "syntax_highlight");
			type_str = NULL;
			switch (annotation->syntax_highlight.type) {
			case R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD:
				type_str = "keyword";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_COMMENT:
				type_str = "comment";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE:
				type_str = "datatype";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME:
				type_str = "function_name";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER:
				type_str = "function_parameter";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE:
				type_str = "local_variable";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE:
				type_str = "constant_variable";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE:
				type_str = "global_variable";
				break;
			}
			if (type_str) {
				pj_ks (pj, "syntax_highlight", type_str);
			}
			break;
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}

static RCodeMetaItem make_code_annotation(int st, int en, RCodeMetaItemType typec,
	ut64 offset, RSyntaxHighlightType types) {
	RCodeMetaItem annotation = {0};
	annotation.start = st;
	annotation.end = en;
	annotation.type = typec;
	if (annotation.type == R_CODEMETA_TYPE_OFFSET) {
		annotation.offset.offset = offset;
	}
	if (annotation.type == R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT) {
		annotation.syntax_highlight.type = types;
	}
	return annotation;
}

static RCodeMetaItem make_variable_annotation(int st, int en, RCodeMetaItemType typec, const char *name) {
	RCodeMetaItem annotation = {0};
	annotation.start = st;
	annotation.end = en;
	annotation.type = typec;
	annotation.variable.name = strdup (name);
	return annotation;
}

static RCodeMetaItem make_reference_annotation(int st, int en, RCodeMetaItemType typec, ut64 offset, const char *name) {
	RCodeMetaItem annotation = {0};
	annotation.start = st;
	annotation.end = en;
	annotation.type = typec;
	annotation.reference.offset = offset;
	if (annotation.type == R_CODEMETA_TYPE_FUNCTION_NAME) {
		annotation.reference.name = strdup (name);
	} else {
		annotation.reference.name = NULL;
	}
	return annotation;
}

static RVector *get_some_code_annotation_for_add(void) {
	RVector *test_annotations = r_vector_new (sizeof (RCodeMetaItem), NULL, NULL);
	RCodeMetaItem annotation;
	r_vector_init (test_annotations, sizeof (RCodeMetaItem), NULL, NULL);
	annotation = make_code_annotation (1, 2, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	annotation = make_code_annotation (1, 5, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	return test_annotations;
}

static RVector *get_some_annotations_for_in(void) {
	RVector *test_annotations = r_vector_new (sizeof (RCodeMetaItem), NULL, NULL);
	RCodeMetaItem annotation;
	annotation = make_code_annotation (1, 2, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	annotation = make_code_annotation (1, 7, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	annotation = make_code_annotation (9, 11, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);

	// For offset = 11, indices expected = 3, 4, 5
	annotation = make_code_annotation (7, 13, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	annotation = make_code_annotation (11, 15, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	annotation = make_code_annotation (10, 16, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);
	annotation = make_code_annotation (17, 20, R_CODEMETA_TYPE_OFFSET, 32, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation);

	return test_annotations;
}

static RVector *get_annotations_for_hello_world(void) {
	RVector *test_annotations = r_vector_new (sizeof (RCodeMetaItem), NULL, NULL);
	RCodeMetaItem annotation;
	// r_vector_init (&test_annotations, sizeof (RCodeMetaItem), NULL, NULL);
	//Code Annotations for a hello world program
	annotation = make_code_annotation (1, 5, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE);
	r_vector_push (test_annotations, &annotation); //1
	annotation = make_code_annotation (6, 10, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME);
	r_vector_push (test_annotations, &annotation); //2
	annotation = make_code_annotation (11, 15, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation); //3
	annotation = make_code_annotation (23, 35, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME);
	r_vector_push (test_annotations, &annotation); //4
	annotation = make_code_annotation (36, 51, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE);
	r_vector_push (test_annotations, &annotation); //5
	annotation = make_code_annotation (23, 52, R_CODEMETA_TYPE_OFFSET, 4440, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation); //6
	annotation = make_code_annotation (58, 64, R_CODEMETA_TYPE_OFFSET, 4447, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation); //7
	annotation = make_code_annotation (58, 64, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation); //8
	annotation = make_code_annotation (58, 64, R_CODEMETA_TYPE_OFFSET, 4447, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (test_annotations, &annotation); //9

	return test_annotations;
}

static RCodeMeta *get_hello_world(void) {
	char *test_string = strdup ("\nvoid main(void)\n{\n    sym.imp.puts(\"Hello, World!\");\n    return;\n}\n");
	RCodeMeta *code = r_codemeta_new (test_string);

	RVector /*<RCodeMetaItem>*/ *test_annotations = get_annotations_for_hello_world ();
	RCodeMetaItem *annotation;
	r_vector_foreach (test_annotations, annotation) {
		r_codemeta_add_item (code, r_codemeta_item_clone (annotation));
	}

	r_vector_free (test_annotations);
	return code;
}

static RCodeMeta *get_all_context_annotated_code(void) {
	char *test_string = strdup ("\nfunc-name\nconst-var\n   global-var(\"Hello, local-var\");\n    function-param\n}\n");
	RCodeMeta *code = r_codemeta_new (test_string);
	RCodeMetaItem function_name = make_reference_annotation (1, 10, R_CODEMETA_TYPE_FUNCTION_NAME, 1234, "func-name");
	RCodeMetaItem constant_variable = make_reference_annotation (10, 19, R_CODEMETA_TYPE_CONSTANT_VARIABLE, 12345, NULL);
	RCodeMetaItem global_variable = make_reference_annotation (23, 33, R_CODEMETA_TYPE_GLOBAL_VARIABLE, 123456, NULL);
	RCodeMetaItem local_variable = make_variable_annotation (42, 51, R_CODEMETA_TYPE_LOCAL_VARIABLE, "local-var");
	RCodeMetaItem function_parameter = make_variable_annotation (59, 73, R_CODEMETA_TYPE_FUNCTION_PARAMETER, "function-param");
	r_codemeta_add_item (code, &function_name);
	r_codemeta_add_item (code, &constant_variable);
	r_codemeta_add_item (code, &global_variable);
	r_codemeta_add_item (code, &local_variable);
	r_codemeta_add_item (code, &function_parameter);
	return code;
}

static bool test_r_codemeta_new(void) {
	//Testing RAnnoatedCode->code
	char *test_string = strdup ("How are you?");
	RCodeMeta *code = r_codemeta_new (test_string);
	mu_assert_streq (code->code, test_string, "Code in RCodeMeta is not set as expected");

	// Testing RAnnoatedCode->annotations
	mu_assert_eq (code->annotations.elem_size, sizeof (RCodeMetaItem), "Code Annotations are initialized is not properly");

	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_free(void) {
	char *test_string = strdup ("How are you?");
	RCodeMeta *code = r_codemeta_new (test_string);

	RCodeMetaItem test_annotation1, test_annotation2;
	test_annotation1 = make_code_annotation (1, 2, R_CODEMETA_TYPE_OFFSET, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (&code->annotations, &test_annotation1);
	test_annotation2 = make_code_annotation (1, 5, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	r_vector_push (&code->annotations, &test_annotation2);

	// This test is only for run errors

	r_codemeta_free (code);
	mu_end;
}

static bool test_equal(RCodeMetaItem *first, RCodeMetaItem *second) { // First - Got, Second - Expected
	mu_assert_eq (first->start, second->start, "start of annotations doesn't match");
	mu_assert_eq (first->end, second->end, "end of annotations doesn't match");
	mu_assert_eq (first->type, second->type, "type of annotation doesn't match");
	if (first->type == R_CODEMETA_TYPE_OFFSET) {
		mu_assert_eq (first->offset.offset, second->offset.offset, "offset of annotations doesn't match");
		return true;
	}
	if (first->type == R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT) {
		mu_assert_eq (first->syntax_highlight.type, second->syntax_highlight.type, "syntax highlight type of offset doesn't match");
		return true;
	}
	return false;
}

static bool test_r_codemeta_add_item(void) {
	char *test_string = strdup ("abcdefghijklmnopqrtstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	RCodeMeta *code = r_codemeta_new (test_string);
	RVector /*<RCodeMetaItem>*/ *test_annotations;
	test_annotations = get_some_code_annotation_for_add ();
	RCodeMetaItem *annotation;
	r_vector_foreach (test_annotations, annotation) {
		r_codemeta_add_item (code, annotation);
	}

	//Comparing
	if (!test_equal (r_vector_index_ptr (&code->annotations, 0), r_vector_index_ptr (test_annotations, 0))) {
		return false;
	}
	if (!test_equal (r_vector_index_ptr (&code->annotations, 1), r_vector_index_ptr (test_annotations, 1))) {
		return false;
	}

	r_vector_free (test_annotations);
	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_at(void) {
	char *test_string = strdup ("abcdefghijklmnopqrtstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	RCodeMeta *code = r_codemeta_new (test_string);
	RVector /*<RCodeMetaItem>*/ *test_annotations;
	test_annotations = get_some_annotations_for_in ();

	RCodeMetaItem *annotation;
	r_vector_foreach (test_annotations, annotation) {
		r_codemeta_add_item (code, annotation);
	}

	RPVector *out = r_codemeta_at (code, 11);
	//Expecting indices = 3, 4, 5
	mu_assert_eq (out->v.len, 3, "Additional annotations found. Bad output.");
	if (!test_equal (*r_pvector_index_ptr (out, 0), r_vector_index_ptr (test_annotations, 3))) {
		return false;
	}
	if (!test_equal (*r_pvector_index_ptr (out, 1), r_vector_index_ptr (test_annotations, 4))) {
		return false;
	}
	if (!test_equal (*r_pvector_index_ptr (out, 2), r_vector_index_ptr (test_annotations, 5))) {
		return false;
	}

	r_vector_free (test_annotations);
	r_pvector_free (out);
	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_in(void) {
	char *test_string = strdup ("abcdefghijklmnopqrtstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	RCodeMeta *code = r_codemeta_new (test_string);
	RVector /*<RCodeMetaItem>*/ *test_annotations;
	test_annotations = get_some_annotations_for_in ();
	RCodeMetaItem *annotation;
	r_vector_foreach (test_annotations, annotation) {
		r_codemeta_add_item (code, annotation);
	}

	RPVector *out = r_codemeta_in (code, 7, 16);
	// Expecting indices = 2, 3, 4, 5
	mu_assert_eq (out->v.len, 4, "Additional annotations found. Bad output.");
	if (!test_equal (*r_pvector_index_ptr (out, 0), r_vector_index_ptr (test_annotations, 2))) {
		return false;
	}
	if (!test_equal (*r_pvector_index_ptr (out, 1), r_vector_index_ptr (test_annotations, 3))) {
		return false;
	}
	if (!test_equal (*r_pvector_index_ptr (out, 2), r_vector_index_ptr (test_annotations, 4))) {
		return false;
	}
	if (!test_equal (*r_pvector_index_ptr (out, 3), r_vector_index_ptr (test_annotations, 5))) {
		return false;
	}

	r_vector_free (test_annotations);
	r_pvector_free (out);
	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_line_offsets(void) {

	RCodeMeta *code = get_hello_world ();
	RVector *offsets = r_codemeta_line_offsets (code);
	mu_assert_eq (offsets->len, 6, "Number of offsets not expected");

	ut64 *off = r_vector_index_ptr (offsets, 0);
	mu_assert_eq_fmt (*off, UT64_MAX, "Unexpected offset", "%"PFMT64u);
	off = r_vector_index_ptr (offsets, 1);
	mu_assert_eq_fmt (*off, UT64_MAX, "Unexpected offset", "%"PFMT64u);
	off = r_vector_index_ptr (offsets, 2);
	mu_assert_eq_fmt (*off, UT64_MAX, "Unexpected offset", "%"PFMT64u);
	off = r_vector_index_ptr (offsets, 3);
	mu_assert_eq_fmt (*off, (ut64)4440, "Unexpected offset", "%"PFMT64u);
	off = r_vector_index_ptr (offsets, 4);
	mu_assert_eq_fmt (*off, (ut64)4447, "Unexpected offset", "%"PFMT64u);
	off = r_vector_index_ptr (offsets, 5);
	mu_assert_eq_fmt (*off, UT64_MAX, "Unexpected offset", "%"PFMT64u);

	r_vector_free (offsets);
	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_print_json(void) {
	RCodeMeta *code = get_hello_world ();
	char *expected = "{\"code\":\"\\nvoid main(void)\\n{\\n    sym.imp.puts(\\\"Hello, World!\\\");\\n    return;\\n}\\n\",\"annotations\":[{\"start\":1,\"end\":5,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"datatype\"},{\"start\":6,\"end\":10,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"function_name\"},{\"start\":11,\"end\":15,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"keyword\"},{\"start\":23,\"end\":35,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"function_name\"},{\"start\":36,\"end\":51,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"constant_variable\"},{\"start\":23,\"end\":52,\"type\":\"offset\",\"offset\":4440},{\"start\":58,\"end\":64,\"type\":\"offset\",\"offset\":4447},{\"start\":58,\"end\":64,\"type\":\"syntax_highlight\",\"syntax_highlight\":\"keyword\"},{\"start\":58,\"end\":64,\"type\":\"offset\",\"offset\":4447}]}";
	char *actual = r_codemeta_print_json (code);
	mu_assert_streq (actual, expected, "pdgj OUTPUT DOES NOT MATCH");

	free (actual);
	r_codemeta_free (code);
	mu_end;
}

/**
 * @brief Tests JSON output for all context related annotations
 */
static bool test_r_codemeta_print_json_context_annotations(void) {
	RCodeMeta *code = get_all_context_annotated_code ();
	char *expected = "{\"code\":\"\\nfunc-name\\nconst-var\\n   global-var(\\\"Hello, local-var\\\");\\n    function-param\\n}\\n\",\"annotations\":[{\"start\":1,\"end\":10,\"type\":\"function_name\",\"name\":\"func-name\",\"offset\":1234},{\"start\":10,\"end\":19,\"type\":\"constant_variable\",\"offset\":12345},{\"start\":23,\"end\":33,\"type\":\"global_variable\",\"offset\":123456},{\"start\":42,\"end\":51,\"type\":\"local_variable\",\"name\":\"local-var\"},{\"start\":59,\"end\":73,\"type\":\"function_parameter\",\"name\":\"function-param\"}]}";
	char *actual = r_codemeta_print_json (code);
	mu_assert_streq (actual, expected, "r_codemeta_print_json() output doesn't match with the expected output");
	free (actual);
	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_print(void) {
	RCodeMeta *code = get_hello_world ();
	char *actual;
	//Checking without line offset
	char *expected_first = "\n"
			       "void main(void)\n"
			       "{\n"
			       "    sym.imp.puts(\"Hello, World!\");\n"
			       "    return;\n"
			       "}\n";
	RCons *cons = r_cons_new ();
	r_kons_push (cons);
	r_codemeta_print (code, NULL);
	actual = strdup (r_cons_get_buffer ());
	r_kons_pop (cons);
	mu_assert_streq (actual, expected_first, "pdg OUTPUT DOES NOT MATCH");
	r_kons_pop (cons);

	//Checking with offset - pdgo
	RVector *offsets = r_codemeta_line_offsets (code);
	char *expected_second = "                  |\n"
				"                  |void main(void)\n"
				"                  |{\n"
				"    0x00001158    |    sym.imp.puts(\"Hello, World!\");\n"
				"    0x0000115f    |    return;\n"
				"                  |}\n";
	r_codemeta_print (code, offsets);
	free (actual);
	actual = strdup (r_cons_get_buffer ());
	r_kons_pop (cons);
	mu_assert_streq (actual, expected_second, "pdgo OUTPUT DOES NOT MATCH");
	r_kons_pop (cons);

	r_kons_free (cons);
	free (actual);
	r_vector_free (offsets);
	r_codemeta_free (code);
	mu_end;
}

static bool test_r_codemeta_print_comment_cmds(void) {
	RCodeMeta *code = get_hello_world ();
	char *actual;
	char *expected = "CCu base64:c3ltLmltcC5wdXRzKCJIZWxsbywgV29ybGQhIik= @ 0x1158\n"
			 "CCu base64:cmV0dXJu @ 0x115f\n";
	RCons *cons = r_cons_new ();
	r_kons_push (cons);
	r_codemeta_print_comment_cmds (code);
	actual = strdup (r_cons_get_buffer ());
	r_kons_pop (cons);
	mu_assert_streq (actual, expected, "pdg* OUTPUT DOES NOT MATCH");

	r_kons_free (cons);
	free (actual);
	r_codemeta_free (code);
	mu_end;
}

/**
 * @brief Tests functions r_codemeta_item_is_variable(), r_codemeta_item_is_reference(), and r_codemeta_itemfree()
 */
static bool test_r_codemeta_itemfree_and_is_annotation_type_functions(void) {
	// Making all types of annotations
	RCodeMetaItem offset = make_code_annotation (58, 64, R_CODEMETA_TYPE_OFFSET, 4447, R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD);
	RCodeMetaItem syntax_highlight = make_code_annotation (1, 5, R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT, 123, R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE);
	RCodeMetaItem local_variable = make_variable_annotation (1, 2, R_CODEMETA_TYPE_LOCAL_VARIABLE, "RADARE2");
	RCodeMetaItem function_parameter = make_variable_annotation (4, 10, R_CODEMETA_TYPE_LOCAL_VARIABLE, "Iaito");
	RCodeMetaItem function_name = make_reference_annotation (10, 12, R_CODEMETA_TYPE_FUNCTION_NAME, 123513, "test_function");
	RCodeMetaItem global_variable = make_reference_annotation (10, 12, R_CODEMETA_TYPE_GLOBAL_VARIABLE, 1234234, NULL);
	RCodeMetaItem constant_variable = make_reference_annotation (21, 200, R_CODEMETA_TYPE_CONSTANT_VARIABLE, 12342314, NULL);
	// Test r_codemeta_item_is_variable()
	char *error_message = "r_codemeta_item_is_variable() result doesn't match with the expected output";
	mu_assert_true (r_codemeta_item_is_variable (&local_variable), error_message);
	mu_assert_true (r_codemeta_item_is_variable (&function_parameter), error_message);
	mu_assert_false (r_codemeta_item_is_variable (&function_name), error_message);
	mu_assert_false (r_codemeta_item_is_variable (&global_variable), error_message);
	mu_assert_false (r_codemeta_item_is_variable (&constant_variable), error_message);
	mu_assert_false (r_codemeta_item_is_variable (&offset), error_message);
	mu_assert_false (r_codemeta_item_is_variable (&syntax_highlight), error_message);
	// Test r_codemeta_item_is_reference()
	error_message = "r_codemeta_item_is_reference() result doesn't match with the expected output";
	mu_assert_true (r_codemeta_item_is_reference (&function_name), error_message);
	mu_assert_true (r_codemeta_item_is_reference (&global_variable), error_message);
	mu_assert_true (r_codemeta_item_is_reference (&constant_variable), error_message);
	mu_assert_false (r_codemeta_item_is_reference (&local_variable), error_message);
	mu_assert_false (r_codemeta_item_is_reference (&function_parameter), error_message);
	mu_assert_false (r_codemeta_item_is_reference (&offset), error_message);
	mu_assert_false (r_codemeta_item_is_reference (&syntax_highlight), error_message);
	// Free dynamically allocated memory for annotations.
	// This is also supposed to be a test of r_codemeta_itemfree() for run errors.
	r_codemeta_item_fini (&local_variable);
	r_codemeta_item_fini (&function_parameter);
	r_codemeta_item_fini (&function_name);
	r_codemeta_item_fini (&global_variable);
	r_codemeta_item_fini (&constant_variable);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_codemeta_new);
	mu_run_test (test_r_codemeta_free);
	mu_run_test (test_r_codemeta_add_item);
	mu_run_test (test_r_codemeta_at);
	mu_run_test (test_r_codemeta_in);
	mu_run_test (test_r_codemeta_line_offsets);
	mu_run_test (test_r_codemeta_print_json);
	mu_run_test (test_r_codemeta_print_json_context_annotations);
	mu_run_test (test_r_codemeta_print);
	mu_run_test (test_r_codemeta_print_comment_cmds);
	mu_run_test (test_r_codemeta_itemfree_and_is_annotation_type_functions);
	return tests_passed != tests_run;
}

int main (int argc, char **argv) {
	return all_tests ();
}
