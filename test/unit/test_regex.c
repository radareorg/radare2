#include <r_regex.h>
#include "minunit.h"

// === Lifecycle tests ===

static int test_new_free(void) {
	RRegex *rx = r_regex_new ("hello", "");
	mu_assert_notnull (rx, "r_regex_new basic");
	r_regex_free (rx);

	rx = r_regex_new ("hello", "e");
	mu_assert_notnull (rx, "r_regex_new extended");
	r_regex_free (rx);

	rx = r_regex_new ("hello", "ei");
	mu_assert_notnull (rx, "r_regex_new extended+icase");
	r_regex_free (rx);

	// free NULL should not crash
	r_regex_free (NULL);
	mu_end;
}

static int test_init_fini(void) {
	RRegex rx = { 0 };
	int rc = r_regex_init (&rx, "hello", R_REGEX_EXTENDED);
	mu_assert_eq (rc, 0, "r_regex_init should succeed");
	r_regex_fini (&rx);

	rc = r_regex_init (&rx, "hello", R_REGEX_NOSUB);
	mu_assert_eq (rc, 0, "r_regex_init nosub");
	r_regex_fini (&rx);
	mu_end;
}

// Issue #16549: r_regex_init/r_regex_new must not leak the prior compilation
// when called on an already-initialized RRegex. Catches a regression only when
// the test binary is built with LeakSanitizer (e.g. `make asan` in test/unit).
static int test_double_init(void) {
	// Pattern A: r_regex_init twice on the same struct, no fini between.
	RRegex rx = { 0 };
	int rc = r_regex_init (&rx, "hello", R_REGEX_EXTENDED);
	mu_assert_eq (rc, 0, "first init succeeded");
	rc = r_regex_init (&rx, "world", R_REGEX_EXTENDED);
	mu_assert_eq (rc, 0, "second init succeeded");
	r_regex_fini (&rx);

	// Pattern B: r_regex_new then r_regex_init on the returned pointer.
	RRegex *rxp = r_regex_new ("hello", "");
	mu_assert_notnull (rxp, "new succeeded");
	rc = r_regex_init (rxp, "world", R_REGEX_EXTENDED);
	mu_assert_eq (rc, 0, "init-after-new succeeded");
	r_regex_free (rxp);

	mu_end;
}

static int test_invalid_pattern(void) {
	// unbalanced parens
	RRegex *rx = r_regex_new ("(hello", "e");
	mu_assert_null (rx, "unbalanced paren should fail");

	// unbalanced brackets
	rx = r_regex_new ("[abc", "e");
	mu_assert_null (rx, "unbalanced bracket should fail");

	// bad repetition
	rx = r_regex_new ("*abc", "e");
	mu_assert_null (rx, "leading * should fail in extended");

	// bad brace
	rx = r_regex_new ("a{3,1}", "e");
	mu_assert_null (rx, "bad brace range should fail");

	mu_end;
}

// === Flags parsing ===

static int test_flags(void) {
	int f;
	f = r_regex_flags ("");
	mu_assert_eq (f, 0, "empty flags");

	f = r_regex_flags ("e");
	mu_assert_eq (f & R_REGEX_EXTENDED, R_REGEX_EXTENDED, "flag e");

	f = r_regex_flags ("i");
	mu_assert_eq (f & R_REGEX_ICASE, R_REGEX_ICASE, "flag i");

	f = r_regex_flags ("s");
	mu_assert_eq (f & R_REGEX_NOSUB, R_REGEX_NOSUB, "flag s");

	f = r_regex_flags ("n");
	mu_assert_eq (f & R_REGEX_NEWLINE, R_REGEX_NEWLINE, "flag n");

	f = r_regex_flags ("N");
	mu_assert_eq (f & R_REGEX_NOSPEC, R_REGEX_NOSPEC, "flag N");

	f = r_regex_flags ("ei");
	mu_assert_eq (f & R_REGEX_EXTENDED, R_REGEX_EXTENDED, "flags ei (e)");
	mu_assert_eq (f & R_REGEX_ICASE, R_REGEX_ICASE, "flags ei (i)");

	mu_end;
}

// === Basic literal matching ===

static int test_literal_match(void) {
	mu_assert_true (r_regex_match ("hello", "e", "hello world"), "literal match");
	mu_assert_true (r_regex_match ("hello", "e", "say hello"), "literal in middle");
	mu_assert_false (r_regex_match ("hello", "e", "HELLO"), "case sensitive no match");
	mu_assert_false (r_regex_match ("hello", "e", "goodbye"), "literal no match");
	mu_assert_true (r_regex_match ("hello", "e", "hello"), "exact match");
	mu_end;
}

static int test_empty_string(void) {
	// empty pattern fails to compile in this engine (R_REGEX_EMPTY)
	mu_assert_false (r_regex_match ("", "e", "anything"), "empty pattern fails to compile");
	// non-empty pattern vs empty string
	mu_assert_false (r_regex_match ("hello", "e", ""), "non-empty pattern vs empty string");
	mu_end;
}

// === Case insensitive ===

static int test_icase(void) {
	mu_assert_true (r_regex_match ("hello", "ei", "HELLO"), "icase upper");
	mu_assert_true (r_regex_match ("hello", "ei", "Hello"), "icase mixed");
	mu_assert_true (r_regex_match ("hello", "ei", "hello"), "icase lower");
	mu_assert_true (r_regex_match ("HELLO", "ei", "hello"), "icase pattern upper");
	mu_assert_true (r_regex_match ("[A-Z]+", "ei", "hello"), "icase char class");
	mu_end;
}

// === Anchors ===

static int test_anchors(void) {
	// BOL
	mu_assert_true (r_regex_match ("^hello", "e", "hello world"), "^ at start");
	mu_assert_false (r_regex_match ("^hello", "e", "say hello"), "^ not at start");

	// EOL
	mu_assert_true (r_regex_match ("world$", "e", "hello world"), "$ at end");
	mu_assert_false (r_regex_match ("world$", "e", "world hello"), "$ not at end");

	// Both
	mu_assert_true (r_regex_match ("^hello$", "e", "hello"), "^...$ exact");
	mu_assert_false (r_regex_match ("^hello$", "e", "hello world"), "^...$ not exact");
	mu_assert_false (r_regex_match ("^hello$", "e", "say hello"), "^...$ prefix mismatch");

	mu_end;
}

// === Dot ===

static int test_dot(void) {
	mu_assert_true (r_regex_match ("h.llo", "e", "hello"), "dot matches char");
	mu_assert_true (r_regex_match ("h.llo", "e", "hallo"), "dot matches other char");
	mu_assert_true (r_regex_match ("h.llo", "e", "h9llo"), "dot matches digit");
	mu_assert_false (r_regex_match ("h.llo", "e", "hllo"), "dot requires char");
	mu_assert_true (r_regex_match ("...", "e", "abc"), "three dots");
	mu_assert_false (r_regex_match ("....", "e", "ab"), "four dots vs two chars");
	mu_end;
}

// === Quantifiers ===

static int test_star(void) {
	mu_assert_true (r_regex_match ("ab*c", "e", "ac"), "star zero");
	mu_assert_true (r_regex_match ("ab*c", "e", "abc"), "star one");
	mu_assert_true (r_regex_match ("ab*c", "e", "abbc"), "star two");
	mu_assert_true (r_regex_match ("ab*c", "e", "abbbc"), "star three");
	mu_assert_true (r_regex_match (".*", "e", ""), "star dot empty");
	mu_assert_true (r_regex_match (".*", "e", "anything"), "star dot anything");
	mu_end;
}

static int test_plus(void) {
	mu_assert_false (r_regex_match ("ab+c", "e", "ac"), "plus zero fails");
	mu_assert_true (r_regex_match ("ab+c", "e", "abc"), "plus one");
	mu_assert_true (r_regex_match ("ab+c", "e", "abbc"), "plus two");
	mu_assert_true (r_regex_match ("ab+c", "e", "abbbc"), "plus three");
	mu_end;
}

static int test_question(void) {
	mu_assert_true (r_regex_match ("ab?c", "e", "ac"), "question zero");
	mu_assert_true (r_regex_match ("ab?c", "e", "abc"), "question one");
	mu_assert_false (r_regex_match ("ab?c", "e", "abbc"), "question two fails");
	mu_end;
}

static int test_braces(void) {
	mu_assert_false (r_regex_match ("a{3}", "e", "aa"), "brace exact too few");
	mu_assert_true (r_regex_match ("a{3}", "e", "aaa"), "brace exact match");
	mu_assert_true (r_regex_match ("a{3}", "e", "aaaa"), "brace exact with extra");

	mu_assert_false (r_regex_match ("a{2,4}", "e", "a"), "brace range too few");
	mu_assert_true (r_regex_match ("a{2,4}", "e", "aa"), "brace range min");
	mu_assert_true (r_regex_match ("a{2,4}", "e", "aaa"), "brace range mid");
	mu_assert_true (r_regex_match ("a{2,4}", "e", "aaaa"), "brace range max");
	mu_assert_true (r_regex_match ("a{2,4}", "e", "aaaaa"), "brace range over");

	mu_assert_true (r_regex_match ("a{2,}", "e", "aa"), "brace min only");
	mu_assert_true (r_regex_match ("a{2,}", "e", "aaaaaaa"), "brace min only many");
	mu_assert_false (r_regex_match ("a{2,}", "e", "a"), "brace min only too few");

	mu_end;
}

// === Alternation ===

static int test_alternation(void) {
	mu_assert_true (r_regex_match ("cat|dog", "e", "cat"), "alt first");
	mu_assert_true (r_regex_match ("cat|dog", "e", "dog"), "alt second");
	mu_assert_false (r_regex_match ("cat|dog", "e", "fish"), "alt neither");

	mu_assert_true (r_regex_match ("(eax|ebx|ecx)", "e", "mov eax"), "alt three first");
	mu_assert_true (r_regex_match ("(eax|ebx|ecx)", "e", "mov ebx"), "alt three second");
	mu_assert_true (r_regex_match ("(eax|ebx|ecx)", "e", "mov ecx"), "alt three third");
	mu_assert_false (r_regex_match ("(eax|ebx|ecx)", "e", "mov edx"), "alt three none");

	mu_end;
}

// === Character classes ===

static int test_char_class(void) {
	mu_assert_true (r_regex_match ("[abc]", "e", "a"), "class a");
	mu_assert_true (r_regex_match ("[abc]", "e", "b"), "class b");
	mu_assert_true (r_regex_match ("[abc]", "e", "c"), "class c");
	mu_assert_false (r_regex_match ("[abc]", "e", "d"), "class not d");

	// negation
	mu_assert_false (r_regex_match ("[^abc]", "e", "a"), "neg class a");
	mu_assert_true (r_regex_match ("[^abc]", "e", "d"), "neg class d");

	// range
	mu_assert_true (r_regex_match ("[a-z]", "e", "m"), "range a-z");
	mu_assert_false (r_regex_match ("[a-z]", "e", "M"), "range a-z not upper");
	mu_assert_true (r_regex_match ("[0-9]", "e", "5"), "range 0-9");
	mu_assert_false (r_regex_match ("[0-9]", "e", "a"), "range 0-9 not alpha");

	// combined
	mu_assert_true (r_regex_match ("[a-zA-Z0-9]", "e", "Z"), "combined range upper");
	mu_assert_true (r_regex_match ("[a-zA-Z0-9]", "e", "z"), "combined range lower");
	mu_assert_true (r_regex_match ("[a-zA-Z0-9]", "e", "9"), "combined range digit");

	mu_end;
}

static int test_posix_classes(void) {
	mu_assert_true (r_regex_match ("[[:digit:]]", "e", "5"), "posix digit");
	mu_assert_false (r_regex_match ("[[:digit:]]", "e", "a"), "posix digit no match");

	mu_assert_true (r_regex_match ("[[:alpha:]]", "e", "a"), "posix alpha lower");
	mu_assert_true (r_regex_match ("[[:alpha:]]", "e", "Z"), "posix alpha upper");
	mu_assert_false (r_regex_match ("[[:alpha:]]", "e", "5"), "posix alpha no digit");

	mu_assert_true (r_regex_match ("[[:alnum:]]", "e", "a"), "posix alnum alpha");
	mu_assert_true (r_regex_match ("[[:alnum:]]", "e", "5"), "posix alnum digit");
	mu_assert_false (r_regex_match ("[[:alnum:]]", "e", "!"), "posix alnum no punct");

	mu_assert_true (r_regex_match ("[[:space:]]", "e", " "), "posix space");
	mu_assert_true (r_regex_match ("[[:space:]]", "e", "\t"), "posix tab");
	mu_assert_false (r_regex_match ("[[:space:]]", "e", "a"), "posix space no alpha");

	mu_assert_true (r_regex_match ("[[:upper:]]", "e", "A"), "posix upper");
	mu_assert_false (r_regex_match ("[[:upper:]]", "e", "a"), "posix upper no lower");

	mu_assert_true (r_regex_match ("[[:lower:]]", "e", "a"), "posix lower");
	mu_assert_false (r_regex_match ("[[:lower:]]", "e", "A"), "posix lower no upper");

	mu_end;
}

// === Grouping and subexpressions ===

static int test_groups(void) {
	RRegex *rx = r_regex_new ("(foo)(bar)", "e");
	mu_assert_notnull (rx, "compile groups");

	RRegexMatch pm[3];
	int rc = r_regex_exec (rx, "foobar", 3, pm, 0);
	mu_assert_eq (rc, 0, "groups match");

	// full match
	mu_assert_eq ((int)pm[0].rm_so, 0, "full match start");
	mu_assert_eq ((int)pm[0].rm_eo, 6, "full match end");

	// group 1
	mu_assert_eq ((int)pm[1].rm_so, 0, "group1 start");
	mu_assert_eq ((int)pm[1].rm_eo, 3, "group1 end");

	// group 2
	mu_assert_eq ((int)pm[2].rm_so, 3, "group2 start");
	mu_assert_eq ((int)pm[2].rm_eo, 6, "group2 end");

	r_regex_free (rx);
	mu_end;
}

static int test_nested_groups(void) {
	RRegex *rx = r_regex_new ("((a)(b))", "e");
	mu_assert_notnull (rx, "compile nested groups");

	RRegexMatch pm[4];
	int rc = r_regex_exec (rx, "ab", 4, pm, 0);
	mu_assert_eq (rc, 0, "nested groups match");

	// full match
	mu_assert_eq ((int)pm[0].rm_so, 0, "nested full start");
	mu_assert_eq ((int)pm[0].rm_eo, 2, "nested full end");

	// outer group
	mu_assert_eq ((int)pm[1].rm_so, 0, "nested outer start");
	mu_assert_eq ((int)pm[1].rm_eo, 2, "nested outer end");

	// inner group 1
	mu_assert_eq ((int)pm[2].rm_so, 0, "nested inner1 start");
	mu_assert_eq ((int)pm[2].rm_eo, 1, "nested inner1 end");

	// inner group 2
	mu_assert_eq ((int)pm[3].rm_so, 1, "nested inner2 start");
	mu_assert_eq ((int)pm[3].rm_eo, 2, "nested inner2 end");

	r_regex_free (rx);
	mu_end;
}

// === NOSPEC flag (literal matching) ===

static int test_nospec(void) {
	// with NOSPEC, special chars are treated literally
	mu_assert_true (r_regex_match ("a.b", "N", "a.b"), "nospec dot literal");
	mu_assert_false (r_regex_match ("a.b", "N", "axb"), "nospec dot not wild");
	mu_assert_true (r_regex_match ("a*b", "N", "a*b"), "nospec star literal");
	mu_assert_false (r_regex_match ("a*b", "N", "ab"), "nospec star not quant");
	mu_end;
}

// === NOTBOL / NOTEOL flags ===

static int test_notbol_noteol(void) {
	RRegex *rx = r_regex_new ("^hello", "e");
	mu_assert_notnull (rx, "compile ^hello");

	// normal: should match at start
	int rc = r_regex_exec (rx, "hello world", 0, NULL, 0);
	mu_assert_eq (rc, 0, "bol matches at start");

	// NOTBOL: should not match even at start
	rc = r_regex_exec (rx, "hello world", 0, NULL, R_REGEX_NOTBOL);
	mu_assert_eq (rc, R_REGEX_NOMATCH, "notbol suppresses ^");

	r_regex_free (rx);

	rx = r_regex_new ("world$", "e");
	mu_assert_notnull (rx, "compile world$");

	rc = r_regex_exec (rx, "hello world", 0, NULL, 0);
	mu_assert_eq (rc, 0, "eol matches at end");

	rc = r_regex_exec (rx, "hello world", 0, NULL, R_REGEX_NOTEOL);
	mu_assert_eq (rc, R_REGEX_NOMATCH, "noteol suppresses $");

	r_regex_free (rx);
	mu_end;
}

// === STARTEND flag ===

static int test_startend(void) {
	RRegex *rx = r_regex_new ("hello", "e");
	mu_assert_notnull (rx, "compile hello for startend");

	RRegexMatch pm[1];
	// search only in substring [4, 9) of "say hello there"
	pm[0].rm_so = 4;
	pm[0].rm_eo = 9;
	int rc = r_regex_exec (rx, "say hello there", 1, pm, R_REGEX_STARTEND);
	mu_assert_eq (rc, 0, "startend finds match in range");
	mu_assert_eq ((int)pm[0].rm_so, 4, "startend match start");
	mu_assert_eq ((int)pm[0].rm_eo, 9, "startend match end");

	// search in range that doesn't contain "hello"
	pm[0].rm_so = 0;
	pm[0].rm_eo = 3;
	rc = r_regex_exec (rx, "say hello there", 1, pm, R_REGEX_STARTEND);
	mu_assert_eq (rc, R_REGEX_NOMATCH, "startend no match outside range");

	r_regex_free (rx);
	mu_end;
}

// === r_regex_check ===

static int test_check(void) {
	RRegex *rx = r_regex_new ("hello", "e");
	mu_assert_notnull (rx, "compile for check");
	// r_regex_check returns 0 on match (wraps r_regex_exec)
	mu_assert_eq (r_regex_check (rx, "hello world"), 0, "check match");
	mu_assert_eq (r_regex_check (rx, "goodbye"), 1, "check no match");
	r_regex_free (rx);
	mu_end;
}

// r_regex_run is declared but not implemented, skip testing it

// === r_regex_match_list ===

static int test_match_list(void) {
	RRegex *rx = r_regex_new ("([a-z]+)", "e");
	mu_assert_notnull (rx, "compile for match_list");

	RList *matches = r_regex_match_list (rx, "hello world");
	mu_assert_notnull (matches, "match_list returns list");
	mu_assert_eq (r_list_length (matches), 2, "match_list length");
	mu_assert_streq (r_list_get_n (matches, 0), "hello", "match_list first");
	mu_assert_streq (r_list_get_n (matches, 1), "world", "match_list second");

	r_list_free (matches);
	r_regex_free (rx);
	mu_end;
}

// === Error messages ===

static int test_error_messages(void) {
	RRegex rx = { 0 };
	int rc = r_regex_init (&rx, "hello", R_REGEX_EXTENDED);
	mu_assert_eq (rc, 0, "init for error test");

	char *err = r_regex_error (&rx, R_REGEX_NOMATCH);
	mu_assert_notnull (err, "error message not null");
	mu_assert_streq (err, "regexec() failed to match", "nomatch message");
	free (err);

	err = r_regex_error (&rx, R_REGEX_BADPAT);
	mu_assert_notnull (err, "badpat error not null");
	free (err);

	err = r_regex_error (&rx, R_REGEX_EPAREN);
	mu_assert_notnull (err, "eparen error not null");
	free (err);

	err = r_regex_error (&rx, R_REGEX_EBRACK);
	mu_assert_notnull (err, "ebrack error not null");
	free (err);

	err = r_regex_error (&rx, R_REGEX_ESPACE);
	mu_assert_notnull (err, "espace error not null");
	free (err);

	r_regex_fini (&rx);
	mu_end;
}

// === Escaping and special chars ===

static int test_escaping(void) {
	// literal dot via backslash in extended mode
	mu_assert_true (r_regex_match ("a\\.b", "e", "a.b"), "escaped dot matches dot");
	mu_assert_false (r_regex_match ("a\\.b", "e", "axb"), "escaped dot no wildcard");

	// in basic mode \ ( \) are group delimiters, not literal parens
	// so \ (b\) captures "b", and "ab" matches
	mu_assert_true (r_regex_match ("a\\(b\\)", "", "ab"), "basic group parens");
	// literal parens in extended mode
	mu_assert_true (r_regex_match ("a\\(b\\)", "e", "a(b)"), "escaped parens extended");

	// literal star
	mu_assert_true (r_regex_match ("a\\*b", "e", "a*b"), "escaped star");
	mu_assert_false (r_regex_match ("a\\*b", "e", "ab"), "escaped star no quant");

	// literal plus
	mu_assert_true (r_regex_match ("a\\+b", "e", "a+b"), "escaped plus");

	// literal brackets
	mu_assert_true (r_regex_match ("a\\[b\\]", "e", "a[b]"), "escaped brackets");

	mu_end;
}

// === Basic vs Extended syntax ===

static int test_basic_vs_extended(void) {
	// In basic mode, ( ) are literal, \ ( \) are grouping
	mu_assert_true (r_regex_match ("(abc)", "", "(abc)"), "basic parens literal");
	// In extended mode, ( ) are grouping
	mu_assert_true (r_regex_match ("(abc)", "e", "abc"), "extended parens group");

	// In basic mode, + and? are literal
	mu_assert_true (r_regex_match ("a+", "", "a+"), "basic plus literal");
	// In extended mode, + is quantifier
	mu_assert_true (r_regex_match ("a+", "e", "aaa"), "extended plus quantifier");

	mu_end;
}

// === Newline handling ===

static int test_newline(void) {
	// without NEWLINE, . matches everything except newline by default
	// and ^ / $ only match at string start/end
	const char *text = "hello\nworld";

	mu_assert_true (r_regex_match ("hello", "e", text), "newline find hello");
	mu_assert_true (r_regex_match ("world", "e", text), "newline find world");

	// with NEWLINE flag, ^ matches after \n and $ matches before \n
	mu_assert_true (r_regex_match ("^world", "en", text), "newline ^ after newline");
	mu_assert_true (r_regex_match ("hello$", "en", text), "newline $ before newline");

	mu_end;
}

// === Backreferences ===

static int test_backrefs(void) {
	// basic mode: \ ( \) for groups, \1 for backreference
	mu_assert_true (r_regex_match ("\\(a\\)\\1", "", "aa"), "backref basic aa");
	mu_assert_false (r_regex_match ("\\(a\\)\\1", "", "ab"), "backref basic ab");

	mu_end;
}

// === Word boundary (if supported by \b or special operators) ===

// === Complex patterns (real-world-ish) ===

static int test_hex_pattern(void) {
	mu_assert_true (r_regex_match ("0x[0-9a-fA-F]+", "e", "addr 0xdeadbeef"), "hex pattern");
	mu_assert_false (r_regex_match ("0x[0-9a-fA-F]+", "e", "no hex here"), "hex pattern no match");
	mu_assert_true (r_regex_match ("0x[0-9a-fA-F]+", "e", "0x0"), "hex pattern 0x0");
	mu_end;
}

static int test_asm_pattern(void) {
	// match mov instructions with register operands
	mu_assert_true (r_regex_match ("mov (e[abcd]x)", "e", "mov eax"), "asm mov eax");
	mu_assert_true (r_regex_match ("mov (e[abcd]x)", "e", "mov ebx"), "asm mov ebx");
	mu_assert_false (r_regex_match ("mov (e[abcd]x)", "e", "mov esi"), "asm mov esi no match");

	// match addresses
	mu_assert_true (r_regex_match ("\\[.*\\]", "e", "mov [ebp+4], eax"), "asm memory ref");
	mu_end;
}

static int test_libc_match(void) {
	mu_assert_true (r_regex_match (".*libc[.-]", "e", "/usr/lib/libc.so.6"), "libc name");
	mu_assert_true (r_regex_match ("\\d.\\d\\d", "e", "2.38"), "libc version");
	mu_end;
}

// === Multiple matches via STARTEND iteration ===

static int test_iterate_matches(void) {
	RRegex *rx = r_regex_new ("[0-9]+", "e");
	mu_assert_notnull (rx, "compile for iteration");

	const char *text = "abc 123 def 456 ghi";
	int len = strlen (text);
	RRegexMatch pm[1];
	int count = 0;

	pm[0].rm_so = 0;
	pm[0].rm_eo = len;
	while (r_regex_exec (rx, text, 1, pm, R_REGEX_STARTEND) == 0) {
		count++;
		if (pm[0].rm_eo >= len) {
			break;
		}
		int next = pm[0].rm_eo;
		pm[0].rm_so = next;
		pm[0].rm_eo = len;
	}
	mu_assert_eq (count, 2, "found two number matches");

	r_regex_free (rx);
	mu_end;
}

// === Stress / edge cases ===

static int test_long_pattern(void) {
	// pattern with many alternatives
	mu_assert_true (r_regex_match ("(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p)", "e", "p"), "many alternatives");
	mu_assert_false (r_regex_match ("(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p)", "e", "q"), "many alternatives no match");
	mu_end;
}

static int test_repetition_combinations(void) {
	// nested quantifiers: (a+)+ is valid in extended
	// just make sure it doesn't crash
	RRegex *rx = r_regex_new ("(a+)+b", "e");
	if (rx) {
		int rc = r_regex_exec (rx, "aaab", 0, NULL, 0);
		mu_assert_eq (rc, 0, "nested quantifiers match");
		rc = r_regex_exec (rx, "b", 0, NULL, 0);
		mu_assert_eq (rc, R_REGEX_NOMATCH, "nested quantifiers no a");
		r_regex_free (rx);
	}
	mu_end;
}

static int test_special_chars_in_class(void) {
	// ] as first char in class
	mu_assert_true (r_regex_match ("[]abc]", "e", "]"), "class ] first");
	mu_assert_true (r_regex_match ("[]abc]", "e", "a"), "class ] first then a");

	// - at start of class
	mu_assert_true (r_regex_match ("[-abc]", "e", "-"), "class - first");

	// ^ not at start is literal
	mu_assert_true (r_regex_match ("[a^b]", "e", "^"), "class ^ not first");

	mu_end;
}

static int test_nsub(void) {
	RRegex *rx = r_regex_new ("(a)(b)(c)", "e");
	mu_assert_notnull (rx, "compile 3 groups");
	mu_assert_eq ((int)rx->re_nsub, 3, "nsub is 3");
	r_regex_free (rx);

	rx = r_regex_new ("abc", "e");
	mu_assert_notnull (rx, "compile no groups");
	mu_assert_eq ((int)rx->re_nsub, 0, "nsub is 0");
	r_regex_free (rx);

	rx = r_regex_new ("((a)(b))", "e");
	mu_assert_notnull (rx, "compile nested groups");
	mu_assert_eq ((int)rx->re_nsub, 3, "nsub nested is 3");
	r_regex_free (rx);

	mu_end;
}

int main(int argc, char **argv) {
	// lifecycle
	mu_run_test (test_new_free);
	mu_run_test (test_init_fini);
	mu_run_test (test_double_init);
	mu_run_test (test_invalid_pattern);
	mu_run_test (test_flags);

	// basic matching
	mu_run_test (test_literal_match);
	mu_run_test (test_empty_string);
	mu_run_test (test_icase);
	mu_run_test (test_anchors);
	mu_run_test (test_dot);

	// quantifiers
	mu_run_test (test_star);
	mu_run_test (test_plus);
	mu_run_test (test_question);
	mu_run_test (test_braces);

	// constructs
	mu_run_test (test_alternation);
	mu_run_test (test_char_class);
	mu_run_test (test_posix_classes);
	mu_run_test (test_groups);
	mu_run_test (test_nested_groups);
	mu_run_test (test_escaping);
	mu_run_test (test_basic_vs_extended);
	mu_run_test (test_backrefs);
	mu_run_test (test_newline);

	// flags
	mu_run_test (test_nospec);
	mu_run_test (test_notbol_noteol);
	mu_run_test (test_startend);

	// api
	mu_run_test (test_check);
	// mu_run_test (test_run); // r_regex_run not implemented
	mu_run_test (test_match_list);
	mu_run_test (test_error_messages);
	mu_run_test (test_nsub);

	// patterns
	mu_run_test (test_hex_pattern);
	mu_run_test (test_asm_pattern);
	mu_run_test (test_libc_match);
	mu_run_test (test_iterate_matches);

	// edge cases
	mu_run_test (test_long_pattern);
	mu_run_test (test_repetition_combinations);
	mu_run_test (test_special_chars_in_class);

	return 0;
}
