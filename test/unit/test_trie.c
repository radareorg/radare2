#include <r_util.h>
#include "minunit.h"

static int freed_values;

static void count_free(void *value) {
	freed_values++;
	free (value);
}

static bool insert_string(RTrie *trie, const char *key, const char *value) {
	char *copy = strdup (value);
	if (!copy) {
		return false;
	}
	if (!r_trie_insert (trie, r_strs_from (key), copy)) {
		free (copy);
		return false;
	}
	return true;
}

static bool test_r_trie_find(void) {
	RTrie *trie = r_trie_new (free);
	mu_assert_true (insert_string (trie, "a", "a"), "insert a");
	mu_assert_true (insert_string (trie, "af", "af"), "insert af");
	mu_assert_true (insert_string (trie, "afl", "afl"), "insert afl");
	mu_assert_true (insert_string (trie, "agn", "agn"), "insert agn");
	mu_assert_true (insert_string (trie, "pdj", "pdj"), "insert pdj");
	mu_assert_eq (r_trie_size (trie), 5, "trie size");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("afl")), "afl", "find afl");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("agn")), "agn", "find agn");
	mu_assert_null (r_trie_find (trie, r_strs_from ("afl?")), "exact lookup rejects suffix");
	mu_assert_null (r_trie_find (trie, r_strs_from ("pd")), "exact lookup rejects prefix");
	r_trie_free (trie);
	mu_end;
}

static bool test_r_trie_longest_prefix(void) {
	RTrie *trie = r_trie_new (free);
	insert_string (trie, "a", "a");
	insert_string (trie, "af", "af");
	insert_string (trie, "afl", "afl");
	insert_string (trie, "agn", "agn");
	insert_string (trie, "pdj", "pdj");
	size_t matched = 0;
	mu_assert_streq (r_trie_find_longest_prefix (trie, r_strs_from ("afl?"), &matched), "afl", "longest afl prefix");
	mu_assert_eq (matched, 3, "afl prefix length");
	mu_assert_streq (r_trie_find_longest_prefix (trie, r_strs_from ("afx"), &matched), "af", "longest af prefix");
	mu_assert_eq (matched, 2, "af prefix length");
	mu_assert_null (r_trie_find_longest_prefix (trie, r_strs_from ("px"), &matched), "missing prefix");
	mu_assert_eq (matched, 0, "missing prefix length");
	r_trie_free (trie);
	mu_end;
}

static bool test_r_trie_split_order(void) {
	RTrie *trie = r_trie_new (free);
	insert_string (trie, "foobar", "foobar");
	insert_string (trie, "foo", "foo");
	insert_string (trie, "food", "food");
	insert_string (trie, "f", "f");
	insert_string (trie, "bar", "bar");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("foobar")), "foobar", "find split descendant");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("foo")), "foo", "find split parent");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("food")), "food", "find split sibling");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("f")), "f", "find split root");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("bar")), "bar", "find sorted root sibling");
	r_trie_free (trie);
	mu_end;
}

static bool test_r_trie_replace_take_delete(void) {
	freed_values = 0;
	RTrie *trie = r_trie_new (count_free);
	insert_string (trie, "foo", "old");
	insert_string (trie, "foobar", "foobar");
	insert_string (trie, "foobaz", "foobaz");
	insert_string (trie, "foo", "new");
	mu_assert_eq (freed_values, 1, "replacement frees old value");
	mu_assert_eq (r_trie_size (trie), 3, "replacement keeps size");
	char *taken = r_trie_take (trie, r_strs_from ("foo"));
	mu_assert_streq (taken, "new", "take returns value");
	free (taken);
	mu_assert_eq (r_trie_size (trie), 2, "take decrements size");
	mu_assert_null (r_trie_find (trie, r_strs_from ("foo")), "taken key is absent");
	mu_assert_true (r_trie_delete (trie, r_strs_from ("foobar")), "delete existing key");
	mu_assert_false (r_trie_delete (trie, r_strs_from ("foobar")), "delete missing key");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("foobaz")), "foobaz", "sibling survives compaction");
	r_trie_free (trie);
	mu_assert_eq (freed_values, 3, "delete and trie free release remaining values");
	mu_end;
}

static bool test_r_trie_empty_and_binary_keys(void) {
	RTrie *trie = r_trie_new (free);
	const char binary_key[] = { 'a', 0, 'b' };
	mu_assert_true (insert_string (trie, "", "root"), "insert empty key");
	char *binary_value = strdup ("binary");
	mu_assert_true (r_trie_insert (trie, r_strs_from_len (binary_key, sizeof (binary_key)), binary_value), "insert binary key");
	mu_assert_streq (r_trie_find (trie, r_strs_from_len (binary_key, sizeof (binary_key))), "binary", "find binary key");
	size_t matched = 0;
	mu_assert_streq (r_trie_find_longest_prefix (trie, r_strs_from ("none"), &matched), "root", "empty key is fallback");
	mu_assert_eq (matched, 0, "empty key prefix length");
	r_trie_free (trie);
	mu_end;
}

static bool test_r_trie_compact_chain(void) {
	RTrie *trie = r_trie_new (free);
	insert_string (trie, "a", "a");
	insert_string (trie, "ab", "ab");
	insert_string (trie, "abc", "abc");
	mu_assert_true (r_trie_delete (trie, r_strs_from ("a")), "delete chain root");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("ab")), "ab", "find after first chain compaction");
	mu_assert_true (r_trie_delete (trie, r_strs_from ("ab")), "delete compacted parent");
	mu_assert_streq (r_trie_find (trie, r_strs_from ("abc")), "abc", "find after second chain compaction");
	mu_assert_true (r_trie_delete (trie, r_strs_from ("abc")), "delete final chain value");
	mu_assert_eq (r_trie_size (trie), 0, "empty after chain deletion");
	r_trie_free (trie);
	mu_end;
}

static int all_tests(void) {
	mu_run_test (test_r_trie_find);
	mu_run_test (test_r_trie_longest_prefix);
	mu_run_test (test_r_trie_split_order);
	mu_run_test (test_r_trie_replace_take_delete);
	mu_run_test (test_r_trie_empty_and_binary_keys);
	mu_run_test (test_r_trie_compact_chain);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests ();
}
