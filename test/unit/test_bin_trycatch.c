#include <r_bin.h>
#include "minunit.h"

#define MODEL_CAPACITY 256

typedef struct {
	RBin *bin;
	RIO *io;
	RBinFile *bf;
} TrycatchFixture;

typedef struct {
	RBinTrycatch entries[MODEL_CAPACITY];
	size_t count;
} TrycatchModel;

static RBinFile *open_buffer(RBin *bin, const char *name, const char *plugin) {
	const ut8 bytes[] = {0, 0, 0, 0};
	RBuffer *buf = r_buf_new_with_bytes (bytes, sizeof (bytes));
	RBinFileOptions opt = {0};
	r_bin_file_options_init (&opt, -1, 0, 0, 0);
	opt.filename = name;
	opt.pluginname = plugin;
	bool opened = r_bin_open_buf (bin, buf, &opt);
	r_unref (buf);
	return opened? r_bin_cur (bin): NULL;
}

static TrycatchFixture fixture_new(void) {
	TrycatchFixture fixture = { .bin = r_bin_new (), .io = r_io_new () };
	r_io_bind (fixture.io, &fixture.bin->iob);
	fixture.bf = open_buffer (fixture.bin, "trycatch-test", "null");
	return fixture;
}

static void fixture_fini(TrycatchFixture *fixture) {
	r_bin_free (fixture->bin);
	r_io_free (fixture->io);
}

static RBuffer *compressed_trycatch_elf(bool frame, bool zdebug, ut64 flags) {
	const ut8 cie[] = {
		0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x7a, 0x4c, 0x52, 0x00, 0x01, 0x78, 0x10,
		0x02, 0x03, 0x03
	};
	const ut8 lsda[] = {
		0xff, 0xff, 0x01, 0x04, 0x00, 0x01, 0x02, 0x00
	};
	const ut8 compressed_lsda[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x78, 0x9c, 0xfb, 0xff, 0x9f, 0x91, 0x85, 0x81,
		0x91, 0x89, 0x01, 0x00, 0x0f, 0x1a, 0x02, 0x07
	};
	const ut8 compressed_frame[] = {
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x78, 0x9c, 0xe3, 0x67, 0x80, 0x00, 0xc6, 0x2a,
		0x9f, 0x20, 0x06, 0xc6, 0x0a, 0x01, 0x26, 0x66,
		0x66, 0x41, 0x20, 0x57, 0x1c, 0x24, 0xd6, 0xc0,
		0xc0, 0x20, 0x00, 0xa4, 0x58, 0x40, 0x24, 0x48,
		0x50, 0x07, 0x45, 0x50, 0x01, 0x22, 0xe8, 0x88,
		0x22, 0x68, 0x00, 0x11, 0x0c, 0x43, 0x11, 0x74,
		0x80, 0x08, 0x66, 0xa3, 0x08, 0x06, 0x40, 0x04,
		0x1b, 0x50, 0x04, 0x13, 0x20, 0x82, 0x53, 0x51,
		0x04, 0x0b, 0x20, 0x82, 0xab, 0x50, 0x04, 0x1b,
		0x20, 0xce, 0x06, 0x00, 0x59, 0xa0, 0x0c, 0x26
	};
	const char names[] = "\0.eh_frame\0.gcc_except_table\0.shstrtab\0.zdebug_except_table\0.zdebug.eh_frame";
	ut8 data[1536] = {0x7f, 'E', 'L', 'F', 2, 1, 1};
	const bool compressed = zdebug || (flags & 0x800);
	r_write_le16 (data + 16, 3);
	r_write_le16 (data + 18, 62);
	r_write_le32 (data + 20, 1);
	r_write_le64 (data + 40, 0x200);
	r_write_le16 (data + 52, 64);
	r_write_le16 (data + 58, 64);
	r_write_le16 (data + 60, 11);
	r_write_le16 (data + 62, 10);
	memcpy (data + 0x40, cie, sizeof (cie));
	size_t i;
	for (i = 0; i < 8; i++) {
		ut8 *fde = data + 0x40 + sizeof (cie) + i * 21;
		r_write_le32 (fde, 17);
		r_write_le32 (fde + 4, sizeof (cie) + i * 21 + 4);
		r_write_le32 (fde + 8, 0x8000);
		r_write_le32 (fde + 12, 16);
		fde[16] = 4;
		r_write_le32 (fde + 17, 0x1000 + i * 0x1000);
	}
	if (frame && compressed) {
		memcpy (data + 0x40, compressed_frame, sizeof (compressed_frame));
	}
	const bool compressed_table = !frame && compressed;
	memcpy (data + 0x100, compressed_table? compressed_lsda: lsda,
		compressed_table? sizeof (compressed_lsda): sizeof (lsda));
	memcpy (data + 0x140, names, sizeof (names));
	for (i = 1; i <= 10; i++) {
		ut8 *section = data + 0x200 + i * 64;
		const bool table = i > 1 && i < 10;
		const bool target = frame? i == 1: table;
		ut32 name = i == 10? 29: table? (zdebug && !frame? 39: 11): (zdebug && frame? 60: 1);
		r_write_le32 (section, name);
		r_write_le32 (section + 4, i == 10? 3: 1);
		r_write_le64 (section + 8, i == 10? 0: target? flags: 2);
		r_write_le64 (section + 16, i == 10? 0: table? (i - 1) * 0x1000: 0x100000);
		r_write_le64 (section + 24, i == 10? 0x140: table? 0x100: 0x40);
		ut64 size = table? (compressed_table? sizeof (compressed_lsda): sizeof (lsda))
			: frame && compressed? sizeof (compressed_frame): sizeof (cie) + 8 * 21 + 4;
		r_write_le64 (section + 32, i == 10? sizeof (names): size);
		r_write_le64 (section + 48, 1);
	}
	return r_buf_new_with_bytes (data, sizeof (data));
}

static bool test_trycatch_compressed_sections(void) {
	const struct {
		bool frame;
		bool zdebug;
		ut64 flags;
	} cases[] = {
		{false, false, 0x802},
		{false, false, 0x800},
		{false, true, 0},
		{true, false, 0x802},
		{true, false, 0x800},
		{true, true, 0},
		{false, false, 0}
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (cases); i++) {
		TrycatchFixture fixture = fixture_new ();
		RBuffer *buf = compressed_trycatch_elf (cases[i].frame, cases[i].zdebug, cases[i].flags);
		mu_assert_notnull (buf, "create ELF with aliased exception sections");
		RBinFileOptions opt = {0};
		r_bin_file_options_init (&opt, -1, 0, 0, 0);
		opt.filename = "compressed-trycatch";
		mu_assert_true (r_bin_open_buf (fixture.bin, buf, &opt), "open ELF exception sections");
		r_unref (buf);
		RBinFile *bf = r_bin_cur (fixture.bin);
		const bool compressed = cases[i].zdebug || (cases[i].flags & 0x800);
		const RVecRBinTrycatch *entries = r_bin_file_get_trycatch (bf);
		mu_assert_notnull (entries, "load exception regions");
		// the eight sections alias the same bytes, which are walked just once
		mu_assert_eq (RVecRBinTrycatch_length (entries), compressed? 0: 1, "only uncompressed exception tables are parsed");
		if (compressed) {
			RBinSection *section;
			R_VEC_FOREACH (&bf->bo->sections_vec, section) {
				if (section->paddr == (cases[i].frame? 0x40: 0x100)) {
					mu_assert_null (section->bytes.ptr, "compressed exception sections must not be inflated or cached");
				}
			}
		}
		fixture_fini (&fixture);
	}
	mu_end;
}

static RBinTrycatch make_entry(ut64 source, ut64 id) {
	RBinTrycatch entry = {
		.source = source,
		.from = id * 16,
		.to = id * 16 + 8,
		.handler = id,
		.filter = id * 16 + 12,
		.type_filter = (st64)(id % 7) - 3,
		.kind = id % 4,
		.catch_all = id % 2
	};
	return entry;
}

static bool entries_equal(const RBinTrycatch *a, const RBinTrycatch *b) {
	return a->source == b->source && a->from == b->from && a->to == b->to
		&& a->handler == b->handler && a->filter == b->filter
		&& a->type_filter == b->type_filter && a->kind == b->kind
		&& a->catch_all == b->catch_all;
}

static bool model_insert(RBinFile *bf, TrycatchModel *model, ut64 source, ut64 id) {
	if (model->count == MODEL_CAPACITY) {
		return false;
	}
	RBinTrycatch entry = make_entry (source, id);
	if (!r_bin_trycatch_insert (bf, &entry)) {
		return false;
	}
	model->entries[model->count++] = entry;
	return true;
}

static bool model_delete(RBinFile *bf, TrycatchModel *model, size_t index) {
	if (!r_bin_trycatch_delete (bf, index)) {
		return false;
	}
	model->entries[index] = model->entries[--model->count];
	return true;
}

typedef struct {
	const RBinTrycatch *entries[MODEL_CAPACITY];
	size_t count;
	size_t visited;
	bool matched;
} ExpectedEntries;

static int compare_entries(const void *a, const void *b) {
	const RBinTrycatch *entry_a = *(const RBinTrycatch * const *)a;
	const RBinTrycatch *entry_b = *(const RBinTrycatch * const *)b;
	return (entry_a->handler > entry_b->handler) - (entry_a->handler < entry_b->handler);
}

static bool check_entry(const RBinTrycatch *entry, void *user) {
	ExpectedEntries *expected = user;
	if (expected->visited == expected->count
			|| !entries_equal (entry, expected->entries[expected->visited])) {
		expected->matched = false;
		return false;
	}
	expected->visited++;
	return true;
}

static bool query_matches(RBinFile *bf, const TrycatchModel *model, ut64 source) {
	ExpectedEntries expected = { .matched = true };
	size_t i;
	for (i = 0; i < model->count; i++) {
		if (model->entries[i].source == source) {
			expected.entries[expected.count++] = &model->entries[i];
		}
	}
	qsort ((void *)expected.entries, expected.count, sizeof (expected.entries[0]), compare_entries);
	return r_bin_trycatch_foreach (bf, source, check_entry, &expected)
		&& expected.matched && expected.visited == expected.count;
}

static bool vector_matches(RBinFile *bf, const TrycatchModel *model) {
	const RVecRBinTrycatch *entries = r_bin_file_get_trycatch (bf);
	if (!entries || RVecRBinTrycatch_length (entries) != model->count) {
		return false;
	}
	size_t i;
	for (i = 0; i < model->count; i++) {
		if (!entries_equal (RVecRBinTrycatch_at (entries, i), &model->entries[i])) {
			return false;
		}
	}
	return true;
}

static bool stop_entry(const RBinTrycatch *entry, void *user) {
	size_t *visited = user;
	(*visited)++;
	return false;
}

static bool test_trycatch_lookup(void) {
	TrycatchFixture fixture = fixture_new ();
	mu_assert_notnull (fixture.bf, "open raw binary");
	TrycatchModel model = {0};
	const ut64 sources[] = {UT64_MAX, 0, 0x100000001ULL, 0, UT64_MAX, 1};
	size_t i;
	mu_assert_true (query_matches (fixture.bf, &model, 0), "empty lookup");
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		mu_assert_true (model_insert (fixture.bf, &model, sources[i], i + 1), "insert unsorted entries");
	}
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		mu_assert_true (query_matches (fixture.bf, &model, sources[i]), "lookup interleaved full-width sources");
	}
	mu_assert_true (query_matches (fixture.bf, &model, 0x100000000ULL), "missing source sharing low bits");
	mu_assert_true (model_insert (fixture.bf, &model, 0, 7), "append to queried source");
	mu_assert_true (model_insert (fixture.bf, &model, 0x100000000ULL, 8), "insert previously missing source");
	mu_assert_true (query_matches (fixture.bf, &model, 0), "query sees append immediately");
	mu_assert_true (query_matches (fixture.bf, &model, 0x100000000ULL), "query sees new source immediately");
	mu_assert_true (vector_matches (fixture.bf, &model), "listing retains insertion order");
	size_t visited = 0;
	mu_assert_false (r_bin_trycatch_foreach (fixture.bf, 0, stop_entry, &visited), "callback can stop iteration");
	mu_assert_eq (visited, 1, "iteration stops on first matching entry");
	fixture_fini (&fixture);
	mu_end;
}

static bool test_trycatch_delete(void) {
	TrycatchFixture fixture = fixture_new ();
	mu_assert_notnull (fixture.bf, "open raw binary");
	const ut64 patterns[][8] = {
		{0, 0, 0, 0, 0, 0, 0, 0},
		{0, 1, 0, 1, 0, 1, 0, 1},
		{0, 0, 1, 1, 2, 2, 0, 0},
		{0, 1, 2, 3, 4, 5, 6, 7},
		{0, 1, 1, 1, 2, 1, 1, 0},
		{1, 1, 0, 1, 1, 0, 1, 0}
	};
	size_t pattern, removed, i, source;
	for (pattern = 0; pattern < R_ARRAY_SIZE (patterns); pattern++) {
		for (removed = 0; removed < R_ARRAY_SIZE (patterns[0]); removed++) {
			TrycatchModel model = {0};
			mu_assert_true (r_bin_trycatch_clear (fixture.bf), "clear before deletion case");
			for (i = 0; i < R_ARRAY_SIZE (patterns[0]); i++) {
				mu_assert_true (model_insert (fixture.bf, &model, patterns[pattern][i], i + 1), "populate deletion case");
			}
			mu_assert_true (query_matches (fixture.bf, &model, 0), "query before deletion");
			mu_assert_false (r_bin_trycatch_delete (fixture.bf, model.count), "reject one-past-end deletion");
			mu_assert_false (r_bin_trycatch_delete (fixture.bf, SIZE_MAX), "reject overflowing index");
			mu_assert_true (model_delete (fixture.bf, &model, removed), "delete selected first/middle/last entry");
			while (model.count) {
				mu_assert_true (vector_matches (fixture.bf, &model), "deletion moves last entry into removed slot");
				for (source = 0; source < 9; source++) {
					mu_assert_true (query_matches (fixture.bf, &model, source), "repair same/different-source links and preserve order");
				}
				mu_assert_true (model_delete (fixture.bf, &model, model.count / 2), "delete through singleton");
			}
			mu_assert_true (query_matches (fixture.bf, &model, 0), "deleted source is empty");
			mu_assert_true (vector_matches (fixture.bf, &model), "all entries deleted");
		}
	}
	fixture_fini (&fixture);
	mu_end;
}

static bool test_trycatch_ownership(void) {
	TrycatchFixture fixture = fixture_new ();
	mu_assert_notnull (fixture.bf, "open raw binary");
	char type[] = "exception";
	RBinTrycatch entry = make_entry (0, 1);
	entry.type = type;
	mu_assert_true (r_bin_trycatch_insert (fixture.bf, &entry), "insert owned type");
	type[0] = 'X';
	const RVecRBinTrycatch *entries = r_bin_file_get_trycatch (fixture.bf);
	const RBinTrycatch *stored = RVecRBinTrycatch_at (entries, 0);
	mu_assert_streq (stored->type, "exception", "input type is copied");
	while (RVecRBinTrycatch_length (entries) < R_VEC_CAPACITY (entries)) {
		mu_assert_true (r_bin_trycatch_insert (fixture.bf, &entry), "fill vector capacity");
	}
	size_t old_count = RVecRBinTrycatch_length (entries);
	stored = RVecRBinTrycatch_at (entries, 0);
	mu_assert_true (r_bin_trycatch_insert (fixture.bf, stored), "insert aliased record across vector growth");
	entries = r_bin_file_get_trycatch (fixture.bf);
	stored = RVecRBinTrycatch_at (entries, old_count);
	mu_assert_streq (stored->type, "exception", "aliased insertion preserves type");
	mu_assert_true (r_bin_trycatch_delete (fixture.bf, 0), "delete aliased original");
	stored = RVecRBinTrycatch_at (r_bin_file_get_trycatch (fixture.bf), 0);
	mu_assert_streq (stored->type, "exception", "copy survives deletion of original");
	mu_assert_true (r_bin_trycatch_clear (fixture.bf), "clear owned strings");
	mu_assert_true (r_bin_trycatch_clear (fixture.bf), "clear empty store");
	entry.from = entry.to;
	mu_assert_false (r_bin_trycatch_insert (fixture.bf, &entry), "reject empty range");
	entry.from++;
	mu_assert_false (r_bin_trycatch_insert (fixture.bf, &entry), "reject reversed range");
	entry = make_entry (UT64_MAX, 2);
	entry.kind = R_BIN_TRYCATCH_FINALLY + 1;
	mu_assert_false (r_bin_trycatch_insert (fixture.bf, &entry), "reject unknown kind");
	entry.kind = (RBinTrycatchKind)-1;
	mu_assert_false (r_bin_trycatch_insert (fixture.bf, &entry), "reject negative kind");
	entry.kind = R_BIN_TRYCATCH_CATCH;
	mu_assert_true (r_bin_trycatch_insert (fixture.bf, &entry), "refill after clear");
	RBinFile *other = open_buffer (fixture.bin, "trycatch-other", "null");
	mu_assert_notnull (other, "open second binfile");
	mu_assert_eq (RVecRBinTrycatch_length (r_bin_file_get_trycatch (other)), 0, "other binfile starts empty");
	mu_assert_true (r_bin_trycatch_insert (other, &entry), "insert into second binfile");
	mu_assert_true (r_bin_trycatch_clear (fixture.bf), "clear first binfile independently");
	mu_assert_eq (RVecRBinTrycatch_length (r_bin_file_get_trycatch (other)), 1, "second binfile survives first clear");
	fixture_fini (&fixture);
	mu_end;
}

static ut32 random_next(ut32 *state) {
	*state = *state * 1664525U + 1013904223U;
	return *state;
}

static bool test_trycatch_mixed_edits(void) {
	TrycatchFixture fixture = fixture_new ();
	mu_assert_notnull (fixture.bf, "open raw binary");
	TrycatchModel model = {0};
	ut32 random = 0x12345678;
	ut64 id = 0;
	size_t i;
	for (i = 0; i < MODEL_CAPACITY; i++) {
		mu_assert_true (model_insert (fixture.bf, &model, i % 32, ++id), "populate model across growth");
	}
	for (i = 0; i < 4000; i++) {
		ut32 choice = random_next (&random);
		ut64 source = ((ut64)(choice % 4) << 32) | ((choice >> 8) % 8);
		if (choice % 97 == 0) {
			mu_assert_true (r_bin_trycatch_clear (fixture.bf), "random clear");
			model.count = 0;
		} else if (model.count && (choice % 3 == 0 || model.count == MODEL_CAPACITY)) {
			size_t index = random_next (&random) % model.count;
			source = model.entries[index].source;
			mu_assert_true (model_delete (fixture.bf, &model, index), "random deletion");
		} else {
			mu_assert_true (model_insert (fixture.bf, &model, source, ++id), "random insertion");
		}
		mu_assert_true (vector_matches (fixture.bf, &model), "listing matches independent model");
		mu_assert_true (query_matches (fixture.bf, &model, source), "edited source matches independent model");
		if (model.count) {
			source = model.entries[random_next (&random) % model.count].source;
			mu_assert_true (query_matches (fixture.bf, &model, source), "other source matches independent model");
		}
		mu_assert_true (query_matches (fixture.bf, &model, UT64_MAX), "missing source remains empty");
	}
	fixture_fini (&fixture);
	mu_end;
}

typedef struct {
	RVecRBinTrycatch entries;
	size_t calls;
} TrycatchPluginData;

static bool plugin_load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	TrycatchPluginData *data = R_NEW0 (TrycatchPluginData);
	bf->bo->bin_obj = data;
	RVecRBinTrycatch_init (&data->entries);
	const ut64 sources[] = {9, 0, 9, 1};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		RBinTrycatch *entry = RVecRBinTrycatch_emplace_back (&data->entries);
		if (!entry) {
			return false;
		}
		*entry = make_entry (sources[i], i + 1);
	}
	RVecRBinTrycatch_at (&data->entries, 0)->type = strdup ("loaded exception");
	return true;
}

static void plugin_destroy(RBinFile *bf) {
	TrycatchPluginData *data = bf->bo->bin_obj;
	RVecRBinTrycatch_fini (&data->entries);
	free (data);
}

static RVecRBinTrycatch *plugin_entries(RBinFile *bf) {
	TrycatchPluginData *data = bf->bo->bin_obj;
	data->calls++;
	return &data->entries;
}

static bool test_trycatch_plugin_load(void) {
	TrycatchFixture fixture = fixture_new ();
	mu_assert_notnull (fixture.bf, "open raw binary");
	RBinPlugin plugin = *fixture.bf->bo->plugin;
	plugin.meta.name = "trycatch-test";
	plugin.load = plugin_load;
	plugin.destroy = plugin_destroy;
	plugin.trycatch = plugin_entries;
	mu_assert_true (r_bin_plugin_add (fixture.bin, &plugin), "register trycatch plugin");
	RBinFile *bf = open_buffer (fixture.bin, "trycatch-plugin", plugin.meta.name);
	mu_assert_notnull (bf, "open trycatch plugin binary");
	TrycatchPluginData *data = bf->bo->bin_obj;
	TrycatchModel model = {0};
	const ut64 sources[] = {9, 0, 9, 1};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (sources); i++) {
		model.entries[model.count++] = make_entry (sources[i], i + 1);
	}
	mu_assert_true (query_matches (bf, &model, 9), "load unsorted plugin entries on first query");
	mu_assert_eq (data->calls, 1, "plugin callback called once");
	mu_assert_eq (RVecRBinTrycatch_length (&data->entries), 0, "plugin vector moved into store");
	mu_assert_true (vector_matches (bf, &model), "loaded entries keep parser order");
	const RBinTrycatch *entry = RVecRBinTrycatch_at (r_bin_file_get_trycatch (bf), 0);
	mu_assert_streq (entry->type, "loaded exception", "store owns loaded type");
	mu_assert_true (model_insert (bf, &model, 9, 5), "append after parser entries");
	mu_assert_true (query_matches (bf, &model, 9), "loaded and appended entries share source");
	mu_assert_true (r_bin_trycatch_clear (bf), "clear loaded metadata");
	model.count = 0;
	mu_assert_true (query_matches (bf, &model, 9), "clear does not reload parser metadata");
	mu_assert_eq (data->calls, 1, "edits never invoke plugin callback again");
	fixture_fini (&fixture);
	mu_end;
}

typedef struct {
	ut64 count;
	ut64 checksum;
} BenchResult;

static bool sum_entry(const RBinTrycatch *entry, void *user) {
	BenchResult *result = user;
	result->count++;
	result->checksum += entry->handler;
	return true;
}

static ut64 bench_source(size_t i, size_t groups) {
	return (((ut64)i * 2654435761ULL) % groups) * 16;
}

static bool benchmark(size_t count) {
	TrycatchFixture fixture = fixture_new ();
	if (!fixture.bf) {
		fixture_fini (&fixture);
		return false;
	}
	const size_t groups = count / 4;
	const size_t queries = 100000;
	const size_t scans = 128;
	const size_t edits = 10000;
	bool success = false;
	ut64 start = r_time_now_mono ();
	size_t i;
	for (i = 0; i < count; i++) {
		RBinTrycatch entry = make_entry ((i % groups) * 16, i + 1);
		if (!r_bin_trycatch_insert (fixture.bf, &entry)) {
			goto beach;
		}
	}
	ut64 load_us = r_time_now_mono () - start;
	BenchResult indexed = {0};
	start = r_time_now_mono ();
	for (i = 0; i < queries; i++) {
		if (!r_bin_trycatch_foreach (fixture.bf, bench_source (i, groups), sum_entry, &indexed)) {
			goto beach;
		}
	}
	ut64 lookup_us = r_time_now_mono () - start;
	BenchResult missing = {0};
	start = r_time_now_mono ();
	for (i = 0; i < queries; i++) {
		if (!r_bin_trycatch_foreach (fixture.bf, bench_source (i, groups) + 1, sum_entry, &missing)) {
			goto beach;
		}
	}
	ut64 missing_us = r_time_now_mono () - start;
	BenchResult naive = {0};
	const RVecRBinTrycatch *entries = r_bin_file_get_trycatch (fixture.bf);
	start = r_time_now_mono ();
	for (i = 0; i < scans; i++) {
		ut64 source = bench_source (i, groups);
		const RBinTrycatch *entry;
		R_VEC_FOREACH (entries, entry) {
			if (entry->source == source) {
				sum_entry (entry, &naive);
			}
		}
	}
	ut64 scan_us = r_time_now_mono () - start;
	BenchResult oracle = {0};
	start = r_time_now_mono ();
	for (i = 0; i < scans; i++) {
		if (!r_bin_trycatch_foreach (fixture.bf, bench_source (i, groups), sum_entry, &oracle)) {
			goto beach;
		}
	}
	ut64 oracle_us = r_time_now_mono () - start;
	if (naive.count != oracle.count || naive.checksum != oracle.checksum || missing.count) {
		goto beach;
	}
	BenchResult edited = {0};
	start = r_time_now_mono ();
	for (i = 0; i < edits; i++) {
		size_t index = ((ut64)i * 2654435761ULL) % count;
		entries = r_bin_file_get_trycatch (fixture.bf);
		ut64 old_source = RVecRBinTrycatch_at (entries, index)->source;
		RBinTrycatch entry = make_entry ((groups + i) * 16, count + i + 1);
		if (!r_bin_trycatch_delete (fixture.bf, index)
				|| !r_bin_trycatch_insert (fixture.bf, &entry)
				|| !r_bin_trycatch_foreach (fixture.bf, old_source, sum_entry, &edited)
				|| !r_bin_trycatch_foreach (fixture.bf, entry.source, sum_entry, &edited)) {
			goto beach;
		}
	}
	ut64 edit_us = r_time_now_mono () - start;
	printf ("entries=%zu sources=%zu load_us=%" PFMT64u "\n", count, groups, load_us);
	printf ("lookup_queries=%zu lookup_us=%" PFMT64u " missing_us=%" PFMT64u " matches=%" PFMT64u " checksum=%" PFMT64u "\n",
		queries, lookup_us, missing_us, indexed.count, indexed.checksum);
	printf ("oracle_queries=%zu scan_us=%" PFMT64u " indexed_us=%" PFMT64u " matches=%" PFMT64u " checksum=%" PFMT64u "\n",
		scans, scan_us, oracle_us, oracle.count, oracle.checksum);
	printf ("delete_insert_query_cycles=%zu edit_us=%" PFMT64u " matches=%" PFMT64u " checksum=%" PFMT64u "\n",
		edits, edit_us, edited.count, edited.checksum);
	success = true;
beach:
	fixture_fini (&fixture);
	return success;
}

int main(int argc, char **argv) {
	if (argc > 1) {
		char *end = NULL;
		ut64 count = argc == 3? strtoull (argv[2], &end, 10): 2000000;
		if (argc > 3 || strcmp (argv[1], "--bench") || (argc == 3 && (!*argv[2] || *end))
				|| count < 4 || count > (SIZE_MAX / sizeof (RBinTrycatch))) {
			fprintf (stderr, "Usage: %s [--bench [entries>=4]]\n", argv[0]);
			return 1;
		}
		return benchmark (count)? 0: 1;
	}
	mu_run_test (test_trycatch_lookup);
	mu_run_test (test_trycatch_compressed_sections);
	mu_run_test (test_trycatch_delete);
	mu_run_test (test_trycatch_ownership);
	mu_run_test (test_trycatch_mixed_edits);
	mu_run_test (test_trycatch_plugin_load);
	return tests_passed != tests_run;
}
