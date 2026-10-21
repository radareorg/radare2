#include <r_util.h>

static bool bench_append(int count, bool distinct, bool dedup) {
	RStrpool *p = r_strpool_new ();
	if (!p) {
		return false;
	}
	char name[64] = "duplicate";
	ut64 start = r_time_now_mono ();
	int i;
	for (i = 0; i < count; i++) {
		if (distinct) {
			snprintf (name, sizeof (name), "file-%d.c", i);
		}
		int pos = dedup? r_strpool_add (p, name): r_strpool_append (p, name);
		if (pos != i) {
			r_strpool_free (p);
			return false;
		}
	}
	ut64 elapsed = r_time_now_mono () - start;
	printf ("%s,%d,%"PFMT64u",%"PFMT64u"\n",
		dedup? "add-distinct": distinct? "append-distinct": "append-duplicates",
		count, elapsed, (ut64)p->index_size * sizeof (ut32));
	bool valid = r_strpool_get (p, name) == (distinct? count - 1: 0);
	r_strpool_free (p);
	return valid;
}

static bool bench_rebuild(int count) {
	RStrpool *p = r_strpool_new ();
	if (!p) {
		return false;
	}
	int i;
	for (i = 0; i < count; i++) {
		if (r_strpool_append (p, "duplicate") != i) {
			r_strpool_free (p);
			return false;
		}
	}
	r_strpool_lock (p);
	ut64 start = r_time_now_mono ();
	int pos = r_strpool_get (p, "duplicate");
	ut64 elapsed = r_time_now_mono () - start;
	printf ("rebuild-duplicates,%d,%"PFMT64u",%"PFMT64u"\n",
		count, elapsed, (ut64)p->index_size * sizeof (ut32));
	bool valid = pos == 0 && r_strpool_get (p, "missing") == -1;
	r_strpool_free (p);
	return valid;
}

int main(int argc, char **argv) {
	const int counts[] = { 1024, 4096, 16384, 65536 };
	puts ("case,count,total_us,index_bytes");
	int i;
	for (i = 0; i < R_ARRAY_SIZE (counts); i++) {
		int count = counts[i];
		if (!bench_append (count, true, false)
				|| !bench_append (count, false, false)
				|| !bench_rebuild (count)
				|| !bench_append (count, true, true)) {
			return 1;
		}
	}
	return 0;
}
