#include <r_search.h>

static const ut8 *buffer =(const ut8*) "ELF,e,e,e,ELF--fooo";

static int hit(RSearchKeyword *kw, void *user, ut64 addr) {
	const ut8 *buf = (const ut8*)user;
	printf ("HIT %d AT %"PFMT64d" (%s)\n", kw->count, addr, buf+addr);
	return 1;
}

int main(int argc, char **argv) {
	RSearch *rs = r_search_new (R_SEARCH_REGEXP);
	r_search_set_callback (rs, &hit, (void*)buffer);
	r_search_kw_add (rs, /* search for /E.F/i */
		r_search_keyword_new_str ("E.F", "i", NULL, 0));
	r_search_begin (rs);
	printf ("Searching strings in '%s'\n", buffer);
	r_search_update (rs, 0LL, buffer, strlen ((const char *)buffer));
	rs = r_search_free (rs);
	return 0;
}
