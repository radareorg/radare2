#include <r_search.h>

const ut8 *buffer = (const ut8*) "hellowor\x01\x02ldlibis\x01\x02niceandcoolib2loblubljb";

int hit(RSearchKeyword *kw, void *user, ut64 addr) {
	const ut8 *buf = (const ut8*)user;
	printf("HIT %d AT %"PFMT64d" (%s)\n", kw->count, addr, buf+addr);
	return 1;
}

int main(int argc, char **argv) {
	struct r_search_t *rs;

	rs = r_search_new (R_SEARCH_STRING);
	r_search_set_callback (rs, &hit, (void *)buffer);
	r_search_begin (rs);
	printf ("Searching strings in '%s'\n", buffer);
	r_search_update_i (rs, 0LL, buffer, strlen ((const char*)buffer));
	rs = r_search_free(rs);

	return 0;
}
