#include <r_search.h>

ut8 *buffer = "ELF,e,e,e,ELF--fooo";

int hit(struct r_search_kw_t *kw, void *user, ut64 addr)
{
	const ut8 *buf = (ut8*)user;
	printf("HIT %d AT %lld (%s)\n", kw->count, addr, buffer+addr);
	return 1;
}

int main(int argc, char **argv)
{
	struct r_search_t *rs;

	rs = r_search_new(R_SEARCH_REGEXP);
	r_search_set_callback(rs, &hit, buffer);
	r_search_kw_add(rs, "E.F", "i"); /* search for /E.F/i */
	r_search_begin(rs);
	printf("Searching strings in '%s'\n", buffer);
	r_search_update_i(rs, 0LL, buffer, strlen(buffer));
	rs = r_search_free(rs);

	return 0;
}
