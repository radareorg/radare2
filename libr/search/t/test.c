#include <r_search.h>

char *buffer = "helloworldlibisniceandcoolib2loblubljb";

int hit(struct r_search_kw_t *kw, void *user, u64 addr)
{
	const u8 *buf = (u8*)user;
	printf("HIT %d AT %lld (%s)\n", kw->count, addr, buffer+addr);
	return 1;
}

int main(int argc, char **argv)
{
	struct r_search_t *rs;

	rs = r_search_new(R_SEARCH_KEYWORD);
	r_search_kw_add(rs, "lib", "");
	r_search_set_callback(rs, &hit, buffer);
	r_search_initialize(rs);
	printf("Searching for '%s' in '%s'\n", "lib", buffer);
	r_search_update_i(rs, 0LL, buffer, strlen(buffer));
	rs = r_search_free(rs);

	/* test binmask */
	rs = r_search_new(R_SEARCH_KEYWORD);
	r_search_kw_add(rs, "lib", "ff00ff");
	r_search_set_callback(rs, &hit, buffer);
	r_search_initialize(rs);
	printf("Searching for '%s' with binmask 'ff00ff' in '%s'\n", "lib", buffer);
	r_search_update_i(rs, 0LL, buffer, strlen(buffer));
	rs = r_search_free(rs);
	return 0;
}
