#include "r_config.h"

int main()
{
	struct r_config_t *cfg;

	/* initialize config table */
	cfg = r_config_new(NULL);
	r_config_set(cfg, "foo", "bar");
	r_config_set_i(cfg, "bar", 33);
	r_config_lock(cfg, 1);

	/* usage */
	printf("foo = %s\n", r_config_get(cfg, "foo"));
	printf("bar = %d\n", (int)r_config_get_i(cfg, "bar"));

	r_config_free(cfg);

	return 0;
}
