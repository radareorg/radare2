#include <sdb/sdb.h>

#ifndef SDB_CUSTOM_HEAP
#define SDB_CUSTOM_HEAP sdb_gh_custom
#endif

int main(int argc, const char **argv) {
#if USE_SDB_HEAP
	sdb_gh_use (&SDB_CUSTOM_HEAP);
#else
	sdb_gh_use (&sdb_gh_libc);
#endif
	return sdb_main (argc, argv);
}
