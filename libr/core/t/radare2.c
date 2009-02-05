/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"
#include "r_io.h"
#include <stdio.h>
#include <getopt.h>

struct r_core_t r;

int main_help(int line)
{
	printf("Usage: radare2 [-wn] [-e k=v] [file]\n");
	if (!line) printf(
		" -w      open file in write mode\n"
		" -n      do not run ~/.radarerc\n"
		" -e k=v  evaluate config var\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct r_core_file_t *fh;
 	int c, perms = R_IO_READ;
	int run_rc = 1;

	if (argc<2)
		return main_help(1);

	r_core_init(&r);

	while((c = getopt(argc, argv, "when"))!=-1) {
		switch(c) {
		case 'h':
			return main_help(0);
		case 'e':
			r_config_eval(&r.config, optarg);
			break;
		case 'n':
			run_rc = 0;
			break;
		case 'w':
			perms = R_IO_RDWR;
			break;
		default:
			return 1;
		}
	}

	while (optind<argc) {
		const char *file = argv[optind];
		fh = r_core_file_open(&r, argv[optind++], perms);
		if (fh == NULL) {
			fprintf(stderr,
			"Cannot open file '%s'\n", argv[1]);
			return 1;
		}
		optind++;
	}

	if (r.file == NULL) {
		fprintf(stderr, "Cannot open file\n");
		return 1;
	}

	if (run_rc) {
		char *homerc = r_str_home(".radarerc");
		if (homerc) {
			r_core_cmd_file(&r, homerc);
			free(homerc);
		}
	}

	while(r_core_prompt(&r) != -1);

	return r_core_file_close(&r, fh);
}
