/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "r_userconf.h"
#include "r_sign.h"

static int rasign_show_help() {
	printf ("Usage: rasign2 [options] [file]\n"
	" -r            show output in radare commands\n"
	" -s [sigfile]  specify one or more signature files\n"
	"Examples:\n"
	"  rasign2 libc.so.6 > libc.sig\n"
	"  rasign2 -s libc.sig ls.static\n");
	return 0;
}

int main(int argc, char **argv) {
	int c;
	int action = 0;
	int rad = 0;
	RSign *sig = r_sign_new ();

	while ((c=getopt (argc, argv, "o:hrs:iV")) !=-1) {
		switch (c) {
		case 'o':
			//r_sign_option (&sig, optarg);
			break;
		case 's':
			action = c;
			//r_sign_load_file (&sig, optarg);
			break;
		case 'r':
			rad = 1;
			break;
		case 'V':
			printf ("rasign2 v"R2_VERSION"\n");
			return 0;
		default:
			return rasign_show_help ();
		}
	}

	if (argv[optind]==NULL)
		return rasign_show_help ();

	r_sign_list (sig, 0);
	rad = rad; /* nop */

	switch (action) {
	case 's':
		/* check sigfiles in optarg file */
	//	r_sign_check (&sig, argv[optind]);
		break;
	default:
		/* generate signature file */
		//r_sign_generate (&sig, argv[optind], stdout);
		break;
	}

	r_sign_free (sig);

	return 0;
}
