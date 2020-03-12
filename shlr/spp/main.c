/* MIT (C) pancake (at) nopcode (dot) org */

#include "spp.h"
#include "r_api.h"

extern struct Proc *procs[];
extern struct Proc *proc;
extern struct Arg *args;

static void spp_help(char *argv0) {
	int i;
	char supported[128] = "";
	for( i = 0; procs[i]; ++i ) {
		if (i) strcat (supported, ",");
		strcat (supported, procs[i]->name);
	}
	printf("Usage: %s [-othesv] [file] [...]\n", argv0);
	printf(	"  -o [file]     set output file (stdout)\n"
		"  -t [type]     define processor type (%s)\n"
		"  -e [str]      evaluate this string with the selected proc\n"
		"  -s [str]      show this string before anything\n"
		"  -l            list all built-in preprocessors\n"
		"  -L            list keywords registered by the processor\n"
		"  -n            do not read from stdin\n"
		"  -v            show version information\n", supported);
	if (proc) {
		printf ("%s specific flags:\n", proc->name);
		for(i = 0; args[i].flag; i++) {
			printf (" %s   %s\n", args[i].flag, args[i].desc);
		}
	}
	exit(0);
}

int main(int argc, char **argv) {
	int dostdin = 1;
	int i, j;
	Output out;
	out.fout = stdout;
	char *arg;

	spp_proc_set (proc, argv[0], 0);

	if (argc < 2)
		spp_io (stdin, &out);
	else {
		for(i = 1; i < argc; i++) {
			/* check preprocessor args */
			if (args)
			for(j = 0; args[j].flag; j++) {
				if (!memcmp (argv[i], args[j].flag, 2)) {
					if (args[j].has_arg) {
						GET_ARG (arg, argv, i);
						args[j].callback (arg);
					} else {
						args[j].callback (NULL);
					}
					continue;
				}
			}

			/* TODO: Add these flags in Arg[] */
			if (!memcmp (argv[i], "-o", 2)) {
				GET_ARG (arg, argv, i);
				if (arg != NULL) {
					if (!strcmp (arg, "buff")) {
						out.fout = NULL;
						out.cout = r_strbuf_new ("");
						r_strbuf_init (out.cout);
					} else {
						out.cout = NULL;
						out.fout = fopen (arg, "w");
					}
				}
				if (!out.cout && (arg == NULL || out.fout == NULL)) {
					fprintf (stderr, "Cannot open output file\n");
					exit (1);
				}
			} else
			if (!memcmp (argv[i],"-t", 2)) {
				GET_ARG (arg, argv, i);
				spp_proc_set (proc, arg, 1);
			} else
			if (!strcmp (argv[i],"-v")) {
				printf ("spp-%s\n", VERSION);
				exit (1);
			} else
			if (!strcmp (argv[i],"-h")) {
				/* show help */
				spp_help (argv[0]);
			} else
			if (!strcmp (argv[i],"-n")) {
				dostdin = 0;
			} else
			if (!strcmp (argv[i],"-l")) {
				spp_proc_list ();
				exit (0);
			} else
			if (!strcmp (argv[i],"-L")) {
				spp_proc_list_kw ();
				exit (0);
			} else
			if (!strcmp (argv[i],"-s")) {
				GET_ARG (arg, argv, i);
				if (arg == NULL) arg = "";
				fprintf (out.fout, "%s\n", arg);
			} else
			if (!strcmp (argv[i],"-e")) {
				GET_ARG (arg, argv, i);
				if (arg == NULL) {
					arg = "";
				}
				spp_eval (arg, &out);
			} else {
				if (i == argc) {
					fprintf (stderr, "No file specified.\n");
				} else {
					spp_file (argv[i], &out);
					dostdin = 0;

					if (!out.fout) {
						D printf ("%s\n", r_strbuf_get (out.cout));
						r_strbuf_free (out.cout);
					}
				}
			}
		}
		if (dostdin) {
			spp_io (stdin, &out);
		}
	}

	if (proc->eof) {
		proc->eof (&proc->state, &out, "");
	}
	if (out.fout) {
		fclose (out.fout);
	}

	return 0;
}
