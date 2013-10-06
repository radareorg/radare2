/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <stdio.h>
#include <string.h>
#include <getopt.c>
#include <r_io.h>
#include <r_hash.h>
#include <r_util.h>
#include <r_print.h>
#include "../blob/version.c"

static ut64 from = 0LL;
static ut64 to = 0LL;
static int incremental = 1;
static int quiet = 0;

static void do_hash_print(RHash *ctx, int hash, int dlen, int rad) {
	int i;
	char *o;
	const ut8 *c = ctx->digest;
	const char *hname = r_hash_name (hash);
	switch (rad) {
	case 0:
		if (!quiet)
			printf ("0x%08"PFMT64x"-0x%08"PFMT64x" %s: ",
				from, to, hname);
		for (i=0; i<dlen; i++)
			printf ("%02x", c[i]);
		printf ("\n");
		break;
	case 1:
		printf ("e file.%s=", hname);
		for (i=0; i<dlen; i++)
			printf ("%02x", c[i]);
		printf ("\n");
		break;
	default:
		o = r_print_randomart (c, dlen, from);
		printf ("%s\n%s\n", hname, o);
		free (o);
		break;
	}
}

static int do_hash_internal(RHash *ctx, int hash, const ut8 *buf, int len, int rad, int print) {
	int dlen = r_hash_calculate (ctx, hash, buf, len);
	if (!dlen) return 0;
	if (!print) return 1;
	if (hash == R_HASH_ENTROPY) {
		double e = r_hash_entropy (buf, len);
		if (rad) {
			eprintf ("entropy: %10f\n", e);
		} else {
			printf ("0x%08"PFMT64x"-0x%08"PFMT64x" %10f: ", 
					from, to, e);
			r_print_progressbar (NULL, 12.5 * e, 60);
			printf ("\n");
		}
	} else do_hash_print (ctx, hash, dlen, rad);
	return 1;
}

static int do_hash(const char *file, const char *algo, RIO *io, int bsize, int rad) {
	ut64 j, fsize, algobit = r_hash_name_to_bits (algo);
	RHash *ctx;
	ut8 *buf;
	int i;
	if (algobit == R_HASH_NONE) {
		eprintf ("rahash2: Invalid hashing algorithm specified\n");
		return 1;
	}
	fsize = r_io_size (io);
	if (fsize <1) {
		eprintf ("rahash2: Invalid file size\n");
		return 1;
	}
	if (bsize<0) bsize = fsize / -bsize;
	if (bsize == 0 || bsize > fsize) bsize = fsize;
	if (to == 0LL) to = fsize;
	if (from>to) {
		eprintf ("rahash2: Invalid -f -t range\n");
		return 1;
	}
	if (fsize == -1LL) {
		eprintf ("rahash2: Unknown file size\n");
		return 1;
	}
	buf = malloc (bsize+1);
	ctx = r_hash_new (R_TRUE, algobit);

	if (incremental) {
		for (i=1; i<0x800000; i<<=1) {
			if (algobit & i) {
				int hashbit = i & algobit;
				int dlen = r_hash_size (hashbit);
				r_hash_do_begin (ctx, i);
				for (j=from; j<to; j+=bsize) {
					r_io_read_at (io, j, buf, bsize);
					do_hash_internal (ctx,
						hashbit, buf, ((j+bsize)<fsize)?
						bsize: (fsize-j), rad, 0);
				}
				r_hash_do_end (ctx, i);
				if (!quiet)
					printf ("%s: ", file);
				do_hash_print (ctx, i, dlen, rad);
			}
		}
	} else {
		/* iterate over all algorithm bits */
		for (i=1; i<0x800000; i<<=1) {
			ut64 f, t, ofrom, oto;
			if (algobit & i) {
				int hashbit = i & algobit;
				ofrom = from;
				oto = to;
				f = from;
				t = to;
				for (j=f; j<t; j+=bsize) {
					int nsize = (j+bsize<fsize)? bsize: (fsize-j);
					r_io_read_at (io, j, buf, bsize);
					from = j;
					to = j+bsize;
					do_hash_internal (ctx, hashbit, buf, nsize, rad, 1);
				}
				from = ofrom;
				to = oto;
			}
		}
	}
	r_hash_free (ctx);
	free (buf);
	return 0;
}

static int do_help(int line) {
	printf ("Usage: rahash2 [-rBhLkv] [-b sz] [-a algo] [-s str] [-f from] [-t to] [file] ...\n");
	if (line) return 0;
	printf (
	" -a algo     comma separated list of algorithms (default is 'sha256')\n"
	" -b bsize    specify the size of the block (instead of full file)\n"
	" -B          show per-block hash\n"
	" -f from     start hashing at given address\n"
	" -k          show hash using the openssh's randomkey algorithm\n"
	" -q          run in quiet mode (only show results)\n"
	" -L          list all available algorithms (see -a)\n"
	" -r          output radare commands\n"
	" -s string   hash this string instead of files\n"
	" -t to       stop hashing at given address\n"
	" -v          show version information\n");
	return 0;
}

static void algolist() {
	ut64 bits;
	int i;
	for (i=0; ; i++) {
		bits = 1<<i;
		const char *name = r_hash_name (bits);
		if (!name||!*name) break;
		printf ("%s\n", name);
	}
}

int main(int argc, char **argv) {
	RIO *io;
	RHash *ctx;
	ut64 algobit;
	const char *hashstr = NULL;
	const char *algo = "sha256"; /* default hashing algorithm */
	int i, ret, c, rad = 0, quit = 0, bsize = 0, numblocks = 0;

	while ((c = getopt (argc, argv, "rva:s:b:nBhf:t:kLq")) != -1) {
		switch (c) {
		case 'q': quiet = 1; break;
		case 'n': numblocks = 1; break;
		case 'L': algolist (); return 0;
		case 'r': rad = 1; break;
		case 'k': rad = 2; break;
		case 'a': algo = optarg; break;
		case 'B': incremental = 0; break;
		case 'b': bsize = (int)r_num_math (NULL, optarg); break;
		case 'f': from = r_num_math (NULL, optarg); break;
		case 't': to = r_num_math (NULL, optarg); break;
		case 'v': return blob_version ("rahash2");
		case 'h': return do_help (0);
		case 's': hashstr = optarg; break;
		default: eprintf ("rahash2: Unknown flag\n"); return 1;
		}
	}
	if (hashstr) {
		algobit = r_hash_name_to_bits (algo);
		for (i=1; i<0x800000; i<<=1) {
			if (algobit & i) {
				int hashbit = i & algobit;
				ctx = r_hash_new (R_TRUE, hashbit);
				from = 0;
				to = strlen (hashstr);
				do_hash_internal (ctx, hashbit,
					(const ut8*) hashstr,
					strlen (hashstr), rad, 1);
				r_hash_free (ctx);
				quit = R_TRUE;
			}
		}
		return 0;
	}
	if (quit)
		return 0;
	if (optind>=argc)
		return do_help (1);
	if (numblocks) {
		bsize = -bsize;
	} else if (bsize<0) {
		eprintf ("rahash2: Invalid block size\n");
		return 1;
	}

	for (ret=0, i=optind; i<argc; i++) {
		io = r_io_new ();
		if (r_file_is_directory (argv[i])) {
			eprintf ("rahash2: Cannot hash directories\n");
			return 1;
		}
		if (!r_io_open (io, argv[i], 0, 0)) {
			eprintf ("rahash2: Cannot open '%s'\n", argv[i]);
			return 1;
		}
		ret |= do_hash (argv[i], algo, io, bsize, rad);
		r_io_free (io);
	}
	return ret;
}
