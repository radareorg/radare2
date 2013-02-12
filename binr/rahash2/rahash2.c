/* radare - LGPL - Copyright 2009-2013 - pancake */

#include <stdio.h>
#include <string.h>
#include <getopt.c>
/* r2 api */
#include <r_io.h>
#include <r_hash.h>
#include <r_util.h>
#include <r_print.h>

static ut64 from = 0LL;
static ut64 to = 0LL;
static int incremental = 1;

static void do_hash_print(RHash *ctx, int hash, int dlen, int rad) {
	char *o;
	const ut8 *c = ctx->digest;
	const char *hname = r_hash_name (hash);
	int i;
	switch (rad) {
	case 0:
		printf ("0x%08"PFMT64x"-0x%08"PFMT64x" %s: ", from, to, hname);
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

static int do_hash(const char *algo, RIO *io, int bsize, int rad) {
	ut8 *buf;
	RHash *ctx;
	ut64 j, fsize;
	int i;
	ut64 algobit = r_hash_name_to_bits (algo);
	if (algobit == R_HASH_NONE) {
		eprintf ("Invalid hashing algorithm specified\n");
		return 1;
	}
	fsize = r_io_size (io);
	if (bsize == 0 || bsize > fsize)
		bsize = fsize;
	if (to == 0LL)
		to = fsize;
	if (from>to) {
		eprintf ("Invalid -f -t range\n");
		return 1;
	}
	if (fsize == -1LL) {
		eprintf ("Unknown file size\n");
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
	printf ("Usage: rahash2 [-rBkv] [-b bsize] [-a algo] [-s str] [-f from] [-t to] [file] ...\n");
	if (line) return 0;
	printf (
	" -a algo     comma separated list of algorithms (default is 'sha256')\n"
	" -b bsize    specify the size of the block (instead of full file)\n"
	" -B          show per-block hash\n"
	" -s string   hash this string instead of files\n"
	" -f from     start hashing at given address\n"
	" -t to       stop hashing at given address\n"
	" -k          show hash using the openssh's randomkey algorithm\n"
	" -r          output radare commands\n"
	" -v          show version information\n"
	"Supported algorithms: md4, md5, sha1, sha256, sha384, sha512, crc16,\n"
	"    crc32, xor, xorpair, parity, mod255, hamdist, entropy, pcprint\n");
	return 0;
}

int main(int argc, char **argv) {
	const char *algo = "sha256"; /* default hashing algorithm */
	int c, rad = 0, quit = 0, bsize = 0;
	RIO *io;

	while ((c = getopt (argc, argv, "rva:s:b:Bhf:t:k")) != -1) {
		switch (c) {
		case 'r': rad = 1; break;
		case 'k': rad = 2; break;
		case 'a': algo = optarg; break;
		case 'B': incremental = 0; break;
		case 'b':
			bsize = (int)r_num_math (NULL, optarg);
			break;
		case 's':
			{
				ut64 algobit = r_hash_name_to_bits (algo);
				RHash *ctx = r_hash_new (R_TRUE, algobit);
				from = 0;
				to = strlen (optarg);
				do_hash_internal (ctx, //0, strlen (optarg),
					algobit, (const ut8*) optarg,
					strlen (optarg), rad, 1);
				r_hash_free (ctx);
				quit = R_TRUE;
			}
			break;
		case 'f':
			from = r_num_math (NULL, optarg);
			break;
		case 't':
			to = r_num_math (NULL, optarg);
			break;
		case 'v':
			printf ("rahash2 v"R2_VERSION"\n");
			return 0;
		case 'h':
			return do_help (0);
		}
	}

	if (quit)
		return 0;
	if (optind>=argc)
		return do_help (1);

	io = r_io_new ();
	if (!r_io_open (io, argv[optind], 0, 0)) {
		eprintf ("Cannot open '%s'\n", argv[optind]);
		return 1;
	}
	return do_hash (algo, io, bsize, rad);
}
