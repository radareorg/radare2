/* radare - LGPL - Copyright 2009-2014 - pancake */

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
static int iterations = 0;
static int quiet = 0;
static RHashSeed s = {0}, *_s = NULL;

static void do_hash_seed(const char *seed) {
	const char *sptr = seed;
	if (!seed) {
		_s = NULL;
		return;
	}
	_s = &s;
	s.buf = (ut8*)malloc (strlen (seed)+128);
	if (!s.buf) {
		_s = NULL;
		return;
	}
	if (*seed=='^') {
		s.prefix = 1;
		sptr++;
	} else s.prefix = 0;
	if (!strncmp (sptr, "s:", 2)) {
		strcpy ((char*)s.buf, sptr+2);
		s.len = strlen (sptr+2);
	} else {
		s.len = r_hex_str2bin (sptr, s.buf);
		if (s.len<1) {
			strcpy ((char*)s.buf, sptr);
			s.len = strlen (sptr);
		}
	}
}

static void do_hash_hexprint (const ut8 *c, int len, int ule) {
	int i;
	if (ule) {
		for (i=len-1; i>=0; i--)
			printf ("%02x", c[i]);
	} else {
		for (i=0; i<len; i++)
			printf ("%02x", c[i]);
	}
	printf ("\n");
}

static void do_hash_print(RHash *ctx, int hash, int dlen, int rad, int ule) {
	char *o;
	const ut8 *c = ctx->digest;
	const char *hname = r_hash_name (hash);
	switch (rad) {
	case 0:
		if (!quiet)
			printf ("0x%08"PFMT64x"-0x%08"PFMT64x" %s: ",
				from, to, hname);
		do_hash_hexprint (c, dlen, ule);
		break;
	case 1:
		printf ("e file.%s=", hname);
		do_hash_hexprint (c, dlen, ule);
		break;
	default:
		o = r_print_randomart (c, dlen, from);
		printf ("%s\n%s\n", hname, o);
		free (o);
		break;
	}
}

static int do_hash_internal(RHash *ctx, int hash, const ut8 *buf, int len, int rad, int print, int le) {
	int dlen;
	if (len<1)
		return 0;
	dlen = r_hash_calculate (ctx, hash, buf, len);
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
	} else {
		if (iterations>0)
			r_hash_do_spice (ctx, hash, iterations, _s);
		do_hash_print (ctx, hash, dlen, rad, le);
	}
	return 1;
}


static int do_hash(const char *file, const char *algo, RIO *io, int bsize, int rad, int ule) {
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
	if (!buf)
		return 1;
	ctx = r_hash_new (R_TRUE, algobit);

	if (incremental) {
		for (i=1; i<0x800000; i<<=1) {
			if (algobit & i) {
				int hashbit = i & algobit;
				int dlen = r_hash_size (hashbit);
				r_hash_do_begin (ctx, i);
				if (s.buf && s.prefix) {
					do_hash_internal (ctx,
						hashbit, s.buf, s.len, rad, 0, ule);
				}
				for (j=from; j<to; j+=bsize) {
					r_io_pread (io, j, buf, bsize);
					do_hash_internal (ctx, hashbit, buf,
						((j+bsize)<fsize)?  bsize:
						(bsize>j)?(fsize-j):0, rad, 0, ule);
				}
				if (s.buf && !s.prefix) {
					do_hash_internal (ctx, hashbit, s.buf,
						s.len, rad, 0, ule);
				}
				r_hash_do_end (ctx, i);
				if (iterations>0)
					r_hash_do_spice (ctx, i, iterations, _s);
				if (!*r_hash_name (i))
					continue;
				if (!quiet)
					printf ("%s: ", file);
				do_hash_print (ctx, i, dlen, rad, ule);
			}
		}
		if (_s)
			free (_s->buf);
	} else {
		/* iterate over all algorithm bits */
		if (s.buf)
			eprintf ("Warning: Seed ignored on per-block hashing.\n");
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
					r_io_pread (io, j, buf, bsize);
					from = j;
					to = j+bsize;
					do_hash_internal (ctx, hashbit, buf, nsize, rad, 1, ule);
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
	" -e          swap endian (use little endian)\n"
	" -d / -D     encode/decode base64 string (-s) or file to stdout\n"
	" -f from     start hashing at given address\n"
	" -i num      repeat hash N iterations\n"
	" -S seed     use given seed (hexa or s:string) use ^ to prefix\n"
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
		bits = ((ut64)1)<<i;
		const char *name = r_hash_name (bits);
		if (!name||!*name) break;
		printf ("%s\n", name);
	}
}

int main(int argc, char **argv) {
	int i, ret, c, rad = 0, bsize = 0, numblocks = 0, ule = 0, b64mode = 0;
	const char *algo = "sha256"; /* default hashing algorithm */
	const char *seed = NULL;
	char *hashstr = NULL;
	ut64 algobit;
	RHash *ctx;
	RIO *io;

	while ((c = getopt (argc, argv, "dDrvea:i:S:s:b:nBhf:t:kLq")) != -1) {
		switch (c) {
		case 'q': quiet = 1; break;
		case 'i': iterations = atoi (optarg);
			if (iterations<1) {
				eprintf ("error: -i argument must be positive\n");
				return 1;
			}
			break;
		case 'S': seed = optarg; break;
		case 'n': numblocks = 1; break;
		case 'd': b64mode = 1; break;
		case 'D': b64mode = 2; break;
		case 'L': algolist (); return 0;
		case 'e': ule = 1; break;
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
	do_hash_seed (seed);
	if (hashstr && !strcmp (hashstr, "-")) {
#define INSIZE 32768
		int res = 0;
		hashstr = malloc (INSIZE);
		if (!hashstr)
			return 1;
		res = fread ((void*)hashstr, 1, INSIZE-1, stdin);
		hashstr[res] = '\0';
	}
	if (hashstr) {
		switch (b64mode) {
		case 1: // encode
			{
			int binlen = strlen (hashstr);
			ut8 *out = malloc (((binlen+1)*4)/3);
			if (out) {
				r_base64_encode (out, (const ut8*)hashstr, binlen);
				printf ("%s\n", out);
				fflush (stdout);
				free (out);
			}
			}
			break;
		case 2: // decode
			{
			ut8 *out = malloc (INSIZE);
			if (out) {
				int outlen = r_base64_decode (out, hashstr, strlen (hashstr));
				write (1, out, outlen);
				free (out);
			}
			}
		       break;
		default:
			{
			       char *str = (char *)hashstr;
			       int strsz = strlen (hashstr);
			       if (_s) {
				       // alloc/concat/resize
				       str = malloc (strsz + s.len);
				       if (s.prefix) {
					       memcpy (str, s.buf, s.len);
					       strcpy (str+s.len, hashstr);
				       } else {
					       strcpy (str, hashstr);
					       memcpy (str+strsz, s.buf, s.len);
				       }
				       strsz += s.len;
				       str[strsz] = 0;
			       }
			       algobit = r_hash_name_to_bits (algo);
			       for (i=1; i<0x800000; i<<=1) {
				       if (algobit & i) {
					       int hashbit = i & algobit;
					       ctx = r_hash_new (R_TRUE, hashbit);
					       from = 0;
					       to = strsz;
					       do_hash_internal (ctx, hashbit,
						       (const ut8*)str, strsz, rad, 1, ule);
					       r_hash_free (ctx);
				       }
			       }
			       if (_s) {
				       free (str);
				       free (s.buf);
			       }
			}
		}
		return 0;
	}
	if (optind>=argc)
		return do_help (1);
	if (numblocks) {
		bsize = -bsize;
	} else if (bsize<0) {
		eprintf ("rahash2: Invalid block size\n");
		return 1;
	}

	io = r_io_new ();
	for (ret=0, i=optind; i<argc; i++) {
		switch (b64mode) {
		case 1: // encode
			{
			int binlen;
			ut8 *out, *bin = (ut8*)r_file_slurp (argv[i], &binlen);
			if (!bin) {
				eprintf ("Cannot open file\n");
				continue;
			}
			out = malloc (((binlen+1)*4)/3);
			if (out) {
				r_base64_encode (out, bin, binlen);
				printf ("%s\n", out);
				fflush (stdout);
				free (out);
			}
			free (bin);
			}
			break;
		case 2: // decode
			{
			int binlen, outlen;
			ut8 *out, *bin = (ut8*)r_file_slurp (argv[i], &binlen);
			if (!bin) {
				eprintf ("Cannot open file\n");
				continue;
			}
			out = malloc (binlen+1);
			if (out) {
				outlen = r_base64_decode (out, (const char*)bin, binlen);
				write (1, out, outlen);
				free (out);
			}
			free (bin);
			}
			break;
		default:
			if (r_file_is_directory (argv[i])) {
				eprintf ("rahash2: Cannot hash directories\n");
				return 1;
			}
			if (!r_io_open_nomap (io, argv[i], 0, 0)) {
				eprintf ("rahash2: Cannot open '%s'\n", argv[i]);
				return 1;
			}
			ret |= do_hash (argv[i], algo, io, bsize, rad, ule);
		}
	}
	free (hashstr);
	r_io_free (io);
	return ret;
}
