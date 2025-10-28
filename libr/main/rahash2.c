/* radare - LGPL - Copyright 2009-2024 - pancake */

#define R_LOG_ORIGIN "rahash2"

#include <r_io.h>
#include <r_main.h>
#include <r_util/r_print.h>
#include <r_muta.h>

typedef struct {
	int quiet;
	int iterations;
	bool incremental; //  = true;
	int direction;
	int endian;
	int mode;
	ut64 from;
	ut64 to;
	RHashSeed *_s;
	RHashSeed s;
	const char *algorithm;
} RahashOptions;

static void compare_hashes(const RHash *ctx, RahashOptions *ro, const ut8 *compare, int length, int *ret, int rad) {
	if (R_LIKELY (compare)) {
		// algobit has only 1 bit set
		if (!memcmp (ctx->digest, compare, length)) {
			if (rad != 'q') {
				R_LOG_INFO ("Computed hash matches the expected one");
			}
		} else {
			if (rad != 'q' || ro->quiet < 2) {
				R_LOG_WARN ("Computed hash doesn't match the expected one");
			}
			*ret = 1;
		}
	}
}

static void do_hash_seed(RahashOptions *ro, const char *seed) {
	const char *sptr = seed;
	if (!seed) {
		ro->_s = NULL;
		return;
	}
	ro->_s = &ro->s;
	if (!strcmp (seed, "-")) {
		ro->s.buf = (ut8 *)r_stdin_slurp (&ro->s.len);
		return;
	}
	if (seed[0] == '@') {
		size_t len;
		ro->s.buf = (ut8 *)r_file_slurp (seed + 1, &len);
		ro->s.len = (size_t)len;
		return;
	}
	ro->s.buf = (ut8 *)malloc (strlen (seed) + 128);
	if (!ro->s.buf) {
		ro->_s = NULL;
		return;
	}
	if (*seed == '^') {
		ro->s.prefix = 1;
		sptr++;
	} else {
		ro->s.prefix = 0;
	}
	if (r_str_startswith (sptr, "s:")) {
		strcpy ((char *)ro->s.buf, sptr + 2);
		ro->s.len = strlen (sptr + 2);
	} else if (r_str_startswith (sptr, "+")) {
		// TODO: honor endian
		ut32 n = r_num_math (NULL, sptr);
		r_write_ble32 (ro->s.buf, n, ro->endian);
		ro->s.len = 4;
	} else {
		ro->s.len = r_hex_str2bin (sptr, ro->s.buf);
		if (ro->s.len < 1) {
			strcpy ((char *)ro->s.buf, sptr);
			ro->s.len = strlen (sptr);
			R_LOG_WARN ("Expected seed/key in hexpair format, use 0x or s: prefix instead")
			// assuming a string, prefix it with 's:' to skip this message");
		}
	}
}

static void do_hash_hexprint(const ut8 *c, int len, int ule, PJ *pj, int rad) {
	int i;
	char *buf = malloc (len * 2 + 1);
	if (!buf) {
		return;
	}
	if (ule) {
		for (i = 0; i < len; i++) {
			snprintf (buf + i * 2, (len - i) * 2 + 1, "%02x", c[len - i - 1]);
		}
	} else {
		for (i = 0; i < len; i++) {
			snprintf (buf + i * 2, (len - i) * 2 + 1, "%02x", c[i]);
		}
	}
	if (rad == 'j') {
		pj_ks (pj, "hash", buf);
	} else if (rad == 'J') {
		pj_s (pj, buf);
	} else {
		printf ("%s%s", buf, rad == 'n'? "": "\n");
	}
	free (buf);
}

static void do_hash_print(RHash *ctx, RahashOptions *ro, ut64 hash, int dlen, PJ *pj, int rad) {
	int ule = ro->endian;
	char *o;
	const ut8 *c = ctx->digest;
	const char *hname = r_hash_name (hash);
	switch (rad) {
	case 0:
		if (!ro->quiet) {
			printf ("0x%08" PFMT64x "-0x%08" PFMT64x " %s: ",
				ro->from, ro->to > 0? ro->to - 1: 0, hname);
		}
		if (hash & R_HASH_SSDEEP) {
			printf ("%s\n", ctx->digest);
		} else if (dlen == R_HASH_SIZE_ENTROPY) {
			printf ("%.8f\n", ctx->entropy);
		} else {
			do_hash_hexprint (c, dlen, ule, pj, rad);
		}
		break;
	case 1:
		printf ("CC file %s:", hname);
		do_hash_hexprint (c, dlen, ule, pj, rad);
		break;
	case 'n':
		if (ro->quiet > 2) {
			// print nothing
		} else {
			if (hash & R_HASH_SSDEEP) {
				printf ("%s", ctx->digest);
			} else {
				do_hash_hexprint (c, dlen, ule, pj, rad);
			}
		}
		break;
	case 'j':
		pj_o (pj);
		pj_ks (pj, "name", hname);
		if (hash & R_HASH_SSDEEP) {
			pj_ks (pj, "hash", (const char *)c);
		} else {
			do_hash_hexprint (c, dlen, ule, pj, rad);
		}
		pj_end (pj);
		break;
	case 'J':
		pj_k (pj, hname);
		do_hash_hexprint (c, dlen, ule, pj, rad);
		break;
	case 'Q':
		// nothing to print
		break;
	case 'q':
	default:
		o = r_print_randomart (c, dlen, ro->from);
		printf ("%s\n%s\n", hname, o);
		free (o);
		break;
	}
}

static int do_hash_internal(RHash *ctx, RahashOptions *ro, ut64 hash, const ut8 *buf, int len, PJ *pj, int rad, int print) {
	if (len < 0) {
		return 0;
	}
	int dlen = r_hash_calculate (ctx, hash, buf, len);
	if (!print) {
		return 1;
	}
	if (ro->iterations > 0) {
		r_hash_do_spice (ctx, hash, ro->iterations, ro->_s);
	}
	do_hash_print (ctx, ro, hash, dlen, pj, rad);
	return 1;
}

static int do_hash(RahashOptions *ro, const char *file, const char *algo, RIO *io, int bsize, int rad, int ule, const ut8 *compare) {
	ut64 j, algobit = r_hash_name_to_bits (algo);
	ut8 *buf;
	int ret = 0;
	ut64 i;
	if (algobit == R_HASH_NONE) {
		R_LOG_ERROR ("Invalid hashing algorithm specified. Use rahash2 -L");
		return 1;
	}
	ut64 fsize = r_io_desc_size (io->desc);
	if (fsize < 1) {
		R_LOG_ERROR ("Invalid file size");
		return 1;
	}
	if (bsize < 0) {
		bsize = fsize / -bsize;
	}
	if (bsize == 0 || bsize > fsize) {
		bsize = fsize;
	}
	if (ro->to == 0LL) {
		ro->to = fsize;
	}
	if (ro->from > ro->to) {
		R_LOG_ERROR ("Invalid -f -t range");
		return 1;
	}
	if (fsize == -1LL) {
		R_LOG_ERROR ("Unknown file size");
		return 1;
	}
	buf = calloc (1, bsize + 1);
	if (!buf) {
		return 1;
	}
	PJ *pj = NULL;
	if (rad == 'j' || rad == 'J') {
		pj = pj_new ();
		if (!pj) {
			free (buf);
			return 1;
		}
		if (rad == 'J') {
			pj_o (pj);
		} else {
			pj_a (pj);
		}
	}
	RHash *ctx = r_hash_new (true, algobit);
	if (ro->incremental) {
		for (i = 1; i < R_HASH_ALL; i <<= 1) {
			if (algobit & i) {
				ut64 hashbit = i & algobit;
				int dlen = r_hash_size (hashbit);
				r_hash_do_begin (ctx, i);
				if (ro->s.buf && ro->s.prefix) {
					do_hash_internal (ctx, ro, hashbit, ro->s.buf, ro->s.len, pj, rad, 0);
				}
				for (j = ro->from; j < ro->to; j += bsize) {
					int len = ((j + bsize) > ro->to)? (ro->to - j): bsize;
					r_io_pread_at (io, j, buf, len);
					do_hash_internal (ctx, ro, hashbit, buf, len, pj, rad, 0);
				}
				if (ro->s.buf && !ro->s.prefix) {
					do_hash_internal (ctx, ro, hashbit, ro->s.buf, ro->s.len, pj, rad, 0);
				}
				r_hash_do_end (ctx, i);
				if (ro->iterations > 0) {
					r_hash_do_spice (ctx, i, ro->iterations, ro->_s);
				}
				if (!*r_hash_name (i)) {
					continue;
				}
				if (!ro->quiet && rad != 'j') {
					printf ("%s: ", file);
				}
				do_hash_print (ctx, ro, i, dlen, pj, ro->quiet? 'n': rad);
				if (ro->quiet == 1) {
					printf (" %s\n", file);
				} else if (ro->quiet > 0 && ro->quiet < 3 && !rad) {
					printf ("\n");
				}
			}
		}
		if (ro->_s) {
			R_FREE (ro->_s->buf);
		}
	} else {
		/* iterate over all algorithm bits */
		if (ro->s.buf) {
			R_LOG_WARN ("Seed ignored on per-block hashing");
		}
		for (i = 1; i < R_HASH_ALL; i <<= 1) {
			ut64 f, t, ofrom, oto;
			if (algobit & i) {
				ut64 hashbit = i & algobit;
				ofrom = ro->from;
				oto = ro->to;
				f = ro->from;
				t = ro->to;
				for (j = f; j < t; j += bsize) {
					int nsize = (j + bsize < fsize)? bsize: (fsize - j);
					r_io_pread_at (io, j, buf, bsize);
					ro->from = j;
					ro->to = j + bsize;
					if (ro->to > fsize) {
						ro->to = fsize;
					}
					do_hash_internal (ctx, ro, hashbit, buf, nsize, pj, rad, 1);
				}
				// Commented out to fix issue #23371
				// do_hash_internal (ctx, ro, hashbit, NULL, 0, pj, rad, 1);
				ro->from = ofrom;
				ro->to = oto;
			}
		}
	}
	if (rad == 'j') {
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}

	int mode = rad;
	if (ro->quiet) {
		mode = 'q';
	}
	compare_hashes (ctx, ro, compare, r_hash_size (algobit), &ret, mode);
	r_hash_free (ctx);
	free (buf);
	return ret;
}

static int do_help(int line) {
	printf ("Usage: rahash2 [-BehjkLqrvX] [-b S] [-a A] [-c H] [-E A] [-s S] [-f O] [-t O] [file] ...\n");
	if (line) {
		return 0;
	}
	printf (
		" -a algo     comma separated list of algorithms (default is 'sha256')\n"
		" -b bsize    specify the size of the block (instead of full file)\n"
		" -B          show per-block hash\n"
		" -c hash     compare with this hash\n"
		" -e          swap endian (use little endian)\n"
		" -E algo     encrypt. Use -S to set key and -I to set IV\n"
		" -D algo     decrypt. Use -S to set key and -I to set IV\n"
		" -f from     start hashing at given address\n"
		" -i num      repeat hash N iterations (f.ex: 3DES)\n"
		" -I iv       use give initialization vector (IV) (hexa or s:string)\n"
		" -j          output in json\n"
		" -J          new simplified json output (same as -jj)\n"
		" -S seed     use given seed (hexa or s:string) use ^ to prefix (key for -E)\n"
		"             (- will slurp the key from stdin, the @ prefix points to a file\n"
		" -k          show hash using the openssh's randomkey algorithm\n"
		" -q          run in quiet mode (-qq to show only the hash)\n"
		" -L          list muta plugins (combines with -q, used by -a, -E and -D)\n"
		" -r          output radare commands\n"
		" -s string   hash this string instead of files\n"
		" -t to       stop hashing at given address\n"
		" -x hexstr   hash this hexpair string instead of files\n"
		" -X          output in hexpairs instead of binary/plain\n"
		" -v          show version information\n");
	return 0;
}

static void algolist(int mode) {
	RMuta *cry = r_muta_new ();
	char *s = r_muta_list (cry, (int)R_MUTA_TYPE_ALL, mode);
	printf ("%s", s);
	free (s);
	r_muta_free (cry);
}

#define setHashString(x, y) \
	{ \
		if (hashstr) { \
			R_LOG_WARN ("Hashstring already defined"); \
			ret (1); \
		} \
		hashstr_hex = y; \
		hashstr = strdup (x); \
	}

static bool is_power_of_two(const ut64 x) {
	return x && ! (x &(x - 1));
}

static void print_result(RahashOptions *ro, const ut8 *result, int result_size) {
	int i;
	switch (ro->mode) {
	case 'j':
		{
			PJ *pj = pj_new ();
			pj_o (pj);
			pj_ks (pj, "algo", ro->algorithm);
			pj_ks (pj, "mode", ro->direction? "encrypt": "decrypt");
			pj_ka (pj, "data");
			for (i = 0; i < result_size; i++) {
				pj_n (pj, result[i]);
			}
			pj_end (pj);
			pj_end (pj);
			char *s = pj_drain (pj);
			printf ("%s\n", s);
			free (s);
		}
		break;
	case 'x':
		for (i = 0; i < result_size; i++) {
			printf ("%02x", result[i]);
		}
		printf ("\n");
		break;
	default:
		if (write (1, result, result_size) != result_size) {
			R_LOG_WARN ("cannot write result");
		}
		break;
	}
}

static int encrypt_or_decrypt(RahashOptions *ro, const char *hashstr, int hashstr_len, const ut8 *iv, int ivlen, int mode) {
	const int direction = ro->direction;
	const char *algo = ro->algorithm;
	// TODO: generalise this for all non key encoding/decoding.
	bool no_key_mode = !strcmp ("base64", algo) || !strcmp ("base91", algo) || !strcmp ("punycode", algo) || !strcmp ("bech32", algo);
	if (no_key_mode || ro->s.len > 0) {
		RMuta *cry = r_muta_new ();
		RMutaSession *cj = r_muta_use (cry, algo);
		if (cj) {
			if (r_muta_session_set_key (cj, ro->s.buf, ro->s.len, 0, direction)) {
				const char *buf = hashstr;
				int buflen = hashstr_len;

				if (iv && !r_muta_session_set_iv (cj, iv, ivlen)) {
					R_LOG_ERROR ("Invalid IV");
					return 0;
				}

				r_muta_session_update (cj, (const ut8 *)buf, buflen);

				int result_size = 0;
				ut8 *result = r_muta_session_get_output (cj, &result_size);
				if (result) {
					print_result (ro, result, result_size);
					free (result);
				}
			} else {
				R_LOG_ERROR ("Invalid key");
			}
			r_muta_free (cry);
			return 0;
		} else {
			R_LOG_ERROR ("Unknown %s algorithm '%s'", (direction? "encryption": "decryption"), algo);
		}
		r_muta_free (cry);
	} else {
		R_LOG_ERROR ("%s key not defined. Use -S [key]", (direction? "Encryption": "Decryption"));
	}
	return 1;
}

static int encrypt_or_decrypt_file(RahashOptions *ro, const char *filename, const ut8 *iv, int ivlen, int mode) {
	const int direction = ro->direction;
	const char *algo = ro->algorithm;
	// TODO: generalise this for all non key encoding/decoding. aka muta vs encoder plugins after moving all those hash algos to muta plugins
	bool no_key_mode = !strcmp ("base64", algo) || !strcmp ("base91", algo) || !strcmp ("punycode", algo) || !strcmp ("bech32", algo);
	if (no_key_mode || ro->s.len > 0) {
		RMuta *cry = r_muta_new ();
		RMutaSession *cj = r_muta_use (cry, algo);
		if (cj) {
			if (r_muta_session_set_key (cj, ro->s.buf, ro->s.len, 0, direction)) {
				size_t file_size;
				ut8 *buf;
				if (!strcmp (filename, "-")) {
					int sz;
					buf = (ut8 *)r_stdin_slurp (&sz);
					file_size = (size_t)sz;
				} else {
					buf = (ut8 *)r_file_slurp (filename, &file_size);
				}
				if (!buf) {
					R_LOG_ERROR ("Cannot open '%s'", filename);
					return -1;
				}
				if (iv && !r_muta_session_set_iv (cj, iv, ivlen)) {
					R_LOG_ERROR ("Invalid IV");
					free (buf);
					return 0;
				}

				r_muta_session_update (cj, buf, file_size);

				int result_size = 0;
				ut8 *result = r_muta_session_get_output (cj, &result_size);
				if (result) {
					print_result (ro, result, result_size);
					free (result);
				}
				free (buf);
			} else {
				R_LOG_ERROR ("Invalid key");
			}
			r_muta_free (cry);
			return 0;
		} else {
			R_LOG_ERROR ("Unknown %s algorithm '%s'", direction? "encryption": "decryption", algo);
		}
		r_muta_free (cry);
	} else {
		R_LOG_ERROR ("%s key not defined. Use -S [key]", direction? "Encryption": "Decryption");
	}
	return 1;
}

static void add_algo(RList *algos, const char *a) {
	R_RETURN_IF_FAIL (algos);
	if (R_STR_ISEMPTY (a)) {
		return;
	}
	RListIter *iter;
	const char *ua;
	char *ha = strdup (a);
	// TODO: Use a set
	RList *words = r_str_split_list (ha, ",", 0);
	r_list_foreach (words, iter, ua) {
		if (!r_list_find (algos, ua, (RListComparator)strcmp)) {
			r_list_append (algos, strdup (ua));
		}
	}
	r_list_free (words);
	free (ha);
}

static bool check_base_flags(RahashOptions *ro) {
	const char *algo = ro->algorithm;
	switch (ro->direction) {
	case R_CRYPTO_DIR_ENCRYPT:
	case R_CRYPTO_DIR_DECRYPT:
		return !strcmp (algo, "base64") || !strcmp (algo, "base91");
	}
	return false;
}

R_API int r_main_rahash2(int argc, const char **argv) {
	ut64 i;
	int c, rad = 0, bsize = 0, numblocks = 0, ule = 0;
	const char *file = NULL;
	char *algo = NULL;
	const char *seed = NULL;
	bool show_version = false;
	char *hashstr = NULL;
	ut8 *iv = NULL;
	int ivlen = -1;
	const char *ivseed = NULL;
	const char *compareStr = NULL;
	const char *ptype = NULL;
	ut8 *compareBin = NULL;
	int hashstr_len = -1;
	int hashstr_hex = 0;
	size_t bytes_read = 0; // bytes read from stdin
	RahashOptions _ro = { 0 };
	RahashOptions *ro = &_ro;
	RList *algos = r_list_newf (free);
	ut64 algobit;
	RHash *ctx;
	RIO *io = NULL;
	bool listplugins = false;
	int _ret = 0;

	ro->direction = -1;
	ro->incremental = true;
#define ret(x) \
	{ \
		_ret = x; \
		goto beach; \
	}
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "p:jJD:rveE:a:i:I:S:s:x:b:nBhf:t:kLqc:X");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'q':
			ro->quiet++;
			break;
		case 'i':
			ro->iterations = atoi (opt.arg);
			if (ro->iterations < 0) {
				R_LOG_ERROR ("-i argument must be positive");
				ret (1);
			}
			break;
		case 'X': rad = 'x'; break;
		case 'j': rad = (rad == 'j')? 'J': 'j'; break;
		case 'J': rad = 'J'; break;
		case 'S': seed = opt.arg; break;
		case 'I': ivseed = opt.arg; break;
		case 'n': numblocks = 1; break;
		case 'D':
			if (ro->direction != -1) {
				R_LOG_ERROR ("Cannot use -D and -E at the same time");
				ret (1);
			}
			ro->direction = R_CRYPTO_DIR_DECRYPT;
			ro->algorithm = opt.arg;
			break;
		case 'E':
			if (ro->direction != -1) {
				R_LOG_ERROR ("Cannot use -D and -E at the same time");
				ret (1);
			}
			ro->direction = R_CRYPTO_DIR_ENCRYPT;
			ro->algorithm = opt.arg;
			break;
		case 'L': listplugins = true; break;
		case 'e':
			ule = 1;
			ro->endian = !ro->endian;
			break;
		case 'r': rad = 1; break;
		case 'k': rad = 2; break;
		case 'p': ptype = opt.arg; break;
		case 'a': add_algo (algos, opt.arg); break;
		case 'B': ro->incremental = false; break;
		case 'b': bsize = (int)r_num_math (NULL, opt.arg); break;
		case 'f': ro->from = r_num_math (NULL, opt.arg); break;
		case 't': ro->to = 1 + r_num_math (NULL, opt.arg); break;
		case 'v': show_version = true; break;
		case 'h': ret (do_help (0));
		case 's': setHashString (opt.arg, 0); break;
		case 'x': setHashString (opt.arg, 1); break;
		case 'c': compareStr = opt.arg; break;
		default: ret (do_help (0));
		}
	}
	if (show_version) {
		ret (r_main_version_print ("rahash2", rad));
	}

	if (listplugins) {
		if (rad == 'j' && ro->quiet) {
			rad = 'J';
		}
		algolist (rad);
		ret (0);
	}
	algo = r_list_empty (algos)? strdup ("sha1"): r_str_list_join (algos, ",");
	if (compareStr) {
		int compareBin_len;
		if (bsize && !ro->incremental) {
			R_LOG_ERROR ("Option -c incompatible with -b and -B options");
			ret (1);
		}
		if (check_base_flags (ro)) {
			R_LOG_ERROR ("Option -c incompatible with -E base64, -E base91, -D base64 or -D base91 options");
			ret (1);
		}
		algobit = r_hash_name_to_bits (algo);
		// if algobit represents a single algorithm then it's a power of 2
		if (!is_power_of_two (algobit)) {
			R_LOG_ERROR ("Option -c incompatible with multiple algorithms in -a");
			ret (1);
		}
		compareBin = malloc ((strlen (compareStr) + 1) * 2);
		if (!compareBin) {
			ret (1);
		}
		compareBin_len = r_hex_str2bin (compareStr, compareBin);
		if (compareBin_len < 1) {
			R_LOG_ERROR ("Invalid -c hex hash");
			free (compareBin);
			ret (1);
		}
		if (compareBin_len != r_hash_size (algobit)) {
			R_LOG_ERROR ("Given -c hash has %d byte(s) but the selected algorithm returns %d byte(s)",
				compareBin_len,
				r_hash_size (algobit));
			free (compareBin);
			ret (1);
		}
	}
	ro->mode = rad;
	if ((st64)ro->from >= 0 && (st64)ro->to < 0) {
		ro->to = 0; // end of file
	}
	if (ro->from || ro->to) {
		if (ro->to && ro->from >= ro->to) {
			R_LOG_ERROR ("Invalid -f or -t offsets");
			ret (1);
		}
	}
	if (ptype) {
		// TODO: support p=%s (horizontal bars)
		// TODO: list supported statistical metrics
		// TODO: support -f and -t
		for (i = opt.ind; i < argc; i++) {
			printf ("%s:\n", argv[i]);
			r_sys_cmdf ("r2 -qfnc \"p==%s 100\" \"%s\"", ptype, argv[i]);
		}
		ret (0);
	}
	// convert iv to hex or string.
	if (ivseed) {
		iv = (ut8 *)malloc (strlen (ivseed) + 128);
		if (!strncmp (ivseed, "s:", 2)) {
			strcpy ((char *)iv, ivseed + 2);
			ivlen = strlen (ivseed + 2);
		} else {
			ivlen = r_hex_str2bin (ivseed, iv);
			if (ivlen < 1) {
				strcpy ((char *)iv, ivseed);
				ivlen = strlen (ivseed);
			}
		}
	}
	do_hash_seed (ro, seed);
	if (hashstr) {
#define INSIZE 32768
		_ret = 0;
		if (!strcmp (hashstr, "-")) {
			free (hashstr);
			hashstr = malloc (INSIZE);
			if (!hashstr) {
				ret (1);
			}
			bytes_read = fread ((void *)hashstr, 1, INSIZE - 1, stdin);
			if (bytes_read < 1) {
				bytes_read = 0;
			}
			hashstr[bytes_read] = '\0';
			hashstr_len = bytes_read;
		}
		if (hashstr_hex) {
			ut8 *out = malloc ((strlen (hashstr) + 1) * 2);
			hashstr_len = r_hex_str2bin (hashstr, out);
			if (hashstr_len < 1) {
				R_LOG_ERROR ("Invalid hex string");
				free (out);
				ret (1);
			}
			free (hashstr);
			hashstr = (char *)out;
			/* out memleaks here, hashstr can't be freed */
		} else {
			if (!bytes_read) {
				hashstr_len = strlen (hashstr);
			}
		}
		if (ro->from) {
			if (ro->from >= hashstr_len) {
				R_LOG_ERROR ("Invalid -f");
				ret (1);
			}
		}
		if (ro->to) {
			if (ro->to > hashstr_len) {
				R_LOG_ERROR ("Invalid -t");
				ret (1);
			}
		} else {
			ro->to = hashstr_len;
		}
		char *nhashstr = hashstr + ro->from;
		hashstr_len = ro->to - ro->from;
		nhashstr[hashstr_len] = '\0';
		if (!bytes_read && !hashstr_hex) {
			hashstr_len = r_str_unescape (nhashstr);
		}
		if (ro->direction != -1) {
			ret (encrypt_or_decrypt (ro, nhashstr, hashstr_len, iv, ivlen, 0));
		} else {
			char *str = (char *)nhashstr;
			int strsz = hashstr_len;
			if (ro->_s) {
				// alloc/concat/resize
				str = malloc (strsz + ro->s.len);
				if (ro->s.prefix) {
					memcpy (str, ro->s.buf, ro->s.len);
					memcpy (str + ro->s.len, nhashstr, hashstr_len);
				} else {
					memcpy (str, nhashstr, hashstr_len);
					memcpy (str + strsz, ro->s.buf, ro->s.len);
				}
				strsz += ro->s.len;
				str[strsz] = 0;
			}
			algobit = r_hash_name_to_bits (algo);
			if (algobit == 0) {
				R_LOG_ERROR ("Invalid algorithm. See -E, -D maybe?");
				if (str != nhashstr) {
					free (str);
				}
				ret (1);
			}
			PJ *pj = NULL;
			if (rad == 'j' || rad == 'J') {
				pj = pj_new ();
				if (!pj) {
					if (str != nhashstr) {
						free (str);
					}
					ret (1);
				}
				if (rad == 'J') {
					pj_o (pj);
				} else {
					pj_a (pj);
				}
			}
			int mode = rad;
			if (ro->quiet) {
				mode = 'q';
			}
			for (i = 1; i < R_HASH_ALL; i <<= 1) {
				if (algobit & i) {
					ut64 hashbit = i & algobit;
					ctx = r_hash_new (true, hashbit);
					ro->from = 0;
					ro->to = strsz;
					do_hash_internal (ctx, ro, hashbit, (const ut8 *)str, strsz, pj, rad, 1);
					compare_hashes (ctx, ro, compareBin, r_hash_size (algobit), &_ret, mode);
					r_hash_free (ctx);
				}
			}
			if (rad == 'j' || rad == 'J') {
				pj_end (pj);
				printf ("%s\n", pj_string (pj));
				pj_free (pj);
			}
			if (str != nhashstr) {
				hashstr = NULL;
			}
			if (ro->_s) {
				if (str != nhashstr) {
					R_FREE (str);
				}
				R_FREE (ro->s.buf);
			}
			hashstr = NULL;
			ret (_ret);
		}
	}
	if (opt.ind >= argc) {
		ret (do_help (1));
	}
	if (numblocks) {
		bsize = -bsize;
	} else if (bsize < 0) {
		R_LOG_ERROR ("Invalid block size");
		ret (1);
	}

	io = r_io_new ();
	for (_ret = 0, i = opt.ind; i < argc; i++) {
		file = argv[i];
		if (file && !*file) {
			R_LOG_ERROR ("Cannot open empty path");
			ret (1);
		}

		if (ro->direction != -1) {
			int rt = encrypt_or_decrypt_file (ro, argv[i], iv, ivlen, 0);
			if (rt == -1) {
				continue;
			}
			ret (rt);
		} else {
			RIODesc *desc = NULL;
			if (!strcmp (argv[i], "-")) {
				int sz = 0;
				ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
				char *uri = r_str_newf ("malloc://%d", sz);
				if (sz > 0) {
					desc = r_io_open_nomap (io, uri, R_PERM_R, 0);
					if (!desc) {
						R_LOG_ERROR ("Cannot open malloc://1024");
						ret (1);
					}
					r_io_pwrite_at (io, 0, buf, sz);
				}
				free (uri);
				free (buf);
			} else {
				if (r_file_is_directory (argv[i])) {
					R_LOG_ERROR ("Cannot hash directories");
					ret (1);
				}
				desc = r_io_open_nomap (io, argv[i], R_PERM_R, 0);
				if (!desc) {
					R_LOG_ERROR ("Cannot open '%s'", argv[i]);
					ret (1);
				}
			}
			// TODO: move some args into the ro struct
			_ret |= do_hash (ro, argv[i], algo, io, bsize, rad, ule, compareBin);
			ro->to = 0;
			r_io_desc_close (desc);
		}
	}
beach:
	r_list_free (algos);
	free (algo);
	free (hashstr);
	r_io_free (io);
	free (iv);

	return _ret;
#undef ret
}
