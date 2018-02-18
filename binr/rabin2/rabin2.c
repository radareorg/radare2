/* radare - LGPL - Copyright 2009-2018 - nibble, pancake */

#include <getopt.c>
#include <r_core.h>
#include <r_types.h>
#include <r_util.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../libr/bin/pdb/pdb_downloader.h"
#include "../blob/version.c"

static struct r_bin_t *bin = NULL;
static char* output = NULL;
static char* create = NULL;
static int rad = false;
static ut64 laddr = UT64_MAX;
static ut64 baddr = UT64_MAX;
static char* file = NULL;
static char *name = NULL;
static int rw = false;
static int va = true;
static char *stdin_buf = NULL;
static const char *do_demangle = NULL;
static ut64 at = 0LL;
static RLib *l;

static int rabin_show_help(int v) {
	printf ("Usage: rabin2 [-AcdeEghHiIjlLMqrRsSUvVxzZ] [-@ at] [-a arch] [-b bits] [-B addr]\n"
		"              [-C F:C:D] [-f str] [-m addr] [-n str] [-N m:M] [-P[-P] pdb]\n"
		"              [-o str] [-O str] [-k query] [-D lang symname] | file\n");
	if (v) {
		printf (
		" -@ [addr]       show section, symbol or import at addr\n"
		" -A              list sub-binaries and their arch-bits pairs\n"
		" -a [arch]       set arch (x86, arm, .. or <arch>_<bits>)\n"
		" -b [bits]       set bits (32, 64 ...)\n"
		" -B [addr]       override base address (pie bins)\n"
		" -c              list classes\n"
		" -cc             list classes in header format\n"
		" -C [fmt:C:D]    create [elf,mach0,pe] with Code and Data hexpairs (see -a)\n"
		" -d              show debug/dwarf information\n"
		" -D lang name    demangle symbol name (-D all for bin.demangle=true)\n"
		" -e              entrypoint\n"
		" -ee             constructor/destructor entrypoints\n"
		" -E              globally exportable symbols\n"
		" -f [str]        select sub-bin named str\n"
		" -F [binfmt]     force to use that bin plugin (ignore header check)\n"
		" -g              same as -SMZIHVResizcld (show all info)\n"
		" -G [addr]       load address . offset to header\n"
		" -h              this help message\n"
		" -H              header fields\n"
		" -i              imports (symbols imported from libraries)\n"
		" -I              binary info\n"
		" -j              output in json\n"
		" -k [sdb-query]  run sdb query. for example: '*'\n"
		" -K [algo]       calculate checksums (md5, sha1, ..)\n"
		" -l              linked libraries\n"
		" -L [plugin]     list supported bin plugins or plugin details\n"
		" -m [addr]       show source line at addr\n"
		" -M              main (show address of main symbol)\n"
		" -n [str]        show section, symbol or import named str\n"
		" -N [min:max]    force min:max number of chars per string (see -z and -zz)\n"
		" -o [str]        output file/folder for write operations (out by default)\n"
		" -O [str]        write/extract operations (-O help)\n"
		" -p              show physical addresses\n"
		" -P              show debug/pdb information\n"
		" -PP             download pdb file for binary\n"
		" -q              be quiet, just show fewer data\n"
		" -qq             show less info (no offset/size for -z for ex.)\n"
		" -Q              show load address used by dlopen (non-aslr libs)\n"
		" -r              radare output\n"
		" -R              relocations\n"
		" -s              symbols\n"
		" -S              sections\n"
		" -u              unfiltered (no rename duplicated symbols/sections)\n"
		" -U              resoUrces\n"
		" -v              display version and quit\n"
		" -V              Show binary version information\n"
		" -x              extract bins contained in file\n"
		" -X [fmt] [f] .. package in fat or zip the given files and bins contained in file\n"
		" -z              strings (from data section)\n"
		" -zz             strings (from raw bins [e bin.rawstr=1])\n"
		" -zzz            dump raw strings to stdout (for huge files)\n"
		" -Z              guess size of binary program\n"
		);
	}
	if (v) {
		printf ("Environment:\n"
		" RABIN2_LANG:      e bin.lang         # assume lang for demangling\n"
		" RABIN2_NOPLUGINS: # do not load shared plugins (speedup loading)\n"
		" RABIN2_DEMANGLE=0:e bin.demangle     # do not demangle symbols\n"
		" RABIN2_MAXSTRBUF: e bin.maxstrbuf    # specify maximum buffer size\n"
		" RABIN2_STRFILTER: e bin.strfilter    # r2 -qe bin.strfilter=? -c '' --\n"
		" RABIN2_STRPURGE:  e bin.strpurge     # try to purge false positives\n"
		" RABIN2_DEBASE64:  e bin.debase64     # try to debase64 all strings\n"
		" RABIN2_DMNGLRCMD: e bin.demanglercmd # try to purge false positives\n"
		" RABIN2_PDBSERVER: e pdb.server       # use alternative PDB server\n"
		" RABIN2_SYMSTORE:  e pdb.symstore     # path to downstream symbol store\n"
		" RABIN2_PREFIX:    e bin.prefix       # prefix symbols/sections/relocs with a specific string\n");
	}
	return 1;
}

static char *stdin_gets() {
#define STDIN_BUF_SIZE 96096
	if (!stdin_buf) {
		/* XXX: never freed. leaks! */
		stdin_buf = malloc (STDIN_BUF_SIZE);
		if (!stdin_buf) {
			return NULL;
		}
	}
	memset (stdin_buf, 0, STDIN_BUF_SIZE);
        fgets (stdin_buf, STDIN_BUF_SIZE - 1, stdin);
		if (feof (stdin)) {
			return NULL;
		}
        stdin_buf[strlen (stdin_buf) - 1] = 0;
        return strdup (stdin_buf);
}

static void __sdb_prompt(Sdb *sdb) {
	char *line;
	for (; (line = stdin_gets ());) {
		sdb_query (sdb, line);
		free (line);
	}
}

static bool isBinopHelp(const char *op) {
	if (!op) {
		return false;
	}
	if (!strcmp (op, "help")) {
		return true;
	}
	if (!strcmp (op, "?")) {
		return true;
	}
	if (!strcmp (op, "h")) {
		return true;
	}
	return false;
}

static bool extract_binobj(const RBinFile *bf, RBinXtrData *data, int idx) {
	ut64 bin_size = data ? data->size : 0;
	ut8 *bytes;
	char *arch = "unknown";
	int bits = 0;
	char *libname = NULL;
	const char *filename = bf ? bf->file : NULL;
	char *path = NULL, *outpath = NULL, *outfile = NULL, *ptr = NULL;
	ut32 outfile_sz = 0, outpath_sz = 0;
	bool res = false;

	if (!bf || !data || !filename) {
		return false;
	}
	if (data->metadata) {
		arch = data->metadata->arch;
		bits = data->metadata->bits;
		libname = data->metadata->libname;
	}
	if (bin_size == bf->size && bin_size) {
		eprintf ("This is not a fat bin\n");
		return false;
	}
	bytes = data->buffer;
	if (!bytes) {
		eprintf ("error: BinFile buffer is empty\n");
		return false;
	}
	if (!arch) {
		arch = "unknown";
	}
	path = strdup (filename);
	if (!path) {
		return false;
	}
	// XXX: Wrong for w32 (/)
	ptr = strrchr (path, DIRSEP);
	if (ptr) {
		*ptr++ = '\0';
	} else {
		ptr = path;
	}
	outpath_sz = strlen (path) + 20;
	if (outpath_sz > 0) {
		outpath = malloc (outpath_sz);
	}

	if (outpath) {
		snprintf (outpath, outpath_sz, "%s.fat", ptr);
	}
	if (!outpath || !r_sys_mkdirp (outpath)) {
		free (path);
		free (outpath);
		eprintf ("Error creating dir structure\n");
		return false;
	}

	outfile_sz = outpath_sz + strlen (ptr) + strlen (arch) + 23;
	if (outfile_sz) {
		outfile = malloc (outfile_sz);
	}

	if (outfile) {
		if (libname) {
			snprintf (outfile, outfile_sz, "%s/%s.%s.%s_%i.%d",
					  outpath, ptr, arch, libname, bits, idx);
		} else {
			snprintf (outfile, outfile_sz, "%s/%s.%s_%i.%d",
					  outpath, ptr, arch, bits, idx);
		}
	}

	if (!outfile || !r_file_dump (outfile, bytes, bin_size, 0)) {
		eprintf ("Error extracting %s\n", outfile);
		res = false;
	} else {
		printf ("%s created (%"PFMT64d")\n", outfile, bin_size);
		res = true;
	}

	free (outfile);
	free (outpath);
	free (path);
	R_FREE (data->buffer);
	return res;
}

static int rabin_extract(int all) {
	RBinXtrData *data = NULL;
	int res = false;
	RBinFile *bf = r_bin_cur (bin);

	if (!bf) {
		return res;
	}
	if (all) {
		int idx = 0;
		RListIter *iter;
		r_list_foreach (bf->xtr_data, iter, data) {
			res = extract_binobj (bf, data, idx++);
			if (!res) {
				break;
			}
		}
	} else {
		data = r_list_get_n (bf->xtr_data, 0);
		if (!data) {
			return res;
		}
		res = extract_binobj (bf, data, 0);
	}
	return res;
}

static int rabin_dump_symbols(int len) {
	RList *symbols;
	RListIter *iter;
	RBinSymbol *symbol;
	ut8 *buf;
	char *ret;
	int olen = len;

	if (!(symbols = r_bin_get_symbols (bin))) {
		return false;
	}

	r_list_foreach (symbols, iter, symbol) {
		if (symbol->size && (olen > symbol->size || !olen)) {
			len = symbol->size;
		} else if (!symbol->size && !olen) {
			len = 32;
		} else {
			len = olen;
		}
		if (!(buf = calloc (1, len))) {
			return false;
		}
		if (!(ret = malloc ((len * 2) + 1))) {
			free (buf);
			return false;
		}
		if (r_buf_read_at (bin->cur->buf, symbol->paddr, buf, len) == len) {
			r_hex_bin2str (buf, len, ret);
			printf ("%s %s\n", symbol->name, ret);
		} else {
			eprintf ("Cannot read from buffer\n");
		}
		free (buf);
		free (ret);
	}
	return true;
}

static int rabin_dump_sections(char *scnname) {
	RList *sections;
	RListIter *iter;
	RBinSection *section;
	ut8 *buf;
	char *ret;
	int r;

	if (!(sections = r_bin_get_sections (bin))) {
		return false;
	}

	r_list_foreach (sections, iter, section) {
		if (!strcmp (scnname, section->name)) {
			if (!(buf = malloc (section->size))) {
				return false;
			}
			if ((section->size * 2) + 1 < section->size) {
				free (buf);
				return false;
			}
			if (!(ret = malloc (section->size*2+1))) {
				free (buf);
				return false;
			}
			if (section->paddr > bin->cur->buf->length ||
			  section->paddr + section->size > bin->cur->buf->length) {
				free (buf);
				free (ret);
				return false;
			}
			r = r_buf_read_at (bin->cur->buf, section->paddr,
					buf, section->size);
			if (r < 1) {
				free (buf);
				free (ret);
				return false;
			}
			//it does mean the user specified an output file
			if (strcmp (output, file)) {
				r_file_dump (output, buf, section->size, 0);
			} else {
				r_hex_bin2str (buf, section->size, ret);
				printf ("%s\n", ret);
			}
			free (buf);
			free (ret);
			break;
		}
	}
	return true;
}

static int rabin_do_operation(const char *op) {
	char *arg = NULL, *ptr = NULL, *ptr2 = NULL;
	bool rc = true;

	/* Implement alloca with fixed-size buffer? */
	if (!(arg = strdup (op))) {
		return false;
	}

	if ((ptr = strchr (arg, '/'))) {
		*ptr++ = 0;
		if ((ptr2 = strchr (ptr, '/'))) {
			ptr2[0] = '\0';
			ptr2++;
		}
	}
	if (!output) {
		output = file;
	}

	switch (arg[0]) {
	case 'e':
		rc = r_bin_wr_entry (bin, r_num_math (NULL, ptr));
		if (rc) {
			rc = r_bin_wr_output (bin, output);
		}
		break;
	case 'd':
		if (!ptr) {
			goto _rabin_do_operation_error;
		}
		switch (*ptr) {
		case 's':
			if (ptr2) {
				if (!rabin_dump_symbols (r_num_math (NULL, ptr2))) {
					goto error;
				}
			} else if (!rabin_dump_symbols (0)) {
				goto error;
			}
			break;
		case 'S':
			if (!ptr2) {
				goto _rabin_do_operation_error;
			}
			if (!rabin_dump_sections (ptr2)) {
				goto error;
			}
			break;
		default:
			goto _rabin_do_operation_error;
		}
		break;
	case 'a':
		if (!ptr) {
			goto _rabin_do_operation_error;
		}
		switch (*ptr) {
		case 'l':
			if (!ptr2 || !r_bin_wr_addlib (bin, ptr2)) {
				goto error;
			}
			break;
		default:
			goto _rabin_do_operation_error;
		}
		break;
	case 'R':
		r_bin_wr_rpath_del (bin);
		rc = r_bin_wr_output (bin, output);
		break;
	case 'C':
		{
		RBinFile *cur   = r_bin_cur (bin);
		RBinPlugin *plg = r_bin_file_cur_plugin (cur);
		if (!plg) {
			//are we in xtr?
			if (cur->xtr_data) {
				//load the first one
				RBinXtrData *xtr_data = r_list_get_n (cur->xtr_data, 0);
				if (!r_bin_file_object_new_from_xtr_data (bin, cur,
						  UT64_MAX, r_bin_get_laddr (bin), xtr_data)) {
					break;
				}
			}
			plg = r_bin_file_cur_plugin (cur);
			if (!plg) {
				break;
			}
		}
		if (plg->signature) {
			const char *sign = plg->signature (cur, rad == R_CORE_BIN_JSON);
			r_cons_println (sign);
			r_cons_flush ();
			free ((char*) sign);
		}
		}
		break;
	case 'r':
		r_bin_wr_scn_resize (bin, ptr, r_num_math (NULL, ptr2));
		rc = r_bin_wr_output (bin, output);
		break;
	case 'p':
		{
			int perms = (int)r_num_math (NULL, ptr2);
			if (!perms) {
				perms = r_str_rwx (ptr2);
			}
			r_bin_wr_scn_perms (bin, ptr, perms);
			rc = r_bin_wr_output (bin, output);
		}
		break;
	default:
	_rabin_do_operation_error:
		eprintf ("Unknown operation. use -O help\n");
		goto error;
	}
	if (!rc) {
		eprintf ("Cannot dump :(\n");
	}
	free (arg);
	return true;
error:
	free (arg);
	return false;
}

static int rabin_show_srcline(ut64 at) {
	char *srcline;
	if ((srcline = r_bin_addr2text (bin, at, true))) {
		printf ("%s\n", srcline);
		free (srcline);
		return true;
	}
	return false;
}

/* bin callback */
static int __lib_bin_cb(RLibPlugin *pl, void *user, void *data) {
	struct r_bin_plugin_t *hand = (struct r_bin_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_add (bin, hand);
	return true;
}

static int __lib_bin_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

/* binxtr callback */
static int __lib_bin_xtr_cb(RLibPlugin *pl, void *user, void *data) {
	struct r_bin_xtr_plugin_t *hand = (struct r_bin_xtr_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_xtr_add (bin, hand);
	return true;
}

static int __lib_bin_xtr_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

/* binldr callback */
static int __lib_bin_ldr_cb(RLibPlugin *pl, void *user, void *data) {
	struct r_bin_ldr_plugin_t *hand = (struct r_bin_ldr_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_ldr_add (bin, hand);
	return true;
}

static int __lib_bin_ldr_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

static char *demangleAs(int type) {
	char *res = NULL;
	switch (type) {
	case R_BIN_NM_CXX: res = r_bin_demangle_cxx (NULL, file, 0); break;
	case R_BIN_NM_JAVA: res = r_bin_demangle_java (file); break;
	case R_BIN_NM_OBJC: res = r_bin_demangle_objc (NULL, file); break;
	case R_BIN_NM_SWIFT: res = r_bin_demangle_swift (file, 0); break; // XX: use
	case R_BIN_NM_MSVC: res = r_bin_demangle_msvc (file); break;
	case R_BIN_NM_RUST: res = r_bin_demangle_rust (NULL, file, 0); break;
	default:
		eprintf ("Unsupported demangler\n");
		break;
	}
	return res;
}

static int rabin_list_plugins(const char* plugin_name) {
	int json = 0;

	if (rad == R_CORE_BIN_JSON) {
		json = 'j';
	} else if (rad) {
		json = 'q';
	}

	bin->cb_printf = (PrintfCallback)printf;

	if (plugin_name) {
		return r_bin_list_plugin (bin, plugin_name, json);
	}
	return r_bin_list (bin, json);
}

int main(int argc, char **argv) {
	const char *query = NULL;
	int c, bits = 0, actions_done = 0, actions = 0;
	ut64 action = R_BIN_REQ_UNK;
	char *tmp, *ptr, *arch = NULL, *arch_name = NULL;
	const char *forcebin = NULL;
	const char *chksum = NULL;
	const char *op = NULL;
	const char *path = NULL;
	RCoreBinFilter filter;
	int xtr_idx = 0; // load all files if extraction is necessary.
	int rawstr = 0;
	int fd = -1;
	RCore core = {0};

	r_core_init (&core);
	bin = core.bin;

	if (!(tmp = r_sys_getenv ("RABIN2_NOPLUGINS"))) {
		char *homeplugindir = r_str_home (R2_HOMEDIR "/plugins");
		l = r_lib_new ("radare_plugin");
		r_lib_add_handler (l, R_LIB_TYPE_BIN, "bin plugins",
			&__lib_bin_cb, &__lib_bin_dt, NULL);
		r_lib_add_handler (l, R_LIB_TYPE_BIN_XTR, "bin xtr plugins",
			&__lib_bin_xtr_cb, &__lib_bin_xtr_dt, NULL);
		r_lib_add_handler (l, R_LIB_TYPE_BIN_LDR, "bin ldr plugins",
			&__lib_bin_ldr_cb, &__lib_bin_ldr_dt, NULL);
		/* load plugins everywhere */

		path = r_sys_getenv (R_LIB_ENV);
		if (path && *path) {
			r_lib_opendir (l, path);
		}
		r_lib_opendir (l, homeplugindir);
		free (homeplugindir);
		r_lib_opendir (l, R2_LIBDIR "/radare2/" R2_VERSION);
		r_lib_opendir (l, R2_LIBDIR "/radare2-extras/" R2_VERSION);
		r_lib_opendir (l, R2_LIBDIR "/radare2-bindings/" R2_VERSION);
	}
	free (tmp);

	if ((tmp = r_sys_getenv ("RABIN2_DMNGLRCMD"))) {
		r_config_set (core.config, "bin.demanglecmd", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_LANG"))) {
		r_config_set (core.config, "bin.lang", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_DEMANGLE"))) {
		r_config_set (core.config, "bin.demangle", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_MAXSTRBUF"))) {
		r_config_set (core.config, "bin.maxstrbuf", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_STRFILTER"))) {
		r_config_set (core.config, "bin.strfilter", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_STRPURGE"))) {
		r_config_set (core.config, "bin.strpurge", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_DEBASE64"))) {
		r_config_set (core.config, "bin.debase64", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_PDBSERVER"))) {
		r_config_set (core.config, "pdb.server", tmp);
		free (tmp);
	}

#define is_active(x) (action & x)
#define set_action(x) { actions++; action |= x; }
#define unset_action(x) action &= ~x
	while ((c = getopt (argc, argv, "DjgAf:F:a:B:G:b:cC:k:K:dD:Mm:n:N:@:isSVIHeEUlRwO:o:pPqQrvLhuxXzZ")) != -1) {
		switch (c) {
		case 'g':
			set_action (R_BIN_REQ_CLASSES);
			set_action (R_BIN_REQ_IMPORTS);
			set_action (R_BIN_REQ_SYMBOLS);
			set_action (R_BIN_REQ_SECTIONS);
			set_action (R_BIN_REQ_STRINGS);
			set_action (R_BIN_REQ_SIZE);
			set_action (R_BIN_REQ_INFO);
			set_action (R_BIN_REQ_FIELDS);
			set_action (R_BIN_REQ_DWARF);
			set_action (R_BIN_REQ_ENTRIES);
			set_action (R_BIN_REQ_MAIN);
			set_action (R_BIN_REQ_LIBS);
			set_action (R_BIN_REQ_RELOCS);
			set_action (R_BIN_REQ_VERSIONINFO);
			break;
		case 'V': set_action (R_BIN_REQ_VERSIONINFO); break;
		case 'q':
			rad = (rad & R_CORE_BIN_SIMPLE ?
				R_CORE_BIN_SIMPLEST : R_CORE_BIN_SIMPLE);
			break;
		case 'j': rad = R_CORE_BIN_JSON; break;
		case 'A': set_action (R_BIN_REQ_LISTARCHS); break;
		case 'a': arch = optarg; break;
		case 'C':
			set_action (R_BIN_REQ_CREATE);
			create = strdup (optarg);
			break;
		case 'u': bin->filter = 0; break;
		case 'k': query = optarg; break;
		case 'K': chksum = optarg; break;
		case 'c': 
			if (is_active (R_BIN_REQ_CLASSES)) {
				rad = R_CORE_BIN_CLASSDUMP;
			} else {
			  	set_action (R_BIN_REQ_CLASSES); 
			}
			break;
		case 'f': arch_name = strdup (optarg); break;
		case 'F': forcebin = optarg; break;
		case 'b': bits = r_num_math (NULL, optarg); break;
		case 'm':
			at = r_num_math (NULL, optarg);
			set_action (R_BIN_REQ_SRCLINE);
			break;
		case 'i': set_action (R_BIN_REQ_IMPORTS); break;
		case 's': set_action (R_BIN_REQ_SYMBOLS); break;
		case 'S': set_action (R_BIN_REQ_SECTIONS); break;
		case 'z':
			if (is_active (R_BIN_REQ_STRINGS)) {
				if (rawstr) {
					/* rawstr mode 2 means that we are not going */
					/* to store them just dump'm all to stdout */
					rawstr = 2;
				} else {
					rawstr = 1;
				}
			} else {
				set_action (R_BIN_REQ_STRINGS);
			}
			break;
		case 'Z': set_action (R_BIN_REQ_SIZE); break;
		case 'I': set_action (R_BIN_REQ_INFO); break;
		case 'H':
			set_action (R_BIN_REQ_FIELDS);
			break;
		case 'd': set_action (R_BIN_REQ_DWARF); break;
		case 'P':
			if (is_active (R_BIN_REQ_PDB)) {
				set_action (R_BIN_REQ_PDB_DWNLD);
			} else {
				set_action (R_BIN_REQ_PDB);
			}
			break;
		case 'D':
			if (argv[optind] && argv[optind+1] && \
				(!argv[optind+1][0] || !strcmp (argv[optind+1], "all"))) {
				r_config_set (core.config, "bin.lang", argv[optind]);
				r_config_set (core.config, "bin.demangle", "true");
				optind += 2;
			} else {
				do_demangle = argv[optind];
			}
			break;
		case 'e':
			if (action & R_BIN_REQ_ENTRIES) {
				action &= ~R_BIN_REQ_ENTRIES;
				action |= R_BIN_REQ_INITFINI;
			} else {
				set_action (R_BIN_REQ_ENTRIES);
			}
			break;
		case 'E': set_action (R_BIN_REQ_EXPORTS); break;
		case 'U': set_action (R_BIN_REQ_RESOURCES); break;
		case 'Q': set_action (R_BIN_REQ_DLOPEN); break;
		case 'M': set_action (R_BIN_REQ_MAIN); break;
		case 'l': set_action (R_BIN_REQ_LIBS); break;
		case 'R': set_action (R_BIN_REQ_RELOCS); break;
		case 'x': set_action (R_BIN_REQ_EXTRACT); break;
		case 'X': set_action (R_BIN_REQ_PACKAGE); break;
		case 'w': rw = true; break;
		case 'O':
			op = optarg;
			set_action (R_BIN_REQ_OPERATION);
			if (isBinopHelp (op)) {
				printf ("Operation string:\n"
					"  Change Entrypoint: e/0x8048000\n"
					"  Dump Symbols: d/s/1024\n"
					"  Dump Section: d/S/.text\n"
					"  Resize Section: r/.data/1024\n"
					"  Remove RPATH: R\n"
					"  Add Library: a/l/libfoo.dylib\n"
					"  Change Permissions: p/.data/rwx\n"
					"  Show LDID entitlements: C\n");
				r_core_fini (&core);
				return 0;
			}
			if (optind == argc) {
				eprintf ("Missing filename\n");
				r_core_fini (&core);
				return 1;
			}
			break;
		case 'o': output = optarg; break;
		case 'p': va = false; break;
		case 'r': rad = true; break;
		case 'v': return blob_version ("rabin2");
		case 'L':
			set_action (R_BIN_REQ_LISTPLUGINS);
			break;
		case 'G':
			laddr = r_num_math (NULL, optarg);
			if (laddr == UT64_MAX) {
				va = false;
			}
			break;
		case 'B':
			baddr = r_num_math (NULL, optarg);
			break;
		case '@':
			at = r_num_math (NULL, optarg);
			break;
		case 'n':
			name = optarg;
			break;
		case 'N':
			tmp = strchr (optarg, ':');
			r_config_set (core.config, "bin.minstr", optarg);
			if (tmp) {
				r_config_set (core.config, "bin.maxstr", tmp + 1);
			}
			break;
		case 'h':
			  r_core_fini (&core);
			  return rabin_show_help (1);
		default: action |= R_BIN_REQ_HELP;
		}
	}

	if (is_active (R_BIN_REQ_LISTPLUGINS)) {
		const char* plugin_name = NULL;
		if (optind < argc) {
			plugin_name = argv[optind];
		}
		rabin_list_plugins (plugin_name);
		return 0;
	}

	if (do_demangle) {
		char *res = NULL;
		int type;
		if ((argc - optind) < 2) {
			return rabin_show_help (0);
		}
		type = r_bin_demangle_type (do_demangle);
		file = argv[optind + 1];
		if (!strcmp (file, "-")) {
			for (;;) {
				file = stdin_gets();
				if (!file || !*file) {
					break;
				}
				res = demangleAs (type);
				if (!res) {
					eprintf ("Unknown lang to demangle. Use: cxx, java, objc, swift\n");
					return 1;
				}
				if (res && *res) {
					printf ("%s\n", res);
				} else if (file && *file) {
					printf ("%s\n", file);
				}
				R_FREE (res);
				R_FREE (file);
			}
		} else {
			res = demangleAs (type);
			if (res && *res) {
				printf ("%s\n", res);
				free(res);
				return 0;
			} else {
				printf ("%s\n", file);
			}
		}
		free (res);
		//eprintf ("%s\n", file);
		return 1;
	}
	file = argv[optind];
	if (!query) {
		if (action & R_BIN_REQ_HELP || action == R_BIN_REQ_UNK || !file) {
			r_core_fini (&core);
			return rabin_show_help (0);
		}
	}
	if (arch) {
		ptr = strchr (arch, '_');
		if (ptr) {
			*ptr = '\0';
			bits = r_num_math (NULL, ptr+1);
		}
	}
	if (action & R_BIN_REQ_CREATE) {
		// TODO: move in a function outside
		RBuffer *b;
		int datalen, codelen;
		ut8 *data = NULL, *code = NULL;
		char *p2, *p = strchr (create, ':');
		if (!p) {
			eprintf ("Invalid format for -C flag. Use 'format:codehexpair:datahexpair'\n");
			r_core_fini (&core);
			return 1;
		}
		*p++ = 0;
		p2 = strchr (p, ':');
		if (p2) {
			// has data
			*p2++ = 0;
			data = malloc (strlen (p2)+1);
			datalen = r_hex_str2bin (p2, data);
			if (datalen < 0) datalen = -datalen;
		} else {
			data = NULL;
			datalen = 0;
		}
		code = malloc (strlen (p) + 1);
		if (!code) {
			r_core_fini (&core);
			return 1;
		}
		codelen = r_hex_str2bin (p, code);
		if (!arch) {
			arch = R_SYS_ARCH;
		}
		if (!bits) {
			bits = 32;
		}
		if (!r_bin_use_arch (bin, arch, bits, create)) {
			eprintf ("Cannot set arch\n");
			r_core_fini (&core);
			return 1;
		}
		b = r_bin_create (bin, code, codelen, data, datalen);
		if (b) {
			if (r_file_dump (file, b->buf, b->length, 0)) {
				eprintf ("Dumped %"PFMT64d" bytes in '%s'\n", b->length, file);
				r_file_chmod (file, "+x", 0);
			} else {
				eprintf ("Error dumping into a.out\n");
			}
			r_buf_free (b);
		} else {
			eprintf ("Cannot create binary for this format '%s'.\n", create);
		}
		r_core_fini (&core);
		return 0;
	}
	if (rawstr == 2) {
		unset_action (R_BIN_REQ_STRINGS);
	}
	r_config_set_i (core.config, "bin.rawstr", rawstr);

	if (!file) {
		eprintf ("Missing file.\n");
		return 1;
	}

	if (file && *file && action & R_BIN_REQ_DLOPEN) {
#if __UNIX__
		int child = r_sys_fork ();
		if (child == -1) {
			return 1;
		}
		if (child == 0) {
			return waitpid (child, NULL, 0);
		}
#endif
		void *addr = r_lib_dl_open (file);
		if (addr) {
			eprintf ("%s is loaded at 0x%"PFMT64x"\n", file, (ut64)(size_t)(addr));
			r_lib_dl_close (addr);
			return 0;
		}
		eprintf ("Cannot open the '%s' library\n", file);
		return 0;
	}
	if (action & R_BIN_REQ_PACKAGE) {
		RList *files = r_list_newf (NULL);
		const char *format = argv[optind];
		const char *file = argv[optind + 1];
		int i, rc = 0;

		if (optind + 3 > argc) {
			eprintf ("Usage: rabin2 -X [fat|zip] foo.zip a b c\n");
			return 1;
		}
		eprintf ("FMT %s\n", format);
		eprintf ("PKG %s\n", file);
		for (i = optind + 2; i < argc; i++) {
			eprintf ("ADD %s\n", argv[i]);
			r_list_append (files, argv[i]);
		}
		RBuffer *buf = r_bin_package (core.bin, format, file, files);
		/* TODO: return bool or something to catch errors\n") */
		if (buf) {
			bool ret = r_buf_dump (buf, file);
			r_buf_free (buf);
			if (!ret) {
				rc = 1;
			}
		}
		r_core_fini (&core);
		return rc;
	}

	if (file && *file) {
		if (r_core_file_open (&core, file, R_IO_READ, 0)) {
			fd = r_io_fd_get_current (core.io);
			if (fd == -1) {
				eprintf ("r_core: Cannot open file '%s'\n", file);
				r_core_fini (&core);
				return 1;
			}
		}
	}
	bin->minstrlen = r_config_get_i (core.config, "bin.minstr");
	bin->maxstrbuf = r_config_get_i (core.config, "bin.maxstrbuf");

	r_bin_force_plugin (bin, forcebin);
	r_bin_load_filter (bin, action);
	if (!r_bin_load (bin, file, baddr, laddr, xtr_idx, fd, rawstr)) {
		//if this return null means that we did not return a valid bin object
		//but we have yet the chance that this file is a fat binary
		if (!bin->cur || !bin->cur->xtr_data) {
			eprintf ("r_bin: Cannot open file\n");
			r_core_fini (&core);
			return 1;
		}
	}
	/* required to automatically select a sub-bin when not specified */
	(void)r_core_bin_update_arch_bits (&core);

	if (baddr != UT64_MAX) {
		r_bin_set_baddr (bin, baddr);
	}
	if (rawstr == 2) {
		rawstr = false;
		RBinFile *bf = r_core_bin_cur (&core);
		if (bf) {
			bf->strmode = rad;
			r_bin_dump_strings (bf, bin->minstrlen);
		}
	}
	if (query) {
		if (rad) {
			r_core_bin_export_info_rad (&core);
			r_cons_flush ();
		} else {
			if (!strcmp (query, "-")) {
				__sdb_prompt (bin->cur->sdb);
			} else {
				sdb_query (bin->cur->sdb, query);
			}
		}
		r_core_fini (&core);
		return 0;
	}
#define isradjson (rad==R_CORE_BIN_JSON&&actions>0)
#define run_action(n,x,y) {\
	if (action&x) {\
		if (isradjson) r_cons_printf ("%s\"%s\":",actions_done?",":"",n);\
		if (!r_core_bin_info (&core, y, rad, va, &filter, chksum)) {\
			if (isradjson) r_cons_print ("false");\
		};\
		actions_done++;\
	}\
}
	core.bin = bin;
	bin->cb_printf = r_cons_printf;
	filter.offset = at;
	filter.name = name;
	r_cons_new ()->is_interactive = false;

	if (isradjson) {
		r_cons_print ("{");
	}
	// List fatmach0 sub-binaries, etc
	if (action & R_BIN_REQ_LISTARCHS || ((arch || bits || arch_name) &&
		!r_bin_select (bin, arch, bits, arch_name))) {
		if (rad == R_CORE_BIN_SIMPLEST || rad == R_CORE_BIN_SIMPLE) {
			r_bin_list_archs (bin, 'q');
		} else {
			r_bin_list_archs (bin, (rad == R_CORE_BIN_JSON)? 'j': 1);
		}
		actions_done++;
		free (arch_name);
	}
	if (action & R_BIN_REQ_PDB_DWNLD) {
		SPDBOptions pdbopts;
		pdbopts.user_agent = (char*) r_config_get (core.config, "pdb.useragent");
		pdbopts.symbol_server = (char*) r_config_get (core.config, "pdb.server");
		pdbopts.extract = r_config_get_i (core.config, "pdb.extract");

		if ((tmp = r_sys_getenv ("RABIN2_SYMSTORE"))) {
			r_config_set (core.config, "pdb.symstore", tmp);
			R_FREE (tmp);
		}
		pdbopts.symbol_store_path = (char*) r_config_get (core.config, "pdb.symstore");
		int r = r_bin_pdb_download (&core, isradjson, &actions_done, &pdbopts);
		r_core_fini (&core);
		return r;
	}

	if ((tmp = r_sys_getenv ("RABIN2_PREFIX"))) {
		r_config_set (core.config, "bin.prefix", tmp);
		free (tmp);
	}

	run_action ("sections", R_BIN_REQ_SECTIONS, R_CORE_BIN_ACC_SECTIONS);
	run_action ("entries", R_BIN_REQ_ENTRIES, R_CORE_BIN_ACC_ENTRIES);
	run_action ("entries", R_BIN_REQ_INITFINI, R_CORE_BIN_ACC_INITFINI);
	run_action ("main", R_BIN_REQ_MAIN, R_CORE_BIN_ACC_MAIN);
	run_action ("imports", R_BIN_REQ_IMPORTS, R_CORE_BIN_ACC_IMPORTS);
	run_action ("classes", R_BIN_REQ_CLASSES, R_CORE_BIN_ACC_CLASSES);
	run_action ("symbols", R_BIN_REQ_SYMBOLS, R_CORE_BIN_ACC_SYMBOLS);
	run_action ("exports", R_BIN_REQ_EXPORTS, R_CORE_BIN_ACC_EXPORTS);
	run_action ("resources", R_BIN_REQ_RESOURCES, R_CORE_BIN_ACC_RESOURCES);
	run_action ("strings", R_BIN_REQ_STRINGS, R_CORE_BIN_ACC_STRINGS);
	run_action ("info", R_BIN_REQ_INFO, R_CORE_BIN_ACC_INFO);
	run_action ("fields", R_BIN_REQ_FIELDS, R_CORE_BIN_ACC_FIELDS);
	run_action ("header", R_BIN_REQ_HEADER, R_CORE_BIN_ACC_HEADER);
	run_action ("libs", R_BIN_REQ_LIBS, R_CORE_BIN_ACC_LIBS);
	run_action ("relocs", R_BIN_REQ_RELOCS, R_CORE_BIN_ACC_RELOCS);
	run_action ("dwarf", R_BIN_REQ_DWARF, R_CORE_BIN_ACC_DWARF);
	run_action ("pdb", R_BIN_REQ_PDB, R_CORE_BIN_ACC_PDB);
	run_action ("size", R_BIN_REQ_SIZE, R_CORE_BIN_ACC_SIZE);
	run_action ("versioninfo", R_BIN_REQ_VERSIONINFO, R_CORE_BIN_ACC_VERSIONINFO);
	if (action & R_BIN_REQ_SRCLINE) {
		rabin_show_srcline (at);
	}
	if (action & R_BIN_REQ_EXTRACT) {
		RBinFile *bf = r_bin_cur (bin);
		if (bf && bf->xtr_data) {
			rabin_extract ((!arch && !arch_name && !bits));
		} else {
			eprintf (
				"Cannot extract bins from '%s'. No supported "
				"plugins found!\n",
				bin->file);
		}
	}
	if (op && action & R_BIN_REQ_OPERATION) {
		rabin_do_operation (op);
	}
	if (isradjson) {
		printf ("}");
	}
	r_cons_flush ();
	r_core_fini (&core);
	free (stdin_buf);

	return 0;
}
