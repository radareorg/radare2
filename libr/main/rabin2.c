/* radare - LGPL - Copyright 2009-2025 - pancake */

#include <r_core.h>
#include "../../libr/bin/format/pdb/pdb_downloader.h"

typedef struct rabin2_state_t {
	char *stdin_buf;
} Rabin2State;

typedef struct {
	const char *name;
	const char *desc;
} Rabin2Env;

static Rabin2Env env[] = {
	{ "R2_NOPLUGINS",				"                      # same as r2 -N. Dont load shared plugins" },
	{ "RABIN2_ARGS",				"                      # ignore cli and use these program arguments" },
	{ "RABIN2_CHARSET",				"e cfg.charset         # set default value charset for -z strings" },
	{ "RABIN2_CODESIGN_VERBOSE",	"                      # show codesign details at parse time" },
//TODO { "RABIN2_MACHO_CODESIGN",	"" },
	{ "RABIN2_DEBASE64",			"e bin.str.debase64    # try to debase64 all strings" },
	{ "RABIN2_DEMANGLE",			"e bin.demangle        # dont demangle symbols if value is 0" },
	{ "RABIN2_DEMANGLE_CMD", 		"e bin.demangle.cmd    # try to purge false positives" },
	{ "RABIN2_DEMANGLE_TRYLIB",		"e bin.demangle.trylib # load Swift libs to demangle (default: false)" },
//	{ "RABIN2_DEMAN_PFXLIB",		"e bin.demangle.pfxlib # prefix symbols with library name" },
//	{ "RABIN2_DEMAN_NAT",			"e bin.demangle.native # load Swift libs to demangle (default: true)" },
	{ "RABIN2_LANG",				"e bin.lang            # assume lang for demangling" },
	{ "RABIN2_MACHO_NOFUNCSTARTS",	"                      # if set it will ignore the FUNCSTART information" },
	{ "RABIN2_MACHO_NOSWIFT",		"                      # avoid parsing the swift metadata" },
	{ "RABIN2_MACHO_SKIPFIXUPS",	"                      # do not parse the mach-o chained fixups" },
	{ "RABIN2_MAXSTRBUF",			"e bin.str.maxbuf      # specify maximum buffer size" },
	{ "RABIN2_PDBSERVER",			"e pdb.server          # use alternative PDB server" },
	{ "RABIN2_PREFIX",				"e bin.prefix          # prefix symbols/sections/relocs with a specific string" },
	{ "RABIN2_STRFILTER",			"e bin.str.filter      # r2 -qc 'e bin.str.filter=?" "?' -" },
	{ "RABIN2_STRPURGE",			"e bin.str.purge       # try to purge false positives" },
//	{ "RABIN2_STR_FILTER",			"e bin.str.filter      # r2 -qc 'e bin.str.filter=?" "?' -" },
//	{ "RABIN2_STR_PURGE",			"e bin.str.purge       # try to purge false positives" },"
	{ "RABIN2_SYMSTORE",			"e pdb.symstore        # path to downstream symbol store" },
	{ "RABIN2_VERBOSE",				"e bin.verbose         # show debugging messages from the parser" },
};

static void rabin_show_env(bool show_desc);

static int rabin_show_help(int v) {
	printf ("Usage: rabin2 [-AcdeEghHiIjJlLMqrRsSUvVxzZ] [-@ at] [-a arch] [-b bits] [-B addr]\n"
		"              [-C F:C:D] [-f str] [-m addr] [-n str] [-N m:M] [-P[-P] pdb]\n"
		"              [-o str] [-O help] [-k query] [-D lang mangledsymbol] file\n");
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
		" -e              program entrypoint\n"
		" -ee             constructor/destructor entrypoints\n"
		" -E              globally exportable symbols\n"
		" -f [str]        select sub-bin named str\n"
		" -F [binfmt]     force to use that bin plugin (ignore header check)\n"
		" -g              same as -SMZIHVResizcld -SS -SSS -ee (show all info)\n"
		" -G [addr]       load address . address to header\n"
		" -h              this help message\n"
		" -H              header fields\n"
		" -i              imports (symbols imported from libraries)\n"
		" -I              binary info\n"
		" -j              output in json\n"
		" -J ([var])      display variable\n"
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
		" -p              show always physical addresses\n"
		" -P              show debug/pdb information\n"
		" -PP             download pdb file for binary\n"
		" -q              be quiet, just show fewer data\n"
		" -qq             show less info (no addr/size for -z for ex.)\n"
		" -Q              show load address used by dlopen (non-aslr libs)\n"
		" -r              radare output\n"
		" -R              relocations\n"
		" -s              symbols\n"
		" -S              sections\n"
		" -SS             segments\n"
		" -SSS            sections mapping to segments\n"
		" -t              display file hashes\n"
		" -T              display file signature\n"
		" -u              unfiltered (no rename duplicated symbols/sections)\n"
		" -U              resoUrces\n"
		" -v              display version and quit\n"
		" -V              show binary version information\n"
		" -w              display try/catch blocks\n"
		" -x              extract bins contained in file\n"
		" -X [fmt] [f] .. package in fat or zip the given files and bins contained in file\n"
		" -z              strings (from data section)\n"
		" -zz             strings (from raw bins [e bin.str.raw=1])\n"
		" -zzz            dump raw strings to stdout (for huge files)\n"
		" -Z              guess size of binary program\n"
		);
	}
	if (v) {
		printf ("Environment:\n");
		rabin_show_env (true);
	}
	return 1;
}

static char *stdin_gets(Rabin2State *state) {
#define STDIN_BUF_SIZE 96096
	memset (state->stdin_buf, 0, STDIN_BUF_SIZE);
	if (!fgets (state->stdin_buf, STDIN_BUF_SIZE, stdin)) {
		return NULL;
	}
	if (feof (stdin)) {
		return NULL;
	}
	return strdup (state->stdin_buf);
}

static void __sdb_prompt(Rabin2State *state, Sdb *sdb) {
	char *line;
	for (; (line = stdin_gets (state));) {
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
	ut64 bin_size = data? data->size: 0;
	ut8 *bytes;
	const char *xtr_type = "";
	char *arch = "unknown";
	int bits = 0, nb;
	char *libname = NULL;
	const char *filename = bf? bf->file: NULL;
	char *path = NULL, *ptr = NULL;
	bool res = false;

	if (!bf || !data || !filename) {
		return false;
	}
	if (data->metadata) {
		arch = data->metadata->arch;
		bits = data->metadata->bits;
		libname = data->metadata->libname;
		xtr_type = data->metadata->xtr_type;
	}
	if (!strcmp (xtr_type, "fat") && bin_size == bf->size && bin_size) {
		R_LOG_ERROR ("This is not a fat bin");
		return false;
	}
	bytes = malloc (bin_size);
	if (!bytes) {
		R_LOG_ERROR ("BinFile buffer is empty");
		return false;
	}
	nb = r_buf_read_at (data->buf, 0, bytes, bin_size);
	if (nb <= 0) {
		R_LOG_ERROR ("Couldn't read xtrdata");
		return false;
	}
	if (!arch) {
		arch = "unknown";
	}
	path = strdup (filename);
	if (!path) {
		return false;
	}
	ptr = (char *)r_file_basename (path);
	char *outpath = r_str_newf ("%s.fat", ptr);
	if (!outpath || !r_sys_mkdirp (outpath)) {
		free (path);
		free (outpath);
		R_LOG_ERROR ("creating dir structure");
		return false;
	}

	char *outfile = libname
		? r_str_newf ("%s/%s.%s.%s_%i.%d", outpath, ptr, arch, libname, bits, idx)
		: r_str_newf ("%s/%s.%s_%i.%d", outpath, ptr, arch, bits, idx);

	if (!outfile || !r_file_dump (outfile, bytes, bin_size, 0)) {
		R_LOG_ERROR ("extract failed %s", outfile);
		res = false;
	} else {
		printf ("%s created (%"PFMT64d")\n", outfile, bin_size);
		res = true;
	}

	free (outfile);
	free (outpath);
	free (path);
	free (bytes);
	return res;
}

static int rabin_extract(RBin *bin, int all) {
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

static int rabin_dump_symbols(RBin *bin, int len) {
	RVecRBinSymbol *symbols = r_bin_get_symbols_vec (bin);
	if (!symbols) {
		return false;
	}

	RBinSymbol *symbol;
	int olen = len;
	R_VEC_FOREACH (symbols, symbol) {
		if (symbol->size && (olen > symbol->size || !olen)) {
			len = symbol->size;
		} else if (!symbol->size && !olen) {
			len = 32;
		} else {
			len = olen;
		}
		ut8 *buf = calloc (1, len);
		if (!buf) {
			return false;
		}
		char *ret = malloc ((len * 2) + 1);
		if (!ret) {
			free (buf);
			return false;
		}
		if (r_buf_read_at (bin->cur->buf, symbol->paddr, buf, len) == len) {
			r_hex_bin2str (buf, len, ret);
			const char *name = r_bin_name_tostring (symbol->name);
			printf ("%s %s\n", name, ret);
		} else {
			R_LOG_ERROR ("Cannot read from buffer");
		}
		free (buf);
		free (ret);
	}
	return true;
}

static bool __dumpSections(RBin *bin, const char *scnname, const char *output, const char *file, bool raw) {
	RListIter *iter;
	RBinSection *section;
	RList *sections = r_bin_get_sections (bin);
	if (!sections || r_list_empty (sections)) {
		R_LOG_WARN ("No sections to dump");
		return false;
	}

	r_list_foreach (sections, iter, section) {
		if (!r_str_glob (section->name, scnname)) {
			continue;
		}
		const size_t ss = section->size;
		if ((ss * 2) + 1 < ss) {
			return false;
		}
		ut8 *buf = malloc (ss);
		char *ret = malloc (ss * 2 + 1);
		if (R_UNLIKELY (!buf || !ret)) {
			free (buf);
			free (ret);
			return false;
		}
		if (section->paddr > r_buf_size (bin->cur->buf) ||
			section->paddr + ss > r_buf_size (bin->cur->buf)) {
			free (buf);
			free (ret);
			return false;
		}
		int r = r_buf_read_at (bin->cur->buf, section->paddr, buf, ss);
		if (r < 1) {
			free (buf);
			free (ret);
			return false;
		}
		//it does mean the user specified an output file
		if (strcmp (output, file)) {
			r_file_dump (output, buf, ss, 0);
		} else {
			if (raw) {
				if (write (1, buf, ss) != ss) {
					R_LOG_WARN ("write truncated");
				}
			} else {
				r_hex_bin2str (buf, ss, ret);
				printf ("%s\n", ret);
			}
		}
		free (buf);
		free (ret);
		break;
	}
	return true;
}

static int rabin_do_operation(RBin *bin, const char *op, int rad, const char *output, const char *file) {
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
	RBinFile *bf = r_bin_cur (bin);
	if (bf) {
		if (!bf->buf) {
			R_LOG_ERROR ("Missing data buffer");
			goto error;
		}
		RBuffer *nb = r_buf_new_with_buf (bf->buf);
		r_buf_free (bf->buf);
		bf->buf = nb;
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
			{
				ut64 a = ptr2? r_num_math (NULL, ptr2): 0;
				if (!rabin_dump_symbols (bin, a)) {
					goto error;
				}
			}
			break;
		case 'S':
			if (!ptr2) {
				goto _rabin_do_operation_error;
			}
			if (!__dumpSections (bin, ptr2, output, file, rad)) {
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
			rc = r_bin_wr_output (bin, output);
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
		RBinFile *cur = r_bin_cur (bin);
		RBinPlugin *plg = r_bin_file_cur_plugin (cur);
		if (!plg && cur) {
			// are we in xtr?
			if (cur->xtr_data) {
				// load the first one
				RBinXtrData *xtr_data = r_list_get_n (cur->xtr_data, 0);
				if (xtr_data && !xtr_data->loaded && !r_bin_file_object_new_from_xtr_data (bin, cur,
					UT64_MAX, r_bin_get_laddr (bin), xtr_data)) {
					break;
				}
			}
			plg = r_bin_file_cur_plugin (cur);
			if (!plg) {
				break;
			}
		}
		if (plg && plg->signature) {
			char *sign = plg->signature (cur, rad == R_MODE_JSON);
			if (sign) {
				r_cons_println (sign);
				r_cons_flush ();
				free (sign);
			}
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
			if (perms < 1) {
				perms = r_str_rwx (ptr2);
				if (perms < 0) {
					R_LOG_ERROR ("Invalid permissions string (%s)", ptr2);
				}
			}
			r_bin_wr_scn_perms (bin, ptr, perms);
			rc = r_bin_wr_output (bin, output);
		}
		break;
	default:
	_rabin_do_operation_error:
		R_LOG_ERROR ("Unknown operation. use -O help");
		goto error;
	}
	if (!rc) {
		R_LOG_ERROR ("Cannot dump :(");
	}
	free (arg);
	return true;
error:
	free (arg);
	return false;
}

static int rabin_show_srcline(RBin *bin, ut64 at) {
	char *srcline;
	if (at != UT64_MAX && (srcline = r_bin_addrline_tostring (bin, at, 1))) {
		printf ("%s\n", srcline);
		free (srcline);
		return true;
	}
	return false;
}

/* bin callback */
static int __lib_bin_cb(RLibPlugin *pl, void *user, void *data) {
	struct r_bin_plugin_t *hand = (struct r_bin_plugin_t *)data;
	RBin *bin = user;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_plugin_add (bin, hand);
	return true;
}

static int __lib_bin_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

/* binxtr callback */
static int __lib_bin_xtr_cb(RLibPlugin *pl, void *user, void *data) {
	struct r_bin_xtr_plugin_t *hand = (struct r_bin_xtr_plugin_t *)data;
	RBin *bin = user;
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
	RBin *bin = user;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_ldr_add (bin, hand);
	return true;
}

static int __lib_bin_ldr_dt(RLibPlugin *pl, void *p, void *u) {
	return true;
}

static char *__demangleAs(RBin *bin, int type, const char *file) {
	bool syscmd = bin->options.demangle_usecmd;
	char *res = NULL;
	switch (type) {
	case R_BIN_LANG_CXX: res = r_bin_demangle_cxx (NULL, file, 0); break;
	case R_BIN_LANG_JAVA: res = r_bin_demangle_java (file); break;
	case R_BIN_LANG_OBJC: res = r_bin_demangle_objc (NULL, file); break;
	case R_BIN_LANG_SWIFT: res = r_bin_demangle_swift (file, syscmd, bin->options.demangle_trylib); break;
	case R_BIN_LANG_MSVC: res = r_bin_demangle_msvc (file); break;
	case R_BIN_LANG_RUST: res = r_bin_demangle_rust (NULL, file, 0); break;
	default:
		R_LOG_ERROR ("Unsupported demangler");
		break;
	}
	return res;
}

static void __listPlugins(RBin *bin, const char* plugin_name, PJ *pj, int rad) {
	int format = (rad == R_MODE_JSON) ? 'j': rad? 'q': 0;
	bin->cb_printf = (PrintfCallback)printf;
	if (plugin_name) {
		r_bin_list_plugin (bin, plugin_name, pj, format);
	} else {
		r_bin_list (bin, pj, format);
	}
}

static void rabin_env_print(const char *name) {
	char *value = r_sys_getenv (name);
	printf ("%s\n", R_STR_ISNOTEMPTY (value) ? value : "");
	free (value);
}

static void rabin_show_env(bool show_desc) {
	int id = 0;
	for (id = 0; id < (sizeof (env) / sizeof (env[0])); id++) {
		if (show_desc) {
			printf ("%s\t%s\n", env[id].name, env[id].desc);
		} else {
			printf ("%s=", env[id].name);
			rabin_env_print(env[id].name);
		}
	}
}

R_API int r_main_rabin2(int argc, const char **argv) {
	Rabin2State state = {0};
	const char *name = NULL;
	const char *file = NULL;
	const char *output = NULL;
	int rad = 0;
	ut64 laddr = UT64_MAX;
	ut64 baddr = UT64_MAX;
	const char *do_demangle = NULL;
	const char *query = NULL;
	int c, bits = 0, actions = 0;
	char* create = NULL;
	bool va = true;
	ut64 action = R_BIN_REQ_UNK;
	char *tmp, *ptr, *arch_name = NULL;
	const char *arch = NULL;
	const char *forcebin = NULL;
	const char *chksum = NULL;
	const char *op = NULL;
	RCoreBinFilter filter;
	int xtr_idx = 0; // load all files if extraction is necessary.
	int rawstr = 0;
	int fd = -1;
	RCore core = {0};
	ut64 at = UT64_MAX;

	r_core_init (&core);
	RBin *bin = core.bin;

	state.stdin_buf = malloc (STDIN_BUF_SIZE);
	if (!state.stdin_buf) {
		return 1;
	}

	if (!(tmp = r_sys_getenv ("R2_NOPLUGINS"))) {
		char *homeplugindir = r_xdg_datadir ("plugins");
		char *plugindir = r_str_r2_prefix (R2_PLUGINS);
		char *extrasdir = r_str_r2_prefix (R2_EXTRAS);
		char *bindingsdir = r_str_r2_prefix (R2_BINDINGS);
		RLib *l = r_lib_new (NULL, NULL);
		r_lib_add_handler (l, R_LIB_TYPE_BIN, "bin plugins",
			&__lib_bin_cb, &__lib_bin_dt, bin);
		r_lib_add_handler (l, R_LIB_TYPE_BIN_XTR, "bin xtr plugins",
			&__lib_bin_xtr_cb, &__lib_bin_xtr_dt, bin);
		r_lib_add_handler (l, R_LIB_TYPE_BIN_LDR, "bin ldr plugins",
			&__lib_bin_ldr_cb, &__lib_bin_ldr_dt, bin);
		/* load plugins everywhere */
		char *path = r_sys_getenv (R_LIB_ENV);
		if (R_STR_ISNOTEMPTY (path)) {
			r_lib_opendir (l, path);
		}
		r_lib_opendir (l, homeplugindir);
		r_lib_opendir (l, plugindir);
		r_lib_opendir (l, extrasdir);
		r_lib_opendir (l, bindingsdir);
		free (homeplugindir);
		free (plugindir);
		free (extrasdir);
		free (bindingsdir);
		free (path);
		r_lib_free (l);
	}
	free (tmp);
#if 0
	if ((tmp = r_sys_getenv ("R2_CONFIG"))) {
		Sdb *config_sdb = sdb_new (NULL, tmp, 0);
		if (config_sdb) {
			r_config_unserialize (core.config, config_sdb, NULL);
			sdb_free (config_sdb);
		} else {
			eprintf ("Cannot open file specified in R2_CONFIG\n");
		}
		free (tmp);
	}
#endif
	if ((tmp = r_sys_getenv ("RABIN2_DEMANGLE_CMD"))) {
		// r_config_set (core.config, "cmd.demangle", tmp);
		r_config_set (core.config, "bin.demangle.usecmd", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_CHARSET"))) {
		r_config_set (core.config, "cfg.charset", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_LANG"))) {
		r_config_set (core.config, "bin.lang", tmp);
		free (tmp);
	}
	if (r_sys_getenv_asbool ("RABIN2_VERBOSE")) {
		r_config_set_b (core.config, "bin.verbose", true);
	}
	r_config_set_b (core.config, "bin.demangle.trylib", r_sys_getenv_asbool ("RABIN2_DEMAN_TRYLIB"));
	r_config_set_b (core.config, "bin.demangle", r_sys_getenv_asbool ("RABIN2_DEMANGLE"));
	if ((tmp = r_sys_getenv ("RABIN2_MAXSTRBUF"))) {
		r_config_set (core.config, "bin.str.maxbuf", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_STRFILTER"))) {
		r_config_set (core.config, "bin.str.filter", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_STRPURGE"))) {
		r_config_set (core.config, "bin.str.purge", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_DEBASE64"))) {
		r_config_set (core.config, "bin.str.debase64", tmp);
		free (tmp);
	}
	if ((tmp = r_sys_getenv ("RABIN2_PDBSERVER"))) {
		r_config_set (core.config, "pdb.server", tmp);
		free (tmp);
	}

#define is_active(x) (action & (x))
#define set_action(x) { actions++; action |= (x); }
#define unset_action(x) action &= ~x
	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "DjJ:gAf:F:a:B:G:b:cC:k:K:dD:Mm:n:N:@:isSVIHeEUlRwO:o:pPqQrTtvLhuxXzZ");
	if (argc == 2 && !strcmp (argv[1], "-J")) {
		rabin_show_env (false);
		r_core_fini (&core);
		free (state.stdin_buf);
		return 0;
	}
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'g':
			set_action (R_BIN_REQ_CLASSES);
			set_action (R_BIN_REQ_IMPORTS);
			set_action (R_BIN_REQ_SYMBOLS);
			set_action (R_BIN_REQ_SECTIONS);
			set_action (R_BIN_REQ_SEGMENTS);
			set_action (R_BIN_REQ_SECTIONS_MAPPING);
			set_action (R_BIN_REQ_STRINGS);
			set_action (R_BIN_REQ_SIZE);
			set_action (R_BIN_REQ_INFO);
			set_action (R_BIN_REQ_FIELDS);
			set_action (R_BIN_REQ_DWARF);
			set_action (R_BIN_REQ_ENTRIES);
			set_action (R_BIN_REQ_INITFINI);
			set_action (R_BIN_REQ_MAIN);
			set_action (R_BIN_REQ_LIBS);
			set_action (R_BIN_REQ_RELOCS);
			set_action (R_BIN_REQ_VERSIONINFO);
			break;
		case 'V': set_action (R_BIN_REQ_VERSIONINFO); break;
		case 'T': set_action (R_BIN_REQ_SIGNATURE); break;
		case 't': set_action (R_BIN_REQ_HASHES); break;
		case 'w': set_action (R_BIN_REQ_TRYCATCH); break;
		case 'q':
			rad = ((rad & R_MODE_SIMPLE || (rad & R_MODE_SIMPLEST))?
				R_MODE_SIMPLEST : R_MODE_SIMPLE);
			break;
		case 'j': rad = R_MODE_JSON; break;
		case 'A': set_action (R_BIN_REQ_LISTARCHS); break;
		case 'a': arch = opt.arg; break;
		case 'C':
			set_action (R_BIN_REQ_CREATE);
			create = strdup (opt.arg);
			break;
		case 'u': bin->filter = 0; break;
		case 'k': query = opt.arg; break;
		case 'K': chksum = opt.arg; break;
		case 'c':
			if (is_active (R_BIN_REQ_CLASSES)) {
				rad = R_MODE_CLASSDUMP;
			} else {
				set_action (R_BIN_REQ_CLASSES);
			}
			break;
		case 'f': arch_name = strdup (opt.arg); break;
		case 'F': forcebin = opt.arg; break;
		case 'b': bits = r_num_math (NULL, opt.arg); break;
		case 'm':
			at = r_num_math (NULL, opt.arg);
			set_action (R_BIN_REQ_SRCLINE);
			break;
		case 'i':
			set_action (R_BIN_REQ_IMPORTS);
			break;
		case 's':
			set_action (R_BIN_REQ_SYMBOLS);
			break;
		case 'S':
			if (is_active (R_BIN_REQ_SEGMENTS)) {
				action &= ~R_BIN_REQ_SEGMENTS;
				action |= R_BIN_REQ_SECTIONS_MAPPING;
			} else if (is_active (R_BIN_REQ_SECTIONS)) {
				action &= ~R_BIN_REQ_SECTIONS;
				action |= R_BIN_REQ_SEGMENTS;
			} else {
				set_action (R_BIN_REQ_SECTIONS);
			}
			break;
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
		case 'J':
			rabin_env_print (opt.arg);
			r_core_fini (&core);
			free (state.stdin_buf);
			return 0;
		case 'H':
			set_action (R_BIN_REQ_FIELDS);
			break;
		case 'd': set_action (R_BIN_REQ_DWARF); break;
		case 'P':
			if (is_active (R_BIN_REQ_PDB)) {
				set_action (R_BIN_REQ_PDB_DWNLD);
				unset_action (R_BIN_REQ_PDB);
			} else {
				set_action (R_BIN_REQ_PDB);
			}
			break;
		case 'D':
			if (argv[opt.ind] && argv[opt.ind + 1] && \
				(!argv[opt.ind + 1][0] || !strcmp (argv[opt.ind + 1], "all"))) {
				r_config_set (core.config, "bin.lang", argv[opt.ind]);
				r_config_set_b (core.config, "bin.demangle", true);
				opt.ind += 2;
			} else {
				do_demangle = argv[opt.ind];
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
		case 'O':
			op = opt.arg;
			set_action (R_BIN_REQ_OPERATION);
			if (*op == 'c') {
				r_sys_setenv ("RABIN2_CODESIGN_VERBOSE", "1");
			}
			if (isBinopHelp (op)) {
				printf ("Usage: iO [expression]:\n"
					" e/0x8048000       change entrypoint\n"
					" d/s/1024          dump symbols\n"
					" d/S/.text         dump section\n"
					" r/.data/1024      resize section\n"
					" R                 remove RPATH\n"
					" a/l/libfoo.dylib  add library\n"
					" p/.data/rwx       change section permissions\n"
					" c                 show Codesign data\n"
					" C                 show LDID entitlements\n");
				r_core_fini (&core);
				free (state.stdin_buf);
				return 0;
			}
			if (opt.ind == argc) {
				R_LOG_ERROR ("Missing filename");
				r_core_fini (&core);
				free (state.stdin_buf);
				return 1;
			}
			break;
		case 'o': output = opt.arg; break;
		case 'p': va = false; break;
		case 'r': rad = true; break;
		case 'v':
			r_core_fini (&core);
			free (state.stdin_buf);
			return r_main_version_print ("rabin2", 0);
		case 'L':
			set_action (R_BIN_REQ_LISTPLUGINS);
			break;
		case 'G':
			laddr = r_num_math (NULL, opt.arg);
			if (laddr == UT64_MAX) {
				va = false;
			}
			break;
		case 'B':
			{
				const char *err = NULL;
				//baddr = r_num_math_err (core.num, opt.arg, &err);
				baddr = r_num_math_err (NULL, opt.arg, &err);
				if (err) {
					R_LOG_ERROR ("%s in base address (-B): '%s'", err, opt.arg);
					return 1;
				}
			}
			break;
		case '@':
			at = r_num_math (NULL, opt.arg);
			if (at == 0LL && *opt.arg != '0') {
				at = UT64_MAX;
			}
			break;
		case 'n':
			name = opt.arg;
			break;
		case 'N':
			tmp = strchr (opt.arg, ':');
			r_config_set (core.config, "bin.str.min", opt.arg);
			if (tmp) {
				r_config_set (core.config, "bin.str.max", tmp + 1);
			}
			break;
		case 'h':
			r_core_fini (&core);
			free (create);
			free (state.stdin_buf);
			return rabin_show_help (1);
		default:
			action |= R_BIN_REQ_HELP;
			break;
		}
	}
	core.io->va = va;

	PJ *pj = NULL;
	if (rad == R_MODE_JSON) {
		pj = r_core_pj_new (&core);
		if (!pj) {
			free (state.stdin_buf);
			return 1;
		}
	}

	if (is_active (R_BIN_REQ_LISTPLUGINS)) {
		const char* plugin_name = NULL;
		if (opt.ind < argc) {
			plugin_name = argv[opt.ind];
		}
		__listPlugins (bin, plugin_name, pj, rad);
		if (rad == R_MODE_JSON) {
			r_cons_println (pj_string (pj));
			r_cons_flush ();
			pj_free (pj);
		}
		r_core_fini (&core);
		free (state.stdin_buf);
		return 0;
	}

	if (do_demangle) {
		char *res = NULL;
		if ((argc - opt.ind) < 2) {
			r_core_fini (&core);
			free (state.stdin_buf);
			return rabin_show_help (0);
		}
		int type = r_bin_demangle_type (do_demangle);
		bin->options.demangle_trylib = (type == R_BIN_LANG_SWIFT && r_sys_getenv_asbool ("RABIN2_DEMAN_TRYLIB"));
		file = argv[opt.ind + 1];
		if (!strcmp (file, "-")) {
			for (;;) {
				file = stdin_gets (&state);
				if (R_STR_ISEMPTY (file)) {
					break;
				}
				res = __demangleAs (bin, type, file);
				if (!res) {
					R_LOG_ERROR ("Unknown lang to demangle. Use: cxx, msvc, dlang, rust, pascal, java, objc, swift");
					r_core_fini (&core);
					free (state.stdin_buf);
					return 1;
				}
				if (R_STR_ISNOTEMPTY (res)) {
					printf ("%s\n", res);
				} else if (file && *file) {
					printf ("%s\n", file);
				}
				R_FREE (res);
				R_FREE (file);
			}
			free (stdin_gets (&state));
		} else {
			res = __demangleAs (bin, type, file);
			if (R_STR_ISNOTEMPTY (res)) {
				printf ("%s\n", res);
				free (res);
				r_core_fini (&core);
				free (state.stdin_buf);
				return 0;
			}
			printf ("%s\n", file);
		}
		free (res);
		//eprintf ("%s\n", file);
		r_core_fini (&core);
		free (state.stdin_buf);
		return 1;
	}
	file = argv[opt.ind];

	if (file && !*file) {
		R_LOG_ERROR ("Cannot open empty path");
		r_core_fini (&core);
		free (state.stdin_buf);
		return 1;
	}

	if (!query) {
		if (action & R_BIN_REQ_HELP || action == R_BIN_REQ_UNK || !file) {
			r_core_fini (&core);
			free (state.stdin_buf);
			return rabin_show_help (0);
		}
	}
	if (arch) {
		ptr = strchr (arch, '_');
		if (ptr) {
			*ptr = '\0';
			bits = r_num_math (NULL, ptr + 1);
		}
	}
	if (action & R_BIN_REQ_CREATE) {
		// TODO: move in a function outside
		RBuffer *b;
		int datalen, codelen;
		ut8 *data = NULL, *code = NULL;
		char *p2, *p = strchr (create, ':');
		if (!p) {
			R_LOG_ERROR ("Invalid format for -C flag. Use 'format:code:data (in hexpairs)");
			r_core_fini (&core);
			free (state.stdin_buf);
			return 1;
		}
		*p++ = 0;
		p2 = strchr (p, ':');
		if (p2) {
			// has data
			*p2++ = 0;
			data = malloc (strlen (p2)+1);
			datalen = r_hex_str2bin (p2, data);
			if (datalen < 0) {
				datalen = -datalen;
			}
		} else {
			data = NULL;
			datalen = 0;
		}
		code = malloc (strlen (p) + 1);
		if (!code) {
			r_core_fini (&core);
			free (state.stdin_buf);
			return 1;
		}
		codelen = r_hex_str2bin (p, code);
		RBinArchOptions opts;
		r_bin_arch_options_init (&opts, arch, bits);
		b = r_bin_create (bin, create, code, codelen, data, datalen, &opts);
		if (b) {
			ut64 tmpsz;
			const ut8 *tmp = r_buf_data (b, &tmpsz);
			if (r_file_dump (file, tmp, tmpsz, 0)) {
				R_LOG_INFO ("Dumped %" PFMT64d " bytes in '%s'", tmpsz, file);
				(void)r_file_chmod (file, "+x", 0);
			} else {
				R_LOG_ERROR ("Cannot dump bytes into a.out");
			}
			r_buf_free (b);
		} else {
			R_LOG_ERROR ("Cannot create binary for this format '%s'", create);
		}
		r_core_fini (&core);
		free (state.stdin_buf);
		return 0;
	}
	if (rawstr == 2) {
		unset_action (R_BIN_REQ_STRINGS);
	}
	r_config_set_i (core.config, "bin.str.raw", rawstr);

	if (!file) {
		R_LOG_ERROR ("Missing file");
		r_core_fini (&core);
		free (state.stdin_buf);
		return 1;
	}

	if (R_STR_ISNOTEMPTY (file) && action & R_BIN_REQ_DLOPEN) {
#if R2__UNIX__ && HAVE_FORK
		int child = r_sys_fork ();
		if (child == -1) {
			r_core_fini (&core);
			free (state.stdin_buf);
			return 1;
		}
		if (child == 0) {
			free (state.stdin_buf);
			return waitpid (child, NULL, 0);
		}
#endif
		void *addr = r_lib_dl_open (file);
		if (addr) {
			R_LOG_INFO ("%s is loaded at 0x%"PFMT64x, file, (ut64)(size_t)(addr));
			r_lib_dl_close (addr);
			r_core_fini (&core);
			free (state.stdin_buf);
			return 0;
		}
		R_LOG_ERROR ("Cannot open the '%s' library", file);
		r_core_fini (&core);
		free (state.stdin_buf);
		return 0;
	}
	if (action & R_BIN_REQ_PACKAGE) {
		RList *files = r_list_newf (NULL);
		const char *format = argv[opt.ind];
		const char *file = argv[opt.ind + 1];
		int i, rc = 0;

		if (opt.ind + 3 > argc) {
			R_LOG_ERROR ("Usage: rabin2 -X [fat|zip] foo.zip a b c");
			free (state.stdin_buf);
			r_core_fini (&core);
			return 1;
		}

		eprintf ("FMT %s\n", format);
		eprintf ("PKG %s\n", file);
		for (i = opt.ind + 2; i < argc; i++) {
			eprintf ("ADD %s\n", argv[i]);
			r_list_append (files, (void*)argv[i]);
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
		r_list_free (files);
		free (state.stdin_buf);
		return rc;
	}

	if (R_STR_ISNOTEMPTY (file)) {
		if (r_core_file_open (&core, file, R_PERM_R, 0)) {
			fd = r_io_fd_get_current (core.io);
			if (fd == -1) {
				R_LOG_ERROR ("Cannot open file '%s'", file);
				r_core_fini (&core);
				free (state.stdin_buf);
				return 1;
			}
		} else {
			R_LOG_ERROR ("Cannot open file '%s'", file);
			r_core_fini (&core);
			free (state.stdin_buf);
			return 1;
		}
	}
	bin->options.minstrlen = r_config_get_i (core.config, "bin.str.min");
	bin->options.maxstrbuf = r_config_get_i (core.config, "bin.str.maxbuf");

	r_bin_force_plugin (bin, forcebin);
	r_bin_load_filter (bin, action);

	RBinFileOptions bo;
	r_bin_file_options_init (&bo, fd, baddr, laddr, rawstr);
	bo.xtr_idx = xtr_idx;

	if (!r_bin_open (bin, file, &bo)) {
		//if this return false means that we did not return a valid bin object
		//but we have yet the chance that this file is a fat binary
		if (!bin->cur || !bin->cur->xtr_data) {
			R_LOG_ERROR ("Cannot open file");
			r_core_fini (&core);
			free (state.stdin_buf);
			return 1;
		}
	}
	/* required to automatically select a sub-bin when not specified */
	(void)r_core_bin_update_arch_bits (&core);

	if (baddr != UT64_MAX) {
		r_bin_set_baddr (bin, baddr);
	}
	if (rawstr == 2) {
		RBinFile *bf = r_bin_cur (core.bin);
		if (bf) {
			bf->strmode = rad;
			r_bin_dump_strings (bf, bin->options.minstrlen, bf->rawstr);
		}
	}
	if (query) {
		if (rad) {
			r_core_bin_export_info (&core, R_MODE_RADARE);
			r_cons_flush ();
		} else {
			if (!strcmp (query, "-")) {
				__sdb_prompt (&state, bin->cur->sdb);
			} else {
				sdb_query (bin->cur->sdb, query);
			}
		}
		r_core_fini (&core);
		free (state.stdin_buf);
		return 0;
	}
#define isradjson ((rad == R_MODE_JSON) && (actions > 0))
#define run_action(n,x,y) {\
	if (action & (x)) {\
		if (isradjson) { pj_k (pj, n); } \
		if (!r_core_bin_info (&core, y, pj, rad, va, &filter, chksum)) {\
			R_LOG_ERROR ("Missing bin header %s", n);\
		};\
	}\
}
	core.bin = bin;
	bin->cb_printf = r_cons_printf;
	filter.addr = at;
	filter.name = name;
	r_cons_new ()->context->is_interactive = false;

	if (isradjson) {
		pj_o (pj);
	}
	// List fatmach0 sub-binaries, etc
	if (action & R_BIN_REQ_LISTARCHS || ((arch || bits || arch_name) &&
		!r_bin_select (bin, arch, bits, arch_name))) {
		if (rad == R_MODE_SIMPLEST || rad == R_MODE_SIMPLE) {
			r_bin_list_archs (bin, pj, NULL, 'q');
		} else {
			r_bin_list_archs (bin, pj, NULL, (rad == R_MODE_JSON)? 'j': 1);
		}
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
		pdbopts.symbol_store_path = (char *)r_config_get (core.config, "pdb.symstore");
		r_bin_pdb_download (&core, pj, isradjson, &pdbopts);
	}

	if ((tmp = r_sys_getenv ("RABIN2_PREFIX"))) {
		r_config_set (core.config, "bin.prefix", tmp);
		free (tmp);
	}

	run_action ("sections", R_BIN_REQ_SECTIONS, R_CORE_BIN_ACC_SECTIONS);
	run_action ("segments", R_BIN_REQ_SEGMENTS, R_CORE_BIN_ACC_SEGMENTS);
	run_action ("entries", R_BIN_REQ_ENTRIES, R_CORE_BIN_ACC_ENTRIES);
	run_action ("initfini", R_BIN_REQ_INITFINI, R_CORE_BIN_ACC_INITFINI);
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
	run_action ("sections", R_BIN_REQ_SIGNATURE, R_CORE_BIN_ACC_SIGNATURE);
	run_action ("hashes", R_BIN_REQ_HASHES, R_CORE_BIN_ACC_HASHES);
	run_action ("sections mapping", R_BIN_REQ_SECTIONS_MAPPING, R_CORE_BIN_ACC_SECTIONS_MAPPING);
	if (action & R_BIN_REQ_SRCLINE) {
		rabin_show_srcline (bin, at);
	}
	if (action & R_BIN_REQ_EXTRACT) {
		RBinFile *bf = r_bin_cur (bin);
		if (bf && bf->xtr_data) {
			rabin_extract (bin, (!arch && !arch_name && !bits));
		} else {
			R_LOG_ERROR ("Cannot extract bins from '%s'. No supported plugins found!", bin->file);
		}
	}
	if (op && action & R_BIN_REQ_OPERATION) {
		rabin_do_operation (bin, op, rad, output, file);
	}
	if (isradjson) {
		pj_end (pj);
		r_cons_println (pj_string (pj));
	}

	pj_free (pj);
	r_cons_flush ();
	r_core_fini (&core);
	r_syscmd_popalld ();
	free (state.stdin_buf);

	return 0;
}
