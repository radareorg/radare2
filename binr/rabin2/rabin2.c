/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.c>
#include <r_core.h>
#include "../blob/version.c"
#include "../../libr/bin/pdb/pdb_downloader.h"

#define ACTION_UNK       0x00000
#define ACTION_ENTRIES   0x00001
#define ACTION_IMPORTS   0x00002
#define ACTION_SYMBOLS   0x00004
#define ACTION_SECTIONS  0x00008
#define ACTION_INFO      0x00010
#define ACTION_OPERATION 0x00020
#define ACTION_HELP      0x00040
#define ACTION_STRINGS   0x00080
#define ACTION_FIELDS    0x00100
#define ACTION_LIBS      0x00200
#define ACTION_SRCLINE   0x00400
#define ACTION_MAIN      0x00800
#define ACTION_EXTRACT   0x01000
#define ACTION_RELOCS    0x02000
#define ACTION_LISTARCHS 0x04000
#define ACTION_CREATE    0x08000
#define ACTION_CLASSES   0x10000
#define ACTION_DWARF     0x20000
#define ACTION_SIZE      0x40000
#define ACTION_PDB       0x80000
#define ACTION_PDB_DWNLD 0x100000

static struct r_bin_t *bin = NULL;
static char* output = NULL;
static char* create = NULL;
static int rad = R_FALSE;
static ut64 laddr = 0LL;
static char* file = NULL;
static char *name = NULL;
static int rw = R_FALSE;
static int va = R_TRUE;
static ut64 at = 0LL;
static RLib *l;

static int rabin_show_help(int v) {
	printf ("Usage: rabin2 [-ACdehHiIjlLMqrRsSvVxzZ] [-@ addr] [-a arch] [-b bits]\n"
		"              [-B addr] [-c F:C:D] [-f str] [-m addr] [-n str] [-N m:M]\n"
		"              [-o str] [-O str] [-k query] file\n");
	if (v) printf (
		" -@ [addr]       show section, symbol or import at addr\n"
		" -A              list archs\n"
		" -a [arch]       set arch (x86, arm, .. or <arch>_<bits>)\n"
		" -b [bits]       set bits (32, 64 ...)\n"
		" -B [addr]       override base address (pie bins)\n"
		" -c [fmt:C:D]    create [elf,mach0,pe] with Code and Data hexpairs (see -a)\n"
		" -C              list classes\n"
		" -d              show debug/dwarf information\n"
		" -P              show debug/pdb information\n"
		" -PP             download pdb file for binary\n"
		" -e              entrypoint\n"
		" -f [str]        select sub-bin named str\n"
		" -k [query]      perform sdb query on loaded file\n"
		" -K [algo]       calculate checksums (md5, sha1, ..)\n"
		" -g              same as -SMRevsiz (show all info)\n"
		" -h              this help\n"
		" -H              header fields\n"
		" -i              imports (symbols imported from libraries)\n"
		" -I              binary info\n"
		" -j              output in json\n"
		" -k [sdb-query]  run sdb query. for example: '*'\n"
		" -l              linked libraries\n"
		" -L              list supported bin plugins\n"
		" -m [addr]       show source line at addr\n"
		" -M              main (show address of main symbol)\n"
		" -n [str]        show section, symbol or import named str\n"
		" -N [min:max]    force min:max number of chars per string (see -z and -zz)\n"
		" -o [str]        output file/folder for write operations (out by default)\n"
		" -O [str]        write/extract operations (-O help)\n"
		" -p              show physical addresses\n"
		" -q              be quiet, just show fewer data\n"
		" -r              radare output\n"
		" -R              relocations\n"
		" -s              symbols (exports)\n"
		" -S              sections\n"
		" -v              display version and quit\n"
		//" -V              show version information\n"
		" -x              extract bins contained in file\n"
		" -z              strings (from data section)\n"
		" -zz             strings (from raw bins [e bin.rawstr=1])\n"
		" -zzz            dump raw strings to stdout (for huge files)\n"
		" -Z              guess size of binary program\n"
		);
	return 1;
}

static char *stdin_gets() {
        static char buf[96096];
        fgets (buf, sizeof (buf)-1, stdin);
        if (feof (stdin)) return NULL;
        buf[strlen (buf)-1] = 0;
        return strdup (buf);
}

static void __sdb_prompt(Sdb *sdb) {
	char *line;
	for (;(line = stdin_gets ());) {
		sdb_query (sdb, line);
		free (line);
	}
}

static int extract_binobj (const RBinFile *bf, const RBinObject *o, int idx ) {
	ut64 boffset = o ? o->boffset : 0;
	ut64 bin_size = o ? o->obj_size : 0;
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	//ut64 sz = bf ? r_buf_size (bf->buf) : 0;
	RBinInfo *info = o ? o->info : NULL;
	const char *arch = info ? info->arch : "unknown";
	char bits = info ? info->bits : 0;
	const char *filename = bf ? bf->file : NULL;
	char *path = NULL, *outpath = NULL, *outfile = NULL, *ptr = NULL;
	ut32 outfile_sz = 0, outpath_sz = 0;
	int res = R_FALSE;

	if (!bf || !o || !filename ) return R_FALSE;

	path = strdup (filename);

	// XXX: Wrong for w32 (/)

	if (r_what_os_am_i () == ON_NIX_OS && (ptr = strrchr (path, '/'))){
		*ptr = '\0';
		ptr++;
	} else if ((ptr = strrchr (path, '\\'))) {
		*ptr = '\0';
		ptr++;
	} else ptr = path;

	outpath_sz = strlen (path) + 20;

	if (outpath_sz)
		outpath = malloc (outpath_sz);

	if (outpath)
		snprintf (outpath, outpath_sz, "%s.fat", ptr);

	if (!outpath || !r_sys_rmkdir (outpath)) {
		free (path);
		free (outpath);
		eprintf ("Error creating dir structure\n");
		return R_FALSE;
	}

	outfile_sz = outpath_sz + strlen (ptr) + strlen (arch) + 3 + 10 + 10;
	if (outfile_sz)
		outfile = malloc (outfile_sz);

	if (outfile)
		snprintf (outfile, outfile_sz, "%s/%s.%s_%i.%d",
			outpath, ptr, arch, bits, idx);

	if (boffset > r_buf_size (bf->buf)) {
			eprintf ("Invalid offsets\n");
			res = R_FALSE;
	} else {
		if (!outfile || !r_file_dump (outfile, bytes+boffset, bin_size)) {
			eprintf ("Error extracting %s\n", outfile);
			res = R_FALSE;
		} else {
			printf ("%s created (%"PFMT64d")\n", outfile, bin_size);
			res = R_TRUE;
		}
	}

	free (outfile);
	free (outpath);
	free (path);
	return res;
}

static int rabin_extract(int all) {
	int res = R_FALSE;
	RBinFile *bf = r_bin_cur (bin);
	RBinObject *obj = NULL;
	if (!bf) return res;
	if (all) {
		int idx = 0;
		RListIter *iter = NULL;
		r_list_foreach (bf->objs, iter, obj)
			res = extract_binobj (bf, obj, idx++);
	} else {
		obj = r_bin_cur_object (bin);
		if (!obj) return res;
		res = extract_binobj (bf, obj, 0);
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

	if ((symbols = r_bin_get_symbols (bin)) == NULL)
		return R_FALSE;

	r_list_foreach (symbols, iter, symbol) {
		if (symbol->size != 0 && (olen > symbol->size || olen == 0))
			len = symbol->size;
		else if (symbol->size == 0 && olen == 0)
			len = 32;
		else len = olen;
		if (!(buf = malloc (len))) {
			return R_FALSE;
		}
		if (!(ret = malloc (len*2+1))) {
			free (buf);
			return R_FALSE;
		}
		r_buf_read_at (bin->cur->buf, symbol->paddr, buf, len);
		r_hex_bin2str (buf, len, ret);
		printf ("%s %s\n", symbol->name, ret);
		free (buf);
		free (ret);
	}
	return R_TRUE;
}

static int rabin_dump_sections(char *scnname) {
	RList *sections;
	RListIter *iter;
	RBinSection *section;
	ut8 *buf;
	char *ret;

	if ((sections = r_bin_get_sections (bin)) == NULL)
		return R_FALSE;

	r_list_foreach (sections, iter, section) {
		if (!strcmp (scnname, section->name)) {
			if (!(buf = malloc (section->size)))
				return R_FALSE;
			if (!(ret = malloc (section->size*2+1))) {
				free (buf);
				return R_FALSE;
			}
			r_buf_read_at (bin->cur->buf, section->paddr, buf, section->size);
			if (output) {
				r_file_dump (output, buf, section->size);
			} else {
				r_hex_bin2str (buf, section->size, ret);
				printf ("%s\n", ret);
			}
			free (buf);
			free (ret);
			break;
		}
	}

	return R_TRUE;
}

static int rabin_do_operation(const char *op) {
	char *arg = NULL, *ptr = NULL, *ptr2 = NULL;

	/* Implement alloca with fixed-size buffer? */
	if (!(arg = strdup (op)))
		return R_FALSE;

	if ((ptr = strchr (arg, '/'))) {
		ptr[0] = '\0';
		ptr++;
		if ((ptr2 = strchr (ptr, '/'))) {
			ptr2[0] = '\0';
			ptr2++;
		}
	}

	switch (arg[0]) {
	case 'd':
		if (!ptr)
			goto _rabin_do_operation_error;
		switch (*ptr) {
		case 's':
			if (ptr2) {
				if (!rabin_dump_symbols (r_num_math (NULL, ptr2)))
					return R_FALSE;
			} else if (!rabin_dump_symbols (0)) {
				free (arg);
				return R_FALSE;
			}
			break;
		case 'S':
			if (!ptr2)
				goto _rabin_do_operation_error;
			if (!rabin_dump_sections (ptr2)) {
				free (arg);
				return R_FALSE;
			}
			break;
		default:
			goto _rabin_do_operation_error;
		}
		break;
	case 'r':
		r_bin_wr_scn_resize (bin, ptr, r_num_math (NULL, ptr2));
		if (!output) output = "out";
		r_bin_wr_output (bin, output);
		break;
	default:
	_rabin_do_operation_error:
		eprintf ("Unknown operation. use -O help\n");
		free (arg);
		return R_FALSE;
	}

	free (arg);
	return R_TRUE;
}

static int rabin_show_srcline(ut64 at) {
	char *srcline;
	if ((srcline = r_bin_addr2text (bin, at))) {
		printf ("%s\n", srcline);
		free (srcline);
		return R_TRUE;
	}
	return R_FALSE;
}

/* bin callback */
static int __lib_bin_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_plugin_t *hand = (struct r_bin_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_add (bin, hand);
	return R_TRUE;
}

static int __lib_bin_dt(struct r_lib_plugin_t *pl, void *p, void *u) {
	return R_TRUE;
}

/* binxtr callback */
static int __lib_bin_xtr_cb(struct r_lib_plugin_t *pl, void *user, void *data) {
	struct r_bin_xtr_plugin_t *hand = (struct r_bin_xtr_plugin_t *)data;
	//printf(" * Added (dis)assembly plugin\n");
	r_bin_xtr_add (bin, hand);
	return R_TRUE;
}

static int __lib_bin_xtr_dt(struct r_lib_plugin_t *pl, void *p, void *u) {
	return R_TRUE;
}

int main(int argc, char **argv) {
	const char *query = NULL;
	int c, bits = 0, actions_done = 0, actions = 0, action = ACTION_UNK;
	char *homeplugindir = r_str_home (R2_HOMEDIR"/plugins");
	char *ptr, *arch = NULL, *arch_name = NULL;
	const char *op = NULL;
	const char *chksum = NULL;
	RCoreBinFilter filter;
	RCore core;
	RCoreFile *cf = NULL;
	int xtr_idx = 0; // load all files if extraction is necessary.
	int fd = -1;
	int rawstr = 0;

	r_core_init (&core);
	bin = core.bin;
	l = r_lib_new ("radare_plugin");
	r_lib_add_handler (l, R_LIB_TYPE_BIN, "bin plugins",
			   &__lib_bin_cb, &__lib_bin_dt, NULL);
	r_lib_add_handler (l, R_LIB_TYPE_BIN_XTR, "bin xtr plugins",
			   &__lib_bin_xtr_cb, &__lib_bin_xtr_dt, NULL);

	/* load plugins everywhere */
	r_lib_opendir (l, getenv ("LIBR_PLUGINS"));
	r_lib_opendir (l, homeplugindir);
	r_lib_opendir (l, LIBDIR"/radare2/"R2_VERSION);

#define is_active(x) (action&x)
#define set_action(x) actions++; action |= x
#define unset_action(x) action &= ~x
	while ((c = getopt (argc, argv, "jgqAf:a:B:b:c:Ck:K:dMm:n:N:@:isSIHelRwO:o:pPrvLhxzZ")) != -1) {
		switch (c) {
		case 'g':
			set_action (ACTION_CLASSES);
			set_action (ACTION_IMPORTS);
			set_action (ACTION_SYMBOLS);
			set_action (ACTION_SECTIONS);
			set_action (ACTION_STRINGS);
			set_action (ACTION_SIZE);
			set_action (ACTION_INFO);
			set_action (ACTION_FIELDS);
			set_action (ACTION_DWARF);
			set_action (ACTION_ENTRIES);
			set_action (ACTION_MAIN);
			set_action (ACTION_LIBS);
			set_action (ACTION_RELOCS);
			set_action (ACTION_EXTRACT);
			break;
		case 'q': rad = R_CORE_BIN_SIMPLE; break;
		case 'j': rad = R_CORE_BIN_JSON; break;
		case 'A': set_action (ACTION_LISTARCHS); break;
		case 'a': if (optarg) arch = optarg; break;
		case 'c':
			if (!optarg) {
				eprintf ("Missing argument for -c");
				r_core_fini (&core);
				return 1;
			}
			set_action (ACTION_CREATE);
			create = strdup (optarg);
			break;
		case 'k': query = optarg; break;
		case 'K': chksum = optarg; break;
		case 'C': set_action (ACTION_CLASSES); break;
		case 'f': if (optarg) arch_name = strdup (optarg); break;
		case 'b': bits = r_num_math (NULL, optarg); break;
		case 'm':
			at = r_num_math (NULL, optarg);
			set_action (ACTION_SRCLINE);
			break;
		case 'i': set_action (ACTION_IMPORTS); break;
		case 's': set_action (ACTION_SYMBOLS); break;
		case 'S': set_action (ACTION_SECTIONS); break;
		case 'z':
			if (is_active (ACTION_STRINGS)) {
				if (rawstr) {
					/* rawstr mode 2 means that we are not going */
					/* to store them just dump'm all to stdout */
					rawstr = 2;
				} else {
					rawstr = R_TRUE;
				}
			} else set_action (ACTION_STRINGS);
			break;
		case 'Z': set_action (ACTION_SIZE); break;
		case 'I': set_action (ACTION_INFO); break;
		case 'H': set_action (ACTION_FIELDS); break;
		case 'd': set_action (ACTION_DWARF); break;
		case 'P':
			if (is_active(ACTION_PDB)) {
				set_action(ACTION_PDB_DWNLD);
			} else {
				set_action (ACTION_PDB);
			}
			break;
		case 'e': set_action (ACTION_ENTRIES); break;
		case 'M': set_action (ACTION_MAIN); break;
		case 'l': set_action (ACTION_LIBS); break;
		case 'R': set_action (ACTION_RELOCS); break;
		case 'x': set_action (ACTION_EXTRACT); break;
		case 'w': rw = R_TRUE; break;
		case 'O':
			op = optarg;
			set_action (ACTION_OPERATION);
			if (op && !strcmp (op, "help")) {
				printf ("Operation string:\n"
						"  Dump symbols: d/s/1024\n"
						"  Dump section: d/S/.text\n"
						"  Resize section: r/.data/1024\n");
				r_core_fini (&core);
				return 0;
			}
			if (optind==argc) {
				eprintf ("Missing filename\n");
				r_core_fini (&core);
				return 1;
			}
			break;
		case 'o': output = optarg; break;
		case 'p': va = R_FALSE; break;
		case 'r': rad = R_TRUE; break;
		case 'v': return blob_version ("rabin2");
		case 'L': r_bin_list (bin); return 1;
		case 'B':
			laddr = r_num_math (NULL, optarg);
			if (laddr == 0LL)
				va = R_FALSE;
			break;
		case '@': at = r_num_math (NULL, optarg); break;
		case 'n': name = optarg; break;
		case 'N': {
				  char *q, *p = strdup (optarg);
				  q = strchr (p, ':');
				  if (q) {
					  r_config_set (core.config, "bin.minstr", p);
					  r_config_set (core.config, "bin.maxstr", q+1);
				  } else {
					  r_config_set (core.config, "bin.minstr", optarg);
				  }
				  free (p);
			} break;
		//case 'V': return blob_version ("rabin2");
		case 'h':
				r_core_fini (&core);
				return rabin_show_help (1);
		default: action |= ACTION_HELP;
		}
	}

	file = argv[optind];
	if (!query)
	if (action & ACTION_HELP || action == ACTION_UNK || file == NULL) {
		r_core_fini (&core);
		return rabin_show_help (0);
	}

	if (arch) {
		ptr = strchr (arch, '_');
		if (ptr) {
			*ptr = '\0';
			bits = r_num_math (NULL, ptr+1);
		}
	}
	if (action & ACTION_CREATE) {
		// TODO: move in a function outside
		RBuffer *b;
		int datalen, codelen;
		ut8 *data = NULL, *code = NULL;
		char *p2, *p = strchr (create, ':');
		if (!p) {
			eprintf ("Invalid format for -c flag. Use 'format:codehexpair:datahexpair'\n");
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
		} else {
			data = NULL;
			datalen = 0;
		}
		code = malloc (strlen (p)+1);
		if (!code) {
			r_core_fini (&core);
		    return 1;
		}
		codelen = r_hex_str2bin (p, code);
		if (!arch) arch = "x86";
		if (!bits) bits = 32;

		if (!r_bin_use_arch (bin, arch, bits, create)) {
			eprintf ("Cannot set arch\n");
			r_core_fini (&core);
			return 1;
		}
		b = r_bin_create (bin, code, codelen, data, datalen);
		if (b) {
			if (r_file_dump (file, b->buf, b->length)) {
				eprintf ("dumped %d bytes in '%s'\n", b->length, file);
				r_file_chmod (file, "+x", 0);
			} else eprintf ("error dumping into a.out\n");
			r_buf_free (b);
		} else eprintf ("Cannot create binary for this format '%s'.\n", create);
		r_core_fini (&core);
		return 0;
	}
	if (rawstr == 2) {
		unset_action (ACTION_STRINGS);
	}
	r_config_set_i (core.config, "bin.rawstr", rawstr);
	cf = r_core_file_open (&core, file, R_IO_READ, 0);
	fd = cf ? r_core_file_cur_fd (&core) : -1;
	if (!cf || fd == -1) {
		eprintf ("r_core: Cannot open file\n");
		r_core_fini (&core);
		return 1;
	}

	bin->minstrlen = r_config_get_i (core.config, "bin.minstr");
	if (!r_bin_load (bin, file, laddr, 0, xtr_idx, fd, rawstr)) {
		if (!r_bin_load (bin, file, laddr, 0, xtr_idx, fd, rawstr)) {
			eprintf ("r_bin: Cannot open file\n");
			r_core_fini (&core);
			return 1;
		}
	}
	if (rawstr == 2) {
		rawstr = R_FALSE;
		r_bin_dump_strings (core.bin->cur, bin->minstrlen);
	}

	if (query) {
		if (rad) {
// TODO: Should be moved into core, to load those flags and formats into r2
			Sdb *db = sdb_ns (bin->cur->sdb, "info", 0);
			char *flagname;
			if (db) {

				SdbListIter *iter;
				SdbKv *kv;
				printf ("fs format\n");
				// iterate over all keys
				ls_foreach (db->ht->list, iter, kv) {
					char *k = kv->key;
					char *v = kv->value;
					char *dup = strdup (k);

					if ((flagname=strstr (dup, ".offset"))) {
						*flagname = 0;
						flagname = dup;

						printf ("f %s @ %s\n", flagname, v);
					}
					if ((flagname=strstr (dup, ".cparse"))) {
						printf ("\"td %s\"\n", v);
					}
					if ((flagname=strstr (dup, ".format"))) {
						*flagname = 0;
						flagname = dup;

						printf ("pf.%s %s\n", flagname, v);
					}
					free (dup);
				}

			}
			//sdb_query (bin->cur->sdb, "info/*");
		} else {
			if (!strcmp (query, "-")) {
				__sdb_prompt (bin->cur->sdb);
			} else sdb_query (bin->cur->sdb, query);
		}
		r_core_fini (&core);
		return 0;
	}

	// XXX: TODO move this to libr/core/bin.c
	if (action & ACTION_LISTARCHS || ((arch || bits || arch_name) &&
		!r_bin_select (bin, arch, bits, arch_name))) {
		if (rad == R_CORE_BIN_JSON) {
			int i;
			printf ("[");
			for (i = 0; i < bin->narch; i++) {
				if (r_bin_select_idx (bin, bin->file, i)) {
					RBinObject *o = r_bin_cur_object (bin);
					RBinInfo *info = o ? o->info : NULL;
					printf ("%s{\"arch\":\"%s\",\"bits\":%d,"
						"\"offset\":%"PFMT64d",\"machine\":\"%s\"}",
						i?",":"",info->arch, info->bits,
						bin->cur->offset, info->machine);
				}
			}
			printf ("]");
		} else r_bin_list_archs (bin, 1);
		free (arch_name);
	}

	// ASLR WTF
	if (laddr != 0LL) {
		//r_bin_set_baddr (bin, laddr);
		//bin->cur->o->baddr = laddr;
	}
	r_config_set_i (core.config, "bin.laddr", laddr);

	core.bin = bin;
	filter.offset = at;
	filter.name = name;

	r_cons_new ()->is_interactive = R_FALSE;

	if (action&ACTION_PDB_DWNLD) {
		char *env_pdbserver = r_sys_getenv ("PDB_SERVER");
		SPDBDownloader pdb_downloader;
		SPDBDownloaderOpt opt;
		RBinInfo *info = r_bin_get_info(core.bin);
		char *path = r_file_dirname(info->file);
		if (env_pdbserver && *env_pdbserver)
			r_config_set (core.config, "pdb.server", env_pdbserver);
		opt.dbg_file = info->debug_file_name;
		opt.guid = info->guid;
		opt.symbol_server = (char *)r_config_get(core.config, "pdb.server");
		opt.user_agent = (char *)r_config_get(core.config, "pdb.user_agent");
		opt.path = path;

		init_pdb_downloader(&opt, &pdb_downloader);
		if (pdb_downloader.download(&pdb_downloader) == 0) {
			printf("PDB file %s has not been downloaded sucessfully\n", opt.dbg_file);
		} else {
			printf("PDB file %s has been downloaded sucessfully\n", opt.dbg_file);
		}
		deinit_pdb_downloader(&pdb_downloader);

		free(path);
		r_core_fini (&core);
		return 0;
	}

#define isradjson (rad==R_CORE_BIN_JSON&&actions>0)
#define run_action(n,x,y) {\
	if (action&x) {\
		if (isradjson) r_cons_printf ("\"%s\":",n);\
		if (!r_core_bin_info (&core, y, rad, va, &filter, laddr, chksum)) {\
			if (isradjson) r_cons_printf  ("false");\
		};\
		actions_done++;\
		if (isradjson) r_cons_printf (actions==actions_done? "":",");\
	}\
}
	if (isradjson) r_cons_printf ("{");
	run_action ("sections", ACTION_SECTIONS, R_CORE_BIN_ACC_SECTIONS);
	run_action ("entries", ACTION_ENTRIES, R_CORE_BIN_ACC_ENTRIES);
	run_action ("main", ACTION_MAIN, R_CORE_BIN_ACC_MAIN);
	run_action ("imports", ACTION_IMPORTS, R_CORE_BIN_ACC_IMPORTS);
	run_action ("classes", ACTION_CLASSES, R_CORE_BIN_ACC_CLASSES);
	run_action ("symbols", ACTION_SYMBOLS, R_CORE_BIN_ACC_SYMBOLS);
	run_action ("strings", ACTION_STRINGS, R_CORE_BIN_ACC_STRINGS);
	run_action ("info", ACTION_INFO, R_CORE_BIN_ACC_INFO);
	run_action ("fields", ACTION_FIELDS, R_CORE_BIN_ACC_FIELDS);
	run_action ("libs", ACTION_LIBS, R_CORE_BIN_ACC_LIBS);
	run_action ("relocs", ACTION_RELOCS, R_CORE_BIN_ACC_RELOCS);
	run_action ("dwarf", ACTION_DWARF, R_CORE_BIN_ACC_DWARF);
	run_action ("pdb", ACTION_PDB, R_CORE_BIN_ACC_PDB);
	run_action ("size", ACTION_SIZE, R_CORE_BIN_ACC_SIZE);
	if (action&ACTION_SRCLINE)
		rabin_show_srcline (at);
	if (action&ACTION_EXTRACT)
		rabin_extract ((arch==NULL && arch_name==NULL && bits==0));
	if (op != NULL && action&ACTION_OPERATION)
		rabin_do_operation (op);
	if (isradjson)
		printf ("}");
	r_cons_flush ();
	r_core_fini (&core);

	return 0;
}
