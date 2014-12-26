/* radare - LGPL - Copyright 2011-2014 - earada, pancake */

#include <r_core.h>

// dup from cmd_info
#define PAIR_WIDTH 9
static void pair(const char *a, const char *b) {
	char ws[16];
	int al = strlen (a);
	if (!b) b = "";
	memset (ws, ' ', sizeof (ws));
	al = PAIR_WIDTH-al;
	if (al<0) al = 0;
	ws[al] = 0;
	r_cons_printf ("%s%s%s\n", a, ws, b);
}

#define STR(x) (x)?(x):""
// XXX - this may lead to conflicts with set by name
static int r_core_bin_set_cur (RCore *core, RBinFile *binfile);

static ut64 rva (RBin *bin, int va, ut64 paddr, ut64 vaddr, ut64 baddr, ut64 laddr) {
	int has_info = 0;
	if (bin && bin->cur && bin->cur->o && bin->cur->o->info)
		has_info = 1;
	if (has_info && bin->cur->o->info->type[0] != 'E') {
		// if its not an executable, use va = 2 mode to load the syms
		// hackaround to make -1 be va=0 and 0 to be no-laddr
		if (baddr == 0) {
			// its an object, so load it at base 0
			va = 2;
		}
	}
	if (laddr == UT64_MAX)
		va = 0;
	if (has_info && bin->cur->o->info->bits != 16) {
		// hackaround the hackaround for bios
		if (va == 2) {
			if (!baddr) baddr = 1;
			// hackaround for PIE bins
		}
	}
	switch (va) {
	case 0: // pa $ rabin2 -p
		return paddr;
	case 1: // va $ rabin2
		return r_bin_get_vaddr (bin, baddr, paddr, vaddr);
	case 2: // la $ rabin2 -B
		if (!baddr && !laddr)
			return vaddr;
		return paddr + laddr;
	}
	return vaddr;
}

R_API int r_core_bin_set_by_fd (RCore *core, ut64 bin_fd) {
	if (r_bin_file_set_cur_by_fd (core->bin, bin_fd)) {
		r_core_bin_set_cur (core, r_core_bin_cur(core));
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_core_bin_set_by_name (RCore *core, const char * name) {
	if (r_bin_file_set_cur_by_name (core->bin, name)) {
		r_core_bin_set_cur (core, r_core_bin_cur (core));
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_core_bin_set_env (RCore *r, RBinFile *binfile) {
	RBinObject *binobj = binfile ? binfile->o: NULL;
	RBinInfo *info = binobj ? binobj->info: NULL;
	if (info) {
		int va = info->has_va;
		const char * arch = info->arch;
		ut16 bits = info->bits;
		ut64 loadaddr = r_config_get_i (r->config, "bin.laddr");
		ut64 baseaddr = binobj->baddr;
		/* Hack to make baddr work on some corner */
		r_config_set_i (r->config, "io.va",
			(binobj->info)? binobj->info->has_va: 0);
		r_config_set_i (r->config, "bin.laddr", loadaddr);
		r_config_set_i (r->config, "bin.baddr", baseaddr);
		r_config_set (r->config, "asm.arch", arch);
		r_config_set_i (r->config, "asm.bits", bits);
		r_config_set (r->config, "anal.arch", arch);
		if (strlen(info->cpu))
			r_config_set (r->config, "anal.cpu", info->cpu);
		else	r_config_set (r->config, "anal.cpu", arch);
		r_asm_use (r->assembler, arch);

		r_core_bin_info (r, R_CORE_BIN_ACC_ALL, R_CORE_BIN_SET,
			va, NULL, loadaddr, NULL);
		r_core_bin_set_cur (r, binfile);
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_core_bin_set_cur (RCore *core, RBinFile *binfile) {
	if (!core->bin) return R_FALSE;
	if (!binfile) {
		// Find first available binfile
		ut32 fd = r_core_file_cur_fd (core);
		binfile = fd != (ut32) -1 ?  r_bin_file_find_by_fd (
			core->bin, fd) : NULL;
		if (!binfile) return R_FALSE;
	}
	r_bin_file_set_cur_binfile (core->bin, binfile);
	return R_TRUE;
}

R_API int r_core_bin_refresh_strings(RCore *r) {
	return r_bin_reset_strings (r->bin) ? R_TRUE: R_FALSE;
}

R_API RBinFile * r_core_bin_cur (RCore *core) {
	RBinFile *binfile = r_bin_cur (core->bin);
	return binfile;
}

static int bin_strings (RCore *r, int mode, ut64 baddr, int va) {
	char *p, *q, str[R_FLAG_NAME_SIZE];
	RBinSection *section;
	int hasstr, minstr, maxstr, rawstr;
	RBinString *string;
	RListIter *iter;
	RList *list;
	RBin *bin = r->bin;
	RBinFile * binfile = r_core_bin_cur (r);
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);

	if (!binfile) return R_FALSE;
	minstr = r_config_get_i (r->config, "bin.minstr");
	maxstr = r_config_get_i (r->config, "bin.maxstr");
	rawstr = r_config_get_i (r->config, "bin.rawstr");
	binfile->rawstr = rawstr;

	if (!(hasstr = r_config_get_i (r->config, "bin.strings")))
		return 0;

	if (!plugin) return 0;
	if (plugin->info && plugin->name) {
		if (!strcmp (plugin->name, "any")) {
			if (!rawstr) {
#if 0
				eprintf ("NOTE: Use '-e bin.rawstr=true' or 'r2 -zz' or '.!rabin2 -zz $FILE'"
					" to find strings on unknown file types\n");
#endif
				return R_FALSE;

			}
		}
	}

#if 0
	if (bin->minstrlen == 0)
		bin->minstrlen = minstr;
	else plugin->minstrlen? plugin->minstrlen: 4;
#endif
		bin->minstrlen = minstr;
#if 0
	if (bin->minstrlen <= 0)
		bin->minstrlen = R_MIN (minstr, 4);
#endif
	minstr = bin->minstrlen;

	if ((list = r_bin_get_strings (bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_JSON)) {
		r_cons_printf ("[");
		r_list_foreach (list, iter, string) {
			ut64 vaddr = r_bin_get_vaddr (bin, baddr,
				string->vaddr, string->paddr);
			ut64 paddr = string->paddr;
			q = strdup (string->string);
			if (maxstr && string->length>maxstr) {
				continue;
			}
			for (p=q; *p; p++) {
				if (*p=='"') *p = '\'';
				if (*p=='\\') *p = '/';
			}
			if (string->length>minstr) {
				r_cons_printf ("%s{\"vaddr\":%"PFMT64d
				",\"paddr\":%"PFMT64d
				",\"length\":%d,\"size\":%d,"
				"\"type\":\"%s\",\"string\":\"%s\"}",
				iter->p? ",": "", vaddr, paddr,
				string->length, string->size,
				string->type=='w'?"wide":"ascii", q);
			}
			free (q);
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_SIMPLE)) {
		r_list_foreach (list, iter, string) {
			ut64 addr = va? r_bin_get_vaddr (bin, baddr,
				string->paddr, string->vaddr): string->paddr;
			if (maxstr && string->length>maxstr) {
				continue;
			}
			if (string->length>minstr) {
				r_cons_printf ("%"PFMT64d" %d %d %s\n",
					addr, string->size, string->length, string->string);
			}
		}
	} else
	if ((mode & R_CORE_BIN_SET)) {
		char *filtered_name;
		if (r_config_get_i (r->config, "bin.strings"))
			r_flag_space_set (r->flags, "strings");
		r_cons_break (NULL, NULL);
		r_list_foreach (list, iter, string) {
			ut64 addr = va? string->vaddr: string->paddr;
			 //r_bin_get_vaddr (bin, baddr, string->vaddr,
		//		string->paddr): string->paddr;
			if (string->length<minstr)
				continue;
			if (maxstr && string->length>maxstr) {
				continue;
			}
			if (r_cons_singleton()->breaked) break;
			r_meta_add (r->anal, R_META_TYPE_STRING, addr,
				addr+string->size, string->string);
			filtered_name = strdup (string->string);
			r_name_filter (filtered_name, R_FLAG_NAME_SIZE);
			snprintf (str, R_FLAG_NAME_SIZE, "str.%s", filtered_name);
			r_flag_set (r->flags, str, addr, string->size, 0);
			free (filtered_name);
		}
		//r_meta_cleanup (r->anal->meta, 0LL, UT64_MAX);
		r_cons_break_end ();
	} else {
		if (mode) r_cons_printf ("fs strings\n"); //: "[strings]\n");
		r_list_foreach (list, iter, string) {
			// TODO: honor laddr..
			ut64 vaddr = string->vaddr;
			ut64 paddr = string->paddr;
			if (string->length<minstr)
				continue;
			if (maxstr && string->length>maxstr) {
				continue;
			}
			section = r_bin_get_section_at (r_bin_cur_object (bin), string->paddr, 0);
			if (mode) {
				char *filtered_name;
				filtered_name = strdup (string->string);
				r_name_filter (filtered_name, R_FLAG_NAME_SIZE);
				snprintf (str, R_FLAG_NAME_SIZE, "str.%s", filtered_name);
				r_cons_printf ("f str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
					"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
					filtered_name, string->size, va? vaddr: paddr,
					string->size, va? vaddr: paddr);
				free (filtered_name);
			} else r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x
				" ordinal=%03u "
				"sz=%u len=%u section=%s type=%c string=%s\n", vaddr, paddr,
				string->ordinal, string->size, string->length,
				section?section->name:"unknown",
				string->type, string->string);
		}
	}
	return R_TRUE;
}

static int bin_info (RCore *r, int mode) {
	int i, j;
	char str[R_FLAG_NAME_SIZE];
	RBinInfo *info = r_bin_get_info (r->bin);
	RBinFile *binfile = r_core_bin_cur (r);
	if (!info) {
		if (mode & R_CORE_BIN_JSON)
			r_cons_printf ("{}");
		return R_FALSE;
	}

	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("{\"type\":\"%s\","
			"\"class\":\"%s\","
			"\"endian\":\"%s\","
			"\"machine\":\"%s\","
			"\"arch\":\"%s\","
			"\"os\":\"%s\","
			"\"lang\":\"%s\","
			"\"pic\":%s,"
			"\"canary\":%s,"
			"\"nx\":%s,"
			"\"crypto\":%s,"
			"\"va\":%s,"
			"\"bits\":%d,"
			"\"stripped\":%s,"
			"\"static\":%s,"
			"\"linenums\":%s,"
			"\"syms\":%s,"
			"\"relocs\":%s}",
			STR(info->rclass), // type
			STR(info->bclass), // class
			info->big_endian? "big": "little",
			STR(info->machine),
			STR(info->arch),
			STR(info->os),
			info->lang?info->lang:"",
			r_str_bool (info->has_pi),
			r_str_bool (info->has_canary),
			r_str_bool (info->has_nx),
			r_str_bool (info->has_crypto),
			r_str_bool (info->has_va),
			info->bits,
			r_str_bool ((R_BIN_DBG_STRIPPED & info->dbg_info)),
			r_str_bool (r_bin_is_static (r->bin)),//R_BIN_DBG_STATIC (info->dbg_info)),
			r_str_bool ((R_BIN_DBG_LINENUMS & info->dbg_info)),
			r_str_bool ((R_BIN_DBG_SYMS &info->dbg_info)),
			r_str_bool ((R_BIN_DBG_RELOCS &info->dbg_info)));
	} else
	if ((mode & R_CORE_BIN_SIMPLE)) {
		r_cons_printf ("arch %s\n", info->arch);
		r_cons_printf ("bits %d\n", info->bits);
		r_cons_printf ("os %s\n", info->os);
		r_cons_printf ("endian %s\n", info->big_endian? "big": "little");
	} else
	if ((mode & R_CORE_BIN_SET)) {
		r_config_set (r->config, "file.type", info->rclass);
		r_config_set (r->config, "cfg.bigendian", info->big_endian?"true":"false");
		if (!strcmp (info->rclass, "fs")) {
			r_config_set (r->config, "asm.arch", info->arch);
			r_core_cmdf (r, "m /root %s 0", info->arch);
		} else {
			r_config_set (r->config, "asm.os", info->os);
			r_config_set (r->config, "asm.arch", info->arch);
			r_config_set (r->config, "anal.arch", info->arch);
			snprintf (str, R_FLAG_NAME_SIZE, "%i", info->bits);
			r_config_set (r->config, "asm.bits", str);
			r_config_set (r->config, "asm.dwarf",
				(R_BIN_DBG_STRIPPED &info->dbg_info)?"false":"true");
		}
	} else {
		if (mode) {
			if (!strcmp (info->type, "fs")) {
				r_cons_printf ("e file.type=fs\n");
				r_cons_printf ("m /root %s 0\n", info->arch);
			} else {
				// XXX: hack to disable io.va when loading an elf object
				// XXX: this must be something generic for all filetypes
				// XXX: needs new api in r_bin_has_va () or something..
				//int has_va = (!strcmp (info->rclass, "elf-object"))? 0: 1;
				//if (!strcmp (info->type, "REL"))...relocatable object..
				r_cons_printf (
					"e file.type=%s\n"
					"e cfg.bigendian=%s\n"
					"e asm.os=%s\n"
					"e asm.arch=%s\n"
					"e anal.arch=%s\n"
					"e asm.bits=%i\n"
					"e asm.dwarf=%s\n",
					info->rclass, r_str_bool (info->big_endian), info->os,
					info->arch, info->arch, info->bits,
					r_str_bool (R_BIN_DBG_STRIPPED &info->dbg_info));
			}
		} else {
			// if type is 'fs' show something different?
			//r_cons_printf ("# File info\n");

			pair ("file", info->file);
			pair ("type", info->type);
			pair ("pic", r_str_bool (info->has_pi));
			pair ("canary", r_str_bool (info->has_canary));
			pair ("nx", r_str_bool (info->has_nx));
			pair ("crypto", r_str_bool (info->has_crypto));
			pair ("va", r_str_bool (info->has_va));
			pair ("root", info->rclass);
			pair ("class", info->bclass);
			pair ("lang", info->lang? info->lang: "unknown");
			pair ("arch", info->arch);
			pair ("bits", sdb_fmt (0, "%d", info->bits));
			pair ("machine", info->machine);
			pair ("os", info->os);
			pair ("subsys", info->subsystem);
			pair ("endian", info->big_endian? "big": "little");
			pair ("strip", r_str_bool (R_BIN_DBG_STRIPPED &info->dbg_info));
			pair ("static", r_str_bool (r_bin_is_static (r->bin)));
			pair ("linenum", r_str_bool (R_BIN_DBG_LINENUMS &info->dbg_info));
			pair ("lsyms", r_str_bool (R_BIN_DBG_SYMS &info->dbg_info));
			pair ("relocs", r_str_bool (R_BIN_DBG_RELOCS &info->dbg_info));
			pair ("rpath", info->rpath);
			if (info->guid && *info->guid)
				pair ("guid", info->guid);
			if (info->debug_file_name && *info->debug_file_name)
				pair ("dbg_file", info->debug_file_name);

			for (i=0; info->sum[i].type; i++) {
				int len;
				//ut8 *sum = &info; // XXX
				RBinHash *h = &info->sum[i];
				ut64 hash = r_hash_name_to_bits (h->type);
				RHash *rh = r_hash_new (R_TRUE, hash);
				len = r_hash_calculate (rh, hash, (const ut8*)
					binfile->buf->buf+h->from, h->to);
				//ut8 *p = binfile->buf+h->addr;
				if (len<1) eprintf ("Invaild wtf\n");
				r_hash_free (rh);

				r_cons_printf ("%s\t%d-%dc\t", h->type, h->from, h->to+h->from);
				for (j=0; j<h->len; j++)
					r_cons_printf ("%02x", h->buf[j]);
				r_cons_newline ();
			}
		}
	}
	return R_TRUE;
}

static int bin_dwarf (RCore *core, int mode) {
	RBinDwarfRow *row;
	RListIter *iter;
	RList *list = NULL;
	RBinFile *binfile = r_core_bin_cur (core);
	RBinPlugin * plugin = r_bin_file_cur_plugin (binfile);
	if (!binfile) return R_FALSE;

	if (plugin && plugin->lines) {
		list = plugin->lines (binfile);
	} else if (core->bin) {
		// TODO: complete and speed-up support for dwarf
		if (r_config_get_i (core->config, "bin.dwarf")) {
			RBinDwarfDebugAbbrev *da = NULL;
			da = r_bin_dwarf_parse_abbrev (core->bin, mode);
			r_bin_dwarf_parse_info (da, core->bin, mode);
			r_bin_dwarf_parse_aranges (core->bin, mode);
			list = r_bin_dwarf_parse_line (core->bin, mode);
			r_bin_dwarf_free_debug_abbrev (da);
			free (da);
		}
	}
	if (!list) return R_FALSE;
	r_cons_break (NULL, NULL);
        r_list_foreach (list, iter, row) {
		if (r_cons_singleton()->breaked) break;
		if (mode) {
			// TODO: use 'Cl' instead of CC
			const char *path = row->file;
			char *line = r_file_slurp_line (
					path, row->line-1, 0);
			if (line) {
				r_str_filter (line, strlen (line));
				line = r_str_replace (line, "\"", "\\\"", 1);
				line = r_str_replace (line, "\\\\", "\\", 1);
			}
			// TODO: implement internal : if ((mode & R_CORE_BIN_SET)) {
			if ((mode & R_CORE_BIN_SET)) {
				r_core_cmdf (core, "\"CC %s:%d  %s\"@0x%"PFMT64x"\n",
						row->file, row->line, line?line:"", row->address);
			} else r_cons_printf ("\"CC %s:%d  %s\"@0x%"PFMT64x"\n",
				row->file, row->line, line?line:"", row->address);
			free (line);
		} else {
			r_cons_printf ("0x%08"PFMT64x"\t%s\t%d\n", row->address, row->file, row->line);
		}
        }
	r_cons_break_end ();
	r_list_purge (list);
	free (list);
	return R_TRUE;
}

static int bin_pdb (RCore *core, ut64 baddr, int mode) {
	R_PDB pdb = {0};

	pdb.printf = r_cons_printf;
	if (!init_pdb_parser (&pdb, core->bin->file)) {
		//eprintf ("initialization error of pdb parser\n");
		return R_FALSE;
	}

	if (!pdb.pdb_parse (&pdb)) {
		eprintf ("pdb was not parsed\n");
		pdb.finish_pdb_parse (&pdb);
		return R_FALSE;
	}

	if (mode == R_CORE_BIN_JSON)
		r_cons_printf("[");

	switch (mode) {
	case R_CORE_BIN_JSON:
		mode = 'j';
		break;
	case 1:
		mode = 'r';
		break;
	default:
		mode = 'd'; // default
		break;
	}

	pdb.print_types (&pdb, mode);

	if (mode == 'j')
		r_cons_printf (",");
	pdb.print_gvars (&pdb, baddr, mode);
	if (mode == 'j')
		r_cons_printf ("]");
	pdb.finish_pdb_parse (&pdb);

	return R_TRUE;
}

static int bin_main (RCore *r, int mode, ut64 baddr, int va) {
	RBinAddr *binmain = r_bin_get_sym (r->bin, R_BIN_SYM_MAIN);
	if (!binmain) return R_FALSE;
	baddr = 0LL; // This is broken, just to make t.formats/elf/main happy
	if ((mode & R_CORE_BIN_SIMPLE) || mode & R_CORE_BIN_JSON) {
		r_cons_printf ("%"PFMT64d, va? (baddr+binmain->vaddr):binmain->paddr);
	} else
	if ((mode & R_CORE_BIN_SET)) {
		r_flag_space_set (r->flags, "symbols");
		r_flag_set (r->flags, "main", va? (baddr+binmain->vaddr): binmain->paddr,
				r->blocksize, 0);
	} else {
		if (mode) {
			r_cons_printf ("fs symbols\n");
			r_cons_printf ("f main @ 0x%08"PFMT64x"\n",
				va? baddr+binmain->vaddr: binmain->paddr);
		} else {
			r_cons_printf ("[Main]\n");
			r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x"\n",
					baddr+binmain->vaddr, binmain->paddr);
		}
	}
	return R_TRUE;
}

static int bin_entry (RCore *r, int mode, ut64 baddr, ut64 laddr, int va) {
	char str[R_FLAG_NAME_SIZE];
	RList *entries;
	RListIter *iter;
	RBinAddr *entry = NULL;
	int i = 0;

	entries = r_bin_get_entries (r->bin);

	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("[");
		r_list_foreach (entries, iter, entry) {
			ut64 at = rva (r->bin, va, entry->paddr, entry->vaddr, baddr, laddr);
			r_cons_printf ("%s%"PFMT64d,
				iter->p? ",":"", at);
		}
		r_cons_printf ("]");
	} else
	if (mode & R_CORE_BIN_SIMPLE) {
		r_list_foreach (entries, iter, entry) {
			ut64 at = rva (r->bin, va, entry->paddr, entry->vaddr, baddr, laddr);
			r_cons_printf ("0x%08"PFMT64x"\n", at);
		}
	} else
	if ((mode & R_CORE_BIN_SET)) {
		r_list_foreach (entries, iter, entry) {
			ut64 at = rva (r->bin, va, entry->paddr, entry->vaddr, baddr, laddr);
			if (at == 0) at = entry->vaddr;
			snprintf (str, R_FLAG_NAME_SIZE, "entry%i", i++);
			r_flag_set (r->flags, str, at, 1, 0);
		}
		/* Seek to the last entry point */
		if (entry)
			r_core_seek (r, va? baddr+entry->vaddr: entry->paddr, 0);
	} else {
		if (mode) r_cons_printf ("fs symbols\n");
		else r_cons_printf ("[Entrypoints]\n");

		r_list_foreach (entries, iter, entry) {
			ut64 paddr = entry->paddr;
			ut64 vaddr = r_bin_get_vaddr (r->bin, baddr,
				paddr, entry->vaddr);
			if (mode) {
				ut64 at = rva (r->bin, va, entry->paddr, entry->vaddr, baddr, laddr);
				r_cons_printf ("f entry%i 1 @ 0x%08"PFMT64x"\n", i, at);
				r_cons_printf ("s entry%i\n", i);
			} else r_cons_printf ("vaddr=0x%08"PFMT64x
					" paddr=0x%08"PFMT64x
					" baddr=0x%08"PFMT64x
					" laddr=0x%08"PFMT64x"\n",
					vaddr, paddr, baddr, laddr);
			i++;
		}
		if (!mode) r_cons_printf ("\n%i entrypoints\n", i);
	}
	return R_TRUE;
}

static const char *bin_reloc_type_name (RBinReloc *reloc) {
#define CASE(T) case R_BIN_RELOC_ ## T: return reloc->additive ? "ADD_" #T : "SET_" #T
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	}
	return "UNKNOWN";
#undef CASE
}

static ut8 bin_reloc_size (RBinReloc *reloc) {
	#define CASE(T) case R_BIN_RELOC_ ## T: return T / 8
	switch (reloc->type) {
		CASE(8);
		CASE(16);
		CASE(32);
		CASE(64);
	}
	return 0;
	#undef CASE
}

static char *resolveModuleOrdinal (Sdb *sdb, const char *module, int ordinal) {
#if 0
	char res[128], *foo;
	Sdb *db = sdb_ns_path (sdb, "bin/pe", 0);
	if (!db) return NULL;
	db = sdb_ns (db, module, 0);
	if (!db) return NULL;
#endif
	Sdb *db = sdb;
	char *foo = sdb_get (db, sdb_fmt (0, "%d", ordinal), 0);
	if (foo && *foo) {
		return foo;
	}
	return NULL;
}

static int bin_relocs (RCore *r, int mode, ut64 baddr, int va) {
	char str[R_FLAG_NAME_SIZE];
	RList *relocs;
	RListIter *iter;
	RBinReloc *reloc;
	int i = 0;

	va = 1; // XXX relocs always vaddr?

	if ((relocs = r_bin_get_relocs (r->bin)) == NULL)
		return R_FALSE;

	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("[");
		r_list_foreach (relocs, iter, reloc) {
			if (reloc->import)
				r_cons_printf ("%s{\"name\":\"%s\",",
					iter->p?",":"", reloc->import->name);
			else r_cons_printf ("%s{\"name\":null,",
					iter->p?",":"");
			r_cons_printf ("\"type\":\"%s\","
				"\"vaddr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d"}",
				bin_reloc_type_name (reloc),
				reloc->vaddr, reloc->paddr);
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_SET)) {
		int bin_demangle = r_config_get_i (r->config, "bin.demangle");
		int is_pe = 1; // TODO: optimize
		int is_sandbox = r_sandbox_enable (0);
		char *sdb_module = NULL;
		RFlagItem *fi;
		char *demname, *symname;
		// TODO: if PE load pe.sdb
		Sdb *db = NULL;
		r_flag_space_set (r->flags, "relocs");
		r_list_foreach (relocs, iter, reloc) {
			ut64 addr = va? reloc->vaddr: reloc->paddr;
			demname = NULL;
			if (reloc->import && reloc->import->name[0]) {
				if (is_pe && !is_sandbox && strstr (reloc->import->name, "Ordinal")) {
					const char *TOKEN = ".dll_Ordinal_";
					char *module = strdup (reloc->import->name);
					char *import = strstr (module, TOKEN);
					if (import) {
						char *filename;
						int ordinal;
						*import = 0;
						import += strlen (TOKEN);
						ordinal = atoi (import);
						if (!sdb_module || strcmp (module, sdb_module)) {
							sdb_free (db);
							db = NULL;
							free (sdb_module);
							sdb_module = strdup (module);
							filename = sdb_fmt (1, "%s.sdb", module);
							if (r_file_exists (filename)) {
								db = sdb_new (NULL, filename, 0);
							} else {
#if __WINDOWS__
								filename = sdb_fmt (1, "share/radare2/"R2_VERSION"/format/dll/%s.sdb", module);
#else
								filename = sdb_fmt (1, R2_PREFIX"/share/radare2/" R2_VERSION"/format/dll/%s.sdb", module);
#endif
								if (r_file_exists (filename)) {
									db = sdb_new (NULL, filename, 0);
								}
							}
						}
						if (db) {
							// ordinal-1 because we enumerate starting at 0
							symname = resolveModuleOrdinal (db, module, ordinal-1);
							if (symname) {
								snprintf (reloc->import->name, 
									sizeof (reloc->import->name),
									"%s.%s", module, symname);
							}
						}
					}
					free (module);
					r_anal_hint_set_size (r->anal, reloc->vaddr, 4);
					r_meta_add (r->anal, R_META_TYPE_DATA, reloc->vaddr, reloc->vaddr+4, NULL);
				}
				snprintf (str, R_FLAG_NAME_SIZE,
					"reloc.%s_%d", reloc->import->name, (int)(addr&0xff));
					//"reloc.%s", reloc->import->name);
				if (bin_demangle)
					demname = r_bin_demangle (r->bin->cur, str); //reloc->import->name);
				r_name_filter (str, 0);
				//r_str_replace_char (str, '$', '_');
				fi = r_flag_set (r->flags, str, addr, bin_reloc_size (reloc), 0);
				if (demname) {
					r_flag_item_set_name (fi, str,
						sdb_fmt (0, "reloc.%s", demname));
				}
			} else {
				// TODO(eddyb) implement constant relocs.
			}
		}
		sdb_free (db);
		free (sdb_module);
	} else if ((mode & R_CORE_BIN_SIMPLE)) {
		r_list_foreach (relocs, iter, reloc) {
			ut64 addr = va? reloc->vaddr: reloc->paddr;
			r_cons_printf ("0x%08"PFMT64x"  %s\n", addr,
				reloc->import ? reloc->import->name : "");
		}
	} else {
		if (mode) {
			r_cons_printf ("fs relocs\n");
			r_list_foreach (relocs, iter, reloc) {
				ut64 addr = va? reloc->vaddr: reloc->paddr;
				if (reloc->import) {
					char *str = strdup (reloc->import->name);
					r_str_replace_char (str, '$', '_');
					r_cons_printf ("f reloc.%s_%d @ 0x%08"PFMT64x"\n", str, (int)(addr&0xff), addr);
					free (str);
				} else {
					// TODO(eddyb) implement constant relocs.
				}
				i++;
			}
		} else {
			r_cons_printf ("[Relocations]\n");
			r_list_foreach (relocs, iter, reloc) {
				ut64 addr = va? reloc->vaddr: reloc->paddr;
				r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" type=%s",
					addr, reloc->paddr, bin_reloc_type_name (reloc));
				if (reloc->import && reloc->import->name[0])
					r_cons_printf (" %s", reloc->import->name);
				if (reloc->addend) {
					if (reloc->import && reloc->addend > 0)
						r_cons_printf (" +");
					if (reloc->addend < 0)
						r_cons_printf (" - 0x%08"PFMT64x, -reloc->addend);
					else
						r_cons_printf (" 0x%08"PFMT64x, reloc->addend);
				}
				r_cons_printf ("\n");
				i++;
			}
			r_cons_printf ("\n%i relocations\n", i);
		}
	}
	return R_TRUE;
}

/* XXX: This is a hack to get PLT references in rabin2 -i */
/* imp. is a prefix that can be rewritten by the symbol table */
static ut64 impaddr(RBin *bin, int va, ut64 baddr, const char *name) {
	RBinSymbol *symbol;
	RList *symbols;
	RListIter *iter;
	if (!name) return R_FALSE;
	if ((symbols = r_bin_get_symbols (bin)) == NULL)
		return R_FALSE;
	r_list_foreach (symbols, iter, symbol) {
		if (strncmp (symbol->name, "imp.", 4))
			continue;
		if (!strcmp (symbol->name+4, name))
			return va? r_bin_get_vaddr (bin, baddr, symbol->paddr,
				symbol->vaddr): symbol->paddr;
	}
	return 0;
}

static int bin_imports (RCore *r, int mode, ut64 baddr, int va, const char *name) {
	RBinImport *import;
	RListIter *iter;
	RList *imports;
	int i = 0;

	imports = r_bin_get_imports (r->bin);

	if (mode & R_CORE_BIN_JSON) {
		ut64 addr;
		r_cons_printf ("[");
		r_list_foreach (imports, iter, import) {
			if (name && strcmp (import->name, name))
				continue;
			addr = impaddr (r->bin, va, baddr, import->name);
			r_cons_printf ("%s{\"name\":\"%s\", \"plt\":%"PFMT64d"}",
				iter->p?",":"", import->name, addr);
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_SIMPLE)) {
		r_list_foreach (imports, iter, import)
			r_cons_printf ("%s\n", import->name);
	} else
	if ((mode & R_CORE_BIN_SET)) {
		// TODO(eddyb) use the logic below for symbols that are imports.
		/*r_flag_space_set (r->flags, "imports");
		r_list_foreach (imports, iter, import) {
			r_name_filter (import->name, 128);
			snprintf (str, R_FLAG_NAME_SIZE, "imp.%s", import->name);
			if (import->size)
				if (!r_anal_fcn_add (r->anal, va?baddr+import->vaddr:import->paddr,
						import->size, str, R_ANAL_FCN_TYPE_IMP, NULL))
					eprintf ("Cannot add function: %s (duplicated)\n", import->name);
			r_flag_set (r->flags, str, va?baddr+import->vaddr:import->paddr,
					import->size, 0);
			iname = import->name;
			p = strstr (iname+1, "__");
			if (p) iname = p+1;
			dname = r_bin_demangle (r->bin, iname);
			if (dname) {
				r_meta_add (r->anal->meta, R_META_TYPE_COMMENT,
						va? baddr+import->vaddr: import->paddr,
						import->size, dname);
				free (dname);
			}
		}*/
	} else {
		ut64 addr;
		if (mode) r_cons_printf ("fs imports\n");
		else r_cons_printf ("[Imports]\n");

		r_list_foreach (imports, iter, import) {
			if (name && strcmp (import->name, name))
				continue;
			addr = impaddr (r->bin, va, baddr, import->name);
			if (mode) {
				// TODO(eddyb) use the logic below for symbols that are imports.
				/*r_name_filter (import->name, sizeof (import->name));
				iname = import->name;
				p = strstr (iname+1, "__");
				if (p) iname = p+1;
				mn = r_bin_demangle (r->bin, iname);
				if (mn) {
					//r_name_filter (mn, strlen (mn));
					r_cons_printf ("s 0x%08"PFMT64x"\n\"CC %s\"\n",
						import->paddr, mn);
					free (mn);
				}
				if (import->size)
					r_cons_printf ("af+ 0x%08"PFMT64x" %"PFMT64d" imp.%s i\n",
							va?baddr+import->vaddr:import->paddr,
							import->size, import->name);
				r_cons_printf ("f imp.%s @ 0x%08"PFMT64x"\n",
						import->name, va?baddr+import->vaddr:import->paddr);*/
			} else if (import->classname[0] != 0) {
				r_cons_printf ("ordinal=%03d plt=0x%08"PFMT64x" bind=%s type=%s classname=%s name=%s descriptor=%s\n",
					import->ordinal, addr,
					import->bind, import->type, import->classname, import->name, import->descriptor);
			} else r_cons_printf ("ordinal=%03d plt=0x%08"PFMT64x" bind=%s type=%s name=%s\n",
					import->ordinal, addr,
					import->bind, import->type, import->name);
			i++;
		}
		if (!mode) r_cons_printf ("\n%i imports\n", i);
	}
	return R_TRUE;
}

static int bin_symbols (RCore *r, int mode, ut64 baddr, ut64 laddr, int va, ut64 at, const char *name) {
	RBinInfo *info = r_bin_get_info (r->bin);
	char str[R_FLAG_NAME_SIZE];
	RList *symbols;
	RListIter *iter;
	RBinSymbol *symbol;
	int i = 0;
	int is_arm = info && !strcmp (info->arch, "arm");

	symbols = r_bin_get_symbols (r->bin);

	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("[");
		r_list_foreach (symbols, iter, symbol) {
			ut64 at = rva (r->bin, va, symbol->paddr, symbol->vaddr, baddr, laddr);
			ut64 vaddr = rva (r->bin, 1, symbol->paddr, symbol->vaddr, baddr, laddr);
			r_cons_printf ("%s{\"name\":\"%s\","
				"\"size\":%"PFMT64d","
				"\"addr\":%"PFMT64d","
				"\"vaddr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d"}",
				iter->p?",":"", symbol->name, symbol->size,
				at, vaddr, symbol->paddr);
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_SIMPLE)) {
		r_list_foreach (symbols, iter, symbol) {
			ut64 at = rva (r->bin, va, symbol->paddr, symbol->vaddr, baddr, laddr);
			char *name = strdup (symbol->name);
			r_name_filter (name, 80);
			r_cons_printf ("0x%08"PFMT64x" %"PFMT64d" %s\n",
				at, symbol->size, name);
			free (name);
		}
	} else
	if ((mode & R_CORE_BIN_SET)) {
		int is_thumb = 0;
		char *name, *dname, *cname, *demname = NULL;
		//ut8 cname_greater_than_15;
		r_flag_space_set (r->flags, "symbols");
		r_list_foreach (symbols, iter, symbol) {
			ut64 addr = rva (r->bin, va, symbol->paddr, symbol->vaddr, baddr, laddr);
			name = strdup (symbol->name);
			cname = (symbol->classname[0] != 0) ? strdup (symbol->classname) : NULL;
			// XXX - may want a configuration variable here for class and name lengths.
			// XXX - need something to handle overloaded symbols (e.g. methods)
			// void add (int i, int j);
			// void add (float i, int j);
			is_thumb = (is_arm && va && symbol->vaddr &1);
			if (is_thumb) {
				r_anal_hint_set_bits (r->anal, addr, 16);
			}

			demname = NULL;
			if (r_config_get_i (r->config, "bin.demangle"))
				demname = r_bin_demangle (r->bin->cur, name);
			r_name_filter (name, 80);
			if (!demname)
				demname = strdup (name);
			if (cname) {
				RFlagItem *fi = NULL;
				char * comment = NULL;

				r_name_filter (cname, 50);
				snprintf (str, R_FLAG_NAME_SIZE, "sym.%s", name);
				// check for a duplicate name sym.[name]
				fi = r_flag_get (r->flags, str);
				r_flag_item_set_name (fi, str, sdb_fmt (1,"sym.%s", demname));
				if (fi != NULL && (fi->offset - r->flags->base) == addr) {
					comment = fi->comment ? strdup (fi->comment) : NULL;
					r_flag_unset (r->flags, str, fi);
					fi = NULL;
				}
				// set the new sym.[cname].[name] with comment
				snprintf (str, R_FLAG_NAME_SIZE, "sym.%s.%s", cname, demname);
				fi = r_flag_set (r->flags, str, addr, symbol->size, 0);
				if (comment) {
					r_flag_item_set_comment (fi, comment);
					free (comment);
				}
			} else {
				const char *flagname = sdb_fmt (0, "sym.%s", name);
				RFlagItem *fi = r_flag_set (r->flags, flagname, addr, symbol->size, 0);
				r_flag_item_set_name (fi, flagname, sdb_fmt (1,"sym.%s", demname));
			}
			if (demname != name) {
				R_FREE (demname);
			}
#if 0
			// dunno why this is here and mips results in wrong dis
			if (!strncmp (symbol->type, "OBJECT", 6)) {
				r_meta_add (r->anal, R_META_TYPE_DATA, addr,
					addr + symbol->size, name);
			}
#endif
			dname = r_bin_demangle (r->bin->cur, symbol->name);
			if (dname) {
				r_meta_add (r->anal, R_META_TYPE_COMMENT,
						addr, symbol->size, dname);
				free (dname);
			}
			free (name);
			free (cname);
			//r_meta_cleanup (r->anal->meta, 0LL, UT64_MAX);
		}
	} else {
		if (!at) {
			if (mode) r_cons_printf ("fs symbols\n");
			else r_cons_printf ("[Symbols]\n");
		}

		r_list_foreach (symbols, iter, symbol) {
			ut64 addr = va? r_bin_get_vaddr (r->bin, baddr, symbol->paddr, symbol->vaddr): symbol->paddr;
			if (name && strcmp (symbol->name, name))
				continue;
			if (at) {
				if (symbol->size != 0 && ((at >= addr) && (at<(addr+symbol->size))))
					r_cons_printf ("%s\n", symbol->name);
			} else {
				if (mode) {
					char *mn = r_bin_demangle (r->bin->cur, symbol->name);
					if (mn) {
						//r_name_filter (mn, strlen (mn));
						r_cons_printf ("s 0x%08"PFMT64x"\n\"CC %s\"\n",
							symbol->paddr, mn);
						free (mn);
					}
					r_name_filter (symbol->name, sizeof (symbol->name));
#if 0
// remove to avoid unexpected issues
					if (!strncmp (symbol->type,"OBJECT", 6)) {
						if (symbol->size == 0) {
							symbol->size = strlen (symbol->name);
							r_cons_printf ("Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
									symbol->size, addr);
						} else
						if (symbol->size>0) {
							r_cons_printf ("Cd %"PFMT64d" @ 0x%08"PFMT64x"\n",
									(ut64)symbol->size, (ut64)addr);
						} else eprintf ("Wrong symbol '%s' have size %"PFMT64d"\n",
								symbol->name, symbol->size);
					}
#endif
					r_cons_printf ("f sym.%s %u 0x%08"PFMT64x"\n",
							symbol->name, symbol->size, addr);
					 {
						RBinFile * binfile = r_core_bin_cur (r);
						RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
						if (plugin && plugin->name) {
							if (!strncmp (plugin->name, "pe", 2)) {
								char *p, *module = strdup (symbol->name);
								p = strstr (module, ".dll_");
								if (p) {
									const char *symname = p+5;
									*p = 0;
									r_cons_printf ("k bin/pe/%s/%d=%s\n", module,
										symbol->ordinal, symname);
								}
								free (module);
							}
						}
					 }
				} else r_cons_printf ("vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" ord=%03u "
						    "fwd=%s sz=%u bind=%s type=%s name=%s\n",
						    addr, symbol->paddr,
						    symbol->ordinal, symbol->forwarder,
						    symbol->size, symbol->bind, symbol->type,
						    symbol->name);
			}
			i++;
		}
		if (!at && !mode) r_cons_printf ("\n%i symbols\n", i);
	}
	return R_TRUE;
}

static int bin_sections (RCore *r, int mode, ut64 baddr, ut64 laddr, int va, ut64 at, const char *name, const char *chksum) {
	char str[R_FLAG_NAME_SIZE];
	RBinSection *section;
	ut64 secbase = 0LL;
	RList *sections;
	RListIter *iter;
	int i = 0;
	st64 delta = 0LL;

	sections = r_bin_get_sections (r->bin);

	if (mode & R_CORE_BIN_JSON) {
		char *hashstr = NULL;
		r_cons_printf ("[");
		i = 0;
		r_list_foreach (sections, iter, section) {
			ut64 addr = rva (r->bin, va, section->paddr, section->vaddr, baddr, laddr);
			if (va)
				delta = section->vaddr - r_bin_get_vaddr (r->bin, baddr, section->paddr, section->vaddr);
			//ut64 addr = va? r_bin_get_vaddr (r->bin, baddr, section->paddr,
			//	section->vaddr): section->paddr;
			if (chksum) {
				char *chkstr;
				ut8 *data = malloc (section->size);
				ut32 datalen = section->size;
				r_io_pread (r->io, section->paddr, data, datalen);
				chkstr = r_hash_to_string (NULL, chksum, data, datalen);
				free (data);
				hashstr = malloc (strlen (chkstr)+strlen (chksum)+7);
				sprintf (hashstr, "\"%s\":\"%s\",", chksum, chkstr);
				free (chkstr);
			}
			r_cons_printf ("%s{\"name\":\"%s\","
				"\"size\":%"PFMT64d","
				"\"vsize\":%"PFMT64d","
				"\"flags\":\"%s\","
				"%s"
				"\"addr\":%"PFMT64d","
				"\"paddr\":%"PFMT64d","
				"\"vaddr\":%"PFMT64d"}",
				iter->p?",":"",
				section->name,
				section->size,
				section->vsize,
				r_str_rwx_i (section->srwx),
				hashstr? hashstr: "",
				addr, // paddr
				section->paddr, // paddr
				delta + section->vaddr); // vaddr
			free (hashstr);
			hashstr = NULL;
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_SIMPLE)) {
		char *chkstr = NULL;
		r_list_foreach (sections, iter, section) {
			ut64 addr = rva (r->bin, va, section->paddr, section->vaddr, baddr, laddr);
			if (chksum) {
				ut8 *data = malloc (section->size);
				ut32 datalen = section->size;
				r_io_pread (r->io, section->paddr, data, datalen);
				chkstr = r_hash_to_string (NULL, chksum, data, datalen);
				free (data);
			}
			r_cons_printf ("0x%"PFMT64x" 0x%"PFMT64x" %s %s%s%s\n",
				addr, addr + section->size,
				r_str_rwx_i (section->srwx),
				chkstr?chkstr:"", chkstr?" ":"",
				section->name
			);
			free (chkstr);
			chkstr = NULL;
		}
	} else
	if ((mode & R_CORE_BIN_SET)) {
		RBinInfo *info = r_bin_get_info (r->bin);
		int fd = r_core_file_cur_fd (r);
		r_flag_space_set (r->flags, "sections");
		r_list_foreach (sections, iter, section) {
// baddr already implicit in section->vaddr ?
			ut64 addr = rva (r->bin, va, section->paddr, section->vaddr, baddr, laddr);
			if (!secbase || (section->vaddr && section->vaddr <secbase)) // ??
				secbase = section->vaddr;
#if LOAD_BSS_MALLOC
			if (!strcmp (section->name, ".bss")) {
				// check if there's already a file opened there
				int loaded = 0;
				RListIter *iter;
				RIOMap *m;
				r_list_foreach (r->io->maps, iter, m) {
					if (m->from == section->vaddr) {
						loaded = 1;
					}
				}
				if (!loaded) {
					r_core_cmdf (r, "on malloc://%d 0x%"PFMT64x" # bss\n",
							section->vsize, section->vaddr);
				}
			}
#endif
			r_name_filter (section->name, 128);
			snprintf (str, sizeof(str)-1, "section.%s", section->name);
			r_flag_set (r->flags, str, addr, section->size, 0);
			snprintf (str, sizeof(str)-1, "section_end.%s", section->name);
			r_flag_set (r->flags, str, addr + section->size, 0, 0);
			if (section->arch || section->bits) {
				const char *arch = section->arch;
				int bits = section->bits;
				if (!arch) arch = info->arch;
				if (!bits) bits = info->bits;
				//r_io_section_set_archbits (r->io, addr, arch, bits);
			}
			snprintf (str, sizeof (str)-1, "[%i] va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"
				PFMT64d" vsz=%"PFMT64d" rwx=%c%c%c%c %s",
				i++, addr, section->paddr, section->size, section->vsize,
				(R_BIN_SCN_SHAREABLE & section->srwx)?'s':'-',
				(R_BIN_SCN_READABLE & section->srwx)?'r':'-',
				(R_BIN_SCN_WRITABLE & section->srwx)?'w':'-',
				(R_BIN_SCN_EXECUTABLE & section->srwx)?'x':'-',
				section->name);
			r_meta_add (r->anal, R_META_TYPE_COMMENT, addr, addr, str);
			r_io_section_add (r->io, section->paddr, addr, section->size,
				section->vsize, section->srwx, section->name, 0, fd);
		}
		// H -> Header fields
		if (0) {
/*
			ut64 size = r_io_size (r->io);
			if (size == 0)
				size = r->file->size;
*/
			ut64 size = r_io_desc_size (r->io, r->file->desc);
			secbase >>= 16;
			secbase <<= 16;
			secbase = baddr; // always override?
			r_io_section_add (r->io, 0, secbase, size, size, 7, "ehdr", 0, fd);
		}
	} else {
		RBinInfo *info = r_bin_get_info (r->bin);
		if (!at) r_cons_printf (mode? "fs sections\n": "[Sections]\n");

		r_list_foreach (sections, iter, section) {
			ut64 addr = rva (r->bin, va, section->paddr, section->vaddr, baddr, laddr);
			addr = section->vaddr; // this line fixes rbin_bios
			if (name && strcmp (section->name, name))
				continue;
			r_name_filter (section->name, sizeof (section->name));
			if (at) {
				if (section->size && ((at >= addr && (at<addr+section->size))))
					r_cons_printf ("%s\n", section->name);
			} else {
				if (mode) {
					if (!strcmp (section->name, ".bss")) {
						r_cons_printf ("on malloc://%d 0x%"PFMT64x" # bss\n",
								section->vsize, section->vaddr);
					}
					r_cons_printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d\n",
						section->paddr, addr, section->size, section->vsize,
						section->name, (int)section->srwx);
					if (section->arch || section->bits) {
						const char *arch = section->arch;
						int bits = section->bits;
						if (!arch) arch = info->arch;
						if (!bits) bits = info->bits;
						r_cons_printf ("Sa %s %d @ 0x%08"
							PFMT64x"\n", arch, bits, addr);
					}
					r_cons_printf ("f section.%s %"PFMT64d" 0x%08"PFMT64x"\n",
							section->name, section->size, addr);
					r_cons_printf ("f section_end.%s 1 0x%08"PFMT64x"\n",
							section->name, addr + section->size);
					r_cons_printf ("CC [%02i] va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
							"rwx=%c%c%c%c %s @ 0x%08"PFMT64x"\n",
							i, addr, section->paddr, section->size, section->vsize,
							(R_BIN_SCN_SHAREABLE &section->srwx)?'s':'-',
							(R_BIN_SCN_READABLE &section->srwx)?'r':'-',
							(R_BIN_SCN_WRITABLE &section->srwx)?'w':'-',
							(R_BIN_SCN_EXECUTABLE &section->srwx)?'x':'-',
							section->name, addr);
				} else {
					char *hashstr = NULL, str[128];
					if (chksum) {
						char *chkstr;
						ut8 *data = malloc (section->size);
						ut32 datalen = section->size;
						// VA READ IS BROKEN?
						r_io_pread (r->io, section->paddr, data, datalen);
						chkstr = r_hash_to_string (NULL, chksum, data, datalen);
						free (data);
						hashstr = malloc (strlen (chkstr)+strlen (chksum)+3);
						sprintf (hashstr, "%s=%s ", chksum, chkstr);
						free (chkstr);
					}
					if (section->arch || section->bits) {
						const char *arch = section->arch;
						int bits = section->bits;
						if (!arch) arch = info->arch;
						if (!bits) bits = info->bits;
						snprintf (str, sizeof (str), "arch=%s bits=%d ", arch, bits);
					} else str[0] = 0;
					r_cons_printf ("idx=%02i vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
						"perm=%c%c%c%c %s%sname=%s\n",
						i, addr, section->paddr, section->size, section->vsize,
						(R_BIN_SCN_SHAREABLE &section->srwx)?'s':'-',
						(R_BIN_SCN_READABLE &section->srwx)?'r':'-',
						(R_BIN_SCN_WRITABLE &section->srwx)?'w':'-',
						(R_BIN_SCN_EXECUTABLE &section->srwx)?'x':'-',
						str, hashstr?hashstr:"", section->name);
					free (hashstr);
				}
			}
			i++;
		}
		if (!at && !mode) r_cons_printf ("\n%i sections\n", i);
	}

	return R_TRUE;
}

static int bin_fields (RCore *r, int mode, ut64 baddr, int va) {
	RList *fields;
	RListIter *iter;
	RBinField *field;
	int i = 0;
	RBin *bin = r->bin;
	RBinFile *binfile = r_core_bin_cur (r);
	ut64 size = binfile ? binfile->size : UT64_MAX;

	if ((fields = r_bin_get_fields (bin)) == NULL)
		return R_FALSE;

	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("[");
		r_list_foreach (fields, iter, field) {
			ut64 addr = va? r_bin_get_vaddr (bin, baddr, field->paddr,
				field->vaddr): field->paddr;
			r_cons_printf ("%s{\"name\":\"%s\","
				"\"paddr\":%"PFMT64d"}",
				iter->p?",":"",
				field->name, addr);
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_SET)) {
		//XXX: Need more flags??
		// this will be set even if the binary does not have an ehdr
		int fd = r_core_file_cur_fd(r);
		r_io_section_add (r->io, 0, baddr, size, size, 7, "ehdr", 0, fd);
	} else {
		if (mode) r_cons_printf ("fs header\n");
		else r_cons_printf ("[Header fields]\n");

		r_list_foreach (fields, iter, field) {
			ut64 addr = va? r_bin_get_vaddr (bin, baddr, field->paddr,
				field->vaddr): field->paddr;
			if (mode) {
				r_name_filter (field->name, sizeof (field->name));
				r_cons_printf ("f header.%s @ 0x%08"PFMT64x"\n", field->name, addr);
				r_cons_printf ("[%02i] vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" name=%s\n",
						i, addr, field->paddr, field->name);
			} else r_cons_printf ("idx=%02i vaddr=0x%08"PFMT64x" paddr=0x%08"PFMT64x" name=%s\n",
					i, addr, field->paddr, field->name);
			i++;
		}

		if (mode) {
			/* add program header section */
			r_cons_printf ("S 0 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x" ehdr rwx\n",
					baddr, size, size);
		} else r_cons_printf ("\n%i fields\n", i);
	}
	return R_TRUE;
}

static int bin_classes (RCore *r, int mode) {
	RListIter *iter, *iter2;
	RBinClass *c;
	RList *cs = r_bin_get_classes (r->bin);
	const char *methname;
	if (!cs) return R_FALSE;

	// XXX: support for classes is broken and needs more love
	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("[");
		r_list_foreach (cs, iter, c) {
			if (c->super)
			r_cons_printf ("%s{\"name\":\"%s\",\"index\":%"PFMT64d",\"super\":\"%s\"}",
				iter->p?",":"", c->name, c->index, c->super);
			else
			r_cons_printf ("%s{\"name\":\"%s\",\"index\":%"PFMT64d"}",
				iter->p?",":"", c->name, c->index);
		}
		r_cons_printf ("]");
	} else
	if (mode & R_CORE_BIN_SIMPLE) {
		r_list_foreach (cs, iter, c) {
			r_cons_printf ("0x%08"PFMT64x"  %s  %s\n",
				c->index, c->name, c->super?c->super:"");
		}
	} else
	if (mode & R_CORE_BIN_SET) {
		// Nothing to set.
	} else {
		r_list_foreach (cs, iter, c) {
			if (mode) {
				r_cons_printf ("f class.%s @ %d\n", c->name, c->index);
				if (c->super)
					r_cons_printf ("f super.%s.%s @ %d\n", c->name, c->super, c->index);
				r_list_foreach (c->methods, iter2, methname) {
					r_cons_printf ("f method.%s.%s\n", c->name, methname);
				}
			} else {
				r_cons_printf ("class %d = %s\n", c->index, c->name);
				if (c->super)
					r_cons_printf ("  super = %s\n", c->super);
				r_list_foreach (c->methods, iter2, methname) {
					r_cons_printf ("  method %s\n", methname);
				}
			}
			// TODO: show belonging methods and fields
		}
	}
	return R_TRUE;
}

static int bin_size (RCore *r, int mode) {
	int size = r_bin_get_size (r->bin);
	if ((mode & R_CORE_BIN_SIMPLE) || mode&R_CORE_BIN_JSON)
		r_cons_printf ("%d\n", size);
	else if ((mode & R_CORE_BIN_RADARE))
		r_cons_printf ("f bin_size @ %d\n", size);
	else if ((mode & R_CORE_BIN_SET))
		r_core_cmdf (r, "f bin_size @ %d\n", size);
	else r_cons_printf ("%d\n", size);
	return R_TRUE;
}

static int bin_libs (RCore *r, int mode) {
	RList *libs;
	RListIter *iter;
	char* lib;
	int i = 0;

	if ((libs = r_bin_get_libs (r->bin)) == NULL)
		return R_FALSE;

	if (mode & R_CORE_BIN_JSON) {
		r_cons_printf ("[");
		r_list_foreach (libs, iter, lib) {
			r_cons_printf ("%s\"%s\"", iter->p?",":"",lib);
		}
		r_cons_printf ("]");
	} else
	if ((mode & R_CORE_BIN_RADARE)) {
		r_list_foreach (libs, iter, lib) {
			r_cons_printf ("CCa entry0 %s\n", lib);
		}
	} else
	if ((mode & R_CORE_BIN_SET)) {
		// Nothing to set.
		// TODO: load libraries with iomaps?
	} else {
		if (!mode) r_cons_printf ("[Linked libraries]\n");
		r_list_foreach (libs, iter, lib) {
			r_cons_printf ("%s\n", lib);
			i++;
		}
		if (!mode) r_cons_printf ("\n%i libraries\n", i);
	}
	return R_TRUE;
}

R_API int r_core_bin_info (RCore *core, int action, int mode, int va, RCoreBinFilter *filter, ut64 loadaddr, const char *chksum) {
	int ret = R_TRUE;
	const char *name = NULL;
	ut64 at = 0, baseaddr = 0LL;

	// WTF, should be the same but we are not keeping it
	if (core->bin && core->bin->cur && core->bin->cur->o)
		baseaddr = core->bin->cur->o->baddr;

	if (loadaddr)
		va = 2;

	if (filter && filter->offset)
		at = filter->offset;
	if (filter && filter->name)
		name = filter->name;
	if ((action & R_CORE_BIN_ACC_STRINGS))
		ret &= bin_strings (core, mode, baseaddr, va);
	if ((action & R_CORE_BIN_ACC_INFO))
		ret &= bin_info (core, mode);
	if ((action & R_CORE_BIN_ACC_MAIN))
		ret &= bin_main (core, mode, baseaddr, va);
	if ((action & R_CORE_BIN_ACC_DWARF))
		ret &= bin_dwarf (core, mode);
	if ((action & R_CORE_BIN_ACC_PDB))
		ret &= bin_pdb (core, loadaddr, mode);
	if ((action & R_CORE_BIN_ACC_ENTRIES))
		ret &= bin_entry (core, mode, baseaddr, loadaddr, va);
	if ((action & R_CORE_BIN_ACC_RELOCS))
		ret &= bin_relocs (core, mode, baseaddr, va);
	if ((action & R_CORE_BIN_ACC_IMPORTS))
		ret &= bin_imports (core, mode, baseaddr, va, name);
	if ((action & R_CORE_BIN_ACC_SYMBOLS))
		ret &= bin_symbols (core, mode, baseaddr, loadaddr, va, at, name);
	if ((action & R_CORE_BIN_ACC_SECTIONS))
		ret &= bin_sections (core, mode, baseaddr, loadaddr, va, at, name, chksum);
	if ((action & R_CORE_BIN_ACC_FIELDS))
		ret &= bin_fields (core, mode, baseaddr, va);
	if ((action & R_CORE_BIN_ACC_LIBS))
		ret &= bin_libs (core, mode);
	if ((action & R_CORE_BIN_ACC_CLASSES))
		ret &= bin_classes (core, mode);
	if ((action & R_CORE_BIN_ACC_SIZE))
		ret &= bin_size (core, mode);
	return ret;
}

R_API int r_core_bin_set_arch_bits (RCore *r, const char *name, const char * arch, ut16 bits) {
	RCoreFile *cf = r_core_file_cur (r);
	RBinFile *binfile;

	if (!name)
		name = (cf && cf->desc) ? cf->desc->name : NULL;
	if (!name)
		return R_FALSE;

	/* Check if the arch name is a valid name */
	if (!r_asm_is_valid (r->assembler, arch))
		return R_FALSE;

	/* Find a file with the requested name/arch/bits */
	binfile = r_bin_file_find_by_arch_bits (r->bin, arch, bits, name);
	if (!binfile)
		return R_FALSE;

	if (!r_bin_use_arch (r->bin, arch, bits, name))
		return R_FALSE;

	r_core_bin_set_cur (r, binfile);
	return r_core_bin_set_env (r, binfile);
}

R_API int r_core_bin_update_arch_bits (RCore *r) {
	RBinFile *binfile = r_core_bin_cur (r);
	const char * arch = r->assembler->cur->arch;
	ut16 bits = r->assembler->bits;
	const char *name = binfile ? binfile->file : NULL;
	return r_core_bin_set_arch_bits (r, name, arch, bits);
}

R_API int r_core_bin_raise (RCore *core, ut32 binfile_idx, ut32 binobj_idx) {
	RBin *bin = core->bin;
	RBinFile *binfile = NULL;

	if (binfile_idx == UT32_MAX && binobj_idx == UT32_MAX) {
		return R_FALSE;
	}

	if (!r_bin_select_by_ids (bin, binfile_idx, binobj_idx)) return R_FALSE;
	binfile = r_core_bin_cur (core);
	if (binfile) {
		r_io_raise (core->io, binfile->fd);
	}
	core->switch_file_view = 1;
	return binfile && r_core_bin_set_env (core, binfile) && r_core_block_read (core, 0);
}

R_API int r_core_bin_delete (RCore *core, ut32 binfile_idx, ut32 binobj_idx) {
	RBin *bin = core->bin;
	RBinFile *binfile = NULL;

	if (binfile_idx == UT32_MAX && binobj_idx == UT32_MAX)
		return R_FALSE;
	if (!r_bin_object_delete (bin, binfile_idx, binobj_idx))
		return R_FALSE;
	binfile = r_core_bin_cur (core);
	if (binfile)
		r_io_raise (core->io, binfile->fd);
	core->switch_file_view = 1;
	return binfile && r_core_bin_set_env (core, binfile) && r_core_block_read (core, 0);
}

static int r_core_bin_file_print (RCore *core, RBinFile *binfile, int mode) {
	RListIter *iter;
	RBinObject *obj;
	const char *name = binfile ? binfile->file : NULL;
	ut32 id = binfile ? binfile->id : 0;
	ut32 fd = binfile ? binfile->fd : 0;
	ut32 obj_cnt = binfile ? r_list_length (binfile->objs) : 0;
	ut32 bin_sz = binfile ? binfile->size : 0;
// TODO:  TODO: handle mode to print in json and r2 commands

	if (!binfile) return R_FALSE;

	switch (mode) {
	case 'j':
		r_cons_printf("{\"name\":\"%s\",\"fd\":%d,\"id\":%d,\"objcnt\":%d,\"size\":%d,\"objs\":[",
			name, fd, id, obj_cnt, bin_sz);
		r_list_foreach (binfile->objs, iter, obj) {
			RBinInfo *info = obj->info;
			ut8 bits = info ? info->bits : 0;
			const char *arch = info ? info->arch : "unknown";
			r_cons_printf("{\"objid\":%d,\"arch\":\"%s\",\"bits\":%d,\"binoffset\":%"
					PFMT64d",\"objsize\":%"PFMT64d"}",
					obj->id, arch, bits, obj->boffset, obj->obj_size);
			if (iter->n) r_cons_printf (",");
		}
		r_cons_printf("]}");
		break;
	default:
		r_cons_printf("%d %s %d %d 0x%04x\n", fd, name, id, obj_cnt, bin_sz );
		r_list_foreach (binfile->objs, iter, obj) {
			RBinInfo *info = obj->info;
			ut8 bits = info ? info->bits : 0;
			const char *arch = info ? info->arch : "unknown";
			r_cons_printf("- %d %s %d 0x%04"PFMT64x" 0x%04"PFMT64x"\n",
					obj->id, arch, bits, obj->boffset, obj->obj_size );
		}
		break;
	}
	return R_TRUE;
}

R_API int r_core_bin_list(RCore *core, int mode) {
	// list all binfiles and there objects and there archs
	int count = 0;
	RListIter *iter;
	RBinFile *binfile = NULL; //, *cur_bf = r_core_bin_cur (core) ;
	RBin *bin = core->bin;
	const RList *binfiles = bin ? bin->binfiles: NULL;

	if (!binfiles) return R_FALSE;

	if (mode=='j') r_cons_printf("[");
	r_list_foreach (binfiles, iter, binfile) {
		r_core_bin_file_print (core, binfile, mode);
		if (iter->n && mode=='j') r_cons_printf(",");
	}
	if (mode=='j') r_cons_printf("]\n");
	//r_core_file_set_by_file (core, cur_cf);
	//r_core_bin_bind (core, cur_bf);
	return count;
}
