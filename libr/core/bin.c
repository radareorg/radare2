/* radare - LGPL - Copyright 2011 earada */
#include <r_core.h>

static int bin_strings (RCore *r, int mode, ut64 baddr, int va) {
	int i = 0;
	RList *list;
	RListIter *iter;
	RBinString *string;
	RBinSection *section;
	char str[R_FLAG_NAME_SIZE];

	if ((list = r_bin_get_strings (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		if (r_config_get_i (r->config, "bin.strings"))
			r_flag_space_set (r->flags, "strings");
		r_list_foreach (list, iter, string) {
			/* Jump the withespaces before the string */
			for (i=0; *(string->string+i)==' '; i++);
			r_meta_add (r->anal->meta, R_META_TYPE_STRING, va?baddr+string->rva:string->offset,
					(va?baddr+string->rva:string->offset)+string->size, string->string+i);
			r_name_filter (string->string, 128);
			snprintf (str, R_FLAG_NAME_SIZE, "str.%s", string->string);
			r_flag_set (r->flags, str, va?baddr+string->rva:string->offset,
					string->size, 0);
		}
	} else {
		if (mode) r_cons_printf ("fs strings\n");
		else r_cons_printf ("[strings]\n");

		r_list_foreach (list, iter, string) {
			section = r_bin_get_section_at (r->bin, string->offset, 0);
			if (mode) {
				r_name_filter (string->string, sizeof (string->string));
				r_cons_printf ("f str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
						"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
						string->string, string->size, va?baddr+string->rva:string->offset,
						string->size, va?baddr+string->rva:string->offset);
			} else r_cons_printf ("addr=0x%08"PFMT64x" off=0x%08"PFMT64x" ordinal=%03"PFMT64d" "
					"sz=%"PFMT64d" section=%s string=%s\n",
					baddr+string->rva, string->offset,
					string->ordinal, string->size,
					section?section->name:"unknown", string->string);
			i++;
		}

		if (!mode) r_cons_printf ("\n%i strings\n", i);
	}
	return R_TRUE;
}

static int bin_info (RCore *r, int mode) {
	char str[R_FLAG_NAME_SIZE];
	RBinInfo *info;

	if ((info = r_bin_get_info (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		r_config_set (r->config, "file.type", info->rclass);
		r_config_set (r->config, "cfg.bigendian", info->big_endian?"true":"false");
		if (!strcmp (info->rclass, "fs")) {
			r_config_set (r->config, "asm.arch", info->arch);
			r_core_cmdf (r, "m /root %s 0", info->arch);
		} else {
			r_config_set (r->config, "asm.os", info->os);
			r_config_set (r->config, "asm.arch", info->arch);
			r_config_set (r->config, "anal.plugin", info->arch);
			snprintf (str, R_FLAG_NAME_SIZE, "%i", info->bits);
			r_config_set (r->config, "asm.bits", str);
			r_config_set (r->config, "asm.dwarf", R_BIN_DBG_STRIPPED (info->dbg_info)?"false":"true");
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
					"e anal.plugin=%s\n"
					"e asm.bits=%i\n"
					"e asm.dwarf=%s\n",
					info->rclass, r_str_bool (info->big_endian), info->os,
					info->arch, info->arch, info->bits,
					r_str_bool (R_BIN_DBG_STRIPPED (info->dbg_info)));
			}
		} else {
			// if type is 'fs' show something different?
			r_cons_printf ("[File info]\n");
			r_cons_printf ("File=%s\n"
					"Type=%s\n"
					"HasVA=%s\n"
					"RootClass=%s\n"
					"Class=%s\n"
					"Arch=%s %i\n"
					"Machine=%s\n"
					"OS=%s\n"
					"Subsystem=%s\n"
					"Big endian=%s\n"
					"Stripped=%s\n"
					"Static=%s\n"
					"Line_nums=%s\n"
					"Local_syms=%s\n"
					"Relocs=%s\n"
					"RPath=%s\n",
					info->file, info->type, r_str_bool (info->has_va),
					info->rclass, info->bclass,
					info->arch, info->bits, info->machine, info->os,
					info->subsystem, 
					r_str_bool (info->big_endian), 
					r_str_bool (R_BIN_DBG_STRIPPED (info->dbg_info)),
					r_str_bool (R_BIN_DBG_STATIC (info->dbg_info)),
					r_str_bool (R_BIN_DBG_LINENUMS (info->dbg_info)),
					r_str_bool (R_BIN_DBG_SYMS (info->dbg_info)),
					r_str_bool (R_BIN_DBG_RELOCS (info->dbg_info)),
					info->rpath);
		}
	}
	return R_TRUE;
}

static int bin_main (RCore *r, int mode, ut64 baddr, int va) {
	RBinAddr *binmain;

	if ((binmain = r_bin_get_sym (r->bin, R_BIN_SYM_MAIN)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		r_flag_space_set (r->flags, "symbols");
		r_flag_set (r->flags, "main", va? baddr+binmain->rva: binmain->offset,
				r->blocksize, 0);
	} else {
		if (mode) {
			r_cons_printf ("fs symbols\n");
			r_cons_printf ("f main @ 0x%08"PFMT64x"\n", va? baddr+binmain->rva: binmain->offset);
		} else {
			r_cons_printf ("[Main]\n");
			r_cons_printf ("addr=0x%08"PFMT64x" off=0x%08"PFMT64x"\n",
					baddr+binmain->rva, binmain->offset);
		}
	}
	return R_TRUE;
}

static int bin_entry (RCore *r, int mode, ut64 baddr, int va) {
	char str[R_FLAG_NAME_SIZE];
	RList *entries;
	RListIter *iter;
	RBinAddr *entry = NULL;
	int i = 0;

	if ((entries = r_bin_get_entries (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		r_list_foreach (entries, iter, entry) {
			snprintf (str, R_FLAG_NAME_SIZE, "entry%i", i++);
			r_flag_set (r->flags, str, va? baddr+entry->rva: entry->offset,
					r->blocksize, 0);
		}
		/* Seek to the last entry point */
		if (entry)
			r_core_seek (r, va? baddr+entry->rva: entry->offset, 0);
	} else {
		if (mode) r_cons_printf ("fs symbols\n");
		else r_cons_printf ("[Entrypoints]\n");

		r_list_foreach (entries, iter, entry) {
			if (mode) {
				r_cons_printf ("f entry%i @ 0x%08"PFMT64x"\n", i, va?baddr+entry->rva:entry->offset);
				r_cons_printf ("s entry%i\n", i);
			} else r_cons_printf ("addr=0x%08"PFMT64x" off=0x%08"PFMT64x" baddr=0x%08"PFMT64x"\n",
					baddr+entry->rva, entry->offset, baddr);
			i++;
		}

		if (!mode) r_cons_printf ("\n%i entrypoints\n", i);
	}
	return R_TRUE;
}

static int bin_relocs (RCore *r, int mode, ut64 baddr, int va) {
	char str[R_FLAG_NAME_SIZE];
	RList *relocs;
	RListIter *iter;
	RBinReloc *reloc;
	int i = 0;

	if ((relocs = r_bin_get_relocs (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		r_flag_space_set (r->flags, "relocs");
		r_list_foreach (relocs, iter, reloc) {
			snprintf (str, R_FLAG_NAME_SIZE, "reloc.%s", reloc->name);
			r_flag_set (r->flags, str, va?baddr+reloc->rva:reloc->offset,
					r->blocksize, 0);
		}
	} else {
		if (mode) {
			r_cons_printf ("fs relocs\n");
			r_list_foreach (relocs, iter, reloc) {
				r_cons_printf ("f reloc.%s @ 0x%08"PFMT64x"\n", reloc->name,
						va?baddr+reloc->rva:reloc->offset);
				i++;
			}
		} else {
			r_cons_printf ("[Relocations]\n");
			r_list_foreach (relocs, iter, reloc) {
				r_cons_printf ("sym=%02i addr=0x%08"PFMT64x" off=0x%08"PFMT64x" type=0x%08x %s\n",
					reloc->sym, baddr+reloc->rva, reloc->offset, reloc->type, reloc->name);
				i++;
			}
			r_cons_printf ("\n%i relocations\n", i);
		}
	}
	return R_TRUE;
}

static int bin_imports (RCore *r, int mode, ut64 baddr, int va, ut64 at, char *name) {
	char str[R_FLAG_NAME_SIZE];
	RList *imports;
	RListIter *iter;
	RBinImport *import;
	int i = 0;

	if ((imports = r_bin_get_imports (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		r_flag_space_set (r->flags, "imports");
		r_list_foreach (imports, iter, import) {
			r_name_filter (import->name, 128);
			snprintf (str, R_FLAG_NAME_SIZE, "imp.%s", import->name);
			if (import->size)
				if (!r_anal_fcn_add (r->anal, va?baddr+import->rva:import->offset,
						import->size, str, R_ANAL_FCN_TYPE_IMP, NULL))
					eprintf ("Cannot add function: %s (duplicated)\n", import->name);
			r_flag_set (r->flags, str, va?baddr+import->rva:import->offset,
					import->size, 0);
		}
	} else {
		if (!at) {
			if (mode) r_cons_printf ("fs imports\n");
			else r_cons_printf ("[Imports]\n");
		}

		r_list_foreach (imports, iter, import) {
			if (name && strcmp (import->name, name))
				continue;
			if (at) {
				if (baddr+import->rva == at || import->offset == at)
					r_cons_printf ("%s\n", import->name);
			} else {
				if (mode) {
					r_name_filter (import->name, sizeof (import->name));
					if (import->size)
						r_cons_printf ("af+ 0x%08"PFMT64x" %"PFMT64d" imp.%s i\n",
								va?baddr+import->rva:import->offset, import->size, import->name);
					r_cons_printf ("f imp.%s @ 0x%08"PFMT64x"\n",
							import->name, va?baddr+import->rva:import->offset);
				} else r_cons_printf ("addr=0x%08"PFMT64x" off=0x%08"PFMT64x" ordinal=%03"PFMT64d" "
						"hint=%03"PFMT64d" bind=%s type=%s name=%s\n",
						baddr+import->rva, import->offset,
						import->ordinal, import->hint,  import->bind,
						import->type, import->name);
			}
			i++;
		}
		if (!at && !mode) r_cons_printf ("\n%i imports\n", i);
	}
	return R_TRUE;
}

static int bin_symbols (RCore *r, int mode, ut64 baddr, int va, ut64 at, char *name) {
	char str[R_FLAG_NAME_SIZE];
	RList *symbols;
	RListIter *iter;
	RBinSymbol *symbol;
	int i = 0;

	if ((symbols = r_bin_get_symbols (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		char *name, *dname;
		r_flag_space_set (r->flags, "symbols");
		r_list_foreach (symbols, iter, symbol) {
			name = strdup (symbol->name);
			r_name_filter (name, 80);
			snprintf (str, R_FLAG_NAME_SIZE, "sym.%s", name);
			if (!strncmp (symbol->type,"OBJECT", 6))
				r_meta_add (r->anal->meta, R_META_TYPE_DATA,
						va? baddr+symbol->rva: symbol->offset,
						(va? baddr+symbol->rva: symbol->offset)+symbol->size, name);
			r_flag_set (r->flags, str, va? baddr+symbol->rva: symbol->offset,
					symbol->size, 0);
			dname = r_bin_demangle (r->bin, symbol->name);
			if (dname) {
				r_meta_add (r->anal->meta, R_META_TYPE_COMMENT,
						va? baddr+symbol->rva: symbol->offset,
						symbol->size, dname);
				free (dname);
			}
			free (name);
		}
	} else {
		if (!at) {
			if (mode) r_cons_printf ("fs symbols\n");
			else r_cons_printf ("[Symbols]\n");
		}

		r_list_foreach (symbols, iter, symbol) {
			if (name && strcmp (symbol->name, name))
				continue;
			if (at) {
				if ((symbol->size != 0 &&
					((baddr+symbol->rva <= at && baddr+symbol->rva+symbol->size > at) ||
						 (symbol->offset <= at && symbol->offset+symbol->size > at))) ||
							baddr+symbol->rva == at || symbol->offset == at)
					r_cons_printf ("%s\n", symbol->name);
			} else {
				if (mode) {
					char *mn = r_bin_demangle (r->bin, symbol->name);
					if (mn) {
						r_cons_printf ("s 0x%08"PFMT64x"\n\"CC %s\"\n", symbol->offset, mn);
						free (mn);
					}
					r_name_filter (symbol->name, sizeof (symbol->name));
					if (!strncmp (symbol->type,"OBJECT", 6))
						r_cons_printf ("Cd %"PFMT64d" @ 0x%08"PFMT64x"\n",
								symbol->size, va?baddr+symbol->rva:symbol->offset);
					r_cons_printf ("f sym.%s %"PFMT64d" 0x%08"PFMT64x"\n",
							symbol->name, symbol->size,
							va?baddr+symbol->rva:symbol->offset);
				} else r_cons_printf ("addr=0x%08"PFMT64x" off=0x%08"PFMT64x" ordinal=%03"PFMT64d" "
						"forwarder=%s sz=%"PFMT64d" bind=%s type=%s name=%s\n",
						baddr+symbol->rva, symbol->offset,
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

static int bin_sections (RCore *r, int mode, ut64 baddr, int va, ut64 at, char *name) {
	char str[R_FLAG_NAME_SIZE];
	RList *sections;
	RListIter *iter;
	RBinSection *section;
	int i = 0;

	if ((sections = r_bin_get_sections (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		r_flag_space_set (r->flags, "sections");
		r_list_foreach (sections, iter, section) {
			r_name_filter (section->name, 128);
			snprintf (str, R_FLAG_NAME_SIZE, "section.%s", section->name);
			r_flag_set (r->flags, str, va?baddr+section->rva:section->offset,
					section->size, 0);
			snprintf (str, R_FLAG_NAME_SIZE, "section_end.%s", section->name);
			r_flag_set (r->flags, str, section->size+(va?baddr+section->rva:section->offset),
					0, 0);
			r_io_section_add (r->io, section->offset, baddr+section->rva,
					section->size, section->vsize, section->srwx, section->name);
			snprintf (str, R_FLAG_NAME_SIZE, "[%i] va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"
					PFMT64d" vsz=%"PFMT64d" rwx=%c%c%c%c %s",
					i++, baddr+section->rva, section->offset, section->size, section->vsize,
					R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
					R_BIN_SCN_READABLE (section->srwx)?'r':'-',
					R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
					R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
					section->name);
			r_meta_add (r->anal->meta, R_META_TYPE_COMMENT, va?baddr+section->rva:section->offset,
					va?baddr+section->rva:section->offset, str);
		}
		// H -> Header fields
		{
			ut64 size = r_io_size (r->io);
			r_io_section_add (r->io, 0, baddr, size, size, 7, "ehdr");
		}
	} else {
		if (!at) {
			if (mode) r_cons_printf ("fs sections\n");
			else r_cons_printf ("[Sections]\n");
		}

		r_list_foreach (sections, iter, section) {
			if (name && strcmp (section->name, name))
				continue;
			r_name_filter (section->name, sizeof (section->name));
			if (at) {
				if ((section->size != 0 &&
							((baddr+section->rva <= at && baddr+section->rva+section->size > at) ||
							 (section->offset <= at && section->offset+section->size > at))) ||
						baddr+section->rva == at || section->offset == at)
					r_cons_printf ("%s\n", section->name);
			} else {
				if (mode) {
					r_cons_printf ("S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d\n",
							section->offset, baddr+section->rva,
							section->size, section->vsize, section->name, (int)section->srwx);
					r_cons_printf ("f section.%s %"PFMT64d" 0x%08"PFMT64x"\n",
							section->name, section->size, va?baddr+section->rva:section->offset);
					r_cons_printf ("f section_end.%s %"PFMT64d" 0x%08"PFMT64x"\n",
							section->name, (ut64)0, section->size+(va?baddr+section->rva:section->offset));
					r_cons_printf ("CC [%02i] va=0x%08"PFMT64x" pa=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
							"rwx=%c%c%c%c %s @ 0x%08"PFMT64x"\n",
							i, baddr+section->rva, section->offset, section->size, section->vsize,
							R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
							R_BIN_SCN_READABLE (section->srwx)?'r':'-',
							R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
							R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
							section->name,va?baddr+section->rva:section->offset);
				} else r_cons_printf ("idx=%02i addr=0x%08"PFMT64x" off=0x%08"PFMT64x" sz=%"PFMT64d" vsz=%"PFMT64d" "
						"perm=%c%c%c%c name=%s\n",
						i, baddr+section->rva, section->offset, section->size, section->vsize,
						R_BIN_SCN_SHAREABLE (section->srwx)?'s':'-',
						R_BIN_SCN_READABLE (section->srwx)?'r':'-',
						R_BIN_SCN_WRITABLE (section->srwx)?'w':'-',
				R_BIN_SCN_EXECUTABLE (section->srwx)?'x':'-',
				section->name);
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
	ut64 size;
	int i = 0;

	size = r->bin->curarch.size;

	if ((fields = r_bin_get_fields (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		//XXX: Need more flags??
		r_io_section_add (r->io, 0, baddr, size, size, 7, "ehdr");
	} else {
		if (mode) r_cons_printf ("fs header\n");
		else r_cons_printf ("[Header fields]\n");

		r_list_foreach (fields, iter, field) {
			if (mode) {
				r_name_filter (field->name, sizeof (field->name));
				r_cons_printf ("f header.%s @ 0x%08"PFMT64x"\n",
						field->name, va?baddr+field->rva:field->offset);
				r_cons_printf ("[%02i] addr=0x%08"PFMT64x" off=0x%08"PFMT64x" name=%s\n",
						i, baddr+field->rva, field->offset, field->name);
			} else r_cons_printf ("idx=%02i addr=0x%08"PFMT64x" off=0x%08"PFMT64x" name=%s\n",
					i, baddr+field->rva, field->offset, field->name);
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
	RList *cs;
	RBinClass *c;
	RListIter *iter;

	if ((cs = r_bin_get_classes (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		// Nothing to set.
	} else {
		r_list_foreach (cs, iter, c) {
			if (mode) {
				r_cons_printf ("f class.%s\n", c->name);
				if (c->super)
					r_cons_printf ("f super.%s.%s\n", c->name, c->super);
			} else {
				r_cons_printf ("class = %s\n", c->name);
				if (c->super)
					r_cons_printf ("  super = %s\n", c->super);
			}
			// TODO: show belonging methods and fields
		}
	}
	return R_TRUE;
}

static int bin_libs (RCore *r, int mode) {
	RList *libs;
	RListIter *iter;
	char* lib;
	int i = 0;

	if ((libs = r_bin_get_libs (r->bin)) == NULL)
		return R_FALSE;

	if ((mode & R_CORE_BIN_SET)) {
		// Nothing to set.
	} else {
		r_cons_printf ("[Linked libraries]\n");
		r_list_foreach (libs, iter, lib) {
			r_cons_printf ("%s\n", lib);
			i++;
		}
		if (!mode) r_cons_printf ("\n%i libraries\n", i);
	}
	return R_TRUE;
}

R_API int r_core_bin_info (RCore *core, int action, int mode, int va, RCoreBinFilter *filter, ut64 offset) {
	int ret = R_TRUE;
	char *name = NULL;
	ut64 at = 0;
	ut64 baddr = r_bin_get_baddr (core->bin);// + offset;


	if (filter && filter->offset)
		at = filter->offset;
	if (filter && filter->name)
		name = filter->name;

	if ((action & R_CORE_BIN_ACC_STRINGS))
		ret |= bin_strings (core, mode, baddr, va);
	if ((action & R_CORE_BIN_ACC_INFO))
		ret |= bin_info (core, mode);
	if ((action & R_CORE_BIN_ACC_MAIN))
		ret |= bin_main (core, mode, baddr, va);
	if ((action & R_CORE_BIN_ACC_ENTRIES))
		ret |= bin_entry (core, mode, baddr+offset, va);
	if ((action & R_CORE_BIN_ACC_RELOCS))
		ret |= bin_relocs (core, mode, baddr, va);
	if ((action & R_CORE_BIN_ACC_IMPORTS))
		ret |= bin_imports (core, mode, baddr+offset, va, at, name);
	if ((action & R_CORE_BIN_ACC_SYMBOLS))
		ret |= bin_symbols (core, mode, baddr+offset, va, at, name);
	if ((action & R_CORE_BIN_ACC_SECTIONS))
		ret |= bin_sections (core, mode, baddr, va, at, name);
	if ((action & R_CORE_BIN_ACC_FIELDS))
		ret |= bin_fields (core, mode, baddr, va);
	if ((action & R_CORE_BIN_ACC_LIBS))
		ret |= bin_libs (core, mode);
	if ((action & R_CORE_BIN_ACC_CLASSES))
		ret |= bin_classes (core, mode);

	return ret;
}
