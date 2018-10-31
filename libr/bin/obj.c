/* radare2 - LGPL - Copyright 2009-2018 - pancake, nibble, dso */

#include <r_bin.h>
#include <r_util.h>

#define bprintf if(binfile->rbin->verbose)eprintf

R_API void r_bin_object_free(void /*RBinObject*/ *o_) {
	RBinObject *o = o_;
	if (!o) {
		return;
	}
	free (o->regstate);
	r_bin_info_free (o->info);
	r_bin_object_delete_items (o);
	R_FREE (o);
}

R_API RBinObject *r_bin_object_new(RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz) {
	const ut8 *bytes = binfile? r_buf_buffer (binfile->buf): NULL;
	ut64 bytes_sz = binfile? r_buf_size (binfile->buf): 0;
	Sdb *sdb = binfile? binfile->sdb: NULL;
	RBinObject *o = R_NEW0 (RBinObject);
	if (!o) {
		return NULL;
	}
	o->obj_size = bytes && (bytes_sz >= sz + offset)? sz: 0;
	o->boffset = offset;
	o->regstate = NULL;
	if (!r_id_pool_grab_id (binfile->rbin->ids->pool, &o->id)) {
		free (o);
		return NULL;
	}
	o->kv = sdb_new0 ();
	o->baddr = baseaddr;
	o->baddr_shift = 0;
	o->plugin = plugin;
	o->loadaddr = loadaddr != UT64_MAX ? loadaddr : 0;

	if (bytes && plugin && plugin->load_buffer) {
		o->bin_obj = plugin->load_buffer (binfile, binfile->buf, loadaddr, sdb); // bytes + offset, sz, loadaddr, sdb);
		if (!o->bin_obj) {
			bprintf (
				"Error in r_bin_object_new: load_bytes failed "
				"for %s plugin\n",
				plugin->name);
			sdb_free (o->kv);
			free (o);
			return NULL;
		}
	} else if (bytes && plugin && plugin->load_bytes && (bytes_sz >= sz + offset)) {
		// XXX more checking will be needed here
		// only use LoadBytes if buffer offset != 0
		// if (offset != 0 && bytes && plugin && plugin->load_bytes && (bytes_sz
		// >= sz + offset) ) {
		ut64 bsz = bytes_sz - offset;
		if (sz < bsz) {
			bsz = sz;
		}
		if (!plugin->load_bytes (binfile, &o->bin_obj, bytes + offset, sz,
					 loadaddr, sdb)) {
			bprintf (
				"Error in r_bin_object_new: load_bytes failed "
				"for %s plugin\n",
				plugin->name);
			sdb_free (o->kv);
			free (o);
			return NULL;
		}
	} else if (binfile && plugin && plugin->load) {
		// XXX - haha, this is a hack.
		// switching out the current object for the new
		// one to be processed
		RBinObject *old_o = binfile->o;
		binfile->o = o;
		if (plugin->load (binfile)) {
			binfile->sdb_info = o->kv;
			// mark as do not walk
			sdb_ns_set (binfile->sdb, "info", o->kv);
		} else {
			binfile->o = old_o;
		}
		o->obj_size = sz;
	} else {
		sdb_free (o->kv);
		free (o);
		return NULL;
	}

	// XXX - binfile could be null here meaning an improper load
	// XXX - object size cant be set here and needs to be set where
	// where the object is created from.  The reason for this is to prevent
	// mis-reporting when the file is loaded from impartial bytes or is
	// extracted
	// from a set of bytes in the file
	r_bin_object_set_items (binfile, o);
	r_bin_file_object_add (binfile, o);

	// XXX this is a very hacky alternative to rewriting the
	// RIO stuff, as discussed here:
	return o;
}

static void filter_classes(RBinFile *bf, RList *list) {
	Sdb *db = sdb_new0 ();
	RListIter *iter, *iter2;
	RBinClass *cls;
	RBinSymbol *sym;
	r_list_foreach (list, iter, cls) {
		if (!cls->name) {
			continue;
		}
		int namepad_len = strlen (cls->name) + 32;
		char *namepad = malloc (namepad_len + 1);
		if (namepad) {
			strcpy (namepad, cls->name);
			r_bin_filter_name (bf, db, cls->index, namepad, namepad_len);
			free (cls->name);
			cls->name = namepad;
			r_list_foreach (cls->methods, iter2, sym) {
				if (sym->name) {
					r_bin_filter_sym (bf, db, sym->vaddr, sym);
				}
			}
		} else {
			eprintf ("Cannot alloc %d byte(s)\n", namepad_len);
		}
	}
	sdb_free (db);
}

R_API int r_bin_object_set_items(RBinFile *binfile, RBinObject *o) {
	RBinObject *old_o;
	RBinPlugin *cp;
	int i, minlen;
	bool isSwift = false;

	r_return_val_if_fail (binfile && o && o->plugin, false);

	RBin *bin = binfile->rbin;
	old_o = binfile->o;
	cp = o->plugin;
	minlen = (binfile->rbin->minstrlen > 0) ? binfile->rbin->minstrlen : cp->minstrlen;
	binfile->o = o;

	if (cp->file_type) {
		int type = cp->file_type (binfile);
		if (type == R_BIN_TYPE_CORE) {
			if (cp->regstate) {
				o->regstate = cp->regstate (binfile);
			}
			if (cp->maps) {
				o->maps = cp->maps (binfile);
			}
		}
	}

	if (cp->baddr) {
		ut64 old_baddr = o->baddr;
		o->baddr = cp->baddr (binfile);
		r_bin_object_set_baddr (o, old_baddr);
	}
	if (cp->boffset) {
		o->boffset = cp->boffset (binfile);
	}
	// XXX: no way to get info from xtr pluginz?
	// Note, object size can not be set from here due to potential
	// inconsistencies
	if (cp->size) {
		o->size = cp->size (binfile);
	}
	// XXX this is expensive because is O(n^n)
	if (cp->binsym) {
		for (i = 0; i < R_BIN_SYM_LAST; i++) {
			o->binsym[i] = cp->binsym (binfile, i);
			if (o->binsym[i]) {
				o->binsym[i]->paddr += o->loadaddr;
			}
		}
	}
	if (cp->entries) {
		o->entries = cp->entries (binfile);
		REBASE_PADDR (o, o->entries, RBinAddr);
	}
	if (cp->fields) {
		o->fields = cp->fields (binfile);
		if (o->fields) {
			o->fields->free = r_bin_field_free;
			REBASE_PADDR (o, o->fields, RBinField);
		}
	}
	if (cp->imports) {
		r_list_free (o->imports);
		o->imports = cp->imports (binfile);
		if (o->imports) {
			o->imports->free = r_bin_import_free;
		}
	}
	//if (bin->filter_rules & (R_BIN_REQ_SYMBOLS | R_BIN_REQ_IMPORTS))
	if (true) {
		if (cp->symbols) {
			o->symbols = cp->symbols (binfile);
			if (o->symbols) {
				o->symbols->free = r_bin_symbol_free;
				REBASE_PADDR (o, o->symbols, RBinSymbol);
				if (bin->filter) {
					r_bin_filter_symbols (binfile, o->symbols);
				}
			}
		}
	}
	o->info = cp->info? cp->info (binfile): NULL;
	if (cp->libs) {
		o->libs = cp->libs (binfile);
	}
	if (cp->sections) {
		// XXX sections are populated by call to size
		if (!o->sections) {
			o->sections = cp->sections (binfile);
		}
		REBASE_PADDR (o, o->sections, RBinSection);
		if (bin->filter) {
			r_bin_filter_sections (binfile, o->sections);
		}
	}
	if (bin->filter_rules & (R_BIN_REQ_RELOCS | R_BIN_REQ_IMPORTS)) {
		if (cp->relocs) {
			o->relocs = cp->relocs (binfile);
			REBASE_PADDR (o, o->relocs, RBinReloc);
		}
	}
	if (bin->filter_rules & R_BIN_REQ_STRINGS) {
		if (cp->strings) {
			o->strings = cp->strings (binfile);
		} else {
			o->strings = r_bin_file_get_strings (binfile, minlen, 0, binfile->rawstr);
		}
		if (bin->debase64) {
			r_bin_object_filter_strings (o);
		}
		REBASE_PADDR (o, o->strings, RBinString);
	}
	if (bin->filter_rules & R_BIN_REQ_CLASSES) {
		if (cp->classes) {
			o->classes = cp->classes (binfile);
			isSwift = r_bin_lang_swift (binfile);
			if (isSwift) {
				o->classes = r_bin_classes_from_symbols (binfile, o);
			}
		} else {
			o->classes = r_bin_classes_from_symbols (binfile, o);
		}
		if (bin->filter) {
			filter_classes (binfile, o->classes);
		}
		// cache addr=class+method
		if (o->classes) {
			RList *klasses = o->classes;
			RListIter *iter, *iter2;
			RBinClass *klass;
			RBinSymbol *method;
			if (!o->addr2klassmethod) {
				// this is slow. must be optimized, but at least its cached
				o->addr2klassmethod = sdb_new0 ();
				r_list_foreach (klasses, iter, klass) {
					r_list_foreach (klass->methods, iter2, method) {
						char *km = sdb_fmt ("method.%s.%s", klass->name, method->name);
						char *at = sdb_fmt ("0x%08"PFMT64x, method->vaddr);
						sdb_set (o->addr2klassmethod, at, km, 0);
					}
				}
			}
		}
	}
	if (cp->lines) {
		o->lines = cp->lines (binfile);
	}
	if (cp->get_sdb) {
		Sdb* new_kv = cp->get_sdb (binfile);
		if (new_kv != o->kv) {
			sdb_free (o->kv);
		}
		o->kv = new_kv;
	}
	if (cp->mem)  {
		o->mem = cp->mem (binfile);
	}
	if (bin->filter_rules & (R_BIN_REQ_SYMBOLS | R_BIN_REQ_IMPORTS)) {
		if (isSwift) {
			o->lang = R_BIN_NM_SWIFT;
		} else {
			o->lang = r_bin_load_languages (binfile);
		}
	}
	binfile->o = old_o;
	return true;
}

R_API RBinObject *r_bin_object_get_cur(RBin *bin) {
	r_return_val_if_fail (bin, NULL);
	return r_bin_file_object_get_cur (r_bin_cur (bin));
}

static void r_bin_mem_free(void *data) {
	RBinMem *mem = (RBinMem *)data;
	if (mem && mem->mirrors) {
		mem->mirrors->free = r_bin_mem_free;
		r_list_free (mem->mirrors);
		mem->mirrors = NULL;
	}
	free (mem);
}

R_API void r_bin_object_delete_items(RBinObject *o) {
	ut32 i = 0;
	r_return_if_fail (o);
	sdb_free (o->addr2klassmethod);
	r_list_free (o->entries);
	r_list_free (o->fields);
	r_list_free (o->imports);
	r_list_free (o->libs);
	r_list_free (o->relocs);
	r_list_free (o->sections);
	r_list_free (o->strings);
	r_list_free (o->symbols);
	r_list_free (o->classes);
	r_list_free (o->lines);
	sdb_free (o->kv);
	if (o->mem) {
		o->mem->free = r_bin_mem_free;
	}
	r_list_free (o->mem);
	o->mem = NULL;
	o->entries = NULL;
	o->fields = NULL;
	o->imports = NULL;
	o->libs = NULL;
	o->relocs = NULL;
	o->sections = NULL;
	o->strings = NULL;
	o->symbols = NULL;
	o->classes = NULL;
	o->lines = NULL;
	o->info = NULL;
	o->kv = NULL;
	for (i = 0; i < R_BIN_SYM_LAST; i++) {
		free (o->binsym[i]);
		o->binsym[i] = NULL;
	}
}

R_API RBinObject *r_bin_object_find_by_arch_bits(RBinFile *binfile, const char *arch, int bits, const char *name) {
	RBinObject *obj = NULL;
	RListIter *iter = NULL;

	r_return_val_if_fail (binfile && arch && name, NULL);

	r_list_foreach (binfile->objs, iter, obj) {
		RBinInfo *info = obj->info;
		if (info && info->arch && info->file &&
			(bits == info->bits) &&
			!strcmp (info->arch, arch) &&
			!strcmp (info->file, name)) {
			return obj;
		}
	}
	return NULL;
}

R_API ut64 r_bin_object_get_baddr(RBinObject *o) {
	r_return_val_if_fail (o, UT64_MAX);
	return o->baddr + o->baddr_shift;
}

R_API bool r_bin_object_delete(RBin *bin, ut32 binfile_id, ut32 binobj_id) {
	RBinFile *binfile = NULL;
	RBinObject *obj = NULL;
	bool res = false;

	r_return_val_if_fail (bin, false);

	if (binfile_id == UT32_MAX) {
		binfile = r_bin_file_find_by_object_id (bin, binobj_id);
		obj = binfile ? r_bin_file_object_find_by_id (binfile, binobj_id) : NULL;
	} else if (binobj_id == UT32_MAX) {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile ? binfile->o : NULL;
	} else {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile ? r_bin_file_object_find_by_id (binfile, binobj_id) : NULL;
	}
	if (binfile && bin->cur == binfile) {
		bin->cur = NULL;
	}

	if (binfile) {
		binfile->o = NULL;
		r_list_delete_data (binfile->objs, obj);
		RBinObject *newObj = (RBinObject *)r_list_get_n (binfile->objs, 0);
		res = newObj && binfile &&
		      r_bin_file_set_cur_binfile_obj (bin, binfile, newObj);
	}
	if (binfile && obj && r_list_length (binfile->objs) == 0) {
		r_list_delete_data (bin->binfiles, binfile);
	}
	return res;
}

R_API void r_bin_object_set_baddr(RBinObject *o, ut64 baddr) {
	r_return_if_fail (o);
	if (baddr != UT64_MAX) {
		o->baddr_shift = baddr - o->baddr;
	}
}

R_API void r_bin_object_filter_strings(RBinObject *bo) {
	r_return_if_fail (bo);

	RList *strings = bo->strings;
	RBinString *ptr;
	RListIter *iter;
	r_list_foreach (strings, iter, ptr) {
		char *dec = (char *)r_base64_decode_dyn (ptr->string, -1);
		if (dec) {
			char *s = ptr->string;
			for (;;) {
				char *dec2 = (char *)r_base64_decode_dyn (s, -1);
				if (!dec2) {
					break;
				}
				if (!r_str_is_printable (dec2)) {
					free (dec2);
					break;
				}
				free (dec);
				s = dec = dec2;
			}
			if (r_str_is_printable (dec) && strlen (dec) > 3) {
				free (ptr->string);
				ptr->string = dec;
				ptr->type = R_STRING_TYPE_BASE64;
			} else {
				free (dec);
			}
		}
	}
}
