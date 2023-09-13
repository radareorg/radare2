/* radare2 - LGPL - Copyright 2009-2023 - pancake, nibble, dso */

#define R_LOG_ORIGIN "bin.obj"

#include <r_bin.h>
#include <sdb/ht_su.h>
#include <r_util.h>
#include "i/private.h"

R_API void r_bin_mem_free(void *data) {
	RBinMem *mem = (RBinMem *)data;
	if (mem && mem->mirrors) {
		mem->mirrors->free = r_bin_mem_free;
		r_list_free (mem->mirrors);
		mem->mirrors = NULL;
	}
	free (mem);
}

static int reloc_cmp(void *incoming, void *in, void *user) {
	RBinReloc *_incoming = (RBinReloc *)incoming;
	RBinReloc *_in = (RBinReloc *)in;
	if (_incoming->vaddr > _in->vaddr) {
		return 1;
	}
	if (_incoming->vaddr < _in->vaddr) {
		return -1;
	}
	return 0;
}

static void object_delete_items(RBinObject *o) {
	r_return_if_fail (o);
	ut32 i = 0;
	r_strpool_free (o->pool);
	ht_up_free (o->addr2klassmethod);
	r_list_free (o->entries);
	r_list_free (o->fields);
	r_list_free (o->imports);
	r_list_free (o->libs);
	r_crbtree_free (o->relocs);
	r_list_free (o->sections);
	r_list_free (o->strings);
	ht_up_free (o->strings_db);

	if (!RVecRBinSymbol_empty (&o->symbols_vec)) {
		RVecRBinSymbol_fini (&o->symbols_vec);
		if (o->symbols) {
			o->symbols->free = NULL;
		}
	}
	r_list_free (o->symbols);

	r_list_free (o->classes);
	ht_pp_free (o->classes_ht);
	ht_pp_free (o->methods_ht);
	r_list_free (o->lines);
	sdb_free (o->kv);
	r_list_free (o->mem);
	for (i = 0; i < R_BIN_SYM_LAST; i++) {
		free (o->binsym[i]);
	}
}

R_IPI void r_bin_object_free(void /*RBinObject*/ *o_) {
	RBinObject *o = o_;
	if (o) {
		free (o->regstate);
		r_bin_info_free (o->info);
		object_delete_items (o);
		free (o);
	}
}

static char *swiftField(const char *dn, const char *cn) {
	if (!dn || !cn) {
		return NULL;
	}

	char *p = strstr (dn, ".getter_");
	if (!p) {
		p = strstr (dn, ".setter_");
		if (!p) {
			p = strstr (dn, ".method_");
		}
	}
	if (p) {
		char *q = strstr (dn, cn);
		if (q && q[strlen (cn)] == '.') {
			q = strdup (q + strlen (cn) + 1);
			char *r = strchr (q, '.');
			if (r) {
				*r = 0;
			}
			return q;
		}
	}
	return NULL;
}

static RList *classes_from_symbols(RBinFile *bf) {
	RBinSymbol *sym;
	RListIter *iter;
	r_list_foreach (bf->bo->symbols, iter, sym) {
		if (!sym->name || sym->name[0] != '_') {
			continue;
		}
		const char *cn = sym->classname;
		if (cn) {
			RBinClass *c = r_bin_file_add_class (bf, sym->classname, NULL, 0);
			if (!c) {
				continue;
			}
			// swift specific
			char *dn = sym->dname;
			char *fn = swiftField (dn, cn);
			if (fn) {
				RBinField *f = r_bin_field_new (sym->paddr, sym->vaddr, sym->size, fn, NULL, NULL, false);
				r_list_append (c->fields, f);
				free (fn);
			} else {
				char *mn = strstr (dn, "..");
				if (!mn) {
					mn = strstr (dn, cn);
					if (mn && mn[strlen (cn)] == '.') {
						RBinSymbol *dsym = r_bin_symbol_clone (sym);
						r_list_append (c->methods, dsym);
					}
				}
			}
		}
	}
	return bf->bo->classes;
}

// TODO: kill offset and sz, because those should be inferred from binfile->buf
R_IPI RBinObject *r_bin_object_new(RBinFile *bf, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz) {
	r_return_val_if_fail (bf && plugin, NULL);
	ut64 bytes_sz = r_buf_size (bf->buf);
	RBinObject *bo = R_NEW0 (RBinObject);
	if (!bo) {
		return NULL;
	}
	bo->obj_size = (bytes_sz >= sz + offset)? sz: 0;
	bo->boffset = offset;
	bo->strings_db = ht_up_new0 ();
	bo->regstate = NULL;
	bo->kv = sdb_new0 (); // XXX bf->sdb bf->bo->sdb wtf
	bo->baddr = baseaddr;
	bo->classes = r_list_newf ((RListFree)r_bin_class_free);
	bo->classes_ht = ht_pp_new0 ();
	bo->methods_ht = ht_pp_new0 ();
	bo->baddr_shift = 0;
	bo->plugin = plugin;
	bo->loadaddr = loadaddr != UT64_MAX ? loadaddr : 0;
	RVecRBinSymbol_init (&bo->symbols_vec);
	bo->pool = r_strpool_new (0);
	bf->bo = bo;

	if (plugin && plugin->load) {
		if (!plugin->load (bf, bf->buf, loadaddr)) {
			R_LOG_DEBUG ("load failed for %s plugin", plugin->meta.name);
			sdb_free (bo->kv);
			free (bo);
			bf->bo = NULL;
			return NULL;
		}
	} else {
		R_LOG_WARN ("Plugin %s should implement load method", plugin->meta.name);
		sdb_free (bo->kv);
		free (bo);
		bf->bo = NULL;
		return NULL;
	}

	// XXX - object size can't be set here and needs to be set where where
	// the object is created from. The reason for this is to prevent
	// mis-reporting when the file is loaded from impartial bytes or is
	// extracted from a set of bytes in the file
	r_bin_file_set_obj (bf->rbin, bf, bo);
	r_bin_set_baddr (bf->rbin, bo->baddr);
	r_bin_object_set_items (bf, bo);

	bf->sdb_info = bo->kv;
	Sdb *root_bin_sdb = bf->rbin->sdb;
	if (root_bin_sdb) {
		Sdb *bdb = bf->sdb; // sdb_new0 ();
		if (!sdb_ns (bdb, "info", 0)) {
			sdb_ns_set (bdb, "info", bo->kv);
		}
		sdb_ns_set (bdb, "addrinfo", bf->sdb_addrinfo);
		bo->kv = bdb;
		sdb_set (bf->sdb, "archs", "0:0:x86:32", 0); // x86??
		/* NOTE */
		/* Those refs++ are necessary because sdb_ns() doesnt rerefs all
		 * sub-namespaces */
		/* And if any namespace is referenced backwards it gets
		 * double-freed */
		// bf->sdb_info = sdb_ns (bf->sdb, "info", 1);
	//	bf->sdb_addrinfo = sdb_ns (bf->sdb, "addrinfo", 1);
	//	bf->sdb_addrinfbo->refs++;
		sdb_ns_set (root_bin_sdb, "cur", bdb); // bf->sdb);
		r_strf_var (fdns, 32, "fd.%d", bf->fd);
		sdb_ns_set (root_bin_sdb, fdns, bdb); // bf->sdb);
		bf->sdb->refs++;
	}
	return bo;
}

static void filter_classes(RBinFile *bf, RList *list) {
	HtSU *db = ht_su_new0 ();
	HtPP *ht = ht_pp_new0 ();
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
			char *p;
			strcpy (namepad, cls->name);
			p = r_bin_filter_name (bf, db, cls->index, namepad);
			if (p) {
				free (namepad);
				namepad = p;
			}
			free (cls->name);
			cls->name = namepad;
			r_list_foreach (cls->methods, iter2, sym) {
				if (sym->name) {
					r_bin_filter_sym (bf, ht, sym->vaddr, sym);
				}
			}
		}
	}
	ht_su_free (db);
	ht_pp_free (ht);
}

static RRBTree *list2rbtree(RList *relocs) {
	RRBTree *tree = r_crbtree_new (free);
	if (tree) {
		RListIter *it;
		RBinReloc *reloc;
		r_list_foreach (relocs, it, reloc) {
			r_crbtree_insert (tree, reloc, reloc_cmp, NULL);
		}
	}
	return tree;
}

static void r_bin_object_rebuild_classes_ht(RBinObject *bo) {
	ht_pp_free (bo->classes_ht);
	bo->classes_ht = ht_pp_new0 ();

	ht_pp_free (bo->methods_ht);
	bo->methods_ht = ht_pp_new0 ();

	RListIter *it, *it2;
	RBinClass *klass;
	RBinSymbol *method;
	r_list_foreach (bo->classes, it, klass) {
		if (klass->name) {
			ht_pp_insert (bo->classes_ht, klass->name, klass);

			r_list_foreach (klass->methods, it2, method) {
				char *name = r_str_newf ("%s::%s", klass->name, method->name);
				ht_pp_insert (bo->methods_ht, name, method);
				free (name);
			}
		}
	}
}

R_API int r_bin_object_set_items(RBinFile *bf, RBinObject *bo) {
	r_return_val_if_fail (bf && bo && bo->plugin, false);

	int i;
	bool isSwift = false;
	RBin *bin = bf->rbin;
	RBinPlugin *p = bo->plugin;
	int minlen = (bf->rbin->minstrlen > 0) ? bf->rbin->minstrlen : p->minstrlen;
	bf->bo = bo;

	bo->info = p->info? p->info (bf): NULL;
	if (bo->info->type) {
		if (strstr (bo->info->type, "CORE")) {
			if (p->regstate) {
				bo->regstate = p->regstate (bf);
			}
			if (p->maps) {
				bo->maps = p->maps (bf);
			}
		}
	}
	// XXX: no way to get info from xtr pluginz?
	// Note, object size can not be set from here due to potential
	// inconsistencies
	if (p->size) {
		bo->size = p->size (bf);
	}
	// XXX this is expensive because is O(n^n)
	if (p->binsym) {
		for (i = 0; i < R_BIN_SYM_LAST; i++) {
			bo->binsym[i] = p->binsym (bf, i);
			if (bo->binsym[i]) {
				bo->binsym[i]->paddr += bo->loadaddr;
			}
		}
	}
	if (p->entries) {
		bo->entries = p->entries (bf);
		REBASE_PADDR (bo, bo->entries, RBinAddr);
	}
	if (p->fields) {
		bo->fields = p->fields (bf);
		if (bo->fields) {
			bo->fields->free = r_bin_field_free;
			REBASE_PADDR (bo, bo->fields, RBinField);
		}
	}
	if (p->imports) {
		r_list_free (bo->imports);
		bo->imports = p->imports (bf);
		if (bo->imports) {
			bo->imports->free = (RListFree)r_bin_import_free;
		}
	}
	if (p->symbols_vec) {
		p->symbols_vec (bf);
		RBinSymbol *sym;
		HtPP *ht = ht_pp_new0 ();
		if (ht) {
			R_VEC_FOREACH (&bo->symbols_vec, sym) {
				r_bin_filter_sym (bf, ht, sym->vaddr, sym);
			}
			ht_pp_free (ht);
		}
	} else if (p->symbols) {
		bo->symbols = p->symbols (bf); // 5s
		if (bo->symbols) {
			bo->symbols->free = r_bin_symbol_free;
			REBASE_PADDR (bo, bo->symbols, RBinSymbol);
			if (bin->filter) {
				r_bin_filter_symbols (bf, bo->symbols); // 5s
			}
		}
	}
	if (p->libs) {
		bo->libs = p->libs (bf);
	}
	if (p->sections) {
		// XXX sections are populated by call to size
		if (!bo->sections) {
			bo->sections = p->sections (bf);
		}
		REBASE_PADDR (bo, bo->sections, RBinSection);
		if (bin->filter) {
			r_bin_filter_sections (bf, bo->sections);
		}
	}
	if (bin->filter_rules & (R_BIN_REQ_RELOCS | R_BIN_REQ_IMPORTS)) {
		if (p->relocs) {
			RList *l = p->relocs (bf);
			if (l) {
				REBASE_PADDR (bo, l, RBinReloc);
				bo->relocs = list2rbtree (l);
				l->free = NULL;
				r_list_free (l);
			}
		}
	}
	if (bin->filter_rules & R_BIN_REQ_STRINGS) {
		bo->strings = p->strings
			? p->strings (bf)
			: r_bin_file_get_strings (bf, minlen, 0, bf->rawstr);
		if (bin->debase64) {
			r_bin_object_filter_strings (bo);
		}
		REBASE_PADDR (bo, bo->strings, RBinString);
	}
	if (bin->filter_rules & R_BIN_REQ_CLASSES) {
		if (p->classes) {
			RList *classes = p->classes (bf);
			if (classes) {
				// XXX we should probably merge them instead
				r_list_free (bo->classes);
				bo->classes = classes;
				r_bin_object_rebuild_classes_ht (bo);
			}
			isSwift = r_bin_lang_swift (bf);
			if (isSwift) {
				bo->classes = classes_from_symbols (bf);
			}
		} else {
			RList *classes = classes_from_symbols (bf);
			if (classes) {
				bo->classes = classes;
			}
		}
		if (bin->filter) {
			filter_classes (bf, bo->classes);
		}
		// cache addr=class+method
		if (bo->classes) {
			RList *klasses = bo->classes;
			RListIter *iter, *iter2;
			RBinClass *klass;
			RBinSymbol *method;
			if (!bo->addr2klassmethod) {
				// this is slow. must be optimized, but at least its cached
				bo->addr2klassmethod = ht_up_new0 ();
				r_list_foreach (klasses, iter, klass) {
					r_list_foreach (klass->methods, iter2, method) {
						ht_up_insert (bo->addr2klassmethod, method->vaddr, method);
					}
				}
			}
		}
	}
	if (p->lines) {
		bo->lines = p->lines (bf);
	}
	if (p->get_sdb) {
		Sdb* new_kv = p->get_sdb (bf);
		if (new_kv != bo->kv) {
			sdb_free (bo->kv);
		}
		bo->kv = new_kv;
	}
	if (p->mem)  {
		bo->mem = p->mem (bf);
	}
	if (bo->info && bin->filter_rules & (R_BIN_REQ_INFO | R_BIN_REQ_SYMBOLS | R_BIN_REQ_IMPORTS)) {
		bo->lang = isSwift? R_BIN_LANG_SWIFT: r_bin_load_languages (bf);
	}
	return true;
}

R_IPI RRBTree *r_bin_object_patch_relocs(RBinFile *bf, RBinObject *bo) {
	r_return_val_if_fail (bf && bo, NULL);

	if (!bo->is_reloc_patched && bo->plugin && bo->plugin->patch_relocs) {
		RList *tmp = bo->plugin->patch_relocs (bf);
		if (R_LIKELY (tmp)) {
			r_crbtree_free (bo->relocs);
			REBASE_PADDR (bo, tmp, RBinReloc);
			bo->relocs = list2rbtree (tmp);
			bo->is_reloc_patched = true;
			tmp->free = NULL;
			r_list_free (tmp);
		}
	}
	return bo->relocs;
}

R_IPI RBinObject *r_bin_object_get_cur(RBin *bin) {
	r_return_val_if_fail (bin && bin->cur, NULL);
	return bin->cur->bo;
}

R_IPI RBinObject *r_bin_object_find_by_arch_bits(RBinFile *bf, const char *arch, int bits, const char *name) {
	r_return_val_if_fail (bf && arch && name, NULL);
	if (bf->bo) {
		RBinInfo *info = bf->bo->info;
		if (info && info->arch && info->file &&
				(bits == info->bits) &&
				!strcmp (info->arch, arch) &&
				!strcmp (info->file, name)) {
			return bf->bo;
		}
	}
	return NULL;
}

R_API bool r_bin_object_delete(RBin *bin, ut32 bf_id) {
	r_return_val_if_fail (bin, false);

	bool res = false;
	RBinFile *bf = r_bin_file_find_by_id (bin, bf_id);
	if (bf) {
		if (bin->cur == bf) {
			bin->cur = NULL;
		}
		// wtf
		if (!bf->bo) {
			r_list_delete_data (bin->binfiles, bf);
		}
	}
	return res;
}

R_IPI void r_bin_object_filter_strings(RBinObject *bo) {
	r_return_if_fail (bo && bo->strings);

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
