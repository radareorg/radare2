/* radare - LGPL - Copyright 2009-2017 - pancake, nibble, dso */

// TODO: dlopen library and show address

#include <r_bin.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_io.h>
#include <config.h>

R_LIB_VERSION (r_bin);

#define bprintf if(binfile->rbin->verbose)eprintf
#define DB a->sdb;
#define RBINLISTFREE(x)\
	if (x) { \
		r_list_free (x);\
		x = NULL;\
	}
#define REBASE_PADDR(o, l, type_t)\
	do { \
		RListIter *_it;\
		type_t *_el;\
		r_list_foreach ((l), _it, _el) { \
			_el->paddr += (o)->loadaddr;\
		}\
	} while (0)

#define ARCHS_KEY "archs"

#if !defined(R_BIN_STATIC_PLUGINS)
#define R_BIN_STATIC_PLUGINS 0
#endif
#if !defined(R_BIN_XTR_STATIC_PLUGINS)
#define R_BIN_XTR_STATIC_PLUGINS 0
#endif

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS, NULL };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS, NULL };

static int is_data_section(RBinFile *a, RBinSection *s);
static RList *get_strings(RBinFile *a, int min, int dump);
static void r_bin_object_delete_items(RBinObject *o);
static void r_bin_object_free(void /*RBinObject*/ *o_);
// static int r_bin_object_set_items(RBinFile *binfile, RBinObject *o);
static int r_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);
//static int remove_bin_file_by_binfile (RBin *bin, RBinFile * binfile);
//static void r_bin_free_bin_files (RBin *bin);
static void r_bin_file_free(void /*RBinFile*/ *bf_);
static RBinFile *r_bin_file_create_append(RBin *bin, const char *file,
					   const ut8 *bytes, ut64 sz,
					   ut64 file_sz, int rawstr, int fd,
					   const char *xtrname, bool steal_ptr);

static RBinFile *r_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr,
					    const char *filename,
					    const ut8 *bytes, ut64 sz,
					    ut64 file_sz, ut64 baseaddr,
					    ut64 loadaddr, int idx, int fd,
					    int rawstr);

int r_bin_load_io_at_offset_as_sz(RBin *bin, int fd, ut64 baseaddr,
				   ut64 loadaddr, int xtr_idx, ut64 offset,
				   const char *name, ut64 sz);

static RBinPlugin *r_bin_get_binplugin_by_name(RBin *bin, const char *name);
static RBinXtrPlugin *r_bin_get_xtrplugin_by_name(RBin *bin, const char *name);
static RBinPlugin *r_bin_get_binplugin_any(RBin *bin);

static RBinObject *r_bin_object_new(RBinFile *binfile, RBinPlugin *plugin,
				     ut64 baseaddr, ut64 loadaddr, ut64 offset,
				     ut64 sz);

static RBinFile *r_bin_file_new(RBin *bin, const char *file, const ut8 *bytes,
				 ut64 sz, ut64 file_sz, int rawstr, int fd,
				 const char *xtrname, Sdb *sdb, bool steal_ptr);

static RBinFile *r_bin_file_new_from_bytes(RBin *bin, const char *file,
					    const ut8 *bytes, ut64 sz,
					    ut64 file_sz, int rawstr,
					    ut64 baseaddr, ut64 loadaddr,
					    int fd, const char *pluginname,
					    const char *xtrname, ut64 offset,
					    bool steal_ptr);

static int getoffset(RBin *bin, int type, int idx) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_offset) {
		return plugin->get_offset (a, type, idx);
	}
	return -1;
}

static const char *getname(RBin *bin, int type, int idx) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (plugin && plugin->get_name) {
		return plugin->get_name (a, type, idx);
	}
	return NULL;
}
static int r_bin_file_object_add(RBinFile *binfile, RBinObject *o) {
	if (!o) {
		return false;
	}
	r_list_append (binfile->objs, o);
	r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, o);
	return true;
}

static void binobj_set_baddr(RBinObject *o, ut64 baddr) {
	if (!o || baddr == UT64_MAX) {
		return;
	}
	o->baddr_shift = baddr - o->baddr;
}

static ut64 binobj_a2b(RBinObject *o, ut64 addr) {
	return addr + (o? o->baddr_shift: 0);
}

static void filterStrings (RBin *bin, RList *strings) {
	RBinString *ptr;
	RListIter *iter;
	r_list_foreach (strings, iter, ptr) {
		char *dec = (char *)r_base64_decode_dyn (ptr->string, -1);
		if (dec) {
			char *s = ptr->string;
			do {
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
			} while (true);
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

R_API void r_bin_iobind(RBin *bin, RIO *io) {
	r_io_bind (io, &bin->iob);
}

// TODO: move these two function do a different file
R_API RBinXtrData *r_bin_xtrdata_new(RBuffer *buf, ut64 offset, ut64 size,
				      ut32 file_count,
				      RBinXtrMetadata *metadata) {
	RBinXtrData *data = R_NEW0 (RBinXtrData);
	if (!data) {
		return NULL;
	}
	data->offset = offset;
	data->size = size;
	data->file_count = file_count;
	data->metadata = metadata;
	data->loaded = 0;
	data->buffer = malloc (size + 1);
	if (!data->buffer) {
		free (data);
		return NULL;
	}
	memcpy (data->buffer, r_buf_buffer (buf), size);
	data->buffer[size] = 0;
	return data;
}

R_API const char *r_bin_string_type (int type) {
	switch (type) {
	case 'a': return "ascii";
	case 'u': return "utf8";
	case 'w': return "utf16le";
	case 'W': return "utf32le";
	case 'b': return "base64";
	}
	return "ascii"; // XXX
}

R_API void r_bin_xtrdata_free(void /*RBinXtrData*/ *data_) {
	RBinXtrData *data = data_;
	if (data) {
		if (data->metadata) {
			free (data->metadata->libname);
			free (data->metadata->arch);
			free (data->metadata->machine);
			free (data->metadata);
		}
		free (data->file);
		free (data->buffer);
		free (data);
	}
}

R_API RBinObject *r_bin_file_object_get_cur(RBinFile *binfile) {
	return binfile? binfile->o: NULL;
}

R_API RBinObject *r_bin_object_get_cur(RBin *bin) {
	return bin
		? r_bin_file_object_get_cur (r_bin_cur (bin))
		: NULL;
}

R_API RBinPlugin *r_bin_file_cur_plugin(RBinFile *binfile) {
	return binfile && binfile->o? binfile->o->plugin: NULL;
}

R_API int r_bin_file_cur_set_plugin(RBinFile *binfile, RBinPlugin *plugin) {
	if (binfile && binfile->o) {
		binfile->o->plugin = plugin;
		return true;
	}
	return false;
}

// maybe too big sometimes? 2KB of stack eaten here..
#define R_STRING_SCAN_BUFFER_SIZE 2048

static int string_scan_range(RList *list, const ut8 *buf, int min,
			      const ut64 from, const ut64 to, int type) {
	ut8 tmp[R_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = R_STRING_TYPE_DETECT;

	if (type == -1) {
		type = R_STRING_TYPE_DETECT;
	}
	if (!buf || !min) {
		return -1;
	}
	while (needle < to) {
		rc = r_utf8_decode (buf + needle, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}

		if (type == R_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc;
			if ((to - needle) > 4) {
				bool is_wide32 = needle + rc + 2 < to && !w[0] && !w[1] && !w[2] && w[3] && !w[4];
				if (is_wide32) {
					str_type = R_STRING_TYPE_WIDE32;
				} else {
					bool is_wide = needle + rc + 2 < to && !w[0] && w[1] && !w[2];
					str_type = is_wide? R_STRING_TYPE_WIDE: R_STRING_TYPE_ASCII;
				}
			} else {
				str_type = R_STRING_TYPE_ASCII;
			}
		} else {
			str_type = type;
		}


		runes = 0;
		str_start = needle;

		/* Eat a whole C string */
		for (rc = i = 0; i < sizeof (tmp) - 3 && needle < to; i += rc) {
			RRune r = {0};

			if (str_type == R_STRING_TYPE_WIDE32) {
				rc = r_utf32le_decode (buf + needle, to - needle, &r);
				if (rc) {
					rc = 4;
				}
			} else if (str_type == R_STRING_TYPE_WIDE) {
				rc = r_utf16le_decode (buf + needle, to - needle, &r);
				if (rc == 1) {
					rc = 2;
				}
			} else {
				rc = r_utf8_decode (buf + needle, to - needle, &r);
				if (rc > 1) {
					str_type = R_STRING_TYPE_UTF8;
				}
			}

			/* Invalid sequence detected */
			if (!rc) {
				needle++;
				break;
			}

			needle += rc;

			if (r_isprint (r)) {
				if (str_type == R_STRING_TYPE_WIDE32) {
					if (r == 0xff) {
						r = 0;
					}
				}
				rc = r_utf8_encode (&tmp[i], r);
				runes++;
				/* Print the escape code */
			} else if (r && r < 0x100 && strchr ("\b\v\f\n\r\t\a\e", (char)r)) {
				if ((i + 32) < sizeof (tmp) && r < 28) {
					tmp[i + 0] = '\\';
					tmp[i + 1] = "       abtnvfr             e"[r];
				} else {
					// string too long
					break;
				}
				rc = 2;
				runes++;
			} else {
				/* \0 marks the end of C-strings */
				break;
			}
		}

		tmp[i++] = '\0';

		if (runes >= min) {
			if (str_type == R_STRING_TYPE_ASCII) {
				// reduce false positives
				int j;
				for (j = 0; j < i; j++) {
					char ch = tmp[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE (tmp[j])) {
							continue;
						}
					}
				}
			}
			if (list) {
				RBinString *new = R_NEW0 (RBinString);
				if (!new) {
					break;
				}
				new->type = str_type;
				new->length = runes;
				new->size = needle - str_start;
				new->ordinal = count++;
				// TODO: move into adjust_offset
				switch (str_type) {
				case R_STRING_TYPE_WIDE:
					{
						const ut8 *p = buf  + str_start - 2;
						if (p[0] == 0xff && p[1] == 0xfe) {
							str_start -= 2; // \xff\xfe
						}
					}
					break;
				case R_STRING_TYPE_WIDE32:
					{
						const ut8 *p = buf  + str_start - 4;
						if (p[0] == 0xff && p[1] == 0xfe) {
							str_start -= 4; // \xff\xfe\x00\x00
						}
					}
					break;
				}
				new->paddr = new->vaddr = str_start;
				new->string = r_str_ndup ((const char *)tmp, i);
				r_list_append (list, new);
			} else {
				// DUMP TO STDOUT. raw dumping for rabin2 -zzz
				printf ("0x%08" PFMT64x " %s\n", str_start, tmp);
			}
		}
	}
	return count;
}

static void get_strings_range(RBinFile *arch, RList *list, int min, ut64 from, ut64 to) {
	RBinPlugin *plugin = r_bin_file_cur_plugin (arch);
	RBinString *ptr;
	RListIter *it;

	if (!arch || !arch->buf || !arch->buf->buf) {
		return;
	}
	if (!arch->rawstr) {
		if (!plugin || !plugin->info) {
			return;
		}
	}
	if (!min) {
		min = plugin? plugin->minstrlen: 4;
	}
	/* Some plugins return zero, fix it up */
	if (!min) {
		min = 4;
	}
	if (min < 0) {
		return;
	}
	if (!to || to > arch->buf->length) {
		to = arch->buf->length;
	}
	if (arch->rawstr != 2) {
		ut64 size = to - from;
		// in case of dump ignore here
		if (arch->rbin->maxstrbuf && size && size > arch->rbin->maxstrbuf) {
			if (arch->rbin->verbose) {
				eprintf ("WARNING: bin_strings buffer is too big "
					"(0x%08" PFMT64x
					")."
					" Use -zzz or set bin.maxstrbuf "
					"(RABIN2_MAXSTRBUF) in r2 (rabin2)\n",
					size);
			}
			return;
		}
	}
	if (string_scan_range (list, arch->buf->buf, min, from, to, -1) < 0) {
		return;
	}
	r_list_foreach (list, it, ptr) {
		RBinSection *s = r_bin_get_section_at (arch->o, ptr->paddr, false);
		if (s) {
			ptr->vaddr = s->vaddr + (ptr->paddr - s->paddr);
		}
	}
}

static int is_data_section(RBinFile *a, RBinSection *s) {
	if (s->has_strings) {
		return true;
	}
	if (s->is_data) {
		return true;
	}
 	// Rust
	return (strstr (s->name, "_const") != NULL);
}

static RList *get_strings(RBinFile *a, int min, int dump) {
	RListIter *iter;
	RBinSection *section;
	RBinObject *o = a? a->o: NULL;
	RList *ret;

	if (!o) {
		return NULL;
	}
	if (dump) {
		/* dump to stdout, not stored in list */
		ret = NULL;
	} else {
		ret = r_list_newf (r_bin_string_free);
		if (!ret) {
			return NULL;
		}
	}
	if (o->sections && !r_list_empty (o->sections) && !a->rawstr) {
		r_list_foreach (o->sections, iter, section) {
			if (is_data_section (a, section)) {
				get_strings_range (a, ret, min, section->paddr,
						section->paddr + section->size);
			}
		}
		r_list_foreach (o->sections, iter, section) {
			RBinString *s;
			RListIter *iter2;
			/* load objc/swift strings */
			const int bits = (a->o && a->o->info) ? a->o->info->bits : 32;
			const int cfstr_size = (bits == 64) ? 32 : 16;
			const int cfstr_offs = (bits == 64) ? 16 :  8;
			if (strstr (section->name, "__cfstring")) {
				int i;
// XXX do not walk if bin.strings == 0
				ut8 *p;
				for (i = 0; i < section->size; i += cfstr_size) {
					ut8 buf[32];
					if (!r_buf_read_at (
						    a->buf, section->paddr + i + cfstr_offs,
						    buf, sizeof (buf))) {
						break;
					}
					p = buf;
					ut64 cfstr_vaddr = section->vaddr + i;
					ut64 cstr_vaddr = (bits == 64)
								   ? r_read_le64 (p)
								   : r_read_le32 (p);
					r_list_foreach (ret, iter2, s) {
						if (s->vaddr == cstr_vaddr) {
							RBinString *new = R_NEW0 (RBinString);
							new->type = s->type;
							new->length = s->length;
							new->size = s->size;
							new->ordinal = s->ordinal;
							new->paddr = new->vaddr = cfstr_vaddr;
							new->string = r_str_newf ("cstr.%s", s->string);
							r_list_append (ret, new);
							break;
						}
					}
				}
			}
		}
	} else {
		get_strings_range (a, ret, min, 0, a->size);
	}
	return ret;
}

R_API RList* r_bin_raw_strings(RBinFile *a, int min) {
	RList *l = NULL;
	if (a) {
		int tmp = a->rawstr;
		a->rawstr = 2;
		l = get_strings (a, min, 0);
		a->rawstr = tmp;
	}
	return l;
}

R_API int r_bin_dump_strings(RBinFile *a, int min) {
	get_strings (a, min, 1);
	return 0;
}

/* This is very slow if there are lot of symbols */
R_API int r_bin_load_languages(RBinFile *binfile) {
	if (r_bin_lang_rust (binfile)) {
		return R_BIN_NM_RUST;
	}
	if (r_bin_lang_swift (binfile)) {
		return R_BIN_NM_SWIFT;
	}
	if (r_bin_lang_objc (binfile)) {
		return R_BIN_NM_OBJC;
	}
	if (r_bin_lang_cxx (binfile)) {
		return R_BIN_NM_CXX;
	}
	if (r_bin_lang_dlang (binfile)) {
		return R_BIN_NM_DLANG;
	}
	if (r_bin_lang_msvc (binfile)) {
		return R_BIN_NM_MSVC;
	}
	return R_BIN_NM_NONE;
}

static void mem_free(void *data) {
	RBinMem *mem = (RBinMem *)data;
	if (mem && mem->mirrors) {
		mem->mirrors->free = mem_free;
		r_list_free (mem->mirrors);
		mem->mirrors = NULL;
	}
	free (mem);
}

static void r_bin_object_delete_items(RBinObject *o) {
	ut32 i = 0;
	if (!o) {
		return;
	}
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
		o->mem->free = mem_free;
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

R_API void r_bin_info_free(RBinInfo *rb) {
	if (!rb) {
		return;
	}
	free (rb->intrp);
	free (rb->file);
	free (rb->type);
	free (rb->bclass);
	free (rb->rclass);
	free (rb->arch);
	free (rb->cpu);
	free (rb->machine);
	free (rb->os);
	free (rb->subsystem);
	free (rb->rpath);
	free (rb->guid);
	free (rb->debug_file_name);
	free (rb);
}

R_API void r_bin_import_free(void *_imp) {
	RBinImport *imp = (RBinImport *)_imp;
	if (imp) {
		R_FREE (imp->name);
		R_FREE (imp->classname);
		R_FREE (imp->descriptor);
		free (imp);
	}
}

R_API void r_bin_symbol_free(void *_sym) {
	RBinSymbol *sym = (RBinSymbol *)_sym;
	free (sym->name);
	free (sym->classname);
	free (sym);
}

R_API void r_bin_string_free(void *_str) {
	RBinString *str = (RBinString *)_str;
	free (str->string);
	free (str);
}

static void r_bin_object_free(void /*RBinObject*/ *o_) {
	RBinObject *o = o_;
	if (!o) {
		return;
	}
	r_bin_info_free (o->info);
	r_bin_object_delete_items (o);
	R_FREE (o);
}

static char *swiftField(const char *dn, const char *cn) {
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

R_API RList *r_bin_classes_from_symbols (RBinFile *bf, RBinObject *o) {
	RBinSymbol *sym;
	RListIter *iter;
	RList *symbols = o->symbols;
	RList *classes = o->classes;
	if (!classes) {
		classes = r_list_newf ((RListFree)r_bin_class_free);
	}
	r_list_foreach (symbols, iter, sym) {
		if (sym->name[0] != '_') {
			continue;
		}
		const char *cn = sym->classname;
		if (cn) {
			RBinClass *c = r_bin_class_new (bf, sym->classname, NULL, 0);
			if (!c) {
				continue;
			}
			// swift specific
			char *dn = sym->dname;
			char *fn = swiftField (dn, cn);
			if (fn) {
				// eprintf ("FIELD %s  %s\n", cn, fn);
				RBinField *f = r_bin_field_new (sym->paddr, sym->vaddr, sym->size, fn, NULL, NULL);
				r_list_append (c->fields, f);
				free (fn);
			} else {
				char *mn = strstr (dn, "..");
				if (mn) {
					// eprintf ("META %s  %s\n", sym->classname, mn);
				} else {
					char *mn = strstr (dn, cn);
					if (mn && mn[strlen(cn)] == '.') {
						mn += strlen (cn) + 1;
						// eprintf ("METHOD %s  %s\n", sym->classname, mn);
						r_list_append (c->methods, sym);
					}
				}
			}
		}
	}
	if (r_list_empty (classes)) {
		r_list_free (classes);
		return NULL;
	}
	return classes;
}

// XXX - change this to RBinObject instead of RBinFile
// makes no sense to pass in a binfile and set the RBinObject
// kinda a clunky functions
R_API int r_bin_object_set_items(RBinFile *binfile, RBinObject *o) {
	RBinObject *old_o;
	RBinPlugin *cp;
	int i, minlen;
	RBin *bin;
	if (!binfile || !o || !o->plugin) {
		return false;
	}
	bin = binfile->rbin;
	old_o = binfile->o;
	cp = o->plugin;
	if (binfile->rbin->minstrlen > 0) {
		minlen = binfile->rbin->minstrlen;
	} else {
		minlen = cp->minstrlen;
	}
	binfile->o = o;
	if (cp->baddr) {
		ut64 old_baddr = o->baddr;
		o->baddr = cp->baddr (binfile);
		binobj_set_baddr (o, old_baddr);
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
	//if (bin->filter_rules & (R_BIN_REQ_SYMBOLS | R_BIN_REQ_IMPORTS)) {
	if (true) {
		if (cp->symbols) {
			o->symbols = cp->symbols (binfile);
			if (o->symbols) {
				o->symbols->free = r_bin_symbol_free;
				REBASE_PADDR (o, o->symbols, RBinSymbol);
				if (bin->filter) {
					r_bin_filter_symbols (o->symbols);
				}
			}
		}
	}
	//}
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
			r_bin_filter_sections (o->sections);
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
			o->strings = get_strings (binfile, minlen, 0);
		}
		if (bin->debase64) {
			filterStrings (bin, o->strings);
		}
		REBASE_PADDR (o, o->strings, RBinString);
	}
	if (bin->filter_rules & R_BIN_REQ_CLASSES) {
		if (cp->classes) {
			o->classes = cp->classes (binfile);
			if (r_bin_lang_swift (binfile)) {
				o->classes = r_bin_classes_from_symbols (binfile, o);
			}
		} else {
			o->classes = r_bin_classes_from_symbols (binfile, o);
		}
		if (bin->filter) {
			r_bin_filter_classes (o->classes);
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
		o->lang = r_bin_load_languages (binfile);
	}
	binfile->o = old_o;
	return true;
}

// XXX - this is a rather hacky way to do things, there may need to be a better
// way.
R_API int r_bin_load(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int xtr_idx, int fd, int rawstr) {
	if (!bin) {
		return false;
	}
	// ALIAS?	return r_bin_load_as (bin, file, baseaddr, loadaddr,
	// xtr_idx, fd, rawstr, 0, file);
	RIOBind *iob = &(bin->iob);
	if (!iob) {
		return false;
	}
	if (!iob->io) {
		iob->io = r_io_new ();	//wtf
		if (!iob->io) {
			return false;
		}
		bin->io_owned = true;
		r_io_bind (iob->io, &bin->iob);		//memleak?
		iob = &bin->iob;
	}
	if (!iob->desc_get (iob->io, fd)) {
		fd = iob->fd_open (iob->io, file, R_IO_READ, 0644);
	}
	bin->rawstr = rawstr;
	// Use the current RIODesc otherwise r_io_map_select can swap them later on
	if (fd < 0) {
		r_io_free (iob->io);
		memset (&bin->iob, 0, sizeof (bin->iob));
		bin->io_owned = false;
		return false;
	}
	//Use the current RIODesc otherwise r_io_map_select can swap them later on
	return r_bin_load_io (bin, fd, baseaddr, loadaddr, xtr_idx);
}

R_API int r_bin_load_as(RBin *bin, const char *file, ut64 baseaddr,
			 ut64 loadaddr, int xtr_idx, int fd, int rawstr,
			 int fileoffset, const char *name) {
	RIOBind *iob = &(bin->iob);
	if (!iob || !iob->io) {
		return false;
	}
	if (fd < 0) {
		fd = iob->fd_open (iob->io, file, R_IO_READ, 0644);
	}
	if (fd < 0) {
		return false;
	}
	return r_bin_load_io_at_offset_as (bin, fd, baseaddr, loadaddr,
						  xtr_idx, fileoffset, name);
}

R_API int r_bin_reload(RBin *bin, int fd, ut64 baseaddr) {
	RIOBind *iob = &(bin->iob);
	RList *the_obj_list;
	int res = false;
	RBinFile *bf = NULL;
	ut8 *buf_bytes = NULL;
	ut64 sz = UT64_MAX;

	if (!iob || !iob->io) {
		return false;
	}
	const char *name = iob->fd_get_name (iob->io, fd);
	bf = r_bin_file_find_by_name (bin, name);
	if (!bf) {
		return false;
	}
	the_obj_list = bf->objs;
	bf->objs = r_list_newf ((RListFree)r_bin_object_free);
	// invalidate current object reference
	bf->o = NULL;

	sz = iob->fd_size (iob->io, fd);
	if (sz == UT64_MAX || sz > (64 * 1024 * 1024)) { 
		// too big, probably wrong
		eprintf ("Too big\n");
		return false;
	}
	if (sz == UT64_MAX && iob->fd_is_dbg (iob->io, fd)) {
		// attempt a local open and read
		// This happens when a plugin like debugger does not have a
		// fixed size.
		// if there is no fixed size or its MAXED, there is no way to
		// definitively
		// load the bin-properly.  Many of the plugins require all
		// content and are not
		// stream based loaders
		int tfd = iob->fd_open (iob->io, name, R_IO_READ, 0);
		if (tfd < 0) {
			return false;
		}
		sz = iob->fd_size (iob->io, tfd);
		if (sz == UT64_MAX) {
			iob->fd_close (iob->io, tfd);
			return false;
		}
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			iob->fd_close (iob->io, tfd);
			return false;
		}
		if (!iob->read_at (iob->io, 0LL, buf_bytes, sz)) {
			free (buf_bytes);
			iob->fd_close (iob->io, tfd);
			return false;
		}
		iob->fd_close (iob->io, tfd);
	} else {
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			return false;
		}
		if (!iob->fd_read_at (iob->io, fd, 0LL, buf_bytes, sz)) {
			free (buf_bytes);
			return false;
		}
	}

	bool yes_plz_steal_ptr = true;
	r_bin_file_set_bytes (bf, buf_bytes, sz, yes_plz_steal_ptr);

	if (r_list_length (the_obj_list) == 1) {
		RBinObject *old_o = (RBinObject *)r_list_get_n (the_obj_list, 0);
		res = r_bin_load_io_at_offset_as (bin, fd, baseaddr,
						old_o->loadaddr, 0, old_o->boffset, NULL);
	} else {
		RListIter *iter = NULL;
		RBinObject *old_o;
		r_list_foreach (the_obj_list, iter, old_o) {
			// XXX - naive. do we need a way to prevent multiple "anys" from being opened?
			res = r_bin_load_io_at_offset_as (bin, fd, baseaddr,
				old_o->loadaddr, 0, old_o->boffset, old_o->plugin->name);
		}
	}
	bf->o = r_list_get_n (bf->objs, 0);
	r_list_free (the_obj_list);
	return res;
}

R_API int r_bin_load_io(RBin *bin, int fd, ut64 baseaddr, ut64 loadaddr, int xtr_idx) {
	return r_bin_load_io_at_offset_as (bin, fd, baseaddr, loadaddr, xtr_idx, 0, NULL);
}

R_API int r_bin_load_io_at_offset_as_sz(RBin *bin, int fd, ut64 baseaddr,
		ut64 loadaddr, int xtr_idx, ut64 offset, const char *name, ut64 sz) {
	RIOBind *iob = &(bin->iob);
	RIO *io = iob? iob->io: NULL;
	RListIter *it;
	ut8 *buf_bytes = NULL;
	RBinXtrPlugin *xtr;
	ut64 file_sz = UT64_MAX;
	RBinFile *binfile = NULL;
	int tfd = -1;

	if (!io || (fd < 0) || (st64)sz < 0) {
		return false;
	}
	bool is_debugger = iob->fd_is_dbg (io, fd);
	const char *fname = iob->fd_get_name (io, fd);
	if (loadaddr == UT64_MAX) {
		loadaddr = 0;
	}
	file_sz = iob->fd_size (io, fd);
	// file_sz = UT64_MAX happens when attaching to frida:// and other non-debugger io plugins which results in double opening
	if (!file_sz || (is_debugger && file_sz == UT64_MAX)) {
		tfd = iob->fd_open (io, fname, R_IO_READ, 0644);
		if (tfd >= 1) {
			file_sz = iob->fd_size (io, tfd);
		}
	}
	if (!sz) {
		sz = file_sz;
	}

	bin->file = fname;
	sz = R_MIN (file_sz, sz);
	if (!r_list_length (bin->binfiles)) {
		if (is_debugger) {
			//use the temporal RIODesc to read the content of the file instead
			//from the memory
			if (tfd >= 0) {
				buf_bytes = calloc (1, sz + 1);
				iob->fd_read_at (io, tfd, 0, buf_bytes, sz);
				// iob->fd_close (io, tfd);
			}
		}
	}
	if (!buf_bytes) {
		buf_bytes = calloc (1, sz + 1);
		if (!buf_bytes) {
			return false;
		}
		ut64 seekaddr = is_debugger? baseaddr: loadaddr;
		if (!iob->fd_read_at (io, fd, seekaddr, buf_bytes, sz)) {
			sz = 0LL;
		}
	}

	if (!name && (st64)sz > 0) {
		// XXX - for the time being this is fine, but we may want to
		// change the name to something like
		// <xtr_name>:<bin_type_name>
		r_list_foreach (bin->binxtrs, it, xtr) {
			if (xtr && xtr->check_bytes (buf_bytes, sz)) {
				if (xtr && (xtr->extract_from_bytes || xtr->extractall_from_bytes)) {
					if (is_debugger && sz != file_sz) {
						R_FREE (buf_bytes);
						if (tfd < 0) {
							tfd = iob->fd_open (io, fname, R_IO_READ, 0);
						}
						sz = iob->fd_size (io, tfd);
						if (sz != UT64_MAX) {
							buf_bytes = calloc (1, sz + 1);
							if (buf_bytes) {
								(void) iob->fd_read_at (io, tfd, 0, buf_bytes, sz);
							}
						}
				//DOUBLECLOSE UAF : iob->fd_close (io, tfd);
						tfd = -1;	// marking it closed
					} else if (sz != file_sz) {
						(void) iob->read_at (io, 0LL, buf_bytes, sz);
					}
					binfile = r_bin_file_xtr_load_bytes (bin, xtr,
						fname, buf_bytes, sz, file_sz,
						baseaddr, loadaddr, xtr_idx,
						fd, bin->rawstr);
				}
				xtr = NULL;
			}
		}
	}
	if (!binfile) {
		bool steal_ptr = true; // transfer buf_bytes ownership to binfile
		binfile = r_bin_file_new_from_bytes (
			bin, fname, buf_bytes, sz, file_sz, bin->rawstr,
			baseaddr, loadaddr, fd, name, NULL, offset, steal_ptr);
	}
	return binfile? r_bin_file_set_cur_binfile (bin, binfile): false;
}

R_API bool r_bin_load_io_at_offset_as(RBin *bin, int fd, ut64 baseaddr,
		ut64 loadaddr, int xtr_idx, ut64 offset, const char *name) {
	// adding file_sz to help reduce the performance impact on the system
	// in this case the number of bytes read will be limited to 2MB
	// (MIN_LOAD_SIZE)
	// if it fails, the whole file is loaded.
	const ut64 MAX_LOAD_SIZE = 0;  // 0xfffff; //128 * (1 << 10 << 10);
	int res = r_bin_load_io_at_offset_as_sz (bin, fd, baseaddr,
		loadaddr, xtr_idx, offset, name, MAX_LOAD_SIZE);
	if (!res) {
		res = r_bin_load_io_at_offset_as_sz (bin, fd, baseaddr,
			loadaddr, xtr_idx, offset, name, UT64_MAX);
	}
	return res;
}

R_API int r_bin_file_deref_by_bind(RBinBind *binb) {
	RBin *bin = binb? binb->bin: NULL;
	RBinFile *a = r_bin_cur (bin);
	return r_bin_file_deref (bin, a);
}

R_API int r_bin_file_deref(RBin *bin, RBinFile *a) {
	RBinObject *o = r_bin_cur_object (bin);
	int res = false;
	if (a && !o) {
		//r_list_delete_data (bin->binfiles, a);
		res = true;
	} else if (a && o->referenced - 1 < 1) {
		//r_list_delete_data (bin->binfiles, a);
		res = true;
		// not thread safe
	} else if (o) {
		o->referenced--;
	}
	// it is possible for a file not
	// to be bound to RBin and RBinFiles
	// XXX - is this an ok assumption?
	if (bin) bin->cur = NULL;
	return res;
}

R_API int r_bin_file_ref_by_bind(RBinBind *binb) {
	RBin *bin = binb? binb->bin: NULL;
	RBinFile *a = r_bin_cur (bin);
	return r_bin_file_ref (bin, a);
}

R_API int r_bin_file_ref(RBin *bin, RBinFile *a) {
	RBinObject *o = r_bin_cur_object (bin);
	if (a && o) {
		o->referenced--;
		return true;
	}
	return false;
}

static void r_bin_file_free(void /*RBinFile*/ *bf_) {
	RBinFile *a = bf_;
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);

	if (!a) {
		return;
	}

	// Binary format objects are connected to the
	// RBinObject, so the plugin must destroy the
	// format data first
	if (plugin && plugin->destroy) {
		plugin->destroy (a);
	}
	if (a->curxtr && a->curxtr->destroy && a->xtr_obj) {
		a->curxtr->free_xtr ((void *)(a->xtr_obj));
	}
	r_buf_free (a->buf);
	// TODO: unset related sdb namespaces
	if (a && a->sdb_addrinfo) {
		sdb_free (a->sdb_addrinfo);
		a->sdb_addrinfo = NULL;
	}
	free (a->file);
	a->o = NULL;
	r_list_free (a->objs);
	r_list_free (a->xtr_data);
	r_id_pool_kick_id (a->rbin->file_ids, a->id);
	memset (a, 0, sizeof (RBinFile));
	free (a);
}

static RBinFile *r_bin_file_create_append(RBin *bin, const char *file,
					   const ut8 *bytes, ut64 sz,
					   ut64 file_sz, int rawstr, int fd,
					   const char *xtrname, bool steal_ptr) {
	RBinFile *bf = r_bin_file_new (bin, file, bytes, sz, file_sz, rawstr,
				       fd, xtrname, bin->sdb, steal_ptr);
	if (bf) {
		r_list_append (bin->binfiles, bf);
	}
	return bf;
}

// This function populate RBinFile->xtr_data, that information is enough to
// create RBinObject when needed using r_bin_file_object_new_from_xtr_data
static RBinFile *r_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr,
					    const char *filename,
					    const ut8 *bytes, ut64 sz,
					    ut64 file_sz, ut64 baseaddr,
					    ut64 loadaddr, int idx, int fd,
					    int rawstr) {
	if (!bin || !bytes) {
		return NULL;
	}
	RBinFile *bf = r_bin_file_find_by_name (bin, filename);
	if (!bf) {
		bf = r_bin_file_create_append (bin, filename, bytes, sz,
					       file_sz, rawstr, fd, xtr->name, false);
		if (!bf) {
			return NULL;
		}
		if (!bin->cur) {
			bin->cur = bf;
		}
	}
	if (bf->xtr_data) {
		r_list_free (bf->xtr_data);
	}
	if (xtr && bytes) {
		RList *xtr_data_list = xtr->extractall_from_bytes (bin, bytes, sz);
		RListIter *iter;
		RBinXtrData *xtr;
		//populate xtr_data with baddr and laddr that will be used later on
		//r_bin_file_object_new_from_xtr_data
		r_list_foreach (xtr_data_list, iter, xtr) {
			xtr->baddr = baseaddr? baseaddr : UT64_MAX;
			xtr->laddr = loadaddr? loadaddr : UT64_MAX;
		}
		bf->loadaddr = loadaddr;
		bf->xtr_data = xtr_data_list ? xtr_data_list : NULL;
	}
	return bf;
}

static RBinPlugin *r_bin_get_binplugin_by_name(RBin *bin, const char *name) {
	RBinPlugin *plugin;
	RListIter *it;
	if (bin && name) {
		r_list_foreach (bin->plugins, it, plugin) {
			if (!strcmp (plugin->name, name)) {
				return plugin;
			}
		}
	}
	return NULL;
}

R_API RBinPlugin *r_bin_get_binplugin_by_bytes(RBin *bin, const ut8 *bytes, ut64 sz) {
	RBinPlugin *plugin;
	RListIter *it;
	if (!bin || !bytes) {
		return NULL;
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (plugin->check_bytes && plugin->check_bytes (bytes, sz)) {
			return plugin;
		}
	}
	return NULL;
}

static RBinXtrPlugin *r_bin_get_xtrplugin_by_name(RBin *bin, const char *name) {
	RBinXtrPlugin *xtr;
	RListIter *it;
	if (!bin || !name) return NULL;
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, name)) {
			return xtr;
		}
		// must be set to null
		xtr = NULL;
	}
	return NULL;
}

static RBinPlugin *r_bin_get_binplugin_any(RBin *bin) {
	return r_bin_get_binplugin_by_name (bin, "any");
}

static RBinObject *r_bin_object_new(RBinFile *binfile, RBinPlugin *plugin,
				     ut64 baseaddr, ut64 loadaddr, ut64 offset,
				     ut64 sz) {
	const ut8 *bytes = binfile? r_buf_buffer (binfile->buf): NULL;
	ut64 bytes_sz = binfile? r_buf_size (binfile->buf): 0;
	Sdb *sdb = binfile? binfile->sdb: NULL;
	RBinObject *o = R_NEW0 (RBinObject);
	if (!o) {
		return NULL;
	}
	o->obj_size = bytes && (bytes_sz >= sz + offset)? sz: 0;
	o->boffset = offset;
	o->id = r_num_rand (0xfffff000);
	o->kv = sdb_new0 ();
	o->baddr = baseaddr;
	o->baddr_shift = 0;
	o->plugin = plugin;
	o->loadaddr = loadaddr != UT64_MAX ? loadaddr : 0;

	// XXX more checking will be needed here
	// only use LoadBytes if buffer offset != 0
	// if (offset != 0 && bytes && plugin && plugin->load_bytes && (bytes_sz
	// >= sz + offset) ) {
	if (bytes && plugin && plugin->load_bytes && (bytes_sz >= sz + offset)) {
		ut64 bsz = bytes_sz - offset;
		if (sz < bsz) {
			bsz = sz;
		}
		o->bin_obj = plugin->load_bytes (binfile, bytes + offset, sz,
						 loadaddr, sdb);
		if (!o->bin_obj) {
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

#define LIMIT_SIZE 0
static int r_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr) {
	if (!bytes) {
		return false;
	}
	r_buf_free (binfile->buf);
	binfile->buf = r_buf_new ();
#if LIMIT_SIZE
	if (sz > 1024 * 1024) {
		eprintf ("Too big\n");
		// TODO: use r_buf_io instead of setbytes all the time to save memory
		return NULL;
	}
#else
	if (steal_ptr) {
		r_buf_set_bytes_steal (binfile->buf, bytes, sz);
	} else {
		r_buf_set_bytes (binfile->buf, bytes, sz);
	}
#endif
	return binfile->buf != NULL;
}

static RBinFile *r_bin_file_new(RBin *bin, const char *file, const ut8 *bytes,
				 ut64 sz, ut64 file_sz, int rawstr, int fd,
				 const char *xtrname, Sdb *sdb, bool steal_ptr) {
	RBinFile *binfile = R_NEW0 (RBinFile);
	if (!binfile) {
		return NULL;
	}
	if (!r_id_pool_grab_id (bin->file_ids, &binfile->id)) {
		if (steal_ptr) { // we own the ptr, free on error
			free ((void*) bytes);
		}
		free (binfile);		//no id means no binfile
		return NULL;
	}
	int res = r_bin_file_set_bytes (binfile, bytes, sz, steal_ptr);
	if (!res && steal_ptr) { // we own the ptr, free on error
		free((void*) bytes);
	}
	binfile->rbin = bin;
	binfile->file = file? strdup (file): NULL;
	binfile->rawstr = rawstr;
	binfile->fd = fd;
	binfile->curxtr = r_bin_get_xtrplugin_by_name (bin, xtrname);
	binfile->sdb = sdb;
	binfile->size = file_sz;
	binfile->xtr_data = r_list_newf ((RListFree)r_bin_xtrdata_free);
	binfile->objs = r_list_newf ((RListFree)r_bin_object_free);
	binfile->xtr_obj  = NULL;

	if (!binfile->buf) {
		//r_bin_file_free (binfile);
		binfile->buf = r_buf_new ();
		//	return NULL;
	}

	if (sdb) {
		binfile->sdb = sdb_ns (sdb, sdb_fmt (0, "fd.%d", fd), 1);
		sdb_set (binfile->sdb, "archs", "0:0:x86:32", 0); // x86??
		/* NOTE */
		/* Those refs++ are necessary because sdb_ns() doesnt rerefs all
		 * sub-namespaces */
		/* And if any namespace is referenced backwards it gets
		 * double-freed */
		binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo", 1);
		binfile->sdb_addrinfo->refs++;
		sdb_ns_set (sdb, "cur", binfile->sdb);
		binfile->sdb->refs++;
	}
	return binfile;
}

R_API bool r_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf,
						ut64 baseaddr, ut64 loadaddr,
						RBinXtrData *data) {
	RBinObject *o = NULL;
	RBinPlugin *plugin = NULL;
	ut8* bytes;
	ut64 offset = data? data->offset: 0;
	ut64 sz = data ? data->size : 0;
	if (!data || !bf) {
		return false;
	}

	// for right now the bytes used will just be the offest into the binfile
	// buffer
	// if the extraction requires some sort of transformation then this will
	// need to be fixed
	// here.
	bytes = data->buffer;
	if (!bytes) {
		return false;
	}
	plugin = r_bin_get_binplugin_by_bytes (bin, (const ut8*)bytes, sz);
	if (!plugin) {
		plugin = r_bin_get_binplugin_any (bin);
	}
	r_buf_free (bf->buf);
	bf->buf = r_buf_new_with_bytes ((const ut8*)bytes, data->size);
	//r_bin_object_new append the new object into binfile
	o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, offset, sz);
	// size is set here because the reported size of the object depends on
	// if loaded from xtr plugin or partially read
	if (!o) {
		return false;
	}
	if (o && !o->size) {
		o->size = sz;
	}
	bf->narch = data->file_count;
	if (!o->info) {
		o->info = R_NEW0 (RBinInfo);
	}
	free (o->info->file);
	free (o->info->arch);
	free (o->info->machine);
	free (o->info->type);
	o->info->file = strdup (bf->file);
	o->info->arch = strdup (data->metadata->arch);
	o->info->machine = strdup (data->metadata->machine);
	o->info->type = strdup (data->metadata->type);
	o->info->bits = data->metadata->bits;
	o->info->has_crypto = bf->o->info->has_crypto;
	data->loaded = true;
	return true;
}

static RBinFile *r_bin_file_new_from_bytes(RBin *bin, const char *file,
					    const ut8 *bytes, ut64 sz,
					    ut64 file_sz, int rawstr,
					    ut64 baseaddr, ut64 loadaddr,
					    int fd, const char *pluginname,
					    const char *xtrname, ut64 offset,
					    bool steal_ptr) {
	ut8 binfile_created = false;
	RBinPlugin *plugin = NULL;
	RBinXtrPlugin *xtr = NULL;
	RBinObject *o = NULL;
	RBinFile *bf = NULL;
	if (sz == UT64_MAX) {
		return NULL;
	}

	if (xtrname) {
		xtr = r_bin_get_xtrplugin_by_name (bin, xtrname);
	}

	if (xtr && xtr->check_bytes (bytes, sz)) {
		return r_bin_file_xtr_load_bytes (bin, xtr, file,
						bytes, sz, file_sz, baseaddr, loadaddr, 0,
						fd, rawstr);
	}

	if (!bf) {
		bf = r_bin_file_create_append (bin, file, bytes, sz, file_sz,
					       rawstr, fd, xtrname, steal_ptr);
		if (!bf) {
			if (!steal_ptr) { // we own the ptr, free on error
				free ((void*) bytes);
			}
			return NULL;
		}
		binfile_created = true;
	}

	if (bin->force) {
		plugin = r_bin_get_binplugin_by_name (bin, bin->force);
	}
	if (!plugin) {
		if (pluginname) {
			plugin = r_bin_get_binplugin_by_name (bin, pluginname);
		}
		if (!plugin) {
			plugin = r_bin_get_binplugin_by_bytes (bin, bytes, sz);
			if (!plugin) {
				plugin = r_bin_get_binplugin_any (bin);
			}
		}
	}

	o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, 0, r_buf_size (bf->buf));
	// size is set here because the reported size of the object depends on
	// if loaded from xtr plugin or partially read
	if (o && !o->size) {
		o->size = file_sz;
	}

	if (!o) {
		if (bf && binfile_created) {
			r_list_delete_data (bin->binfiles, bf);
		}
		return NULL;
	}
	/* WTF */
	if (strcmp (plugin->name, "any")) {
		bf->narch = 1;
	}

	/* free unnecessary rbuffer (???) */
	return bf;
}

static void plugin_free(RBinPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
	R_FREE (p);
}

// rename to r_bin_plugin_add like the rest
R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	RListIter *it;
	RBinPlugin *plugin;
	if (foo->init) {
		foo->init (bin->user);
	}
	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, foo->name)) {
			return false;
		}
	}
	plugin = R_NEW0 (RBinPlugin);
	memcpy (plugin, foo, sizeof (RBinPlugin));
	r_list_append (bin->plugins, plugin);
	return true;
}

R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	RListIter *it;
	RBinXtrPlugin *xtr;

	if (foo->init) {
		foo->init (bin->user);
	}
	// avoid duplicates
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, foo->name)) {
			return false;
		}
	}
	r_list_append (bin->binxtrs, foo);
	return true;
}

R_API void *r_bin_free(RBin *bin) {
	if (!bin) {
		return NULL;
	}
	if (bin->io_owned) {
		r_io_free (bin->iob.io);
	}
	bin->file = NULL;
	free (bin->force);
	free (bin->srcdir);
	//r_bin_free_bin_files (bin);
	r_list_free (bin->binfiles);
	r_list_free (bin->binxtrs);
	r_list_free (bin->plugins);
	sdb_free (bin->sdb);
	r_id_pool_free (bin->file_ids);
	memset (bin, 0, sizeof (RBin));
	free (bin);
	return NULL;
}

static int r_bin_print_plugin_details(RBin *bin, RBinPlugin *bp, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bp->name);
	} else if (json) {
		bin->cb_printf (
			"{\"name\":\"%s\",\"description\":\"%s\","
			"\"license\":\"%s\"}\n",
			bp->name, bp->desc, bp->license? bp->license: "???");
	} else {
		bin->cb_printf ("Name: %s\n", bp->name);
		bin->cb_printf ("Description: %s\n", bp->desc);
		if (bp->license) {
			bin->cb_printf ("License: %s\n", bp->license);
		}
		if (bp->version) {
			bin->cb_printf ("Version: %s\n", bp->version);
		}
		if (bp->author) {
			bin->cb_printf ("Author: %s\n", bp->author);
		}
	}
	return true;
}

static int r_bin_print_xtrplugin_details(RBin *bin, RBinXtrPlugin *bx, int json) {
	if (json == 'q') {
		bin->cb_printf ("%s\n", bx->name);
	} else if (json) {
		bin->cb_printf (
			"{\"name\":\"%s\",\"description\":\"%s\","
			"\"license\":\"%s\"}\n",
			bx->name, bx->desc, bx->license? bx->license: "???");
	} else {
		bin->cb_printf ("Name: %s\n", bx->name);
		bin->cb_printf ("Description: %s\n", bx->desc);
		if (bx->license) {
			bin->cb_printf ("License: %s\n", bx->license);
		}
	}
	return true;
}

R_API int r_bin_list(RBin *bin, int json) {
	RListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;

	if (json == 'q') {
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("%s\n", bp->name);
		}
		r_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf ("%s\n", bx->name);
		}
	} else if (json) {
		int i;

		i = 0;
		bin->cb_printf ("{\"bin\":[");
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", bp->name, bp->desc, bp->license? bp->license: "???");
			i++;
		}

		i = 0;
		bin->cb_printf ("],\"xtr\":[");
		r_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf (
				"%s{\"name\":\"%s\",\"description\":\"%s\","
				"\"license\":\"%s\"}",
				i? ",": "", bx->name, bx->desc, bx->license? bx->license: "???");
			i++;
		}
		bin->cb_printf ("]}\n");
	} else {
		r_list_foreach (bin->plugins, it, bp) {
			bin->cb_printf ("bin  %-11s %s (%s) %s %s\n",
				bp->name, bp->desc, bp->license? bp->license: "???",
				bp->version? bp->version: "",
				bp->author? bp->author: "");
		}
		r_list_foreach (bin->binxtrs, it, bx) {
			bin->cb_printf ("xtr  %-11s %s (%s)\n", bx->name,
				bx->desc, bx->license? bx->license: "???");
		}
	}
	return false;
}

R_API int r_bin_list_plugin(RBin *bin, const char* name, int json) {
	RListIter *it;
	RBinPlugin *bp;
	RBinXtrPlugin *bx;

	r_list_foreach (bin->plugins, it, bp) {
		if (!r_str_cmp (name, bp->name, strlen (name))) {
			continue;
		}
		return r_bin_print_plugin_details (bin, bp, json);
	}
	r_list_foreach (bin->binxtrs, it, bx) {
		if (!r_str_cmp (name, bx->name, strlen (name))) {
			continue;
		}
		return r_bin_print_xtrplugin_details (bin, bx, json);
	}

	eprintf ("cannot find plugin %s\n", name);
	return false;
}

static ut64 binobj_get_baddr(RBinObject *o) {
	return o? o->baddr + o->baddr_shift: UT64_MAX;
}

R_API ut64 r_binfile_get_baddr(RBinFile *binfile) {
	return binfile? binobj_get_baddr (binfile->o): UT64_MAX;
}

/* returns the base address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_baddr(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return binobj_get_baddr (o);
}

/* returns the load address of bin or UT64_MAX in case of errors */
R_API ut64 r_bin_get_laddr(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->loadaddr: UT64_MAX;
}

R_API void r_bin_set_baddr(RBin *bin, ut64 baddr) {
	RBinObject *o = r_bin_cur_object (bin);
	binobj_set_baddr (o, baddr);
	// XXX - update all the infos?
}

R_API ut64 r_bin_get_boffset(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->boffset: UT64_MAX;
}

R_API RBinAddr *r_bin_get_sym(RBin *bin, int sym) {
	RBinObject *o = r_bin_cur_object (bin);
	if (sym < 0 || sym >= R_BIN_SYM_LAST) {
		return NULL;
	}
	return o? o->binsym[sym]: NULL;
}

// XXX: those accessors are redundant
R_API RList *r_bin_get_entries(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->entries: NULL;
}

R_API RList *r_bin_get_fields(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->fields: NULL;
}

R_API RList *r_bin_get_imports(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->imports: NULL;
}

R_API RBinInfo *r_bin_get_info(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->info: NULL;
}

R_API RList *r_bin_get_libs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->libs: NULL;
}


R_API RList * r_bin_patch_relocs(RBin *bin) {
	static bool first = true;
	RBinObject *o = r_bin_cur_object (bin);
	if (!o) {
		return NULL;
	}
	// r_bin_object_set_items set o->relocs but there we don't have access
	// to io
	// so we need to be run from bin_relocs, free the previous reloc and get
	// the patched ones
	if (first && o->plugin && o->plugin->patch_relocs) {
		RList *tmp = o->plugin->patch_relocs (bin);
		first = false;
		if (!tmp) {
			return o->relocs;
		}
		r_list_free (o->relocs);
		o->relocs = tmp;
		REBASE_PADDR (o, o->relocs, RBinReloc);
		first = false;
		return o->relocs;
	}
	return o->relocs;
}

R_API RList *r_bin_get_relocs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->relocs: NULL;
}

R_API RList *r_bin_get_sections(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->sections: NULL;
}

// TODO: Move into section.c and rename it to r_io_section_get_at ()
R_API RBinSection *r_bin_get_section_at(RBinObject *o, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;
	if (o) {
		// TODO: must be O(1) .. use sdb here
		r_list_foreach (o->sections, iter, section) {
			from = va? binobj_a2b (o, section->vaddr): section->paddr;
			to = va? (binobj_a2b (o, section->vaddr) + section->vsize) :
				(section->paddr + section->size);
			if (off >= from && off < to) {
				return section;
			}
		}
	}
	return NULL;
}

R_API RList *r_bin_reset_strings(RBin *bin) {
	RBinFile *a = r_bin_cur (bin);
	RBinObject *o = r_bin_cur_object (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);

	if (!a || !o) {
		return NULL;
	}
	if (o->strings) {
		r_list_purge (o->strings);
		o->strings = NULL;
	}

	if (bin->minstrlen <= 0) {
		return NULL;
	}
	a->rawstr = bin->rawstr;

	if (plugin && plugin->strings) {
		o->strings = plugin->strings (a);
	} else {
		o->strings = get_strings (a, bin->minstrlen, 0);
	}
	if (bin->debase64) {
		filterStrings (bin, o->strings);
	}
	return o->strings;
}

R_API RList *r_bin_get_strings(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->strings: NULL;
}

R_API int r_bin_is_string(RBin *bin, ut64 va) {
	RBinString *string;
	RListIter *iter;
	RList *list;
	if (!(list = r_bin_get_strings (bin))) {
		return false;
	}
	r_list_foreach (list, iter, string) {
		if (string->vaddr == va) {
			return true;
		}
		if (string->vaddr > va) {
			return false;
		}
	}
	return false;
}

//callee must not free the symbol
R_API RBinSymbol *r_bin_get_symbol_at_vaddr(RBin *bin, ut64 addr) {
	//use skiplist here
	RList *symbols = r_bin_get_symbols (bin);
	RListIter *iter;
	RBinSymbol *symbol;
	r_list_foreach (symbols, iter, symbol) {
		if (symbol->vaddr == addr) {
			return symbol;
		}
	}
	return NULL;
}

//callee must not free the symbol
R_API RBinSymbol *r_bin_get_symbol_at_paddr(RBin *bin, ut64 addr) {
	//use skiplist here
	RList *symbols = r_bin_get_symbols (bin);
	RListIter *iter;
	RBinSymbol *symbol;
	r_list_foreach (symbols, iter, symbol) {
		if (symbol->paddr == addr) {
			return symbol;
		}
	}
	return NULL;
}

R_API RList *r_bin_get_symbols(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->symbols: NULL;
}

R_API RList *r_bin_get_mem(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->mem: NULL;
}

R_API int r_bin_is_big_endian(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return (o && o->info)? o->info->big_endian: -1;
}

R_API int r_bin_is_stripped(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_STRIPPED & o->info->dbg_info): 1;
}

R_API int r_bin_is_static(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o && r_list_length (o->libs) > 0)
		return R_BIN_DBG_STATIC & o->info->dbg_info;
	return true;
}

// TODO: Integrate with r_bin_dbg */
R_API int r_bin_has_dbg_linenums(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_LINENUMS & o->info->dbg_info): false;
}

R_API int r_bin_has_dbg_syms(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_SYMS & o->info->dbg_info): false;
}

R_API int r_bin_has_dbg_relocs(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? (R_BIN_DBG_RELOCS & o->info->dbg_info): false;
}

R_API RBin *r_bin_new() {
	int i;
	RBinXtrPlugin *static_xtr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) {
		return NULL;
	}
	bin->force = NULL;
	bin->filter_rules = UT64_MAX;
	bin->sdb = sdb_new0 ();
	bin->cb_printf = (PrintfCallback)printf;
	bin->plugins = r_list_newf ((RListFree)plugin_free);
	bin->minstrlen = 0;
	bin->want_dbginfo = true;
	bin->cur = NULL;
	bin->io_owned = false;

	bin->binfiles = r_list_newf ((RListFree)r_bin_file_free);
	for (i = 0; bin_static_plugins[i]; i++) {
		r_bin_add (bin, bin_static_plugins[i]);
	}
	bin->binxtrs = r_list_new ();
	bin->binxtrs->free = free;
	for (i = 0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW0 (RBinXtrPlugin);
		if (!static_xtr_plugin) {
			free (bin);
			return NULL;
		}
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		r_bin_xtr_add (bin, static_xtr_plugin);
	}
	bin->file_ids = r_id_pool_new (0, 0xffffffff);
	return bin;
}

R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits,
			  const char *name) {
	RBinFile *binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	RBinObject *obj = NULL;
	if (binfile) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
		if (!obj) {
			if (binfile->xtr_data) {
				RBinXtrData *xtr_data = r_list_get_n (binfile->xtr_data, 0);
				if (!r_bin_file_object_new_from_xtr_data (bin, binfile,
						UT64_MAX, r_bin_get_laddr (bin), xtr_data)) {
					return false;
				}
				obj = r_list_get_n (binfile->objs, 0);
			}
		}
	} else {
		void *plugin = r_bin_get_binplugin_by_name (bin, name);
		if (plugin) {
			if (bin->cur) {
				bin->cur->curplugin = plugin;
			}
			binfile = r_bin_file_new (bin, "-", NULL, 0, 0, 0, 999, NULL, NULL, false);
			// create object and set arch/bits
			obj = r_bin_object_new (binfile, plugin, 0, 0, 0, 1024);
			binfile->o = obj;
			obj->info = R_NEW0 (RBinInfo);
			obj->info->arch = strdup (arch);
			obj->info->bits = bits;
		}
	}
	return (binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj));
}

R_API RBinObject *r_bin_object_find_by_arch_bits(RBinFile *binfile,
						  const char *arch, int bits,
						  const char *name) {
	RBinObject *obj = NULL;
	RListIter *iter = NULL;
	RBinInfo *info = NULL;
	r_list_foreach (binfile->objs, iter, obj) {
		info = obj->info;
		if (info && info->arch && info->file &&
		   (bits == info->bits) &&
			!strcmp (info->arch, arch) &&
			!strcmp (info->file, name)) {
			break;
		}
		obj = NULL;
	}
	return obj;
}

R_API RBinFile *r_bin_file_find_by_arch_bits(RBin *bin, const char *arch,
					      int bits, const char *name) {
	RListIter *iter;
	RBinFile *binfile = NULL;
	RBinXtrData *xtr_data;

	if (!name || !arch) {
		return NULL;
	}
	r_list_foreach (bin->binfiles, iter, binfile) {
		RListIter *iter_xtr;
		if (!binfile->xtr_data) {
			continue;
		}
		// look for sub-bins in Xtr Data and Load if we need to
		r_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (xtr_data->metadata && xtr_data->metadata->arch) {
				char *iter_arch = xtr_data->metadata->arch;
				int iter_bits = xtr_data->metadata->bits;
				if (bits == iter_bits && !strcmp (iter_arch, arch)) {
					if (!xtr_data->loaded) {
						if (!r_bin_file_object_new_from_xtr_data (
							    bin, binfile, xtr_data->baddr,
							    xtr_data->laddr, xtr_data)) {
							return NULL;
						}
						return binfile;
					}
				}
			}
		}
	}
	return binfile;
}

R_API int r_bin_select(RBin *bin, const char *arch, int bits,
			const char *name) {
	RBinFile *cur = r_bin_cur (bin), *binfile = NULL;
	RBinObject *obj = NULL;
	name = !name && cur? cur->file: name;
	binfile = r_bin_file_find_by_arch_bits (bin, arch, bits, name);
	if (binfile && name) {
		obj = r_bin_object_find_by_arch_bits (binfile, arch, bits, name);
	}
	return binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_object(RBinFile *binfile, const char *arch, int bits,
			       const char *name) {
	RBinObject *obj = binfile ? r_bin_object_find_by_arch_bits (
					    binfile, arch, bits, name) :
				    NULL;
	return obj &&
	       r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, obj);
}

static RBinObject *r_bin_file_object_find_by_id(RBinFile *binfile,
						 ut32 binobj_id) {
	RBinObject *obj;
	RListIter *iter;
	if (binfile)  {
		r_list_foreach (binfile->objs, iter, obj) {
			if (obj->id == binobj_id) {
				return obj;
			}
		}
	}
	return NULL;
}

static RBinFile *r_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id) {
	RListIter *iter;
	RBinFile *binfile;
	r_list_foreach (bin->binfiles, iter, binfile) {
		if (r_bin_file_object_find_by_id (binfile, binobj_id)) {
			return binfile;
		}
	}
	return NULL;
}

static RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 binfile_id) {
	RBinFile *binfile = NULL;
	RListIter *iter = NULL;
	r_list_foreach (bin->binfiles, iter, binfile) {
		if (binfile->id == binfile_id) {
			break;
		}
		binfile = NULL;
	}
	return binfile;
}

R_API int r_bin_object_delete(RBin *bin, ut32 binfile_id, ut32 binobj_id) {
	RBinFile *binfile = NULL; //, *cbinfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	int res = false;

#if 0
	if (binfile_id == UT32_MAX && binobj_id == UT32_MAX) {
		return false;
	}
#endif
	if (binfile_id == -1) {
		binfile = r_bin_file_find_by_object_id (bin, binobj_id);
		obj = binfile? r_bin_file_object_find_by_id (binfile, binobj_id): NULL;
	} else if (binobj_id == -1) {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile? binfile->o: NULL;
	} else {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile? r_bin_file_object_find_by_id (binfile, binobj_id): NULL;
	}

	// lazy way out, always leaving at least 1 bin object loaded
	if (binfile && (r_list_length (binfile->objs) > 1)) {
		binfile->o = NULL;
		r_list_delete_data (binfile->objs, obj);
		obj = (RBinObject *)r_list_get_n (binfile->objs, 0);
		res = obj && binfile &&
		      r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
	}
	return res;
}

R_API int r_bin_select_by_ids(RBin *bin, ut32 binfile_id, ut32 binobj_id) {
	RBinFile *binfile = NULL;
	RBinObject *obj = NULL;

	if (binfile_id == UT32_MAX && binobj_id == UT32_MAX) {
		return false;
	}
	if (binfile_id == -1) {
		binfile = r_bin_file_find_by_object_id (bin, binobj_id);
		obj = binfile? r_bin_file_object_find_by_id (binfile, binobj_id): NULL;
	} else if (binobj_id == -1) {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile? binfile->o: NULL;
	} else {
		binfile = r_bin_file_find_by_id (bin, binfile_id);
		obj = binfile? r_bin_file_object_find_by_id (binfile, binobj_id): NULL;
	}
	if (!binfile || !obj) {
		return false;
	}
	return obj && binfile && r_bin_file_set_cur_binfile_obj (bin, binfile, obj);
}

R_API int r_bin_select_idx(RBin *bin, const char *name, int idx) {
	RBinFile *nbinfile = NULL, *binfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	const char *tname = !name && binfile? binfile->file: name;
	int res = false;
	if (!tname || !bin) {
		return res;
	}
	nbinfile = r_bin_file_find_by_name_n (bin, tname, idx);
	obj = nbinfile? r_list_get_n (nbinfile->objs, idx): NULL;
	return obj && nbinfile &&
	       r_bin_file_set_cur_binfile_obj (bin, nbinfile, obj);
}

static void list_xtr_archs(RBin *bin, int mode) {
	RBinFile *binfile = r_bin_cur (bin);
	if (binfile->xtr_data) {
		RListIter *iter_xtr;
		RBinXtrData *xtr_data;
		int bits, i = 0;
		char *arch, *machine;
		r_list_foreach (binfile->xtr_data, iter_xtr, xtr_data) {
			if (!xtr_data || !xtr_data->metadata ||
			    !xtr_data->metadata->arch) {
				continue;
			}
			arch = xtr_data->metadata->arch;
			machine = xtr_data->metadata->machine;
			bits = xtr_data->metadata->bits;
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				bin->cb_printf (
					"%s{\"arch\":\"%s\",\"bits\":%d,"
					"\"offset\":%" PFMT64d
					",\"size\":\"%" PFMT64d
					",\"machine\":\"%s\"}",
					i++ ? "," : "", arch, bits,
					xtr_data->offset, xtr_data->size,
					machine);
				break;
			default:
				bin->cb_printf ("%03i 0x%08" PFMT64x
						" %" PFMT64d " %s_%i %s\n",
						i++, xtr_data->offset,
						xtr_data->size, arch, bits,
						machine);
				break;
			}
		}
	}
}

R_API void r_bin_list_archs(RBin *bin, int mode) {
	RListIter *iter;
	int i = 0;
	char unk[128];
	char archline[128];
	RBinFile *binfile = r_bin_cur (bin);
	RBinObject *obj = NULL;
	const char *name = binfile? binfile->file: NULL;
	int narch = binfile? binfile->narch: 0;

	//are we with xtr format?
	if (binfile && binfile->curxtr) {
		list_xtr_archs (bin, mode);
		return;
	}
	Sdb *binfile_sdb = binfile? binfile->sdb: NULL;
	if (!binfile_sdb) {
		eprintf ("Cannot find SDB!\n");
		return;
	} else if (!binfile) {
		eprintf ("Binary format not currently loaded!\n");
		return;
	}
	sdb_unset (binfile_sdb, ARCHS_KEY, 0);
	if (mode == 'j') {
		bin->cb_printf ("\"bins\":[");
	}
	RBinFile *nbinfile = r_bin_file_find_by_name_n (bin, name, i);
	if (!nbinfile) {
		return;
	}
	i = -1;
	r_list_foreach (nbinfile->objs, iter, obj) {
		RBinInfo *info = obj->info;
		char bits = info? info->bits: 0;
		ut64 boffset = obj->boffset;
		ut32 obj_size = obj->obj_size;
		const char *arch = info? info->arch: NULL;
		const char *machine = info? info->machine: "unknown_machine";

		i++;
		if (!arch) {
			snprintf (unk, sizeof (unk), "unk_%d", i);
			arch = unk;
		}

		if (info && narch > 1) {
			switch (mode) {
			case 'q':
				bin->cb_printf ("%s\n", arch);
				break;
			case 'j':
				bin->cb_printf ("%s{\"arch\":\"%s\",\"bits\":%d,"
						"\"offset\":%" PFMT64d ",\"size\":%d,"
						"\"machine\":\"%s\"}",
						i? ",": "", arch, bits,
						boffset, obj_size, machine);
				break;
			default:
				bin->cb_printf ("%03i 0x%08" PFMT64x " %d %s_%i %s\n", i,
						boffset, obj_size, arch, bits, machine);
			}
			snprintf (archline, sizeof (archline) - 1,
				"0x%08" PFMT64x ":%d:%s:%d:%s",
				boffset, obj_size, arch, bits, machine);
			/// xxx machine not exported?
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		} else {
			if (info) {
				switch (mode) {
				case 'q':
					bin->cb_printf ("%s\n", arch);
					break;
				case 'j':
					bin->cb_printf ("%s{\"arch\":\"%s\",\"bits\":%d,"
							"\"offset\":%" PFMT64d ",\"size\":%d,"
							"\"machine\":\"%s\"}",
							i? ",": "", arch, bits,
							boffset, obj_size, machine);
					break;
				default:
					bin->cb_printf ("%03i 0x%08" PFMT64x " %d %s_%d\n", i,
							boffset, obj_size, arch, bits);
				}
				snprintf (archline, sizeof (archline),
					"0x%08" PFMT64x ":%d:%s:%d",
					boffset, obj_size, arch, bits);
			} else if (nbinfile && mode) {
				switch (mode) {
				case 'q':
					bin->cb_printf ("%s\n", arch);
					break;
				case 'j':
					bin->cb_printf ("%s{\"arch\":\"unk_%d\",\"bits\":%d,"
							"\"offset\":%" PFMT64d ",\"size\":%d,"
							"\"machine\":\"%s\"}",
							i? ",": "", i, bits,
							boffset, obj_size, machine);
					break;
				default:
					bin->cb_printf ("%03i 0x%08" PFMT64x " %d unk_0\n", i,
							boffset, obj_size);
				}
				snprintf (archline, sizeof (archline),
					"0x%08" PFMT64x ":%d:%s:%d",
					boffset, obj_size, "unk", 0);
			} else {
				eprintf ("Error: Invalid RBinFile.\n");
			}
			//sdb_array_push (binfile_sdb, ARCHS_KEY, archline, 0);
		}
	}
	if (mode == 'j') {
		bin->cb_printf ("]");
	}
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static RBinSection* _get_vsection_at(RBin *bin, ut64 vaddr) {
	RBinObject *cur = r_bin_object_get_cur (bin);
	return r_bin_get_section_at (cur, vaddr, true);
}
R_API void r_bin_bind(RBin *bin, RBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = getoffset;
		b->get_name = getname;
		b->get_sections = r_bin_get_sections;
		b->get_vsect_at = _get_vsection_at;
	}
}

R_API RBuffer *r_bin_create(RBin *bin, const ut8 *code, int codelen,
			     const ut8 *data, int datalen) {
	RBinFile *a = r_bin_cur (bin);
	RBinPlugin *plugin = r_bin_file_cur_plugin (a);
	if (codelen < 0) {
		codelen = 0;
	}
	if (datalen < 0) {
		datalen = 0;
	}
	if (plugin && plugin->create) {
		return plugin->create (bin, code, codelen, data, datalen);
	}
	return NULL;
}

R_API RBuffer *r_bin_package(RBin *bin, const char *type, const char *file, RList *files) {
	if (!strcmp (type, "zip")) {
#if 0
		int zep = 0;
		struct zip * z = zip_open (file, 8 | 1, &zep);
		if (z) {
			RListIter *iter;
			const char *f;
			eprintf ("zip file created\n");
			r_list_foreach (files, iter, f) {
				struct zip_source *zs = NULL;
				zs = zip_source_file (z, f, 0, 1024);
				if (zs) {
					eprintf ("ADD %s\n", f);
					zip_add (z, f, zs);
					zip_source_free (zs);
				} else {
					eprintf ("Cannot find file %s\n", f);
				}
				eprintf ("zS %p\n", zs);
			}
			zip_close (z);
		} else {
			eprintf ("Cannot create zip file\n");
		}
#endif
	} else if (!strcmp (type, "fat")) {
		const char *f;
		RListIter *iter;
		ut32 num;
		ut8 *num8 = (ut8*)&num;
		RBuffer *buf = r_buf_new_file (file, true);
		r_buf_write_at (buf, 0, (const ut8*)"\xca\xfe\xba\xbe", 4);
		int count = r_list_length (files);

		num = r_read_be32 (&count);
		ut64 from = 0x1000;
		r_buf_write_at (buf, 4, num8, 4);
		int off = 12;
		int item = 0;
		r_list_foreach (files, iter, f) {
			int f_len = 0;
			ut8 *f_buf = (ut8 *)r_file_slurp (f, &f_len);
			if (f_buf && f_len >= 0) {
				eprintf ("ADD %s %d\n", f, f_len);
			} else {
				eprintf ("Cannot open %s\n", f);
				free (f_buf);
				continue;
			}
			item++;
			/* CPU */
			num8[0] = f_buf[7];
			num8[1] = f_buf[6];
			num8[2] = f_buf[5];
			num8[3] = f_buf[4];
			r_buf_write_at (buf, off - 4, num8, 4);
			/* SUBTYPE */
			num8[0] = f_buf[11];
			num8[1] = f_buf[10];
			num8[2] = f_buf[9];
			num8[3] = f_buf[8];
			r_buf_write_at (buf, off, num8, 4);
			ut32 from32 = from;
			/* FROM */
			num = r_read_be32 (&from32);
			r_buf_write_at (buf, off + 4, num8, 4);
			r_buf_write_at (buf, from, f_buf, f_len);
			/* SIZE */
			num = r_read_be32 (&f_len);
			r_buf_write_at (buf, off + 8, num8, 4);
			off += 20;
			from += f_len + (f_len % 0x1000);
			free (f_buf);
		}
		r_buf_free (buf);
		return NULL;
	} else {
		eprintf ("Usage: rabin2 -X [fat|zip] [filename] [files ...]\n");
	}
	return NULL;
}

R_API RBinObject *r_bin_get_object(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	if (o) {
		o->referenced++;
	}
	return o;
}

R_API RList * /*<RBinClass>*/ r_bin_get_classes(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->classes: NULL;
}

R_API void r_bin_class_free(RBinClass *c) {
	free (c->name);
	free (c->super);
	r_list_free (c->methods);
	r_list_free (c->fields);
	free (c);
}

R_API RBinClass *r_bin_class_new(RBinFile *binfile, const char *name,
				  const char *super, int view) {
	RBinObject *o = binfile? binfile->o: NULL;
	RList *list = NULL;
	RBinClass *c;
	if (!o) {
		return NULL;
	}
	list = o->classes;
	if (!name) {
		return NULL;
	}
	c = r_bin_class_get (binfile, name);
	if (c) {
		if (super) {
			free (c->super);
			c->super = strdup (super);
		}
		return c;
	}
	c = R_NEW0 (RBinClass);
	if (!c) {
		return NULL;
	}
	c->name = strdup (name);
	c->super = super? strdup (super): NULL;
	c->index = r_list_length (list);
	c->methods = r_list_new ();
	c->fields = r_list_new ();
	c->visibility = view;
	if (!list) {
		list = o->classes = r_list_new ();
	}
	r_list_append (list, c);
	return c;
}

R_API RBinClass *r_bin_class_get(RBinFile *binfile, const char *name) {
	if (!binfile || !binfile->o || !name) {
		return NULL;
	}
	RBinClass *c;
	RListIter *iter;
	RList *list = binfile->o->classes;
	r_list_foreach (list, iter, c) {
		if (!strcmp (c->name, name)) {
			return c;
		}
	}
	return NULL;
}

R_API RBinSymbol *r_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs) {
	RBinClass *c = r_bin_class_get (binfile, classname);
	if (!c) {
		c = r_bin_class_new (binfile, classname, NULL, 0);
		if (!c) {
			eprintf ("Cannot allocate class %s\n", classname);
			return NULL;
		}
	}
	RBinSymbol *m;
	RListIter *iter;
	r_list_foreach (c->methods, iter, m) {
		if (!strcmp (m->name, name)) {
			return NULL;
		}
	}
	RBinSymbol *sym = R_NEW0 (RBinSymbol);
	if (!sym) {
		return NULL;
	}
	sym->name = strdup (name);
	r_list_append (c->methods, sym);
	return sym;
}

R_API void r_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name) {
	//TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

/* returns vaddr, rebased with the baseaddr of binfile, if va is enabled for
 * bin, paddr otherwise */
R_API ut64 r_binfile_get_vaddr(RBinFile *binfile, ut64 paddr, ut64 vaddr) {
	int use_va = 0;
	if (binfile && binfile->o && binfile->o->info) {
		use_va = binfile->o->info->has_va;
	}
	return use_va? binobj_a2b (binfile->o, vaddr): paddr;
}

/* returns vaddr, rebased with the baseaddr of bin, if va is enabled for bin,
 * paddr otherwise */
R_API ut64 r_bin_get_vaddr(RBin *bin, ut64 paddr, ut64 vaddr) {
	if (!bin || !bin->cur) {
		return UT64_MAX;
	}
	if (paddr == UT64_MAX) {
		return UT64_MAX;
	}
	/* hack to realign thumb symbols */
	if (bin->cur->o && bin->cur->o->info && bin->cur->o->info->arch) {
		if (bin->cur->o->info->bits == 16) {
			RBinSection *s = r_bin_get_section_at (bin->cur->o, paddr, false);
			// autodetect thumb
			if (s && s->srwx & 1 && strstr (s->name, "text")) {
				if (!strcmp (bin->cur->o->info->arch, "arm") && (vaddr & 1)) {
					vaddr = (vaddr >> 1) << 1;
				}
			}
		}
	}
	return r_binfile_get_vaddr (bin->cur, paddr, vaddr);
}

R_API ut64 r_bin_a2b(RBin *bin, ut64 addr) {
	RBinObject *o = r_bin_cur_object (bin);
	return o? o->baddr_shift + addr: addr;
}

R_API ut64 r_bin_get_size(RBin *bin) {
	RBinObject *o = r_bin_cur_object (bin);
	return o ? o->size : 0;
}

R_API int r_bin_file_delete_all(RBin *bin) {
	int counter = 0;
	if (bin) {
		counter = r_list_length (bin->binfiles);
		r_list_purge (bin->binfiles);
		bin->cur = NULL;
	}
	return counter;
}

R_API int r_bin_file_delete(RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf;
	RBinFile *cur = r_bin_cur (bin);
	if (bin && cur) {
		r_list_foreach (bin->binfiles, iter, bf) {
			if (bf && bf->fd == bin_fd) {
				if (cur->fd == bin_fd) {
					//avoiding UaF due to dead reference 
					bin->cur = NULL;
				}
				r_list_delete (bin->binfiles, iter);
				return 1;
			}
		}
	}
	return 0;
}

R_API RBinFile *r_bin_file_find_by_fd(RBin *bin, ut32 bin_fd) {
	RListIter *iter;
	RBinFile *bf;
	if (bin) {
		r_list_foreach (bin->binfiles, iter, bf) {
			if (bf && bf->fd == bin_fd) {
				return bf;
			}
		}
	}
	return NULL;
}

R_API RBinFile *r_bin_file_find_by_name(RBin *bin, const char *name) {
	RListIter *iter;
	RBinFile *bf = NULL;
	if (!bin || !name) {
		return NULL;
	}
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->file && !strcmp (bf->file, name)) {
			break;
		}
		bf = NULL;
	}
	return bf;
}

R_API RBinFile *r_bin_file_find_by_name_n(RBin *bin, const char *name, int idx) {
	RListIter *iter;
	RBinFile *bf = NULL;
	int i = 0;
	if (!bin) {
		return bf;
	}

	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->file && !strcmp (bf->file, name)) {
			if (i == idx) {
				break;
			}
			i++;
		}
		bf = NULL;
	}
	return bf;
}

R_API int r_bin_file_set_cur_by_fd(RBin *bin, ut32 bin_fd) {
	RBinFile *bf = r_bin_file_find_by_fd (bin, bin_fd);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API int r_bin_file_set_cur_binfile_obj(RBin *bin, RBinFile *bf, RBinObject *obj) {
	RBinPlugin *plugin = NULL;
	if (!bin || !bf || !obj) {
		return false;
	}
	bin->file = bf->file;
	bin->cur = bf;
	bin->narch = bf->narch;
	bf->o = obj;
	plugin = r_bin_file_cur_plugin (bf);
	if (bin->minstrlen < 1) {
		bin->minstrlen = plugin? plugin->minstrlen: bin->minstrlen;
	}
	return true;
}

R_API int r_bin_file_set_cur_binfile(RBin *bin, RBinFile *bf) {
	RBinObject *obj = bf? bf->o: NULL;
	return obj? r_bin_file_set_cur_binfile_obj (bin, bf, obj): false;
}

R_API int r_bin_file_set_cur_by_name(RBin *bin, const char *name) {
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API RBinFile *r_bin_cur(RBin *bin) {
	return bin? bin->cur: NULL;
}

R_API RBinObject *r_bin_cur_object(RBin *bin) {
	RBinFile *binfile = r_bin_cur (bin);
	return binfile? binfile->o: NULL;
}

R_API void r_bin_force_plugin(RBin *bin, const char *name) {
	free (bin->force);
	bin->force = (name && *name)? strdup (name): NULL;
}

R_API int r_bin_read_at(RBin *bin, ut64 addr, ut8 *buf, int size) {
	RIOBind *iob;
	if (!bin || !(iob = &(bin->iob))) {
		return false;
	}
	return iob->read_at (iob->io, addr, buf, size);
}

R_API int r_bin_write_at(RBin *bin, ut64 addr, const ut8 *buf, int size) {
	RIOBind *iob;
	if (!bin || !(iob = &(bin->iob))) {
		return false;
	}
	return iob->write_at (iob->io, addr, buf, size);
}

R_API const char *r_bin_entry_type_string(int etype) {
	switch (etype) {
	case R_BIN_ENTRY_TYPE_PROGRAM:
		return "program";
	case R_BIN_ENTRY_TYPE_MAIN:
		return "main";
	case R_BIN_ENTRY_TYPE_INIT:
		return "init";
	case R_BIN_ENTRY_TYPE_FINI:
		return "fini";
	case R_BIN_ENTRY_TYPE_TLS:
		return "tls";
	}
	return NULL;
}

R_API void r_bin_load_filter(RBin *bin, ut64 rules) {
	bin->filter_rules = rules;
}

/* RBinField */
R_API RBinField *r_bin_field_new(ut64 paddr, ut64 vaddr, int size, const char *name, const char *comment, const char *format) {
	RBinField *ptr;
	if (!(ptr = R_NEW0 (RBinField))) {
		return NULL;
	}
	ptr->name = strdup (name);
	ptr->comment = (comment && *comment)? strdup (comment): NULL;
	ptr->format = (format && *format)? strdup (format): NULL;
	ptr->paddr = paddr;
	ptr->size = size;
//	ptr->visibility = ???
	ptr->vaddr = vaddr;
	return ptr;
}

// use void* to honor the RListFree signature
R_API void r_bin_field_free(void *_field) {
	RBinField *field = (RBinField*) _field;
	free (field->name);
	free (field->comment);
	free (field->format);
	free (field);
}

R_API const char *r_bin_get_meth_flag_string(ut64 flag, bool compact) {
	switch (flag) {
	case R_BIN_METH_CLASS:
		return compact ? "c" : "class";
	case R_BIN_METH_STATIC:
		return compact ? "s" : "static";
	case R_BIN_METH_PUBLIC:
		return compact ? "p" : "public";
	case R_BIN_METH_PRIVATE:
		return compact ? "P" : "private";
	case R_BIN_METH_PROTECTED:
		return compact ? "r" : "protected";
	case R_BIN_METH_INTERNAL:
		return compact ? "i" : "internal";
	case R_BIN_METH_OPEN:
		return compact ? "o" : "open";
	case R_BIN_METH_FILEPRIVATE:
		return compact ? "e" : "fileprivate";
	case R_BIN_METH_FINAL:
		return compact ? "f" : "final";
	case R_BIN_METH_VIRTUAL:
		return compact ? "v" : "virtual";
	case R_BIN_METH_CONST:
		return compact ? "k" : "const";
	case R_BIN_METH_MUTATING:
		return compact ? "m" : "mutating";
	case R_BIN_METH_ABSTRACT:
		return compact ? "a" : "abstract";
	case R_BIN_METH_SYNCHRONIZED:
		return compact ? "y" : "synchronized";
	case R_BIN_METH_NATIVE:
		return compact ? "n" : "native";
	case R_BIN_METH_BRIDGE:
		return compact ? "b" : "bridge";
	case R_BIN_METH_VARARGS:
		return compact ? "g" : "varargs";
	case R_BIN_METH_SYNTHETIC:
		return compact ? "h" : "synthetic";
	case R_BIN_METH_STRICT:
		return compact ? "t" : "strict";
	case R_BIN_METH_MIRANDA:
		return compact ? "A" : "miranda";
	case R_BIN_METH_CONSTRUCTOR:
		return compact ? "C" : "constructor";
	case R_BIN_METH_DECLARED_SYNCHRONIZED:
		return compact ? "Y" : "declared_synchronized";
	default:
		return NULL;
	}
}
