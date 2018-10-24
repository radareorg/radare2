/* radare2 - LGPL - Copyright 2009-2018 - pancake, nibble, dso */

#include <r_bin.h>

// maybe too big sometimes? 2KB of stack eaten here..
#define R_STRING_SCAN_BUFFER_SIZE 2048
#define R_STRING_MAX_UNI_BLOCKS 4

static void print_string(RBinString *string, RBinFile *bf) {
	if (!string || !bf) {
		return;
	}
	int mode = bf->strmode;
	ut64 addr , vaddr;
	RBin *bin = bf->rbin;
	const char *section_name, *type_string;
	RIO *io = bin->iob.io;
	if (!io) {
		return;
	}
	RBinSection *s = r_bin_get_section_at (bf->o, string->paddr, false);
	if (s) {
		string->vaddr = s->vaddr + (string->paddr - s->paddr);
	}
	section_name = s ? s->name : "";
	type_string = r_bin_string_type (string->type);
	vaddr = addr = r_bin_get_vaddr (bin, string->paddr, string->vaddr);

	switch (mode) {
	case R_MODE_SIMPLE:
		io->cb_printf ("0x%08" PFMT64x " %s\n", addr, string->string);
		break;
	case R_MODE_RADARE: {
		char *f_name, *nstr;
		f_name = strdup (string->string);
		r_name_filter (f_name, 512);
		if (bin->prefix) {
			nstr = r_str_newf ("%s.str.%s", bin->prefix, f_name);
			io->cb_printf ("f %s.str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
					"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
					bin->prefix, f_name, string->size, addr,
					string->size, addr);
		} else {
			nstr = r_str_newf ("str.%s", f_name);
			io->cb_printf ("f str.%s %"PFMT64d" @ 0x%08"PFMT64x"\n"
					"Cs %"PFMT64d" @ 0x%08"PFMT64x"\n",
					f_name, string->size, addr,
					string->size, addr);
		}
		free (nstr);
		free (f_name);
		break;
	}
	case R_MODE_PRINT:
		io->cb_printf ("%03u 0x%08" PFMT64x " 0x%08" PFMT64x " %3u %3u "
			       "(%s) %5s %s\n",
			string->ordinal, string->paddr, vaddr,
			string->length, string->size,
			section_name, type_string, string->string);
		break;
	}
}

static int string_scan_range(RList *list, RBinFile *bf, int min,
			      const ut64 from, const ut64 to, int type) {
	ut8 tmp[R_STRING_SCAN_BUFFER_SIZE];
	ut64 str_start, needle = from;
	int count = 0, i, rc, runes;
	int str_type = R_STRING_TYPE_DETECT;

	if (type == -1) {
		type = R_STRING_TYPE_DETECT;
	}
	if (from >= to) {
		eprintf ("Invalid range to find strings 0x%"PFMT64x" .. 0x%"PFMT64x"\n", from, to);
		return -1;
	}
	int len = to - from;
	ut8 *buf = calloc (len, 1);
	if (!buf || !min) {
		free (buf);
		return -1;
	}
	r_buf_read_at (bf->buf, from, buf, len);
	// may oobread
	while (needle < to) {
		rc = r_utf8_decode (buf + needle - from, to - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (type == R_STRING_TYPE_DETECT) {
			char *w = (char *)buf + needle + rc - from;
			if ((to - needle) > 5 + rc) {
				bool is_wide32 = (needle + rc + 2 < to) && (!w[0] && !w[1] && !w[2] && w[3] && !w[4]);
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
				rc = r_utf32le_decode (buf + needle - from, to - needle, &r);
				if (rc) {
					rc = 4;
				}
			} else if (str_type == R_STRING_TYPE_WIDE) {
				rc = r_utf16le_decode (buf + needle - from, to - needle, &r);
				if (rc == 1) {
					rc = 2;
				}
			} else {
				rc = r_utf8_decode (buf + needle - from, to - needle, &r);
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

			if (r_isprint (r) && r != '\\') {
				if (str_type == R_STRING_TYPE_WIDE32) {
					if (r == 0xff) {
						r = 0;
					}
				}
				rc = r_utf8_encode (&tmp[i], r);
				runes++;
				/* Print the escape code */
			} else if (r && r < 0x100 && strchr ("\b\v\f\n\r\t\a\033\\", (char)r)) {
				if ((i + 32) < sizeof (tmp) && r < 93) {
					tmp[i + 0] = '\\';
					tmp[i + 1] = "       abtnvfr             e  "
					             "                              "
					             "                              "
					             "  \\"[r];
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
			// reduce false positives
			int j, num_blocks, *block_list;
			if (str_type == R_STRING_TYPE_ASCII) {
				for (j = 0; j < i; j++) {
					char ch = tmp[j];
					if (ch != '\n' && ch != '\r' && ch != '\t') {
						if (!IS_PRINTABLE (tmp[j])) {
							continue;
						}
					}
				}
			}
			switch (str_type) {
			case R_STRING_TYPE_UTF8:
			case R_STRING_TYPE_WIDE:
			case R_STRING_TYPE_WIDE32:
				num_blocks = 0;
				block_list = r_utf_block_list ((const ut8*)tmp, i - 1);
				if (block_list) {
					for (j = 0; block_list[j] != -1; j++) {
						num_blocks++;
					}
				}
				free (block_list);
				if (num_blocks > R_STRING_MAX_UNI_BLOCKS) {
					continue;
				}
			}
			RBinString *bs = R_NEW0 (RBinString);
			if (!bs) {
				break;
			}
			bs->type = str_type;
			bs->length = runes;
			bs->size = needle - str_start;
			bs->ordinal = count++;
			// TODO: move into adjust_offset
			switch (str_type) {
			case R_STRING_TYPE_WIDE:
				if (str_start -from> 1) {
					const ut8 *p = buf + str_start - 2 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 2; // \xff\xfe
					}
				}
				break;
			case R_STRING_TYPE_WIDE32:
				if (str_start -from> 3) {
					const ut8 *p = buf + str_start - 4 - from;
					if (p[0] == 0xff && p[1] == 0xfe) {
						str_start -= 4; // \xff\xfe\x00\x00
					}
				}
				break;
			}
			bs->paddr = bs->vaddr = str_start;
			bs->string = r_str_ndup ((const char *)tmp, i);
			if (list) {
				r_list_append (list, bs);
			} else {
				print_string (bs, bf);
				r_bin_string_free (bs);
			}
		}
	}
	free (buf);
	return count;
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

R_API RList *r_bin_classes_from_symbols(RBinFile *bf, RBinObject *o) {
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

R_API RBinFile *r_bin_file_new(RBin *bin, const char *file, const ut8 *bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr) {
	RBinFile *binfile = R_NEW0 (RBinFile);
	if (!binfile) {
		return NULL;
	}
	// TODO: use r_id_storage api
	if (!r_id_pool_grab_id (bin->ids->pool, &binfile->id)) {
		if (steal_ptr) { // we own the ptr, free on error
			free ((void*) bytes);
		}
		free (binfile);		//no id means no binfile
		return NULL;
	}
	int res = r_bin_file_set_bytes (binfile, bytes, sz, steal_ptr);
	if (!res && steal_ptr) { // we own the ptr, free on error
		free ((void *)bytes);
	}
	binfile->rbin = bin;
	binfile->file = file ? strdup (file) : NULL;
	binfile->rawstr = rawstr;
	binfile->fd = fd;
	binfile->curxtr = xtrname ? r_bin_get_xtrplugin_by_name (bin, xtrname) : NULL;
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
		binfile->sdb = sdb_ns (sdb, sdb_fmt ("fd.%d", fd), 1);
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

R_API bool r_bin_file_object_new_from_xtr_data(RBin *bin, RBinFile *bf, ut64 baseaddr, ut64 loadaddr, RBinXtrData *data) {
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


R_API RBinFile *r_bin_file_new_from_fd(RBin *bin, int fd, RBinFileOptions *options) {
int file_sz = 0;
	RBinPlugin *plugin = NULL;
	RBinFile *bf = r_bin_file_create_append (bin, "-", NULL, 0, file_sz,
				       0, fd, NULL, false);
	if (!bf) {
		return NULL;
	}
	int loadaddr = options? options->laddr: 0;
	int baseaddr = options? options->baddr: 0;
	// int loadaddr = options? options->laddr: 0;
	bool binfile_created = true;
	r_buf_free (bf->buf);
	bf->buf = r_buf_new_with_io (&bin->iob, fd);
	if (bin->force) {
		plugin = r_bin_get_binplugin_by_name (bin, bin->force);
	}
	if (!plugin) {
		if (options && options->plugname) {
			plugin = r_bin_get_binplugin_by_name (bin, options->plugname);
		}
		if (!plugin) {
			ut8 bytes[1024];
			int sz = sizeof (bytes);
			r_buf_read_at (bf->buf, 0, bytes, sz);
			plugin = r_bin_get_binplugin_by_bytes (bin, bytes, sz);
			if (!plugin) {
				plugin = r_bin_get_binplugin_any (bin);
			}
		}
	}

	RBinObject *o = r_bin_object_new (bf, plugin, baseaddr, loadaddr, 0, r_buf_size (bf->buf));
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
#if 0
	/* WTF */
	if (strcmp (plugin->name, "any")) {
		bf->narch = 1;
	}
#endif
	/* free unnecessary rbuffer (???) */
	return bf;
}

R_API RBinFile *r_bin_file_new_from_bytes(RBin *bin, const char *file, const ut8 *bytes, ut64 sz, ut64 file_sz, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname, const char *xtrname, ut64 offset, bool steal_ptr) {
	ut8 binfile_created = false;
	RBinPlugin *plugin = NULL;
	RBinXtrPlugin *xtr = NULL;
	RBinObject *o = NULL;
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

	RBinFile *bf = r_bin_file_create_append (bin, file, bytes, sz, file_sz,
				       rawstr, fd, xtrname, steal_ptr);
	if (!bf) {
		if (!steal_ptr) { // we own the ptr, free on error
			free ((void*) bytes);
		}
		return NULL;
	}
	binfile_created = true;

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
#if 0
	/* WTF */
	if (strcmp (plugin->name, "any")) {
		bf->narch = 1;
	}
#endif
	/* free unnecessary rbuffer (???) */
	return bf;
}

R_API RBinFile *r_bin_file_find_by_arch_bits(RBin *bin, const char *arch, int bits, const char *name) {
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

R_API RBinObject *r_bin_file_object_find_by_id(RBinFile *binfile, ut32 binobj_id) {
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

R_API RBinFile *r_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id) {
	RListIter *iter;
	RBinFile *binfile;
	r_list_foreach (bin->binfiles, iter, binfile) {
		if (r_bin_file_object_find_by_id (binfile, binobj_id)) {
			return binfile;
		}
	}
	return NULL;
}

R_API RBinFile *r_bin_file_find_by_id(RBin *bin, ut32 binfile_id) {
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

R_API int r_bin_file_object_add(RBinFile *binfile, RBinObject *o) {
	if (!o) {
		return false;
	}
	r_list_append (binfile->objs, o);
	r_bin_file_set_cur_binfile_obj (binfile->rbin, binfile, o);
	return true;
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

R_API bool r_bin_file_set_cur_binfile_obj(RBin *bin, RBinFile *bf, RBinObject *obj) {
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
	return r_bin_file_set_cur_binfile_obj (bin, bf, obj);
}

R_API int r_bin_file_set_cur_by_name(RBin *bin, const char *name) {
	RBinFile *bf = r_bin_file_find_by_name (bin, name);
	return r_bin_file_set_cur_binfile (bin, bf);
}

R_API RBinObject *r_bin_file_object_get_cur(RBinFile *binfile) {
	return binfile? binfile->o: NULL;
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
	if (bin) {
		bin->cur = NULL;
	}
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

R_API void r_bin_file_free(void /*RBinFile*/ *bf_) {
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
	r_buf_free (a->buf);
	a->buf = NULL;
	if (a->curxtr && a->curxtr->destroy && a->xtr_obj) {
		a->curxtr->free_xtr ((void *)(a->xtr_obj));
	}
	// TODO: unset related sdb namespaces
	if (a && a->sdb_addrinfo) {
		sdb_free (a->sdb_addrinfo);
		a->sdb_addrinfo = NULL;
	}
	free (a->file);
	a->o = NULL;
	r_list_free (a->objs);
	r_list_free (a->xtr_data);
	r_buf_free (a->buf);
	if (a->id != -1) {
		// TODO: use r_storage api
		r_id_pool_kick_id (a->rbin->ids->pool, a->id);
	}
	free (a);
}

// This is an unnecessary piece of overengineering
R_API RBinFile *r_bin_file_create_append(RBin *bin, const char *file, const ut8 *bytes, ut64 sz, ut64 file_sz, int rawstr, int fd, const char *xtrname, bool steal_ptr) {
	RBinFile *bf = r_bin_file_new (bin, file, bytes, sz, file_sz, rawstr,
				       fd, xtrname, bin->sdb, steal_ptr);
	if (bf) {
		r_list_append (bin->binfiles, bf);
	}
	return bf;
}

// This function populate RBinFile->xtr_data, that information is enough to
// create RBinObject when needed using r_bin_file_object_new_from_xtr_data
R_API RBinFile *r_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr) {
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

#define LIMIT_SIZE 0
R_API bool r_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr) {
	if (!binfile) {
		return false;
	}
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

R_API RBinPlugin *r_bin_file_cur_plugin(RBinFile *binfile) {
	return binfile && binfile->o? binfile->o->plugin: NULL;
}

static int is_data_section(RBinFile *a, RBinSection *s) {
	if (s->has_strings || s->is_data) {
		return true;
	}
 	// Rust
	return strstr (s->name, "_const") != NULL;
}

R_API RList *r_bin_file_get_strings(RBinFile *a, int min, int dump, int raw) {
	RListIter *iter;
	RBinSection *section;
	RBinObject *o = a? a->o: NULL;
	RList *ret;

	if (dump) {
		/* dump to stdout, not stored in list */
		ret = NULL;
	} else {
		ret = r_list_newf (r_bin_string_free);
		if (!ret) {
			return NULL;
		}
	}
	if (!raw && o && o->sections && !r_list_empty (o->sections)) {
		r_list_foreach (o->sections, iter, section) {
			if (is_data_section (a, section)) {
				r_bin_file_get_strings_range (a, ret, min, raw, section->paddr,
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
				if (section->size > a->size) {
					continue;
				}
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
							RBinString *bs = R_NEW0 (RBinString);
							if (bs) {
								bs->type = s->type;
								bs->length = s->length;
								bs->size = s->size;
								bs->ordinal = s->ordinal;
								bs->paddr = bs->vaddr = cfstr_vaddr;
								bs->string = r_str_newf ("cstr.%s", s->string);
								r_list_append (ret, bs);
							}
							break;
						}
					}
				}
			}
		}
	} else {
		if (a) {
			r_bin_file_get_strings_range (a, ret, min, raw, 0, a->size);
		}
	}
	return ret;
}

R_API void r_bin_file_get_strings_range(RBinFile *bf, RList *list, int min, int raw, ut64 from, ut64 to) {
	RBinPlugin *plugin = r_bin_file_cur_plugin (bf);
	RBinString *ptr;
	RListIter *it;

	if (!bf || !bf->buf) {
		return;
	}
	if (!raw) {
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
	if (!to || to > bf->buf->length) {
		to = r_buf_size (bf->buf);
	}
	if (!to) {
		return;
	}
	if (raw != 2) {
		ut64 size = to - from;
		// in case of dump ignore here
		if (bf->rbin->maxstrbuf && size && size > bf->rbin->maxstrbuf) {
			if (bf->rbin->verbose) {
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
	if (string_scan_range (list, bf, min, from, to, -1) < 0) {
		return;
	}
	r_list_foreach (list, it, ptr) {
		RBinSection *s = r_bin_get_section_at (bf->o, ptr->paddr, false);
		if (s) {
			ptr->vaddr = s->vaddr + (ptr->paddr - s->paddr);
		}
	}
}

R_API ut64 r_bin_file_get_baddr(RBinFile *binfile) {
	return binfile? r_bin_object_get_baddr (binfile->o): UT64_MAX;
}
