/* radare - LGPL - Copyright 2009-2014 - pancake, nibble */

// TODO: dlopen library and show address

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_list.h>
#include <r_bin.h>
#include <r_io.h>
#include <list.h>
#include "../config.h"

R_LIB_VERSION(r_bin);

#define DB a->sdb;
#define RBINLISTFREE(x) if(x){r_list_free(x);x=NULL;}

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS };

//static int r_bin_use_arch_from_plugin (RBin *bin);
static void get_strings_range(RBinFile *arch, RList *list, int min, ut64 from, ut64 to, ut64 scnrva);
static void delete_bin_items (RBinObject *o);
static void set_bin_items(RBin *bin, RBinPlugin *cp);
//static void r_bin_free_bin_files (RBin *bin);
//static void r_bin_file_free_it (RBinFile *a);
static void r_bin_file_free (RBinFile *a);
static void r_bin_free_items(RBin *bin);
static void r_bin_init(RBin *bin, int rawstr, ut64 baseaddr, ut64 loadaddr);


static void get_strings_range(RBinFile *arch, RList *list, int min, ut64 from, ut64 to, ut64 scnrva) {
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0;
	RBinString *ptr = NULL;
	char type = 'A';

	if (!arch->rawstr)
		if (!arch->curplugin || !arch->curplugin->info)
			return;
	if (arch->curplugin && min==0)
		min = arch->curplugin->minstrlen;
	if (min==0)
		min = 4; // defaults
	if (min <= 0)
		return;

	if (arch && arch->buf && (!to || to > arch->buf->length))
		to = arch->buf->length;
	if (to != 0 && (to<1 || to > 0xf00000)) {
		eprintf ("WARNING: bin_strings buffer is too big at 0x%08"PFMT64x"\n", from);
		return;
	}
	if (!arch->buf)
		return;
	if (to == 0 && arch->buf)
		to = arch->buf->length;
	if (arch->buf && arch->buf->buf)
	for (i = from; i < to; i++) {
		if ((IS_PRINTABLE (arch->buf->buf[i])) && \
				matches < R_BIN_SIZEOF_STRINGS-1) {
			str[matches] = arch->buf->buf[i];
			/* add support for wide char strings */
			if (arch->buf->buf[i+1]==0) {
				if (IS_PRINTABLE (arch->buf->buf[i+2])) {
					if (arch->buf->buf[i+3]==0) {
						i++;
						type = 'W';
					}
				}
			}
			matches++;
			continue;
		}
		/* check if the length fits in our request */
		if (matches >= min) {
			if (!(ptr = R_NEW (RBinString))) {
				eprintf ("Error allocating string\n");
				break;
			}
			str[matches] = '\0';
			ptr->offset = i-matches;
			if (scnrva) {
				ptr->rva = (ptr->offset+scnrva-from);
			} else {
				ptr->rva = ptr->offset;
			}
			//HACK if (scnrva) ptr->rva = ptr->offset-from+scnrva; else ptr->rva = ptr->offset;
			ptr->size = matches+1;
			ptr->length = ptr->size << ((type=='W')? 1:0);
			ptr->type = type;
			type = 'A';
			ptr->ordinal = ctr;
			// copying so many bytes here..
			memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
			ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
			//r_name_filter (ptr->string, R_BIN_SIZEOF_STRINGS-1);
			r_list_append (list, ptr);
			//if (!sdb_add (DB, 
			ctr++;
		}
		matches = 0;
	}
}

static int is_data_section(RBinFile *a, RBinSection *s) {
	RBinObject *o = a->o;
	if (strstr (o->info->bclass, "MACH0") && strstr (s->name, "_cstring")) // OSX
		return 1;
	if (strstr (o->info->bclass, "ELF") && strstr (s->name, "data") && !strstr (s->name, "rel")) // LINUX
		return 1;
#define X 1
#define ROW (4|2)
	if (strstr (o->info->bclass, "PE") && s->srwx & ROW && !(s->srwx&X) && s->size>0 )
		return 1;
	if (strstr (s->name, "_const")) // Rust
		return 1;
	return 0;
}

static RList* get_strings(RBinFile *a, int min) {
	int count = 0;
	RListIter *iter;
	RBinSection *section;
	RBinObject *o = a ? a->o : NULL;

	RList *ret = r_list_new ();
	if (!ret) {
		eprintf ("Error allocating array\n");
		return NULL;
	} else if (!o) {
		eprintf ("Error bin object unitialized\n");
		return ret;
	}
	ret->free = free;

	if (o->sections && !a->rawstr) {
		r_list_foreach (o->sections, iter, section) {
			if (is_data_section (a, section)) {
				count++;
				get_strings_range (a, ret, min,
					section->offset,
					section->offset+section->size,
					section->rva);
			}
		}
		if (r_list_empty (o->sections)) {
			int i, next = 0, from = 0, funn = 0, to = 0;
			ut8 *buf = a->buf->buf;
			for (i=0; i<a->buf->length; i++) {
				if (!buf[i] || IS_PRINTABLE (buf[i])) {
					if (buf[i]) {
						if (!from) from = i;
						funn++;
						next = 0;
					}
				} else {
					next++;
					if (next>5) from = 0;
					if (!to) to = i;
					to = i;
					if (from && next==5 && funn>16) {
						get_strings_range (a, ret, min, from, to, 0);
				//eprintf ("FUNN %d\n", funn);
				//eprintf ("MIN %d %d\n", from, to);
						funn = 0;
						from = 0;
						to = 0;
					}
				}
			}
		}
	} else {
		get_strings_range (a, ret, min,
			0, a->size, 0);
	}
	return ret;
}

R_API int r_bin_load_languages(RBin *bin) {
	if (r_bin_lang_objc (bin))
		return R_BIN_NM_OBJC;
	if (r_bin_lang_cxx (bin))
		return R_BIN_NM_CXX;
	return R_BIN_NM_NONE;
}

R_API void r_bin_update_items(RBin *bin, RBinPlugin *cp) {
	RBinFile *binfile = bin->cur;
	if (binfile) {
		delete_bin_items (binfile->o);
		set_bin_items (bin, cp);
	}
}

static void delete_bin_items (RBinObject *o) {
	if (!o) return;
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

	free (o->info);

	o->baddr = 0;
	o->boffset = 0;
	o->size = 0;

	ut32 i = 0;
	for (i=0; i<R_BIN_SYM_LAST; i++){
		free (o->binsym[i]);
		o->binsym[i] = NULL;
	}
	o->entries = NULL;
	o->fields = NULL;
	o->imports = NULL;
	o->info = NULL;
	o->libs = NULL;
	o->relocs = NULL;
	o->sections = NULL;
	o->strings = NULL;
	o->symbols = NULL;
	o->classes = NULL;
	o->lines = NULL;
	o->lang = 0;
}

static void set_bin_items(RBin *bin, RBinPlugin *cp) {
	RBinFile *a = bin->cur;
	RBinObject *o = a->o;
	int i, minlen = bin->minstrlen;

	if (cp->baddr) o->baddr = cp->baddr (a);
	if (cp->boffset) o->boffset = cp->boffset (a);
	// XXX: no way to get info from xtr pluginz?
	if (cp->size) o->size = cp->size (a);
	if (cp->binsym)
		for (i=0; i<R_BIN_SYM_LAST; i++)
			o->binsym[i] = cp->binsym (a, i);
	if (cp->entries) o->entries = cp->entries (a);
	if (cp->fields) o->fields = cp->fields (a);
	if (cp->imports) o->imports = cp->imports (a);
	o->info = cp->info? cp->info (a): NULL;
	if (cp->libs) o->libs = cp->libs (a);
	if (cp->relocs) o->relocs = cp->relocs (a);
	if (cp->sections) o->sections = cp->sections (a);
	if (cp->strings) o->strings = cp->strings (a);
	else o->strings = get_strings (a, minlen);
	if (cp->symbols) o->symbols = cp->symbols (a);
	if (cp->classes) o->classes = cp->classes (a);
	if (cp->lines) o->lines = cp->lines (a);
	o->lang = r_bin_load_languages (bin);
}

R_API int r_bin_io_load(RBin *bin, RIO *io, RIODesc *desc, ut64 baseaddr, ut64 loadaddr, int dummy) {
	RBinFile *a;
	RListIter *it;
	ut8* buf_bytes;
	char fdkey[128];
	RBinXtrPlugin *xtr;
	RBinPlugin *any, *plugin;
	ut64 start, end, sz = UT64_MAX;
	RBinFile *binfile = NULL;
	RBinObject *o = NULL;

	if (!desc || !desc->plugin || !desc->plugin->read || !desc->plugin->lseek)
		return R_FALSE;

	buf_bytes = NULL;
	end = desc->plugin->lseek (io, desc, 0, SEEK_END);
	start = desc->plugin->lseek (io, desc, 0, SEEK_SET);

	if (end == UT64_MAX || start == UT64_MAX)
		return R_FALSE;

	sz = end - start;
	if (sz>(64*1024*1024)) // too big, probably wrong
		return R_FALSE;
	buf_bytes = malloc (sz);

	if (!buf_bytes || !desc->plugin->read (io, desc, buf_bytes, sz)) {
		free (buf_bytes);
		return R_FALSE;
	}

	binfile = R_NEW0 (RBinFile);
	bin->cur = binfile;
	binfile->file = strdup (desc->name);
	binfile->buf = r_buf_new ();
	binfile->rawstr = 0;
	snprintf (fdkey, sizeof (fdkey)-1, "fd.%i", desc->fd);
	binfile->sdb = sdb_ns (bin->sdb, fdkey);
	binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo");
	bin->file = desc->name;

	if (binfile->buf)
		r_buf_set_bytes (binfile->buf, buf_bytes, sz);
	free (buf_bytes);

	// Here is the pertinent code from r_bin_init
	// we can't call r_bin_init, because it will
	// deref all work done previously by IO Plugin.
	o = binfile->o = R_NEW0 (RBinObject);

	// XXX - probably not the best mechanism but its better
	o->loadaddr = loadaddr;
	o->baddr = baseaddr;

	r_list_foreach (bin->binxtrs, it, xtr) {
		if (xtr->check && xtr->check (bin)) {
			binfile->curxtr = xtr;
			break;
		}
	}
	if (binfile->curxtr && binfile->curxtr->load)
		binfile->curxtr->load (bin);

	a = binfile;
	a->curplugin = NULL;

	r_list_foreach (bin->plugins, it, plugin) {
		if (strncmp (plugin->name, "any", 5)==0) any = plugin;
		if ((dummy && !strncmp (plugin->name, "any", 5)) ||
			(!dummy && (plugin->check && plugin->check (a)))) {
			a->curplugin = plugin;
			break;
		}
	}

	if (a->curplugin == NULL)
		a->curplugin = any;

	if (a->curplugin && a->curplugin->minstrlen)
		bin->minstrlen = a->curplugin->minstrlen;

	if (a->curplugin && a->curplugin->load) {
		if (! a->curplugin->load (a) )
			return R_FALSE;
		set_bin_items (bin, a->curplugin);
	}

	o->referenced ++;
	r_list_append (bin->binfiles, binfile);
	return R_TRUE;
}

R_API int r_bin_init_items(RBin *bin, int dummy) {
	int minlen = bin->minstrlen;
	RListIter *it;
	RBinPlugin *plugin, *cp = NULL;
	RBinFile *binfile = bin->cur;
	RBinObject *o = binfile ? binfile->o : NULL;

	if (!binfile) {
		// XXX - dont remember if i need to set this in case of a failed load.
		/*
		bin->cur = R_NEW0 (RBinFile);
		binfile->o = R_NEW0 (RBinObject);
		binfile->file = strdup (bin->file);
		*/
		return R_FALSE;
	}

	o = binfile->o;
	cp = binfile->curplugin = NULL;

	r_list_foreach (bin->plugins, it, plugin) {
		if ((dummy && !strncmp (plugin->name, "any", 5)) ||
			(!dummy && (plugin->check && plugin->check (binfile)))) {
			binfile->curplugin = plugin;
			break;
		}
	}
	cp = binfile->curplugin;
	if (minlen<=0) {
		if (cp && cp->minstrlen)
			bin->minstrlen = cp->minstrlen;
		else bin->minstrlen = -minlen;
	}
	if (!cp || !cp->load || !cp->load (binfile)) {
		// already freed in format/pe/pe.c:r_bin_pe_free()
		// r_buf_free (binfile->buf);
		if (!binfile->buf){
			binfile->buf = r_buf_mmap (binfile->file, 0);
			binfile->fd = binfile->buf->mmap->fd;
			binfile->size = binfile->buf ? binfile->buf->length: 0;
		}
		o->strings = get_strings (binfile, minlen);
		return R_FALSE;
	}
	set_bin_items (bin, cp);
	return R_TRUE;
}

static int remove_bin_file_by_binfile (RBin *bin, RBinFile * binfile) {
	RListIter *iter;
	RBinFile *tmp_binfile = NULL;
	int found_bin = R_FALSE;
	r_list_foreach (bin->binfiles, iter, tmp_binfile) {
		if (tmp_binfile == binfile) {
			r_list_delete (bin->binfiles, iter);
			found_bin = R_TRUE;
			break;
		}
	}
	return found_bin;
}

#if 0
static void r_bin_free_bin_files (RBin *bin) {
	RListIter *iter, *t_iter;
	RBinFile *a;
	r_list_foreach_safe (bin->binfiles, iter, t_iter, a) {
		r_bin_file_free (a);
		r_list_delete(bin->binfiles,iter);
	}
}
#endif


R_API int r_bin_file_deref_by_bind (RBinBind * binb) {
	RBin *bin = binb ? binb->bin : NULL;
	RBinFile *a = bin ? bin->cur : NULL;
	return r_bin_file_deref (bin, a);
}

R_API int r_bin_file_deref (RBin *bin, RBinFile * a) {
	RBinObject *o = a ? a->o : NULL;
	int res = R_FALSE;
	if (a && !o) {
		r_bin_file_free (a);
		res = R_TRUE;
	} else if (a && o->referenced-1 < 1) {
		r_bin_file_free (a);
		res = R_TRUE;
	// not thread safe
	} else if (o) o->referenced--;
	// it is possible for a file not
	// to be bound to RBin and RBinFiles
	// XXX - is this an ok assumption?
	if (bin) bin->cur = NULL;
	return res;
}

R_API int r_bin_file_ref_by_bind (RBinBind * binb) {
	RBin *bin = binb ? binb->bin : NULL;
	RBinFile *a = bin ? bin->cur : NULL;
	return r_bin_file_ref (bin, a);
}

R_API int r_bin_file_ref (RBin *bin, RBinFile * a) {
	RBinObject *o = a ? a->o : NULL;
	int res = R_FALSE;
	if (!a) return R_FALSE;
	if (o) {
		o->referenced--;
		res = R_TRUE;
	}
	return res;
}

static void r_bin_file_free (RBinFile *a) {
	RBinObject *o = a->o;
	delete_bin_items (o);

	if (a->curplugin && a->curplugin->destroy)
		a->curplugin->destroy (a);
	else if (a->buf)
		r_buf_free (a->buf);

	free (a->file);
	memset (a, 0, sizeof (RBinFile));
}

// XXX - This is called on everytime a new bin created

static void r_bin_free_items(RBin *bin) {
	int i;
	RBinFile *a = bin->cur;
	RBinObject *o = a->o;
	remove_bin_file_by_binfile (bin, a);
	RBINLISTFREE (o->entries);
	RBINLISTFREE (o->fields);
	RBINLISTFREE (o->imports);
	RBINLISTFREE (o->libs);
	RBINLISTFREE (o->relocs);
	RBINLISTFREE (o->sections);
	RBINLISTFREE (o->strings);
	RBINLISTFREE (o->symbols);
	RBINLISTFREE (o->classes);
	free (o->info);
	o->info = NULL;
	for (i=0; i<R_BIN_SYM_LAST; i++){
		free (o->binsym[i]);
		o->binsym[i] = NULL;
	}
	if (a->curplugin && a->curplugin->destroy)
		a->curplugin->destroy (a);
	else free (a->buf);

	free (a->file);
	memset (a, 0, sizeof(RBinFile));
	free (o);
	bin->cur = NULL;
}

static void r_bin_init(RBin *bin, int rawstr, ut64 baseaddr, ut64 loadaddr) {
	RListIter *it;
	RBinXtrPlugin *xtr;
	RBinFile *binfile = bin->cur;
	RBinObject *o = binfile? binfile->o : NULL;

	// XXX - this is probably incorrect if multiple files will be loaded
	if (binfile && binfile->o) {
		//if (!o->referenced)
		//r_bin_free_items (bin);
		r_bin_file_free (binfile);
	}

	binfile = bin->cur = R_NEW0 (RBinFile);
	binfile->file = strdup (bin->file);
	o = binfile->o = R_NEW0 (RBinObject);
	o->loadaddr = loadaddr;
	o->baddr = baseaddr;

	binfile->curxtr = NULL;
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (xtr->check && xtr->check (bin)) {
			binfile->curxtr = xtr;
			break;
		}
	}
	if (binfile->curxtr && binfile->curxtr->load)
		binfile->curxtr->load (bin);
	binfile->rawstr = rawstr;
}

static int r_bin_load_file_data(RBin *bin, int idx) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	if (!binfile)
		return R_FALSE;
	if (binfile->curxtr && binfile->curxtr->extract)
		return binfile->curxtr->extract (bin, idx);
	//if (!binfile)
	//	return R_FALSE;
	binfile->file = strdup (bin->file);
	binfile->buf = r_buf_mmap (bin->file, 0);
	if (binfile->buf && binfile->buf->mmap)
		binfile->fd = binfile->buf->mmap->fd;
	else binfile->fd = r_num_rand (100);
	return R_TRUE;
}

R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	RListIter *it;
	RBinPlugin *plugin;
	if (foo->init)
		foo->init (bin->user);
	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, foo->name))
			return R_FALSE;
	}
	plugin = R_NEW0 (RBinPlugin);
	memcpy (plugin, foo, sizeof (RBinPlugin));
	r_list_append (bin->plugins, plugin);
	return R_TRUE;
}

R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	RListIter *it;
	RBinXtrPlugin *xtr;

	if (foo->init)
		foo->init (bin->user);

	// avoid duplicates
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (!strcmp (xtr->name, foo->name))
			return R_FALSE;
	}
	r_list_append (bin->binxtrs, foo);

	return R_TRUE;
}

R_API void* r_bin_free(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	if (!bin) return NULL;
	bin->file = NULL;
	//r_bin_free_bin_files (bin);
	sdb_free (bin->sdb);
	// TODO: unset related sdb namespaces
	if (binfile && binfile->sdb_addrinfo) {
		sdb_free (binfile->sdb_addrinfo);
		binfile->sdb_addrinfo = 0;
	}
	r_list_free (bin->binfiles);
	if (bin->cur && binfile->curxtr && binfile->curxtr->destroy)
		binfile->curxtr->destroy (bin);
	r_list_free (bin->binxtrs);
	r_list_free (bin->plugins);
	free (bin);
	return NULL;
}

R_API int r_bin_list(RBin *bin) {
	RListIter *it;
	RBinXtrPlugin *bp;
	RBinXtrPlugin *bx;
	r_list_foreach (bin->plugins, it, bp) {
		printf ("bin  %-11s %s (%s)\n",
			bp->name, bp->desc, bp->license);
	}
	r_list_foreach (bin->binxtrs, it, bx) {
		printf ("xtr  %-11s %s (%s)\n", bx->name,
			bx->desc, bx->license);
	}
	return R_FALSE;
}

R_API int r_bin_load(RBin *bin, const char *file, ut64 baseaddr, ut64 loadaddr, int dummy) {
	int res = 0;
	char fdkey[128];
	RBinFile *binfile = bin ? bin->cur : NULL;

	if (!bin || !file)
		return R_FALSE;

	bin->file = r_file_abspath (file);
	if (!binfile) binfile = bin->cur = R_NEW0 (RBinFile);

	r_bin_init (bin, binfile->rawstr, baseaddr, loadaddr);
	bin->narch = r_bin_load_file_data (bin, 0);
	// bin->cur can be changed
	binfile = bin->cur;
	if (bin->narch == 0)
		return R_FALSE;
	// XXX necessary because ?.  Regressions fail without this check
	if (binfile->buf == NULL) return R_FALSE;
	res = r_bin_init_items (bin, dummy);

	if (binfile && binfile->o) binfile->o->referenced += 1;

	snprintf (fdkey, sizeof (fdkey)-1, "fd.%i", binfile->fd);
	binfile->sdb = sdb_ns (bin->sdb, fdkey);
	binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo");
	// ----XXXX----XXXX---XXXX----
	// XXX: this function destroys all contents of RBinFile.. which is very bad.
	// we need a way to list all archs without destroying the data inside
	// ----XXXX----XXXX---XXXX----
	//  r_bin_list_archs (bin, 0);
	// the following line is just a hack for testing
	sdb_set (binfile->sdb, "archs", "0:0:x86:32", 0);
	r_list_append (bin->binfiles, bin->cur);
	return res;
}

R_API ut64 r_bin_get_baddr(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return binfile->o->baddr;
	return 0LL;
}

R_API void r_bin_set_baddr(RBin *bin, ut64 baddr) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o) {
		o->baddr = baddr;
		// XXX - update all the infos?
	}
}

R_API ut64 r_bin_get_boffset(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->boffset;
	return UT64_MAX;
}

R_API RBinAddr* r_bin_get_sym(RBin *bin, int sym) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (sym<0 || sym>=R_BIN_SYM_LAST)
		return NULL;
	if (o)
		return o->binsym[sym];
	return NULL;
}

// XXX: those accessors are redundant
R_API RList* r_bin_get_entries(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->entries;
	return NULL;
}

R_API RList* r_bin_get_fields(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->fields;
	return NULL;
}

R_API RList* r_bin_get_imports(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->imports;
	return NULL;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (!o)
		return NULL;
	return o->info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->libs;
	return NULL;
}

R_API RList* r_bin_get_relocs(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->relocs;
	return NULL;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->sections;
	return NULL;
}

R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o) {
		o = binfile->o;
		r_list_foreach (o->sections, iter, section) {
			from = va ? o->baddr+section->rva : section->offset;
			to = va ? o->baddr+section->rva+section->vsize :
					  section->offset + section->size;
			if (off >= from && off < to)
				return section;
		}
	}
	return NULL;
}

R_API RList* r_bin_reset_strings(RBin *bin) {
	RBinFile *a = bin ? bin->cur : NULL;
	RBinObject *o = a ? a->o : NULL;
	if (!o) return NULL;
	if (o->strings) {
		r_list_destroy (o->strings);
		o->strings = NULL;
	}

	if (bin->minstrlen <= 0)
		return NULL;

	if (a->curplugin && a->curplugin->strings)
		o->strings = a->curplugin->strings (a);
	else o->strings = get_strings (a, bin->minstrlen);
	return o->strings;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->strings;
	return NULL;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->symbols;
	return NULL;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->info->big_endian;
	return R_FALSE;
}

R_API int r_bin_is_stripped (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return R_BIN_DBG_STRIPPED (o->info->dbg_info);
	return 1;
}

R_API int r_bin_is_static (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o && r_list_length (o->libs)>0)
		return R_FALSE;
	return R_BIN_DBG_STATIC (o->info->dbg_info);
}

// TODO: Integrate with r_bin_dbg */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return R_BIN_DBG_LINENUMS (o->info->dbg_info);
	return R_FALSE;
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return R_BIN_DBG_SYMS (o->info->dbg_info);
	return R_FALSE;
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
	return R_BIN_DBG_RELOCS (o->info->dbg_info);
	return R_FALSE;
}

R_API RBin* r_bin_new() {
	int i;
	RBinXtrPlugin *static_xtr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) return NULL;
	bin->sdb = sdb_new0 ();
	bin->printf = (PrintfCallback)printf;
	bin->plugins = r_list_new();
	bin->plugins->free = free;
	bin->minstrlen = -2;
	bin->cur = NULL;//R_NEW0 (RBinFile);
	//binfile->o = NULL;
#if 0
R_NEW0 (RBinObject);
	snprintf (fdkey, sizeof (fdkey)-1, "fd.%d", binfile->fd);
	binfile->sdb = sdb_ns (bin->sdb, fdkey);
	binfile->sdb_addrinfo = sdb_ns (binfile->sdb, "addrinfo");
#endif
	bin->binfiles = r_list_newf ((RListFree)r_bin_file_free);
	for (i=0; bin_static_plugins[i]; i++) {
		r_bin_add (bin, bin_static_plugins[i]);
	}
	bin->binxtrs = r_list_new ();
	bin->binxtrs->free = free;
	for (i=0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW (RBinXtrPlugin);
		*static_xtr_plugin = *bin_xtr_static_plugins[i];
		r_bin_xtr_add (bin, static_xtr_plugin);
	}
	return bin;
}

#if 0
/* arch and bits are implicit in the plugin name, do we really need
 * to overwrite binfile->info? */
static int r_bin_use_arch_from_plugin (RBin *bin) {
	RBinPlugin *cp = NULL;
	int res = R_TRUE;
	if (!bin || !bin->cur || !binfile->o || !binfile->curplugin) return R_FALSE;
	cp = binfile->curplugin;

	if (cp->info) o->info = cp->info (bin->cur);
	else res = r_bin_use_arch(bin, "TEMP_FAIL", 32, cp->name);
	return res;
}
#endif

R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	RListIter *it;
	RBinPlugin *plugin;

	if (!o) return R_FALSE;
	if (!o->info) o->info = R_NEW0 (RBinInfo);
	else memset (o->info, 0, sizeof (RBinInfo));

	strncpy (o->info->arch, arch, R_BIN_SIZEOF_STRINGS);
	o->info->bits = bits;

	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (name, plugin->name)) {
			binfile->curplugin = plugin;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// DUPDUPDUP
// XXX - whats the purpose of this function, and can it be refactored out or
// combined with the r_bin_load functions.   Or do we need a separate loader
// for binaries that carry multi-architecture?
R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	int i;
	RBinInfo *info;
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;

	if (!o) return R_FALSE;
	//if (bin->narch >1) // fix double load when no multiarch bin is loaded
	for (i=0; i<bin->narch; i++) {
		r_bin_select_idx (bin, i);
		info = o->info;
		if (!info || !binfile->file ||
			(arch && !strstr (info->arch, arch)) ||
			(bits && bits != info->bits) ||
			(name && !strstr (info->file, name)))
			continue;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bin_select_idx(RBin *bin, int idx) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;

	if (!o) return R_FALSE;

	ut64 baseaddr = o->baddr,
		 loadaddr = o->loadaddr;
	int rawstr = binfile->rawstr;
	// XXX - this is a messy process, and it needs to be fixed
	// free the current bin, and then init the bin for reload
	r_bin_free_items (bin);
	r_bin_init (bin, rawstr, baseaddr, loadaddr);
	if (binfile->curxtr && binfile->curxtr->extract) {
		if (r_bin_load_file_data (bin, idx))
			return r_bin_init_items (bin, R_FALSE);
	}
	return r_bin_init_items (bin, R_FALSE);
}

R_API void r_bin_list_archs(RBin *bin, int mode) {
#undef DB
#define KEY "archs"
	int i;
	char archline[128];
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;

	if (!o) return ;

	RBinInfo *info = o->info;
	Sdb *DB = binfile->sdb;
	if (!DB) {
		eprintf ("Cannot find SDB!\n");
		return;
	}
	sdb_unset (DB, KEY, 0);
	for (i = 0; i < bin->narch; i++) {
		int many = r_bin_select_idx (bin, i);
		if (many) {
			info = o->info;
			if (mode)
				printf ("%03i 0x%08"PFMT64x" %d %s_%i %s\n", i,
					binfile->offset, binfile->size, info->arch,
					info->bits, info->machine);
			snprintf (archline, sizeof (archline)-1,
				"0x%08"PFMT64x":%d:%s:%d:%s",
				 binfile->offset,
				 binfile->size,
				 info->arch,
				 info->bits,
				 info->machine);
			/// xxx machine not exported?
			sdb_array_push (DB, KEY, archline, 0);
		} else {
			if (info) {
				if (mode)
					printf ("%03i 0x%08"PFMT64x" %d %s_%d\n", i,
						binfile->offset, binfile->size,
						info->arch, info->bits);
				snprintf (archline, sizeof (archline),
					"0x%08"PFMT64x":%d:%s:%d",
					 binfile->offset,
					 binfile->size,
					 info->arch,
					 info->bits);
			} else {
				if (mode)
					printf ("%03i 0x%08"PFMT64x" %d unk_0\n", i,
						binfile->offset, binfile->size);
				snprintf (archline, sizeof (archline),
					"0x%08"PFMT64x":%d:%s:%d",
					 binfile->offset,
					 binfile->size,
					 "unk", 0);
			}
			sdb_array_push (DB, KEY, archline, 0);
		}
	}
	//r_bin_select_idx (bin, 0);
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static int getoffset (RBin *bin, int type, int idx) {
	RBinFile *a = bin->cur;
	if (a && a->curplugin && a->curplugin->get_offset)
		return a->curplugin->get_offset (a, type, idx);
	return -1;
}

static const char *getname (RBin *bin, int off) {
	// walk symbols, find index, return name, ignore offset wtf
	return NULL;
}

R_API void r_bin_bind (RBin *bin, RBinBind *b) {
	if (b) {
		b->bin = bin;
		b->get_offset = getoffset;
		b->get_name = getname;
	}
}

R_API RBuffer *r_bin_create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBinFile *a = bin->cur;
	if (codelen<0) codelen = 0;
	if (datalen<0) datalen = 0;
	if (a && a->curplugin && a->curplugin->create)
		return a->curplugin->create (bin, code, codelen, data, datalen);
	return NULL;
}

R_API RBinObject *r_bin_get_object(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o) o->referenced++;
	return o;
}

R_API void r_bin_object_free(RBinObject *obj) {
	free (obj);
}

R_API RList* /*<RBinClass>*/r_bin_get_classes(RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o)
		return o->classes;
	return NULL;
}

R_API RBinClass *r_bin_class_new (RBin *bin, const char *name, const char *super, int view) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	RList *list = NULL;
	RBinClass *c;
	if (!o)
		return NULL;

	list = o->classes;
	if (!name) return NULL;
	c = r_bin_class_get (bin, name);
	if (c) {
		if (super) {
			free (c->super);
			c->super = strdup (super);
		}
		return c;
	}
	c = R_NEW0 (RBinClass);
	if (!c) return NULL;
	c->name = strdup (name);
	c->super = super? strdup (super): NULL;
	c->index = r_list_length (list);
	c->methods = r_list_new ();
	c->fields = r_list_new ();
	c->visibility = view;
	if (!list)
		list = o->classes = r_list_new ();
	r_list_append (list, c);
	return c;
}

R_API RBinClass *r_bin_class_get (RBin *bin, const char *name) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	RList *list = NULL;
	RListIter *iter;
	RBinClass *c;
	
	if (!o) return NULL;
	list = o->classes;
	r_list_foreach (list, iter, c) {
		if (!strcmp (c->name, name))
			return c;
	}
	return NULL;
}

R_API int r_bin_class_add_method (RBin *bin, const char *classname, const char *name, int nargs) {
	RBinClass *c = r_bin_class_get (bin, classname);
	char *n = strdup (name);
	if (c) {
		r_list_append (c->methods, (void*)n);
		return R_TRUE;
	}
	c = r_bin_class_new (bin, classname, NULL, 0);
	r_list_append (c->methods, (void*)n);
	return R_FALSE;
}

R_API void r_bin_class_add_field (RBin *bin, const char *classname, const char *name) {
#warning TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

R_API ut64 r_bin_get_offset (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	if (binfile) return binfile->offset;
	return UT64_MAX;
}

R_API ut64 r_bin_get_vaddr (RBin *bin, ut64 baddr, ut64 paddr, ut64 vaddr) {
	ut32 delta;
	RBinPlugin *cp = NULL;
	RBinFile *binfile = bin ? bin->cur : NULL;

	if (!binfile) return UT64_MAX;
	cp = binfile->curplugin;
	if (cp && cp->get_vaddr)
		return cp->get_vaddr (bin->cur, baddr, paddr, vaddr);
	if (!baddr) return vaddr;
 	delta = (paddr & 0xfffff000) | (vaddr & 0xfff);
	return baddr + delta;
}

R_API ut64 r_bin_get_size (RBin *bin) {
	RBinFile *binfile = bin ? bin->cur : NULL;
	RBinObject *o = binfile ? binfile->o : NULL;
	if (o) return o->size;
	return UT64_MAX;
}

R_API RBinFile * r_bin_file_find_by_fd (RBin *bin, ut64 bin_fd) {
	RListIter *iter;
	RBinFile *bf = NULL;

	if (!bin) return bf;
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->fd == bin_fd) break;
		bf = NULL;
	}
	return bf;
}

R_API RBinFile * r_bin_file_find_by_name (RBin * bin, const char * name) {
	RListIter *iter;
	RBinFile *bf = NULL;

	if (!bin) return bf;
	r_list_foreach (bin->binfiles, iter, bf) {
		if (bf && bf->file && !strcmp (bf->file, name)) break;
		bf = NULL;
	}
	return bf;
}

R_API int r_bin_file_set_cur_by_fd (RBin * bin, ut64 bin_fd) {
	RBinFile *bf = r_bin_file_find_by_fd (bin, bin_fd);

	if (bf) {
		bin->cur = bf;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bin_file_set_cur_by_name (RBin * bin, const char * name) {
	RBinFile *bf = r_bin_file_find_by_name (bin, name);

	if (bf) {
		bin->cur = bf;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API RBinFile * r_bin_cur (RBin *bin) {
	if (bin) return bin->cur;
	return NULL;
}
