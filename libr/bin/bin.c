/* radare - LGPL - Copyright 2009-2013 - pancake, nibble */

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

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS };

static void get_strings_range(RBinArch *arch, RList *list, int min, ut64 from, ut64 to, ut64 scnrva) {
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0;
	RBinString *ptr = NULL;

	if (!arch->rawstr)
		if (!arch->curplugin || !arch->curplugin->info)
			return;
	if (arch && arch->buf && (!to || to > arch->buf->length))
		to = arch->buf->length;
	if (to<1 || to > 0xf00000) {
		eprintf ("WARNING: bin_strings buffer is too big at 0x%08"PFMT64x"\n", from);
		return;
	}
	if (to == 0)
		to = arch->buf->length;
	if (arch->buf && arch->buf->buf)
	for (i = from; i < to; i++) { 
		if ((IS_PRINTABLE (arch->buf->buf[i])) && \
				matches < R_BIN_SIZEOF_STRINGS-1) {
			str[matches] = arch->buf->buf[i];
			/* add support for wide char strings */
			if (arch->buf->buf[i+1]==0) {
				if (IS_PRINTABLE (arch->buf->buf[i+2]))
					if (arch->buf->buf[i+3]==0)
						i++;
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
				ptr->rva = (ptr->offset-from+scnrva);
			} else {
				ptr->rva = ptr->offset;
			}
			//HACK if (scnrva) ptr->rva = ptr->offset-from+scnrva; else ptr->rva = ptr->offset;
			ptr->size = matches+1;
			ptr->ordinal = ctr;
			// copying so many bytes here..
			memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
			ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
			//r_name_filter (ptr->string, R_BIN_SIZEOF_STRINGS-1);
			r_list_append (list, ptr);
			ctr++;
		}
		matches = 0;
	}
}

static int is_data_section(RBinArch *a, RBinSection *s) {
	RBinObject *o = a->o;
	if (strstr (o->info->bclass, "MACH0") && strstr (s->name, "_cstring")) // OSX
		return 1;
	if (strstr (o->info->bclass, "ELF") && strstr (s->name, "data") && !strstr (s->name, "rel")) // LINUX
		return 1;
#define X 1
#define ROW (4|2)
	if (strstr (o->info->bclass, "PE") && s->srwx & ROW && !(s->srwx&X) )
		return 1;
	return 0;
}

static RList* get_strings(RBinArch *a, int min) {
	int count = 0;
	RListIter *iter;
	RBinSection *section;
	RList *ret = r_list_new ();
	if (!ret) {
		eprintf ("Error allocating array\n");
		return NULL;
	}
	ret->free = free;
	if (a->o->sections && !a->rawstr) {
		r_list_foreach (a->o->sections, iter, section) {
			if (is_data_section (a, section)) {
				count++;
				get_strings_range (a, ret, min,
					section->offset,
					section->offset+section->size,
					section->rva);
			}
		}	
		if (r_list_empty (a->o->sections)) {
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

static void set_bin_items(RBin *bin, RBinPlugin *cp) {

	RBinArch *a = &bin->cur;
	RBinObject *o = a->o;
	int i, minlen = bin->minstrlen;

	if (cp->baddr) o->baddr = cp->baddr (a);
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

R_API int r_bin_io_load(RBin *bin, RIO *io, RIODesc *desc, int dummy) {
	int rawstr = 0;
	RBuffer *bin_buf = NULL;
	ut64 start, end, 
		 sz = -1, 
		 offset = 0;
	
	ut8* buf_bytes;

	if (!io || !io->plugin || !io->plugin->read || !io->plugin->lseek) {
		return R_FALSE;
	} else if (!desc || !desc->fd) {
		return R_FALSE;
	}

	buf_bytes = NULL;
	end = io->plugin->lseek(io, desc, 0, SEEK_END);
	start = io->plugin->lseek(io, desc, 0, SEEK_SET);
	sz = -1;
	offset = 0;
	
	if (end == -1 || start == -1) return R_FALSE;

	sz = end - start;
	buf_bytes = malloc(sz);
	
	if (!buf_bytes || !io->plugin->read(io, desc, buf_bytes, sz)) {
		free(buf_bytes);
		return R_FALSE;
	}

	memcpy(&rawstr, buf_bytes, 4);
	bin->cur.file = strdup (desc->name);
	bin->cur.buf = bin_buf;			
	bin->cur.rawstr = rawstr;
		
	bin_buf = r_buf_new();
	if (bin_buf) {	
		r_buf_set_bytes(bin_buf, buf_bytes, sz);
	}

	if (buf_bytes)	free(buf_bytes);

	//r_config_set_i (r->config, "bin.rawstr", rawstr);
	bin->cur.file = strdup (desc->name);
	bin->cur.buf = bin_buf;			
	bin->cur.rawstr = rawstr;
	// Here is the pertinent code from r_bin_init
	// we can't call r_bin_init, because it will
	// deref all work done previously by IO Plugin.
	{
		RListIter *it;
		RBinXtrPlugin *xtr;
		bin->cur.o = R_NEW0 (RBinObject);
		memset (bin->cur.o, 0, sizeof (RBinObject));
		bin->curxtr = NULL;
		r_list_foreach (bin->binxtrs, it, xtr) {
			if (xtr->check && xtr->check (bin)) {
				bin->curxtr = xtr;
				break;
			}
		}
		if (bin->curxtr && bin->curxtr->load)
			bin->curxtr->load (bin);
	}

	{

		int i, minlen = bin->minstrlen;
		RListIter *it;
		RBinPlugin *any, *plugin, *cp = NULL;
		RBinArch *a = &bin->cur;
		RBinObject *o = a->o;
		a->curplugin = NULL;

		r_list_foreach (bin->plugins, it, plugin) {
			if ((dummy && !strncmp (plugin->name, "any", 5)) ||
				(!dummy && (plugin->check && plugin->check (a)))) {
				a->curplugin = plugin;
				break;
			}
		}

		a->buf = r_buf_new();
		r_buf_set_bytes(a->buf, bin->cur.buf->buf, bin->cur.buf->length);

		if (cp) set_bin_items(bin, cp);
	}

	return R_TRUE;
}

R_API int r_bin_init_items(RBin *bin, int dummy) {
	int i, minlen = bin->minstrlen;
	RListIter *it;
	RBinPlugin *plugin, *cp;
	RBinArch *a = &bin->cur;
	RBinObject *o = a->o;
	a->curplugin = NULL;

	r_list_foreach (bin->plugins, it, plugin) {
		if ((dummy && !strncmp (plugin->name, "any", 5)) ||
			(!dummy && (plugin->check && plugin->check (a)))) {
			a->curplugin = plugin;
			break;
		}
	}
	cp = a->curplugin;
	if (minlen<0) {
		if (cp && cp->minstrlen) 
			minlen = cp->minstrlen;
		else minlen = -minlen;
	}
	if (!cp || !cp->load || !cp->load (a)) {
		// already freed in format/pe/pe.c:r_bin_pe_free()
		// r_buf_free (a->buf);
		a->buf = r_buf_mmap (bin->cur.file, 0);
		a->size = a->buf? a->buf->length: 0;
		o->strings = get_strings (a, minlen);
		return R_FALSE;
	}
	set_bin_items(bin, cp);
	return R_TRUE;
}

#define RBINLISTFREE(x) if(x){r_list_free(x);x=NULL;}
static void r_bin_free_items(RBin *bin) {
	int i;
	RBinArch *a = &bin->cur;
	RBinObject *o = a->o;
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
	if (o->binsym)
		for (i=0; i<R_BIN_SYM_LAST; i++){
			free (o->binsym[i]);
			o->binsym[i] = NULL;
		}
	if (a->curplugin && a->curplugin->destroy)
		a->curplugin->destroy (a);
}

static void r_bin_init(RBin *bin, int rawstr) {
	RListIter *it;
	RBinXtrPlugin *xtr;

	if (bin->cur.o) {
		if (!bin->cur.o->referenced)
			r_bin_free_items (bin);
		free (bin->cur.file);
	}
	memset (&bin->cur, 0, sizeof (bin->cur));
	bin->cur.o = R_NEW0 (RBinObject);
	memset (bin->cur.o, 0, sizeof (RBinObject));
	bin->curxtr = NULL;
	r_list_foreach (bin->binxtrs, it, xtr) {
		if (xtr->check && xtr->check (bin)) {
			bin->curxtr = xtr;
			break;
		}
	}
	if (bin->curxtr && bin->curxtr->load)
		bin->curxtr->load (bin);
	bin->cur.rawstr = rawstr;
}

static int r_bin_extract(RBin *bin, int idx) {
	if (bin->curxtr && bin->curxtr->extract)
		return bin->curxtr->extract (bin, idx);
	if (!bin->file)
		return R_FALSE;
	bin->cur.file = strdup (bin->file);
	bin->cur.buf = r_buf_mmap (bin->file, 0);
	return R_TRUE;
}

R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	RListIter *it;
	RBinPlugin *plugin;
	if (foo->init)
		foo->init (bin->user);
	r_list_foreach(bin->plugins, it, plugin) {
		if (!strcmp (plugin->name, foo->name))
			return R_FALSE;
	}
	r_list_append(bin->plugins, foo);
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
	if (!bin) return NULL;
	r_bin_free_items (bin);
	if (bin->curxtr && bin->curxtr->destroy)
		bin->curxtr->destroy (bin);
	r_list_free (bin->binxtrs);
	r_list_free (bin->plugins);
	free (bin->file);
	free (bin);
	return NULL;
}

R_API int r_bin_list(RBin *bin) {
	RListIter *it;
	RBinXtrPlugin *plugin;
	RBinXtrPlugin *xtr;
	r_list_foreach (bin->plugins, it, plugin) {
		printf ("bin  %-11s %s\n", plugin->name, plugin->desc);
	}
	r_list_foreach (bin->binxtrs, it, xtr) {
		printf ("xtr  %-11s %s\n", xtr->name, xtr->desc);
	}
	return R_FALSE;
}

R_API int r_bin_load(RBin *bin, const char *file, int dummy) {
	if (!bin || !file)
		return R_FALSE;
	bin->file = r_file_abspath (file);
	r_bin_init (bin, bin->cur.rawstr);
	
	bin->narch = r_bin_extract (bin, 0);
	
	if (bin->narch == 0)
		return R_FALSE;
	/* FIXME: temporary hack to fix malloc:// */
	if (bin->cur.buf == NULL)
		return R_FALSE;
	return r_bin_init_items (bin, dummy);
}

R_API ut64 r_bin_get_baddr(RBin *bin) {
	return bin->cur.o->baddr;
}

R_API RBinAddr* r_bin_get_sym(RBin *bin, int sym) {
	if (sym<0 || sym>=R_BIN_SYM_LAST)
		return NULL;
	return bin->cur.o->binsym[sym];
}

// XXX: those accessors are redundant
R_API RList* r_bin_get_entries(RBin *bin) {
	return bin->cur.o->entries;
}

R_API RList* r_bin_get_fields(RBin *bin) {
	return bin->cur.o->fields;
}

R_API RList* r_bin_get_imports(RBin *bin) {
	return bin->cur.o->imports;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	if (!bin->cur.buf) return NULL;
	return bin->cur.o->info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	return bin->cur.o->libs;
}

R_API RList* r_bin_get_relocs(RBin *bin) {
	return bin->cur.o->relocs;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	return bin->cur.o->sections;
}

R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va) {
	RBinObject *o = bin->cur.o;
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	if (o->sections)
	r_list_foreach (o->sections, iter, section) {
		from = va ? o->baddr+section->rva : section->offset;
		to = va ? o->baddr+section->rva+section->vsize :
				  section->offset + section->size;
		if (off >= from && off < to)
			return section;
	}
	return NULL;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	return bin->cur.o->strings;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	return bin->cur.o->symbols;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	return bin->cur.o->info->big_endian;
}

R_API int r_bin_is_stripped (RBin *bin) {
	return R_BIN_DBG_STRIPPED (bin->cur.o->info->dbg_info);
}

R_API int r_bin_is_static (RBin *bin) {
	if (r_list_length (bin->cur.o->libs)>0)
		return R_FALSE;
	return R_BIN_DBG_STATIC (bin->cur.o->info->dbg_info);
}

// TODO: Integrate with r_bin_dbg */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	return R_BIN_DBG_LINENUMS (bin->cur.o->info->dbg_info);
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	return R_BIN_DBG_SYMS (bin->cur.o->info->dbg_info);
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	return R_BIN_DBG_RELOCS (bin->cur.o->info->dbg_info);
}

R_API RBin* r_bin_new() {
	int i;
	RBinPlugin *static_plugin;
	RBinXtrPlugin *static_xtr_plugin;
	RBin *bin = R_NEW0 (RBin);
	if (!bin) return NULL;
	bin->plugins = r_list_new();
	bin->plugins->free = free;
	bin->minstrlen = -2;
	bin->cur.o = R_NEW0 (RBinObject);
	for (i=0; bin_static_plugins[i]; i++) {
		static_plugin = R_NEW (RBinPlugin);
		memcpy (static_plugin, bin_static_plugins[i],
			sizeof (RBinPlugin));
		r_bin_add (bin, static_plugin);
	}
	bin->binxtrs = r_list_new ();
	bin->binxtrs->free = free;
	for (i=0; bin_xtr_static_plugins[i]; i++) {
		static_xtr_plugin = R_NEW (RBinXtrPlugin);
		memcpy (static_xtr_plugin, bin_xtr_static_plugins[i],
			sizeof (RBinXtrPlugin));
		r_bin_xtr_add (bin, static_xtr_plugin);
	}
	return bin;
}

/* arch and bits are implicit in the plugin name, do we really need
 * to overwrite bin->cur.info? */
R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	RBinObject *o = bin->cur.o;
	RListIter *it;
	RBinPlugin *plugin;

	if (!o->info) o->info = R_NEW0 (RBinInfo);
	strncpy (o->info->arch, arch, R_BIN_SIZEOF_STRINGS);
	o->info->bits = bits;

	r_list_foreach (bin->plugins, it, plugin) {
		if (!strcmp (name, plugin->name)) {
			bin->cur.curplugin = plugin;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// DUPDUPDUP
R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	int i;
	RBinInfo *info;
	//if (bin->narch >1) // fix double load when no multiarch bin is loaded
	for (i=0; i<bin->narch; i++) {
		r_bin_select_idx (bin, i);
		info = bin->cur.o->info;
		if (!info || !bin->cur.file ||
			(arch && !strstr (info->arch, arch)) ||
			(bits && bits != info->bits) ||
			(name && !strstr (info->file, name)))
			continue;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bin_select_idx(RBin *bin, int idx) {
	r_bin_free_items (bin);
	if (r_bin_extract (bin, idx))
		return r_bin_init_items (bin, R_FALSE);
	return R_FALSE;
}

R_API void r_bin_list_archs(RBin *bin) {
	int i;
	for (i = 0; i < bin->narch; i++)
		if (r_bin_select_idx (bin, i)) {
			RBinInfo *info = bin->cur.o->info;
			printf ("%03i 0x%08"PFMT64x" %d %s_%i %s %s\n", i, 
				bin->cur.offset, bin->cur.size, info->arch,
				info->bits, info->machine, bin->cur.file);
		} else eprintf ("%03i 0x%08"PFMT64x" %d unknown_0\n", i,
				bin->cur.offset, bin->cur.size);
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static int getoffset (RBin *bin, int type, int idx) {
	RBinArch *a = &bin->cur;
	if (a && a->curplugin && a->curplugin->get_offset)
		return a->curplugin->get_offset (a, type, idx);
	return -1;
}

static const char *getname (RBin *bin, int off) {
	// walk symbols, find index, return name, ignore offset wtf
	return NULL;
}

R_API void r_bin_bind (RBin *bin, RBinBind *b) {
	b->bin = bin;
	b->get_offset = getoffset;
	b->get_name = getname;
}

R_API RBuffer *r_bin_create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBinArch *a = &bin->cur;
	if (codelen<0) codelen = 0;
	if (datalen<0) datalen = 0;
	if (a && a->curplugin && a->curplugin->create)
		return a->curplugin->create (bin, code, codelen, data, datalen);
	return NULL;
}

R_API RBinObject *r_bin_get_object(RBin *bin) {
	bin->cur.o->referenced = R_TRUE;
	return bin->cur.o;
}

R_API void r_bin_object_free(RBinObject *obj) {
	free (obj);
}

R_API RList* /*<RBinClass>*/r_bin_get_classes(RBin *bin) {
	return bin->cur.o->classes;
}

R_API RBinClass *r_bin_class_new (RBin *bin, const char *name, const char *super, int view) {
	RList *list = bin->cur.o->classes;
	RBinClass *c;
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
		list = bin->cur.o->classes = r_list_new ();
	r_list_append (list, c);
	return c;
}

R_API RBinClass *r_bin_class_get (RBin *bin, const char *name) {
	RList *list = bin->cur.o->classes;
	RListIter *iter;
	RBinClass *c;
	r_list_foreach (list, iter, c) {
		if (!strcmp (c->name, name))
			return c;
	}
	return NULL;
}

R_API int r_bin_class_add_method (RBin *bin, const char *classname, const char *name, int nargs) {
	RBinClass *c = r_bin_class_get (bin, classname);
	name = strdup (name); // XXX
	if (c) {
		r_list_append (c->methods, (void*)name);
		return R_TRUE;
	}
	c = r_bin_class_new (bin, classname, NULL, 0);
	r_list_append (c->methods, (void*)name);
	return R_FALSE;
}

R_API void r_bin_class_add_field (RBin *bin, const char *classname, const char *name) {
#warning TODO: add_field into class
	//eprintf ("TODO add field: %s \n", name);
}

R_API ut64 r_bin_get_offset (RBin *bin) {
	return bin->cur.offset;
}

R_API ut64 r_bin_get_vaddr (RBin *bin, ut64 baddr, ut64 paddr, ut64 vaddr) {
	RBinPlugin *cp = bin->cur.curplugin;
	if (cp && cp->get_vaddr)
	    return cp->get_vaddr (baddr, paddr, vaddr);

	ut32 delta;
	if (!baddr) return vaddr;
 	delta = (paddr & 0xfffff000) | (vaddr & 0xfff);
	return baddr + delta;
}

R_API ut64 r_bin_get_size (RBin *bin) {
	return bin->cur.o->size;
}
