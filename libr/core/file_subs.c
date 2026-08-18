/* radare - LGPL - Copyright 2026 - pancake */

#include <r_core.h>

R_API void r_core_sub_option_free(RCoreSubOption *o) {
	if (!o) {
		return;
	}
	free (o->name);
	free (o->uri);
	free (o->arch);
	free (o->cpu);
	free (o->machine);
	free (o->hint);
	free (o->envs);
	free (o);
}

R_API void r_core_subs_free(RCoreSubs *s) {
	if (!s) {
		return;
	}
	free (s->uri);
	free (s->format);
	r_list_free (s->options);
	free (s);
}

static void collect_io_subs(RCore *core, const char *uri, RList *options, char **format) {
	// Resolve plugin without opening: works for both single-entry
	// (zip://foo//entry) and many-entry (apk://foo) forms.
	RIOPlugin *plugin = r_io_plugin_resolve (core->io, uri, false);
	if (!plugin || !plugin->list_subs) {
		plugin = r_io_plugin_resolve (core->io, uri, true);
	}
	if (!plugin || !plugin->list_subs) {
		return;
	}
	RList *io_subs = plugin->list_subs (core->io, uri);
	if (!io_subs) {
		return;
	}
	RListIter *it;
	RIOSubEntry *e;
	r_list_foreach (io_subs, it, e) {
		RCoreSubOption *o = R_NEW0 (RCoreSubOption);
		o->kind = R_CORE_SUB_FILE;
		o->index = -1;
		o->name = e->name ? strdup (e->name) : NULL;
		o->uri = e->uri ? strdup (e->uri) : NULL;
		o->offset = e->offset;
		o->size = e->size;
		o->hint = e->hint ? strdup (e->hint) : NULL;
		r_list_append (options, o);
	}
	if (!*format && plugin->meta.name) {
		*format = strdup (plugin->meta.name);
	}
	r_list_free (io_subs);
}

static RList *xtr_extractall(RBinXtrPlugin *xtr, RBin *bin, RBuffer *buf) {
	if (xtr->extractall_from_buffer) {
		return xtr->extractall_from_buffer (bin, buf);
	}
	if (xtr->extractall_from_bytes) {
		ut64 sz = r_buf_size (buf);
		if (!sz) {
			return NULL;
		}
		ut8 *bytes = malloc (sz);
		if (!bytes) {
			return NULL;
		}
		RList *slices = NULL;
		if (r_buf_read_at (buf, 0, bytes, sz) == (int)sz) {
			slices = xtr->extractall_from_bytes (bin, bytes, sz);
		}
		free (bytes);
		return slices;
	}
	return NULL;
}

static void collect_xtr_slices(RCore *core, RIODesc *desc, RList *options, char **format) {
	if (!core->bin || !core->bin->libstore || desc->fd < 0) {
		return;
	}
	RBuffer *buf = r_buf_new_with_io (&core->bin->iob, desc->fd);
	if (!buf) {
		return;
	}
	// HACK: xtr plugins dereference bin->cur->{xtr_obj,file,buf} directly
	// (e.g. xtr.dyldcache reads bin->cur->file, xtr.sep64 reads bin->cur->buf
	// via load()). Install a temporary stand-in RBinFile for the scan and
	// restore. Fields here are borrowed — freed by their real owners. The
	// xtr API should be revised to pass these in as arguments instead of
	// requiring the plugin to reach into bin->cur.
	RBinFile *saved_cur = core->bin->cur;
	RBinFile *tmp_bf = R_NEW0 (RBinFile);
	tmp_bf->file = (char *)(desc->uri ? desc->uri : desc->name);
	tmp_bf->buf = buf;
	tmp_bf->fd = desc->fd;
	core->bin->cur = tmp_bf;

	RList *xtrs = core->bin->libstore->xtrs;
	RBinXtrPlugin *xtr;
	RListIter *it;
	r_list_foreach (xtrs, it, xtr) {
		tmp_bf->xtr_obj = NULL;
		if (!xtr->check || !xtr->check (NULL, buf)) {
			continue;
		}
		RList *slices = xtr_extractall (xtr, core->bin, buf);
		if (!slices) {
			continue;
		}
		const char *plugin_name = xtr->meta.name ? xtr->meta.name : "xtr";
		const char *short_name = r_str_startswith (plugin_name, "xtr.")
			? plugin_name + 4 : plugin_name;
		RCoreSubKind kind = R_CORE_SUB_ARCH;
		if (!strcmp (short_name, "dyldcache") || !strcmp (short_name, "sep64")) {
			kind = R_CORE_SUB_IMAGE;
		}
		if (!*format) {
			*format = strdup (short_name);
		}
		int idx = 0;
		RListIter *it2;
		RBinXtrData *x;
		r_list_foreach (slices, it2, x) {
			RCoreSubOption *o = R_NEW0 (RCoreSubOption);
			o->kind = kind;
			o->index = idx++;
			o->offset = x->offset;
			o->size = x->size;
			if (x->metadata) {
				if (x->metadata->arch) {
					o->arch = strdup (x->metadata->arch);
					o->name = strdup (x->metadata->arch);
				}
				o->bits = x->metadata->bits;
				if (x->metadata->machine) {
					o->machine = strdup (x->metadata->machine);
				}
				if (x->metadata->libname && !o->name) {
					o->name = strdup (x->metadata->libname);
				}
			}
			if (!o->name) {
				o->name = r_str_newf ("%s:%d", short_name, o->index);
			}
			o->hint = r_str_newf ("%s slice at 0x%"PFMT64x" (%"PFMT64u" bytes)",
				short_name, o->offset, o->size);
			o->envs = r_str_newf ("bin.xtr.idx=%d", o->index);
			r_list_append (options, o);
		}
		r_list_free (slices);
		if (tmp_bf->xtr_obj && xtr->free_xtr) {
			xtr->free_xtr (tmp_bf->xtr_obj);
			tmp_bf->xtr_obj = NULL;
		}
	}
	core->bin->cur = saved_cur;
	tmp_bf->file = NULL;
	tmp_bf->buf = NULL;
	free (tmp_bf);
	r_unref (buf);
}

static const char *kind_str(RCoreSubKind k) {
	switch (k) {
	case R_CORE_SUB_ARCH:  return "arch";
	case R_CORE_SUB_IMAGE: return "image";
	case R_CORE_SUB_FILE:  return "file";
	case R_CORE_SUB_WHOLE: return "whole";
	case R_CORE_SUB_ALL:   return "all";
	}
	return "?";
}

R_API void r_core_subs_print(RCore *core, RCoreSubs *subs) {
	R_RETURN_IF_FAIL (core && subs);
	r_cons_printf (core->cons, "[+] %s subbinaries in %s:\n", subs->format, subs->uri);
	int i = 0;
	RListIter *it;
	RCoreSubOption *o;
	r_list_foreach (subs->options, it, o) {
		r_cons_printf (core->cons, "%3d  %-6s  %-14s  %-6s %-4d  0x%08"PFMT64x"  %10"PFMT64u"  %s\n",
			i++, kind_str (o->kind), r_str_get (o->name),
			r_str_get (o->arch), o->bits, o->offset, o->size,
			r_str_get (o->hint));
	}
}

static void apply_envs(RCore *core, const char *envs) {
	if (R_STR_ISEMPTY (envs)) {
		return;
	}
	char *dup = strdup (envs);
	char *p = dup;
	while (p && *p) {
		char *eol = strchr (p, '\n');
		if (eol) {
			*eol = 0;
		}
		char *eq = strchr (p, '=');
		if (eq) {
			*eq = 0;
			r_config_set (core->config, p, eq + 1);
		}
		if (!eol) {
			break;
		}
		p = eol + 1;
	}
	free (dup);
}

// Handle the cfg.choice UI for a URI. Returns a newly-allocated URI to open
// instead (caller frees), or NULL to keep the original URI. When the user
// picks an option with envs, the config is updated as a side-effect.
R_API char *r_core_file_subs_prompt(RCore *core, const char *uri) {
	R_RETURN_VAL_IF_FAIL (core && core->config && uri, NULL);
	if (!r_config_get_b (core->config, "cfg.choice")) {
		return NULL;
	}
	RCoreSubs *subs = r_core_file_subs (core, uri);
	if (!subs) {
		return NULL;
	}
	r_core_subs_print (core, subs);
	char *chosen = NULL;
	if (r_config_get_b (core->config, "scr.interactive")) {
		char *ans = r_cons_input (core->cons, "Select sub [index, Enter=default]: ");
		if (!R_STR_ISEMPTY (ans)) {
			int idx = atoi (ans);
			RCoreSubOption *o = r_list_get_n (subs->options, idx);
			if (o) {
				apply_envs (core, o->envs);
				if (o->uri) {
					chosen = strdup (o->uri);
				}
				if (o->arch) {
					r_config_set (core->config, "asm.arch", o->arch);
				}
				if (o->cpu) {
					r_config_set (core->config, "asm.cpu", o->cpu);
				}
				if (o->bits > 0) {
					r_config_set_i (core->config, "asm.bits", o->bits);
				}
			}
		}
		free (ans);
	}
	r_core_subs_free (subs);
	return chosen;
}

R_API RCoreSubs *r_core_file_subs(RCore *core, const char *uri) {
	R_RETURN_VAL_IF_FAIL (core && core->io && uri, NULL);

	RList *options = r_list_newf ((RListFree)r_core_sub_option_free);
	char *format = NULL;

	// URI-level subs: plugin-level, no open required (works for apk://foo.apk).
	collect_io_subs (core, uri, options, &format);

	// Byte-level xtr: only attempt when the URI can be opened read-only
	// as a single RIODesc. For multi-entry URIs like apk:// this will fail,
	// which is fine — xtr wouldn't apply to an archive anyway.
	// r_io_open_nomap sets io->desc when autofd is on or io->desc is NULL;
	// save and restore around the probe to avoid a dangling pointer after close.
	RIODesc *saved_desc = core->io->desc;
	RIODesc *desc = r_io_open_nomap (core->io, uri, R_PERM_R, 0);
	if (desc) {
		collect_xtr_slices (core, desc, options, &format);
		r_io_desc_close (desc);
	}
	core->io->desc = saved_desc;

	if (r_list_empty (options)) {
		r_list_free (options);
		free (format);
		return NULL;
	}

	RCoreSubs *subs = R_NEW0 (RCoreSubs);
	subs->uri = strdup (uri);
	subs->format = format ? format : strdup ("unknown");
	subs->options = options;
	return subs;
}
