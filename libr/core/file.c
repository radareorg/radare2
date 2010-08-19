/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_core.h>

R_API ut64 r_core_file_resize(struct r_core_t *core, ut64 newsize) {
	if (newsize==0 && core->file)
		return core->file->size;
	return 0LL;
}

R_API void r_core_sysenv_update(RCore *core) {
	char buf[64];
#if DISCUSS
 EDITOR      cfg.editor (vim or so)
 CURSOR      cursor position (offset from curseek)
 COLOR       scr.color?1:0
 VERBOSE     cfg.verbose
// only if cmd matches BYTES or BLOCK ?
 BYTES       hexpairs of current block
 BLOCK       temporally file with contents of current block
#endif
	if (!core->file)
		return;
	if (core->file->filename)
		r_sys_setenv ("FILE", core->file->filename);
	snprintf (buf, sizeof (buf), "%"PFMT64d, core->offset);
	r_sys_setenv ("OFFSET", buf);
	snprintf (buf, sizeof (buf), "0x%08"PFMT64x, core->offset);
	r_sys_setenv ("XOFFSET", buf);
	snprintf (buf, sizeof (buf), "%"PFMT64d, core->file->size);
	r_sys_setenv ("SIZE", buf);
	r_sys_setenv ("ENDIAN", core->assembler->big_endian?"big":"little");
	snprintf (buf, sizeof (buf), "%d", core->blocksize);
	r_sys_setenv ("BSIZE", buf);
	r_sys_setenv ("ARCH", r_config_get (core->config, "asm.arch"));
	r_sys_setenv ("DEBUG", r_config_get_i (core->config, "cfg.debug")?"1":"0");
	r_sys_setenv ("IOVA", r_config_get_i (core->config, "io.va")?"1":"0");
}

R_API RCoreFile *r_core_file_open(RCore *r, const char *file, int mode) {
	RCoreFile *fh;
	const char *cp;
	char *p;
	int fd = r_io_open (r->io, file, mode, 0644);
	if (fd == -1)
		return NULL;

	fh = R_NEW (RCoreFile);
	fh->fd = fd;
	fh->uri = strdup (file);
	fh->filename = fh->uri;
	p = strstr (fh->filename, "://");
	if (p != NULL)
		fh->filename = p+3;
	fh->rwx = mode;
	r->file = fh;
	fh->size = r_io_size (r->io, fd);
	list_add (&(fh->list), &r->files);

	r_bin_load (r->bin, fh->filename, NULL);

	r_core_block_read (r, 0);

	cp = r_config_get (r->config, "cmd.open");
	if (cp && *cp)
		r_core_cmd (r, cp, 0);
	r_config_set (r->config, "file.path", file);
	return fh;
}

R_API int r_core_file_close(struct r_core_t *r, struct r_core_file_t *fh) {
	int ret = r_io_close (r->io, fh->fd);
	list_del (&(fh->list));
	// TODO: set previous opened file as current one
	return ret;
}

R_API struct r_core_file_t *r_core_file_get_fd(struct r_core_t *core, int fd) {
	struct list_head *pos;
	list_for_each_prev (pos, &core->files) {
		RCoreFile *file = list_entry (pos, RCoreFile, list);
		if (file->fd == fd)
			return file;
	}
	return NULL;
}

R_API int r_core_file_list(struct r_core_t *core) {
	int count = 0;
	struct list_head *pos;
	list_for_each_prev (pos, &core->files) {
		RCoreFile *f = list_entry (pos, RCoreFile, list);
		eprintf ("%d %s\n", f->fd, f->uri);
		count++;
	}
	return count;
}

R_API int r_core_file_close_fd(struct r_core_t *core, int fd) {
	int ret = r_io_close (core->io, fd);
	struct r_core_file_t *fh = r_core_file_get_fd (core, fd);
	if (fh != NULL)
		list_del (&(fh->list));
	return ret;
}
