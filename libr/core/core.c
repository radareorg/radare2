/* radare - LGPL - Copyright 2009-2011 pancake<nopcode.org> */

#include <r_core.h>
#include <r_socket.h>
#include "../config.h"
#if __UNIX__
#include <signal.h>
#endif

static int endian = 1; // XXX HACK

static int core_cmd_callback (void *user, const char *cmd) {
	RCore *core = (RCore *)user;
	return r_core_cmd0 (core, cmd);
}

static ut64 num_callback(RNum *userptr, const char *str, int *ok) {
	RCore *core = (RCore *)userptr; // XXX ?
	RFlagItem *flag;
	RAnalOp op;
	ut64 ret = 0;
	*ok = 0;
	if (str[0]=='$') {
		*ok = 1;
		r_anal_op (core->anal, &op, core->offset,
			core->block, core->blocksize);
		switch (str[1]) {
		case '{':
			{
				char *ptr, *bptr = strdup (str+2);
				ptr = strchr (bptr, '}');
				if (ptr != NULL) {
					ut64 ret;
					ptr[0]='\0';
					ret = r_config_get_i (core->config, bptr);
					free (bptr);
					return ret;
				}
			}
			return 0;
		case 'e': return op.eob;
		case 'j': return op.jump;
		case 'f': return op.fail;
		case 'r': return op.ref;
		case 'l': return op.length;
		case 'b': return core->blocksize;
		case 's': return core->file->size;
		case '?': return core->num->value;
		case '$': return core->offset;
		case 'o': return core->io->off;
		}
	}
	if (*str>'A') {
		if ((flag = r_flag_get (core->flags, str))) {
			ret = flag->offset;
			*ok = R_TRUE;
		} else *ok = ret = 0;
	}
	return ret;
}

R_API RCore *r_core_new() {
	RCore *c = R_NEW (struct r_core_t);
	r_core_init (c);
	return c;
}

/*-----------------------------------*/
#define CMDS (sizeof (radare_argv)/sizeof(const char*))
static const char *radare_argv[] = {
	"?", 
	"dH", "ds", "dso", "dsl", "dc", "dd", "dm", "db", "dp", "dr", "dcu",
	"S", 
	"s", "s+", "s++", "s-", "s--", "s*", "sa", "sb", "sr",
	"!", "!!", 
	"#sha1", "#crc32", "#pcprint", "#sha256", "#sha512", "#md4", "#md5", 
	"#!python", "#!perl", "#!vala",
	"V",
	"aa", "ab", "af", "ar", "ag", "at", "a?", 
	"aga", "agc", "agd", "agl", "agfl",
	"e", "e-", "e*", "e!",
	"i", "ii", "iI", "is", "iS", "iz",
	"q", 
	"f", "fr", "f-", "f*", "fs", "fS", "fr", "f?",
	"m", "m*", "ml", "m-", "my", "mg", "md", "mp", "m?",
	"o", "o-",
	"x",
	".", ".!", ".(", "./",
	"r", "r+", "r-",
	"b", "bf", "b?",
	"/", "//", "/a", "/c", "/m", "/x", "/v",
	"y", "yy", "y?",
	"wx", "ww", "wf", "w?",
	"p6d", "p6e", "p8", "pb", "pc", "pd", "pD", "px", "pX", "po",
	"pm", "pr", "pt", "ps", "pz", "pu", "pU", "p?",
	NULL
};

#define TMP_ARGV_SZ 256
static const char *tmp_argv[TMP_ARGV_SZ];
static int autocomplete(RLine *line) {
	RCore *core = line->user;
	RListIter *iter;
	RFlagItem *flag;
	if (core) {
		char *ptr = strchr (line->buffer.data, '@');
		if (ptr && line->buffer.data+line->buffer.index >= ptr) {
			int sdelta, n, i = 0;
			ptr = (char *)r_str_chop_ro (ptr+1);
			n = strlen (ptr);//(line->buffer.data+sdelta);
			sdelta = (int)(size_t)(ptr - line->buffer.data);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!memcmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i==TMP_ARGV_SZ)
						break;
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else
		if ((!memcmp (line->buffer.data, "o ", 2)) ||
		     !memcmp (line->buffer.data, ". ", 2)) {
			// XXX: SO MANY FUCKING MEMORY LEAKS
			char *str, *p, *path;
			RList *list;
			int n, i = 0;
			int sdelta = 2; //(line->buffer.data[1]==' ')?2:3;
			if (!line->buffer.data[sdelta]) {
				path = r_sys_getdir ();
			} else {
				path = strdup (line->buffer.data+sdelta);
			}
			p = r_str_lchr (path, '/');
			if (p) {
				if (p==path) path = "/";
				else *p = 0;
				p++;
			}
			if (p) {
				if (*p) n = strlen (p);
				else p = "";
			}
#if 0
printf ("DIR(%s)\n", path);
printf ("FILE(%s)\n", p);
printf ("FILEN %d\n", n);
#endif
 			list = r_sys_dir (path);
			if (list) {
				char buf[4096];
				r_list_foreach (list, iter, str) {
					if (*str == '.')
						continue;
					if (!*p || !memcmp (str, p, n)) {
						snprintf (buf, sizeof (buf), "%s%s%s",
							path, strlen(path)>1?"/":"", str);
						tmp_argv[i++] = strdup (buf);
						if (i==TMP_ARGV_SZ)
							break;
					}
				}
				// XXX LEAK r_list_destroy (list);
			} else eprintf ("\nInvalid directory\n");
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
			//free (path);
		} else
		if ((!memcmp (line->buffer.data, "s ", 2)) ||
		    (!memcmp (line->buffer.data, "ag ", 3)) ||
		    (!memcmp (line->buffer.data, "aga ", 4)) ||
		    (!memcmp (line->buffer.data, "agc ", 4)) ||
		    (!memcmp (line->buffer.data, "agl ", 4)) ||
		    (!memcmp (line->buffer.data, "agd ", 4)) ||
		    (!memcmp (line->buffer.data, "agfl ", 5)) ||
		    (!memcmp (line->buffer.data, "b ", 2)) ||
		    (!memcmp (line->buffer.data, "dcu ", 4)) ||
		    (!memcmp (line->buffer.data, "/v ", 3)) ||
		    (!memcmp (line->buffer.data, "f ", 2)) ||
		    (!memcmp (line->buffer.data, "fr ", 3)) ||
		    (!memcmp (line->buffer.data, "/a ", 3)) ||
		    (!memcmp (line->buffer.data, "? ", 2))) {
			int n, i = 0;
			int sdelta = (line->buffer.data[1]==' ')?2:
				(line->buffer.data[2]==' ')?3:4;
			n = strlen (line->buffer.data+sdelta);
			r_list_foreach (core->flags->flags, iter, flag) {
				if (!memcmp (flag->name, line->buffer.data+sdelta, n)) {
					tmp_argv[i++] = flag->name;
					if (i==TMP_ARGV_SZ)
						break;
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else
		if (!memcmp (line->buffer.data, "e ", 2)) {
			RConfigNode *bt;
			RListIter *iter;
			int i = 0, n = strlen (line->buffer.data+2);
			r_list_foreach (core->config->nodes, iter, bt) {
				if (!memcmp (bt->name, line->buffer.data+2, n)) {
					tmp_argv[i++] = bt->name;
					if (i==TMP_ARGV_SZ)
						break;
				}
			}
			tmp_argv[i] = NULL;
			line->completion.argc = i;
			line->completion.argv = tmp_argv;
		} else {
			int i, j;
			for (i=j=0; radare_argv[i] && i<CMDS; i++)
				if (!memcmp (radare_argv[i], line->buffer.data, line->buffer.index))
					tmp_argv[j++] = radare_argv[i];
			tmp_argv[j] = NULL;
			line->completion.argc = j;
			line->completion.argv = tmp_argv;
		}
	} else {
		int i,j;
		for (i=j=0; radare_argv[i] && i<CMDS; i++)
			if (!memcmp (radare_argv[i], line->buffer.data, line->buffer.index))
				tmp_argv[j++] = radare_argv[i];
		tmp_argv[j] = NULL;
		line->completion.argc = j;
		line->completion.argv = tmp_argv;
	}
	return R_TRUE;
}

static int myfgets(char *buf, int len) {
	/* TODO: link against dietline if possible for autocompletion */
	char *ptr;
	RLine *rli = r_line_singleton (); 
	buf[0]='\0';
	rli->completion.argc = CMDS;
	rli->completion.argv = radare_argv;
	rli->completion.run = autocomplete;
	ptr = r_line_readline (); //CMDS, radare_argv);
	if (ptr == NULL)
		return -2;
	strncpy (buf, ptr, len);
	//free(ptr); // XXX leak
	return strlen (buf)+1;
}
/*-----------------------------------*/

#if 0
static int __dbg_read(void *user, int pid, ut64 addr, ut8 *buf, int len)
{
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_read_at(core, addr, buf, len);
}

static int __dbg_write(void *user, int pid, ut64 addr, const ut8 *buf, int len) {
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_write_at(core, addr, buf, len);
}
#endif

static const char *r_core_print_offname(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_i (c->flags, addr);
	if (item) return item->name;
	return NULL;
}

R_API int r_core_init(RCore *core) {
	static int singleton = R_TRUE;
	core->rtr_n = 0;
	core->visual = R_FALSE;
	core->ffio = 0;
	core->oobi = NULL;
	core->oobi_len = 0;
	core->printidx = 0;
	core->lastcmd = NULL;
	core->cmdqueue = NULL;
	core->cmdrepeat = R_TRUE;
	core->yank = NULL;
	core->reflines = NULL;
	core->reflines2 = NULL;
	core->yank_len = 0;
	core->yank_off = 0LL;
	core->num = r_num_new (&num_callback, core);
	//core->num->callback = &num_callback;
	//core->num->userptr = core;
	core->curasmstep = 0;

	/* initialize libraries */
	if (singleton) {
		RLine *line = r_line_new ();
		r_cons_new ();
		line->user = core;
		r_cons_singleton()->user_fgets = (void *)myfgets;
		//r_line_singleton()->user = (void *)core;
		r_line_hist_load (".radare2_history");
		singleton = R_FALSE;
	}
	core->cons = r_cons_singleton ();
	core->cons->num = core->num;
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8*)malloc (R_CORE_BLOCKSIZE);
	if (core->block == NULL) {
		eprintf ("Cannot allocate %d bytes\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return R_FALSE;
	}
	core->print = r_print_new ();
	core->print->user = core;
	core->print->offname = r_core_print_offname;
	core->print->printf = (void *)r_cons_printf;
	core->lang = r_lang_new ();
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	core->anal = r_anal_new ();
	r_anal_set_user_ptr (core->anal, core);
	core->anal->meta->printf = (void *) r_cons_printf;
	core->assembler = r_asm_new ();
	r_asm_set_user_ptr (core->assembler, core);
	core->parser = r_parse_new ();
	r_parse_set_user_ptr (core->parser, core);
	core->bin = r_bin_new ();
	r_bin_set_user_ptr (core->bin, core);
	core->io = r_io_new ();
	core->io->user = (void *)core;
	core->io->core_cmd_cb = core_cmd_callback;
	core->sign = r_sign_new ();
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	core->fs = r_fs_new ();
	r_bin_bind (core->bin, &(core->assembler->binb));
	r_io_bind (core->io, &(core->search->iob));
	r_io_bind (core->io, &(core->print->iob));
	r_io_bind (core->io, &(core->anal->iob));
	r_io_bind (core->io, &(core->fs->iob));
	//r_cmd_macro_init (&core->macro);
	core->file = NULL;
	core->files = r_list_new ();
	core->files->free = (RListFree)r_core_file_free;
	core->offset = 0LL;
	r_core_cmd_init (core);
	core->flags = r_flag_new ();
	core->dbg = r_debug_new (R_TRUE);
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
	//r_debug_use (core->dbg, "native");
	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->sign->printf = r_cons_printf;
	core->io->printf = r_cons_printf;
	core->dbg->printf = r_cons_printf;
	core->dbg->bp->printf = r_cons_printf;
	r_debug_io_bind (core->dbg, core->io);
	r_core_config_init (core);
	// XXX fix path here

	/* load plugins */
	r_core_loadlibs (core);

	// TODO: get arch from r_bin or from native arch
	r_asm_use (core->assembler, R_SYS_ARCH);
	r_anal_use (core->anal, R_SYS_ARCH);
	r_bp_use (core->dbg->bp, R_SYS_ARCH);
	if (R_SYS_BITS & R_SYS_BITS_64)
		r_config_set_i (core->config, "asm.bits", 64);
	else
	if (R_SYS_BITS & R_SYS_BITS_32)
		r_config_set_i (core->config, "asm.bits", 32);
	r_config_set (core->config, "asm.arch", R_SYS_ARCH);
	return 0;
}

R_API RCore *r_core_free(RCore *c) {
	/* TODO: it leaks as shit */
	free (c);
	return NULL;
}

R_API void r_core_prompt_loop(RCore *r) {
	int ret;
	do { 
		if (r_core_prompt (r, R_FALSE)<1)
			break;
//			if (lock) r_th_lock_enter (lock);
		if ((ret = r_core_prompt_exec (r))==-1)
			eprintf ("Invalid command\n");
/*			if (lock) r_th_lock_leave (lock);
		if (rabin_th && !r_th_wait_async (rabin_th)) {
			eprintf ("rabin thread end \n");
			r_th_free (rabin_th);
			r_th_lock_free (lock);
			lock = NULL;
			rabin_th = NULL;
		}
*/
	} while (ret != R_CORE_CMD_EXIT);
}

R_API int r_core_prompt(RCore *r, int sync) {
	int ret;
	char line[1024];
	char prompt[32];
	const char *cmdprompt = r_config_get (r->config, "cmd.prompt");

	if (cmdprompt && *cmdprompt)
		ret = r_core_cmd (r, cmdprompt, 0);

	if (!r_line_singleton()->echo)
		*prompt = 0;
#if __UNIX__
	else if (r_config_get_i (r->config, "scr.color"))
		snprintf (prompt, sizeof (prompt),
			Color_YELLOW"[0x%08"PFMT64x"]> "Color_RESET, r->offset);
#endif
	else sprintf (prompt, "[0x%08"PFMT64x"]> ", r->offset);
	r_line_singleton()->prompt = prompt;
	ret = r_cons_fgets (line, sizeof (line), 0, NULL);
	if (ret == -2) return R_CORE_CMD_EXIT;
	if (ret == -1) return R_FALSE;
	if (sync) return r_core_prompt_exec (r);
	r->cmdqueue = line;
	return R_TRUE;
}

R_API int r_core_prompt_exec(RCore *r) {
	int ret = r_core_cmd (r, r->cmdqueue, R_TRUE);
	r_cons_flush ();
	return ret;
}

R_API int r_core_block_size(RCore *core, ut32 bsize) {
	int ret = R_FALSE;
	if (bsize == core->blocksize)
		return R_FALSE;
	if (bsize<1)
		bsize = R_TRUE;
	else if (bsize> R_CORE_BLOCKSIZE_MAX)
		bsize = R_CORE_BLOCKSIZE_MAX;
	else ret = R_TRUE;
	core->block = realloc (core->block, bsize+1);
	if (core->block == NULL) {
		eprintf ("Oops. cannot allocate that much (%u)\n", bsize);
		core->block = malloc (R_CORE_BLOCKSIZE);
		core->blocksize = R_CORE_BLOCKSIZE;
		if (core->block == NULL) {
			eprintf ("Panic in the heap!\n");
			exit (1);
		}
	} else core->blocksize = bsize;
	memset (core->block, 0xff, core->blocksize);
	r_core_block_read (core, 0);
	return ret;
}

R_API int r_core_seek_align(RCore *core, ut64 align, int times) {
	int inc = (times>=0)?1:-1;
	int diff = core->offset%align;
	ut64 seek = core->offset;
	
	if (times == 0)
		diff = -diff;
	else if (diff) {
		if (inc>0) diff += align-diff;
		else diff = -diff;
		if (times) times -= inc;
	}
	while ((times*inc)>0) {
		times -= inc;
		diff += align*inc;
	}
	if (diff<0 && -diff>seek)
		seek = diff = 0;
	return r_core_seek (core, seek+diff, 1);
}

R_API int r_core_seek_delta(RCore *core, st64 addr) {
	ut64 tmp = core->offset;
	int ret;
	if (addr == 0)
		return R_TRUE;
	if (addr>0LL) {
		/* check end of file */
		if (0) addr = 0; // XXX tmp+addr>) {
		else addr += tmp;
	} else {
		/* check < 0 */
		if (-addr > tmp) addr = 0;
		else addr += tmp;
	}
	core->offset = addr;
	ret = r_core_block_read (core, 0);
	//if (ret == -1)
	//	memset (core->block, 0xff, core->blocksize);
	//	core->offset = tmp;
	return ret;
}

R_API char *r_core_op_str(RCore *core, ut64 addr) {
	RAsmOp op;
	ut8 buf[64];
	int ret;
	r_asm_set_pc (core->assembler, addr);
	r_core_read_at (core, addr, buf, sizeof (buf));
	ret = r_asm_disassemble (core->assembler, &op, buf, sizeof (buf));
	return (ret>0)?strdup (op.buf_asm): NULL;
}

R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr) {
	ut8 buf[64];
	RAnalOp *op = R_NEW (RAnalOp);
	r_core_read_at (core, addr, buf, sizeof (buf));
	r_anal_op (core->anal, op, addr, buf, sizeof (buf));
	return op;
}

// TODO: move into core/io/rap? */
R_API int r_core_serve(RCore *core, RIODesc *file) {
	ut8 cmd, flg, *ptr, buf[1024];
	int i, j, pipefd;
	ut64 x;
	RSocket *c, *fd;
	RIORap *rior;
	RListIter *iter;

	rior = (RIORap *)file->data;
	if (rior == NULL|| rior->fd == NULL) {
		eprintf ("rap: cannot listen.\n");
		return -1;
	}
	fd = rior->fd;

	eprintf ("RAP Server started (rap.loop=%s)\n",
			r_config_get (core->config, "rap.loop"));
#if __UNIX__
	// XXX: ugly workaround
	signal (SIGINT, SIG_DFL);
	signal (SIGPIPE, SIG_DFL);
#endif
reaccept:
	core->io->plugin = NULL;
	while ((c = r_socket_accept (fd))) {
		if (c == NULL) {
			eprintf ("rap: cannot accept\n");
			r_socket_close (c);
			return -1;
		}

		eprintf ("rap: client connected\n");
		for (;;) {
			if (!r_socket_read (c, &cmd, 1)) {
				eprintf ("rap: connection closed\n");
				if (r_config_get_i (core->config, "rap.loop")) {
					eprintf ("rap: waiting for new connection\n");
					goto reaccept;
				}
				return -1;
			}

			switch ((ut8)cmd) {
			case RMT_OPEN:
				r_socket_read_block (c, &flg, 1); // flags
				eprintf ("open (%d): ", cmd);
				r_socket_read_block (c, &cmd, 1); // len
				pipefd = -1;
				ptr = malloc (cmd);
				//XXX cmd is ut8..so <256 if (cmd<RMT_MAX) {
				if (ptr == NULL) {
					eprintf ("Cannot malloc in rmt-open len = %d\n", cmd);
				} else {
					RCoreFile *file;
					r_socket_read_block (c, ptr, cmd); //filename
					ptr[cmd] = 0;
					file = r_core_file_open (core, (const char *)ptr, R_IO_READ, 0); // XXX: write mode?
					if (file) {
						r_core_bin_load (core, NULL);
						file->map = r_io_map_add (core->io, file->fd->fd, R_IO_READ, 0, 0, file->size);
						pipefd = core->file->fd->fd;
						eprintf ("(flags: %hhd) len: %hhd filename: '%s'\n",
							flg, cmd, ptr); //config.file);
					} else {
						pipefd = -1;
						eprintf ("Cannot open file (%s)\n", ptr);
						return -1; //XXX: Close conection and goto accept
					}
				}
				buf[0] = RMT_OPEN | RMT_REPLY;
				r_mem_copyendian (buf+1, (ut8 *)&pipefd, 4, !endian);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);

				/* Write meta info */
				RMetaItem *d;
				r_list_foreach (core->anal->meta->data, iter, d) {
					if (d->type == R_META_TYPE_COMMENT)
						snprintf ((char *)buf, sizeof (buf), "%s %s @ 0x%08"PFMT64x,
							r_meta_type_to_string (d->type), d->str, d->from);
					else
						snprintf ((char *)buf, sizeof (buf),
							"%s %d %s @ 0x%08"PFMT64x,
							r_meta_type_to_string (d->type),
							(int)(d->to-d->from), d->str, d->from);
					i = strlen ((char *)buf);
					r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !endian);
					r_socket_write (c, (ut8 *)&j, 4);
					r_socket_write (c, buf, i);
					r_socket_flush (c);
				}
#if 0
				RIOSection *s;
				r_list_foreach_prev (core->io->sections, iter, s) {
					snprintf ((char *)buf, sizeof (buf),
							"S 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" 0x%08"PFMT64x" %s %d",
							s->offset, s->vaddr, s->size, s->vsize, s->name, s->rwx);
					i = strlen ((char *)buf);
					r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !endian);
					r_socket_write (c, (ut8 *)&j, 4);
					r_socket_write (c, buf, i);
					r_socket_flush (c);
				}
#endif
				int fs = -1;
				RFlagItem *flag;
				r_list_foreach_prev (core->flags->flags, iter, flag) {
					if (fs == -1 || flag->space != fs) {
						fs = flag->space;
						snprintf ((char *)buf, sizeof (buf),
								"fs %s", r_flag_space_get_i (core->flags, fs));
						i = strlen ((char *)buf);
						r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !endian);
						r_socket_write (c, (ut8 *)&j, 4);
						r_socket_write (c, buf, i);
					}
					snprintf ((char *)buf, sizeof (buf),
									"f %s %"PFMT64d" 0x%08"PFMT64x,
									flag->name, flag->size, flag->offset);
						i = strlen ((char *)buf);
						r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !endian);
						r_socket_write (c, (ut8 *)&j, 4);
						r_socket_write (c, buf, i);
						r_socket_flush (c);
				}

				snprintf ((char *)buf, sizeof (buf), "s 0x%"PFMT64x, core->offset);
				i = strlen ((char *)buf);
				r_mem_copyendian ((ut8 *)&j, (ut8 *)&i, 4, !endian);
				r_socket_write (c, (ut8 *)&j, 4);
				r_socket_write (c, buf, i);

				i = 0;
				r_socket_write (c, (ut8 *)&i, 4);
				r_socket_flush (c);
				free (ptr);
				break;
			case RMT_READ:
				r_socket_read_block (c, (ut8*)&buf, 4);
				r_mem_copyendian ((ut8*)&i, buf, 4, !endian);
				ptr = (ut8 *)malloc (i+core->blocksize+5);
				if (ptr==NULL) {
					eprintf ("Cannot read %d bytes\n", i);
					// TODO: reply error here
					return -1;
				} else {
					r_core_block_read (core, 0);
					ptr[0] = RMT_READ|RMT_REPLY;
					if (i>RMT_MAX)
						i = RMT_MAX;
					if (i>core->blocksize)
						r_core_block_size (core, i);
					r_mem_copyendian (ptr+1, (ut8 *)&i, 4, !endian);
					memcpy (ptr+5, core->block, i); //core->blocksize);
					r_socket_write (c, ptr, i+5);
					r_socket_flush (c);
				}
				break;
			case RMT_CMD:
				{
				char bufr[8], *bufw = NULL;
				char *cmd = NULL, *cmd_output = NULL;
				int i, cmd_len = 0;

				/* read */
				r_socket_read_block (c, (ut8*)&bufr, 4);
				r_mem_copyendian ((ut8*)&i, (ut8 *)bufr, 4, !endian);
				if (i>0 && i<RMT_MAX) {
					if ((cmd=malloc(i))) {
						r_socket_read_block (c, (ut8*)cmd, i);
						cmd[i] = '\0';
						eprintf ("len: %d cmd: '%s'\n",
							i, cmd); fflush(stdout);
						cmd_output = r_core_cmd_str (core, cmd);
						free(cmd);
					} else eprintf ("rap: cannot malloc\n");
				} else eprintf ("rap: invalid length '%d'\n", i);
				/* write */
				if (cmd_output)
					cmd_len = strlen(cmd_output) + 1;
				else {
					cmd_output = strdup("");
					cmd_len = 0; 
				}
				bufw = malloc(cmd_len + 5);
				bufw[0] = RMT_CMD | RMT_REPLY;
				r_mem_copyendian((ut8*)bufw+1, (ut8 *)&cmd_len, 4, !endian);
				memcpy(bufw+5, cmd_output, cmd_len);
				r_socket_write (c, bufw, cmd_len+5);
				r_socket_flush (c);
				free(bufw);
				free(cmd_output);
				break;
				}
			case RMT_WRITE:
				r_socket_read (c, buf, 5);
				r_mem_copyendian((ut8 *)&x, buf+1, 4, endian);
				ptr = malloc (x);
				r_socket_read (c, ptr, x);
				r_core_write_at (core, core->offset, ptr, x);
				free (ptr);
				break;
			case RMT_SEEK:
				r_socket_read_block (c, buf, 9);
				r_mem_copyendian((ut8 *)&x, buf+1, 8, !endian);
				if (buf[0]!=2) {
					r_core_seek (core, x, buf[0]);
					x = core->offset;
				} else x = core->file->size;
				buf[0] = RMT_SEEK | RMT_REPLY;
				r_mem_copyendian (buf+1, (ut8*)&x, 8, !endian);
				r_socket_write (c, buf, 9);
				r_socket_flush (c);
				break;
			case RMT_CLOSE:
				eprintf ("CLOSE\n");
				// XXX : proper shutdown
				r_socket_read_block (c, buf, 4);
				r_mem_copyendian ((ut8*)&i, buf, 4, endian);
				{
				//FIXME: Use r_socket_close
				int ret = close (i);
				r_mem_copyendian (buf+1, (ut8*)&ret, 4, !endian);
				buf[0] = RMT_CLOSE | RMT_REPLY;
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				}
				break;
			case RMT_SYSTEM:
				// read
				r_socket_read_block (c, buf, 4);
				r_mem_copyendian((ut8*)&i, buf, 4, !endian);
				if (i>0&&i<RMT_MAX) {
					ptr = (ut8 *) malloc(i+6);
					ptr[5]='!';
					r_socket_read_block (c, ptr+6, i);
					ptr[6+i]='\0';
					//env_update();
					//pipe_stdout_to_tmp_file((char*)&buf, (char*)ptr+5);
					strcpy((char*)buf, "/tmp/.out");
					pipefd = r_cons_pipe_open ((const char *)buf, 0);
					//eprintf("SYSTEM(%s)\n", ptr+6);
					system((const char*)ptr+6);
					r_cons_pipe_close (pipefd);
					{
						FILE *fd = fopen((char*)buf, "r");
						 i = 0;
						if (fd == NULL) {
							eprintf("Cannot open tmpfile\n");
							i = -1;
						} else {
							fseek(fd, 0, SEEK_END);
							i = ftell(fd);
							fseek(fd, 0, SEEK_SET);
							free(ptr);
							ptr = (ut8 *) malloc(i+5);
							fread(ptr+5, i, 1, fd);
							ptr[i+5]='\0';
							fclose(fd);
						}
					}
					{
					char *out = r_file_slurp ((char*)buf, &i);
					free(ptr);
					//eprintf("PIPE(%s)\n", out);
					ptr = (ut8 *) malloc(i+5);
					if (ptr) {
						memcpy (ptr+5, out, i);
						free(out);
					}
					}
					//unlink((char*)buf);
				}

				// send
				ptr[0] = (RMT_SYSTEM | RMT_REPLY);
				r_mem_copyendian ((ut8*)ptr+1, (ut8*)&i, 4, !endian);
				if (i<0)i=0;
				r_socket_write (c, ptr, i+5);
				r_socket_flush (c);
				eprintf ("REPLY SENT (%d) (%s)\n", i, ptr+5);
				free (ptr);
				break;
			default:
				eprintf ("unknown command 0x%02x\n", cmd);
				r_socket_close (c);
				return -1;
			}
		}
		eprintf ("client: disconnected\n");
	}
	return -1;
}

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb) {
	int ret, len = core->blocksize;
	ut8 *buf;
	if ((buf = malloc (len)) == NULL)
		eprintf ("Cannot allocate blocksize\n");
	else while (from<to) {
		ut64 delta = to-from;
		if (delta<len)
			len = (int)delta;
		if (!r_io_read_at (core->io, from, buf, len)) {
			eprintf ("Cannot read at 0x%"PFMT64x"\n", from);
			break;
		}
		for (ret=0; ret<len;) {
			int done = cb (core, from, buf+ret, len-ret);
			if (done<1) /* interrupted */
				return R_FALSE;
			ret += done;
		}
		from += len;
	}
	return R_TRUE;
}

R_API char *r_core_editor (RCore *core, const char *str) {
	char *name, *ret;
	int len, fd = r_file_mkstemp ("r2editor", &name);
	if (fd == -1)
		return NULL;
	if (str) write (fd, str, strlen (str));
	close (fd);
	r_sys_cmdf ("%s %s", r_config_get (core->config, "cfg.editor"), name);
	ret = r_file_slurp (name, &len);
	ret[len-1] = 0; // chop
	r_file_rm (name);
	free (name);
	return ret;
}
