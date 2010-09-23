/* radare - LGPL - Copyright 2009-2010 pancake<nopcode.org> */

#include <r_core.h>
#include <r_socket.h>
#include "../config.h"

static int endian = 1; // XXX HACK

static ut64 num_callback(RNum *userptr, const char *str, int *ok) {
	RCore *core = (RCore *)userptr; // XXX ?
	RFlagItem *flag;
	RAnalOp aop;
	ut64 ret;
	
	if (str[0]=='$') {
		/* analyze opcode */
		switch (str[1]) {
		case '$': 
			return (str[2]=='$')? aop.length:core->offset;
		case 'e':
		case 'j':
		case 'f':
		case 'r':
			r_anal_aop (core->anal, &aop, core->offset,
				core->block, core->blocksize);
			break;
		}
		
		/* return value */
		switch (str[1]) {
		case '{':
			{
				char *ptr, *bptr = strdup(str+2);
				ptr = strchr(bptr, '}');
				if (ptr != NULL) {
					ut64 ret;
					ptr[0]='\0';
					ret = r_config_get_i (core->config, bptr);
					free (bptr);
					return ret;
				}
			}
			return 0;
		case 'e': return aop.eob;
		case 'j': return aop.jump;
		case 'f': return aop.fail;
		case 'r': return aop.ref;
		case 'b': return core->blocksize;
		case 's': return core->file->size;
		case '?': return core->num->value;
		}
	}
	if ( (flag = r_flag_get (core->flags, str)) ) {
		ret = flag->offset;
		*ok = R_TRUE;
	} else *ok = ret = 0;
	return ret;
}

R_API RCore *r_core_new() {
	RCore *c = R_NEW (struct r_core_t);
	r_core_init (c);
	return c;
}

/*-----------------------------------*/
#define CMDS 54
static const char *radare_argv[CMDS] ={
	"?", "ds", "dso", "dc", "dd", "dm", "db", "S", "s",
	"!", "!!", "#md5", "#sha1", "#crc32", "V", "ad", "ac",
	"ag", "ag", "e", "i", "m", "q", "f", "fr", "x", "b", "/", "/a", "/x",
	"y", "yy", "y?", "wx", "ww", "wf", "w?", "pD", "pG", "pb", "px",
	"pX", "po", "pm", "pz", "pr >", "p?", NULL
};

#define TMP_ARGV_SZ 256
static const char *tmp_argv[TMP_ARGV_SZ];
static int autocomplete(RLine *line) {
	RCore *core = line->user;
	struct list_head *pos;
	if (core) {
		if ((!memcmp (line->buffer.data, "s ", 2)) ||
		    (!memcmp (line->buffer.data, "f ", 2)) ||
		    (!memcmp (line->buffer.data, "fr ", 3)) ||
		    (!memcmp (line->buffer.data, "/a ", 3)) ||
		    (!memcmp (line->buffer.data, "? ", 2))) {
			int n, i = 0;
			int sdelta = (line->buffer.data[1]==' ')?2:3;
			n = strlen (line->buffer.data+sdelta);
			list_for_each_prev (pos, &core->flags->flags) {
				RFlagItem *flag = list_entry (pos, RFlagItem, list);
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
			int i = 0, n = strlen (line->buffer.data+2);
			list_for_each_prev (pos, &core->config->nodes) {
				RConfigNode *bt = list_entry(pos, RConfigNode, list);
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
			int i,j;
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

static int __dbg_write(void *user, int pid, ut64 addr, const ut8 *buf, int len)
{
	RCore *core = (RCore *)user;
	// TODO: pid not used
	return r_core_write_at(core, addr, buf, len);
}
#endif

R_API int r_core_init(RCore *core) {
	static int singleton = R_TRUE;
	core->rtr_n = 0;
	core->ffio = 0;
	core->oobi = NULL;
	core->oobi_len = 0;
	core->yank = NULL;
	core->reflines = NULL;
	core->yank_len = 0;
	core->yank_off = 0LL;
	core->num = r_num_new (&num_callback, core);
	//core->num->callback = &num_callback;
	//core->num->userptr = core;
	core->cons = r_cons_singleton ();

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
	core->syscall = r_syscall_new ();
	core->vm = r_vm_new ();
	core->print = r_print_new ();
	core->print->printf = (void *)r_cons_printf;
	core->lang = r_lang_new ();
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	core->anal = r_anal_new ();
	r_anal_set_user_ptr (core->anal, core);
	core->assembler = r_asm_new ();
	r_asm_set_user_ptr (core->assembler, core);
	core->parser = r_parse_new ();
	r_parse_set_user_ptr (core->parser, core);
	core->bin = r_bin_new ();
	r_bin_set_user_ptr (core->bin, core);
	core->meta = r_meta_new ();
	core->meta->printf = (void *) r_cons_printf;
	core->io = r_io_new ();
	core->sign = r_sign_new ();
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	//r_cmd_macro_init (&core->macro);
	core->file = NULL;
	INIT_LIST_HEAD (&core->files);
	core->offset = 0LL;
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8*)malloc (R_CORE_BLOCKSIZE);
	if (core->block == NULL) {
		eprintf ("Cannot allocate %d bytes\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return R_FALSE;
	}
	r_core_cmd_init (core);
	core->flags = r_flag_new ();
	core->dbg = r_debug_new (R_TRUE);
	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->sign->printf = r_cons_printf;
	core->io->printf = r_cons_printf;
	core->dbg->printf = r_cons_printf;
	core->dbg->bp->printf = r_cons_printf;
	r_debug_io_bind (core->dbg, core->io);
	r_io_bind (core->io, &(core->vm->iob));
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

R_API int r_core_prompt(RCore *r, int sync) {
	static char *prevcmd = NULL;
	int ret;
	char *cmd;
	char line[1024];
	char prompt[32];
	const char *cmdprompt = r_config_get (r->config, "cmd.prompt");

	if (cmdprompt && cmdprompt[0])
		ret = r_core_cmd (r, cmdprompt, 0);

	/* XXX : ultraslow */
	if (!r_config_get_i (r->config, "scr.prompt"))
		*prompt = 0;
	else if (r_config_get_i (r->config, "scr.color"))
		sprintf (prompt, Color_YELLOW"[0x%08"PFMT64x"]> "Color_RESET, r->offset);
	else sprintf (prompt, "[0x%08"PFMT64x"]> ", r->offset);
	r_line_singleton()->prompt = prompt;
	ret = r_cons_fgets (line, sizeof (line), 0, NULL);
	if (ret == -2)
		return R_CORE_CMD_EXIT;
	if (ret == -1)
		return R_FALSE;
	if (strcmp (line, ".")) {
		free (prevcmd);
		prevcmd = strdup (line);
		cmd = line;
	} else cmd = prevcmd;
	if (sync) {
		ret = r_core_cmd (r, r->cmdqueue, R_TRUE);
		r_cons_flush ();
	} else {
		r->cmdqueue = cmd;
		ret = R_TRUE;
	}
	return ret;
}

R_API int r_core_prompt_exec(RCore *r) {
	int ret = r_core_cmd (r, r->cmdqueue, R_TRUE);
	r_cons_flush ();
	return ret;
}

R_API int r_core_block_size(RCore *core, ut32 bsize) {
	int ret = R_FALSE;
	if (bsize<1)
		bsize = R_TRUE;
	else if (bsize> R_CORE_BLOCKSIZE_MAX)
		bsize = R_CORE_BLOCKSIZE_MAX;
	else ret = R_TRUE;
	core->block = realloc (core->block, bsize);
	if (core->block == NULL) {
		eprintf ("Oops. cannot allocate that much (%u)\n", bsize);
		core->block = malloc (R_CORE_BLOCKSIZE);
		core->blocksize = R_CORE_BLOCKSIZE;
	} else core->blocksize = bsize;
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
	if (ret == -1)
		core->offset = tmp;
	return ret;
}

R_API char *r_core_op_str(RCore *core, ut64 addr) {
	RAsmAop aop;
	ut8 buf[64];
	int ret;
	r_asm_set_pc (core->assembler, addr);
	r_core_read_at (core, addr, buf, sizeof (buf));
	ret = r_asm_disassemble (core->assembler, &aop, buf, sizeof (buf));
	return (ret>0)?strdup (aop.buf_asm): NULL;
}

R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr) {
	ut8 buf[64];
	RAnalOp *aop = R_NEW (RAnalOp);
	r_core_read_at (core, addr, buf, sizeof (buf));
	r_anal_aop (core->anal, aop, addr, buf, sizeof (buf));
	return aop;
}

// TODO: move into core/io? */
R_API int r_core_serve(RCore *core, int fd) {
	ut8 cmd, flg, *ptr, buf[1024];
	int i, c, pipefd;
	ut64 x;

	if (fd == -1) {
		eprintf ("rap: cannot listen.\n");
		return -1;
	}

	eprintf ("RAP Server running\n");
#if __UNIX__
	// XXX: ugly workaround
	signal (SIGINT, SIG_DFL);
	signal (SIGPIPE, SIG_DFL);
#endif
reaccept:
	while ((c = r_socket_accept (fd))) {
		if (c == -1) {
			eprintf ("rap: cannot accept\n");
			r_socket_close (c);
			return -1;
		}

		eprintf ("rap: client connected\n");
		
		for (;;) {
			i = r_socket_read (c, &cmd, 1);
			if (i==0) {
				eprintf ("rap: connection closed\n");
				if (r_config_get_i (core->config, "rap.loop"))
					goto reaccept;
				return -1;
			}

			switch ((ut8)cmd) {
			case RMT_OPEN:
				r_socket_read_block (c, &flg, 1); // flags
				eprintf ("open (%d): ", cmd);
				r_socket_read_block (c, &cmd, 1); // len
				pipefd = -1;
				if (cmd<RMT_MAX) {
					ptr = malloc(cmd);
					if (ptr == NULL) {
						eprintf ("Cannot malloc in rmt-open len = %d\n", cmd);
					} else {
						r_socket_read_block (c, ptr, cmd); //filename
						ptr[cmd] = 0;
						r_core_file_open (core, (const char *)ptr, R_IO_READ); // XXX: mode write?
						pipefd = core->file->fd;
						eprintf("(flags: %hhd) len: %hhd filename: '%s'\n",
							flg, cmd, ptr); //config.file);
					}
				}
				buf[0] = RMT_OPEN | RMT_REPLY;
				r_mem_copyendian (buf+1, (ut8 *)&pipefd, 4, !endian);
				r_socket_write (c, buf, 5);
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
					write (c, ptr, i+5);
				}
				break;
			case RMT_CMD:
				{
				char bufr[8], *bufw = NULL;
				char *cmd = NULL, *cmd_output = NULL;
				int i, cmd_len = 0;

				/* read */
				r_socket_read_block (c, (ut8*)&bufr, 4);
				r_mem_copyendian ((ut8*)&i, (ut8 *)bufr, 4, endian);
				if (i >0 && i<RMT_MAX) {
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
				free(bufw);
				free(cmd_output);
				break;
				}
			case RMT_WRITE:
				read (c, buf, 5);
				r_mem_copyendian((ut8 *)&x, buf+1, 4, endian);
				ptr = malloc (x);
				read (c, ptr, x);
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
				break;
			case RMT_CLOSE:
				eprintf ("CLOSE\n");
				// XXX : proper shutdown
				r_socket_read_block (c, buf, 4);
				r_mem_copyendian ((ut8*)&i, buf, 4, endian);
				{
				int ret = r_socket_close (i);
				r_mem_copyendian (buf+1, (ut8*)&ret, 4, !endian);
				buf[0] = RMT_CLOSE | RMT_REPLY;
				r_socket_write (c, buf, 5);
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
				r_mem_copyendian ((ut8*)ptr+1, (ut8*)&i, 4, endian);
				if (i<0)i=0;
				r_socket_write (c, ptr, i+5);
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
