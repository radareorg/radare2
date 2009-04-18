/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include "r_core.h"
#include "r_flags.h"
#include "r_hash.h"
#include "r_asm.h"
#include "r_anal.h"

#include <stdarg.h>

static int cmd_iopipe(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case '\0':
		r_lib_list(&core->lib);
		r_io_handle_list(&core->io);
		break;
	default:
		r_io_system(&core->io, core->file->fd, input);
		break;
	}
	return R_TRUE;
}

/* TODO: this should be moved to the core->yank api */
static int cmd_yank_to(struct r_core_t *core, char *arg)
{
	u64 src = core->seek;
	u64 len =  0;
	u64 pos = -1;
	char *str;
	u8 *buf;

	while(*arg==' ')arg=arg+1;
	str = strchr(arg, ' ');
	if (str) {
		str[0]='\0';
		len = r_num_math(&core->num, arg);
		pos = r_num_math(&core->num, str+1);
		str[0]=' ';
	}
	if ( (str == NULL) || (pos == -1) || (len == 0) ) {
		eprintf("Usage: yt [len] [dst-addr]\n");
		return 1;
	}

#if 0
	if (!config_get("file.write")) {
		eprintf("You are not in read-write mode.\n");
		return 1;
	}
#endif

	buf = (u8*)malloc( len );
	r_core_read_at (core, src, buf, len);
	r_core_write_at (core, pos, buf, len);
	free(buf);

	core->seek = src;
	r_core_block_read(core, 0);
	return 0;
}

static int cmd_yank(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case ' ':
		r_core_yank(core, core->seek, atoi(input+1));
		break;
	case 'y':
		r_core_yank_paste(core, r_num_math(&core->num, input+2), 0);
		break;
	case 't':
		{ /* hacky implementation */
			char *arg = strdup(input+1);
			cmd_yank_to(core, arg);
			free(arg);
		}
		break;
	case '\0':
		if (core->yank == NULL) {
			fprintf(stderr, "No buffer yanked already\n");
		} else {
			int i;
			r_cons_printf("0x%08llx %d ",
				core->yank_off, core->yank_len);
			for(i=0;i<core->yank_len;i++)
				r_cons_printf("%02x", core->yank[i]);
			r_cons_newline();
		}
		break;
	default:
		r_cons_printf(
		"Usage: y[y] [len] [[@]addr]\n"
		" y            ; show yank buffer information (srcoff len bytes)\n"
		" y 16         ; copy 16 bytes into clipboard\n"
		" y 16 0x200   ; copy 16 bytes into clipboard from 0x200\n"
		" y 16 @ 0x200 ; copy 16 bytes into clipboard from 0x200\n"
		" yy 0x3344    ; paste clipboard\n");
		break;
	}
	return R_TRUE;
}

static int cmd_quit(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case '?':
		fprintf(stderr,
		"Usage: q[!] [retvalue]\n"
		" q     ; quit program\n"
		" q!    ; force quit (no questions)\n"
		" q 1   ; quit with return value 1\n"
		" q a-b ; quit with return value a-b\n");
		break;
	case '\0':
	case ' ':
	case '!':
	default:
		r_line_hist_save(".radare2_history");
		exit(r_num_math(&core->num, input+1));
		break;
	}
	return 0;
}

static int cmd_interpret(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case ' ':
		/* interpret file */
		r_core_cmd_file(core, input+1);
		break;
	case '!':
		/* from command */
		fprintf(stderr, "TODO\n");
		break;
	case '(':
		//fprintf(stderr, "macro call (%s)\n", input+1);
		r_macro_call(&core->macro, input+1);
		break;
	case '?':
		fprintf(stderr,
		"Usage: . [file] | [!command] | [(macro)]\n"
		" . foo.rs          ; interpret r script\n"
		" .!rabin -ri $FILE ; interpret output of command\n"
		" .(foo 1 2 3)      ; run macro 'foo' with args 1, 2, 3\n"
		" ./m ELF           ; interpret output of command /m ELF as r. commands\n");
		break;
	default:
		{
		char *str = r_core_cmd_str(core, input);
		char *ptr = str;
		while(1) {
			char *eol = strchr(ptr, '\n');
			if (eol) eol[0]='\0';
			r_core_cmd(core, ptr, 0);
			if (!eol) break;
			ptr = eol+1;
		}
		free(str);
		}
		break;
	}
	return 0;
}

static int cmd_seek(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;

	if (input[0]=='\0') {
		r_cons_printf("0x%llx\n", core->seek);
	} else {
		int idelta = (input[1]==' ')?2:1;
		u64 off = r_num_math(&core->num, input+idelta);
		if (input[0]==' ' && (input[1]=='+'||input[1]=='-'))
			input = input+1;
		switch(input[0]) {
		case ' ':
			r_core_seek(core, off, 1);
			break;
		case '+':
			if (input[1]=='+') r_core_seek_delta(core, core->blocksize);
			else r_core_seek_delta(core, off);
			break;
		case '-':
			if (input[1]=='-') r_core_seek_delta(core, -core->blocksize);
			else r_core_seek_delta(core, -off);
			break;
		case 'a':
			{
				u64 alsz = core->blocksize;

				if (input[1]&&input[2]) {
					char *cmd, *p; 
					cmd = strdup(input);
					p = strchr(cmd+2, ' ');
					if (p) {
						alsz = r_num_math(&core->num, p+1);;
						*p='\0';
					}
					cmd[0]='s';
					// perform real seek if provided
					r_cmd_call(&core->cmd, cmd);
					free(cmd);
				}

				r_core_seek_align(core, alsz, 0);
			}
			break;
		case '?':
			fprintf(stderr,
			"Usage: s[+-] [addr]\n"
			" s 0x320    ; seek to this address\n"
			" s++        ; seek blocksize bytes forward\n"
			" s--        ; seek blocksize bytes backward\n"
			" s+ 512     ; seek 512 bytes forward\n"
			" s- 512     ; seek 512 bytes backward\n"
			" sa [[+-]a] [asz] ; seek asz (or bsize) aligned to addr\n");
			break;
		}
	}
	return 0;
}

static int cmd_help(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	u64 n;

	switch(input[0]) {
	case ' ':
		n = r_num_math(&core->num, input+1);
		r_cons_printf("%lld 0x%llx\n", n,n);
		break;
	case '=':
		r_num_math(&core->num, input+1);
		break;
	case '+':
		if (input[1]) {
			if (core->num.value & U64_GT0)
				r_core_cmd(core, input+1, 0);
		} else r_cons_printf("0x%llx\n", core->num.value);
		break;
	case '-':
		if (input[1]) {
			if (core->num.value & U64_LT0)
				r_core_cmd(core, input+1, 0);
		} else r_cons_printf("0x%llx\n", core->num.value);
		break;
	case '!': // ??
		if (input[1]) {
			if (core->num.value != U64_MIN)
				r_core_cmd(core, input+1, 0);
		} else r_cons_printf("0x%llx\n", core->num.value);
		break;
	case '$':
		return cmd_help(data, " $?");
	case 'z':
		for(input=input+1;input[0]==' ';input=input+1);
		core->num.value = strlen(input);
		break;
	case 't':
		{
			struct r_prof_t prof;
			r_prof_start(&prof);
			r_core_cmd(core, input+1, 0);
			r_prof_end(&prof);
			core->num.value = (u64)prof.result;
			eprintf("%lf\n", prof.result);
		}
		break;
	case '?': // ???
		if (input[1]=='?') {
			fprintf(stderr,
			"Usage: ?[?[?]] expression\n"
			" ? eip-0x804800  ; calculate result for this math expr\n"
			" ?= eip-0x804800 ; same as above without user feedback\n"
			" ?? [cmd]        ; ? == 0  run command when math matches\n"
			" ?z str          ; returns the length of string (0 if null)\n"
			" ?t cmd          ; returns the time to run a command\n"
			" ?! [cmd]        ; ? != 0\n"
			" ?+ [cmd]        ; ? > 0\n"
			" ?- [cmd]        ; ? < 0\n"
			" ???             ; show this help\n"
			"$variables:\n"
			" $$  = here (current seek)\n"
			" $s  = file size\n"
			" $b  = block size\n"
			" $j  = jump address\n"
			" $f  = address of next opcode\n"
			" $r  = opcode reference pointer\n"
			" $e  = 1 if end of block, else 0\n"
			" ${eval} = get value of eval variable\n"
			" $?  = last comparision value\n");
			return 0;
		} else
		if (input[1]) {
			if (core->num.value == U64_MIN)
				r_core_cmd(core, input+1, 0);
		} else r_cons_printf("0x%llx\n", core->num.value);
		break;
	case '\0':
	default:
		r_cons_printf(
		"Usage:\n"
		" a                 ; perform analysis of code\n"
		" b [bsz]           ; get or change block size\n"
		" C[CFf..]          ; Code metadata management\n"
		" d[hrscb]          ; debugger commands\n"
		" e [a[=b]]         ; list/get/set config evaluable vars\n"
		" f [name][sz][at]  ; set flag at current address\n"
		" s [addr]          ; seek to address\n"
		" i [file]          ; get info about opened file\n"
		" p?[len]           ; print current block with format and length\n"
		" V[vcmds]          ; enter visual mode (vcmds=visualvisual  keystrokes)\n"
		" w[mode] [arg]     ; multiple write operations\n"
		" x [len]           ; alias for 'px' (print hexadecimal\n"
		" y [len] [off]     ; yank/paste bytes from/to memory\n"
		" ? [expr]          ; help or evaluate math expression\n"
		" /[xmp/]           ; search for bytes, regexps, patterns, ..\n"
		" |[cmd]            ; run this command thru the io pipe (no args=list)\n"
		" #[algo] [len]     ; calculate hash checksum of current block\n"
		" .[ file|!cmd|cmd|(macro)]  ; interpret as radare cmds\n"
		" (macro arg0 arg1) ; define scripting macros\n"
		" q [ret]           ; quit program with a return value\n"
		"Use '?$' to get help for the variables\n"
		"Use '?""??' for extra help about '?' subcommands.\n"
		"Append '?' to any char command to get detailed help\n");
		break;
	}
	return 0;
}

static int cmd_bsize(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case '\0':
		r_cons_printf("0x%x\n", core->blocksize);
		break;
	default:
		//input = r_str_clean(input);
		r_core_block_size(core, r_num_math(NULL, input));
		break;
	}
	return 0;
}

static int cmd_info(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	char buf[1024];
	switch(input[0]) {
	case 's':
	case 'i':
	case 'I':
	case 'e':
	case 'S':
	case 'z':
		snprintf(buf, 1023, "rabin2 -%c%s '%s'", input[0],
			input[1]=='*'?"r":"", core->file->filename);
		fprintf(stderr, "(%s)\n", buf);
		system(buf);
		break;
	case '?':
		r_cons_printf(
		"Usage: i[eiIsSz]*      ; get info from opened file (rabin2)\n"
		"; Append a '*' to get the output in radare commands\n"
		" ii    ; imports\n"
		" iI    ; binary info\n"
		" ie    ; entrypoint\n"
		" is    ; symbols\n"
		" iS    ; sections\n"
		" iz    ; strings\n");
		break;
	case '*':
		break;
	default:
		r_cons_printf("uri: %s\n", core->file->uri);
		r_cons_printf("filesize: 0x%x\n", core->file->size);
		r_cons_printf("blocksize: 0x%x\n", core->blocksize);
	}
	return 0;
}

static int cmd_print(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	int l, len = core->blocksize;
	u32 tbs = core->blocksize;
	int show_offset  = r_config_get_i(&core->config, "asm.offset");
	int show_bytes = r_config_get_i(&core->config, "asm.bytes");
	int show_lines = r_config_get_i(&core->config, "asm.reflines");
	int linesout = r_config_get_i(&core->config, "asm.reflinesout");
	int show_comments = r_config_get_i(&core->config, "asm.comments");
	int linesopts = 0;
	int pseudo = r_config_get_i(&core->config, "asm.pseudo");

	if (r_config_get_i(&core->config, "asm.reflinesstyle"))
		linesopts |= R_ANAL_REFLINE_STYLE;
	if (r_config_get_i(&core->config, "asm.reflineswide"))
		linesopts |= R_ANAL_REFLINE_WIDE;

	if (input[0] && input[1]) {
		l = (int) r_num_get(&core->num, input+2);
		if (l>0) len = l;
		if (l>tbs) {
			r_core_block_size(core, l);
			len = l;
		}
	}
	
	switch(input[0]) {
	case 'd':
		{
			int ret, idx; 
			u8 *buf = core->block;
			char str[128];
			char line[128];
			char *comment;
			struct r_asm_aop_t asmop;
			struct r_anal_aop_t analop;
			struct r_anal_refline_t *reflines;
		
			r_anal_set_pc(&core->anal, core->seek);
			r_asm_set_pc(&core->assembler, core->seek);

			reflines = r_anal_reflines_get(&core->anal, buf, len, -1, linesout);
			for(idx=ret=0; idx < len; idx+=ret) {
				r_asm_set_pc(&core->assembler, core->assembler.pc + ret);
				r_anal_set_pc(&core->anal, core->anal.pc + ret);
				if (show_comments) {
					comment = r_meta_get_string(&core->meta, R_META_COMMENT, core->anal.pc+ret);
					if (comment) {
						r_cons_strcat(comment);
						free(comment);
					}
				}
				r_anal_reflines_str(&core->anal, reflines, line, linesopts);
				ret = r_asm_disassemble(&core->assembler, &asmop, buf+idx, len-idx);
				if (ret<1) {
					ret = 1;
					eprintf("** invalid opcode at 0x%08llx **\n", core->assembler.pc + ret);
				}
				r_anal_aop(&core->anal, &analop, buf+idx);

				if (show_lines) r_cons_printf("%s", line);
				if (show_offset) r_cons_printf("0x%08llx ", core->seek + idx);
				if (show_bytes) {
					struct r_flag_item_t *flag = r_flag_get_i(&core->flags, core->seek+idx);
					if (flag) {
						r_cons_printf("*[ %10s] ", flag->name);
					} else r_cons_printf("%14s ", asmop.buf_hex);
				}
				if (pseudo) {
					r_parse_parse(&core->parser, asmop.buf_asm, str);
					r_cons_printf("%s\n", str);
				} else r_cons_printf("%s\n", asmop.buf_asm);
				if (show_lines && analop.type == R_ANAL_AOP_TYPE_RET) {
					if (strchr(line, '>'))
						memset(line, ' ', strlen(line));
					r_cons_printf("%s", line);
					r_cons_printf("\t\t; ------------------------------------\n");
				}
			}
			free(reflines);
		}
		break;
	case 's':
		r_print_string(&core->print, core->seek, core->block, len, 0, 1, 0); //, 78, 1);
		break;
	case 'S':
		r_print_string(&core->print, core->seek, core->block, len, 1, 1, 0); //, 78, 1);
		break;
	case 'u':
		r_print_string(&core->print, core->seek, core->block, len, 0, 1, 1); //, 78, 1);
		break;
	case 'U':
		r_print_string(&core->print, core->seek, core->block, len, 1, 1, 1); //, 78, 1);
		break;
	case 'c':
		r_print_code(&core->print, core->seek, core->block, len); //, 78, 1);
		break;
	case 'r':
		r_print_raw(&core->print, core->block, len);
		break;
	case 'o':
        	r_print_hexdump(&core->print, core->seek, core->block, len, 8, 1); //, 78, !(input[1]=='-'));
		break;
	case 'x':
        	r_print_hexdump(&core->print, core->seek, core->block, len, 16, 1); //, 78, !(input[1]=='-'));
		break;
	case '8':
		r_print_bytes(&core->print, core->block, len, "%02x");
		break;
	default:
		//r_cons_printf("Unknown subcommand '%c'\n", input[0]);
		r_cons_printf("Usage: p[8] [len]    ; '%c' is unknown\n"
		" p8 [len]    8bit hexpair list of bytes\n"
		" px [len]    hexdump of N bytes\n"
		" po [len]    octal dump of N bytes\n"
		" pc [len]    output C format\n"
		" ps [len]    print string\n"
		" pS [len]    print wide string\n"
		" pd [len]    disassemble N bytes\n"
		" pr [len]    print N raw bytes\n"
		" pu [len]    print N url encoded bytes\n"
		" pU [len]    print N wide url encoded bytes\n", input[0]);
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size(core, tbs);
	return 0;
}

static int cmd_hexdump(void *data, const char *input)
{
	return cmd_print(data, input-1);
}

static int cmd_flag(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	int len = strlen(input)+1;
	char *str = alloca(len);
	memcpy(str, input+1, len);

	switch(input[0]) {
	case '+':
		r_flag_set(&core->flags, str, core->seek, core->blocksize, 1);
		break;
	case ' ': {
		char *s = NULL, *s2 = NULL;
		u64 seek = core->seek;
		u32 bsze = core->blocksize;
		s = strchr(str, ' ');
		if (s) {
			*s = '\0';
			s2 = strchr(s+1, ' ');
			if (s2) {
				*s2 = '\0';
				seek = r_num_math(&core->num, s2+1);
			}
			bsze = r_num_math(&core->num, s+1);
		}
		r_flag_set(&core->flags, str, seek, bsze, 0);
		if (s) *s=' ';
		if (s2) *s2=' ';
		}
		break;
	case '-':
		r_flag_unset(&core->flags, input+1);
		break;
	case 'b':
		r_flag_set_base(&core->flags, r_num_math(&core->num, input+1));
		break;
	case 's':
		if (input[1]==' ')
			r_flag_space_set(&core->flags, input+2);
		else r_flag_space_list(&core->flags);
		break;
	case 'o':
		{
			char *file = PREFIX"/share/doc/radare2/fortunes";
			char *line = r_file_slurp_random_line (file);
			r_cons_printf("%s\n", line);
			free(line);
		}
		break;
	case '*':
		r_flag_list(&core->flags, 1);
		break;
	case '\0':
		r_flag_list(&core->flags, 0);
		break;
	case '?':
		fprintf(stderr, "Usage: f[ ] [flagname]\n"
		" fb 0x8048000     ; set base address for flagging\n"
		" f name 12 @ 33   ; set flag 'name' with size 12 at 33\n"
		" f name 12 33     ; same as above\n"
		" f+name 12 @ 33   ; like above but creates new one if doesnt exist\n"
		" f-name           ; remove flag 'name'\n"
		" f                ; list flags\n"
		" f*               ; list flags in r commands\n");
		break;
	}
	return 0;
}

static int cmd_anal(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	int l, len = core->blocksize;
	u32 tbs = core->blocksize;

	if (input[0] && input[1]) {
		l = (int) r_num_get(&core->num, input+2);
		if (l>0) len = l;
		if (l>tbs) {
			r_core_block_size(core, l);
			len = l;
		}
	}
	
	switch(input[0]) {
	case '\0':
		r_anal_list(&core->anal);
		break;
	case 'o':
		{
			/* XXX hardcoded */
			int ret, idx; 
			u8 *buf = core->block;
			struct r_anal_aop_t aop;
			r_anal_set(&core->anal, "anal_x86_bea");
			
			for(idx=ret=0; idx < len; idx+=ret) {
				r_anal_set_pc(&core->anal, core->seek + idx);
				ret = r_anal_aop(&core->anal, &aop, buf + idx);
			}
		}
		break;
	default:
		fprintf(stderr, "Usage: a[o] [len]\n"
		" ao [len]    Analyze raw bytes\n");
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size(core, tbs);
	return 0;
}

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input)
{
	int i, len = strlen(input);
	char *tmp, *str = alloca(len)+1;
	struct r_core_t *core = (struct r_core_t *)data;
	memcpy(str, input+1, len);
	switch(input[0]) {
	case ' ':
		/* write string */
		len = r_str_escape(str);
		r_io_lseek(&core->io, core->file->fd, core->seek, R_IO_SEEK_SET);
		r_io_write(&core->io, core->file->fd, (const u8*)str, len);
		r_core_block_read(core, 0);
		break;
	case 't':
		{
			/* TODO: Support user defined size? */
			int len = core->blocksize;
			char *arg = input+(input[1]==' ')?2:1;
			char *buf = core->block;
			r_file_dump(arg, buf, len);
		}
		break;
	case 'T':
		fprintf(stderr, "TODO\n");
		break;
	case 'f':
		{
			int size;
			char *arg = input+(input[1]==' ')?2:1;
			u8 *buf = r_file_slurp(arg, &size);
			if (buf == NULL) {
				eprintf("Cannot open file '%s'\n", arg);
			} else {
				r_io_write(&core->io, core->file->fd, buf, size);
				free(buf);
			}
		}
		break;
	case 'F':
		{
			int size;
			char *arg = input+(input[1]==' ')?2:1;
			u8 *buf = r_file_slurp_hexpairs(arg, &size);
			if (buf == NULL) {
				eprintf("Cannot open file '%s'\n", arg);
			} else {
				r_io_write(&core->io, core->file->fd, buf, size);
				free(buf);
			}
		}
		break;
	case 'w':
		str = str+1;
		len = len-1;
		len *= 2;
		tmp = alloca(len);
		for(i=0;i<len;i++) {
			if (i%2) tmp[i] = 0;
			else tmp[i] = str[i>>1];
		}
		str = tmp;

		// write strifng
		r_io_lseek(&core->io, core->file->fd, core->seek, R_IO_SEEK_SET);
		r_io_write(&core->io, core->file->fd, str, len);
		r_core_block_read(core, 0);
		break;
	case 'x':
		{
		int len = strlen(input);
		char *buf = alloca(len);
		len = r_hex_str2bin(input+1, buf);
		r_core_write_at(core, core->seek, buf, len);
		r_core_block_read(core, 0);
		}
		// write hexpairs
		break;
	case 'a':
		{
		int ret = 0;
		struct r_asm_aop_t aop;
		char buf[128];
		/* XXX ULTRAUGLY , needs fallback support in rasm */
		r_asm_set(&core->assembler, "asm_x86_olly");
		r_asm_set_pc(&core->assembler, core->seek);
		if (input[1]==' ')input=input+1;
		ret = r_asm_massemble(&core->assembler, &aop, input+1);
		eprintf("Written %d bytes (%s)=wx %s\n", ret, input+1, aop.buf_hex);
		r_core_write_at(core, core->seek, aop.buf, ret);
		r_core_block_read(core, 0);
		r_asm_set(&core->assembler, "asm_x86"); /* XXX */
		}
		break;
	case 'b':
		{
		int len = strlen(input);
		char *buf = alloca(len);
		len = r_hex_str2bin(input+1, buf);
		r_mem_copyloop(core->block, buf, core->blocksize, len);
		r_core_write_at(core, core->seek, core->block, core->blocksize);
		r_core_block_read(core, 0);
		}
		break;
	case 'm':
		{
		int len = strlen(input+1);
		len = r_hex_str2bin(input+1, str);
		switch(input[1]) {
		case '\0':
			fprintf(stderr, "Current write mask: TODO\n");
			// TODO
			break;
		case '?':
			break;
		case '-':
			r_io_set_write_mask(&core->io, -1, 0, 0);
			fprintf(stderr, "Write mask disabled\n");
			break;
		case ' ':
			if (len == 0) {
				fprintf(stderr, "Invalid string\n");
			} else {
				r_io_set_write_mask(&core->io, core->file->fd, str, len);
				fprintf(stderr, "Write mask set to '");
				for (i=0;i<len;i++)
					fprintf(stderr, "%02x", str[i]);
				fprintf(stderr, "'\n");
			}
			break;
		}
		}
		break;
	case 'v':
		{
		u64 off = r_num_math(&core->num, input+1);
		r_io_lseek(&core->io, core->file->fd, core->seek, R_IO_SEEK_SET);
		if (off&U64_32U) {
			/* 8 byte addr */
			u64 addr8;
			memcpy((u8*)&addr8, (u8*)&off, 8); // XXX needs endian here
		//	endian_memcpy((u8*)&addr8, (u8*)&off, 8);
			r_io_write(&core->io, core->file->fd, (const u8 *)&addr8, 8);
		} else {
			/* 4 byte addr */
			u32 addr4, addr4_ = (u32)off;
			//drop_endian((u8*)&addr4_, (u8*)&addr4, 4); /* addr4_ = addr4 */
			//endian_memcpy((u8*)&addr4, (u8*)&addr4_, 4); /* addr4 = addr4_ */
			memcpy((u8*)&addr4, (u8*)&addr4_, 4); // XXX needs endian here too
			r_io_write(&core->io, core->file->fd, (const u8 *)&addr4, 4);
		}
		r_core_block_read(core, 0);
		}
		break;
	case 'o':
                switch(input[1]) {
                case 'a':
                case 's':
                case 'A':
                case 'x':
                case 'r':
                case 'l':
                case 'm':
                case 'd':
                case 'o':
                        if (input[2]!=' ') {
                                fprintf(stderr, "Usage: 'wo%c 00 11 22'\n", input[1]);
                                return 0;
                        }
                case '2':
                case '4':
                        r_core_write_op(core, input+3, input[1]);
                        break;
                case '\0':
                case '?':
                default:
                        fprintf(stderr, 
                        "Usage: wo[xrlasmd] [hexpairs]\n"
                        "Example: wox 90    ; xor cur block with 90\n"
                        "Example: woa 02 03 ; add 2, 3 to all bytes of cur block\n"
                        "Supported operations:\n"
                        "  woa  addition            +=\n"
                        "  wos  substraction        -=\n"
                        "  wom  multiply            *=\n"
                        "  wod  divide              /=\n"
                        "  wox  xor                 ^=\n"
                        "  woo  or                  |=\n"
                        "  woA  and                 &=\n"
                        "  wor  shift right         >>=\n"
                        "  wol  shift left          <<=\n"
                        "  wo2  2 byte endian swap  2=\n"
                        "  wo4  4 byte endian swap  4=\n"
                        );
                        break;
                }
                break;
	default:
	case '?':
		if (core->oobi) {
			fprintf(stderr, "Writing oobi buffer!\n");
			r_io_write(&core->io, core->file->fd, core->oobi, core->oobi_len);
		} else
			r_cons_printf("Usage: w[x] [str] [<file] [<<EOF] [@addr]\n"
			" w foobar    ; write string 'foobar'\n"
			" ww foobar   ; write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'\n"
			" wa push ebp ; write opcode, separated by ';' (use '\"' around the command)\n"
			" wb 010203   ; fill current block with cyclic hexpairs\n"
			" wx 9090     ; write two intel nops\n"
			" wv eip+34   ; write 32-64 bit value\n"
			" wo[] hex    ; write in block with operation. 'wo?' fmi\n"
			" wm f0ff     ; cyclic write mask\n"
			" wf file     ; write contents of file at current offset\n"
			" wF file     ; write contents of hexpairs file here\n"
			" wt file     ; write current block to file\n");
			//TODO: add support for offset+seek
			// " wf file o s ; write contents of file from optional offset 'o' and size 's'.\n"
		break;
	}
	return 0;
}

static char *cmdhit = NULL;
static int __cb_hit(struct r_search_kw_t *kw, void *user, u64 addr)
{
	struct r_core_t *core = (struct r_core_t *)user;

	r_cons_printf("f hit%d_%d %d 0x%08llx\n",
		kw->kwidx, kw->count, kw->keyword_length, addr);

	if (!strnull(cmdhit)) {
		u64 here = core->seek;
		r_core_seek(core, addr, R_FALSE);
		r_core_cmd(core, cmdhit, 0);
		r_core_seek(core, here, R_TRUE);
	}

	return R_TRUE;
}

static int cmd_search(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	u64 at;
	u32 n32;
	int ret, dosearch = 0;
	u8 *buf;
	switch (input[0]) {
	case '/':
		r_search_begin(core->search);
		dosearch = 1;
		break;
	case 'v':
		r_search_free(core->search);
		core->search = r_search_new(R_SEARCH_KEYWORD);
		n32 = r_num_math(&core->num, input+1);
		r_search_kw_add_bin(core->search, &n32, 4, "",0);
		r_search_begin(core->search);
		dosearch = 1;
		break;
	case ' ': /* search string */
		r_search_free(core->search);
		core->search = r_search_new(R_SEARCH_KEYWORD);
		r_search_kw_add(core->search, input+1, "");
		r_search_begin(core->search);
		dosearch = 1;
		break;
	case 'm': /* match regexp */
		{
		char *inp = strdup(input+2);
		char *res = r_str_lchr(inp+1, inp[0]);
		char *opt = NULL;
		if (res > inp) {
			opt = strdup(res+1);
			res[1]='\0';
		}
		r_search_free(core->search);
		core->search = r_search_new(R_SEARCH_REGEXP);
		r_search_kw_add(core->search, inp, opt);
		r_search_begin(core->search);
		dosearch = 1;
		free(inp);
		free(opt);
		}
		break;
	case 'x': /* search hex */
		r_search_free(core->search);
		core->search = r_search_new(R_SEARCH_KEYWORD);
		r_search_kw_add_hex(core->search, input+2, "");
		r_search_begin(core->search);
		dosearch = 1;
		break;
	default:
		r_cons_printf("Usage: /[xm/] [arg]\n"
		" / foo     ; search for string 'foo'\n"
		" /m /E.F/i ; match regular expression\n"
		" /x ff0033 ; search for hex string\n"
		" //        ; repeat last search\n");
		break;
	}
	if (core->search->n_kws==0) {
		printf("No keywords defined\n");
	} else
	if (dosearch) {
		/* set callback */
		/* TODO: handle last block of data */
		/* TODO: handle ^C */
		/* TODO: launch search in background support */
		buf = (u8 *)malloc(core->blocksize);
		r_search_set_callback(core->search, &__cb_hit, core);
		cmdhit = r_config_get(&core->config, "cmd.hit");
		r_cons_break(NULL, NULL);
		for(at = core->seek; at < core->file->size; at += core->blocksize) {
			if (r_cons_breaked)
				break;
			r_io_lseek(&core->io, core->file->fd, at, R_IO_SEEK_SET);
			ret = r_io_read(&core->io, core->file->fd, buf, core->blocksize);
			if (ret != core->blocksize)
				break;
			if (r_search_update(core->search, &at, buf, ret) == -1) {
				printf("search:update error\n");
				break;
			}
		}
		r_cons_break_end();
	}
	return R_TRUE;
}

static int cmd_eval(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case '\0':
		r_config_list(&core->config, NULL, 0);
		break;
	case '!':
		input = r_str_chop_ro(input+1);
		if (!r_config_swap(&core->config, input))
			eprintf("r_config: '%s' is not a boolean variable.\n", input);
		break;
	case '-':
		r_core_config_init(core);
		eprintf("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*':
		r_config_list(&core->config, NULL, 1);
		break;
	case '?':
		r_cons_printf(
		"Usage: e[?] [var[=value]]\n"
		"  e     ; list config vars\n"
		"  e-    ; reset config vars\n"
		"  e*    ; dump config vars in r commands\n"
		"  e!a   ; invert the boolean value of 'a' var\n"
		"  e a   ; get value of var 'a'\n"
		"  e a=b ; set var 'a' the 'b' value\n");
		//r_cmd_help(&core->cmd, "e");
		break;
	default:
		r_config_eval(&core->config, input);
	}
	return 0;
}

static int cmd_hash(void *data, const char *input)
{
	char algo[32];
	struct r_core_t *core = (struct r_core_t *)data;
	u32 len = core->blocksize;
	const char *ptr;

	if (input[0]=='!') {
#if 0
		#!lua < file
		#!lua <<EOF
		#!lua
		#!lua foo bar
#endif
		if (input[1]=='\0') {
			r_lang_list(&core->lang);
			return R_TRUE;
		}
		// TODO: set argv here
		r_lang_set(&core->lang, input+1);
		if (core->oobi)
			r_lang_run(&core->lang,(const char *)
				core->oobi, core->oobi_len);
		else r_lang_prompt(&core->lang);
		return R_TRUE;
	}

	ptr = strchr(input, ' ');
	sscanf(input, "%31s", algo);
	if (ptr != NULL)
		len = r_num_math(&core->num, ptr+1);

	if (!r_str_ccmp(input, "crc32", ' ')) {
		r_cons_printf("%04x\n", r_hash_crc32(core->block, len));
	} else
	if (!r_str_ccmp(input, "crc16", ' ')) {
		r_cons_printf("%02x\n", r_hash_crc16(0, core->block, len));
	} else {
		r_cons_printf(
		"Usage: #algo <size> @ addr\n"
		" #crc32               ; calculate crc32 of current block\n"
		" #crc32 < /etc/fstab  ; calculate crc32 of this file\n"
		" #md5 128K @ edi      ; calculate md5 of 128K from 'edi'\n"
		"Usage #!interpreter [<args>] [<file] [<<eof]\n"
		" #!                   ; list all available interpreters\n"
		" #!python             ; run python commandline\n"
		" #!python < foo.py    ; run foo.py python script\n"
		" #!python <<EOF       ; get python code until 'EOF' mark\n"
		" #!python arg0 a1 <<q ; set arg0 and arg1 and read until 'q'\n");
	}

	return 0;
}

static int cmd_visual(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	r_core_visual(core, input);
	return 0;
}

static int cmd_system(void *data, const char *input)
{
	//struct r_core_t *core = (struct r_core_t *)data;
	// slurped from teh old radare_system
#if __FreeBSD__
	/* freebsd system() is broken */
	int fds[2];
	int st,pid;
	char *argv[] ={ "/bin/sh", "-c", input, NULL};
	pipe(fds);
	/* not working ?? */
	//pid = rfork(RFPROC|RFCFDG);
	pid = vfork();
	if (pid == 0) {
		dup2(1, fds[1]);
		execv(argv[0], argv);
		_exit(127); /* error */
	} else {
		dup2(1, fds[0]);
		waitpid(pid, &st, 0);
	}
	return WEXITSTATUS(st);
#else
	return system(input);
#endif
}

static int cmd_meta(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	int ret, line = 0;
	char file[1024];
	//struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case '*':
		r_meta_list(&core->meta, R_META_ANY);
		break;
	case 'L': // debug information of current offset
		ret = r_bininfo_get_line(
			&core->bininfo, core->seek, file, 1023, &line);
		if (ret)
			r_cons_printf("file %s\nline %d\n", file, line);
		break;
	case 'C': /* add comment */
		// TODO: do we need to get the size? or the offset?
		// TODO: is this an exception compared to other C? commands?
		if (input[1]==' ') input = input+1;
		if (input[1]=='-') {
			r_meta_del(&core->meta, R_META_COMMENT, core->seek, 1, input+2);
		} else r_meta_add(&core->meta, R_META_COMMENT, core->seek, 1, input+1);
		break;
	case 'S':
	case 's':
	case 'm': /* struct */
	case 'x': /* code xref */
	case 'X': /* data xref */
	case 'F': /* add function */
		{
		u64 addr = core->seek;
		char fun_name[128];
		int size = atoi(input);
		int type = R_META_FUNCTION;
		char *t, *p = strchr(input+1, ' ');
		if (p) {
			t = strdup(p+1);
printf("T=(%s)\n", t);
			p = strchr(t, ' ');
			if (p) {
				*p='\0';
				strncpy(fun_name, p+1, sizeof(fun_name));
			} else sprintf(fun_name, "sub_%08llx", addr);
			addr = r_num_math(&core->num, t);
			free(t);
		}
		r_meta_add(&core->meta, type, addr, size, fun_name);
		}
		break;
	case '\0':
	case '?':
		eprintf(
		"Usage: C[CDF?] [arg]\n"
		" CL [addr]               ; show 'code line' information (bininfo)\n"
		" CF [size] [name] [addr] [name] ; register function size here (TODO)\n"
		" CC [string]             ; add comment (TODO)\n");
	}
	return R_TRUE;
}

static int cmd_undowrite(void *data, const char *input)
{
	//struct r_core_t *core = (struct r_core_t *)data;
	// TODO:
	return 0;
}

static int cmd_io_system(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	return r_io_system(&core->io, core->file->fd, input);
}

static int cmd_macro(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	switch(input[0]) {
	case ')':
		r_macro_break(&core->macro, input+1);
		break;
	case '-':
		r_macro_rm(&core->macro, input+1);
		break;
	case '\0':
		r_macro_list(&core->macro);
		break;
	case '?':
		eprintf(
		"Usage: (foo\\n..cmds..\\n)\n"
		" Record macros grouping commands\n"
		" (foo args\\n ..)  ; define a macro\n"
		" (-foo)            ; remove a macro\n"
		" .(foo)            ; to call it\n"
		" ()                ; break inside macro\n"
		"Argument support:\n"
		" (foo x y\\n$1 @ $2) ; define fun with args\n"
		" .(foo 128 0x804800) ; call it with args\n"
		"Iterations:\n"
		" .(foo\\n() $@)      ; define iterator returning iter index\n"
		" x @@ .(foo)         ; iterate over them\n"
		);
		break;
	default:
		r_macro_add(&core->macro, input);
		break;
	}
	return 0;
}

static int r_core_cmd_subst(struct r_core_t *core, char *cmd, int *rs, int *rfd, int *times)
{
	char *ptr, *ptr2, *str;
	int i, len = strlen(cmd);

	len = atoi(cmd);
	if (len>0) {
		for(i=0;cmd[i]>='0'&&cmd[i]<='9'; i++);
		if (i>0) strcpy(cmd, cmd+i);
		*times = len;
	}
	if (cmd[0]=='\0')
		return 0;

	ptr = strchr(cmd, ';');
	if (ptr)
		ptr[0]='\0';

	ptr = strchr(cmd+1, '|');
	if (ptr) {
		ptr[0] = '\0';
		eprintf("System pipes not yet supported.\n");
	}

	/* Out Of Band Input */
	free(core->oobi);
	core->oobi = NULL;
	ptr = strchr(cmd, '<');
	if (ptr) {
		ptr[0] = '\0';
		if (ptr[1]=='<') {
			/* this is a bit mess */
			char *oprompt = r_line_prompt;
			oprompt = ">";
			for(str=ptr+2;str[0]== ' ';str=str+1);
			eprintf("==> Reading from stdin until '%s'\n", str);
			free(core->oobi);
			core->oobi = malloc(1);
			core->oobi[0] = '\0';
			core->oobi_len = 0;
			for (;;) {
				char buf[1024];
				int ret;
				printf("> "); fflush(stdout);
				fgets(buf, 1023, stdin);
				if (feof(stdin))
					break;
				buf[strlen(buf)-1]='\0';
				ret = strlen(buf);
				core->oobi_len+=ret;
				core->oobi = realloc(core->oobi, core->oobi_len+1);
				if (!strcmp(buf, str))
					break;
				strcat((char *)core->oobi, buf);
			}
			r_line_prompt = oprompt;
		} else {
			for(str=ptr+1;str[0]== ' ';str=str+1);
			eprintf("SLURPING FILE '%s'\n", str);
			core->oobi = r_file_slurp(str, &core->oobi_len);
			if (core->oobi == NULL)
				eprintf("Cannot open file\n");
			else if (ptr == cmd)
				return r_core_cmd_buffer(core, core->oobi);
		}
	}
	/* Pipe console to file */
	ptr = strchr(cmd, '>');
	if (ptr) {
		ptr[0] = '\0';
		for(str=ptr+1; str[0]== ' '; str=str+1);
		*rfd = r_cons_pipe_open(str, ptr[1]=='>');
	}

	while(((ptr = strchr(cmd, '`')))) {
		ptr2 = strchr(ptr+1, '`');
		if (ptr2==NULL) {
			fprintf(stderr, "parse: Missing '`' in expression (%s).\n", ptr+1);
			return 0;
		}
		ptr2[0]='\0';
		str = r_core_cmd_str(core, ptr+1);
		for(i=0;str[i];i++) if (str[i]=='\n') str[i]=' ';
		r_str_inject(ptr, ptr2+1, str, 1024); // XXX overflow here, fix maxlength
		free(str);
	}

	ptr = strchr(cmd, '~');
	if (ptr) {
		ptr[0]='\0';
		r_cons_grep(ptr+1);
	} else r_cons_grep(NULL);

	ptr = strchr(cmd, '@');
	if (ptr) {
		char *pt = ptr;
		ptr[0]='\0';
		while(pt[0]==' '||pt[0]=='\t') {
			pt[0]='\0';
			pt = pt-1;
		}
		*rs = 1;
		if (ptr[1]=='@') {
			// TODO: remove temporally seek (should be done by cmd_foreach)
			u64 tmpoff = core->seek;
			r_core_cmd_foreach(core, cmd, ptr+2);
			r_core_seek(core, tmpoff, 1);
			return -1; /* do not run out-of-foreach cmd */
		} else r_core_seek(core, r_num_math(&core->num, ptr+1),1);
	}

	return 0;
}

R_API int r_core_cmd_foreach(struct r_core_t *core, const char *cmd, char *each)
{
//void radare_cmd_foreach(const char *cmd, const char *each)
	int i=0,j;
	char ch;
	char *word = NULL;
	char *str, *ostr;
	struct list_head *pos;
	u64 oseek, addr;

	for(;*each==' ';each=each+1);
	for(;*cmd==' ';cmd=cmd+1);

	oseek = core->seek;
	ostr = str = strdup(each);
	//radare_controlc();

	switch(each[0]) {
	case '?':
		eprintf("Foreach '@@' iterator command:\n");
		eprintf(" This command is used to repeat a command over a list of offsets.\n");
		eprintf(" x @@ sym.          ; run 'x' over all flags matching 'sym.'\n");
		eprintf(" x @@.file          ; \"\" over the offsets specified in the file (one offset per line)\n");
		eprintf(" x @@=off1 off2 ..  ; manual list of offsets\n");
		eprintf(" x @@=`pdf~call[0]` ; run 'x' at every call offset of the current function\n");
		break;
	case '=':
		/* foreach list of items */
		each = str+1;
		do {
			while(each[0]==' ') each=each+1;
			if (!*each) break;
			str = strchr(each, ' ');
			if (str) {
				str[0]='\0';
				addr = r_num_math(&core->num, each);
				str[0]=' ';
			} else addr = r_num_math(&core->num, each);
			eprintf("; 0x%08llx:\n", addr);
			each = str+1;
			r_core_seek(core, addr, 1);
			r_core_cmd(core, cmd, 0);
			r_cons_flush();
		} while(str != NULL);
		break;
	case '.':
		if (each[1]=='(') {
			char cmd2[1024];
			// TODO: use controlc() here
			for(core->macro.counter=0;i<999;core->macro.counter++) {
				r_macro_call(&core->macro, each+2);
				if (core->macro.brk_value == NULL) {
					//eprintf("==>breaks(%s)\n", each);
					break;
				}

				addr = core->macro._brk_value;
				sprintf(cmd2, "%s @ 0x%08llx", cmd, addr);
				eprintf("0x%08llx (%s)\n", addr, cmd2);
				r_core_seek(core, addr, 1);
				r_core_cmd(core, cmd2, 0);
				i++;
			}
		} else {
			char buf[1024];
			char cmd2[1024];
			FILE *fd = fopen(each+1, "r");
			if (fd == NULL) {
				eprintf("Cannot open file '%s' for reading one offset per line.\n", each+1);
			} else {
				core->macro.counter=0;
				while(!feof(fd)) {
					buf[0]='\0';
					fgets(buf, 1024, fd);
					addr = r_num_math(&core->num, buf);
					eprintf("0x%08llx: %s\n", addr, cmd);
					sprintf(cmd2, "%s @ 0x%08llx", cmd, addr);
					r_core_seek(core, buf, 1);
					r_core_cmd(core, cmd2, 0);
					core->macro.counter++;
				}
				fclose(fd);
			}
		}
		break;
	default:
		core->macro.counter = 0;
		//while(str[i])  && !core->interrupted) {
		while(str[i]) {
			j = i;
			for(;str[j]&&str[j]==' ';j++); // skip spaces
			for(i=j;str[i]&&str[i]!=' ';i++); // find EOS
			ch = str[i];
			str[i] = '\0';
			word = strdup(str+j);
			if (word == NULL)
				break;
			str[i] = ch;
			if (strchr(word, '*')) {
#if 0
				/* for all flags in current flagspace */
				list_for_each(pos, &flags) {
					flag_t *flag = (flag_t *)list_entry(pos, flag_t, list);
					//if (core->interrupted)
					//	break;
					/* filter per flag spaces */
	//				if ((flag_space_idx != -1) && (flag->space != flag_space_idx))
	//					continue;

					config.seek = flag->offset;
					radare_read(0);
					cons_printf("; @@ 0x%08llx (%s)\n", config.seek, flag->name);
					radare_cmd(cmd,0);
				}
#else
printf("No flags foreach implemented\n");
#endif
			} else {
				/* for all flags in current flagspace */
				list_for_each(pos, &core->flags.flags) {
					struct r_flag_item_t *flag =
						(struct r_flag_item_t *)list_entry(pos, struct r_flag_item_t, list);

					if (r_cons_breaked)
						break;
					/* filter per flag spaces */
					if ((core->flags.space_idx != -1) && (flag->space != core->flags.space_idx))
						continue;
					if (word[0]=='\0' || strstr(flag->name, word) != NULL) {
						r_core_seek(core, flag->offset, 1);
						r_cons_printf("; @@ 0x%08llx (%s)\n", core->seek, flag->name);
						r_core_cmd(core, cmd, 0);
					}
				}
	#if 0
				/* ugly copypasta from tmpseek .. */
				if (strstr(word, each)) {
					if (word[i]=='+'||word[i]=='-')
						config.seek = config.seek + get_math(word);
					else	config.seek = get_math(word);
					radare_read(0);
					cons_printf("; @@ 0x%08llx\n", config.seek);
					radare_cmd(cmd,0);
				}
	#endif
			r_cons_break(NULL, NULL);

			core->macro.counter++ ;
			free(word);
			word = NULL;
			}
		}
	}
	r_cons_break_end();
	// XXX: use r_core_seek here
	core->seek = oseek;

	free(word);
	word = NULL;
	free(ostr);
	return R_TRUE;
}

int r_core_cmd(struct r_core_t *core, const char *command, int log)
{
	int i, len;
	char *cmd , *ocmd = NULL;
	int ret = -1;
	int times = 1;
	int newfd = 1;
	int quoted = 0;
	
	u64 tmpseek = core->seek;
	int restoreseek = 0;

	if (command == NULL )
		return 0;
	while(command[0]==' ') // TODO: handle tabs to with iswhitespace()
		command = command+1;

	len = strlen(command)+1;
	ocmd = cmd = malloc(len+8192);
	memcpy(cmd, command, len);

	/* quoted / raw command */
	len = strlen(cmd);
	if (cmd[0]=='"') {
		if (cmd[len-1]!='"') {
			fprintf(stderr, "parse: Missing ending "
			"'\"': '%s' (%c) len=%d\n", cmd, cmd[2], len);
			free(cmd);
			return 0;
		}
		cmd[len-1]='\0';
		strcpy(cmd, cmd+1);
		ret = r_cmd_call(&core->cmd, cmd);
		free(ocmd);
		return ret;
	}

	ret = r_core_cmd_subst(core, cmd, &restoreseek, &newfd, &times);
	if (ret != -1) {
		for(i=0;i<times;i++) {
			if (quoted) {
				ret = r_cmd_call(&core->cmd, cmd);
				if (ret == -1) // stop on error?
					break;
			} else {
				char *ptr;
				ptr = strchr(cmd, '&');
				while (ptr&&ptr[1]=='&') {
					ptr[0]='\0';
					ret = r_cmd_call(&core->cmd, cmd);
					if (ret == -1){
						fprintf(stderr, "command error(%s)\n", cmd);
						break;
					}
					for(cmd=ptr+2;cmd&&cmd[0]==' ';cmd=cmd+1);
					ptr = strchr(cmd, '&');
				}
				r_cmd_call(&core->cmd, cmd);
			}
		}
		if (ret == -1){
			if (cmd[0])
				fprintf(stderr, "Invalid command: '%s'\n", command);
			ret = 1;
		}
	}
	if (log) r_line_hist_add(command);
	if (restoreseek)
		r_core_seek(core, tmpseek, 1);

	if (newfd != 1) {
		r_cons_flush();
		r_cons_pipe_close(newfd);
	}

	free (core->oobi);
	free (ocmd);
	core->oobi = NULL;
	core->oobi_len = 0;

	return 0;
}

int r_core_cmd_file(struct r_core_t *core, const char *file)
{
	char buf[1024];
	FILE *fd = fopen(file, "r");
	if (fd == NULL)
		return -1;
	while (!feof(fd)) {
		if (fgets(buf, 1023, fd) != NULL) {
			buf[strlen(buf)-1]='\0';
			if (r_core_cmd(core, buf, 0) == -1) {
				fprintf(stderr, "Error running command '%s'\n", buf);
				break;
			}
		}
	}
	fclose(fd);
	return 0;
}

static int cmd_debug(void *data, const char *input)
{
	struct r_core_t *core = (struct r_core_t *)data;
	char *ptr;
	switch(input[0]) {
	case 'k':
		{
		/* XXX: not for threads? signal is for a whole process!! */
		/* XXX: but we want fine-grained access to process resources */
			int pid = 0;
			int sig = 9;
			pid = atoi(input);
			ptr = strchr(input, ' ');
			if (ptr) sig = atoi(ptr+1);
			if (pid > 0) {
				fprintf(stderr, "Sending signal '%d' to pid '%d'\n", sig, pid);
				r_debug_kill(&core->dbg, pid, sig);
			} else fprintf(stderr, "Invalid arguments\n");
		}
		break;
	case 's':
		fprintf(stderr, "step\n");
		r_debug_step(&core->dbg, 1);
		break;
	case 'b':
		if (input[1]==' ') input = input+1;
		switch(input[1]) {
		case '\0':
			r_bp_list(&core->dbg.bp, input[1]=='*');
			break;
		case '-':
			r_debug_bp_del(&core->dbg, r_num_math(&core->num, input+2));
			break;
		case 'e':
			r_debug_bp_enable(&core->dbg, r_num_math(&core->num, input+2), 1);
			break;
		case 'd':
			r_debug_bp_enable(&core->dbg, r_num_math(&core->num, input+2), 0);
			break;
		case 'h':
			if (input[2]==' ') {
				if (!r_bp_handle_set(&core->dbg.bp, input+3)) {
					eprintf("Invalid name: '%s'.\n", input+3);
				}
			} else r_bp_handle_list(&core->dbg.bp);
			break;
		case '?':
			r_cons_printf(
			"Usage: db [[-]addr] [len] [rwx] [condstring]\n"
			"db              ; list breakpoints\n"
			"db 0x804800     ; add breakpoint\n"
			"db -0x804800    ; remove breakpoint\n"
			"dbe 0x8048000   ; enable breakpoint\n"
			"dbd 0x8048000   ; disable breakpoint\n"
			"dbh x86         ; set/list breakpoint plugin handlers\n");
			break;
		default:
			r_debug_bp_add(&core->dbg, r_num_math(&core->num, input+1), 1, 0, R_BP_EXEC);
			break;
		}
		break;
	case 't':
		fprintf(stderr, "TODO: list/select thread\n");
		break;
	case 'H':
		fprintf(stderr, "TODO: transplant process\n");
		break;
	case 'c':
		fprintf(stderr, "continue\n");
		r_debug_continue(&core->dbg);
		break;
	case 'm':
		{char pid[16]; sprintf(pid, "%d", core->dbg.pid);
		r_sys_setenv("PID", pid, 1);
		system("cat /proc/$PID/maps"); }
		break;
	case 'r':
#if 1
		r_debug_reg_sync(&core->dbg, 0);
		r_debug_reg_list(&core->dbg, NULL, input[1]=='*');
#else
		r_core_cmd(core, "|reg", 0);
#endif
		break;
	case 'p':
		// TODO: Support PID and Thread
		if (input[1]==' ')
			//r_debug_select(&core->dbg, core->dbg.pid, atoi(input+2));
			r_debug_select(&core->dbg, atoi(input+2), atoi(input+2));
		else fprintf(stderr, "TODO: List processes..\n");
		break;
	case 'h':
		if (input[1]==' ')
			r_debug_handle_set(&core->dbg, input+2);
		else r_debug_handle_list(&core->dbg, "");
		break;
	default:
		r_cons_printf("Usage: d[sbhcrbo] [arg]\n"
		" dh [handler] ; list or set debugger handler\n"
		" dH [handler] ; transplant process to a new handler\n"
		" ds           ; perform one step\n"
		" df           ; file descriptors\n"
		" ds 3         ; perform 3 steps\n"
		" do 3         ; perform 3 steps overs\n"
		" dp [pid]     ; list or set pid\n"
		" dt [tid]     ; select thread id\n"
		" dc           ; continue execution\n"
		" dr           ; show registers\n"
		" dr*          ; show registers in radare commands\n"
		" dr eax       ; show value of eax register\n"
		" dr eax = 33  ; set register value. eax = 33\n"
		" db           ; list breakpoints\n"
		" db sym.main  ; set breakpoint\n"
		" db -sym.main ; drop breakpoint\n"
		" dm           ; show memory maps\n"
		" dm 4096      ; allocate 4KB in child process\n"
		" dm rw- esp 9K; set 9KB of the stack as read+write (no exec)\n"
		" dk pid sig   ; send signal to a process ID\n");
		break;
	}
	return 0;
}

R_API int r_core_cmd_buffer(void *user, const char *buf)
{
	char *str = strdup(buf);
	char *ptr = strchr(str, '\n');
	char *optr = str;
	while(ptr) {
		ptr[0]='\0';
		r_core_cmd(user, optr, 0);
		optr = ptr+1;
		ptr = strchr(str,'\n');
	}
	r_core_cmd(user, optr, 0);
	free(str);
	return R_TRUE;
}

R_API int r_core_cmdf(void *user, const char *fmt, ...)
{
	char string[1024];
	int ret;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(string, 1023, fmt, ap);
	ret = r_core_cmd((struct r_core_t *)user, string, 0);
	va_end(ap);
	return ret;
}

R_API int r_core_cmd0(void *user, const char *cmd)
{
	return r_core_cmd((struct r_core_t *)user, cmd, 0);
}

R_API char *r_core_cmd_str(struct r_core_t *core, const char *cmd)
{
	char *retstr;
	r_cons_reset();
	if (r_core_cmd(core, cmd, 0) == -1) {
		fprintf(stderr, "Invalid command: %s\n", cmd);
		retstr = strdup("");
	} else {
		const char *static_str = r_cons_get_buffer();
		if (retstr==NULL)
			retstr = strdup("");
		else retstr = strdup(static_str);
		r_cons_reset();
	}
	return retstr;
}

int r_core_cmd_init(struct r_core_t *core)
{
	r_cmd_init(&core->cmd);
	r_cmd_set_data(&core->cmd, core);
	r_cmd_add(&core->cmd, "x",        "alias for px", &cmd_hexdump);
	r_cmd_add(&core->cmd, "analysis", "analysis", &cmd_anal);
	r_cmd_add(&core->cmd, "flag",     "get/set flags", &cmd_flag);
	r_cmd_add(&core->cmd, "debug",    "debugger operations", &cmd_debug);
	r_cmd_add(&core->cmd, "info",     "get file info", &cmd_info);
	r_cmd_add(&core->cmd, "seek",     "seek to an offset", &cmd_seek);
	r_cmd_add(&core->cmd, "bsize",    "change block size", &cmd_bsize);
	r_cmd_add(&core->cmd, "eval",     "evaluate configuration variable", &cmd_eval);
	r_cmd_add(&core->cmd, "print",    "print current block", &cmd_print);
	r_cmd_add(&core->cmd, "write",    "write bytes", &cmd_write);
	r_cmd_add(&core->cmd, "Code",     "code metadata", &cmd_meta);
	r_cmd_add(&core->cmd, "yank",     "yank bytes", &cmd_yank);
	r_cmd_add(&core->cmd, "Visual",   "enter visual mode", &cmd_visual);
	r_cmd_add(&core->cmd, "undo",     "undo writes", &cmd_undowrite);
	r_cmd_add(&core->cmd, "!",        "run system command", &cmd_system);
	r_cmd_add(&core->cmd, "|",        "run io system command", &cmd_io_system);
	r_cmd_add(&core->cmd, "#",        "calculate hash", &cmd_hash);
	r_cmd_add(&core->cmd, "?",        "help message", &cmd_help);
	r_cmd_add(&core->cmd, ".",        "interpret", &cmd_interpret);
	r_cmd_add(&core->cmd, "/",        "search kw, pattern aes", &cmd_search);
	r_cmd_add(&core->cmd, "(",        "macro", &cmd_macro);
	r_cmd_add(&core->cmd, "|",        "io pipe", &cmd_iopipe);
	r_cmd_add(&core->cmd, "quit",     "exit program session", &cmd_quit);

	return 0;
}
