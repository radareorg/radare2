/* radare - LGPL - Copyright 2009-2013 - pancake */

/* TODO: simplify using r_write */
static int cmd_write(void *data, const char *input) {
	ut64 off;
	ut8 *buf;
	const char *arg;
	int wseek, i, size, len = strlen (input);
	char *tmp, *str, *ostr;
	RCore *core = (RCore *)data;
	#define WSEEK(x,y) if (wseek)r_core_seek_delta (x,y)
	wseek = r_config_get_i (core->config, "cfg.wseek");
	str = ostr = strdup (input+1);

	switch (*input) {
	case 'p':
		if (input[1]=='-' || (input[1]==' '&&input[2]=='-')) {
			const char *tmpfile = ".tmp";
			char *out = r_core_editor (core, NULL);
			if (out) {
				// XXX hacky .. patch should support str, not only file
				r_file_dump (tmpfile, (ut8*)out, strlen (out));
				r_core_patch (core, tmpfile);
				r_file_rm (tmpfile);
			}
		} else
		if (input[1]==' ' && input[2]) {
			r_core_patch (core, input+2);
		} else {
			eprintf ("Usage: wp [-|r2patch-file]\n"
			         "TODO: rapatch format documentation here\n");
		}
		break;
	case 'r':
		off = r_num_math (core->num, input+1);
		len = (int)off;
		if (len>0) {
			buf = malloc (len);
			if (buf != NULL) {
				r_num_irand ();
				for (i=0; i<len; i++)
					buf[i] = r_num_rand (256);
				r_core_write_at (core, core->offset, buf, len);
				WSEEK (core, len);
				free (buf);
			} else eprintf ("Cannot allocate %d bytes\n", len);
		}
		break;
	case 'A':
		switch (input[1]) {
		case ' ':
			if (input[2] && input[3]==' ') {
				r_asm_set_pc (core->assembler, core->offset);
				eprintf ("modify (%c)=%s\n", input[2], input+4);
				len = r_asm_modify (core->assembler, core->block, input[2],
					r_num_math (core->num, input+4));
				eprintf ("len=%d\n", len);
				if (len>0) {
					r_core_write_at (core, core->offset, core->block, len);
					WSEEK (core, len);
				} else eprintf ("r_asm_modify = %d\n", len);
			} else eprintf ("Usage: wA [type] [value]\n");
			break;
		case '?':
		default:
			r_cons_printf ("Usage: wA [type] [value]\n"
			"Types:\n"
			" r   raw write value\n"
			" v   set value (taking care of current address)\n"
			" d   destination register\n"
			" 0   1st src register\n"
			" 1   2nd src register\n"
			"Example: wA r 0 # e800000000\n");
			break;
		}
		break;
	case 'c':
		switch (input[1]) {
		case 'i':
			r_io_cache_commit (core->io);
			r_core_block_read (core, 0);
			break;
		case 'r':
			r_io_cache_reset (core->io, R_TRUE);
			/* Before loading the core block we have to make sure that if
			 * the cache wrote past the original EOF these changes are no
			 * longer displayed. */
			memset (core->block, 0xff, core->blocksize);
			r_core_block_read (core, 0);
			break;
		case '-':
			if (input[2]=='*') {
				r_io_cache_reset (core->io, R_TRUE);
			} else if (input[2]==' ') {
				char *p = strchr (input+3, ' ');
				ut64 to, from = core->offset;
				if (p) {
					*p = 0;
					from = r_num_math (core->num, input+3);
					to = r_num_math (core->num, input+3);
					if (to<from) {
						eprintf ("Invalid range (from>to)\n");
						return 0;
					}
				} else {
					from = r_num_math (core->num, input+3);
					to = from + core->blocksize;
				}
				r_io_cache_invalidate (core->io, from, to);
			} else {
				eprintf ("Invalidate write cache at 0x%08"PFMT64x"\n", core->offset);
				r_io_cache_invalidate (core->io, core->offset, core->offset+core->blocksize);
			}
			/* See 'r' above. */
			memset (core->block, 0xff, core->blocksize);
			r_core_block_read (core, 0);
			break;
		case '?':
			r_cons_printf (
			"Usage: wc[ir*?]\n"
			" wc           list all write changes\n"
			" wc- [a] [b]  remove write op at curseek or given addr\n"
			" wc*          \"\" in radare commands\n"
			" wcr          reset all write changes in cache\n"
			" wci          commit write cache\n"
			"NOTE: Requires 'e io.cache=true'\n");
			break;
		case '*':
			r_io_cache_list (core->io, R_TRUE);
			break;
		case '\0':
			if (!r_config_get_i (core->config, "io.cache"))
				eprintf ("[warning] e io.cache must be true\n");
			r_io_cache_list (core->io, R_FALSE);
			break;
		}
		break;
	case ' ':
		/* write string */
		len = r_str_escape (str);
		r_core_write_at (core, core->offset, (const ut8*)str, len);
#if 0
		r_io_set_fd (core->io, core->file->fd);
		r_io_write_at (core->io, core->offset, (const ut8*)str, len);
#endif
		WSEEK (core, len);
		r_core_block_read (core, 0);
		break;
	case 't':
		if (*str != ' ') {
			eprintf ("Usage: wt file [size]\n");
		} else {
			tmp = strchr (str+1, ' ');
			if (tmp) {
				st64 sz = (st64) r_num_math (core->num, tmp+1);
				*tmp = 0;
				if (sz<1) eprintf ("Invalid length\n");
				else r_core_dump (core, str+1, core->offset, (ut64)sz);
			} else r_file_dump (str+1, core->block, core->blocksize);
		}
		break;
	case 'T':
		eprintf ("TODO: wT // why?\n");
		break;
	case 'f':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if (!strcmp (arg, "-")) {
			char *out = r_core_editor (core, NULL);
			if (out) {
				r_io_write_at (core->io, core->offset,
					(ut8*)out, strlen (out));
				free (out);
			}
		} else
		if ((buf = (ut8*) r_file_slurp (arg, &size))) {
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, buf, size);
			WSEEK (core, size);
			free (buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'F':
		arg = (const char *)(input+((input[1]==' ')?2:1));
		if (!strcmp (arg, "-")) {
			int len;
			ut8 *out;
			char *in = r_core_editor (core, NULL);
			if (in) {
				out = (ut8 *)strdup (in);
				if (out) {
					len = r_hex_str2bin (in, out);
					if (len>0)
						r_io_write_at (core->io, core->offset, out, len);
					free (out);
				}
				free (in);
			}
		} else
		if ((buf = r_file_slurp_hexpairs (arg, &size))) {
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, buf, size);
			WSEEK (core, size);
			free (buf);
			r_core_block_read (core, 0);
		} else eprintf ("Cannot open file '%s'\n", arg);
		break;
	case 'w':
		str++;
		len = (len-1)<<1;
		if (len>0) tmp = malloc (len+1);
		else tmp = NULL;
		if (tmp) {
			for (i=0; i<len; i++) {
				if (i%2) tmp[i] = 0;
				else tmp[i] = str[i>>1];
			}
			str = tmp;
			r_io_set_fd (core->io, core->file->fd);
			r_io_write_at (core->io, core->offset, (const ut8*)str, len);
			WSEEK (core, len);
			r_core_block_read (core, 0);
			free (tmp);
		} else eprintf ("Cannot malloc %d\n", len);
		break;
	case 'x':
		{
		int b, len = strlen (input);
		ut8 *buf = malloc (len+1);
		len = r_hex_str2bin (input+1, buf);
		if (len != 0) {
			if (len<0) len = -len+1;
			b = core->block[len]&0xf;
			b |= (buf[len]&0xf0);
			buf[len] = b;
			r_core_write_at (core, core->offset, buf, len);
			WSEEK (core, len);
			r_core_block_read (core, 0);
		} else eprintf ("Error: invalid hexpair string\n");
		free (buf);
		}
		break;
	case 'a':
		switch (input[1]) {
		case 'o':
			if (input[2] == ' ')
				r_core_hack (core, input+3);
			else r_core_hack_help (core);
			break;
		case ' ':
		case '*':
			{ const char *file = input[1]=='*'? input+2: input+1;
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, file);
			if (acode) {
				if (input[1]=='*') {
					r_cons_printf ("wx %s\n", acode->buf_hex);
				} else {
					if (r_config_get_i (core->config, "scr.prompt"))
					eprintf ("Written %d bytes (%s)=wx %s\n", acode->len, input+1, acode->buf_hex);
					r_core_write_at (core, core->offset, acode->buf, acode->len);
					WSEEK (core, acode->len);
					r_core_block_read (core, 0);
				}
				r_asm_code_free (acode);
			}
			} break;
		case 'f':
			if ((input[2]==' '||input[2]=='*')) {
				const char *file = input[2]=='*'? input+4: input+3;
				RAsmCode *acode;
				r_asm_set_pc (core->assembler, core->offset);
				acode = r_asm_assemble_file (core->assembler, file);
				if (acode) {
					if (input[2]=='*') {
						r_cons_printf ("wx %s\n", acode->buf_hex);
					} else {
						if (r_config_get_i (core->config, "scr.prompt"))
						eprintf ("Written %d bytes (%s)=wx %s\n", acode->len, input+1, acode->buf_hex);
						r_core_write_at (core, core->offset, acode->buf, acode->len);
						WSEEK (core, acode->len);
						r_core_block_read (core, 0);
					}
					r_asm_code_free (acode);
				} else eprintf ("Cannot assemble file\n");
			} else eprintf ("Wrong argument\n");
			break;
		default:
			eprintf ("Usage: wa[of*] [arg]\n"
				" wa nop           : write nopcode using asm.arch and asm.bits\n"
				" wa* mov eax, 33  : show 'wx' op with hexpair bytes of sassembled opcode\n"
				" \"wa nop;nop\"     : assemble more than one instruction (note the quotes)\n"
				" waf foo.asm      : assemble file and write bytes\n"
				" wao nop          : convert current opcode into nops\n"
				" wao?             : show help for assembler operation on current opcode (hack)\n");
			break;
		}
		break;
	case 'b':
		{
		int len = strlen (input);
		ut8 *buf = malloc (len+1);
		if (buf) {
			len = r_hex_str2bin (input+1, buf);
			if (len > 0) {
				r_mem_copyloop (core->block, buf, core->blocksize, len);
				r_core_write_at (core, core->offset, core->block, core->blocksize);
				WSEEK (core, core->blocksize);
				r_core_block_read (core, 0);
			} else eprintf ("Wrong argument\n");
		} else eprintf ("Cannot malloc %d\n", len+1);
		}
		break;
	case 'm':
		size = r_hex_str2bin (input+1, (ut8*)str);
		switch (input[1]) {
		case '\0':
			eprintf ("Current write mask: TODO\n");
			// TODO
			break;
		case '?':
			break;
		case '-':
			r_io_set_write_mask (core->io, 0, 0);
			eprintf ("Write mask disabled\n");
			break;
		case ' ':
			if (size>0) {
				r_io_set_fd (core->io, core->file->fd);
				r_io_set_write_mask (core->io, (const ut8*)str, size);
				WSEEK (core, size);
				eprintf ("Write mask set to '");
				for (i=0; i<size; i++)
					eprintf ("%02x", str[i]);
				eprintf ("'\n");
			} else eprintf ("Invalid string\n");
			break;
		}
		break;
	case 'v':
		{
			int type = 0;
			ut8 addr1;
			ut16 addr2;
			ut32 addr4, addr4_;
			ut64 addr8;

			switch (input[1]) {
			case '?':
				r_cons_printf ("Usage: wv[size] [value]    # write value of given size\n"
					"  wv1 234      # write one byte with this value\n"
					"  wv 0x834002  # write dword with this value\n"
					"Supported sizes are: 1, 2, 4, 8\n");
				return 0;
			case '1': type = 1; break;
			case '2': type = 2; break;
			case '4': type = 4; break;
			case '8': type = 8; break;
			}
			off = r_num_math (core->num, input+2);
			r_io_set_fd (core->io, core->file->fd);
			r_io_seek (core->io, core->offset, R_IO_SEEK_SET);
			if (type == 0)
				type = (off&UT64_32U)? 8: 4;
			switch (type) {
			case 1:
				addr1 = (ut8)off;
				r_io_write (core->io, (const ut8 *)&addr1, 1);
				WSEEK (core, 1);
				break;
			case 2:
				addr2 = (ut16)off;
				r_io_write (core->io, (const ut8 *)&addr2, 2);
				WSEEK (core, 2);
				break;
			case 4:
				addr4_ = (ut32)off;
				//drop_endian((ut8*)&addr4_, (ut8*)&addr4, 4); /* addr4_ = addr4 */
				//endian_memcpy((ut8*)&addr4, (ut8*)&addr4_, 4); /* addr4 = addr4_ */
				memcpy ((ut8*)&addr4, (ut8*)&addr4_, 4); // XXX needs endian here too
				r_io_write (core->io, (const ut8 *)&addr4, 4);
				WSEEK (core, 4);
				break;
			case 8:
				/* 8 byte addr */
				memcpy ((ut8*)&addr8, (ut8*)&off, 8); // XXX needs endian here
			//	endian_memcpy((ut8*)&addr8, (ut8*)&off, 8);
				r_io_write (core->io, (const ut8 *)&addr8, 8);
				WSEEK (core, 8);
				break;
			}
			r_core_block_read (core, 0);
		}
		break;
	case 'o':
		switch (input[1]) {
			case 'a':
			case 's':
			case 'e':
			case 'A':
			case 'x':
			case 'r':
			case 'l':
			case 'm':
			case 'd':
			case 'o':
			case 'w':
				if (input[2]!=' ') {
					if (input[1]=='e') r_cons_printf (
						"Usage: 'woe from-to step'\n");
					else r_cons_printf (
						"Usage: 'wo%c 00 11 22'\n", input[1]);
					return 0;
				}
			case '2':
			case '4':
				r_core_write_op (core, input+3, input[1]);
				r_core_block_read (core, 0);
				break;
			case 'R':
				r_core_cmd0 (core, "wr $b");
				break;
			case 'n':
				r_core_write_op (core, "ff", 'x');
				r_core_block_read (core, 0);
				break;
			case '\0':
			case '?':
			default:
				r_cons_printf (
						"Usage: wo[asmdxoArl24] [hexpairs] @ addr[:bsize]\n"
						"Example:\n"
						"  wox 0x90   ; xor cur block with 0x90\n"
						"  wox 90     ; xor cur block with 0x90\n"
						"  wox 0x0203 ; xor cur block with 0203\n"
						"  woa 02 03  ; add [0203][0203][...] to curblk\n"
						"  woe 02 03  \n"
						"Supported operations:\n"
						"  wow  ==  write looped value (alias for 'wb')\n"
						"  woa  +=  addition\n"
						"  wos  -=  substraction\n"
						"  wom  *=  multiply\n"
						"  wod  /=  divide\n"
						"  wox  ^=  xor\n"
						"  woo  |=  or\n"
						"  woA  &=  and\n"
						"  woR  random bytes (alias for 'wr $b'\n"
						"  wor  >>= shift right\n"
						"  wol  <<= shift left\n"
						"  wo2  2=  2 byte endian swap\n"
						"  wo4  4=  4 byte endian swap\n"
						);
				break;
		}
		break;
	case 's':
		{
			ut8 ulen;
			len = r_str_escape (str+1);
			if (len>255) {
				eprintf ("Too large\n");
			} else {
				ulen = (ut8)len;
				r_core_write_at (core, core->offset, &ulen, 1);
				r_core_write_at (core, core->offset+1, (const ut8*)str+1, len);
				WSEEK (core, len);
				r_core_block_read (core, 0);
			}
		}
		break;
	default:
	case '?':
		if (core->oobi) {
			eprintf ("Writing oobi buffer!\n");
			r_io_set_fd (core->io, core->file->fd);
			r_io_write (core->io, core->oobi, core->oobi_len);
			WSEEK (core, core->oobi_len);
			r_core_block_read (core, 0);
		} else r_cons_printf (
			"Usage: w[x] [str] [<file] [<<EOF] [@addr]\n"
			" w foobar     write string 'foobar'\n"
			" wr 10        write 10 random bytes\n"
			" ww foobar    write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'\n"
			" wa push ebp  write opcode, separated by ';' (use '\"' around the command)\n"
			" waf file     assemble file and write bytes\n"
			" wA r 0       alter/modify opcode at current seek (see wA?)\n"
			" wb 010203    fill current block with cyclic hexpairs\n"
			" wc[ir*?]     write cache undo/commit/reset/list (io.cache)\n"
			" wx 9090      write two intel nops\n"
			" wv eip+34    write 32-64 bit value\n"
			" wo? hex      write in block with operation. 'wo?' fmi\n"
			" wm f0ff      set binary mask hexpair to be used as cyclic write mask\n"
			" ws pstring   write 1 byte for length and then the string\n"
			" wf -|file    write contents of file at current offset\n"
			" wF -|file    write contents of hexpairs file here\n"
			" wp -|file    apply radare patch file. See wp? fmi\n"
			" wt file [sz] write to file (from current seek, blocksize or sz bytes)\n"
			);
			//TODO: add support for offset+seek
			// " wf file o s ; write contents of file from optional offset 'o' and size 's'.\n"
		break;
	}
	free (ostr);
	return 0;
}

