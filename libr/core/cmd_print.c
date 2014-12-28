/* radare - LGPL - Copyright 2009-2014 - pancake */
/*#include <r_anal_ex.h>*/

static void set_asm_configs(RCore *core, char *arch, ut32 bits, int segoff){
	r_config_set (core->config, "asm.arch", arch);
	r_config_set_i (core->config, "asm.bits", bits);
	// XXX - this needs to be done here, because
	// if arch == x86 and bits == 16, segoff automatically changes
	r_config_set_i (core->config, "asm.segoff", segoff);
}

static void cmd_pDj (RCore *core, const char *arg) {
	int bsize = r_num_math (core->num, arg);
	if (bsize < 0) bsize = -bsize;
	if (bsize <= core->blocksize) {
		r_core_print_disasm_json (core, core->offset, core->block,
			bsize, 0);
	} else {
		ut8 *buf = malloc (bsize);
		if (buf) {
			r_io_read_at (core->io, core->offset, buf, bsize);
			r_core_print_disasm_json (core, core->offset, buf,
				bsize, 0);
			free (buf);
		} else eprintf ("cannot allocate %d bytes\n", bsize);
	}
	r_cons_newline ();
}

static void cmd_pdj (RCore *core, const char *arg) {
	int nblines = r_num_math(core->num, arg);
	ut8 buf[256];
	r_core_print_disasm_json (core, core->offset, buf, sizeof(buf), nblines);
	r_cons_newline ();
}

static int process_input(RCore *core, const char *input, ut64* blocksize, char **asm_arch, ut32 *bits) {
	// input: start of the input string e.g. after the command symbols have been consumed
	// size: blocksize if present, otherwise -1
	// asm_arch: asm_arch to interpret as if present and valid, otherwise NULL;
	// bits: bits to use if present, otherwise -1

	int result = R_FALSE;
	char *input_one = NULL, *input_two = NULL, *input_three = NULL;
	char *str_clone = NULL,
		 *ptr_str_clone = NULL,
		 *trimmed_clone = NULL;

	if (input == NULL || blocksize == NULL || asm_arch == NULL || bits == NULL) {
		return R_FALSE;
	}

	str_clone = strdup (input);
	trimmed_clone = r_str_trim_head_tail (str_clone);

	input_one = trimmed_clone;

	ptr_str_clone = strchr (trimmed_clone, ' ');
	// terminate input_one
	if (ptr_str_clone) {
		*ptr_str_clone = '\0';
		input_two = (++ptr_str_clone);
		ptr_str_clone = strchr (input_two, ' ');
	}

	// terminate input_two
	if (ptr_str_clone && input_two) {
		*ptr_str_clone = '\0';
		input_three = (++ptr_str_clone);
		ptr_str_clone = strchr (input_three, ' ');
	}

	// terminate input_three
	if (ptr_str_clone && input_three) {
		*ptr_str_clone = '\0';
		ptr_str_clone = strchr (input_three, ' ');
	}

	// command formats
	// <size> <arch> <bits>
	// <size> <arch>
	// <size> <bits>
	// <arch> <bits>
	// <arch>

	// initialize
	*asm_arch = NULL;
	*blocksize = *bits = -1;

	if (input_one && input_two && input_three) {
		// <size> <arch> <bits>
		*blocksize = r_num_is_valid_input (core->num, input_one) ? r_num_get_input_value (core->num, input_one): 0;
		*asm_arch = r_asm_is_valid (core->assembler, input_two) ? strdup (input_two) : NULL;
		*bits = r_num_get_input_value (core->num, input_three);
		result = R_TRUE;

	} else if (input_one && input_two) {

		*blocksize = r_num_is_valid_input (core->num, input_one) ? r_num_get_input_value (core->num, input_one): 0;

		if (!r_num_is_valid_input (core->num, input_one) ) {
			// input_one can only be one other thing
			*asm_arch = r_asm_is_valid (core->assembler, input_one) ? strdup (input_one) : NULL;
			*bits = r_num_is_valid_input (core->num, input_two) ? r_num_get_input_value (core->num, input_two): -1;
		} else {
			if (r_str_contains_macro (input_two) ){
				r_str_truncate_cmd (input_two);
			}
			*asm_arch = r_asm_is_valid (core->assembler, input_two) ? strdup (input_two) : NULL;
		}

		result = R_TRUE;
	} else if (input_one) {
		*blocksize = r_num_is_valid_input (core->num, input_one) ? r_num_get_input_value (core->num, input_one): 0;
		if (!r_num_is_valid_input (core->num, input_one) ) {
			// input_one can only be one other thing
			if (r_str_contains_macro (input_one))
				r_str_truncate_cmd (input_one);
			*asm_arch = r_asm_is_valid (core->assembler, input_one) ? strdup (input_one) : NULL;
		}
		result = R_TRUE;
	}
	return result;
}

static void print_format_help(RCore *core) {
	const char* help_msg[] = {
	"Usage:", " pf[.key[.field[=value]]|[ val]]|[times][ [size] format] [arg0 arg1 ...]", " # Define and print format strings",
	"Examples:","","",
	"pf", "?", "Show this help",
	"pf?", "fmt", "Show format of that stored one",
	"pf", " iwq foo bar troll", "Print the iwq format with foo, bar, troll as the respective names for the fields",
	"pf", " 10xiz pointer length string", "Print a size 10 array of the xiz struct with its field names",
	"pf", " {integer}bifc", "Print integer times the following format (bifc)",
	"pf", " [4]w[7]i", "Print an array of 4 words and then an array of 7 integers",
	"pfo", "", "List all format files",
	"pfo", " elf32", "Load the elf32 format definition file",
	"pfs", " format_name", "Print the size of the format in bytes",
	"pf.", "", "List all formats",
	"pf.", "obj xxdz prev next size name", "Define the obj format as xxdz",
	"pf",  " obj=xxdz prev next size name", "Same as above",
	"pf.", "obj", "Run stored format",
	"pf.", "obj.name", "Show string inside object",
	"pf.", "obj.size=33", "Set new value for the size field in obj",
	"Format chars:", "", "",
	"        ", "e", "temporally swap endian",
	//" D - double (8 bytes)\n",
	"        ", "f", "float value (4 bytes)",
	"        ", "b", "byte (unsigned)",
	"        ", "B", "resolve enum bitfield (see t?) `pf B (Bitfield_type)arg_name`",
	"        ", "c", "char (signed byte)",
	"        ", "E", "resolve enum name  (see t?) `pf E (Enum_type)arg_name`",
	"        ", "X", "show n hexpairs (default n=1)",
	"        ", "i", "%%i integer value (4 bytes)",
	"        ", "w", "word (2 bytes unsigned short in hex)",
	"        ", "q", "quadword (8 bytes)",
	"        ", "t", "UNIX timestamp (4 bytes)",
	"        ", "p", "pointer reference (2, 4 or 8 bytes)",
	"        ", "T", "show Ten first bytes of buffer",
	"        ", "d", "0x%%08x hexadecimal value (4 bytes)",
	"        ", "D", "disassemble one opcode",
	"        ", "o", "0x%%08o octal value (4 byte)",
	"        ", "x", "0x%%08x hexadecimal value and flag (fd @ addr)",
	"        ", "X", "show formatted hexpairs",
	"        ", "z", "\\0 terminated string",
	"        ", "Z", "\\0 terminated wide string",
	"        ", "s", "32bit pointer to string (4 bytes)",
	"        ", "S", "64bit pointer to string (8 bytes)",
	//" t - unix timestamp string\n",
	"        ", "?", "data structure `pf ? (struct_type)struct_name`",
	"        ", "*", "next char is pointer (honors asm.bits)",
	"        ", "+", "toggle show flags for each offset",
	"        ", ":", "skip 4 bytes",
	"        ", ".", "skip 1 byte",
	NULL};
	r_core_cmd_help (core, help_msg);
}

static void cmd_print_format (RCore *core, const char *_input, int len) {
	char *input;
	int flag = -1;
	switch (_input[1]) {
	case '*':
		_input++;
		flag = SEEFLAG;
		break;
	case 'j':
		_input++;
		flag = JSONOUTPUT;
		break;
	case 's':
		{
		const char *val = NULL;
		_input+=2;
		if (*_input == '.') {
			_input++;
			val = r_strht_get (core->print->formats, _input);
			if (val != NULL)
				r_cons_printf ("%d bytes\n", r_print_format_struct_size (val, core->print));
			else {
				eprintf ("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') _input++;
			if (_input != '\0')
				r_cons_printf ("%d bytes\n", r_print_format_struct_size (_input, core->print));
			else {
				eprintf ("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else {
			eprintf ("Usage: pfs.struct_name | pfs format\n");
		}

		}
		return;
	case '?':
		_input+=2;
		if (*_input) {
			RListIter *iter;
			RStrHT *sht = core->print->formats;
			int *i;
			r_list_foreach (sht->ls, iter, i) {
				int idx = ((int)(size_t)i)-1;
				const char *key = r_strpool_get (sht->sp, idx);
				if (!strcmp (_input, key)) {
					const char *val = r_strht_get (core->print->formats, key);
					r_cons_printf ("%s\n", val);
				}
			}
		} else {
			print_format_help (core);
		}
		return;
	}

	input = strdup (_input);
	// "pfo" // open formatted thing
	if (input[1]=='o') { // "pfo"
		if (input[2] == '?') {
			eprintf ("|Usage: pfo [format-file]\n"
			" ~/.config/radare2/format\n"
			" "R2_DATDIR"/radare2/"R2_VERSION"/format/\n");
		} else if (input[2] == ' ') {
			char *home, path[512];
			snprintf (path, sizeof (path), ".config/radare2/format/%s", input+3);
			home = r_str_home (path);
			snprintf (path, sizeof (path), R2_DATDIR"/radare2/"
					R2_VERSION"/format/%s", input+3);
			if (!r_core_cmd_file (core, home))
				if (!r_core_cmd_file (core, path))
					if (!r_core_cmd_file (core, input+3))
						eprintf ("ecf: cannot open colorscheme profile (%s)\n", path);
			free (home);
		} else {
			RList *files;
			RListIter *iter;
			const char *fn;
			char *home = r_str_home (".config/radare2/format/");
			if (home) {
				files = r_sys_dir (home);
				r_list_foreach (files, iter, fn) {
					if (*fn && *fn != '.')
						r_cons_printf ("%s\n", fn);
				}
				r_list_free (files);
				free (home);
			}
			files = r_sys_dir (R2_DATDIR"/radare2/"R2_VERSION"/format/");
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.')
					r_cons_printf ("%s\n", fn);
			}
			r_list_free (files);
		}
		return;
	}
	/* syntax aliasing bridge for 'pf foo=xxd' -> 'pf.foo xxd' */
	if (input[1]==' ') {
		char *eq = strchr (input+2, '=');
		if (eq) {
			input[1] = '.';
			*eq = ' ';
		}
	}
	if (input[1]=='.') {
		if (input[2]=='\0') {
			RListIter *iter;
			RStrHT *sht = core->print->formats;
			int *i;
			r_list_foreach (sht->ls, iter, i) {
				int idx = ((int)(size_t)i)-1;
				const char *key = r_strpool_get (sht->sp, idx);
				const char *val = r_strht_get (core->print->formats, key);
				r_cons_printf ("pf.%s %s\n", key, val);
			}
		} else if (input[2]=='-') {
			if (input[3]) r_strht_del (core->print->formats, input+3);
			else r_strht_clear (core->print->formats);
		} else {
			const char *fmt;
			char *name = strdup (input+2);
			char *space = strchr (name, ' ');
			char *eq, *dot = strchr (name, '.');
			if (space) {
				*space++ = 0;
				//printf ("SET (%s)(%s)\n", name, space);
				r_strht_set (core->print->formats, name, space);
				free (input);
				return;
			}
			if (dot) {
				*dot++ = 0;
				fmt = r_strht_get (core->print->formats, name);
				eq = strchr (dot, '=');
				if (eq) {
					*eq++ = 0;
					r_print_format (core->print, core->offset,
							core->block, core->blocksize, fmt, 0, eq, dot);
				} else {
					r_print_format (core->print, core->offset,
							core->block, core->blocksize, fmt, 0, NULL, dot);
				}
			} else {
				const char *fmt = r_strht_get (core->print->formats, name);
				if (fmt) {
					r_print_format (core->print, core->offset,
							core->block, len, fmt, flag, NULL, NULL);
				} else eprintf ("Unknown format (%s)\n", name);
			}
			free (name);
		}
	} else r_print_format (core->print, core->offset,
			core->block, len, input+1, flag, NULL, NULL);
	free (input);
}

// > pxa
/* In this function, most of the buffers have 4 times
 * the required length. This is because we supports colours,
 * that are 4 chars long. */
#define append(x,y) { strcat (x,y);x += strlen (y); }
static void annotated_hexdump(RCore *core, const char *str, int len) {
	const int usecolor = r_config_get_i (core->config, "scr.color");
	int nb_cols = r_config_get_i (core->config, "hex.cols");
	int flagsz = r_config_get_i (core->config, "hex.flagsz");
	const ut8 *buf = core->block;
	ut64 addr = core->offset;
	int color_idx = 0;
	char *bytes, *chars;
	char *ebytes, *echars; //They'll walk over the vars above
	ut64 fend = UT64_MAX;
	char *comment;
	int i, j, low, max, here, rows;
	boolt marks = R_FALSE, setcolor = R_TRUE, hascolor = R_FALSE;
	ut8 ch;
	const char **colors = (const char **)&core->cons->pal.list;
#if 0
	const char *colors[] = {
		Color_WHITE, /*Color_GREEN,*/ Color_YELLOW, Color_RED,
		Color_CYAN, Color_MAGENTA, Color_GRAY, Color_BLUE
	};
#endif
//	const char* colors[] = Colors_PLAIN;
	const int col = core->print->col;
	RFlagItem *flag, *current_flag = NULL;
	char** note;
	int nb_cons_cols;

	// Adjust the number of columns
	if (nb_cols < 1)
		nb_cols = 16;
	nb_cols -= (nb_cols % 2); //nb_cols should be even

	nb_cons_cols = 12 + nb_cols * 2 + (nb_cols/2);
	nb_cons_cols += 17;
	rows = len/nb_cols;

	chars = calloc (nb_cols * 20, sizeof(char));
	if (!chars)
		return;
	note = calloc (nb_cols, sizeof(char*));
	if (!note) {
		free (chars);
		return;
	}
	bytes = calloc (nb_cons_cols*20, sizeof(char));
	if (!bytes) {
		free (chars);
		free (note);
		return;
	}
#if 1
	int addrpadlen = strlen (sdb_fmt (0, "%08"PFMT64x, addr))-8;
	char addrpad[32];
	if (addrpadlen>0) {
		memset (addrpad, ' ', addrpadlen);
		addrpad[addrpadlen] = 0;

		//Compute, then show the legend
		strcpy (bytes, addrpad);
	} else {
		*addrpad = 0;
		addrpadlen = 0;
	}
	strcpy (bytes+addrpadlen, "- offset -  ");
#endif
	j = strlen (bytes);
	for (i=0; i<nb_cols; i+=2) {
		sprintf (bytes+j, " %X %X  ", (i&0xf), (i+1)&0xf);
		j += 5;
	}
	sprintf (bytes+j+i, " ");
	j++;
	for (i=0; i<nb_cols; i++)
		sprintf (bytes+j+i, "%0X", i%17);
	if (usecolor) r_cons_strcat (Color_GREEN);
	r_cons_strcat (bytes);
	if (usecolor) r_cons_strcat (Color_RESET);
	r_cons_newline ();

	//hexdump
	for (i=0; i<rows; i++) {
		bytes[0] = '\0';
		chars[0] = '\0';
		ebytes = bytes;
		echars = chars;
		hascolor = R_FALSE;

		if (usecolor) append (ebytes, core->cons->pal.offset);
		ebytes += sprintf (ebytes, "0x%08"PFMT64x, addr);
		if (usecolor) append (ebytes, Color_RESET);
		append (ebytes, (col==1)?" |":"  ");

		for (j=0; j<nb_cols; j++) {
			setcolor = R_TRUE;
			free (note[j]);
			note[j] = NULL;

			// collect comments
			comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr+j);
			if (comment) {
				comment = r_str_prefix (comment, ";");
				note[j] = comment;
				marks = R_TRUE;
			}

			// collect flags
			flag = r_flag_get_i (core->flags, addr+j);
			if (flag) { // Beginning of a flag
				if (flagsz) {
					fend = addr + flagsz; //core->blocksize;
				} else {
					fend = addr + j + flag->size;
				}
				note[j] = r_str_prefix (strdup (flag->name), "/");
				marks = R_TRUE;
				color_idx++;
				color_idx %= R_CONS_PALETTE_LIST_SIZE;
				current_flag = flag;
			} else {
				// Are we past the current flag?
				if (current_flag && addr+j > (current_flag->offset + current_flag->size)){
					setcolor = R_FALSE;
					current_flag = NULL;
				}
				// Turn colour off if we're at the end of the current flag
				if (fend == UT64_MAX || fend <= addr + j)
					setcolor = R_FALSE;
			}
			if (setcolor && !hascolor) {
				hascolor = R_TRUE;
				if (usecolor) {
					if (current_flag && current_flag->color) {
						char *ansicolor = r_cons_pal_parse (current_flag->color);
						append (ebytes, ansicolor);
						append (echars, ansicolor);
						free (ansicolor);
					} else { // Use "random" colours
						append (ebytes, colors[color_idx]);
						append (echars, colors[color_idx]);
					}
				} else {
					append (ebytes, Color_INVERT);
				}
			}
			here = R_MIN ((i * nb_cols) + j, core->blocksize);
			ch = buf[here];
			if (core->print->ocur!=-1) {
				low = R_MIN (core->print->cur, core->print->ocur);
				max = R_MAX (core->print->cur, core->print->ocur);
			} else {
				low = max = core->print->cur;
			}
			if (core->print->cur_enabled) {
				if (low==max) {
					if (low == here) {
						append (echars, Color_INVERT);
						append (ebytes, Color_INVERT);
					}
				} else {
					if (here >= low && here <max) {
						append (ebytes, Color_INVERT);
						append (echars, Color_INVERT);
					}
				}
			}
			sprintf (ebytes, "%02x", ch);
			ebytes += strlen (ebytes);
			sprintf (echars, "%c", IS_PRINTABLE (ch)?ch:'.');
			echars++;
			if (core->print->cur_enabled && max == here) {
				append (ebytes, Color_RESET);
				append (echars, Color_RESET);
				hascolor = R_FALSE;
			}

			if (j < (nb_cols-1) && (j%2))
				append (ebytes, " ");

			if (fend != UT64_MAX && fend == addr+j+1) {
				if (usecolor) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				fend = UT64_MAX;
				hascolor = R_FALSE;
			}

		}
		append (ebytes, Color_RESET);
		append (echars, Color_RESET);
		append (ebytes, (col==1)?"| ":(col==2)?" |":"  ");
		if (col==2) append (echars, "|");

		if (marks) { // show comments and flags
			int hasline = 0;
			int out_sz = nb_cons_cols+20;
			char* out = calloc (out_sz, sizeof(char));
			memset (out, ' ', nb_cons_cols-1);
			for (j=0; j<nb_cols; j++) {
				if (note[j]) {
					int off = (j*3) - (j/2) + 13;
					int notej_len = strlen (note[j]);
					int sz = R_MIN (notej_len, nb_cons_cols-off);
					if (j%2) off--;
					memcpy (out+off, note[j], sz);
					if (sz < notej_len) {
						out[off+sz-2] = '.';
						out[off+sz-1] = '.';
					}
					hasline = (out[off] != ' ');
					R_FREE (note[j]);
				}
			}
			out[out_sz-1] = 0;
			if (hasline) {
				r_cons_strcat (addrpad);
				r_cons_strcat (out);
				r_cons_newline ();
			}
			marks = R_FALSE;
			free (out);
		}
		r_cons_strcat (bytes);
		r_cons_strcat (chars);
		r_cons_newline ();
		addr += nb_cols;
	}
	free (note);
	free (bytes);
	free (chars);
}

R_API void r_core_print_examine(RCore *core, const char *str) {
	char cmd[128], *p;
	ut64 addr = core->offset;
	int size = (core->anal->bits/4);
	int count = atoi (str);
	int i, n;
	if (count<1) count = 1;
	// skipsapces
	while (*str>='0' && *str<='9') str++;

	// "px/" alone isn't a full command.
	if (!str[0]) return;
#if 0
Size letters are b(byte), h(halfword), w(word), g(giant, 8 bytes).
#endif
	switch (str[1]) {
	case 'b': size = 1; break;
	case 'h': size = 2; break;
	case 'd': size = 4; break;
	case 'w': size = 4; break;
	case 'g': size = 8; break;
	}
	if ((p=strchr (str, ' ')))
		addr = r_num_math (core->num, p+1);
	switch (*str) {
	case '?':
		eprintf (
"Format is x/[num][format][size]\n"
"Num specifies the number of format elements to display\n"
"Format letters are o(octal), x(hex), d(decimal), u(unsigned decimal),\n"
"  t(binary), f(float), a(address), i(instruction), c(char) and s(string),\n"
"  T(OSType), A(floating point values in hex).\n"
"Size letters are b(byte), h(halfword), w(word), g(giant, 8 bytes).\n"
);
		break;
	case 's':
		r_core_cmdf (core, "psb %d @ 0x%"PFMT64x, count*size, addr);
		break;
	case 'o':
		r_core_cmdf (core, "pxo %d @ 0x%"PFMT64x, count*size, addr);
		break;
	case 'f':
	case 'A': // XXX (float in hex wtf)
		n = 3;
		snprintf (cmd, sizeof (cmd), "pxo %d @ 0x%"PFMT64x,
			count*size, addr);
		strcpy (cmd, "pf ");
		for (i=0;i<count && n<sizeof (cmd);i++)
			cmd[n++] = 'f';
		cmd[n] = 0;
		r_core_cmd0 (core, cmd);
		break;
	case 'x':
		r_core_cmdf (core, "px %d @ 0x%"PFMT64x, count, addr);
		break;
	case 'a':
	case 'd':
		r_core_cmdf (core, "pxw %d @ 0x%"PFMT64x, count*size, addr);
		break;
	case 'i':
		r_core_cmdf (core, "pid %d @ 0x%"PFMT64x, count, addr);
		break;
	}
}

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size) {
	RCore *core = (RCore *) user;
	int j, ret = 0;
	RListIter *iter;
	RFlagItem *flag;

	switch (mode) {
	case 'p':
		for (j=0; j<size; j++)
			if (IS_PRINTABLE (bufz[j]))
				ret++;
		break;
	case 'f':
		r_list_foreach (core->flags->flags, iter, flag)
			if (flag->offset <= addr  && addr < flag->offset+flag->size)
				ret++;
		break;
	case 's':
		j = r_flag_space_get (core->flags, "strings");
		r_list_foreach (core->flags->flags, iter, flag) {
			if (flag->space == j && ((addr <= flag->offset
					&& flag->offset < addr+size)
					|| (addr <= flag->offset+flag->size
					&& flag->offset+flag->size < addr+size)))
				ret++;
		}
		break;
	case '0': // 0x00
		for (j=0; j<size; j++)
			if (bufz[j] == 0)
				ret++;
		break;
	case 'F': // 0xFF
		for (j=0; j<size; j++)
			if (bufz[j] == 0xff)
				ret++;
		break;
	case 'e': // entropy
		ret = (ut8) (r_hash_entropy_fraction (bufz, size)*255);
		break;
	case 'h': // head
	default:
		ret = *bufz;
	}
	return ret;
}

R_API void r_core_print_cmp(RCore *core, ut64 from, ut64 to) {
	long int delta = 0;
	int col = core->cons->columns>123;
	ut8 *b = malloc (core->blocksize);
	ut64 addr = core->offset;
	memset (b, 0xff, core->blocksize);
	delta = addr - from;
	r_core_read_at (core, to+delta, b, core->blocksize);
	r_print_hexdiff (core->print, core->offset, core->block,
		to+delta, b, core->blocksize, col);
	free (b);
}

static int pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt) {
	int show_offset = r_config_get_i (core->config, "asm.offset");
	int show_bytes = r_config_get_i (core->config, "asm.bytes");
	int decode = r_config_get_i (core->config, "asm.decode");
	int esil = r_config_get_i (core->config, "asm.esil");
	int flags = r_config_get_i (core->config, "asm.flags");
	int i=0, j, ret, err = 0;
	ut64 old_offset = core->offset;
	RAsmOp asmop;

	if (fmt=='e') {
		show_bytes = 0;
		decode = 1;
	}

	if (!nb_opcodes) {
		nb_opcodes = 0xffff;
		if (nb_bytes < 0) {
			// Backward disasm `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			core->offset -= nb_bytes;
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		}
	} else if (!nb_bytes) {
		if (nb_opcodes < 0) {
			/* Backward disassembly of `ilen` opcodes
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;
			r_core_asm_bwdis_len (core, &nb_bytes, &core->offset, nb_opcodes);
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		} else // workaround for the `for` loop below
			nb_bytes = core->blocksize;
	}

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal && core->anal->cur && core->anal->cur->reset_counter	) {
		core->anal->cur->reset_counter (core->anal, core->offset);
	}

	r_cons_break (NULL, NULL);
	for (i=j=0; j<nb_opcodes; j++) {
		RFlagItem *item;
		if (r_cons_singleton ()->breaked) {
			err = 1;
			break;
		}
		r_asm_set_pc (core->assembler, core->offset+i);
		ret = r_asm_disassemble (core->assembler, &asmop, core->block+i,
			core->blocksize-i);
		if (flags) {
			item = r_flag_get_i (core->flags, core->offset+i);
			if (item) {
				if (show_offset)
					r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
				r_cons_printf ("  %s:\n", item->name);
			}
		}
		if (show_offset)
			r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ret<1) {
			err = 1;
			ret = asmop.size;
			if (ret<1) ret = 1;
			if (show_bytes)
				r_cons_printf ("%14s%02x  ", "", core->block[i]);
			r_cons_printf ("%s\n", "invalid"); //???");
		} else {
			if (show_bytes)
				r_cons_printf ("%16s  ", asmop.buf_hex);
			ret = asmop.size;
			if (decode || esil) {
				RAnalOp analop = {0};
				char *tmpopstr, *opstr = NULL;
				r_anal_op (core->anal, &analop, core->offset+i,
					core->block+i, core->blocksize-i);
				tmpopstr = r_anal_op_to_string (core->anal, &analop);
				if (fmt == 'e') { // pie
					char spaces[26];
					char *code = asmop.buf_asm;
					char *esil = (R_STRBUF_SAFEGET (&analop.esil));
					int j, wlen = sizeof (spaces)-strlen (code);
					for (j=0; j<wlen; j++) {
						spaces[j] = ' ';
					}
					if (!esil) esil = "";
					spaces[R_MIN(sizeof (spaces)-1,j)] = 0;
					r_cons_printf ("%s%s%s\n",
						code, spaces, esil);
				} else {
					if (decode) {
						opstr = (tmpopstr)? tmpopstr: (asmop.buf_asm);
					} else if (esil) {
						opstr = (R_STRBUF_SAFEGET (&analop.esil));
					}
					r_cons_printf ("%s\n", opstr);
				}
			} else r_cons_printf ("%s\n", asmop.buf_asm);
		}
		i+=ret;
		if (nb_bytes && (nb_bytes <= i))
			break;
	}
	r_cons_break_end ();
	core->offset = old_offset;
	return err;
}

static void cmd_print_pwn(const RCore* core) {
	int i, n = r_num_rand (10);
	ut64 num, base = r_num_get (core->num, "entry0");
	if (!base)
		base = 0x8048000;

	eprintf ("[+] Analyzing code starting at 0x%08"PFMT64x"...\n", base);
	r_sys_sleep (3);

	eprintf ("[+] Looking for vulnerabilities...\n");
	r_sys_sleep (3);

	eprintf ("[+] Found %d bugs...\n", n);
	for (i=0; i<n; i++) {
		eprintf ("[+] Deeply analyzing bug %d at 0x%08"PFMT64x"...\n",
				i, base+r_num_rand (0xffff));
		r_sys_sleep (1);
	}

	eprintf ("[+] Finding ROP gadgets...\n");
	n = r_num_rand (0x20);
	num = base;
	for (i=0; i<n; i++) {
		num += r_num_rand (0xfff);
		eprintf (" * 0x%08"PFMT64x" %d : %02x %02x ..\n",
				num, r_num_rand (10),
				r_num_rand (0xff), r_num_rand (0xff));
		r_sys_sleep (r_num_rand (2));
	}

	eprintf ("[+] Cooking the shellcode...\n");
	r_sys_sleep (4);

	eprintf ("[+] Launching the exploit...\n");
	r_sys_sleep (1);

	r_sys_cmd ("sh");
}


static int cmd_print(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int mode, w, p, i, l, len, total[10];
	ut64 off, from, to, at, ate, piece;
	ut32 tbs = core->blocksize;
	ut8 *ptr = core->block;
	RCoreAnalStats *as;
	ut64 n, nbsz, obsz, fsz;

	l = len = core->blocksize;
	if (input[0] && input[1]) {
		const char *p = strchr (input, ' ');
		if (p) {
			l = (int) r_num_math (core->num, p+1);
			/* except disasm and memoryfmt (pd, pm) */
			if (input[0] != 'd' && input[0] != 'D' && input[0] != 'm' && input[0]!='a' && input[0]!='f') {
				if (l>0) {
					len = l;
					if (l>tbs) {
						if (!r_core_block_size (core, l)) {
							eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
								*input, input+2);
							return R_FALSE;
						}
						l = core->blocksize;
					} else {
						l = len;
					}
				}
			}
		}// else l = 0;
	} else l = len;

	if (len > core->blocksize)
		len = core->blocksize;

	if (input[0] != 'd' && input[0] != 'm' && input[0]!='a') {
		n = core->blocksize_max;
		i = (int)n;
		if (i != n) i = 0;
		if (i && l > i) {
			eprintf ("This block size is too big (%d<%d). Did you mean 'p%c @ %s' instead?\n",
					i, l, *input, input+2);
			return R_FALSE;
		}
	}

	if (input[0] && input[0]!='z' && input[1] == 'f') {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) {
			len = f->size;
		} else {
			eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			return R_FALSE;
		}
	}
	ptr = core->block;
	core->num->value = len;
	if (len>core->blocksize)
		len = core->blocksize;
	switch (*input) {
	case 'w': //pw
		if (input[1]=='n') {
			cmd_print_pwn(core);
		}	else if (input[1]=='d') {
			if (!r_sandbox_enable (0)) {
				char *cwd = r_sys_getdir ();
				if (cwd) {
					eprintf ("%s\n", cwd);
					free (cwd);
				}
			}
		} else {
			r_cons_printf("| pwd               display current working directory\n");
		}
		break;
	case 'v': //pv
		mode = input[1];
		w = len? len: core->print->cols * 4;
		if (mode == 'j') r_cons_strcat ("{");
		off = core->offset;
		for (i=0; i<10; i++) total[i] = 0;
		{
		RList* list = r_core_get_boundaries (core, "file", &from, &to);
		if (from && to && list)
			r_list_free (list);
		}
		piece = (to-from) / w;
		if (piece<1) piece = 1;
		as = r_core_anal_get_stats (core, from, to, piece);
		//eprintf ("RANGE = %llx %llx\n", from, to);
		switch (mode) {
		case '?':{
			const char* help_msg[] = {
				"Usage:", "p%%[jh] [pieces]", "bar|json|histogram blocks",
				"pv", "", "show ascii-art bar of metadata in file boundaries",
				"pvj", "", "show json format",
				"pvh", "", "show histogram analysis of metadata per block",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			return 0;
		case 'j': //pvj
			r_cons_printf (
				"\"from\":%"PFMT64d","
				"\"to\":%"PFMT64d","
				"\"blocksize\":%d,"
				"\"blocks\":[", from, to, piece);
			break;
		case 'h': //pvh
			r_cons_printf (".-------------.---------------------------------.\n");
			r_cons_printf ("|   offset    | flags funcs cmts imps syms str  |\n");
			r_cons_printf ("|-------------)---------------------------------|\n");
			break;
		default:
			r_cons_printf ("0x%"PFMT64x" [", from);
		}

		len = 0;
		for (i=0; i<w; i++) {
			at = from + (piece*i);
			ate = at + piece;
			p = (at-from)/piece;
			switch (mode) {
			case 'j':
				r_cons_printf ("%s{",len?",":"");
				if ((as->block[p].flags)
						|| (as->block[p].functions)
						|| (as->block[p].comments)
						|| (as->block[p].imports)
						|| (as->block[p].symbols)
						|| (as->block[p].strings))
					r_cons_printf ("\"offset\":%"PFMT64d",", at), l++;
				// TODO: simplify with macro
				l = 0;
				if (as->block[p].flags) r_cons_printf ("%s\"flags\":%d", l?",":"", as->block[p].flags), l++;
				if (as->block[p].functions) r_cons_printf ("%s\"functions\":%d", l?",":"", as->block[p].functions), l++;
				if (as->block[p].comments) r_cons_printf ("%s\"comments\":%d", l?",":"", as->block[p].comments), l++;
				if (as->block[p].imports) r_cons_printf ("%s\"imports\":%d", l?",":"", as->block[p].imports), l++;
				if (as->block[p].symbols) r_cons_printf ("%s\"symbols\":%d", l?",":"", as->block[p].symbols), l++;
				if (as->block[p].strings) r_cons_printf ("%s\"strings\":%d", l?",":"", as->block[p].strings), l++;
				r_cons_strcat ("}");
				len++;
				break;
			case 'h':
				total[0] += as->block[p].flags;
				total[1] += as->block[p].functions;
				total[2] += as->block[p].comments;
				total[3] += as->block[p].imports;
				total[4] += as->block[p].symbols;
				total[5] += as->block[p].strings;
				if ((as->block[p].flags)
						|| (as->block[p].functions)
						|| (as->block[p].comments)
						|| (as->block[p].imports)
						|| (as->block[p].symbols)
						|| (as->block[p].strings))
					r_cons_printf ("| 0x%09"PFMT64x" | %4d %4d %4d %4d %4d %4d   |\n", at,
							as->block[p].flags,
							as->block[p].functions,
							as->block[p].comments,
							as->block[p].imports,
							as->block[p].symbols,
							as->block[p].strings);
				break;
			default:
				if (off>=at && off<ate) {
					r_cons_memcat ("^", 1);
				} else {
					if (as->block[p].strings>0)
						r_cons_memcat ("z", 1);
					else if (as->block[p].imports>0)
						r_cons_memcat ("i", 1);
					else if (as->block[p].symbols>0)
						r_cons_memcat ("s", 1);
					else if (as->block[p].functions>0)
						r_cons_memcat ("F", 1);
					else if (as->block[p].flags>0)
						r_cons_memcat ("f", 1);
					else if (as->block[p].comments>0)
						r_cons_memcat ("c", 1);
					else r_cons_memcat (".", 1);
				}
				break;
			}
		}
		switch (mode) {
			case 'j':
				r_cons_strcat ("]}\n");
				break;
			case 'h':
				//r_cons_printf ("  total    | flags funcs cmts imps syms str  |\n");
				r_cons_printf ("|-------------)---------------------------------|\n");
				r_cons_printf ("|    total    | %4d %4d %4d %4d %4d %4d   |\n",
					total[0], total[1], total[2], total[3], total[4], total[5]);
				r_cons_printf ("`-------------'---------------------------------'\n");
				break;
			default:
				r_cons_printf ("] 0x%"PFMT64x"\n", to);
		}
		r_core_anal_stats_free (as);
		break;
	case '=': //p=
		nbsz = r_num_get (core->num, *input?input[1]?input+2:input+1:input);
		fsz = (core->file && core->io)? r_io_desc_size (core->io, core->file->desc): 0;
		if (nbsz) {
			nbsz = fsz / nbsz;
			obsz = core->blocksize;
			r_core_block_size (core, nbsz);
		} else {
			nbsz = core->blocksize;
			obsz = 0LL;
		}
		switch (input[1]) {
		case '?':{ // bars
			const char* help_msg[] = {
			"Usage:", "p=[bep?] [num-of-blocks]", "show entropy/printable chars/chars bars",
			"p=", "", "print bytes of current block in bars",
			"p=", "b", "same as above",
			"p=", "e", "print entropy for each filesize/blocksize",
			"p=", "p", "print number of printable bytes for each filesize/blocksize",
			NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		case 'e': // entropy
			{
			ut8 *p;
			int psz, i = 0;
			if (nbsz<1) nbsz=1;
			psz = fsz / nbsz;
			if (!psz) psz = 1;
			ptr = malloc (psz);
			if (!ptr) {
				eprintf ("Error: failed to malloc memory");
				return R_FALSE;
			}
			eprintf ("block = %d * %d\n", (int)nbsz, psz);
			p = malloc (core->blocksize);
			if (!p) {
				free (ptr);
				eprintf ("Error: failed to malloc memory");
				return R_FALSE;
			}
			for (i=0; i<psz; i++) {
				r_core_read_at (core, i*nbsz, p, nbsz);
				ptr[i] = (ut8) (256 * r_hash_entropy_fraction (p, core->blocksize));
			}
			free (p);
			r_print_fill (core->print, ptr, psz);
			if (ptr != core->block)
				free (ptr);
			}
			break;
		case 'p': // printable chars
			{
			ut8 *p;
			int psz, i = 0, j, k;
			if (nbsz<1) nbsz=1;
			psz = fsz / nbsz;
			if (!psz) psz = 1;
			ptr = malloc (psz);
			if (!ptr) {
				eprintf ("Error: failed to malloc memory");
				return R_FALSE;
			}
			eprintf ("block = %d * %d\n", (int)nbsz, (int)psz);
			p = malloc (core->blocksize);
			if (!p) {
				eprintf ("Error: failed to malloc memory");
                                free(ptr);
				return R_FALSE;
			}
			for (i=0; i<psz; i++) {
				r_core_read_at (core, i*nbsz, p, nbsz);
				for (j=k=0; j<nbsz; j++) {
					if (IS_PRINTABLE (p[j]))
						k++;
				}
				ptr[i] = 256 * k / nbsz;
			}
			free (p);
			r_print_fill (core->print, ptr, psz);
			if (ptr != core->block)
				free (ptr);
			}
			break;
		case 'b': // bytes
		case '\0':
			r_print_fill (core->print, ptr, core->blocksize);
			if (ptr != core->block) {
				free (ptr);
			}
		}
		if (nbsz)
			r_core_block_size (core, obsz);
		break;
	case 'a': //pa
		if (input[1]=='e') { // "pae"
			if (input[2]=='?') {
				r_cons_printf ("|Usage: pae [hex]       assemble esil from hexpairs\n");
			} else {
				int ret, bufsz;
				RAnalOp aop = {0};
				const char *str;
				char *buf = strdup (input+2);
				bufsz = r_hex_str2bin (buf, (ut8*)buf);
				ret = r_anal_op (core->anal, &aop, core->offset,
					(const ut8*)buf, bufsz);
				if (ret>0) {
					str = R_STRBUF_SAFEGET (&aop.esil);
					r_cons_printf ("%s\n", str);
				}
				r_anal_op_fini (&aop);
			}
		} else if (input[1]=='d') { // "pad"
			if (input[2]=='?') {
				r_cons_printf ("|Usage: pad [asm]       disasm\n");
			} else {
				RAsmCode *c;
				r_asm_set_pc (core->assembler, core->offset);
				c = r_asm_mdisassemble_hexstr (core->assembler, input+2);
				if (c) {
					r_cons_puts (c->buf_asm);
					r_asm_code_free (c);
				} else eprintf ("Invalid hexstr\n");
			}
		} else if (input[1]=='?') {
			r_cons_printf("|Usage: pa[ed] [hex|asm]  assemble (pa) disasm (pad) or"
										"esil (pae) from hexpairs\n");
		} else {
			RAsmCode *acode;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, input+1);
			if (acode && *acode->buf_hex) {
				r_cons_printf ("%s\n", acode->buf_hex);
				r_asm_code_free (acode);
			}
		}
		break;
	case 'b': { //pb
		if (input[1]=='?') {
			r_cons_printf("|Usage: p[bB] [len]       bitstream of N bytes\n");
		} else {
			ut32 n;
			int i, c;
			char buf[32];
#define P(x) (IS_PRINTABLE(x)?x:'.')
#define SPLIT_BITS(x) memmove (x+5, x+4, 5); x[4]=0
			for (i=c=0; i<len; i++,c++) {
				if (c==0) r_print_offset (core->print, core->offset+i, 0, 0);
				r_str_bits (buf, core->block+i, 8, NULL);
				SPLIT_BITS (buf);
				r_cons_printf ("%s.%s  ", buf, buf+5);
				if (c==3) {
					const ut8 *b = core->block + i-3;
					#define K(x) (b[3-x]<<(8*x))
					n = K (0) | K (1) | K (2) | K (3);
					r_cons_printf ("0x%08x  %c%c%c%c\n",
						n, P (b[0]), P (b[1]), P (b[2]), P (b[3]));
					c = -1;
				}
			}
			}
		}
		break;
	case 'B': { //pB
		if (input[1]=='?') {
			r_cons_printf ("|Usage: p[bB] [len]       bitstream of N bytes\n");
		} else {
			const int size = len*8;
			char *buf = malloc (size+1);
			if (buf) {
				r_str_bits (buf, core->block, size, NULL);
				r_cons_printf ("%s\n", buf);
				free (buf);
			} else eprintf ("ERROR: Cannot malloc %d bytes\n", size);
		} }
		break;
	case 'I': // "pI"
		switch (input[1]) {
			case 'j': // "pIj" is the same as pDj
				cmd_pDj (core, input+2);
				break;
			case 'f':
				{
					const RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
							R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
					if (f) {
						r_core_print_disasm_instructions (core, f->size, l);
						break;
					}
				}
			case 'd': // "pId" is the same as pDi
				pdi (core, 0, l, 0);
				break;
			case '?': // "pi?"
				r_cons_printf("|Usage: p[iI][df] [len]   print N instructions/bytes"
						"(f=func) (see pi? and pdi)\n");
				break;
			default:
				r_core_print_disasm_instructions (core, l, 0);
		}
		break;
	case 'i': // "pi"
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: pi[defj] [num]\n");
			break;
		case 'j': //pij is the same as pdj
			cmd_pdj (core, input+2);
			break;
		case 'd': //pid is the same as pdi
			pdi (core, l, 0, 0);
			break;
		case 'e':
			pdi (core, l, 0, 'e');
			break;
		case 'f': //pif
			{
			RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
					R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
			if (f) {
				r_core_print_disasm_instructions (core, f->size, l);
			} else {
				r_core_print_disasm_instructions (core,
					core->blocksize, l);
			}
			}
			break;
		default:
			r_core_print_disasm_instructions (core, 0, l);
			break;
		}
		return 0;
	case 'D': // "pD"
	case 'd': // "pd"
		{
		ut64 current_offset = core->offset;
		ut32 new_bits = -1;
		ut64 use_blocksize = core->blocksize;
		int segoff, old_bits, pos = 0;
		ut8 settings_changed = R_FALSE, bw_disassemble = R_FALSE;
		char *new_arch = NULL, *old_arch = NULL;
		ut32 pd_result = R_FALSE, processed_cmd = R_FALSE;
		old_arch = strdup (r_config_get (core->config, "asm.arch"));
		segoff = r_config_get_i (core->config, "asm.segoff");
		old_bits = r_config_get_i (core->config, "asm.bits");

		// XXX - this is necessay b/c radare will automatically
		// swap flags if arch is x86 and bits == 16 see: __setsegoff in config.c

		// get to the space
		if (input[0])
			for (pos = 1; pos < R_BIN_SIZEOF_STRINGS && input[pos]; pos++)
				if (input[pos] == ' ') break;

		if (!process_input (core, input+pos, &use_blocksize, &new_arch, &new_bits)) {
			// XXX - print help message
			//return R_FALSE;
		}
		if (!use_blocksize)
			use_blocksize = core->blocksize;

		if (core->blocksize_max < use_blocksize && (int)use_blocksize < -core->blocksize_max) {
			eprintf ("This block size is too big (%"PFMT64d"<%"PFMT64d"). Did you mean 'p%c @ 0x%08"PFMT64x"' instead?\n",
				(ut64)core->blocksize_max, (ut64)use_blocksize, input[0], (ut64) use_blocksize);
			free (old_arch);
			free (new_arch);
			return R_FALSE;
		} else if (core->blocksize_max < use_blocksize && (int)use_blocksize > -core->blocksize_max) {
			bw_disassemble = R_TRUE;
			use_blocksize = -use_blocksize;
		}

		if (new_arch == NULL) new_arch = strdup (old_arch);
		if (new_bits == -1) new_bits = old_bits;

		if (strcmp (new_arch, old_arch) != 0 || new_bits != old_bits){
			set_asm_configs (core, new_arch, new_bits, segoff);
			settings_changed = R_TRUE;
		}

		switch (input[1]) {
		case 'i': // "pdi"
			processed_cmd = R_TRUE;
			if (*input == 'D')
				pdi (core, 0, l, 0);
			else
				pdi (core, l, 0, 0);
			pd_result = 0;
			break;
		case 'a': // "pda"
			processed_cmd = R_TRUE;
			{
				RAsmOp asmop;
				int ret, err = 0;
				ut8 *buf = core->block;
				if (l<1) l = len;
				if (l>core->blocksize) {
					buf = malloc (l+1);
					r_core_read_at (core, core->offset, buf, l);
				}
				r_cons_break (NULL, NULL);
				for (i=0; i<l; i++) {
					r_asm_set_pc (core->assembler, core->offset+i);
					if (r_cons_singleton ()->breaked)
						break;
					ret = r_asm_disassemble (core->assembler, &asmop,
						buf+i, l-i);
					if (ret<1) {
						ret = err = 1;
						//r_cons_printf ("???\n");
						r_cons_printf ("0x%08"PFMT64x" ???\n", core->offset+i);
					} else r_cons_printf ("0x%08"PFMT64x" %16s  %s\n",
						core->offset+i, asmop.buf_hex, asmop.buf_asm);
				}
				r_cons_break_end ();
				if (buf != core->block)
					free (buf);
				pd_result = R_TRUE;
			}
			break;
		case 'r': // "pdr"
			processed_cmd = R_TRUE;
			{
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
						R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f) {
					RListIter *iter;
					RAnalBlock *b;
					// XXX: hack must be reviewed/fixed in code analysis
					if (r_list_length (f->bbs) == 1) {
						b = r_list_get_top (f->bbs);
						if (b->size > f->size) b->size = f->size;
					}
					// TODO: sort by addr
					//r_list_sort (f->bbs, &r_anal_ex_bb_address_comparator);
					r_list_foreach (f->bbs, iter, b) {
						r_core_cmdf (core, "pD %"PFMT64d" @0x%"PFMT64x, b->size, b->addr);
						/*switch (control_type) {
							case R_ANAL_OP_TYPE_CALL:
								break;
							case R_ANAL_OP_TYPE_JMP:
								break;
							case R_ANAL_OP_TYPE_CJMP:
								break;
							case R_ANAL_OP_TYPE_SWITCH:
						}*/
						if (b->jump != UT64_MAX)
							r_cons_printf ("-[true]-> 0x%08"PFMT64x"\n", b->jump);
						if (b->fail != UT64_MAX)
							r_cons_printf ("-[false]-> 0x%08"PFMT64x"\n", b->fail);
						r_cons_printf ("--\n");
					}
				} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
				pd_result = R_TRUE;
			}
			break;
		case 'b': // "pdb"
			processed_cmd = R_TRUE;
			{
				RAnalBlock *b = r_anal_bb_from_offset (core->anal, core->offset);
				if (b) {
					ut8 *block = malloc (b->size+1);
					if (block) {
						r_core_read_at (core, b->addr, block, b->size);
						core->num->value = r_core_print_disasm (
							core->print, core, b->addr, block,
							b->size, 9999, 0, 2);
						free (block);
						pd_result = 0;
					}
				} else eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			}
			break;
		case 'f': // "pdf"
			processed_cmd = R_TRUE;
			{
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
						R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f && input[2] == 'j') { // "pdfj"
					r_cons_printf ("{");
					r_cons_printf ("\"name\":\"%s\"", f->name);
					r_cons_printf (",\"size\":%d", f->size);
					r_cons_printf (",\"addr\":%"PFMT64d, f->addr);
					r_cons_printf (",\"ops\":");
					// instructions are all outputted as a json list
					{
						ut8 *buf = malloc (f->size);
						if (buf) {
							r_io_read_at (core->io, f->addr, buf, f->size);
							r_core_print_disasm_json (core, f->addr, buf, f->size, 0);
							r_cons_newline ();
							free (buf);
						} else eprintf ("cannot allocate %d bytes\n", f->size);
					}
					//close function json
					r_cons_printf ("}");
					pd_result = 0;


				} else if (f) {
#if 0
#if 1
// funsize = sum(bb)
					core->num->value = r_core_print_fcn_disasm (core->print, core, f->addr, 9999, 0, 2);
#else
//  funsize = addrend-addrstart
					ut8 *block = malloc (f->size+1);
					if (block) {
						r_core_read_at (core, f->addr, block, f->size);
						core->num->value = r_core_print_disasm (
							core->print, core, f->addr, block,
							f->size, 9999, 0, 2);
						free (block);
						pd_result = 0;
					}
#endif
#else
					r_core_cmdf (core, "pD %d @ 0x%08llx", f->size, f->addr);
					pd_result = 0;
#endif
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
					processed_cmd = R_TRUE;
				}
			}
			l = 0;
			break;
		case 'l': //pdl
			processed_cmd = R_TRUE;
			{
				RAsmOp asmop;
				int j, ret;
				const ut8 *buf = core->block;
				if (l==0) l= len;
				r_cons_break (NULL, NULL);
				for (i=j=0; i<core->blocksize && j<l; i+=ret,j++ ) {
					ret = r_asm_disassemble (core->assembler, &asmop, buf+i, len-i);
					if (r_cons_singleton ()->breaked) break;
					r_cons_printf ("%d\n", ret);
					if (ret<1) ret = 1;
				}
				r_cons_break_end ();
				pd_result = 0;
			}
			break;
		case 'j': //pdj
			processed_cmd = R_TRUE;
			if (*input == 'D'){
				cmd_pDj (core, input+2);
			} else cmd_pdj (core, input+2);
			r_cons_newline ();
			pd_result = 0;
			break;
		case 0:
			/* "pd" -> will disassemble blocksize/4 instructions */
			if (*input=='d') {
				l/=4;
			}
			break;
		case '?': // "pd?"
			processed_cmd = R_TRUE;
			const char* help_msg[] = {
				"Usage:", "p[dD][fil] [len] [arch] [bits] @ [addr]", " # Print Disassembly",
				"NOTE:", "len", "parameter can be negative",
				"pda", "", "disassemble all possible opcodes (byte per byte)",
				"pdj", "", "disassemble to json",
				"pdb", "", "disassemble basic block",
				"pdr", "", "recursive disassemble across the function graph",
				"pdf", "", "disassemble function",
				"pdi", "", "like 'pi', with offset and bytes",
				"pdl", "", "show instruction sizes",
				"pds", "", "disassemble with back sweep (greedy disassembly backwards)",
				NULL};
				r_core_cmd_help (core, help_msg);
			pd_result = 0;
		}
		if (!processed_cmd) {
			ut64 addr = core->offset;
			ut8 *block = NULL;

			if (bw_disassemble) {
				block = malloc (core->blocksize);
				l = -l;
				if (block) {
					if (*input == 'D'){ //pD
						r_core_read_at (core, addr-l, block, core->blocksize);
						core->num->value = r_core_print_disasm (core->print,
							core, addr-l, block, R_MIN (l, core->blocksize), l, 0, 1);
					} else { //pd
						int instr_len;
						r_core_asm_bwdis_len (core, &instr_len, &addr, l);
						r_core_read_at (core, addr, block, instr_len);
						core->num->value = r_core_print_disasm (core->print,
								core, addr, block, instr_len, l, 0, 1);
					}
				}
			} else {
				const int bs = core->blocksize;
				// XXX: issue with small blocks
				if (*input == 'D' && l>0) { //pD
					block = malloc (l);
					if (l>core->blocksize) {
						r_core_read_at (core, addr, block, l); //core->blocksize);
					} else {
						memcpy (block, core->block, l);
					}
					core->num->value = r_core_print_disasm (core->print,
						core, addr, block, l, l, 0, 1);
				} else {
					block = malloc (R_MAX(l*10, bs));
					memcpy (block, core->block, bs);
					r_core_read_at (core, addr+bs, block+bs, (l*10)-bs); //core->blocksize);
					//core->num->value = r_core_print_disasm (core->print,
					//	core, addr, block, l*10, l, 0, 0);
					core->num->value = r_core_print_disasm (core->print,
							core, addr, block, l*10, l, 0, 0);
				}
			}
			free (block);
		}
		core->offset = current_offset;
		// change back asm setting is they were changed
		if (settings_changed)
			set_asm_configs (core, old_arch, old_bits, segoff);

		free (old_arch);
		free (new_arch);

		if (processed_cmd)
			return pd_result;
		}
		break;
	case 's': //ps
		switch (input[1]) {
		case '?':{
			const char* help_msg[] = {
				"Usage:", "ps[zpw] [N]", "Print String",
				"ps", "", "print string",
				"psi", "", "print string inside curseek",
				"psb", "", "print strings in current block",
				"psx", "", "show string with scaped chars",
				"psz", "", "print zero terminated string",
				"psp", "", "print pascal string",
				"psw", "", "print wide string",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		case 'i': //psi
			{
			ut8 *buf = malloc (1024);
			int delta = 512;
			ut8 *p, *e, *b;
			if (!buf) return 0;
			if (core->offset<delta)
				delta = core->offset;
			p = buf+delta;
			r_core_read_at (core, core->offset-delta, buf, 1024);
			for (b = p; b>buf; b--) {
				if (!IS_PRINTABLE (*b)) {
					b++;
					break;
				}
			}
			for (e = p; e<(buf+1024); e++) {
				if (!IS_PRINTABLE (*b)) {
					*e = 0;
					e--;
					break;
				}
			}
			r_cons_strcat ((const char *)b);
			r_cons_newline ();
			//r_print_string (core->print, core->offset, b,
			//	(size_t)(e-b), 0);
			free (buf);
			}
			break;
		case 'x': // "psx"
			r_print_string (core->print, core->offset, core->block, len, 0);
			break;
		case 'b': // "psb"
			{
				char *s = malloc (core->blocksize+1);
				int i, j, hasnl = 0;;
				if (s) {
					memset (s, 0, core->blocksize);
					// TODO: filter more chars?
					for (i=j=0;i<core->blocksize; i++) {
						char ch = (char)core->block[i];
						if (!ch) {
							if (!hasnl) {
								s[j] = 0;
								if (*s) r_cons_printf ("%s\n", s);
								j = 0;
								s[0] = 0;
							}
							hasnl = 1;
							continue;
						}
						hasnl = 0;
						if (IS_PRINTABLE (ch))
							s[j++] = ch;
					}
					s[j] = 0;
					r_cons_printf ("%s", s); // TODO: missing newline?
					free (s);
				}
			}
			break;
		case 'z': //psz
			{
				char *s = malloc (core->blocksize+1);
				int i, j;
				if (s) {
					memset (s, 0, core->blocksize);
					// TODO: filter more chars?
					for (i=j=0;i<core->blocksize; i++) {
						char ch = (char)core->block[i];
						if (!ch) break;
						if (IS_PRINTABLE (ch))
							s[j++] = ch;
					}
					r_cons_printf ("%s\n", s);
					free (s);
				}
			}
			break;
		case 'p': //psp
			{
			int mylen = core->block[0];
			// TODO: add support for 2-4 byte length pascal strings
			if (mylen < core->blocksize) {
				r_print_string (core->print, core->offset,
					core->block+1, mylen, R_PRINT_STRING_ZEROEND);
				core->num->value = mylen;
			} else core->num->value = 0; // error
			}
			break;
		case 'w': //psw
			r_print_string (core->print, core->offset, core->block, len,
				R_PRINT_STRING_WIDE | R_PRINT_STRING_ZEROEND);
			break;
		case ' ':
			len = r_num_math (core->num, input+2);
			r_print_string (core->print, core->offset, core->block, len, 0);
			break;
		default:
			r_print_string (core->print, core->offset, core->block, len,
				R_PRINT_STRING_ZEROEND);
			break;
		}
		break;
	case 'm': //pm
		if (input[1]=='?') {
			r_cons_printf ("|Usage: pm [file|directory]\n"
				"| r_magic will use given file/dir as reference\n"
				"| output of those magic can contain expressions like:\n"
				"|   foo@0x40   # use 'foo' magic file on address 0x40\n"
				"|   @0x40      # use current magic file on address 0x40\n"
				"|   \\n         # append newline\n"
				"| e dir.magic  # defaults to "R_MAGIC_PATH"\n"
				);
		} else r_core_magic (core, input+1, R_TRUE);
		break;
	case 'u': //pu
		if (input[1]=='?') {
			r_cons_printf ("|Usage: pu[w] [len]       print N url"
					"encoded bytes (w=wide)\n");
		} else {
			r_print_string (core->print, core->offset, core->block, len,
					R_PRINT_STRING_URLENCODE |
					((input[1]=='w')?R_PRINT_STRING_WIDE:0));
		}
		break;
	case 'c': //pc
		r_print_code (core->print, core->offset, core->block, len, input[1]);
		break;
	case 'r': //pr
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: prl: print raw with lines offsets\n");
			break;
		case 'l':
			r_print_raw (core->print, core->block, len, 1);
			break;
		default:
			r_print_raw (core->print, core->block, len, 0);
		}
		break;
	case 'x': // "px"
		{
		int show_offset = r_config_get_i (core->config, "asm.offset");
		if (show_offset) {
			core->print->flags |= R_PRINT_FLAGS_HEADER;
			core->print->flags |= R_PRINT_FLAGS_OFFSET;
		} else {
			core->print->flags &= ~R_PRINT_FLAGS_OFFSET;
			core->print->flags &= ~R_PRINT_FLAGS_HEADER;
		}
		}
		switch (input[1]) {
		case '/':
			r_core_print_examine (core, input+2);
			break;
		case '?':{
			const char* help_msg[] = {
				"Usage:", "px[afoswqWqQ][f]", " # Print heXadecimal",
				"px",  "", "show hexdump",
				"px/", "", "same as x/ in gdb (help x)",
				"pxa", "", "show annotated hexdump",
				"pxe", "", "emoji hexdump! :)",
				"pxf", "", "show hexdump of current function",
				"pxl", "", "display N lines (rows) of hexdump",
				"pxo", "", "show octal dump",
				"pxq", "", "show hexadecimal quad-words dump (64bit)",
				"pxs", "", "show hexadecimal in sparse mode",
				"pxQ", "", "same as above, but one per line",
				"pxw", "", "show hexadecimal words dump (32bit)",
				"pxW", "", "same as above, but one per line",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		case 'a':
			if (len%16)
				len += 16-(len%16);
			annotated_hexdump (core, input+2, len);
			break;
		case 'o':
			r_print_hexdump (core->print, core->offset, core->block, len, 8, 1);
			break;
		case 'd':
			r_print_hexdump (core->print, core->offset,
				core->block, len, 10, 4);
			break;
		case 'w':
			r_print_hexdump (core->print, core->offset, core->block, len, 32, 4);
			break;
		case 'W':
			for (i=0; i<len; i+=4) {
				ut32 *p = (ut32*)((ut8*)core->block+i);
				r_mem_copyendian((ut8*)p, (ut8*)p, 4, !core->print->big_endian);
				r_cons_printf ("0x%08"PFMT64x" 0x%08x\n", core->offset+i, *p);
			}
			break;
		case 'r':
			{
			int ocols = core->print->cols;
			core->print->cols = 1;
			core->print->flags |= R_PRINT_FLAGS_REFS;
			r_print_hexdump (core->print, core->offset, core->block, len,
				core->assembler->bits, core->assembler->bits/8);
			core->print->flags &= ~R_PRINT_FLAGS_REFS;
			core->print->cols = ocols;
			}
			break;
		case 'q':
			r_print_hexdump (core->print, core->offset, core->block, len, 64, 8);
			break;
		case 'Q':
			for (i=0; i<len; i+=8) {
				ut64 *p = (ut64*)core->block+i;
				r_cons_printf ("0x%08"PFMT64x" 0x%016"PFMT64x"\n",
					core->offset+i, *p);
			}
			break;
		case 's':
			core->print->flags |= R_PRINT_FLAGS_SPARSE;
			r_print_hexdump (core->print, core->offset,
				core->block, len, 16, 1);
			core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SPARSE));
			break;
		case 'e':
			{
				int j;
				char emoji[] = {'\x8c','\x80','\x8c','\x82','\x8c','\x85','\x8c','\x88',
					'\x8c','\x99','\x8c','\x9e','\x8c','\x9f','\x8c','\xa0',
					'\x8c','\xb0','\x8c','\xb1','\x8c','\xb2','\x8c','\xb3',
					'\x8c','\xb4','\x8c','\xb5','\x8c','\xb7','\x8c','\xb8',
					'\x8c','\xb9','\x8c','\xba','\x8c','\xbb','\x8c','\xbc',
					'\x8c','\xbd','\x8c','\xbe','\x8c','\xbf','\x8d','\x80',
					'\x8d','\x81','\x8d','\x82','\x8d','\x83','\x8d','\x84',
					'\x8d','\x85','\x8d','\x86','\x8d','\x87','\x8d','\x88',
					'\x8d','\x89','\x8d','\x8a','\x8d','\x8b','\x8d','\x8c',
					'\x8d','\x8d','\x8d','\x8e','\x8d','\x8f','\x8d','\x90',
					'\x8d','\x91','\x8d','\x92','\x8d','\x93','\x8d','\x94',
					'\x8d','\x95','\x8d','\x96','\x8d','\x97','\x8d','\x98',
					'\x8d','\x9c','\x8d','\x9d','\x8d','\x9e','\x8d','\x9f',
					'\x8d','\xa0','\x8d','\xa1','\x8d','\xa2','\x8d','\xa3',
					'\x8d','\xa4','\x8d','\xa5','\x8d','\xa6','\x8d','\xa7',
					'\x8d','\xa8','\x8d','\xa9','\x8d','\xaa','\x8d','\xab',
					'\x8d','\xac','\x8d','\xad','\x8d','\xae','\x8d','\xaf',
					'\x8d','\xb0','\x8d','\xb1','\x8d','\xb2','\x8d','\xb3',
					'\x8d','\xb4','\x8d','\xb5','\x8d','\xb6','\x8d','\xb7',
					'\x8d','\xb8','\x8d','\xb9','\x8d','\xba','\x8d','\xbb',
					'\x8d','\xbc','\x8e','\x80','\x8e','\x81','\x8e','\x82',
					'\x8e','\x83','\x8e','\x84','\x8e','\x85','\x8e','\x88',
					'\x8e','\x89','\x8e','\x8a','\x8e','\x8b','\x8e','\x8c',
					'\x8e','\x8d','\x8e','\x8e','\x8e','\x8f','\x8e','\x92',
					'\x8e','\x93','\x8e','\xa0','\x8e','\xa1','\x8e','\xa2',
					'\x8e','\xa3','\x8e','\xa4','\x8e','\xa5','\x8e','\xa6',
					'\x8e','\xa7','\x8e','\xa8','\x8e','\xa9','\x8e','\xaa',
					'\x8e','\xab','\x8e','\xac','\x8e','\xad','\x8e','\xae',
					'\x8e','\xaf','\x8e','\xb0','\x8e','\xb1','\x8e','\xb2',
					'\x8e','\xb3','\x8e','\xb4','\x8e','\xb5','\x8e','\xb7',
					'\x8e','\xb8','\x8e','\xb9','\x8e','\xba','\x8e','\xbb',
					'\x8e','\xbd','\x8e','\xbe','\x8e','\xbf','\x8f','\x80',
					'\x8f','\x81','\x8f','\x82','\x8f','\x83','\x8f','\x84',
					'\x8f','\x86','\x8f','\x87','\x8f','\x88','\x8f','\x89',
					'\x8f','\x8a','\x90','\x80','\x90','\x81','\x90','\x82',
					'\x90','\x83','\x90','\x84','\x90','\x85','\x90','\x86',
					'\x90','\x87','\x90','\x88','\x90','\x89','\x90','\x8a',
					'\x90','\x8b','\x90','\x8c','\x90','\x8d','\x90','\x8e',
					'\x90','\x8f','\x90','\x90','\x90','\x91','\x90','\x92',
					'\x90','\x93','\x90','\x94','\x90','\x95','\x90','\x96',
					'\x90','\x97','\x90','\x98','\x90','\x99','\x90','\x9a',
					'\x90','\x9b','\x90','\x9c','\x90','\x9d','\x90','\x9e',
					'\x90','\x9f','\x90','\xa0','\x90','\xa1','\x90','\xa2',
					'\x90','\xa3','\x90','\xa4','\x90','\xa5','\x90','\xa6',
					'\x90','\xa7','\x90','\xa8','\x90','\xa9','\x90','\xaa',
					'\x90','\xab','\x90','\xac','\x90','\xad','\x90','\xae',
					'\x90','\xaf','\x90','\xb0','\x90','\xb1','\x90','\xb2',
					'\x90','\xb3','\x90','\xb4','\x90','\xb5','\x90','\xb6',
					'\x90','\xb7','\x90','\xb8','\x90','\xb9','\x90','\xba',
					'\x90','\xbb','\x90','\xbc','\x90','\xbd','\x90','\xbe',
					'\x91','\x80','\x91','\x82','\x91','\x83','\x91','\x84',
					'\x91','\x85','\x91','\x86','\x91','\x87','\x91','\x88',
					'\x91','\x89','\x91','\x8a','\x91','\x8b','\x91','\x8c',
					'\x91','\x8d','\x91','\x8e','\x91','\x8f','\x91','\x90',
					'\x91','\x91','\x91','\x92','\x91','\x93','\x91','\x94',
					'\x91','\x95','\x91','\x96','\x91','\x97','\x91','\x98',
					'\x91','\x99','\x91','\x9a','\x91','\x9b','\x91','\x9c',
					'\x91','\x9d','\x91','\x9e','\x91','\x9f','\x91','\xa0',
					'\x91','\xa1','\x91','\xa2','\x91','\xa3','\x91','\xa4',
					'\x91','\xa5','\x91','\xa6','\x91','\xa7','\x91','\xa8',
					'\x91','\xa9','\x91','\xaa','\x91','\xae','\x91','\xaf',
					'\x91','\xba','\x91','\xbb','\x91','\xbc','\x91','\xbd',
					'\x91','\xbe','\x91','\xbf','\x92','\x80','\x92','\x81',
					'\x92','\x82','\x92','\x83','\x92','\x84','\x92','\x85'};
				for (i=0; i<len; i+=16) {
					r_print_addr (core->print, core->offset+i);
					for (j=i; j<i+16; j+=1) {
						ut8 *p = (ut8*)core->block+j;
						if (j<len)
							r_cons_printf ("\xf0\x9f%c%c  ", emoji[*p*2], emoji[*p*2+1]);
						else
							r_cons_printf ("   ");
					}
					r_cons_printf (" ");
					for (j=i; j<len && j<i+16; j+=1) {
						ut8 *p = (ut8*)core->block+j;
						r_print_byte (core->print, "%c", j, *p);
					}
					r_cons_printf ("\n");
				}
			}
			break;
		case 'l':
			len = core->print->cols*len;
		default: {
				 ut64 from = r_config_get_i (core->config, "diff.from");
				 ut64 to = r_config_get_i (core->config, "diff.to");
				 if (from == to && from == 0) {
					 r_print_hexdump (core->print, core->offset,
						core->block, len, 16, 1);
				 } else {
					 r_core_print_cmp (core, from, to);
				 }
				 core->num->value = len;
			 }
			break;
		}
		break;
	case '2':
		if (input[1] == '?')
			r_cons_printf ("|Usage: p2 [number of bytes representing tiles]\n"
					"NOTE: Only full tiles will be printed\n");
		else r_print_2bpp_tiles (core->print, core->block, len/16);
		break;
	case '6':
		{
		int malen = (core->blocksize*4)+1;
		ut8 *buf = malloc (malen);
		if (!buf) break;
		memset (buf, 0, malen);
		switch (input[1]) {
		case 'd':
			if (input[2] == '?')
				r_cons_printf ("|Usage: p6d [len]    base 64 decode\n");
			else if (r_base64_decode (buf, (const char *)core->block, len))
				r_cons_printf ("%s", buf);
			else eprintf ("r_base64_decode: invalid stream\n");
			break;
		case '?':
			r_cons_printf ("|Usage: p6[ed] [len]    base 64 encode/decode\n");
			break;
		case 'e':
			if (input[2] == '?') {
				r_cons_printf ("|Usage: p6e [len]    base 64 encode\n");
				break;
			} else {
				len = len > core->blocksize ? core->blocksize : len;
				r_base64_encode (buf, core->block, len);
				r_cons_printf ("%s", buf);
			}
			break;
		default:
			r_cons_printf ("|Usage: p6[ed] [len]    base 64 encode/decode\n");
			break;
		}
		free (buf);
		}
		break;
	case '8':
		if (input[1] == '?')
			r_cons_printf("|Usage: p8 [len]          8bit hexpair list of bytes\n");
		else r_print_bytes (core->print, core->block, len, "%02x");
		break;
	case 'f':
		cmd_print_format (core, input, len);
		break;
	case 'k':
		if (input[1] == '?') {
			r_cons_printf("|Usage: pk [len]       print key in randomart\n");
		} else {
			len = len > core->blocksize ? core->blocksize : len;
			char *s = r_print_randomart (core->block, len, core->offset);
			r_cons_printf ("%s\n", s);
			free (s);
		}
		break;
	case 'K':
		if (input[1] == '?') {
			r_cons_printf("|Usage: pK [len]       print key in randomart mosaic\n");
		} else {
			len = len > core->blocksize ? core->blocksize : len;
			int w, h;
			RConsCanvas *c;
			w = r_cons_get_size (&h);
			ut64 offset0 = core->offset;
			int cols = (w/20);
			int rows = (h/12);
			int i, j;
			char *s;
			if (rows<1) rows = 1;
			c = r_cons_canvas_new (w, rows*11);
			for (i = 0; i<rows; i++) {
				for (j = 0; j<cols; j++) {
					r_cons_canvas_gotoxy (c, j*20, i*11);
					core->offset += len;
					r_core_read_at (core, core->offset, core->block, len);
					s = r_print_randomart (core->block, len, core->offset);
					r_cons_canvas_write (c, s);
					free (s);
				}
			}
			r_cons_canvas_print (c);
			r_cons_canvas_free (c);
			r_core_read_at (core, offset0, core->block, len);
			core->offset = offset0;
		}
		break;
	case 'n': // easter penis
		for (l=0; l<10; l++) {
			printf ("\r8");
			for (len=0; len<l; len++)
				printf ("=");
			printf ("D");
			r_sys_usleep (100000);
			fflush (stdout);
		}
		for (l=0; l<3; l++) {
			printf ("~");
			fflush (stdout);
			r_sys_usleep (100000);
		}
		printf ("\n");
		break;
	case 't':
		switch (input[1]) {
		case ' ':
		case '\0':
			for (l=0; l<len; l+=sizeof (time_t))
				r_print_date_unix (core->print, core->block+l, sizeof (time_t));
			break;
		case 'd':
			for (l=0; l<len; l+=4)
				r_print_date_dos (core->print, core->block+l, 4);
			break;
		case 'n':
			core->print->big_endian = !core->print->big_endian;
			for (l=0; l<len; l+=sizeof (ut64))
				r_print_date_w32 (core->print, core->block+l, sizeof (ut64));
			core->print->big_endian = !core->print->big_endian;
			break;
		case '?':{
			const char* help_msg[] = {
			"Usage: pt", "[dn]", "print timestamps",
			"pt", "", "print unix time (32 bit `cfg.big_endian`",
			"ptd","", "print dos time (32 bit `cfg.big_endian`",
			"ptn","", "print ntfs time (64 bit `cfg.big_endian`",
			NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		}
		break;
	case 'z':
		if (input[1]=='?') {
			const char *help_msg[] = {
			"Usage: pz [len]", "", "print zoomed blocks (filesize/N)",
			"e ","zoom.maxsz","max size of block",
			"e ","zoom.from","start address",
			"e ","zoom.to","end address",
			"e ","zoom.byte","specify how to calculate each byte",
			"pzp","","number of printable chars",
			"pzf","","count of flags in block",
			"pzs","","strings in range",
			"pz0","","number of bytes with value '0'",
			"pzF","","number of bytes with value 0xFF",
			"pze","","calculate entropy and expand to 0-255 range",
			"pzh","","head (first byte value); This is the default mode",
			//"WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
			NULL};
			r_core_cmd_help (core, help_msg);
		} else {
			char *oldzoom = NULL;
			ut64 maxsize = r_config_get_i (core->config, "zoom.maxsz");
			ut64 from, to;
			int oldva = core->io->va;

			from = 0;
			core->io->va = 0;
			to = r_io_size (core->io);
			from = r_config_get_i (core->config, "zoom.from");
			to = r_config_get_i (core->config, "zoom.to");
			if (input[1] && input[1] != ' ') {
				oldzoom = strdup (r_config_get (core->config, "zoom.byte"));
				if (!r_config_set (core->config, "zoom.byte", input+1)) {
					eprintf ("Invalid zoom.byte mode (%s)\n", input+1);
					free (oldzoom);
					return R_FALSE;
				}
			}
			r_print_zoom (core->print, core, printzoomcallback,
				from, to, core->blocksize, (int)maxsize);
			if (oldzoom) {
				r_config_set (core->config, "zoom.byte", oldzoom);
				free (oldzoom);
			}
			if (oldva)
				core->io->va = oldva;
		}
		break;
	default: {
		 const char* help_msg[] = {
			 "Usage:", "p[=68abcdDfiImrstuxz] [arg|len]", "",
			 "p=","[bep?] [blks]","show entropy/printable chars/chars bars",
			 "p2"," [len]","8x8 2bpp-tiles",
			 "p6","[de] [len]", "base64 decode/encode",
			 "p8"," [len]","8bit hexpair list of bytes",
			 "pa","[ed] [hex|asm]", "assemble (pa) disasm (pad) or esil (pae) from hexpairs",
			 "p","[bB] [len]","bitstream of N bytes",
			 "pc","[p] [len]","output C (or python) format",
			 "p","[dD][lf] [l]","disassemble N opcodes/bytes (see pd?)",
			 "pf","[?|.nam] [fmt]","print formatted data (pf.name, pf.name $<expr>) ",
			 "p","[iI][df] [len]", "print N instructions/bytes (f=func) (see pi? and pdi)",
			 "pm"," [magic]","print libmagic data (pm? for more information)",
			 "pr"," [len]","print N raw bytes",
			 "p","[kK] [len]","print key in randomart (K is for mosaic)",
			 "ps","[pwz] [len]","print pascal/wide/zero-terminated strings",
			 "pt","[dn?] [len]","print different timestamps",
			 "pu","[w] [len]","print N url encoded bytes (w=wide)",
			 "pv","[jh] [mode]","bar|json|histogram blocks (mode: e?search.in)",
			 "p","[xX][owq] [len]","hexdump of N bytes (o=octal, w=32bit, q=64bit)",
			 "pz"," [len]","print zoom view (see pz? for help)",
			 "pwd","","display current working directory",
			 NULL
		 };
		 r_core_cmd_help (core, help_msg);
		 }
		 break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	return 0;
}

static int cmd_hexdump(void *data, const char *input) {
	return cmd_print (data, input-1);
}

// TODO : move to r_util? .. depends on r_cons...
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int opt) {
	int show_color = p->flags & R_PRINT_FLAGS_COLOR;
	if (show_color) {
		const char *k = r_cons_singleton ()->pal.offset; // TODO etooslow. must cache
		if (invert)
			r_cons_invert (R_TRUE, R_TRUE);
		if (opt) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off-a)>>4;
			r_cons_printf ("%s%04x:%04x"Color_RESET,
				k, s&0xFFFF, a&0xFFFF);
		} else r_cons_printf ("%s0x%08"PFMT64x""Color_RESET, k, off);
		r_cons_puts (" ");
	} else {
		if (opt) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off-a)>>4;
			r_cons_printf ("%04x:%04x", s&0xFFFF, a&0xFFFF);
		} else {
			r_cons_printf ("0x%08"PFMT64x" ", off);
		}
	}
}
