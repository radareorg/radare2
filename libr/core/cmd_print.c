/* radare - LGPL - Copyright 2009-2016 - pancake */

#include "r_asm.h"
#include "r_core.h"
#include "r_config.h"
#include "r_print.h"
#include "r_types.h"
#include "r_util.h"
#include "ht.h"

#define R_CORE_MAX_DISASM (1024*1024*8)

static void cmd_pCd(RCore *core, const char *input) {
#define C(x) r_cons_canvas_##x
	int h, w = r_cons_get_size (&h);
	int colwidth = r_config_get_i (core->config, "hex.cols") * 2.5;
	int i, columns = w / colwidth;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = r_num_math (core->num, input);
	bool asm_minicols = r_config_get_i (core->config, "asm.minicols");
	char *o_ao = strdup (r_config_get (core->config, "asm.offset"));
	char *o_ab = strdup (r_config_get (core->config, "asm.bytes"));
	if (asm_minicols) {
		r_config_set (core->config, "asm.offset", "false");
		r_config_set (core->config, "asm.bytes", "false");
	}
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	r_cons_push ();
	RConsCanvas *c = r_cons_canvas_new (w, rows);
	ut64 osek = core->offset;
	c->color = r_config_get_i (core->config, "scr.color");
	r_core_block_size (core, rows * 32);
	for (i = 0; i < columns; i++) {
		(void)C(gotoxy)(c, i * (w / columns), 0);
		char *cmd = r_str_newf ("pid %d @i:%d", rows, rows * i);
		char *dis = r_core_cmd_str (core, cmd);
		C(write)(c, dis);
		free (cmd);
		free (dis);
	}
	r_core_block_size (core, obsz);
	r_core_seek (core, osek, 1);

	r_cons_pop ();
	C(print)(c);
	C(free)(c);
	if (asm_minicols) {
		r_config_set (core->config, "asm.offset", o_ao);
		r_config_set (core->config, "asm.bytes", o_ab);
	}
	free (o_ao);
	free (o_ab);
}

static char get_string_type (const ut8 *buf, ut64 len){
	ut64 needle = 0;
	int rc, i;
	char str_type = 0;

	if (!buf) {
		return '?';
	}
	while (needle < len){
		rc = r_utf8_decode (buf+needle, len-needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (needle+rc+2 < len &&
			buf[needle+rc+0] == 0x00 &&
			buf[needle+rc+1] == 0x00 &&
			buf[needle+rc+2] == 0x00) {
			str_type = 'w';
		} else {
			str_type = 'a';
		}
		for (rc = i = 0; needle < len ; i+= rc){
			RRune r;
			if (str_type == 'w'){
				if (needle+1 < len){
					r = buf[needle+1] << 8 | buf[needle];
					rc = 2;
				} else {
					break;
				}
			} else {
				rc = r_utf8_decode (buf+needle, len-needle, &r);
				if(rc > 1) str_type = 'u';
			}
			/*Invalid sequence detected*/
			if (!rc) {
				needle++;
				break;
			}
			needle += rc;
		}
	}
	return str_type;
}

static void cmd_print_eq_dict(RCore *core, int bsz) {
	int i;
	int min = 0;
	int max = 0;
	int dict = 0;
	int range = 0;
	ut8 buf[0xff+1];

	for (i=0; i<0xff; i++) {
		buf[i] = 0;
	}
	for (i=0; i<bsz; i++) {
		buf[core->block[i]] = 1;
	}
	for (i=0; i<0xff; i++) {
		if (buf[i]) {
			if (min == 0)
				min = i;
			max = i;
			dict++;
		}
	}
	range = max - min;
	r_cons_printf ("min:   %d  0x%x\n", min, min);
	r_cons_printf ("max:   %d  0x%x\n", max, max);
	r_cons_printf ("dict:  %d  0x%x\n", dict, dict);
	r_cons_printf ("range: %d  0x%x\n", range, range);
	r_cons_printf ("block: %d  0x%x\n", bsz, bsz);
}

R_API void r_core_set_asm_configs(RCore *core, char *arch, ut32 bits, int segoff){
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
			r_core_print_disasm_json (core, core->offset, buf, bsize, 0);
			free (buf);
		} else {
			eprintf ("cannot allocate %d bytes\n", bsize);
		}
	}
	r_cons_newline ();
}

static void cmd_pdj (RCore *core, const char *arg) {
	int nblines = r_num_math (core->num, arg);
	r_core_print_disasm_json (core, core->offset, core->block, core->blocksize, nblines);
	r_cons_newline ();
}

static int process_input(RCore *core, const char *input, ut64* blocksize, char **asm_arch, ut32 *bits) {
	// input: start of the input string e.g. after the command symbols have been consumed
	// size: blocksize if present, otherwise -1
	// asm_arch: asm_arch to interpret as if present and valid, otherwise NULL;
	// bits: bits to use if present, otherwise -1

	int result = false;
	char *input_one = NULL, *input_two = NULL, *input_three = NULL;
	char *str_clone = NULL, *ptr_str_clone = NULL, *trimmed_clone = NULL;

	if (!input || !blocksize || !asm_arch || !bits) {
		return false;
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
		result = true;

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
			*bits = r_num_is_valid_input (core->num, input_two) ? r_num_get_input_value (core->num, input_two): -1;
			*asm_arch = r_asm_is_valid (core->assembler, input_two) ? strdup (input_two) : NULL;
		}

		result = true;
	} else if (input_one) {
		*blocksize = r_num_is_valid_input (core->num, input_one) ? r_num_get_input_value (core->num, input_one): 0;
		if (!r_num_is_valid_input (core->num, input_one) ) {
			// input_one can only be one other thing
			if (r_str_contains_macro (input_one))
				r_str_truncate_cmd (input_one);
			*asm_arch = r_asm_is_valid (core->assembler, input_one) ? strdup (input_one) : NULL;
		}
		result = true;
	}
	free (str_clone);
	return result;
}

/* This function is not necessary anymore, but it's kept for discussion */
R_API int r_core_process_input_pade(RCore *core, const char *input, char** hex, char **asm_arch, ut32 *bits) {
	// input: start of the input string e.g. after the command symbols have been consumed
	// size: hex if present, otherwise -1
	// asm_arch: asm_arch to interpret as if present and valid, otherwise NULL;
	// bits: bits to use if present, otherwise -1

	int result = false;
	char *input_one = NULL, *input_two = NULL, *input_three = NULL;
	char *str_clone = NULL,
		 *trimmed_clone = NULL;

	if (!input || !hex || !asm_arch || !bits) {
		return false;
	}

	str_clone = strdup (input);
	trimmed_clone = r_str_trim_head_tail (str_clone);

	input_one = trimmed_clone;

#if 0
	char *ptr_str_clone = NULL;
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
#endif

	// command formats
	// <hex> <arch> <bits>
	// <hex> <arch>
	// <hex> <bits>
	// <hex>

	// initialize
	*hex = *asm_arch = NULL;
	*bits = -1;

	if (input_one && input_two && input_three) {
		// <size> <arch> <bits>
		*hex = input_one;
		*asm_arch = r_asm_is_valid (core->assembler, input_two) ? strdup (input_two) : NULL;
		*bits = r_num_get_input_value (core->num, input_three);
		result = true;

	} else if (input_one && input_two) {
		*hex = input_one;
		if (r_str_contains_macro (input_two) ){
			r_str_truncate_cmd (input_two);
		}
		*bits = r_num_is_valid_input (core->num, input_two) ? r_num_get_input_value (core->num, input_two): -1;
		*asm_arch = r_asm_is_valid (core->assembler, input_two) ? strdup (input_two) : NULL;
		result = true;
	} else if (input_one) {
		*hex = input_one;
		result = true;
	} else {
		free (input_one);
	}
	return result;
}

static void print_format_help(RCore *core) {
	const char* help_msg[] = {
	"pf:", "pf[.k[.f[=v]]|[ v]]|[n]|[0][ [sz] fmt] [a0 a1 ...]", "",
	"Commands:","","",
	"pf", "?", "Show this help",
	"pf", "??", "Format characters",
	"pf", "???", "pf usage examples",
	"pf", " xsi foo bar cow", "format named hex str and int (see `pf??`)",
	"pf.", "", "List all formats",
	"pf?", "fmt_name", "Show format of that stored one",
	"pfs", " fmt_name", "Print the size of the format in bytes",
	"pfo", "", "List all format files",
	"pfo", " elf32", "Load the elf32 format definition file",
	"pf.", "fmt_name", "Run stored format",
	"pf.", "fmt_name.field_name", "Show specific field inside format",
	"pf.", "fmt_name.size=33", "Set new value for the size field in obj",
	"pfj.", "fmt_name", "Print format in JSON",
	"pfv.", "fmt_name", "Print the value(s) only. Useful for one-liners",
	"pf*.", "fmt_name", "Display flag commands",
	"pfd.", "fmt_name", "Display graphviz commands",
	NULL};
	r_core_cmd_help (core, help_msg);
}

static void print_format_help_help(RCore *core) {
	const char* help_msg[] = {
	"pf:", "pf[.k[.f[=v]]|[ v]]|[n]|[0][ [sz] fmt] [a0 a1 ...]", "",
	"Format:", "", "",
	" ", "b", "byte (unsigned)",
	" ", "B", "resolve enum bitfield (see t?)",
	" ", "c", "char (signed byte)",
	" ", "d", "0x%%08x hexadecimal value (4 bytes)",
	" ", "D", "disassemble one opcode",
	" ", "e", "temporally swap endian",
	" ", "E", "resolve enum name (see t?)",
	" ", "f", "float value (4 bytes)",
	" ", "i", "%%i integer value (4 bytes)",
	" ", "n", "next char specifies size of signed value (1, 2, 4 or 8 byte(s))",
	" ", "N", "next char specifies size of unsigned value (1, 2, 4 or 8 byte(s))",
	" ", "o", "0x%%08o octal value (4 byte)",
	" ", "p", "pointer reference (2, 4 or 8 bytes)",
	" ", "q", "quadword (8 bytes)",
	" ", "r", "CPU register `pf r (eax)plop`",
	" ", "s", "32bit pointer to string (4 bytes)",
	" ", "S", "64bit pointer to string (8 bytes)",
	" ", "t", "UNIX timestamp (4 bytes)",
	" ", "T", "show Ten first bytes of buffer",
	" ", "u", "uleb128 (variable length)",
	" ", "w", "word (2 bytes unsigned short in hex)",
	" ", "x", "0x%%08x hex value and flag (fd @ addr)",
	" ", "X", "show formatted hexpairs",
	" ", "z", "\\0 terminated string",
	" ", "Z", "\\0 terminated wide string",
	" ", "?", "data structure `pf ? (struct_name)example_name`",
	" ", "*", "next char is pointer (honors asm.bits)",
	" ", "+", "toggle show flags for each offset",
	" ", ":", "skip 4 bytes",
	" ", ".", "skip 1 byte",
	NULL};
	r_core_cmd_help (core, help_msg);
}

static void print_format_help_help_help(RCore *core) {
	const char* help_msg[] = {
	"pf:", "pf[.k[.f[=v]]|[ v]]|[n]|[0][ [sz] fmt] [a0 a1 ...]", "",
	"Examples:","","",
	"pf", " B (BitFldType)arg_name`", "bitfield type",
	"pf", " E (EnumType)arg_name`", "enum type",
	"pf.", "obj xxdz prev next size name", "Define the obj format as xxdz",
	"pf",  " obj=xxdz prev next size name", "Same as above",
	"pf", " iwq foo bar troll", "Print the iwq format with foo, bar, troll as the respective names for the fields",
	"pf", " 0iwq foo bar troll", "Same as above, but considered as a union (all fields at offset 0)",
	"pf.", "plop ? (troll)mystruct", "Use structure troll previously defined",
	"pf", " 10xiz pointer length string", "Print a size 10 array of the xiz struct with its field names",
	"pf", " {integer}? (bifc)", "Print integer times the following format (bifc)",
	"pf", " [4]w[7]i", "Print an array of 4 words and then an array of 7 integers",
	"pf", " ic...?i foo bar \"(pf xw yo foo)troll\" yo", "Print nested anonymous structres",
	"pf", "n2", "print signed short (2 bytes) value. Use N insted of n for printing unsigned values",
	NULL};
	r_core_cmd_help (core, help_msg);
}

static void print_format_help_help_help_help(RCore *core) {
	const char* help_msg[] = {
	"    STAHP IT!!!", "", "",
	NULL};
	r_core_cmd_help (core, help_msg);
}

static void cmd_print_format(RCore *core, const char *_input, int len) {
	char *input;
	int mode = R_PRINT_MUSTSEE;
	switch (_input[1]) {
	case '*':
		_input++;
		mode = R_PRINT_SEEFLAGS;
		break;
	case 'd':
		_input++;
		mode = R_PRINT_DOT;
		break;
	case 'j':
		_input++;
		mode = R_PRINT_JSON;
		break;
	case 'v':
		_input++;
		mode = R_PRINT_VALUE | R_PRINT_MUSTSEE;
		break;
	case 's':
		{
		const char *val = NULL;
		_input+=2;
		if (*_input == '.') {
			_input++;
			val = r_strht_get (core->print->formats, _input);
			if (val != NULL)
				r_cons_printf ("%d bytes\n", r_print_format_struct_size (val, core->print, mode));
			else {
				eprintf ("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') {
				_input++;
			}
			if (*_input) {
				r_cons_printf ("%d bytes\n", r_print_format_struct_size (_input, core->print, mode));
			} else {
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
			if (*_input == '?') {
				_input++;
				if (_input && *_input == '?') {
					_input++;
					if (_input && *_input == '?') {
						print_format_help_help_help_help (core);
					} else {
						print_format_help_help_help (core);
					}
				} else {
					print_format_help_help (core);
				}
			} else {
				RListIter *iter;
				RStrHT *sht = core->print->formats;
				int *i;
				r_list_foreach (sht->ls, iter, i) {
					int idx = ((int)(size_t)i)-1;
					const char *key = r_strpool_get (sht->sp, idx);
					if (!strcmp (_input, key)) {
						const char *val = r_strht_get (core->print->formats, key);
						r_cons_println (val);
					}
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
					if (*fn && *fn != '.') {
						r_cons_println (fn);
					}
				}
				r_list_free (files);
				free (home);
			}
			files = r_sys_dir (R2_DATDIR"/radare2/"R2_VERSION"/format/");
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.') {
					r_cons_println (fn);
				}
			}
			r_list_free (files);
		}
		free (input);
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

	int listFormats = 0;
	if (input[1]=='.')
		listFormats = 1;
	if (!strcmp (input, "*") && mode == R_PRINT_SEEFLAGS)
		listFormats = 1;

	core->print->reg = core->dbg->reg;
	core->print->get_register = r_reg_get;
	core->print->get_register_value = r_reg_get_value;

	int o_blocksize = core->blocksize;

	if (listFormats) {
		core->print->num = core->num;
		/* print all stored format */
		if (input[1]==0 || input[2]=='\0') {
			RListIter *iter;
			RStrHT *sht = core->print->formats;
			int *i;
			r_list_foreach (sht->ls, iter, i) {
				int idx = ((int)(size_t)i)-1;
				const char *key = r_strpool_get (sht->sp, idx);
				const char *val = r_strht_get (core->print->formats, key);
				r_cons_printf ("pf.%s %s\n", key, val);
			}
			/* delete a format */
		} else if (input[1] && input[2]=='-') {
			if (input[2] && input[3]) r_strht_del (core->print->formats, input+3);
			else r_strht_clear (core->print->formats);
		} else {
			char *name = strdup (input+(input[1]?2:1));
			char *space = strchr (name, ' ');
			char *eq = strchr (name, '=');
			char *dot = strchr (name, '.');

			if (eq && !dot) {
				*eq = ' ';
				space = eq;
				eq = NULL;
			}

			/* store a new format */
			if (space && (!eq || space < eq)) {
				//char *fields = NULL;
				*space++ = 0;
				// fields = strchr (space, ' ');
				if (strchr (name, '.') != NULL) {// || (fields != NULL && strchr(fields, '.') != NULL)) // if anon struct, then field can have '.'
					eprintf ("Struct or fields name can not contain dot symbol (.)\n");
				} else {
					r_strht_set (core->print->formats, name, space);
				}
				free (name);
				free (input);
				return;
			}

			if (!strchr (name, '.') && !r_strht_get (core->print->formats, name)) {
				eprintf ("Cannot find '%s' format.\n", name);
				free (name);
				free (input);
				return;
			}

			/* Load format from name into fmt to get the size */
			/* This make sure the whole structure will be printed */
			const char *fmt = NULL;
			fmt = r_strht_get (core->print->formats, name);
			if (fmt != NULL) {
				int size = r_print_format_struct_size (fmt, core->print, mode)+10;
				if (size > core->blocksize)
					r_core_block_size (core, size);
			}
			/* display a format */
			if (dot) {
				*dot++ = 0;
				eq = strchr (dot, '=');
				if (eq) { // Write mode (pf.field=value)
					*eq++ = 0;
					mode = R_PRINT_MUSTSET;
					r_print_format (core->print, core->offset,
							core->block, core->blocksize, name, mode, eq, dot);
				} else {
					r_print_format (core->print, core->offset,
							core->block, core->blocksize, name, mode, NULL, dot);
				}
			} else {
				r_print_format (core->print, core->offset,
						core->block, core->blocksize, name, mode, NULL, NULL);
			}
			free (name);
		}
	} else {
		/* This make sure the structure will be printed entirely */
		char *fmt = input+1;
		int size = 0;
		while (*fmt && iswhitechar (*fmt)) fmt++;
		size = r_print_format_struct_size (fmt, core->print, mode)+10;
		if (size > core->blocksize)
			r_core_block_size (core, size);
		r_print_format (core->print, core->offset,
			core->block, core->blocksize, fmt, mode, NULL, NULL);
	}
	free (input);
	r_core_block_size (core, o_blocksize);
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
	bool marks = false, setcolor = true, hascolor = false;
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
	int html = r_config_get_i (core->config, "scr.html");
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
		hascolor = false;

		if (usecolor) append (ebytes, core->cons->pal.offset);
		ebytes += sprintf (ebytes, "0x%08"PFMT64x, addr);
		if (usecolor) append (ebytes, Color_RESET);
		append (ebytes, (col==1)?" |":"  ");

		for (j=0; j<nb_cols; j++) {
			setcolor = true;
			free (note[j]);
			note[j] = NULL;

			// collect comments
			comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr+j);
			if (comment) {
				comment = r_str_prefix (comment, ";");
				note[j] = comment;
				marks = true;
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
				marks = true;
				color_idx++;
				color_idx %= R_CONS_PALETTE_LIST_SIZE;
				current_flag = flag;
			} else {
				// Are we past the current flag?
				if (current_flag && addr+j > (current_flag->offset + current_flag->size)){
					setcolor = false;
					current_flag = NULL;
				}
				// Turn colour off if we're at the end of the current flag
				if (fend == UT64_MAX || fend <= addr + j)
					setcolor = false;
			}
			if (setcolor && !hascolor) {
				hascolor = true;
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
					if (html) {
						append (ebytes, "[");
					} else {
						append (ebytes, Color_INVERT);
					}
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
						if (html) {
							append (ebytes, "[");
							append (echars, "[");
						} else {
							append (echars, Color_INVERT);
							append (ebytes, Color_INVERT);
						}
					}
				} else {
					if (here >= low && here <max) {
						if (html) {
							append (ebytes, "[");
							append (echars, "[");
						} else {
							append (ebytes, Color_INVERT);
							append (echars, Color_INVERT);
						}
					}
				}
			}
			sprintf (ebytes, "%02x", ch);
			ebytes += strlen (ebytes);
			sprintf (echars, "%c", IS_PRINTABLE (ch)?ch:'.');
			echars++;
			if (core->print->cur_enabled && max == here) {
				if (!html) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				hascolor = false;
			}

			if (j < (nb_cols-1) && (j%2))
				append (ebytes, " ");

			if (fend != UT64_MAX && fend == addr+j+1) {
				if (!html) {
					append (ebytes, Color_RESET);
					append (echars, Color_RESET);
				}
				fend = UT64_MAX;
				hascolor = false;
			}

		}
		if (!html) {
			append (ebytes, Color_RESET);
			append (echars, Color_RESET);
		}
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
			marks = false;
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
		for (j = 0; j < size; j++) {
			if (IS_PRINTABLE (bufz[j])) {
				ret++;
			}
		}
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
	int col = core->cons->columns > 123;
	ut8 *b = malloc (core->blocksize);
	ut64 addr = core->offset;
	memset (b, 0xff, core->blocksize);
	delta = addr - from;
	r_core_read_at (core, to + delta, b, core->blocksize);
	r_print_hexdiff (core->print, core->offset, core->block,
		to + delta, b, core->blocksize, col);
	free (b);
}

static int pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt) {
	int show_offset = r_config_get_i (core->config, "asm.offset");
	int show_bytes = r_config_get_i (core->config, "asm.bytes");
	int decode = r_config_get_i (core->config, "asm.decode");
	int filter = r_config_get_i (core->config, "asm.filter");
	int show_color = r_config_get_i (core->config, "scr.color");
	bool asm_ucase = r_config_get_i (core->config, "asm.ucase");
	int esil = r_config_get_i (core->config, "asm.esil");
	int flags = r_config_get_i (core->config, "asm.flags");
	int i=0, j, ret, err = 0;
	ut64 old_offset = core->offset;
	RAsmOp asmop;
	#define PAL(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
	const char *color_reg = PAL(reg): Color_YELLOW;
	const char *color_num = PAL(num): Color_CYAN;

	if (fmt == 'e') {
		show_bytes = 0;
		decode = 1;
	}
	if (!nb_opcodes && !nb_bytes) return 0;

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
			ut64 start;
			/* Backward disassembly of `ilen` opcodes
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;
			if (r_core_prevop_addr (core, core->offset, nb_opcodes, &start)) {
				// We have some anal_info.
				nb_bytes = core->offset - start;
			} else {
				// anal ignorance.
				r_core_asm_bwdis_len (core, &nb_bytes, &core->offset,
						nb_opcodes);
			}
			r_core_read_at (core, core->offset, core->block, nb_bytes);
		} else {
			// workaround for the `for` loop below
			nb_bytes = core->blocksize;
		}
	}

	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	if (core->anal && core->anal->cur && core->anal->cur->reset_counter) {
		core->anal->cur->reset_counter (core->anal, core->offset);
	}

	int len = (nb_opcodes + nb_bytes) * 5;
	if (core->fixedblock) {
		len = core->blocksize;
	} else {
		if (len > core->blocksize) {
			r_core_block_size (core, len);
			r_core_block_read (core);
		}
	}
	r_cons_break (NULL, NULL);
#define isTheEnd (nb_opcodes? nb_bytes? (j<nb_opcodes && i<nb_bytes) : j<nb_opcodes: i<nb_bytes)
	for (i=j=0; isTheEnd; j++) {
		RFlagItem *item;
		if (r_cons_singleton ()->breaked) {
			err = 1;
			break;
		}
		r_asm_set_pc (core->assembler, core->offset+i);
		ret = r_asm_disassemble (core->assembler, &asmop, core->block + i,
			core->blocksize - i);
		if (flags) {
			if (fmt != 'e') { // pie
				item = r_flag_get_i (core->flags, core->offset + i);
				if (item) {
					if (show_offset)
						r_cons_printf ("0x%08"PFMT64x"  ", core->offset + i);
					r_cons_printf ("  %s:\n", item->name);
				}
			} // do not show flags in pie
		}
		if (show_offset) {
			const int show_offseg = (core->print->flags & R_PRINT_FLAGS_SEGOFF) != 0;
			const int show_offdec = (core->print->flags & R_PRINT_FLAGS_ADDRDEC) != 0;
			ut64 at = core->offset + i;
			r_print_offset (core->print, at, 0, show_offseg, show_offdec, 0, NULL);
		}
		// r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ret < 1) {
			err = 1;
			ret = asmop.size;
			if (ret<1) ret = 1;
			if (show_bytes) {
				r_cons_printf ("%14s%02x  ", "", core->block[i]);
			}
			r_cons_println ("invalid"); //???");
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
					char *esil = (R_STRBUF_SAFEGET (&analop.esil));
					r_cons_println (esil);
				} else {
					if (decode) {
						opstr = (tmpopstr)? tmpopstr: (asmop.buf_asm);
					} else if (esil) {
						opstr = (R_STRBUF_SAFEGET (&analop.esil));
					}
					r_cons_println (opstr);
				}
			} else {
				if (filter) {
					char opstr[128] = {0};
					if (asm_ucase) {
						r_str_case (asmop.buf_asm, 1);
					}
					if (show_color) {
						RAnalOp aop = {0};
						char *asm_str = r_print_colorize_opcode (asmop.buf_asm, color_reg, color_num);
						r_anal_op (core->anal, &aop, core->offset+i,
							core->block+i, core->blocksize-i);
						r_parse_filter (core->parser, core->flags,
							asm_str, opstr, sizeof (opstr)-1, core->print->big_endian);
						r_cons_printf ("%s%s"Color_RESET"\n", r_print_color_op_type (core->print, aop.type), opstr);
					} else {
						r_parse_filter (core->parser, core->flags,
							asmop.buf_asm, opstr, sizeof (opstr)-1, core->print->big_endian);
						r_cons_println (opstr);
					}
				} else {
					if (show_color) {
						RAnalOp aop;
						r_anal_op (core->anal, &aop, core->offset+i,
							core->block+i, core->blocksize-i);
						r_cons_printf ("%s%s"Color_RESET"\n",
							r_print_color_op_type (core->print, aop.type),
								  asmop.buf_asm);
					} else {
						r_cons_println (asmop.buf_asm);
					}
				}
			}
		}
		i += ret;
#if 0
		if ((nb_bytes && (nb_bytes <= i)) || (i >= core->blocksize))
			break;
#endif
	}
	r_cons_break_end ();
	core->offset = old_offset;
	return err;
}

static void cmd_print_pwn(const RCore* core) {
	r_cons_printf ("easter egg license has expired\n");
}

static int cmd_print_pxA(RCore *core, int len, const char *data) {
	RConsPalette *pal = &core->cons->pal;
	int show_offset = true;
	int cols = r_config_get_i (core->config, "hex.cols");
	int show_color = r_config_get_i (core->config, "scr.color");
	int onechar = r_config_get_i (core->config, "hex.onechar");
	int bgcolor_in_heap = false;
	bool show_cursor = core->print->cur_enabled;
	char buf[2];
	char *bgcolor, *fgcolor, *text;
	ut64 i, c, oi;
	RAnalOp op;

	if (len < 0 || len > core->blocksize) {
		eprintf ("Invalid length\n");
		return 0;
	}
	if (onechar) {
		cols *= 4;
	} else {
		cols *= 2;
	}
	if (show_offset) {
		char offstr[128];
		snprintf (offstr, sizeof(offstr),
			"0x%08"PFMT64x"  ", core->offset);
		if (strlen (offstr)>12)
			cols -= ((strlen(offstr)-12)*2);
	}
	for (oi = i = c = 0; i< len; c++) {
		if (i && (cols != 0) && !(c % cols)) {
			show_offset = true;
			r_cons_printf ("  %d\n", i-oi);
			oi = i;
		}
		if (show_offset) {
			r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
			show_offset = false;
		}
		if (bgcolor_in_heap) {
			free (bgcolor);
			bgcolor_in_heap = false;
		}
		bgcolor = Color_BGBLACK;
		fgcolor = Color_WHITE;
		text = NULL;
		if (!r_anal_op (core->anal, &op, core->offset+i, core->block+i, len-i)) {
			op.type = 0;
			bgcolor = Color_BGRED;
			op.size = 1;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_LEA:
		case R_ANAL_OP_TYPE_MOV:
		case R_ANAL_OP_TYPE_CAST:
		case R_ANAL_OP_TYPE_LENGTH:
		case R_ANAL_OP_TYPE_CMOV:
			text = "mv";
			bgcolor = pal->mov;
			fgcolor = Color_YELLOW;
			break;
		case R_ANAL_OP_TYPE_PUSH:
		case R_ANAL_OP_TYPE_UPUSH:
			bgcolor = pal->push;
			fgcolor = Color_WHITE;
			text = "->";
			break;
		case R_ANAL_OP_TYPE_IO:
			bgcolor = pal->swi;
			fgcolor = Color_WHITE;
			text = "io";
			break;
		case R_ANAL_OP_TYPE_TRAP:
		case R_ANAL_OP_TYPE_SWI:
		case R_ANAL_OP_TYPE_NEW:
			//bgcolor = Color_BGRED;
			bgcolor = pal->trap; //r_cons_swap_ground (pal->trap);
			fgcolor = Color_WHITE;
			text = "$$";
			break;
		case R_ANAL_OP_TYPE_POP:
			text = "<-";
			bgcolor = r_cons_swap_ground (pal->pop);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			break;
		case R_ANAL_OP_TYPE_NOP:
			fgcolor = Color_WHITE;
			bgcolor = r_cons_swap_ground (pal->nop);
			bgcolor_in_heap = true;
			text = "..";
			break;
		case R_ANAL_OP_TYPE_MUL:
			fgcolor = Color_BLACK;
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			text = "_*";
			break;
		case R_ANAL_OP_TYPE_DIV:
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_/";
			break;
		case R_ANAL_OP_TYPE_AND:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_&";
			break;
		case R_ANAL_OP_TYPE_XOR:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_^";
			break;
		case R_ANAL_OP_TYPE_OR:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_|";
			break;
		case R_ANAL_OP_TYPE_SHR:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = ">>";
			break;
		case R_ANAL_OP_TYPE_SHL:
			bgcolor = r_cons_swap_ground (pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "<<";
			break;
		case R_ANAL_OP_TYPE_SUB:
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "--";
			break;
		case R_ANAL_OP_TYPE_ADD:
			bgcolor = r_cons_swap_ground (pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "++";
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_IRJMP:
		case R_ANAL_OP_TYPE_MJMP:
			bgcolor = r_cons_swap_ground (pal->jmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_J";
			break;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_UCJMP:
			bgcolor = r_cons_swap_ground (pal->cjmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "cJ";
			break;
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_IRCALL:
		case R_ANAL_OP_TYPE_UCCALL:
			bgcolor = r_cons_swap_ground (pal->call);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "_C";
			break;
		case R_ANAL_OP_TYPE_ACMP:
		case R_ANAL_OP_TYPE_CMP:
			bgcolor = r_cons_swap_ground (pal->cmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "==";
			break;
		case R_ANAL_OP_TYPE_RET:
			bgcolor = r_cons_swap_ground (pal->ret);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "_R";
			break;
		case -1:
		case R_ANAL_OP_TYPE_ILL:
		case R_ANAL_OP_TYPE_UNK:
			bgcolor = r_cons_swap_ground (pal->invalid);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "XX";
			break;
#if 0
		default:
			color = Color_BGCYAN;
			fgcolor = Color_BLACK;
			break;
#endif
		}
		int opsz = R_MAX (op.size, 1);
		if (show_cursor) {
			if (core->print->cur >=i && core->print->cur < i+opsz)
				r_cons_invert (1, 1);
		}
		if (onechar) {
			if (text) {
				if (text[0] == '_' || text[0] == '.')
					buf[0] = text[1];
				else buf[0] = text[0];
			} else buf[0] = '.';
			buf[1] = 0;
			text = buf;
		}
		if (show_color) {
			if (!text) text = "  ";
			r_cons_printf ("%s%s%s\x1b[0m", bgcolor, fgcolor, text);
		} else {
			if (text) {
				r_cons_print (text);
			} else {
				r_cons_print ("  ");
			}
		}
		if (show_cursor) {
			if (core->print->cur >=i && core->print->cur < i+opsz)
				r_cons_invert (0, 1);
		}
		i += opsz;
	}
	r_cons_printf ("  %d\n", i-oi);
	if (bgcolor_in_heap) free (bgcolor);

	return true;
}

static void printraw (RCore *core, int len, int mode) {
	int obsz = core->blocksize;
	int restore_obsz = 0;
	if (len != obsz) {
		if (!r_core_block_size (core, len)) {
			len = core->blocksize;
		} else {
			restore_obsz = 1;
		}
	}
	r_print_raw (core->print, core->offset, core->block, len, mode);
	if (restore_obsz) {
		(void)r_core_block_size (core, obsz);
	}
	core->cons->newline = true;
}


static void _handle_call(RCore *core, char * line, char **str) {
	if (!core || !core->assembler || !core->assembler->cur) {
		*str = NULL;
		return;
	}
	if (strstr (core->assembler->cur->arch, "x86")) {
		*str = strstr (line , "call ");
	} else if (strstr (core->assembler->cur->arch, "arm")) {
		*str = strstr (line, " b ");
		if (*str && strstr (*str, " 0x")) {
			/*
			 * avoid treating branches to
			 * non-symbols as calls
			 */
			*str = NULL;
		}
		if (!*str) {
			*str = strstr (line, "bl ");
		}
		if (!*str) {
			*str = strstr (line, "bx ");
		}
	}
}

// TODO: this is just a PoC, the disasm loop should be rewritten
// TODO: this is based on string matching, it should be written upon RAnalOp to know
// when we have a call and such
static void disasm_strings(RCore *core, const char *input, RAnalFunction *fcn) {
#define MYPAL(x) (core->cons && core->cons->pal.x)? core->cons->pal.x: ""
	const char *linecolor = NULL;
	char *ox, *qo, *string = NULL;
	char *line, *s, *str, *string2 = NULL;
	int i, count, use_color = r_config_get_i (core->config, "scr.color");
	bool is_free_pending = false;

	r_config_set_i (core->config, "scr.color", 0);
	if (!strncmp (input, "dsf", 3)) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
		if (fcn) {
			line = s = r_core_cmd_str (core, "pdr");
		} else {
			eprintf ("Cannot find function.\n");
			r_config_set_i (core->config, "scr.color", use_color);
			return;
		}
	} else if (!strncmp (input, "ds ", 3)) {
		char *cmd = r_str_newf ("pD %s", input+3);
		line = s = r_core_cmd_strf (core, cmd);
		free (cmd);
	} else {
		line = s = r_core_cmd_str (core, "pd");
	}
	r_config_set_i (core->config, "scr.color", use_color);
	count = r_str_split (s, '\n');
	if (!line || !*line || count < 1) {
		free (s);
		return;
	}
	for (i = 0; i < count; i++) {
		ut64 addr = UT64_MAX;
		ox = strstr (line, "0x");
		qo = strstr (line, "\"");
		R_FREE (string);
		if (ox) {
			addr = r_num_get (NULL, ox);
		}
		if (qo) {
			char *qoe = strchr (qo + 1, '"');
			if (qoe) {
				int len = qoe - qo - 1;
				if (len > 2) {
					string = r_str_ndup (qo, len+2);
				}
				linecolor = MYPAL (comment);
			}
		}
		ox = strstr (line, "; 0x");
		if (!ox) {
			ox = strstr (line, "@ 0x");
		}
		if (ox) {
			char *qoe = strchr (ox + 3, ' ');
			if (!qoe) {
				qoe = strchr (ox + 3, '\x1b');
			}
			int len = qoe? qoe - ox: strlen (ox + 3);
			string2 = r_str_ndup (ox + 2, len - 1);
			if (r_num_get (NULL, string2) < 0x100) {
				R_FREE (string2);
			}
		}
		str = strstr (line, " str.");
		if (str) {
			char *qoe = NULL;
			if (!qoe) {
				qoe = strchr (str + 1, '\x1b');
			}
			if (!qoe) {
				qoe = strchr (str + 1, ';');
			}
			if (!qoe) {
				qoe = strchr (str + 1, ' ');
			}
			if (qoe) {
				string2 = r_str_ndup (str + 1, qoe - str - 1);
			} else {
				string2 = strdup (str + 1);
			}
			if (!string && string2) {
				string = string2;
				string2 = NULL;
			}
		}
		if (string2) {
			R_FREE (string2);
		}
		_handle_call (core, line, &str);
		if (!str) {
			str = strstr (line, "sym.");
			if (!str) {
				str = strstr (line, "fcn.");
			}
		}
		if (str) {
			char *qoe = strstr (str, ";");
			if (qoe) {
				//XXX str leaks
				str = r_str_ndup (str, qoe - str);
				is_free_pending = true;
			}
		}
		if (str) {
			string2 = strdup (str);
			linecolor = MYPAL(call);
		}
		if (!string && string2) {
			string = string2;
			string2 = NULL;
		}

		if (strstr (line, "XREF")) {
			addr = UT64_MAX;
		}
		if (addr != UT64_MAX) {
			const char *str = NULL;
			if (fcn) {
				bool label = false;
				/* show labels, basic blocks and (conditional) branches */
				RAnalBlock *bb;
				RListIter *iter;
				r_list_foreach (fcn->bbs, iter, bb) {
					if (addr == bb->jump) {
						r_cons_printf ("%s0x%08"PFMT64x":\n", use_color? Color_YELLOW:"", addr);
						label = true;
						break;
					}
				}
				if (!label && strstr (line, "->")) {
					r_cons_printf ("%s0x%08"PFMT64x":\n", use_color? Color_YELLOW:"", addr);
				}
				if (strstr (line, "=<")) {
					r_list_foreach (fcn->bbs, iter, bb) {
						if (addr >= bb->addr && addr < bb->addr + bb->size) {
							const char *op;
							if (use_color) {
								op = (bb->fail == UT64_MAX)? Color_GREEN"jmp": "cjmp";
							} else {
								op = (bb->fail == UT64_MAX)? "jmp": "cjmp";
							}
							r_cons_printf ("%s0x%08"PFMT64x" %s 0x%08"PFMT64x"%s\n",
									use_color? MYPAL(offset):"", addr, op,
									bb->jump, use_color?Color_RESET:"");
							break;
						}
					}
				}
			}
			if (string && *string) {
				if (string && !strncmp (string, "0x", 2)) {
					str = string;
				}
				if (string2 && !strncmp (string2, "0x", 2)) {
					str = string2;
				}
				ut64 ptr = r_num_math (NULL, str);
				RFlagItem *flag = NULL;
				if (str) {
					flag = r_flag_get_i2 (core->flags, ptr);
				}
				if (!flag) {
					if (string && !strncmp (string, "0x", 2)) {
						R_FREE (string);
					}
					if (string2 && !strncmp (string2, "0x", 2)) {
						R_FREE (string2);
					}
				}
				if (string) {
					string = r_str_chop (string);
					string2 = r_str_chop (string2);
					if (use_color) {
						r_cons_printf ("%s0x%08"PFMT64x"%s %s%s%s%s%s%s%s\n",
								MYPAL(offset), addr, Color_RESET,
								linecolor? linecolor: "",
								string2? string2: "", string2?" ":"", string,
								flag?" ":"", flag?flag->name:"", Color_RESET);
					} else {
						r_cons_printf ("0x%08"PFMT64x" %s%s%s%s%s\n", addr,
								string2? string2 :"", string2? " ":"", string,
								flag?" ":"", flag?flag->name:"");
					}
				}
			}
		}
		line = line + strlen (line) + 1;
	}
	//r_cons_printf ("%s", s);
	free (string2);
	free (string);
	free (s);
	if (is_free_pending) {
		free (str);
	}
}

static void algolist(int mode) {
	int i;
	for (i = 0; i < R_HASH_NBITS ; i++) {
		ut64 bits = 1ULL << i;
		const char *name = r_hash_name (bits);
		if (name && *name) {
			if (mode) {
				r_cons_println (name);
			} else {
				r_cons_printf ("%s ", name);
			}
		}
	}
	if (!mode) r_cons_newline ();
}

static bool cmd_print_ph(RCore *core, const char *input) {
	char algo[128];
	ut32 osize = 0, len = core->blocksize;
	const char *ptr;
	int pos = 0, handled_cmd = false;

	if (!*input || *input == '?') {
		algolist (1);
		return true;
	}
	if (*input == '=') {
		algolist (0);
		return true;
	}
	input = r_str_chop_ro (input);
	ptr = strchr (input, ' ');
	sscanf (input, "%31s", algo);
	if (ptr && ptr[1]) { // && r_num_is_valid_input (core->num, ptr + 1)) {
		int nlen = r_num_math (core->num, ptr + 1);
		if (nlen > 0) {
			len = nlen;
		}
		osize = core->blocksize;
		if (nlen > core->blocksize) {
			r_core_block_size (core, nlen);
			if (nlen != core->blocksize) {
				eprintf ("Invalid block size\n");
				r_core_block_size (core, osize);
				return false;
			}
			r_core_block_read (core);
		}
	} else if (!ptr || !*(ptr + 1)) {
		osize = len;
	}
	/* TODO: Simplify this spaguetti monster */
	while (osize > 0 && hash_handlers[pos].name) {
		if (!r_str_ccmp (input, hash_handlers[pos].name, ' ')) {
			hash_handlers[pos].handler (core->block, len);
			handled_cmd = true;
			break;
		}
		pos++;
	}
	if (osize) {
		r_core_block_size (core, osize);
	}
	return handled_cmd;
}

static void cmd_print_pv(RCore *core, const char *input) {
	const char *stack[] = { "ret", "arg0", "arg1", "arg2", "arg3", "arg4", NULL };
	int i, n = core->assembler->bits / 8;
	int type = 'v';
	bool fixed_size = true;
	const char* help_msg[] = {
		 "Usage: pv[j][1,2,4,8,z]", "", "",
		 "pv", "",  "print bytes based on asm.bits",
		 "pv1", "", "print 1 byte in memory",
		 "pv2", "", "print 2 bytes in memory",
		 "pv4", "", "print 4 bytes in memory",
		 "pv8", "", "print 8 bytes in memory",
		 "pvz", "", "print value as string (alias for ps)",
		 NULL};
	switch (input[0]) {
	case '1':
		n = 1;
		input++;
		break;
	case '2':
		n = 2;
		input++;
		break;
	case '4':
		n = 4;
		input++;
		break;
	case '8':
		n = 8;
		input++;
		break;
	default:
		fixed_size = false;
		break;
	}
	// variables can be
	switch (input[0]) {
	case 'z': // "pvz"
		type = 'z';
		if (input[1]) {
			input++;
		} else {
			r_core_cmdf (core, "ps");
			break;
		}
	/* fallthrough */
	case ' ':
		for (i = 0; stack[i]; i++) {
			if (!strcmp (input + 1, stack[i])) {
				if (type == 'z') {
					r_core_cmdf (core, "ps @ [`drn sp`+%d]", n * i);
				} else {
					r_core_cmdf (core, "?v [`drn sp`+%d]", n * i);
				}
			}
		}
		break;
	case 'j':
		{
		char *str = r_str_chop (r_core_cmd_str (core, "ps @ [$$]"));
		char *p = str;
		if (p) {
			while (*p) {
				if (*p == '\\' && p[1] == 'x') {
					memmove (p, p + 4, strlen (p + 4) + 1);
				}
			}
		}
		r_cons_printf ("{\"value\":%"PFMT64d",\"string\":\"%s\"}\n",
				r_num_get (core->num, "[$$]"),
				str
			);
		free (str);
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	default:
		{
			ut64 v;
			if (!fixed_size) n = 0;
			switch (n) {
			case 1:
				v = r_read_ble8 (core->block);
				r_cons_printf ("0x%02" PFMT64x "\n", v);
				break;
			case 2:
				v = r_read_ble16 (core->block, core->print->big_endian);
				r_cons_printf ("0x%04" PFMT64x "\n", v);
				break;
			case 4:
				v = r_read_ble32 (core->block, core->print->big_endian);
				r_cons_printf ("0x%08" PFMT64x "\n", v);
				break;
			case 8:
				v = r_read_ble64 (core->block, core->print->big_endian);
				r_cons_printf ("0x%016" PFMT64x "\n", v);
				break;
			default:
				v = r_read_ble64 (core->block, core->print->big_endian);
				switch (core->assembler->bits / 8) {
				case 1: r_cons_printf ("0x%02" PFMT64x "\n", v & UT8_MAX); break;
				case 2: r_cons_printf ("0x%04" PFMT64x "\n", v & UT16_MAX); break;
				case 4: r_cons_printf ("0x%08" PFMT64x "\n", v & UT32_MAX); break;
				case 8: r_cons_printf ("0x%016" PFMT64x "\n", v & UT64_MAX); break;
				default: break;
				}
				break;
			}
		}
		//r_core_cmd0 (core, "?v [$$]");
		break;
	}
}

static void cmd_print_bars(RCore *core, const char *input) {
	bool print_bars = false;
	ut8 *ptr = core->block;
	// p=e [nblocks] [totalsize] [skip]
	int nblocks = -1;
	int totalsize = -1;
	int skipblocks = -1;

	int blocksize = -1;
	int mode = 'b'; // e, p, b, ...
	int submode = 0; // q, j, ...

	if (input[0]) {
		char *spc = strchr (input, ' ');
		if (spc) {
			nblocks = r_num_get (core->num, spc + 1);
			if (nblocks < 1) {
				nblocks = core->blocksize;
				return;
			}
			spc = strchr (spc + 1, ' ');
			if (spc) {
				totalsize = r_num_get (core->num, spc + 1);
				spc = strchr (spc + 1, ' ');
				if (spc) {
					skipblocks = r_num_get (core->num, spc + 1);
				}
			}
		}
		mode = input[1];
		if (mode && mode != ' ' && input[2]) {
			submode = input[2];
		}
	}
	if (skipblocks < 0) {
		skipblocks = 0;
	}
	if (totalsize == UT64_MAX) {
		if (core->file && core->io) {
			totalsize = r_io_desc_size (core->io, core->file->desc);
			if ((st64) totalsize < 1) {
				totalsize = -1;
			}
		}
		if (totalsize == UT64_MAX) {
			eprintf ("Cannot determine file size\n");
			return;
		}
	}
	blocksize = (blocksize > 0) ? (totalsize / blocksize) : (core->blocksize);
	if (blocksize < 1) {
		eprintf ("Invalid block size: %d\n", blocksize);
		return;
	}
	if (nblocks < 1) {
		nblocks = totalsize / blocksize;
	} else {
		blocksize = totalsize / nblocks;
	}

	switch (mode) {
	case '?': { // bars
			 const char* help_msg[] = {
				 "Usage:", "p=[bep?][qj] [num-of-blocks] ([len]) ([block-offset]) ", "show entropy/printable chars/chars bars",
				 "p=", "", "print bytes of current block in bars",
				 "p=", "b", "same as above",
				 "p=", "d", "print different bytes from block",
				 "p=", "e", "print entropy for each filesize/blocksize",
				 "p=", "p", "print number of printable bytes for each filesize/blocksize",
				 "p=", "0", "print number of 0x00 bytes for each filesize/blocksize",
				 "p=", "F", "print number of 0xFF bytes for each filesize/blocksize",
				 NULL};
			 r_core_cmd_help (core, help_msg);
		 }
		 break;
	case 'd':
		 cmd_print_eq_dict (core, blocksize);
		 break;
	case 'e': // "p=e" entropy
		 {
			ut8 *p;
			int i = 0;
			ptr = calloc (1, nblocks);
			if (!ptr) {
				eprintf ("Error: failed to malloc memory");
				goto beach;
			}
			p = malloc (blocksize);
			if (!p) {
				R_FREE (ptr);
				eprintf ("Error: failed to malloc memory");
				goto beach;
			}
			for (i = 0; i < nblocks; i++) {
				ut64 off = core->offset + (i + skipblocks) * blocksize;
				r_core_read_at (core, off, p, blocksize);
				ptr[i] = (ut8) (256 * r_hash_entropy_fraction (p, blocksize));
			}
			free (p);
			print_bars = true;
		}
		break;
	 case '0': // 0x00 bytes
	 case 'F': // 0xff bytes
	 case 'p': // printable chars
		 {
			ut8 *p;
			int i, j, k;
			ptr = calloc (1, nblocks);
			if (!ptr) {
				eprintf ("Error: failed to malloc memory");
				goto beach;
			}
			p = calloc (1, blocksize);
			if (!p) {
				R_FREE (ptr);
				eprintf ("Error: failed to malloc memory");
				goto beach;
			}
			for (i = 0; i < nblocks; i++) {
				ut64 off = (i + skipblocks) * blocksize;
				r_core_read_at (core, off, p, blocksize);
				for (j = k = 0; j < blocksize; j++) {
					switch (mode) {
					case '0':
						if (!p[j]) k++;
						break;
					case 'f':
						if (p[j] == 0xff) k++;
						break;
					case 'p':
						if (IS_PRINTABLE (p[j])) k++;
						break;
					}
				}
				ptr[i] = 256 * k / blocksize;
			}
			free (p);
			print_bars = true;
		}
		break;
	case 'b': // bytes
	case '\0':
		ptr = calloc (1, nblocks);
		r_core_read_at (core, core->offset, ptr, nblocks);
		// TODO: support print_bars
		r_print_fill (core->print, ptr, nblocks, core->offset, blocksize);
		R_FREE (ptr);
		break;
	}
	if (print_bars) {
		int i;
		switch (submode) {
		case 'j':
			r_cons_printf ("{\"blocksize\":%d,\"address\":%"PFMT64d",\"size\":%"PFMT64d",\"entropy\":[",
				blocksize, core->offset, totalsize);
			for (i = 0; i < nblocks; i++) {
				ut8 ep = ptr[i];
				ut64 off = blocksize * i;
				const char *comma = (i+1< (nblocks))?",": "";
				off += core->offset;
				r_cons_printf ("{\"addr\":%"PFMT64d",\"value\":%d}%s",
						off, ep, comma);

			}
			r_cons_printf ("]}\n");
			break;
		case 'q':
			for (i = 0; i < nblocks; i++) {
				ut64 off = core->offset + (blocksize * i);
				r_cons_printf ("0x%08"PFMT64x" %d %d\n", off, i, ptr[i]);
			}
			break;
		default:
			r_print_fill (core->print, ptr, nblocks, core->offset, blocksize);
			break;
		}
	}
beach:
	return;
}

static int bbcmp(RAnalBlock *a, RAnalBlock *b) {
	return a->addr - b->addr;
}

/* TODO: integrate this into r_anal */
static void _pointer_table (RCore *core, ut64 origin, ut64 offset, const ut8 *buf, int len, int step, int mode) {
	int i;
	ut64 addr;
	st32 *delta; // only for step == 4
	if (step <1) {
		step = 4;
	}
	if (origin != offset) {
		switch (mode) {
		case '*':
			r_cons_printf ("CC-@ 0x%08"PFMT64x"\n", origin);
			r_cons_printf ("CC switch table @ 0x%08"PFMT64x"\n", origin);
			r_cons_printf ("axd 0x%"PFMT64x" 0x%08"PFMT64x"\n", origin, offset);
			break;
		case '.':
			r_core_cmdf (core, "CC-@ 0x%08"PFMT64x"\n", origin);
			r_core_cmdf (core, "CC switch table @ 0x%08"PFMT64x"\n", origin);
			r_core_cmdf (core, "axd 0x%"PFMT64x" 0x%08"PFMT64x"\n", origin, offset);
			break;
		}
	} else if (mode == '.') {
		r_core_cmdf (core, "CC-@ 0x%08"PFMT64x"\n", origin);
		r_core_cmdf (core, "CC switch table @ 0x%08"PFMT64x"\n", offset);
	}
	for (i = 0; i < len; i += step) {
		delta = (st32*)(buf + i);
		addr = offset + *delta;
		if (!r_io_is_valid_offset (core->io, addr, 0)) {
			break;
		}
		if (mode == '*') {
			r_cons_printf ("af case.%d.0x%"PFMT64x" 0x%08"PFMT64x"\n", i, offset, addr);
			r_cons_printf ("ax 0x%"PFMT64x" 0x%08"PFMT64x"\n", offset, addr);
			r_cons_printf ("ax 0x%"PFMT64x" 0x%08"PFMT64x"\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			r_cons_printf ("aho case 0x%"PFMT64x" 0x%08"PFMT64x" @ 0x%08"PFMT64x"\n", i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			r_cons_printf ("ahs %d @ 0x%08"PFMT64x"\n", step, offset + i);
		} else if (mode == '.') {
			r_core_cmdf (core, "af case.%d.0x%"PFMT64x" @ 0x%08"PFMT64x"\n", i, offset, addr);
			r_core_cmdf (core, "ax 0x%"PFMT64x" 0x%08"PFMT64x"\n", offset, addr);
			r_core_cmdf (core, "ax 0x%"PFMT64x" 0x%08"PFMT64x"\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			r_core_cmdf (core, "CC+ case %d: 0x%08"PFMT64x" @ 0x%08"PFMT64x"\n", i / step, addr, origin);
			r_core_cmdf (core, "aho case %d 0x%08"PFMT64x" @ 0x%08"PFMT64x"\n", i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			r_core_cmdf (core, "ahs %d @ 0x%08"PFMT64x"\n", step, offset + i);
		} else {
			r_cons_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"\n", offset + i, addr);
		}
	}
}

//TODO: this function is a temporary fix. All analysis should be based on realsize. However, now for same architectures realisze is not used
static ut32 tmp_get_contsize (RAnalFunction *f) {
	int size = r_anal_fcn_contsize (f);
	size = (size > 0) ? size : r_anal_fcn_size (f);
	return (size < 0) ? 0 : size;
}

static void pdr_bb(RCore * core, RAnalFunction * fcn, RAnalBlock * b, bool emu, ut64 saved_gp, ut8 *saved_arena) {
	core->anal->gp = saved_gp;
	if (emu) {
		if (b->parent_reg_arena) {
			ut64 gp;
			r_reg_arena_poke (core->anal->reg, b->parent_reg_arena);
			R_FREE (b->parent_reg_arena);
			gp = r_reg_getv (core->anal->reg, "gp");
			if (gp) {
				core->anal->gp = gp;
			}
		} else {
			r_reg_arena_poke (core->anal->reg, saved_arena);
		}
	}
	r_core_cmdf (core, "pD %"PFMT64d" @0x%"PFMT64x, b->size, b->addr);
#if 1
	/*
	 * Parent's reg arena is propagated only on forward jumps / fails
	 * because in pdr the visit occours in order of address, this is
	 * to avoid leaking the arenas.
	 *
	 * If a block already has a parent_reg_arena, it does not get
	 * owerwritten.
	 */
	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr && emu && core->anal->last_disasm_reg != NULL) {
			RAnalBlock * jumpbb = r_anal_bb_get_jumpbb (fcn, b);
			if (jumpbb && !jumpbb->parent_reg_arena) {
				jumpbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
			}
		}
		r_cons_printf ("| ----------- true: 0x%08"PFMT64x, b->jump);
	}
	if (b->fail != UT64_MAX) {
		if (b->fail > b->addr && emu && core->anal->last_disasm_reg != NULL) {
			RAnalBlock * failbb = r_anal_bb_get_failbb (fcn, b);
			if (failbb && !failbb->parent_reg_arena) {
				failbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
			}
		}
		r_cons_printf ("  false: 0x%08"PFMT64x, b->fail);
	}
	r_cons_newline ();
#endif
}

static int cmd_print(void *data, const char *input) {
	int mode, w, p, i, l, len, total[10];
	ut64 off, from, to, at, ate, piece;
	RCore *core = (RCore *)data;
	ut32 tbs = core->blocksize;
	ut64 tmpseek = UT64_MAX;
	RCoreAnalStats *as;
	int ret = 0;
	ut64 n;

	r_print_init_rowoffsets (core->print);
	off = UT64_MAX;
	l = len = core->blocksize;
	if (input[0] && input[1]) {
		int idx = (input[0] == 'h')? 2: 1;
		const char *p = off? strchr (input + idx, ' '): NULL;
		if (p) {
			l = (int) r_num_math (core->num, p + 1);
			/* except disasm and memoryfmt (pd, pm) */
			if (input[0] != 'd' && input[0] != 'D' && input[0] != 'm' && input[0]!='a' && input[0]!='f' && input[0] != 'i' && input[0] != 'I') {
				int n = (st32) l; //r_num_math (core->num, input+1);
				if (l<0) {
					off = core->offset + n;
					len = l = - n;
					tmpseek = core->offset;
				} else if (l > 0) {
					len = l;
					if (l > tbs) {
						if (input[0] == 'x' && input[1] == 'l') {
							l *= core->print->cols;
						}
						if (!r_core_block_size (core, l)) {
							eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
								*input, input+2);
							goto beach;
						}
						l = core->blocksize;
					} else {
						l = len;
					}
				}
			}
		}// else l = 0;
	} else {
		l = len;
	}

	if (len > core->blocksize) {
		len = core->blocksize;
	}

	if (input[0] != 'd' && input[0] != 'm' && input[0]!='a' && input[0] != 'f') {
		n = core->blocksize_max;
		i = (int)n;
		if (i != n) i = 0;
		if (i && l > i) {
			eprintf ("This block size is too big (0x%"PFMT64x
				" < 0x%x). Did you mean 'p%c @ %s' instead?\n",
				n, l, *input, input+2);
			goto beach;
		}
	}
	if (input[0] == 'x' || input[0] == 'D'){
		if (l > 0 && tmpseek == UT64_MAX){
			if (!r_core_block_size (core, l)){
				eprintf ("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
						*input, input+2);
				goto beach;
			}
		}
	}

	if (input[0] && input[0]!='z' && input[1] == 'f') {
		RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
				// R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) {
			len = r_anal_fcn_size (f);
		} else {
			eprintf ("p: Cannot find function at 0x%08"PFMT64x"\n", core->offset);
			core->num->value = 0;
			goto beach;
		}
	}
	core->num->value = len;
	if (len > core->blocksize) {
		len = core->blocksize;
	}
	if (off != UT64_MAX) {
		r_core_seek (core, off, SEEK_SET);
	}
	switch (*input) {
	case 'w': // "pw"
		if (input[1]=='n') {
			cmd_print_pwn (core);
		} else if (input[1]=='d') {
			if (!r_sandbox_enable (0)) {
				char *cwd = r_sys_getdir ();
				if (cwd) {
					r_cons_println (cwd);
					free (cwd);
				}
			}
		} else {
			r_cons_printf("| pwd               display current working directory\n");
		}
		break;
	case 'h': // "ph"
		cmd_print_ph (core, input + 1);
		break;
	case 'v': // "pv"
		cmd_print_pv (core, input + 1);
		break;
	case '-': // "p-"
		mode = input[1];
		w = len? len: core->print->cols * 4;
		if (mode == 'j') r_cons_strcat ("{");
		off = core->offset;
		for (i=0; i<10; i++)
			total[i] = 0;
		r_list_free (r_core_get_boundaries (core, "file", &from, &to));
		piece = R_MAX((to - from) / w, 1);
		as = r_core_anal_get_stats (core, from, to, piece);
		if (!as && mode !='?') return 0;
		//eprintf ("RANGE = %llx %llx\n", from, to);
		switch (mode) {
		case '?':{
			const char* help_msg[] = {
				"Usage:", "p%%[jh] [pieces]", "bar|json|histogram blocks",
				"p-", "", "show ascii-art bar of metadata in file boundaries",
				"p-j", "", "show json format",
				"p-h", "", "show histogram analysis of metadata per block",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			return 0;
		case 'j': //p-j
			r_cons_printf (
				"\"from\":%"PFMT64d","
				"\"to\":%"PFMT64d","
				"\"blocksize\":%d,"
				"\"blocks\":[", from, to, piece);
			break;
		case 'h': //p-h
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
		cmd_print_bars (core, input);
		break;
	case 'A': // "pA"
		{
		ut64 from = r_config_get_i (core->config, "search.from");
		ut64 to = r_config_get_i (core->config, "search.to");
		int count = r_config_get_i (core->config, "search.count");

		int want = r_num_math (core->num, input+1);
		if (input[1]=='?') {
			r_core_cmd0 (core, "/A?");
		} else {
			r_config_set_i (core->config, "search.count", want);
			r_config_set_i (core->config, "search.from", core->offset);
			r_config_set_i (core->config, "search.to", core->offset+core->blocksize);
			r_core_cmd0 (core, "/A");
			r_config_set_i (core->config, "search.count", count);
			r_config_set_i (core->config, "search.from", from);
			r_config_set_i (core->config, "search.to", to);
		}
		}
		break;
	case 'a': // "pa"
	{
		ut32 new_bits = -1;
		int segoff, old_bits, pos = 0;
		ut8 settings_changed = false;
		char *new_arch = NULL, *old_arch = NULL, *hex = NULL;
		old_arch = strdup (r_config_get (core->config, "asm.arch"));
		old_bits = r_config_get_i (core->config, "asm.bits");
		segoff = r_config_get_i (core->config, "asm.segoff");
		if (input[1] != ' ') {
			if (input[0])
				for (pos = 1; pos < R_BIN_SIZEOF_STRINGS && input[pos]; pos++)
					if (input[pos] == ' ') break;

			if (!r_core_process_input_pade (core, input+pos, &hex, &new_arch, &new_bits)) {
				// XXX - print help message
				//return false;
			}

			if (!new_arch) new_arch = strdup (old_arch);
			if (new_bits == -1) new_bits = old_bits;

			if (strcmp (new_arch, old_arch) != 0 || new_bits != old_bits){
				r_core_set_asm_configs (core, new_arch, new_bits, segoff);
				settings_changed = true;
			}
		}
		if (input[1]=='e') { // "pae"
			if (input[2]=='?') {
				r_cons_printf ("|Usage: pae [hex]       assemble esil from hexpairs\n");
			} else {
				int ret, bufsz;
				RAnalOp aop = {0};
				const char *str;
//				char *buf = strdup (input+2);
				bufsz = r_hex_str2bin (hex, (ut8*)hex);
				ret = r_anal_op (core->anal, &aop, core->offset,
					(const ut8*)hex, bufsz);
				if (ret > 0) {
					str = R_STRBUF_SAFEGET (&aop.esil);
					r_cons_println (str);
				}
				r_anal_op_fini (&aop);
			}
		} else if (input[1] == 'D') {
			if (input[2] == '?') {
				r_cons_printf ("|Usage: paD [asm]       disasm like in pdi\n");
			} else {
				r_core_cmdf (core, "pdi@x:%s", input+2);
			}
		} else if (input[1]=='d') { // "pad"
			if (input[2]=='?') {
				r_cons_printf ("|Usage: pad [asm]       disasm\n");
			} else {
				RAsmCode *c;
				r_asm_set_pc (core->assembler, core->offset);
				c = r_asm_mdisassemble_hexstr (core->assembler, hex);
				if (c) {
					r_cons_print (c->buf_asm);
					r_asm_code_free (c);
				} else eprintf ("Invalid hexstr\n");
			}
		} else if (input[1]=='?') {
			r_cons_printf("|Usage: pa[ed] [hex|asm]  assemble (pa) disasm (pad)"
				" esil (pae) from hexpairs\n");
		} else {
			RAsmCode *acode;
			int i;
			int bytes;
			r_asm_set_pc (core->assembler, core->offset);
			acode = r_asm_massemble (core->assembler, input + 1);
			if (acode && *acode->buf_hex) {
				bytes = strlen (acode->buf_hex) >> 1;
				for (i = 0; i < bytes; i++) {
					ut8 b = acode->buf[i]; // core->print->big_endian? (bytes - 1 - i): i ];
					r_cons_printf ("%02x", b);
				}
				r_cons_newline ();
				r_asm_code_free (acode);
			}
		}
		if (settings_changed)
			r_core_set_asm_configs (core, old_arch, old_bits, segoff);
		free (old_arch);
		free (new_arch);
	}
		break;
	case 'b': { // "pb"
		if (input[1]=='?') {
			r_cons_printf("|Usage: p[bB] [len] ([skip])  ; see also pB and pxb\n");
		} else if (l != 0) {
			int from, to;
			const int size = len*8;
			char *spc, *buf = malloc (size+1);
			spc = strchr (input, ' ');
			if (spc) {
				len = r_num_math (core->num, spc+1);
				if (len<1)
					len = 1;
				spc = strchr (spc+1, ' ');
				if (spc) {
					from = r_num_math (core->num, spc+1);
				} else {
					from = 0;
				}
				to = from+len;
			} else {
				from = 0;
				to = size;
			}
			if (buf) {
				int buf_len;
				r_str_bits (buf, core->block, size, NULL);
				buf_len = strlen (buf);
				if (from>=buf_len) {
					from = buf_len;
				}
				if (to<buf_len) {
					buf[to] = 0;
				}
				r_cons_println (buf+from);
				free (buf);
			} else eprintf ("ERROR: Cannot malloc %d bytes\n", size);
		}
		}
		break;
	case 'B': { // "pB"
		if (input[1]=='?') {
			r_cons_printf ("|Usage: p[bB] [len]       bitstream of N bytes\n");
		} else if (l != 0) {
			int size;
			char *buf;
			if (!r_core_block_size (core, len)) {
				len = core->blocksize;
			}
			size = len*8;
			buf = malloc (size+1);
			if (buf) {
				r_str_bits (buf, core->block, size, NULL);
				r_cons_println (buf);
				free (buf);
			} else eprintf ("ERROR: Cannot malloc %d bytes\n", size);
		} }
		break;
	case 'I': // "pI"
		switch (input[1]) {
		case 'j': // "pIj" is the same as pDj
			if (l != 0) {
				if (input[2]) {
					cmd_pDj (core, input + 2);
				} else {
					cmd_pDj (core, sdb_fmt (0, "%d", core->blocksize));
				}
			}
			break;
		case 'f': // "pIf"
			{
				const RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
						R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f) {
					r_core_print_disasm_instructions (core,
						r_anal_fcn_size (f), 0);
					break;
				}
			}
		case 'd': // "pId" is the same as pDi
			if (l) {
				pdi (core, 0, l, 0);
			}
			break;
		case '?': // "pi?"
			r_cons_printf ("|Usage: p[iI][df] [len]   print N instructions/bytes"
					"(f=func) (see pi? and pdi)\n");
			break;
		default:
			if (l) {
				r_core_print_disasm_instructions (core, l, 0);
			}
		}
		break;
	case 'i': // "pi"
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: pi[defj] [num]\n");
			break;
		case 'a': // "pia" is like "pda", but with "pi" output
			if (l != 0) {
				r_core_print_disasm_all (core, core->offset,
					l, len, 'i');
			}
			break;
		case 'j': //pij is the same as pdj
			if (l != 0) {
				cmd_pdj (core, input+2);
			}
			break;
		case 'd': //pid is the same as pdi
			if (l != 0) {
				pdi (core, l, 0, 0);
			}
			break;
		case 'e':
			if (l != 0) {
				pdi (core, l, 0, 'e');
			}
			break;
		case 'f': // "pif"
			if (l != 0) {
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
						R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f) {
					ut32 bsz = core->blocksize;
					r_core_block_size (core, r_anal_fcn_size (f));
					r_core_print_disasm_instructions (core, 0, 0);
					r_core_block_size (core, bsz);
				} else {
					r_core_print_disasm_instructions (core,
						core->blocksize, l);
				}
			}
			break;
		default:
			if (l != 0) {
				r_core_print_disasm_instructions (core, 0, l);
			}
			break;
		}
		goto beach;
	case 'D': // "pD"
	case 'd': // "pd"
		{
		ut64 current_offset = core->offset;
		ut32 new_bits = -1;
		ut64 use_blocksize = core->blocksize;
		int segoff, old_bits, pos = 0;
		ut8 settings_changed = false, bw_disassemble = false;
		char *new_arch = NULL, *old_arch = NULL;
		ut32 pd_result = false, processed_cmd = false;
		old_arch = strdup (r_config_get (core->config, "asm.arch"));
		segoff = r_config_get_i (core->config, "asm.segoff");
		old_bits = r_config_get_i (core->config, "asm.bits");

		if (input[1] && input[2]) {
			char* p = strchr(input,' ');
			if (p) {
				int len = (int)r_num_math (core->num, p);
				if (len == 0) {
					break;
				}
			}
		}
		// XXX - this is necessay b/c radare will automatically
		// swap flags if arch is x86 and bits == 16 see: __setsegoff in config.c

		// get to the space
		if (input[0]) {
			for (pos = 1; pos < R_BIN_SIZEOF_STRINGS && input[pos]; pos++) {
				if (input[pos] == ' ') {
					break;
				}
			}
		}

		if (!process_input (core, input+pos, &use_blocksize, &new_arch, &new_bits)) {
			// XXX - print help message
			//return false;
		}
		if (!use_blocksize) {
			use_blocksize = core->blocksize;
		}

		if (core->blocksize_max < use_blocksize && (int)use_blocksize < -core->blocksize_max) {
			eprintf ("This block size is too big (%"PFMT64d"<%"PFMT64d"). Did you mean 'p%c @ 0x%08"PFMT64x"' instead?\n",
				(ut64)core->blocksize_max, (ut64)use_blocksize, input[0], (ut64) use_blocksize);
			free (old_arch);
			free (new_arch);
			goto beach;
		} else if (core->blocksize_max < use_blocksize && (int)use_blocksize > -core->blocksize_max) {
			bw_disassemble = true;
			use_blocksize = -use_blocksize;
		}
		l = use_blocksize;

		if (!new_arch) new_arch = strdup (old_arch);
		if (new_bits == -1) new_bits = old_bits;

		if (strcmp (new_arch, old_arch) != 0 || new_bits != old_bits){
			r_core_set_asm_configs (core, new_arch, new_bits, segoff);
			settings_changed = true;
		}

		switch (input[1]) {
		case 'c': // "pdc" // "pDc"
			r_core_pseudo_code (core, input + 2);
			pd_result = 0;
			processed_cmd = true;
			break;
		case 'i': // "pdi" // "pDi"
			processed_cmd = true;
			if (*input == 'D') {
				pdi (core, 0, l, 0);
			} else {
				pdi (core, l, 0, 0);
			}
			pd_result = 0;
			break;
		case 'a': // "pda"
			processed_cmd = true;
			r_core_print_disasm_all (core, core->offset, l, len, input[2]);
			pd_result = true;
			break;
		case 'r': // "pdr"
			processed_cmd = true;
			{
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
						R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
				if (f) {
					RListIter *iter;
					RAnalBlock *b;
					RAnalFunction *tmp_func;
					RListIter *locs_it = NULL;
					if (f->fcn_locs) {
						locs_it = f->fcn_locs->head;
					}
					// XXX: hack must be reviewed/fixed in code analysis
					if (r_list_length (f->bbs) == 1) {
						ut32 fcn_size = r_anal_fcn_size (f);
						b = r_list_get_top (f->bbs);
						if (b->size > fcn_size) {
							b->size = fcn_size;
						}
					}
					r_list_sort (f->bbs, (RListComparator)bbcmp);
					if (input[2] == 'j') {
						r_cons_print ("[");
						bool isFirst = true;
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							if (tmp_func->addr > f->addr) {
								break;
							}
							r_list_foreach (tmp_func->bbs, iter, b) {
								if (isFirst) {
									isFirst = false;
								} else {
									r_cons_print (",");
								}
								r_core_cmdf (core, "pDj %"PFMT64d" @0x%"PFMT64x, b->size, b->addr);
							}
						}
						r_list_foreach (f->bbs, iter, b) {
							if (isFirst) {
								isFirst = false;
							} else {
								r_cons_print (",");
							}
							r_core_cmdf (core, "pDj %"PFMT64d" @0x%"PFMT64x, b->size, b->addr);
						}
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							r_list_foreach (tmp_func->bbs, iter, b) {
								if (isFirst) {
									isFirst = false;
								} else {
									r_cons_print (",");
								}
								r_core_cmdf (core, "pDj %"PFMT64d" @0x%"PFMT64x, b->size, b->addr);
							}
						}
						r_cons_print ("]");
					} else {
						// TODO: sort by addr
						bool asm_lines = r_config_get_i (core->config, "asm.lines");
						bool emu = r_config_get_i (core->config, "asm.emu");
						ut64 saved_gp;
						ut8 *saved_arena;
						if (emu) {
							saved_gp = core->anal->gp;
							saved_arena = r_reg_arena_peek (core->anal->reg);
						}

						r_config_set_i (core->config, "asm.lines", 0);
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							if (tmp_func->addr < f->addr) {
								r_list_foreach (tmp_func->bbs, iter, b) {
									pdr_bb (core, tmp_func, b, emu, saved_gp, saved_arena);
								}
							} else {
								break;
							}
						}
						r_list_foreach (f->bbs, iter, b) {
							pdr_bb (core, f, b, emu, saved_gp, saved_arena);
						}
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							//this should be more advanced
							r_list_foreach (tmp_func->bbs, iter, b) {
								pdr_bb (core, tmp_func, b, emu, saved_gp, saved_arena);
							}
						}

						if (emu) {
							core->anal->gp = saved_gp;
							if (saved_arena) {
								r_reg_arena_poke (core->anal->reg, saved_arena);
								R_FREE (saved_arena);
							}
						}
						r_config_set_i (core->config, "asm.lines", asm_lines);
					}
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
					core->num->value = 0;
				}
				pd_result = true;
			}
			break;
		case 'b': // "pdb"
			processed_cmd = true;
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
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x"\n", core->offset);
					core->num->value = 0;
				}
			}
			break;
		case 's': // "pds" and "pdsf"
			processed_cmd = true;
			if (input[2] == '?') {
				r_cons_printf ("Usage: pds[f]  - sumarize N bytes or function (pdfs)\n");
			} else {
				disasm_strings (core, input, NULL);
			}
			break;
		case 'f': // "pdf"
			processed_cmd = true;
			if (input[2] == '?') {
				r_cons_printf ("Usage: pdf[sj]  - disassemble function (summary+cjmp), json)\n");
			} else if (input[2] == 's') { // "pdfs"
				ut64 oseek = core->offset;
				int oblock = core->blocksize;
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset,
						R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (f) {
					r_core_seek (core, oseek, SEEK_SET);
					r_core_block_size (core, r_anal_fcn_size (f));
					disasm_strings (core, input, f);
					r_core_block_size (core, oblock);
					r_core_seek (core, oseek, SEEK_SET);
				}
				processed_cmd = true;
			} else {
				ut32 bsz = core->blocksize;
				RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
						// R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				RAnalFunction *tmp_func;
				ut32 cont_size = 0;
				RListIter *locs_it = NULL;
				if (f && f->fcn_locs) {
					locs_it = f->fcn_locs->head;
				}
				if (f && input[2] == 'j') { // "pdfj"
					ut8 *func_buf = NULL, *loc_buf = NULL;
					ut32 fcn_size = r_anal_fcn_realsize (f);
					cont_size = tmp_get_contsize (f);
					r_cons_printf ("{");
					r_cons_printf ("\"name\":\"%s\"", f->name);
					r_cons_printf (",\"size\":%d", fcn_size);
					r_cons_printf (",\"addr\":%"PFMT64d, f->addr);
					r_cons_printf (",\"ops\":");
					// instructions are all outputted as a json list
					func_buf = calloc (cont_size, 1);
					if (func_buf) {
						//TODO: can loc jump to another locs?
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							if (tmp_func->addr > f->addr) {
								break;
							}
							cont_size = tmp_get_contsize (tmp_func);
							loc_buf = calloc (cont_size, 1);;
							r_io_read_at (core->io, tmp_func->addr, loc_buf, cont_size);
							r_core_print_disasm_json (core, tmp_func->addr, loc_buf, cont_size, 0);
							free (loc_buf);
						}
						cont_size = tmp_get_contsize (f);
						r_io_read_at (core->io, f->addr, func_buf, cont_size);
						r_core_print_disasm_json (core, f->addr, func_buf, cont_size, 0);
						free (func_buf);
						for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
							cont_size = tmp_get_contsize (tmp_func);
							loc_buf = calloc (cont_size, 1);;
							r_io_read_at (core->io, tmp_func->addr, loc_buf, cont_size);
							r_core_print_disasm_json (core, tmp_func->addr, loc_buf, cont_size, 0);
							free (loc_buf);
						}
					} else {
						eprintf ("cannot allocate %d bytes\n", fcn_size);
					}
					r_cons_printf ("}\n");
					pd_result = 0;
				} else if (f) {
					for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
						if (tmp_func->addr > f->addr) {
							break;
						}
						cont_size = tmp_get_contsize (tmp_func);
						r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x, cont_size, tmp_func->addr);
					}
					cont_size = tmp_get_contsize (f);
					r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x, cont_size, f->addr);
					for (; locs_it && (tmp_func = locs_it->data); locs_it = locs_it->n) {
						cont_size = tmp_get_contsize (tmp_func);
						r_core_cmdf (core, "pD %d @ 0x%08" PFMT64x, cont_size, tmp_func->addr);
					}
					pd_result = 0;
				} else {
					eprintf ("pdf: Cannot find function at 0x%08"PFMT64x"\n", core->offset);
					processed_cmd = true;
					core->num->value = 0;
				}
				if (bsz != core->blocksize)
					r_core_block_size (core, bsz);
			}
			l = 0;
			break;
		case 'l': //pdl
			processed_cmd = true;
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
			processed_cmd = true;
			if (*input == 'D') {
				cmd_pDj (core, input+2);
			} else cmd_pdj (core, input+2);
			r_cons_newline ();
			pd_result = 0;
			break;
		case 0:
			/* "pd" -> will disassemble blocksize/4 instructions */
			if (*input=='d') {
				l /= 4;
			}
			break;
		case '?': // "pd?"
			processed_cmd = true;
			const char* help_msg[] = {
				"Usage:", "p[dD][ajbrfils] [sz] [arch] [bits]", " # Print Disassembly",
				"NOTE: ", "len", "parameter can be negative",
				"NOTE: ", "", "Pressing ENTER on empty command will repeat last pd command and also seek to end of disassembled range.",
				"pd", " N", "disassemble N instructions",
				"pd", " -N", "disassemble N instructions backward",
				"pD", " N", "disassemble N bytes",
				"pda", "", "disassemble all possible opcodes (byte per byte)",
				"pdb", "", "disassemble basic block",
				"pdc", "", "pseudo disassembler output in C-like syntax",
				"pdj", "", "disassemble to json",
				"pdr", "", "recursive disassemble across the function graph",
				"pdf", "", "disassemble function",
				"pdi", "", "like 'pi', with offset and bytes",
				"pdl", "", "show instruction sizes",
				//"pds", "", "disassemble with back sweep (greedy disassembly backwards)",
				"pds", "", "disassemble summary (strings, calls, jumps, refs) (see pdsf and pdfs)",
				"pdt", "", "disassemble the debugger traces (see atd)",
				NULL};
				r_core_cmd_help (core, help_msg);
			pd_result = 0;
		}
		if (!processed_cmd) {
			ut64 addr = core->offset;
			ut8 *block = NULL;
			ut64 start;

			if (bw_disassemble) {
				block = malloc (core->blocksize);
				if (l < 0) {
					l = -l;
				}
				if (block) {
					if (*input == 'D'){ //pD
						free (block);
						block = malloc (l);
						r_core_read_at (core, addr-l, block, l); //core->blocksize);
						core->num->value = r_core_print_disasm (core->print, core, addr-l, block, l, l, 0, 1);
					} else { //pd
						const int bs = core->blocksize;
						int instr_len;
						if (r_core_prevop_addr (core, core->offset, l, &start)) {
							// We have some anal_info.
							instr_len = core->offset - start;
						} else {
							// anal ignorance.
							r_core_asm_bwdis_len (core, &instr_len, &addr, l);
						}
						ut64 prevaddr = core->offset;
						r_core_seek (core, prevaddr - instr_len, true);
						block = realloc (block, R_MAX(instr_len, bs));
						memcpy (block, core->block, bs);
						r_core_read_at (core, addr+bs, block+bs, instr_len-bs); //core->blocksize);
						core->num->value = r_core_print_disasm (core->print,
								core, core->offset, block, instr_len, l, 0, 1);
						r_core_seek (core, prevaddr, true);
					}
				}
			} else {
				const int bs = core->blocksize;
				// XXX: issue with small blocks
				if (*input == 'D' && l>0) {
					if (l < 1) {
						//eprintf ("Block size too small\n");
						return 1;
					}
					if (l > R_CORE_MAX_DISASM) { // pD
						eprintf ("Block size too big\n");
						return 1;
					}
					block = malloc (l);
					if (block) {
						if (l>core->blocksize) {
							r_core_read_at (core, addr, block, l); //core->blocksize);
						} else {
							memcpy (block, core->block, l);
						}
						core->num->value = r_core_print_disasm (core->print,
								core, addr, block, l, l, 0, 1);
					} else {
						eprintf ("Cannot allocate %d bytes\n", l);
					}
				} else {
					block = malloc (R_MAX(l*10, bs));
					memcpy (block, core->block, bs);
					r_core_read_at (core, addr+bs, block+bs, (l*10)-bs); //core->blocksize);
					core->num->value = r_core_print_disasm (core->print, core, addr, block, l*10, l, 0, 0);
				}
			}
			free (block);
		}
		core->offset = current_offset;
		// change back asm setting if they were changed
		if (settings_changed)
			r_core_set_asm_configs (core, old_arch, old_bits, segoff);

		free (old_arch);
		free (new_arch);

		if (processed_cmd) {
			ret = pd_result;
			goto beach;
		}
		}
		break;
	case 's': // "ps"
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
				"psu", "", "print utf16 unicode (json)",
				"psw", "", "print wide string",
				"psj", "", "print string in JSON format",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		case 'j':
			if (l > 0) {
				char *str, *type;
				ut64 vaddr;
				RIOSection *section;

				if (input[2] == ' ' && input[3]){
					len = r_num_math (core->num, input+3);
					len = R_MIN (len, core->blocksize);
				}
				/* try to get the section that contains the
				 * string, by considering current offset as
				 * paddr and if it isn't, trying to consider it
				 * as vaddr. */
				vaddr = r_io_section_maddr_to_vaddr (core->io, core->offset);
				section = core->io->section;
				if (vaddr == UT64_MAX) {
					section = r_io_section_vget (core->io, core->offset);
					if (section) {
						vaddr = core->offset;
					}
				}

				r_cons_printf ("{\"string\":");
				str = r_str_utf16_encode ((const char*)core->block, len);
				r_cons_printf ("\"%s\"", str);
				r_cons_printf (",\"offset\":%"PFMT64d, core->offset);
				r_cons_printf (",\"section\":\"%s\"", vaddr == UT64_MAX ? "unknown" : section->name);
				r_cons_printf (",\"length\":%d", len);
				switch (get_string_type (core->block, len)){
					case 'w' : type = "wide" ; break;
					case 'a' : type = "ascii"; break;
					case 'u' : type = "utf" ; break;
					default : type = "unknown" ; break;
				}
				r_cons_printf (",\"type\":\"%s\"}", type);
				r_cons_newline ();
				free (str);
			}
			break;
		case 'i': //psi
			if (l > 0) {
			ut8 *buf = malloc (1024);
			int delta = 512;
			ut8 *p, *e, *b;
			if (!buf) return 0;
			if (core->offset<delta)
				delta = core->offset;
			p = buf + delta;
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
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block, len, 0);
			}
			break;
		case 'b': // "psb"
			if (l > 0) {
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
								if (*s) {
									r_cons_println (s);
								}
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
					r_cons_print (s); // TODO: missing newline?
					free (s);
				}
			}
			break;
		case 'z': //psz
			if (l > 0) {
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
					r_cons_println (s);
					free (s);
				}
			}
			break;
		case 'p': // "psp"
			if (l > 0) {
				int mylen = core->block[0];
				// TODO: add support for 2-4 byte length pascal strings
				if (mylen < core->blocksize) {
					r_print_string (core->print, core->offset,
						core->block + 1, mylen, R_PRINT_STRING_ZEROEND);
					core->num->value = mylen;
				} else core->num->value = 0; // error
			}
			break;
		case 'w': // "psw"
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block, len,
					R_PRINT_STRING_WIDE | R_PRINT_STRING_ZEROEND);
			}
			break;
		case ' ':
			r_print_string (core->print, core->offset, core->block, l, 0);
			break;
		case 'u':
			if (l > 0) {
				char *str = r_str_utf16_encode (
					(const char*)core->block, len);
				r_cons_println (str);
				free (str);
			}
			break;
		default:
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block,
					 len, R_PRINT_STRING_ZEROEND);
			}
			break;
		}
		break;
	case 'm': // "pm"
		if (input[1]=='?') {
			r_cons_printf ("|Usage: pm [file|directory]\n"
				"| r_magic will use given file/dir as reference\n"
				"| output of those magic can contain expressions like:\n"
				"|   foo@0x40   # use 'foo' magic file on address 0x40\n"
				"|   @0x40      # use current magic file on address 0x40\n"
				"|   \\n         # append newline\n"
				"| e dir.magic  # defaults to "R_MAGIC_PATH"\n"
				"| /m           # search for magic signatures\n"
				);
		} else {
			// XXX: need cmd_magic header for r_core_magic
			if (l > 0) {
				r_core_magic (core, input + 1, true);
			}
		}
		break;
	case 'u': // "pu"
		if (input[1]=='?') {
			r_cons_printf ("|Usage: pu[w] [len]       print N url"
					"encoded bytes (w=wide)\n");
		} else {
			if (l > 0) {
				r_print_string (core->print, core->offset, core->block, len,
						R_PRINT_STRING_URLENCODE |
						((input[1]=='w')?R_PRINT_STRING_WIDE:0));
			}
		}
		break;
	case 'c': // "pc"
		if (l != 0) {
			r_print_code (core->print, core->offset, core->block, len, input[1]);
		}
		break;
	case 'C':
		switch (input[1]) {
		case 0:
		case ' ':
		case 'd':
			cmd_pCd (core, input + 2);
			break;
		default:
			eprintf ("Usage: pCd\n");
			break;
		}
		break;
	case 'r': // "pr"
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: pr[glx] [size]\n"
			"| prl: print raw with lines offsets\n"
			"| prx: printable chars with real offset (hyew)\n"
			"| prg: print raw GUNZIPped block\n"
			"| prz: print raw zero terminated string\n");
			break;
		case 'g': // "prg" // gunzip
			switch (input[2]) {
			case '?':
				r_cons_printf ("|Usage: prg[io]\n"
				"| prg: print gunzipped data of current block\n"
				"| prgi: show consumed bytes when inflating\n"
				"| prgo: show output bytes after inflating\n");
				break;
			case 'i':
				 {
				int sz, outlen = 0;
				int inConsumed = 0;
				ut8 *in, *out;
				in = core->block;
				sz = core->blocksize;
				out = r_inflate (in, sz, &inConsumed, &outlen);
				r_cons_printf ("%d\n", inConsumed);
				free (out);
				}
				break;
			case 'o':
				 {
				int sz, outlen = 0;
				ut8 *in, *out;
				in = core->block;
				sz = core->blocksize;
				out = r_inflate (in, sz, NULL, &outlen);
				r_cons_printf ("%d\n", outlen);
				free (out);
				}
				break;
			default:
				 {
				int sz, outlen = 0;
				ut8 *in, *out;
				in = core->block;
				sz = core->blocksize;
				out = r_inflate (in, sz, NULL, &outlen);
				if (out) {
					r_cons_memcat ((const char*)out, outlen);
				}
				free (out);
				}
			}
			break;
		/* TODO: compact */
		case 'l': // "prl"
			if (l != 0) {
				printraw (core, len, 1);
			}
			break;
		case 'x': // "prx"
			if (l != 0) {
				printraw (core, len, 2);
			}
			break;
		case 'z': // "prz"
			if (l != 0) {
				printraw (core, strlen ((const char*)core->block), 0);
			}
			break;
		default:
			if (l != 0) {
				printraw (core, len, 0);
			}
			break;
		}
		break;
	case '3': // "p3" [file]
		if (input[1]=='?') {
			eprintf ("Usage: p3 [file] - print 3D stereogram image of current block\n");
		} else
		if (input[1]==' ') {
			char *data = r_file_slurp (input+2, NULL);
			char *res = r_print_stereogram (data, 78, 20);
			r_print_stereogram_print (core->print, res);
			//if (data) eprintf ("%s\n", data);
			free (res);
			free (data);
		} else {
			char *res = r_print_stereogram_bytes (core->block, core->blocksize);
			r_print_stereogram_print (core->print, res);
			free (res);
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
		r_cons_break (NULL, NULL);
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
				"pxA", "", "show op analysis color map",
				"pxb", "", "dump bits in hexdump form",
				"pxd", "[124]", "signed integer dump (1 byte, 2 and 4)",
				"pxe", "", "emoji hexdump! :)",
				"pxi", "", "HexII compact binary representation",
				"pxf", "", "show hexdump of current function",
				"pxh", "", "show hexadecimal half-words dump (16bit)",
				"pxH", "", "same as above, but one per line",
				"pxl", "", "display N lines (rows) of hexdump",
				"pxo", "", "show octal dump",
				"pxq", "", "show hexadecimal quad-words dump (64bit)",
				"pxQ", "", "same as above, but one per line",
				"pxr", "[j]", "show words with references to flags and code",
				"pxs", "", "show hexadecimal in sparse mode",
				"pxt", "[*.] [origin]", "show delta pointer table in r2 commands",
				"pxw", "", "show hexadecimal words dump (32bit)",
				"pxW", "", "same as above, but one per line",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		case 'a': // "pxa"
			if (l != 0) {
				if (len%16) {
					len += 16-(len%16);
				}
				annotated_hexdump (core, input + 2, len);
			}
			break;
		case 'A': // "pxA"
			if (input[2]=='?') {
				eprintf ("Usage: pxA [len]   # f.ex: pxA 4K\n"
				" mv    move,lea,li\n"
				" ->    push\n"
				" <-    pop\n"
				" io    in/out ops\n"
				" $$    int/swi/trap/new\n"
				" ..    nop\n"
				" +-*/  math ops\n"
				" |&^   bin ops\n"
				" <<>>  shift ops\n"
				" _J    jump\n"
				" cJ    conditional jump\n"
				" _C    call\n"
				" _R    ret\n"
				" ==    cmp/test\n"
				" XX    invalid\n");
			} else if (l != 0) {
				cmd_print_pxA (core, len, input+1);
			}
			break;
		case 'b': // "pxb"
			if (l != 0) {
			ut32 n;
			int i, c;
			char buf[32];
#define P(x) (IS_PRINTABLE(x)?x:'.')
#define SPLIT_BITS(x) memmove (x + 5, x + 4, 5); x[4]=0
			for (i = c = 0; i < len; i++,c++) {
				if (c == 0) {
					r_print_offset (core->print,
						core->offset + i, 0, 0, 0, 0, NULL);
				}
				r_str_bits (buf, core->block+i, 8, NULL);
				SPLIT_BITS (buf);
				r_cons_printf ("%s.%s  ", buf, buf+5);
				if (c==3) {
					const ut8 *b = core->block + i-3;
					#define K(x) (b[3-x]<<(8*x))
					n = K (0) | K (1) | K (2) | K (3);
					r_cons_printf ("0x%08x  %c%c%c%c\n",
						n, P (b[0]), P (b[1]), P (b[2]),
						P (b[3]));
					c = -1;
				}
			}
			}
			break;
		case 'i': // "pxi"
			if (l != 0) {
				r_print_hexii (core->print, core->offset, core->block,
					core->blocksize, r_config_get_i (core->config, "hex.cols"));
			}
			break;
		case 'o': // "pxo"
			if (l != 0) {
				r_print_hexdump (core->print, core->offset,
					core->block, len, 8, 1);
			}
			break;
		case 't': // "pxt"
			if (input[2] == '?') {
				r_cons_printf ("Usage: pxt[.*] - print delta pointer table\n");
			} else {
				ut64 origin = core->offset;
				const char *arg = strchr (input, ' ');
				if (arg) {
					origin = r_num_math (core->num, arg + 1);
				}
				_pointer_table (core, origin, core->offset, core->block, len, 4, input[2]);
			}
			break;
		case 'd': // "pxd"
			if (l != 0) {
			switch (input[2]) {
			case '1':
				// 1 byte signed words (byte)
				r_print_hexdump (core->print, core->offset,
					core->block, len, -1, 4);
				break;
			case '2':
				// 2 byte signed words (short)
				r_print_hexdump (core->print, core->offset,
					core->block, len, -10, 2);
				break;
			case '8':
				r_print_hexdump (core->print, core->offset,
					core->block, len, -8, 4);
				break;
			case '4':
			default:
				// 4 byte signed words
				r_print_hexdump (core->print, core->offset,
					core->block, len, 10, 4);
			}
			}
			break;
		case 'w': // "pxw"
			if (l != 0) {
				r_print_hexdump (core->print, core->offset, core->block, len, 32, 4);
			}
			break;
		case 'W': // "pxW"
			if (l != 0) {
			len = len - (len%4);
			for (i=0; i<len; i+=4) {
				const char *a, *b;
				char *fn;
				RPrint *p = core->print;
				RFlagItem *f;
				ut32 v = r_read_ble32 (core->block + i, core->print->big_endian);
				if (p && p->colorfor) {
					a = p->colorfor (p->user, v);
					if (a && *a) {
						b = Color_RESET;
					} else {
						a = b = "";
					}
				} else {
					a = b = "";
				}
				f = r_flag_get_at (core->flags, v);
				fn = NULL;
				if (f) {
					st64 delta = (v - f->offset);
					if (delta >= 0 && delta < 8192) {
						if (v == f->offset) {
							fn = strdup (f->name);
						} else {
							fn = r_str_newf ("%s+%d",
								f->name, v-f->offset);
						}
					}
				}
				r_cons_printf ("0x%08"PFMT64x" %s0x%08"PFMT64x"%s %s\n",
					(ut64)core->offset+i, a, (ut64)v, b, fn? fn: "");
				free (fn);
			}
			}
			break;
		case 'r': // "pxr"
			if (l != 0) {
				if (input[2] == 'j') {
					int base = core->anal->bits;
					r_cons_printf ("[");
					const char *comma = "";
					const ut8 *buf = core->block;
					int withref = 0;
					for (i=0; i< core->blocksize; i+= (base/4)) {
						ut64 addr = core->offset + i;
						ut64 *foo = (ut64*)(buf+i);
						ut64 val = *foo;
						if (base==32) val &= UT32_MAX;
						r_cons_printf ("%s{\"addr\":%"PFMT64d",\"value\":%" \
								PFMT64d, comma, addr, val);
						comma = ",";
						// XXX: this only works in little endian
						withref = 0;
						if (core->print->hasrefs) {
							const char *rstr = core->print->hasrefs (core->print->user, val);
							if (rstr && *rstr) {
								char *ns; //r_str_ansi_chop (ns, -1, 0);
								ns = r_str_escape (rstr);
								r_cons_printf (",\"ref\":\"%s\"}", *ns==' '?ns+1:ns);
								free (ns);
								withref = 1;
							}
						}
						if (!withref) r_cons_printf ("}");
					}
					r_cons_printf ("]\n");
				} else {
					const int ocols = core->print->cols;
					int bitsize = core->assembler->bits;
					/* Thumb is 16bit arm but handles 32bit data */
					if (bitsize == 16) bitsize = 32;
					core->print->cols = 1;
					core->print->flags |= R_PRINT_FLAGS_REFS;
					r_cons_break (NULL, NULL);
					r_print_hexdump (core->print, core->offset,
							core->block, len,
							bitsize, bitsize / 8);
					r_cons_break_end ();
					core->print->flags &= ~R_PRINT_FLAGS_REFS;
					core->print->cols = ocols;
				}
			}
			break;
		case 'h':
			if (l != 0) {
				r_print_hexdump (core->print, core->offset,
					core->block, len, 32, 2);
			}
			break;
		case 'H':
			if (l != 0) {
			len = len - (len % 2);
			for (i = 0; i < len; i += 2) {
				const char *a, *b;
				char *fn;
				RPrint *p = core->print;
				RFlagItem *f;
				ut64 v = (ut64)r_read_ble16 (core->block + i, p->big_endian);
				if (p && p->colorfor) {
					a = p->colorfor (p->user, v);
					if (a && *a) { b = Color_RESET; } else { a = b = ""; }
				} else { a = b = ""; }
				f = r_flag_get_at (core->flags, v);
				fn = NULL;
				if (f) {
					st64 delta = (v - f->offset);
					if (delta>=0 && delta<8192) {
						if (v == f->offset) {
							fn = strdup (f->name);
						} else fn = r_str_newf ("%s+%d", f->name, v-f->offset);
					}
				}
				r_cons_printf ("0x%08"PFMT64x" %s0x%04"PFMT64x"%s %s\n",
					(ut64)core->offset+i, a, v, b, fn? fn: "");
				free (fn);
			}
			}
			break;
		case 'q':
			if (l != 0) {
				r_print_hexdump (core->print, core->offset, core->block, len, 64, 8);
			}
			break;
		case 'Q':
			// TODO. show if flag name, or inside function
			if (l != 0) {
			len = len - (len % 8);
			for (i = 0; i < len; i += 8) {
				const char *a, *b;
				char *fn;
				RPrint *p = core->print;
				RFlagItem *f;
				ut64 v = r_read_ble64 (core->block + i, p->big_endian);
				if (p && p->colorfor) {
					a = p->colorfor (p->user, v);
					if (a && *a) { b = Color_RESET; } else { a = b = ""; }
				} else { a = b = ""; }
				f = r_flag_get_at (core->flags, v);
				fn = NULL;
				if (f) {
					st64 delta = (v - f->offset);
					if (delta>=0 && delta<8192) {
						if (v == f->offset) {
							fn = strdup (f->name);
						} else fn = r_str_newf ("%s+%d", f->name, v-f->offset);
					}
				}
				r_cons_printf ("0x%08"PFMT64x" %s0x%016"PFMT64x"%s %s\n",
					(ut64)core->offset+i, a, v, b, fn? fn: "");
				free (fn);
			}
			}
			break;
		case 's':
			if (l != 0) {
				core->print->flags |= R_PRINT_FLAGS_SPARSE;
				r_print_hexdump (core->print, core->offset,
					core->block, len, 16, 1);
				core->print->flags &= (((ut32)-1) & (~R_PRINT_FLAGS_SPARSE));
			}
			break;
		case 'e': // "pxe"
			if (l != 0) {
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
				int cols = core->print->cols;
				if (cols < 1) {
					cols = 1;
				}
				for (i = 0; i < len; i += cols) {
					r_print_addr (core->print, core->offset+i);
					for (j = i; j < i + cols; j += 1) {
						ut8 *p = (ut8*)core->block + j;
						if (j<len) {
							r_cons_printf ("\xf0\x9f%c%c  ", emoji[*p*2], emoji[*p*2+1]);
						} else {
							r_cons_print ("   ");
						}
					}
					r_cons_print (" ");
					for (j = i; j < len && j < i + cols; j += 1) {
						ut8 *p = (ut8*)core->block + j;
						r_print_byte (core->print, "%c", j, *p);
					}
					r_cons_newline ();
				}
			}
			break;
		case 'l':
			len = core->print->cols*len;
			/* faltrhou */
		default:
			if (l != 0) {
				ut64 from = r_config_get_i (core->config, "diff.from");
				ut64 to = r_config_get_i (core->config, "diff.to");
				if (from == to && from == 0) {
					if (!r_core_block_size (core, len)) {
						 len = core->blocksize;
					}
					 r_print_hexdump (core->print, core->offset,
							 core->block, len, 16, 1);
				} else {
					 r_core_print_cmp (core, from, to);
				}
				core->num->value = len;
			}
			break;
		}
		r_cons_break_end ();
		break;
	case '2': // "p2"
		if (l != 0) {
			if (input[1] == '?')
				r_cons_printf ("|Usage: p2 [number of bytes representing tiles]\n"
						"NOTE: Only full tiles will be printed\n");
			else r_print_2bpp_tiles (core->print, core->block, len/16);
		}
		break;
	case '6':
		if (l != 0) {
		int malen = (core->blocksize*4)+1;
		ut8 *buf = malloc (malen);
		if (!buf) break;
		memset (buf, 0, malen);
		switch (input[1]) {
		case 'd':
			if (input[2] == '?')
				r_cons_printf ("|Usage: p6d [len]    base 64 decode\n");
			else if (r_base64_decode (buf, (const char *)core->block, len))
				r_cons_println ((const char*)buf);
			else eprintf ("r_base64_decode: invalid stream\n");
			break;
		case 'e':
			if (input[2] == '?') {
				r_cons_printf ("|Usage: p6e [len]    base 64 encode\n");
				break;
			} else {
				len = len > core->blocksize ? core->blocksize : len;
				r_base64_encode ((char *)buf, core->block, len);
				r_cons_println ((const char*)buf);
			}
			break;
		case '?':
		default:
			r_cons_printf ("|Usage: p6[ed] [len]    base 64 encode/decode\n");
			break;
		}
		free (buf);
		}
		break;
	case '8': // "p8"
		if (input[1] == '?') {
			r_cons_printf("|Usage: p8[fj] [len]     8bit hexpair list of bytes (see pcj)\n");
		} else if (l != 0) {
			if (!r_core_block_size (core, len)) {
				len = core->blocksize;
			}
			if (input[1] == 'j') {
				r_core_cmdf (core, "pcj %s", input+2);
			} else if (input[1] == 'f') {
				r_core_cmdf (core, "p8 $F @ $B");
			} else {
				r_print_bytes (core->print, core->block, len, "%02x");
			}
		}
		break;
	case 'f': // "pf"
		cmd_print_format (core, input, len);
		break;
	case 'k': // "pk"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: pk [len]       print key in randomart\n");
		} else if (l > 0) {
			len = len > core->blocksize ? core->blocksize : len;
			char *s = r_print_randomart (core->block, len, core->offset);
			r_cons_println (s);
			free (s);
		}
		break;
	case 'K': // "pK"
		if (input[1] == '?') {
			r_cons_printf ("|Usage: pK [len]       print key in randomart mosaic\n");
		} else if (l > 0) {
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
			r_cons_printf("\n");
		}
		break;
	case 'n': // easter
		eprintf ("easter egg license has expired\n");
		break;
	case 't':
		switch (input[1]) {
		case ' ':
		case '\0':
			//len must be multiple of 4 since r_mem_copyendian move data in fours - sizeof(ut32)
			if (len < sizeof (ut32)) eprintf ("You should change the block size: b %d\n", (int)sizeof (ut32));
			if (len % sizeof (ut32) != 0) len = len - (len % sizeof (ut32));
			for (l=0; l<len; l+=sizeof (ut32))
				r_print_date_unix (core->print, core->block+l, sizeof (ut32));
			break;
		case 'd':
			//len must be multiple of 4 since r_print_date_dos read buf+3
			//if block size is 1 or 5 for example it reads beyond the buffer
			if (len < sizeof (ut32)) eprintf ("You should change the block size: b %d\n", (int)sizeof (ut32));
			if (len % sizeof (ut32) != 0) len = len - (len % sizeof (ut32));
			for (l=0; l<len; l+=sizeof (ut32))
				r_print_date_dos (core->print, core->block+l, sizeof (ut32));
			break;
		case 'n':
			if (len < sizeof (ut64)) eprintf ("You should change the block size: b %d\n", (int)sizeof (ut64));
			if (len % sizeof (ut64) != 0) len = len - (len % sizeof (ut64));
			for (l=0; l<len; l+=sizeof (ut64))
				r_print_date_w32 (core->print, core->block+l, sizeof (ut64));
			break;
		case '?':{
			const char* help_msg[] = {
			"Usage: pt", "[dn]", "print timestamps",
			"pt", "", "print unix time (32 bit `cfg.bigendian`)",
			"ptd","", "print dos time (32 bit `cfg.bigendian`)",
			"ptn","", "print ntfs time (64 bit `cfg.bigendian`)",
			NULL};
			r_core_cmd_help (core, help_msg);
			}
			break;
		}
		break;
	case 'z': // "pz"
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
			int do_zoom = 1;

			core->io->va = 0;
			from = 0;
			to = r_io_size (core->io);
			from = r_config_get_i (core->config, "zoom.from");
			to = r_config_get_i (core->config, "zoom.to");
			if (input[1] && input[1] != ' ') {
				oldzoom = strdup (r_config_get (core->config, "zoom.byte"));
				if (!r_config_set (core->config, "zoom.byte", input+1)) {
					eprintf ("Invalid zoom.byte mode (%s)\n", input+1);
					R_FREE (oldzoom);
					do_zoom = 0;
				}
			}
			if (do_zoom && l > 0) {
				r_print_zoom (core->print, core, printzoomcallback,
					from, to, core->blocksize, (int)maxsize);
			}
			if (oldzoom) {
				r_config_set (core->config, "zoom.byte", oldzoom);
				R_FREE (oldzoom);
			}
			if (oldva) {
				core->io->va = oldva;
			}
		}
		break;
	default: {
		 const char* help_msg[] = {
			 "Usage:", "p[=68abcdDfiImrstuxz] [arg|len] [@addr]", "",
			 "p=","[?][bep] [blks] [len] [blk]","show entropy/printable chars/chars bars",
			 "p2"," [len]", "8x8 2bpp-tiles",
			 "p3"," [file]", "print stereogram (3D)",
			 "p6","[de] [len]", "base64 decode/encode",
			 "p8","[?][j] [len]","8bit hexpair list of bytes",
			 "pa","[edD] [arg]", "pa:assemble  pa[dD]:disasm or pae: esil from hexpairs",
			 "pA","[n_ops]", "show n_ops address and type",
			 "p","[b|B|xb] [len] ([skip])", "bindump N bits skipping M",
			 "pb","[?] [n]","bitstream of N bits",
			 "pB","[?] [n]","bitstream of N bytes",
			 "pc","[p] [len]","output C (or python) format",
			 "pC","[d] [rows]","print disassembly in columns (see hex.cols and pdi)",
			 "pd","[?] [sz] [a] [b]","disassemble N opcodes (pd) or N bytes (pD)",
			 "pf","[?][.nam] [fmt]","print formatted data (pf.name, pf.name $<expr>)",
			 "ph","[?][=|hash] ([len])","calculate hash for a block",
			 "p","[iI][df] [len]", "print N ops/bytes (f=func) (see pi? and pdi)",
			 "pm","[?] [magic]","print libmagic data (see pm? and /m?)",
			 "pr","[glx] [len]","print N raw bytes (in lines or hexblocks, 'g'unzip)",
			 "p","[kK] [len]","print key in randomart (K is for mosaic)",
			 "ps","[pwz] [len]","print pascal/wide/zero-terminated strings",
			 "pt","[?][dn] [len]","print different timestamps",
			 "pu","[?][w] [len]","print N url encoded bytes (w=wide)",
			 "pv","[?][jh] [mode]","show variable/pointer/value in memory",
			 "p-","[jh] [mode]","bar|json|histogram blocks (mode: e?search.in)",
			 "px","[?][owq] [len]","hexdump of N bytes (o=octal, w=32bit, q=64bit)",
			 "pz","[?] [len]","print zoom view (see pz? for help)",
			 "pwd","","display current working directory",
			 NULL
		};
		r_core_cmd_help (core, help_msg);
		}
		break;
	}
beach:
	if (tmpseek != UT64_MAX) {
		r_core_seek (core, tmpseek, SEEK_SET);
	}
	if (tbs != core->blocksize) {
		r_core_block_size (core, tbs);
	}
	return ret;
}

static int cmd_hexdump(void *data, const char *input) {
	return cmd_print (data, input-1);
}

static int lenof (ut64 off, int two) {
	char buf[64];
	buf[0] = 0;
	if (two) snprintf (buf, sizeof (buf), "+0x%"PFMT64x, off);
	else snprintf (buf, sizeof (buf), "0x%08"PFMT64x, off);

	return strlen (buf);
}

// TODO : move to r_util? .. depends on r_cons...
// XXX: dupe of r_print_addr
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int offseg, int offdec, int delta, const char *label) {
	char space[32] = { 0 };
	const char *white;
	bool show_color = p->flags & R_PRINT_FLAGS_COLOR;
	if (show_color) {
		const char *k = r_cons_singleton ()->pal.offset; // TODO etooslow. must cache
		if (invert) {
			r_cons_invert (true, true);
		}
		if (offseg) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off - a) >> 4;
			if (offdec) {
				snprintf (space, sizeof (space), "%d:%d", s & 0xffff, a & 0xffff);
				white = r_str_pad (' ', 9 - strlen (space));
				r_cons_printf ("%s%s%s"Color_RESET, k, white, space);
			} else {
				r_cons_printf ("%s%04x:%04x"Color_RESET,
						k, s & 0xFFFF, a & 0xFFFF);
			}
		} else {
			int sz = lenof (off, 0);
			int sz2 = lenof (delta, 1);
			if (delta > 0 || label) {
				if (label) {
					const int label_padding = 10;
					if (delta > 0) {
						if (offdec) {
							const char *pad = r_str_pad (' ', sz - sz2 + label_padding);
							r_cons_printf ("%s%s"Color_RESET"+%d%s", k, label, delta, pad);
						} else {
							const char *pad = r_str_pad (' ', sz - sz2 + label_padding);
							r_cons_printf ("%s%s"Color_RESET"+0x%x%s", k, label, delta, pad);
						}
					} else {
						const char *pad = r_str_pad (' ', sz + label_padding);
						r_cons_printf ("%s%s"Color_RESET"%s", k, label, pad);
					}
				} else {
					const char *pad = r_str_pad (' ', sz - sz2);
					if (offdec) {
						r_cons_printf ("%s+%d"Color_RESET, pad, delta);
					} else {
						r_cons_printf ("%s+0x%x"Color_RESET, pad, delta);
					}
				}
			} else {
				if (offdec) {
					snprintf (space, sizeof (space), "%"PFMT64d, off);
					white = r_str_pad (' ', 10 - strlen (space));
					r_cons_printf ("%s%s%s"Color_RESET, k, white, space, off);
				} else {
					r_cons_printf ("%s0x%08"PFMT64x""Color_RESET, k, off);
				}
			}
		}
		r_cons_print (" ");
	} else {
		if (offseg) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off - a) >> 4;
			if (offdec) {
				snprintf (space, sizeof (space), "%d:%d", s & 0xffff, a & 0xffff);
				white = r_str_pad (' ', 9 - strlen (space));
				r_cons_printf ("%s%s"Color_RESET, white, space);
			} else {
				r_cons_printf ("%04x:%04x", s & 0xFFFF, a & 0xFFFF);
			}
		} else {
			int sz = lenof (off, 0);
			int sz2 = lenof (delta, 1);
			const char *pad = r_str_pad (' ', sz - 5 - sz2 - 3);
			if (delta > 0) {
				if (offdec) {
					r_cons_printf ("%s+%d"Color_RESET, pad, delta);
				} else {
					r_cons_printf ("%s+0x%x"Color_RESET, pad, delta);
				}
			} else {
				if (offdec) {
					snprintf (space, sizeof (space), "%"PFMT64d, off);
					white = r_str_pad (' ', 10 - strlen (space));
					r_cons_printf ("%s%s", white, space);
				} else {
					r_cons_printf ("0x%08"PFMT64x" ", off);
				}
			}
		}
	}
}
