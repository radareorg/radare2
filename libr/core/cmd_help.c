/* radare - LGPL - Copyright 2009-2016 - pancake */

#include <stddef.h>
#include "r_cons.h"
#include "r_core.h"
#include "r_util.h"

static const char* findBreakChar(const char *s) {
	while (*s) {
		if (!r_name_validate_char (*s)) {
			break;
		}
		s++;
	}
	return s;
}

static char *filterFlags(RCore *core, const char *msg) {
	const char *dollar, *end;
	char *word, *buf = NULL;
	for (;;) {
		dollar = strchr (msg, '$');
		if (!dollar) {
			break;
		}
		buf = r_str_concatlen (buf, msg, dollar-msg);
		if (dollar[1]=='{') {
			// find }
			end = strchr (dollar+2, '}');
			if (end) {
				word = r_str_newlen (dollar+2, end-dollar-2);
				end++;
			} else {
				msg = dollar+1;
				buf = r_str_concat (buf, "$");
				continue;
			}
		} else {
			end = findBreakChar (dollar+1);
			if (!end) {
				end = dollar + strlen (dollar);
			}
			word = r_str_newlen (dollar+1, end-dollar-1);
		}
		if (end && word) {
			ut64 val = r_num_math (core->num, word);
			char num[32];
			snprintf (num, sizeof (num), "0x%"PFMT64x, val);
			buf = r_str_concat (buf, num);
			msg = end;
		} else {
			break;
		}
		free (word);
	}
	buf = r_str_concat (buf, msg);
	return buf;
}

R_API void r_core_clippy(const char *msg) {
	int msglen = strlen (msg);
	char *l = strdup (r_str_pad ('-', msglen));
	char *s = strdup (r_str_pad (' ', msglen));
	r_cons_printf (
" .--.     .-%s-.\n"
" | _|     | %s |\n"
" | O O   <  %s |\n"
" |  |  |  | %s |\n"
" || | /   `-%s-'\n"
" |`-'|\n"
" `---'\n", l, s, msg, s, l);
	free (l);
	free (s);
}

static int cmd_help(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *k;
	char *p, out[128] = {0};
	ut64 n, n2;
	int i;
	RList *tmp;

	switch (input[0]) {
	case '0':
		core->curtab = 0;
		break;
	case '1':
		if (core->curtab < 0) {
			core->curtab = 0;
		}
		core->curtab ++;
		break;
	case ':':
		{
		RListIter *iter;
		RCorePlugin *cp;
		if (input[1]=='?') {
			const char* help_msg[] = {
				"Usage:", ":[plugin] [args]", "",
				":", "", "list RCore plugins",
				":java", "", "run java plugin",
				NULL};
			r_core_cmd_help (core, help_msg);
			return 0;
		}
		if (input[1]) {
			return r_core_cmd0 (core, input + 1);
		}
		r_list_foreach (core->rcmd->plist, iter, cp) {
			r_cons_printf ("%s: %s\n", cp->name, cp->desc);
		}
	}
		break;
	case 'r':
		{ // TODO : Add support for 64bit random numbers
		ut64 b = 0;
		ut32 r = UT32_MAX;
		if (input[1]) {
			strncpy (out, input+(input[1]==' '? 2: 1), sizeof (out)-1);
			p = strchr (out+1, ' ');
			if (p) {
				*p = 0;
				b = (ut32)r_num_math (core->num, out);
				r = (ut32)r_num_math (core->num, p+1)-b;
			} else {
				r = (ut32)r_num_math (core->num, out);
			}
		} else {
			r = 0LL;
		}
		if (!r) {
			r = UT32_MAX >> 1;
		}
		core->num->value = (ut64) (b + r_num_rand (r));
		r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case 'b':
		if (input[1] == '6' && input[2] == '4') {
			//b64 decoding takes at most strlen(str) * 4
			const int buflen = (strlen (input+3) * 4) + 1;
			char* buf = calloc (buflen, sizeof(char));
			if (!buf) {
				return false;
			}
			if (input[3] == '-') {
				r_base64_decode ((ut8*)buf, input + 5, strlen (input + 5));
			} else {
				r_base64_encode (buf, (const ut8*)input + 4, strlen (input + 4));
			}
			r_cons_println (buf);
			free (buf);
		} else {
			n = r_num_get (core->num, input+1);
			r_num_to_bits (out, n);
			r_cons_printf ("%sb\n", out);
		}
		break;
	case 'B':
		k = r_str_chop_ro (input+1);
		tmp = r_core_get_boundaries (core, k, &n, &n2);
		r_cons_printf ("0x%"PFMT64x" 0x%"PFMT64x"\n", n, n2);
		r_list_free (tmp);
		break;
	case 'd':
		if (input[1]=='.') {
			int cur = R_MAX(core->print->cur, 0);
			// XXX: we need cmd_xxx.h (cmd_anal.h)
			core_anal_bytes(core, core->block + cur, core->blocksize, 1, 'd');
		} else if (input[1]==' '){
			char *d = r_asm_describe (core->assembler, input+2);
			if (d && *d) {
				r_cons_println (d);
				free (d);
			} else {
				eprintf ("Unknown opcode\n");
			}
		} else {
			eprintf ("Use: ?d[.] [opcode]    to get the description of the opcode\n");
		}
		break;
	case 'h':
		if (input[1]==' ') {
			r_cons_printf ("0x%08x\n", (ut32)r_str_hash (input+2));
		} else {
			eprintf ("Usage: ?h [string-to-hash]\n");
		}
		break;
	case 'y':
		for (input++; input[0]==' '; input++);
		if (*input) {
			r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, input, strlen (input)+1);
		} else {
			r_core_yank_cat (core, 0);
		}
		break;
	case 'F':
		r_cons_flush ();
		break;
	case 'f':
		if (input[1] == ' ') {
			char *q, *p = strdup (input + 2);
			if (!p) {
				eprintf ("Cannot strdup\n");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n) * 8, q + 1);
				r_cons_println (out);
			} else {
				eprintf ("Usage: \"?b value bitstring\"\n");
			}
			free (p);
		} else {
			eprintf ("Whitespace expected after '?f'\n");
		}
		break;
	case 'o':
		n = r_num_math (core->num, input+1);
		r_cons_printf ("0%"PFMT64o"\n", n);
		break;
	case 'O':
		if (input[1] == '?') {
			r_cons_printf ("Usage: ?O[jd] [arg] .. list all mnemonics for asm.arch (d = describe, j=json)\n");
		} else if (input[1] == 'd') {
			const int id = (input[2]==' ')
				?(int)r_num_math (core->num, input + 2): -1;
			char *ops = r_asm_mnemonics (core->assembler, id, false);
			if (ops) {
				char *ptr = ops;
				char *nl = strchr (ptr, '\n');
				while (nl) {
					*nl = 0;
					char *desc = r_asm_describe (core->assembler, ptr);
					if (desc) {
						const char *pad = r_str_pad (' ', 16 - strlen (ptr));
						r_cons_printf ("%s%s%s\n", ptr, pad, desc);
						free (desc);
					} else {
						r_cons_printf ("%s\n", ptr);
					}
					ptr = nl + 1;
					nl = strchr (ptr, '\n');
				}
				free (ops);
			}
		} else if (input[1] && !IS_DIGIT (input[2])) {
			r_cons_printf ("%d\n", r_asm_mnemonics_byname (core->assembler, input + 2));
		} else {
			bool json = false;
			if (input[1] == 'j') {
				json = true;
			}
			const int id = (input[2]== ' ')
				?(int)r_num_math (core->num, input + 2): -1;
			char *ops = r_asm_mnemonics (core->assembler, id, json);
			if (ops) {
				r_cons_print (ops);
				free (ops);
			}
		}
		break;
	case 'T':
		r_cons_printf("plug.init = %"PFMT64d"\n"
			"plug.load = %"PFMT64d"\n"
			"file.load = %"PFMT64d"\n",
			core->times->loadlibs_init_time,
			core->times->loadlibs_time,
			core->times->file_open_time);
		break;
	case 'u':
		{
			char unit[32];
			n = r_num_math (core->num, input+1);
			r_num_units (unit, n);
			r_cons_println (unit);
		}
		break;
	case ' ':
		{
			char *asnum, unit[32];
			ut32 s, a;
			double d;
			float f;
			n = r_num_math (core->num, input + 1);
			if (core->num->dbz) {
				eprintf ("RNum ERROR: Division by Zero\n");
			}
			asnum  = r_num_as_string (NULL, n, false);
			/* decimal, hexa, octal */
			s = n >> 16 << 12;
			a = n & 0x0fff;
			r_num_units (unit, n);
			r_cons_printf ("%"PFMT64d" 0x%"PFMT64x" 0%"PFMT64o
				" %s %04x:%04x ",
				n, n, n, unit, s, a);
			if (n >> 32) {
				r_cons_printf ("%"PFMT64d" ", (st64)n);
			} else {
				r_cons_printf ("%d ", (st32)n);
			}
			if (asnum) {
				r_cons_printf ("\"%s\" ", asnum);
				free (asnum);
			}
			/* binary and floating point */
			r_str_bits64 (out, n);
			f = d = core->num->fvalue;
			r_cons_printf ("%s %.01lf %ff %lf\n", out, core->num->fvalue, f, d);
		}
		break;
	case 'v':
		{
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else {
				n = r_num_math (core->num, "$?");
			}
		}
		if (core->num->dbz) {
			eprintf ("RNum ERROR: Division by Zero\n");
		}
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: ?v[id][ num]  # Show value\n"
				"|?vi1 200    -> 1 byte size value (char)\n"
				"|?vi2 0xffff -> 2 byte size value (short)\n"
				"|?vi4 0xffff -> 4 byte size value (int)\n"
				"|?vi8 0xffff -> 8 byte size value (st64)\n"
				"| No argument shows $? value\n"
				"|?vi will show in decimal instead of hex\n");
			break;
		case '\0':
			r_cons_printf ("%d\n", (st32)n);
			break;
		case 'i': // "?vi"
			switch (input[2]) {
			case '1': // byte
				r_cons_printf ("%d\n", (st8)(n & UT8_MAX));
				break;
			case '2': // word
				r_cons_printf ("%d\n", (st16)(n & UT16_MAX));
				break;
			case '4': // dword
				r_cons_printf ("%d\n", (st32)(n & UT32_MAX));
				break;
			case '8': // qword
				r_cons_printf ("%"PFMT64d"\n", (st64)(n & UT64_MAX));
				break;
			default:
				r_cons_printf ("%"PFMT64d"\n", n);
				break;
			}
			break;
		case 'd':
			r_cons_printf ("%"PFMT64d"\n", n);
			break;
		default:
			r_cons_printf ("0x%"PFMT64x"\n", n);
		}
		core->num->value = n; // redundant
		break;
	case '=': // set num->value
		if (input[1]) {
			r_num_math (core->num, input+1);
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '+':
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n > 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '-':
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n < 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '!': // "?!"
		if (input[1]) {
			if (!core->num->value) {
				if (input[1] == '?') {
					r_core_sysenv_help (core);
					return 0;
				} else {
					return core->num->value = r_core_cmd (core, input+1, 0);
				}
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '@':
		{
		const char* help_msg[] = {
			"Usage: [.][#]<cmd>[*] [`cmd`] [@ addr] [~grep] [|syscmd] [>[>]file]", "", "",
			"0", "", "alias for 's 0'",
			"0x", "addr", "alias for 's 0x..'",
			"#", "cmd", "if # is a number repeat the command # times",
			"/*", "", "start multiline comment",
			"*/", "", "end multiline comment",
			".", "cmd", "execute output of command as r2 script",
			".:", "8080", "wait for commands on port 8080",
			".!", "rabin2 -re $FILE", "run command output as r2 script",
			"*", "", "output of command in r2 script format (CC*)",
			"j", "", "output of command in JSON format (pdj)",
			"~", "?", "count number of lines (like wc -l)",
			"~", "??", "show internal grep help",
			"~", "..", "internal less",
			"~", "{}", "json indent",
			"~", "{}..", "json indent and less",
			"~", "word", "grep for lines matching word",
			"~", "!word", "grep for lines NOT matching word",
			"~", "word[2]", "grep 3rd column of lines matching word",
			"~", "word:3[0]", "grep 1st column from the 4th line matching word",
			"@", " 0x1024", "temporary seek to this address (sym.main+3)",
			"@", " addr[!blocksize]", "temporary set a new blocksize",
			"@a:", "arch[:bits]", "temporary set arch and bits",
			"@b:", "bits", "temporary set asm.bits",
			"@e:", "k=v,k=v", "temporary change eval vars",
			"@r:", "reg", "tmp seek to reg value (f.ex pd@r:PC)",
			"@i:", "nth.op", "temporary seek to the Nth relative instruction",
			"@f:", "file", "temporary replace block with file contents",
			"@o:", "fd", "temporary switch to another fd",
			"@s:", "string", "same as above but from a string",
			"@x:", "909192", "from hex pairs string",
			"@..", "from to", "temporary set from and to for commands supporting ranges",
			"@@=", "1 2 3", "run the previous command at offsets 1, 2 and 3",
			"@@", " hit*", "run the command on every flag matching 'hit*'",
			"@@?", "[ktfb..]", "show help for the iterator operator",
			"@@@", " [type]", "run a command on every [type] (see @@@? for help)",
			">", "file", "pipe output of command to file",
			">>", "file", "append to file",
			"H>", "file", "pipe output of command to file in HTML",
			"H>>", "file", "append to file with the output of command in HTML",
			"`", "pdi~push:0[0]`",  "replace output of command inside the line",
			"|", "cmd", "pipe output to command (pd|less) (.dr*)",
			NULL};
		r_core_cmd_help (core, help_msg);
		return 0;
		}
	case '$':
		if (input[1] == '?') {
			const char* help_msg[] = {
			"Usage: ?v [$.]","","",
			"$$", "", "here (current virtual seek)",
			"$?", "", "last comparison value",
			"$alias", "=value", "Alias commands (simple macros)",
			"$b", "", "block size",
			"$B", "", "base address (aligned lowest map address)",
			"$f", "", "jump fail address (e.g. jz 0x10 => next instruction)",
			"$fl", "", "flag length (size) at current address (fla; pD $l @ entry0)",
			"$F", "", "current function size",
			"$FB", "", "begin of function",
			"$Fb", "", "address of the current basic block",
			"$Fs", "", "size of the current basic block",
			"$FE", "", "end of function",
			"$FS", "", "function size",
			"$FI", "", "function instructions",
			"$c,$r", "", "get width and height of terminal",
			"$Cn", "", "get nth call of function",
			"$Dn", "", "get nth data reference in function",
			"$D", "", "current debug map base address ?v $D @ rsp",
			"$DD", "", "current debug map size",
			"$e", "", "1 if end of block, else 0",
			"$j", "", "jump address (e.g. jmp 0x10, jz 0x10 => 0x10)",
			"$Ja", "", "get nth jump of function",
			"$Xn", "", "get nth xref of function",
			"$l", "", "opcode length",
			"$m", "", "opcode memory reference (e.g. mov eax,[0x10] => 0x10)",
			"$M", "", "map address (lowest map address)",
			"$o", "", "here (current disk io offset)",
			"$p", "", "getpid()",
			"$P", "", "pid of children (only in debug)",
			"$s", "", "file size",
			"$S", "", "section offset",
			"$SS", "", "section size",
			"$v", "", "opcode immediate value (e.g. lui a0,0x8010 => 0x8010)",
			"$w", "", "get word size, 4 if asm.bits=32, 8 if 64, ...",
			"${ev}", "", "get value of eval config variable",
			"$k{kv}", "", "get value of an sdb query value",
			"RNum", "", "$variables usable in math expressions",
			NULL};
			r_core_cmd_help (core, help_msg);
		} else {
			int i = 0;
			const char *vars[] = {
				"$$", "$?", "$b", "$B", "$F", "$FB", "$Fb", "$Fs", "$FE", "$FS", "$FI",
				"$c", "$r", "$D", "$DD", "$e", "$f", "$j", "$Ja", "$l", "$m", "$M", "$o",
				"$p", "$P", "$s", "$S", "$SS", "$v", "$w", NULL
			};
			while (vars[i]) {
				const char *pad = r_str_pad (' ', 6 - strlen (vars[i]));
				eprintf ("%s %s 0x%08"PFMT64x"\n", vars[i], pad, r_num_math (core->num, vars[i]));
				i++;
			}
		}
		return true;
	case 'V':
		switch (input[1]) {
		case '?':
			{
				const char* help_msg[] = {
					"Usage: ?V[jq]","","",
					"?V", "", "show version information",
					"?Vj", "", "same as above but in JSON",
					"?Vq", "", "quiet mode, just show the version number",
					NULL};
				r_core_cmd_help (core, help_msg);
			}
			break;
		case 0:
#if R2_VERSION_COMMIT == 0
			r_cons_printf ("%s release\n", R2_VERSION);
#else
			if (!strcmp (R2_VERSION, R2_GITTAP)) {
				r_cons_printf ("%s %d\n", R2_VERSION, R2_VERSION_COMMIT);
			} else {
				r_cons_printf ("%s aka %s commit %d\n", R2_VERSION, R2_GITTAP, R2_VERSION_COMMIT);
			}
#endif
			break;
		case 'j':
			r_cons_printf ("{\"system\":\"%s-%s\"", R_SYS_OS, R_SYS_ARCH);
			r_cons_printf (",\"version\":\"%s\"}\n",  R2_VERSION);
			break;
		case 'q':
			r_cons_println (R2_VERSION);
			break;
		}
		break;
	case 'l':
		for (input++; input[0] == ' '; input++);
		core->num->value = strlen (input);
		break;
	case 'X':
		for (input++; input[0] == ' '; input++);
		n = r_num_math (core->num, input);
		r_cons_printf ("%"PFMT64x"\n", n);
		break;
	case 'x':
		for (input++; input[0] == ' '; input++);
		if (*input == '-') {
			ut8 *out = malloc (strlen (input)+1);
			int len = r_hex_str2bin (input+1, out);
			out[len] = 0;
			r_cons_println ((const char*)out);
			free (out);
		} else if (*input == '+') {
			ut64 n = r_num_math (core->num, input);
			int bits = r_num_to_bits (NULL, n) / 8;
			for (i = 0; i < bits; i++) {
				r_cons_printf ("%02x", (ut8)((n >> (i * 8)) &0xff));
			}
			r_cons_newline ();
		} else {
			if (*input == ' ') {
				input++;
			}
			for (i = 0; input[i]; i++) {
				r_cons_printf ("%02x", input[i]);
			}
			r_cons_newline ();
		}
		break;
	case 'E': // clippy echo
		r_core_clippy (r_str_chop_ro (input + 1));
		break;
	case 'e': // echo
		{
		if (input[1] == 's') { // say
			char *msg = strdup (input + 2);
			msg = r_str_chop (msg);
			char *p = strchr (msg, '&');
			if (p) *p = 0;
			r_sys_tts (msg, p != NULL);
			free (msg);
		} else
		if (input[1] == 'n') { // mimic echo -n
			const char *msg = r_str_chop_ro (input+2);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_print (newmsg);
			free (newmsg);
		} else {
			const char *msg = r_str_chop_ro (input+1);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_println (newmsg);
			free (newmsg);
		}
		}
		break;
	case 's': // sequence from to step
		{
		ut64 from, to, step;
		char *p, *p2;
		for (input++; *input==' '; input++);
		p = strchr (input, ' ');
		if (p) {
			*p = '\0';
			from = r_num_math (core->num, input);
			p2 = strchr (p+1, ' ');
			if (p2) {
				*p2 = '\0';
				step = r_num_math (core->num, p2 + 1);
			} else {
				step = 1;
			}
			to = r_num_math (core->num, p + 1);
			for (;from <= to; from += step)
				r_cons_printf ("%"PFMT64d" ", from);
			r_cons_newline ();
		}
		}
		break;
	case 'P':
		if (core->io->va) {
			SdbList *secs;
			RIOSection *sec;
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			secs = r_io_section_get_secs_at (core->io, n);
			sec = secs ? (RIOSection *)ls_pop (secs) : NULL;
			ls_free (secs);
			if (sec) {
				o = n + sec->vaddr - sec->addr;
				r_cons_printf ("0x%08"PFMT64x"\n", o);
			} else 	eprintf ("no sections at 0x%08"PFMT64x"\n", n);
		} else eprintf ("io.va is false\n");
		break;
	case 'p':
		if (core->io->va) {
			// physical address
			SdbList *secs;
			RIOSection *sec;
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			secs = r_io_section_vget_secs_at (core->io, n);
			sec = secs ? ls_pop (secs) : NULL;
			ls_free (secs);
			if (sec) {
				o = n - sec->vaddr + sec->addr;
				r_cons_printf ("0x%08"PFMT64x"\n", o);
			} else eprintf ("no section at 0x%08"PFMT64x"\n", n);
		} else eprintf ("Virtual addresses not enabled!\n");
		break;
	case 'S': {
		// section name
		RIOSection *s;
		SdbList *sections;
		SdbListIter *iter;
		ut64 n = (input[0] && input[1])?
			r_num_math (core->num, input+2): core->offset;
#if 0
		n = r_io_section_vaddr_to_maddr_try (core->io, n);
		s = r_io_section_mget_in (core->io, n);
		if (s && *(s->name)) {
			r_cons_println (s->name);
		}
#endif
		if ((sections = r_io_section_get_secs_at (core->io, n))) {
			ls_foreach (sections, iter, s)
				r_cons_printf ("%s\n", s->name);
			ls_free (sections);
		}
		break;
		}
	case '_': // hud input
		r_core_yank_hud_file (core, input+1);
		break;
	case 'i': // "?i" input num
		r_cons_set_raw(0);
		if (!r_config_get_i (core->config, "scr.interactive")) {
			eprintf ("Not running in interactive mode\n");
		} else {
			switch (input[1]) {
			case 'f': // "?if"
				core->num->value = !r_num_conditional (core->num, input + 2);
				eprintf ("%s\n", r_str_bool (!core->num->value));
				break;
			case 'm':
				r_cons_message (input+2);
				break;
			case 'p': 
				core->num->value = r_core_yank_hud_path (core, input + 2, 0) == true;
				break;
			case 'k': // "?ik"
				 r_cons_any_key (NULL);
				 break;
			case 'y': // "?iy"
				 for (input += 2; *input==' '; input++);
				 core->num->value = r_cons_yesno (1, "%s? (Y/n)", input);
				 break;
			case 'n': // "?in"
				 for (input += 2; *input==' '; input++);
				 core->num->value = r_cons_yesno (0, "%s? (y/N)", input);
				 break;
			default: 
				{
				char foo[1024];
				r_cons_flush ();
				for (input++; *input == ' '; input++);
				// TODO: r_cons_input()
				snprintf (foo, sizeof (foo) - 1, "%s: ", input);
				r_line_set_prompt (foo);
				r_cons_fgets (foo, sizeof (foo)-1, 0, NULL);
				foo[strlen (foo)] = 0;
				r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, foo, strlen (foo) + 1);
				core->num->value = r_num_math (core->num, foo);
				}
				break;
			}
		}
		r_cons_set_raw (0);
		break;
	case 'w':
		{
		ut64 addr = r_num_math (core->num, input + 1);
		const char *rstr = core->print->hasrefs (core->print->user, addr, true);
		r_cons_println (rstr);
		}
		break;
	case 't': {
		struct r_prof_t prof;
		r_prof_start (&prof);
		r_core_cmd (core, input + 1, 0);
		r_prof_end (&prof);
		core->num->value = (ut64)(int)prof.result;
		eprintf ("%lf\n", prof.result);
		} break;
	case '?': // "??" "???"
		if (input[1]=='?') {
			if (input[2]=='?') {
				r_core_clippy ("What are you doing?");
				return 0;
			}
			if (input[2]) {
				if (core->num->value) {
					r_core_cmd (core, input + 1, 0);
				}
				break;
			}
			const char* help_msg[] = {
			"Usage: ?[?[?]] expression", "", "",
			"?", " eip-0x804800", "show hex and dec result for this math expr",
			"?:", "", "list core cmd plugins",
			"?!", " [cmd]", "? != 0",
			"?+", " [cmd]", "? > 0",
			"?-", " [cmd]", "? < 0",
			"?=", " eip-0x804800", "hex and dec result for this math expr",
			"?$", "", "show value all the variables ($)",
			"??", "", "show value of operation",
			"??", " [cmd]", "? == 0 run command when math matches",
			"?B", " [elem]", "show range boundaries like 'e?search.in",
			"?P", " paddr", "get virtual address for given physical one",
			"?S", " addr", "return section name of given address",
			"?T", "", "show loading times",
			"?V", "", "show library version of r_core",
			"?X", " num|expr", "returns the hexadecimal value numeric expr",
			"?_", " hudfile", "load hud menu with given file",
			"?b", " [num]", "show binary value of number",
			"?b64[-]", " [str]", "encode/decode in base64",
			"?d[.]", " opcode", "describe opcode for asm.arch",
			"?e[n]", " string", "echo string, optionally without trailing newline",
			"?f", " [num] [str]", "map each bit of the number as flag string index",
			"?h", " [str]", "calculate hash for given string",
			"?i", "[ynmkp] arg", "prompt for number or Yes,No,Msg,Key,Path and store in $$?",
			"?ik", "", "press any key input dialog",
			"?im", " message", "show message centered in screen",
			"?in", " prompt", "noyes input prompt",
			"?iy", " prompt", "yesno input prompt",
			"?l", " str", "returns the length of string",
			"?o", " num", "get octal value",
			"?O", " [id]", "List mnemonics for current asm.arch / asm.bits",
			"?p", " vaddr", "get physical address for given virtual address",
			"?r", " [from] [to]", "generate random number between from-to",
			"?s", " from to step", "sequence of numbers from to by steps",
			"?t", " cmd", "returns the time to run a command",
			"?u", " num", "get value in human units (KB, MB, GB, TB)",
			"?v", " eip-0x804800", "show hex value of math expr",
			"?vi", " rsp-rbp", "show decimal value of math expr",
			"?w", " addr", "show what's in this address (like pxr/pxq does)",
			"?x", "+num", "like ?v, but in hexpairs honoring cfg.bigendian",
			"?x", " str", "returns the hexpair of number or string",
			"?x", "-hexst", "convert hexpair into raw string with newline",
			"?y", " [str]", "show contents of yank buffer, or set with string",
			NULL};
			r_core_cmd_help (core, help_msg);
			return 0;
		} else if (input[1]) {
			if (core->num->value) {
				core->num->value = r_core_cmd (core, input+1, 0);
			}
		} else {
			if (core->num->dbz) {
				eprintf ("RNum ERROR: Division by Zero\n");
			}
			r_cons_printf ("%"PFMT64d"\n", core->num->value);
		}
		break;
	case '\0':
	default:{
		const char* help_message[] = {
		"%var", "=value", "Alias for 'env' command",
		"*", "[?] off[=[0x]value]", "Pointer read/write data/values (see ?v, wx, wv)",
		"(macro arg0 arg1)",  "", "Manage scripting macros",
		".", "[?] [-|(m)|f|!sh|cmd]", "Define macro or load r2, cparse or rlang file",
		"=","[?] [cmd]", "Send/Listen for Remote Commands (rap://, http://, <fd>)",
		"/","[?]", "Search for bytes, regexps, patterns, ..",
		"!","[?] [cmd]", "Run given command as in system(3)",
		"#","[?] !lang [..]", "Hashbang to run an rlang script",
		"a","[?]", "Analysis commands",
		"b","[?]", "Display or change the block size",
		"c","[?] [arg]", "Compare block with given data",
		"C","[?]", "Code metadata (comments, format, hints, ..)",
		"d","[?]", "Debugger commands",
		"e","[?] [a[=b]]", "List/get/set config evaluable vars",
		"f","[?] [name][sz][at]", "Add flag at current address",
		"g","[?] [arg]", "Generate shellcodes with r_egg",
		"i","[?] [file]", "Get info about opened file from r_bin",
		"k","[?] [sdb-query]", "Run sdb-query. see k? for help, 'k *', 'k **' ...",
		"m","[?]", "Mountpoints commands",
		"o","[?] [file] ([offset])", "Open file at optional address",
		"p","[?] [len]", "Print current block with format and length",
		"P","[?]", "Project management utilities",
		"q","[?] [ret]", "Quit program with a return value",
		"r","[?] [len]", "Resize file",
		"s","[?] [addr]", "Seek to address (also for '0x', '0x1' == 's 0x1')",
		"S","[?]", "Io section manipulation information",
		"t","[?]", "Types, noreturn, signatures, C parser and more",
		"T","[?] [-] [num|msg]", "Text log utility",
		"u","[?]", "uname/undo seek/write",
		"V","", "Enter visual mode (V! = panels, VV = fcngraph, VVV = callgraph)",
		"w","[?] [str]", "Multiple write operations",
		"x","[?] [len]", "Alias for 'px' (print hexadecimal)",
		"y","[?] [len] [[[@]addr", "Yank/paste bytes from/to memory",
		"z", "[?]", "Zignatures management",
		"?[??]","[expr]", "Help or evaluate math expression",
		"?$?", "", "Show available '$' variables and aliases",
		"?@?", "", "Misc help for '@' (seek), '~' (grep) (see ~?""?)",
		"?:?", "", "List and manage core plugins",
		NULL
		};
		r_cons_printf("Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...\n"
			"Append '?' to any char command to get detailed help\n"
			"Prefix with number to repeat command N times (f.ex: 3x)\n");
		r_core_cmd_help (core, help_message);
		}
		break;
	}
	return 0;
}
