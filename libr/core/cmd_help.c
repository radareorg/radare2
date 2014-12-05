/* radare - LGPL - Copyright 2009-2014 - pancake */

static int cmd_help(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *k;
	char *p, out[128];
	ut64 n, n2;
	int i;
	RList *tmp;

	switch (input[0]) {
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
			} else r = (ut32)r_num_math (core->num, out);
		} else r = 0LL;
		if (r == 0)
			r = UT32_MAX>>1;
		core->num->value = (ut64) (b + r_num_rand (r));
		r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case 'b':
		if (input[1] == '6' && input[2] == '4') {
			//b64 decoding takes at most strlen(str) * 4
			const int buflen = (strlen (input+3) * 4) + 1;
			ut8* buf = calloc (buflen, sizeof(char));
			if (!buf)
				return R_FALSE;
			if (input[3] == '-')
				r_base64_decode (buf, input+5, strlen (input+5));
			else r_base64_encode (buf, (const ut8*)input+4, strlen (input+4));
			r_cons_printf ("%s\n", buf);
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
		if (input[1]==' '){
			char *d = r_asm_describe (core->assembler, input+2);
			if (d && *d) {
				r_cons_printf ("%s\n", d);
				free (d);
			} else eprintf ("Unknown opcode\n");
		} else eprintf ("Use: ?d [opcode]    to get the description of the opcode\n");
		break;
	case 'h':
		if (input[1]==' ') {
			r_cons_printf ("0x%08x\n", (ut32)r_str_hash (input+2));
		} else eprintf ("Usage: ?h [string-to-hash]\n");
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
		if (input[1]==' ') {
			char *q, *p = strdup (input+2);
			if (!p) {
				eprintf ("Cannot strdup\n");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n), q+1);
				r_cons_printf ("%s\n", out);
			} else eprintf ("Usage: \"?b value bitstring\"\n");
			free (p);
		} else eprintf ("Whitespace expected after '?f'\n");
		break;
	case 'o':
		n = r_num_math (core->num, input+1);
		r_cons_printf ("0%"PFMT64o"\n", n);
		break;
	case 'u':
		{
			char unit[32];
			n = r_num_math (core->num, input+1);
			r_num_units (unit, n);
			r_cons_printf ("%s\n", unit);
		}
		break;
	case ' ':
		{
			char *asnum, unit[32];
			ut32 n32, s, a;
			float f;

			n = r_num_math (core->num, input+1);
			if (core->num->dbz) {
				eprintf ("RNum ERROR: Division by Zero\n");
			}
			asnum  = r_num_as_string (NULL, n);
			n32 = (ut32)n;
			memcpy (&f, &n32, sizeof (f));
			/* decimal, hexa, octal */
			s = n>>16<<12;
			a = n & 0x0fff;
			r_num_units (unit, n);
			r_cons_printf ("%"PFMT64d" 0x%"PFMT64x" 0%"PFMT64o
				" %s %04x:%04x ",
				n, n, n, unit, s, a);
			if (n>>32) r_cons_printf ("%"PFMT64d" ", (st64)n);
			else r_cons_printf ("%d ", (st32)n);
			if (asnum) {
				r_cons_printf ("\"%s\" ", asnum);
				free (asnum);
			}
			/* binary and floating point */
			r_str_bits (out, (const ut8*)&n, sizeof (n), NULL);
			r_cons_printf ("%s %.01lf %f\n", out, core->num->fvalue, f);
		}
		break;
	case 'v':
		n = (input[1] != '\0') ? r_num_math (core->num, input+2) : 0;
		if (core->num->dbz) {
			eprintf ("RNum ERROR: Division by Zero\n");
		}
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: ?v[id][ num]  # Show value\n"
				"| No argument shows $? value\n"
				"|?vi will show in decimal instead of hex\n");
			break;
		case '\0':
			r_cons_printf ("%d\n", core->num->value);
			break;
		case 'i':
			if (n>>32) r_cons_printf ("%"PFMT64d"\n", (st64)n);
			else r_cons_printf ("%d\n", (st32)n);
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
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '+':
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n>0) r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '-':
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n<0) r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		break;
	case '!': // ??
		if (input[1]) {
			if (!core->num->value)
				r_core_cmd (core, input+1, 0);
		} else r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
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
			"~", "..", "internal less",
			"~", "word", "grep for lines matching word",
			"~", "!word", "grep for lines NOT matching word",
			"~", "word[2]", "grep 3rd column of lines matching word",
			"~", "word:3[0]", "grep 1st column from the 4th line matching mov",
			"@", " 0x1024", "temporary seek to this address (sym.main+3",
			"@", " addr[!blocksize]", "temporary set a new blocksize",
			"@@=", "1 2 3", " run the previous command at offsets 1, 2 and 3",
			"@@", " hit*", "run the command on every flag matching 'hit*'",
			"@f:", "file", "temporary replace block with file contents",
			"@s:", "string", "same as above but from a string",
			"@b:", "909192", "from hex pairs string",
			">", "file", "pipe output of command to file",
			">>", "file", "append to file",
			"`", "pdi~push:0[0]`",  "replace output of command inside the line",
			"|", "cmd", "pipe output to command (pd|less) (.dr*)",
			NULL};
		r_core_cmd_help (core, help_msg);
		return 0;
		}
	case '$':{
		const char* help_msg[] = {
			"Usage: ?v [$.]","","",
			"$$", "", "here (current virtual seek)",
			"$?", "", "last comparison value",
			"$alias", "=value", "Alias commands (simple macros)",
			"$Cn", "", "get nth call of function",
			"$Dn", "", "get nth data reference in function",
			"$F", "", "current function size",
			"$I", "", "number of instructions of current function",
			"$Ja", "", "get nth jump of function",
			"$S", "", "section offset",
			"$SS", "", "section size",
			"$Xn", "", "get nth xref of function",
			"$b", "", "block size",
			"$c,$r", "", "get width and height of terminal",
			"$e", "", "1 if end of block, else 0",
			"$f", "", "jump fail address (e.g. jz 0x10 => next instruction)",
			"$j", "", "jump address (e.g. jmp 0x10, jz 0x10 => 0x10)",
			"$l", "", "opcode length",
			"$m", "", "opcode memory reference (e.g. mov eax,[0x10] => 0x10)",
			"$p", "", "getpid()",
			"$o", "", "here (current disk io offset)",
			"$s", "", "file size",
			"$v", "", "opcode immediate value (e.g. lui a0,0x8010 => 0x8010)",
			"$w", "", "get word size, 4 if asm.bits=32, 8 if 64, ...",
			"${ev}", "", "get value of eval config variable", //TODO: use ?k too
			"RNum", "", " $variables usable in math expressions",
			NULL};
		r_core_cmd_help (core, help_msg);
		}
		return R_TRUE;
	case 'V':
		if (!strcmp (R2_VERSION, GIT_TAP))
			r_cons_printf ("%s\n", R2_VERSION);
		else r_cons_printf ("%s aka %s\n", R2_VERSION, GIT_TAP);
		break;
	case 'l':
		for (input++; input[0]==' '; input++);
		core->num->value = strlen (input);
		break;
	case 'X':
		for (input++; input[0]==' '; input++);
		n = r_num_math (core->num, input);
		r_cons_printf ("%"PFMT64x"\n", n);
		break;
	case 'x':
		for (input++; input[0]==' '; input++);
		if (*input=='-') {
			ut8 *out = malloc (strlen (input)+1);
			int len = r_hex_str2bin (input+1, out);
			out[len] = 0;
			r_cons_printf ("%s\n", (const char*)out);
			free (out);
		} else if (!memcmp (input, "0x", 2) || (*input>='0' && *input<='9')) {
			ut64 n = r_num_math (core->num, input);
			int bits = r_num_to_bits (NULL, n) / 8;
			for (i=0; i<bits; i++)
				r_cons_printf ("%02x", (ut8)((n>>(i*8)) &0xff));
			r_cons_newline ();
		} else {
			for (i=0; input[i]; i++)
				r_cons_printf ("%02x", input[i]);
			r_cons_newline ();
		}
		break;
	case 'e': // echo
		for (input++; *input==' '; input++);
		r_cons_printf ("%s\n", input);
		break;
	case 's': // sequence from to step
		{
		ut64 from, to, step;
		char *p, *p2;
		for (input++; *input==' '; input++);
		p = strchr (input, ' ');
		if (p) {
			*p='\0';
			from = r_num_math (core->num, input);
			p2 = strchr (p+1, ' ');
			if (p2) {
				*p2='\0';
				step = r_num_math (core->num, p2+1);
			} else step = 1;
			to = r_num_math (core->num, p+1);
			for (;from<=to; from+=step)
				r_cons_printf ("%"PFMT64d" ", from);
			r_cons_newline ();
		}
		}
		break;
	case 'P':
		if (core->io->va) {
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			o = r_io_section_offset_to_vaddr (core->io, n);
			r_cons_printf ("0x%08"PFMT64x"\n", o);
		} else eprintf ("io.va is false\n");
		break;
	case 'p':
		if (core->io->va) {
			// physical address
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			o = r_io_section_vaddr_to_offset (core->io, n);
			r_cons_printf ("0x%08"PFMT64x"\n", o);
		} else eprintf ("Virtual addresses not enabled!\n");
		break;
	case 'S': {
		// section name
		RIOSection *s;
		ut64 n = (input[0] && input[1])?
			r_num_math (core->num, input+2): core->offset;
		n = r_io_section_vaddr_to_offset (core->io, n);
		s = r_io_section_vget (core->io, n);
		if (s && *(s->name))
			r_cons_printf ("%s\n", s->name);
		} break;
	case '_': // hud input
		r_core_yank_hud_file (core, input+1);
		break;
	case 'i': // input num
		if (!r_config_get_i (core->config, "scr.interactive")) {
			eprintf ("Not running in interactive mode\n");
		} else
		switch (input[1]) {
		case 'f':
			core->num->value = !r_num_conditional (core->num, input+2);
			eprintf ("%s\n", r_str_bool (!core->num->value));
			break;
		case 'm':
			r_cons_message (input+2);
			break;
		case 'p': {
			core->num->value = r_core_yank_hud_path (core, input+2, 0) == R_TRUE;
			} break;
		case 'k':
			r_cons_any_key ();
			break;
		case 'y':
			for (input+=2; *input==' '; input++);
			core->num->value =
			r_cons_yesno (1, "%s? (Y/n)", input);
			break;
		case 'n':
			for (input+=2; *input==' '; input++);
			core->num->value =
			r_cons_yesno (0, "%s? (y/N)", input);
			break;
		default: {
			char foo[1024];
			r_cons_flush ();
			for (input++; *input==' '; input++);
			// TODO: use prompt input
			eprintf ("%s: ", input);
			fgets (foo, sizeof (foo)-1, stdin);
			foo[strlen (foo)-1] = 0;
			r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, foo, strlen(foo)+1);
			core->num->value = r_num_math (core->num, foo);
			}
			break;
		}
		break;
	case 't': {
		struct r_prof_t prof;
		r_prof_start (&prof);
		r_core_cmd (core, input+1, 0);
		r_prof_end (&prof);
		core->num->value = (ut64)(int)prof.result;
		eprintf ("%lf\n", prof.result);
		} break;
	case '?': // ???
		if (input[1]=='?') {
			if (input[2]=='?') {
				r_cons_printf ("What are you doing?\n");
				return 0;
			}
			if (input[2]) {
				if (core->num->value)
					r_core_cmd (core, input+1, 0);
				break;	
			}
			const char* help_msg[] = {
			"Usage: ?[?[?]] expression", "", "",
			"?", " eip-0x804800", "show hex and dec result for this math expr",
			"?!", " [cmd]", "? != 0",
			"?+", " [cmd]", "? > 0",
			"?-", " [cmd]", "? < 0",
			"?=", " eip-0x804800", "hex and dec result for this math expr",
			"??", "", "show value of operation",
			"??", " [cmd]", "? == 0 run command when math matches",
			"?B", " [elem]", "show range boundaries like 'e?search.in",
			"?P", " paddr", "get virtual address for given physical one",
			"?S", " addr", "return section name of given address",
			"?V", "", "show library version of r_core",
			"?X", " num|expr", "returns the hexadecimal value numeric expr",
			"?_", " hudfile", "load hud menu with given file",
			"?b", " [num]", "show binary value of number",
			"?b64[-]", " [str]", "encode/decode in base64",
			"?d", " opcode", "describe opcode for asm.arch",
			"?e", " string", "echo string",
			"?f", " [num] [str]", "map each bit of the number as flag string index",
			"?h", " [str]", "calculate hash for given string",
			"?i", "[ynmkp] arg", "prompt for number or Yes,No,Msg,Key,Path and store in $$?",
			"?ik", "", "press any key input dialog",
			"?im", " message", "show message centered in screen",
			"?in", " prompt", "noyes input prompt",
			"?iy", " prompt", "yesno input prompt",
			"?l", " str", "returns the length of string",
			"?o", " num", "get octal value",
			"?p", " vaddr", "get physical address for given virtual address",
			"?r", " [from] [to]", "generate random number between from-to",
			"?s", " from to step", "sequence of numbers from to by steps",
			"?t", " cmd", "returns the time to run a command",
			"?u", " num", "get value in human units (KB, MB, GB, TB)",
			"?v", " eip-0x804800", "show hex value of math expr",
			"?vi", " rsp-rbp", "show decimal value of math expr",
			"?x", " num|str|-hexst", "returns the hexpair of number or string",
			"?y", " [str]", "show contents of yank buffer, or set with string",
			NULL};
			r_core_cmd_help (core, help_msg);
			return 0;
		} else if (input[1]) {
			if (core->num->value) {
				r_core_cmd (core, input+1, 0);
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
		"*", "off[=[0x]value]", "Pointer read/write data/values (see ?v, wx, wv)",
		"(macro arg0 arg1)",  "", "Manage scripting macros",
		".", "[-|(m)|f|!sh|cmd]", "Define macro or load r2, cparse or rlang file",
		"="," [cmd]", "Run this command via rap://",
		"/","", "Search for bytes, regexps, patterns, ..",
		"!"," [cmd]", "Run given command as in system(3)",
		"#"," [algo] [len]", "Calculate hash checksum of current block",
		"a","", "Perform analysis of code",
		"b","", "Get or change block size",
		"c"," [arg]", "Compare block with given data",
		"C","", "Code metadata management",
		"d","", "Debugger commands",
		"e"," [a[=b]]", "List/get/set config evaluable vars",
		"f"," [name][sz][at]", "Set flag at current address",
		"g"," [arg]", "Go compile shellcodes with r_egg",
		"i"," [file]", "Get info about opened file",
		"k"," [sdb-query]", "Run sdb-query. see k? for help, 'k *', 'k **' ...",
		"m","", "Mountpoints commands",
		"o"," [file] ([offset])", "Open file at optional address",
		"p"," [len]", "Print current block with format and length",
		"P","", "Project management utilities",
		"q"," [ret]", "Quit program with a return value",
		"r"," [len]", "Resize file",
		"s"," [addr]", "Seek to address (also for '0x', '0x1' == 's 0x1')",
		"S","", "Io section manipulation information",
		"t","", "Cparse types management",
		"T"," [-] [num|msg]", "Text log utility",
		"V","", "Enter visual mode (vcmds=visualvisual  keystrokes)",
		"w"," [str]", "Multiple write operations",
		"x"," [len]", "Alias for 'px' (print hexadecimal)",
		"y"," [len] [[[@]addr", "Yank/paste bytes from/to memory",
		"z", "", "Zignatures management",
		"?[??]","[expr]", "Help or evaluate math expression",
		"?$?", "", "Show available '$' variables and aliases",
		"?@?", "", "Misc help for '@' (seek), '~' (grep) (see ~?""?)",
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
