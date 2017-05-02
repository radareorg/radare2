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
		buf = r_str_appendlen (buf, msg, dollar-msg);
		if (dollar[1]=='{') {
			// find }
			end = strchr (dollar+2, '}');
			if (end) {
				word = r_str_newlen (dollar+2, end-dollar-2);
				end++;
			} else {
				msg = dollar+1;
				buf = r_str_append (buf, "$");
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
			buf = r_str_append (buf, num);
			msg = end;
		} else {
			break;
		}
		free (word);
	}
	buf = r_str_append (buf, msg);
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
	char *p, out[128] = R_EMPTY;
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
				":", "", "Список плагинов RCore",
				":java", "", "Запустить плагин java",
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
		if (input[1] == '@'){
			helpCmdForeach (core);
		} else {
			helpCmdAt (core);
		}
		}
		break;
	case '&':
		helpCmdTasks (core);
		break;
	case '$':
		if (input[1] == '?') {
			const char* help_msg[] = {
			"Usage: ?v [$.]","","",
			"$$", "", "здесь (текущий виртуальный поиск)",
            "$?", "", "Последнее сравнительное значение",
			"$alias", "=value", "Команды псевдонима (простые макросы)",
			"$b", "", "Размер блока",
			"$B", "", "Базовый адрес (выровненный наименьший адрес карты) ",
			"$f", "", "Адрес отказа перехода (например, jz 0x10 => следующая инструкция)",
			"$fl", "", "длина флага (размер) текущего адреса (fla; pD $l @ entry0)",
			"$F", "", "размер текущей функии",
			"$FB", "", "начать функию",
			"$Fb", "", "aдрес текущего базвого блока",
			"$Fs", "", "размер текущего базвого блока",
			"$FE", "", "закончить функцию",
			"$FS", "", "размер функции",
			"$FI", "", "инструкции функции",
			"$c,$r", "", "получить ширину и высоту терминалп",
			"$Cn", "", "получить nth вызов функции",
			"$Dn", "", "получить nth данные справки о функции",
			"$D", "", " ?v $D @ rsp",
			"$DD", "", "текущий размер отладчика ",
			"$e", "", "1 если конц блока, иначе 0",
			"$j", "", "переместиться по адресу (e.g. jmp 0x10, jz 0x10 => 0x10)",
			"$Ja", "", "получить nth перемещение по функии",
			"$Xn", "", "получить nth xref функции",
			"$l", "", "длина опкода ",
			"$m", "", "ссылка памяти опкода (e.g. mov eax,[0x10] => 0x10)",
			"$M", "", "map адрес (Самый младший адрес карты)",
			"$o", "", "здесь (текущий диск io смещения)",
			"$p", "", "getpid()",
			"$P", "", "pid дочернего процесса (only in debug)",
			"$s", "", "размер файла",
			"$S", "", "смещение секии",
			"$SS", "", "размер секции",
			"$v", "", "Непосредственное значение opcode(e.g. lui a0,0x8010 => 0x8010)",
			"$w", "", "получить размер слова, 4 если asm.bits=32, 8 if 64, ...",
			"${ev}", "", "получить знчание eval config переменной",
			"$k{kv}", "", "Получить значение значения запроса sdb",
			"RNum", "", "$используемые переменные в математическом выражении",
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
					"?V", "", "показать информацию о версии",
					"?Vj", "", "то же самое, только  а JSON",
					"?Vq", "", "quiet mode, только показывает номер версии",
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
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			o = r_io_section_maddr_to_vaddr (core->io, n);
			r_cons_printf ("0x%08"PFMT64x"\n", o);
		} else {
			eprintf ("io.va is false\n");
		}
		break;
	case 'p':
		if (core->io->va) {
			// physical address
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input + 2): core->offset;
			o = r_io_section_vaddr_to_maddr (core->io, n);
			r_cons_printf ("0x%08"PFMT64x"\n", o);
		} else {
			eprintf ("Virtual addresses not enabled!\n");
		}
		break;
	case 'S': {
		// section name
		RIOSection *s;
		ut64 n = (input[0] && input[1])?
			r_num_math (core->num, input+2): core->offset;
		n = r_io_section_vaddr_to_maddr_try (core->io, n);
		s = r_io_section_mget_in (core->io, n);
		if (s && *(s->name)) {
			r_cons_println (s->name);
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
				foo[sizeof (foo) - 1] = 0;
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
			"?", " eip-0x804800", "показать десятичный и 16-ричный результат математического вражения",
			"?:", "", "список плагинов cmd",
			"?!", " [cmd]", "? != 0",
			"?+", " [cmd]", "? > 0",
			"?-", " [cmd]", "? < 0",
			"?=", " eip-0x804800", "десятичный и 16-ричный результат математического вражения",
			"?$", "", "показать значения всех переменных ($)",
			"??", "", "показать значение операции",
			"??", " [cmd]", "? == 0 запуск команды, когда выполня",
			"?B", " [elem]", "Показывать границы диапазона, такие как 'e? Search.in",
			"?P", " paddr", "Получить виртуальный адрес для данного физического",
			"?S", " addr", "Возвращение раздела название данного адреса",
			"?T", "", "Показать время загрузки",
			"?V", "", "Показать библиотечную версию r_core",
			"?X", " num|expr", "Возвращает шестнадцатеричное числовое число expr",
			"?_", " hudfile", "Загрузить hud menu с заданным файлом",
			"?b", " [num]", "Показать двоичное значение числа",
			"?b64[-]", " [str]", "Кодировать / декодировать в base64",
			"?d[.]", " opcode", "Описать код операции для asm.arch",
			"?e[n]", " string", "Эхо-строка, необязательно без завершающей строки",
			"?f", " [num] [str]", "Сопоставьте каждый бит числа в качестве индекса строкового флага",
			"?h", " [str]", "Вычислять хеш для заданной строки",
			"?i", "[ynmkp] arg", "Запрашивать номер или Да, Нет, Msg, Ключ, Путь и хранить в $$?",
			"?ik", "", "Нажмите любой диалог ввода ключа",
			"?im", " message", "Показать сообщение в центре экрана",
			"?in", " prompt", "noyes Запрос ввода",
			"?iy", " prompt", "yesno Запрос ввода",
			"?l", " str", "Возвращает длину строки",
			"?o", " num", "Получить восьмеричное значение",
			"?O", " [id]", "Список мнемоник для текущего asm.arch / asm.bits",
			"?p", " vaddr", "Получить физический адрес для данного виртуального адреса",
			"?r", " [from] [to]", "Генерировать случайное число от-до",
			"?s", " from to step", "Последовательность чисел от до с шагом",
			"?t", " cmd", "Возвращает время для выполнения команды",
			"?u", " num", "Получить ценность в человеческих единицах (KB, MB, GB, TB)",
			"?v", " eip-0x804800", "Показать шестнадцатеричное значение выражения ",
			"?vi", " rsp-rbp", "Показывает десятичное значение выражения math",
			"?w", " addr", "Показать, что в этом адресе (например, pxr / pxq )",
			"?x", "+num", "Как? V, но в шестнадцатеричном почитании cfg.bigendian",
			"?x", " str", "Возвращает шестнадцатеричное число или строку",
			"?x", "-hexst", "Преобразовать шестнадцатеричное число в необработанную строку с новой строкой",
			"?y", " [str]", "Показать содержимое буфера yank или установить со строкой",
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
		"%var", "=value", "Псевдоним для команды 'env'",
		"*", "[?] off[=[0x]value]", "Указатель чтения / записи данных / значений (см.? V, wx, wv)",
		"(macro arg0 arg1)",  "", "Управление макросами сценариев",
		".", "[?] [-|(m)|f|!sh|cmd]", "Определите макрос или загрузите файл r2, cparse или rlang",
		"=","[?] [cmd]", "Отправка / прослушивание удаленных команд (rap://, http://, <fd>)",
		"/","[?]", "Поиск байтов, регулярных выражений, паттернов, ..",
		"!","[?] [cmd]", "Выполнить заданную команду, как в системе (3)",
		"#","[?] !lang [..]", "Hashbang для запуска скрипта rlang",
		"a","[?]", "Команды анализа",
		"b","[?]", "Отображение или изменение размера блока",
		"c","[?] [arg]", "Сравнить блок с данными",
		"C","[?]", "Метаданные кода (комментарии, формат, подсказки,..)",
		"d","[?]", "Команды отладчика",
		"e","[?] [a[=b]]", "Список / получить / установить конфигурационные переменные",
		"f","[?] [name][sz][at]", "Добавить флаг по текущему адресу",
		"g","[?] [arg]", "Создание шеллкодов с помощью r_egg",
		"i","[?] [file]", "Получить информацию об открытом файле из r_bin",
		"k","[?] [sdb-query]", "Запуск SDB-запрос. См. K? Для помощи, 'k *', 'k **' ...",
		"m","[?]", "Команды точек монтирования",
		"o","[?] [file] ([offset])", "Открыть файл по дополнительному адресу",
		"p","[?] [len]", "Печатать текущий блок с форматом и длиной",
		"P","[?]", "Утилиты управления проектами",
		"q","[?] [ret]", "Выйти из программы с возвращаемым значением",
		"r","[?] [len]", "Изменить размер файла",
		"s","[?] [addr]", "Поиск адрес (также для'0x', '0x1' == 's 0x1')",
		"S","[?]", "Информация о манипуляциях с секциями Io",
		"t","[?]", "Типы, noreturn, подписи, C-парсер и многое другое",
		"T","[?] [-] [num|msg]", "Text log utility",
		"u","[?]", "переименовать/отменить поиск/запись",
		"V","", "Вход в визуальный режим (V! = panels, VV = fcngraph, VVV = callgraph)",
		"w","[?] [str]", "Множественная запись операции",
		"x","[?] [len]", "Псевдоним для 'px' (печатать в шестнадцатеричном формате)",
		"y","[?] [len] [[[@]addr", "Вырезание / вставка байтов из / в память",
		"z", "[?]", "Управление зонами",
		"?[??]","[expr]", "Помощь или оценка математического выражения",
		"?$?", "", "Показывать доступные переменные «$» и псевдонимы",
		"?@?", "", "Разное help для '@' (seek), '~' (grep) (см. ~? ""?)",
		"?:?", "", "Список и управление основными плагинами",
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
