static const RCoreHelpMessage help_msg_y = {
	"Usage:", "y[fptxy] [len] [[@]addr]", " # See wd? for memcpy, same as 'yf'.",
	"y!", "", "open cfg.editor to edit the clipboard",
	"y", " 16 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16 @ 0x200", "copy 16 bytes into clipboard from 0x200",
	"y", " 16", "copy 16 bytes into clipboard",
	"y", "", "show yank buffer information (origin len bytes)",
	"y*", "", "print in r2 commands what's been yanked",
	"y-", "", "empty / reset clipboard",
	"y8", "", "print contents of clipboard in hexpairs",
	"yf", " [L] [O] [file]", "copy [L] bytes from offset [O] of [file] into clipboard",
	"yfa", " [filepath]", "copy all bytes from file into clipboard",
	"yfx", " 10203040", "yank from hexpairs (same as ywx)",
	"yj", "", "print in JSON commands what's been yanked",
	"yp", "", "print contents of clipboard",
	"ys", "", "print contents of clipboard as string",
	"yt", " 64 0x200", "copy 64 bytes from current seek to 0x200",
	"ytf", " file", "dump the clipboard to given file",
	"yw", " hello world", "yank from string",
	"ywx", " 10203040", "yank from hexpairs (same as yfx)",
	"yx", "", "print contents of clipboard in hexadecimal",
	"yy", " 0x3344", "paste contents of clipboard to 0x3344",
	"yy", " @ 0x3344", "paste contents of clipboard to 0x3344",
	"yy", "", "paste contents of clipboard at current seek",
	"yz", " [len]", "copy nul-terminated string (up to blocksize) into clipboard",
	NULL
};

static int cmd_yank(void *data, const char *input) {
	ut64 n;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case ' ': // "y "
		{
			char *args = r_str_trim_dup (input + 1);
			char *arg = r_str_after (args, ' ');
			ut64 addr = arg? r_num_math (core->num, arg): core->addr;
			r_core_yank (core, addr, r_num_math (core->num, args));
			free (args);
		}
		break;
	case '-': // "y-"
		r_core_yank_unset (core);
		break;
	case 'l': // "yl"
		r_core_return_value (core, r_buf_size (core->yank_buf));
		break;
	case 'r': // "yr"
		R_LOG_ERROR ("Missing plugin. Run: r2pm -ci r2yara");
		r_core_return_code (core, 1);
		break;
	case 'y': // "yy"
		input = r_str_trim_head_ro (input);
		n = input[1]? r_num_math (core->num, input + 1): core->addr;
		r_core_yank_paste (core, n, 0);
		break;
	case 'x': // "yx"
		r_core_yank_hexdump (core, r_num_math (core->num, input + 1));
		break;
	case 'z': // "yz"
		r_core_yank_string (core, core->addr, r_num_math (core->num, input + 1));
		break;
	case 'w': // "yw" ... we have yf which makes more sense than 'w'
		switch (input[1]) {
		case ' ':
			r_core_yank_set (core, 0, (const ut8*)input + 2, strlen (input + 2));
			break;
		case 'x':
			if (input[2] == ' ') {
				char *out = strdup (input + 3);
				int len = r_hex_str2bin (input + 3, (ut8*)out);
				if (len > 0) {
					r_core_yank_set (core, core->addr, (const ut8*)out, len);
				} else {
					R_LOG_ERROR ("Invalid length");
				}
				free (out);
			} else {
				r_core_cmd_help_match (core, help_msg_y, "ywx");
			}
			// r_core_yank_write_hex (core, input + 2);
			break;
		default:
			r_core_cmd_help_match (core, help_msg_y, "ywx");
			break;
		}
		break;
	case 'p': // "yp"
		r_core_yank_cat (core, r_num_math (core->num, input + 1));
		break;
	case 's': // "ys"
		r_core_yank_cat_string (core, r_num_math (core->num, input + 1));
		break;
	case 't': // "yt"
		switch (input[1]) {
		case 'f': // "ytf"
			{
			ut64 tmpsz;
			const char *file = r_str_trim_head_ro (input + 2);
			const ut8 *tmp = r_buf_data (core->yank_buf, &tmpsz);
			if (!tmpsz) {
				R_LOG_ERROR ("No buffer has been yanked");
				break;
			}

			if (*file == '$') {
				r_cmd_alias_set_raw (core->rcmd, file+1, tmp, tmpsz);
			} else if (*file == '?' || !*file) {
				r_core_cmd_help_match (core, help_msg_y, "ytf");
			} else {
				if (!r_file_dump (file, tmp, tmpsz, false)) {
					R_LOG_ERROR ("Cannot dump to '%s'", file);
				}
			}
			}
			break;
		case ' ':
			r_core_yank_to (core, input + 1);
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_y, "yt");
			break;
		default:
			r_core_return_invalid_command (core, "yt", input[1]);
			break;
		}
		break;
	case 'f': // "yf"
		switch (input[1]) {
		case ' ': // "yf" // "yf [filename] [nbytes] [offset]"
			r_core_yank_file_ex (core, input + 1);
			break;
		case 'x': // "yfx"
			r_core_yank_hexpair (core, input + 2);
			break;
		case 'a': // "yfa"
			r_core_yank_file_all (core, input + 2);
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_y, "yf");
			break;
		default:
			r_core_return_invalid_command (core, "yf", input[1]);
			break;
		}
		break;
	case '!': // "y!"
		{
			char *sig = r_core_cmd_str (core, "y*");
			if (R_STR_ISEMPTY (sig)) {
				free (sig);
				sig = strdup ("'wx 10203040");
			}
			char *data = r_core_editor (core, NULL, sig);
			if (data) {
				char *save_ptr = NULL;
				(void) r_str_tok_r (data, ";\n", &save_ptr);
				r_core_cmdf (core, "y%s", data);
				free (data);
			}
			free (sig);
		}
		break;
	case '*': // "y*"
	case 'j': // "yj"
	case '8': // "y8"
	case '\0': // "y"
		r_core_yank_dump (core, 0, input[0]);
		break;
	case '?':
		r_core_cmd_help (core, help_msg_y);
		break;
	default:
		r_core_return_invalid_command (core, "y", *input);
		break;
	}
	return true;
}

