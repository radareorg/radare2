typedef struct {
	const char *name;
	int w;
	int h;
	int count;
	const char *lines[];
} Avatar;

static Avatar avatar_orangg = {
	.name = "orangg",
	.w = 19,
	.h = 9,
	.count = 1,
	.lines = {
		"      _______      ",
		"     /       \\     ",
		"   _| ( o) (o)\\_   ",
		"  / _     .\\. | \\  ",
		"  \\| \\   ____ / 7` ",
		"  '|\\|  `---'/     ",
		"     | /----. \\    ",
		"     | \\___/  |___ ",
		"     `-----'`-----'" }
};

static Avatar avatar_croco = {
	.name = "croco",
	.w = 16,
	.h = 6,
	.count = 2,
	.lines = {
		" __   __        ",
		"(o |_| o)_____  ",
		"|  ___________) ",
		"\\            /  ",
		" \\          /   ",
		"  \\________/    ",
		" __   __        ",
		"( o|_|o )_____  ",
		"| .___________) ",
		"\\  `___'     /  ",
		" \\          /   ",
		"  \\________/    " }
};

static Avatar avatar_cybcat = {
	.name = "cybercat",
	.w = 19,
	.h = 5,
	.count = 3,
	.lines = {
		"     /\\.---./\\     ",
		" '--           --' ",
		"----   ^   ^   ----",
		"  _.-    Y    -._  ",
		"                   ",
		"     /\\.---./\\     ",
		" '--   @   @   --' ",
		"----     Y     ----",
		"  _.-    O    -._  ",
		"                   ",
		"     /\\.---./\\     ",
		" '--   =   =   --' ",
		"----     Y     ----",
		"  _.-    U    -._  ",
		"                   " }
};

static Avatar avatar_clippy_utf8 = {
	.name = "clippy",
	.w = 7,
	.h = 7,
	.count = 3,
	.lines = {
		" ╭──╮  ",
		" │ _│  ",
		" │ O O ",
		" │  │╭ ",
		" ││ ││ ",
		" │└─┘│ ",
		" ╰───╯ ",
		" ╭──╮  ",
		" │ ╶│╶ ",
		" │ O o ",
		" │  │  ",
		" │ ╭┘ ╱",
		" │ ╰ ╱ ",
		" ╰──'  ",
		" ╭──╮  ",
		" │ _│_ ",
		" │ O O ",
		" │  │╷ ",
		" │  ││ ",
		" │ ─╯│ ",
		" ╰───╯ " }
};

static Avatar avatar_clippy = {
	.name = "clippy",
	.w = 8,
	.h = 7,
	.count = 3,
	.lines = {
		" .--.   ",
		" | _|   ",
		" | O O  ",
		" |  |  |",
		" || | / ",
		" |`-'|  ",
		" `---'  ",
		" .--.   ",
		" |   \\  ",
		" | O o  ",
		" |   | /",
		" |  ( / ",
		" |   /  ",
		" `--'   ",
		" .--.   ",
		" | _|_  ",
		" | O O  ",
		" |  ||  ",
		" | _:|  ",
		" |   |  ",
		" `---'  " }
};

static Avatar avatar_mini_clippy = {
	.name = "mini",
	.w = 5,
	.h = 3,
	.count = 1,
	.lines = {
		" _,  ",
		"|oo _",
		"|_|  " }
};

enum {
	R_AVATAR_ORANGG,
	R_AVATAR_CYBCAT,
	R_AVATAR_CROCO,
	R_AVATAR_CLIPPY,
	R_AVATAR_MINI,
};

R_API void r_core_clippy(RCore *core, const char *msg) {
	// Get default type from config
	const char *clippy_type = r_config_get (core->config, "scr.clippy");
	int type = R_AVATAR_CLIPPY;
	if (!strcmp (clippy_type, "orangg")) {
		type = R_AVATAR_ORANGG;
	} else if (!strcmp (clippy_type, "croco")) {
		type = R_AVATAR_CROCO;
	} else if (!strcmp (clippy_type, "cybercat")) {
		type = R_AVATAR_CYBCAT;
	} else if (!strcmp (clippy_type, "mini")) {
		type = R_AVATAR_MINI;
	}

	int frame = -1; // -1 means random
	while (*msg && *msg != ' ') {
		if (isdigit (*msg)) {
			frame = *msg - '0';
			msg++;
		} else if (isalpha (*msg)) {
			switch (*msg) {
			case 'O':
				type = R_AVATAR_ORANGG;
				break;
			case 'C':
				type = R_AVATAR_CROCO;
				break;
			case 'K':
				type = R_AVATAR_CYBCAT;
				break;
			case 'M':
				type = R_AVATAR_MINI;
				break;
			default:
				type = R_AVATAR_CLIPPY;
				break;
			}
			msg++;
		} else {
			break;
		}
	}
	if (*msg == ' ') {
		msg++;
	}

	int w = r_cons_get_size (core->cons, NULL);

	int i;
	Avatar *avatar;
	const bool utf8 = r_config_get_b (core->config, "scr.utf8");

	switch (type) {
	case R_AVATAR_ORANGG:
		avatar = &avatar_orangg;
		break;
	case R_AVATAR_CROCO:
		avatar = &avatar_croco;
		break;
	case R_AVATAR_CYBCAT:
		avatar = &avatar_cybcat;
		break;
	case R_AVATAR_MINI:
		avatar = &avatar_mini_clippy;
		break;
	default:
		avatar = utf8? &avatar_clippy_utf8: &avatar_clippy;
		break;
	}
	int baseline = 0;
	if (frame != -1) {
		if (frame < avatar->count) {
			baseline = frame * avatar->h;
		}
	} else if (avatar->count > 1) {
		baseline += r_num_rand (avatar->count) * avatar->h;
	}
	msg = r_str_trim_head_ro (msg);
	int margin_right = avatar->w * 4;
	char *m = r_str_wrap (msg, w - margin_right - 1);
	RList *lines = r_str_split_list (m, "\n", 0);
	const int lines_length = r_list_length (lines);
	int bubble_w;
	if (lines_length == 1) {
		bubble_w = r_str_display_width (m);
	} else {
		bubble_w = (w < margin_right)? 10: w - margin_right;
	}
	RStrBuf *buf = r_strbuf_new ("");
	const bool mini = type == R_AVATAR_MINI;
	const int avatar_gap = mini? 0: 1;
	int rows = mini? R_MAX (lines_length + 2, avatar->h): R_MAX (lines_length + 4, avatar->h);
	for (i = 0; i < rows; i++) {
		const bool bubble_active = mini? (i <= lines_length + 1): (i <= lines_length + 3);
		// draw clippy
		if (i < avatar->h) {
			const char *avatar_line = avatar->lines[baseline + i];
			if (bubble_active) {
				r_strbuf_append (buf, avatar_line);
				if (avatar_gap > 0) {
					r_strbuf_append (buf, " ");
				}
			} else {
				size_t avatar_len = strlen (avatar_line);
				while (avatar_len && avatar_line[avatar_len - 1] == ' ') {
					avatar_len--;
				}
				if (avatar_len) {
					r_strbuf_appendf (buf, "%.*s\n", (int)avatar_len, avatar_line);
				} else {
					r_strbuf_append (buf, "\n");
				}
				continue;
			}
		} else {
			if (bubble_active) {
				r_strbuf_pad (buf, ' ', avatar->w + avatar_gap);
			} else {
				r_strbuf_append (buf, "\n");
				continue;
			}
		}
		// draw bubble
		const char *bubble_begin = "";
		const char *bubble_end = "";
		if (mini) {
			if (i == 0) {
				bubble_begin = ".-";
				bubble_end = "-.";
			} else if (i == lines_length + 1) {
				bubble_begin = "|";
				bubble_end = "|";
			} else if (i <= lines_length) {
				bubble_begin = "| ";
				bubble_end = " |";
			}
		} else if (i == 0) {
			if (utf8) {
				bubble_begin = " ╭─";
				bubble_end = "─╮";
			} else {
				bubble_begin = " .-";
				bubble_end = "-.";
			}
		} else if (i == 2) {
			bubble_begin = "<  ";
			if (utf8) {
				bubble_end = " │";
			} else {
				bubble_end = " |";
			}
		} else if (i == lines_length + 3) {
			if (utf8) {
				bubble_begin = " ╰─";
				bubble_end = "─╯";
			} else {
				bubble_begin = " `-";
				bubble_end = "-'";
			}
		} else if (i < lines_length + 3) {
			if (utf8) {
				bubble_begin = " │ ";
				bubble_end = " │";
			} else {
				bubble_begin = " | ";
				bubble_end = " |";
			}
		}
		r_strbuf_append (buf, bubble_begin);
		// print text
		if ((mini && i > 0 && i <= lines_length) || (!mini && i > 1 && i < lines_length + 2)) {
			RListIter *line = r_list_get_nth (lines, mini? i - 1: i - 2);
			if (line) {
				r_strbuf_append (buf, line->data);
				const int tw = r_str_display_width (line->data);
				r_strbuf_pad (buf, ' ', bubble_w - tw);
			}
		} else {
			if (mini && i == lines_length + 1) {
				r_strbuf_pad (buf, '_', bubble_w + 2);
			} else if (i == 0 || (!mini && i == lines_length + 3)) {
				// pad with lines
				if (!mini && utf8) {
					int j;
					for (j = 0; j < bubble_w; j++) {
						r_strbuf_append (buf, "─");
					}
				} else {
					r_strbuf_pad (buf, '-', bubble_w);
				}
			} else {
				r_strbuf_pad (buf, ' ', bubble_w);
			}
		}
		// print bubble_end
		r_strbuf_appendf (buf, "%s\n", bubble_end);
	}
	r_cons_print (core->cons, r_strbuf_get (buf));
	r_strbuf_free (buf);
}
