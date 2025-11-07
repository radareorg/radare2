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

enum {
	R_AVATAR_ORANGG,
	R_AVATAR_CYBCAT,
	R_AVATAR_CROCO,
	R_AVATAR_CLIPPY,
};

R_API void r_core_clippy(RCore *core, const char *msg) {
	int type = R_AVATAR_CLIPPY;
	switch (*msg) {
	case '+':
	case '3':
	case 'C':
		{
			const char *space = strchr (msg, ' ');
			if (!space) {
				space = msg;
			}
			switch (*msg) {
			case '+':
				type = R_AVATAR_ORANGG;
				break;
			case 'C':
				type = R_AVATAR_CROCO;
				break;
			case '3':
				type = R_AVATAR_CYBCAT;
				break;
			}
			msg = space + 1;
		}
		break;
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
	default:
		avatar = utf8? &avatar_clippy_utf8: &avatar_clippy;
		break;
	}
	int baseline = 0;
	if (avatar->count > 1) {
		baseline += r_num_rand (avatar->count) * avatar->h;
	}
	int margin_right = avatar->w * 4;
	char *m = r_str_wrap (msg, w - margin_right - 1);
	RList *lines = r_str_split_list (m, "\n", 0);
	const int lines_length = r_list_length (lines);
	int bubble_w;
	if (lines_length == 1) {
		bubble_w = r_utf8_display_width ( (const ut8 *)m);
	} else {
		bubble_w = (w < margin_right)? 10: w - margin_right;
	}
	int rows = R_MAX (lines_length + 4, avatar->h);
	for (i = 0; i < rows; i++) {
		// draw clippy
		if (i < avatar->h) {
			const char *avatar_line = avatar->lines[baseline + i];
			r_cons_printf (core->cons, "%s ", avatar_line);
		} else {
			r_cons_printf (core->cons, r_str_pad (' ', avatar->w + 1));
		}
		// draw bubble
		const char *bubble_begin = "";
		const char *bubble_end = "";
		if (i == 0) {
			if (utf8) {
				bubble_begin = " ╭─";
				bubble_end = "─╮";
			} else {
				bubble_begin = " .-";
				bubble_end = "-. ";
			}
		} else if (i == 2) {
			bubble_begin = "<  ";
			if (utf8) {
				bubble_end = " │ ";
			} else {
				bubble_end = " | ";
			}
		} else if (i == lines_length + 3) {
			if (utf8) {
				bubble_begin = " ╰─";
				bubble_end = "─╯";
			} else {
				bubble_begin = " `-";
				bubble_end = "-' ";
			}
		} else if (i < lines_length + 3) {
			if (utf8) {
				bubble_begin = " │ ";
				bubble_end = " │ ";
			} else {
				bubble_begin = " | ";
				bubble_end = " | ";
			}
		}
		r_cons_print (core->cons, bubble_begin);
		// print text
		if (i > 1 && i < lines_length + 2) {
			RListIter *line = r_list_get_nth (lines, i - 2);
			if (line) {
				r_cons_printf (core->cons, "%s", line->data);
				const int tw = r_utf8_display_width ((const ut8 *)line->data);
				r_cons_printf (core->cons, r_str_pad (' ', bubble_w - tw));
			}
		} else {
			if (i == 0 || i == lines_length + 3) {
				// pad with lines
				if (utf8) {
					int j;
					for (j = 0; j < bubble_w; j++) {
						r_cons_printf (core->cons, "─");
					}
				} else {
					r_cons_printf (core->cons, r_str_pad ('-', bubble_w));
				}
			} else {
				r_cons_printf (core->cons, r_str_pad (' ', bubble_w));
			}
		}
		// print bubble_end
		r_cons_println (core->cons, bubble_end);
	}
}
