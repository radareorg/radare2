static const char *avatar_orangg[] = {
	"      _______\n"
	"     /       \\      .-%s-.\n"
	"   _| ( o) (o)\\_    | %s |\n"
	"  / _     .\\. | \\  <| %s |\n"
	"  \\| \\   ____ / 7`  | %s |\n"
	"  '|\\|  `---'/      `-%s-'\n"
	"     | /----. \\\n"
	"     | \\___/  |___\n"
	"     `-----'`-----'\n"
};

static const char *avatar_croco[] = {
	" __   __          .-%s-.\n"
	"(o |_| o)_____    | %s |\n"
	"|  ___________)  <  %s |\n"
	"\\            /    | %s |\n"
	" \\          /     `-%s-'\n"
	"  \\________/\n"
};
#if 0

static const char *avatar_clippy[] = {
	" .--.     .-%s-.\n"
	" | _|     | %s |\n"
	" | O O   <  %s |\n"
	" |  |  |  | %s |\n"
	" || | /   `-%s-'\n"
	" |`-'|\n"
	" `---'\n",
	" .--.     .-%s-.\n"
	" |   \\    | %s |\n"
	" | O o   <  %s |\n"
	" |   | /  | %s |\n"
	" |  ( /   `-%s-'\n"
	" |   / \n"
	" `--'\n",
	" .--.     .-%s-.\n"
	" | _|_    | %s |\n"
	" | O O   <  %s |\n"
	" |  ||    | %s |\n"
	" | _:|    `-%s-'\n"
	" |   |\n"
	" `---'\n",
};
#endif

static const char *avatar_clippy_utf8[] = {
	" ╭──╮    ╭─%s─╮\n"
	" │ _│    │ %s │\n"
	" │ O O  <  %s │\n"
	" │  │╭   │ %s │\n"
	" ││ ││   ╰─%s─╯\n"
	" │└─┘│\n"
	" ╰───╯\n",
	" ╭──╮    ╭─%s─╮\n"
	" │ ╶│╶   │ %s │\n"
	" │ O o  <  %s │\n"
	" │  │  ╱ │ %s │\n"
	" │ ╭┘ ╱  ╰─%s─╯\n"
	" │ ╰ ╱\n"
	" ╰──'\n",
	" ╭──╮    ╭─%s─╮\n"
	" │ _│_   │ %s │\n"
	" │ O O  <  %s │\n"
	" │  │╷   │ %s │\n"
	" │  ││   ╰─%s─╯\n"
	" │ ─╯│\n"
	" ╰───╯\n",
};

static const char *avatar_cybcat[] = {
"     /\\.---./\\       .-%s-.\n"
" '--           --'   | %s |\n"
"----   ^   ^   ---- <  %s |\n"
"  _.-    Y    -._    | %s |\n"
"                     `-%s-'\n",
"     /\\.---./\\       .-%s-.\n"
" '--   @   @   --'   | %s |\n"
"----     Y     ---- <  %s |\n"
"  _.-    O    -._    | %s |\n"
"                     `-%s-'\n",
"     /\\.---./\\       .-%s-.\n"
" '--   =   =   --'   | %s |\n"
"----     Y     ---- <  %s |\n"
"  _.-    U    -._    | %s |\n"
"                     `-%s-'\n",
};

static const char *avatar_clippy[] = {
	" .--.     .-%s-.\n"
	" | _|     | %s |\n"
	" | O O   <  %s |\n"
	" |  |  |  | %s |\n"
	" || | /   `-%s-'\n"
	" |`-'|\n"
	" `---'\n",
	" .--.     .-%s-.\n"
	" |   \\    | %s |\n"
	" | O o   <  %s |\n"
	" |   | /  | %s |\n"
	" |  ( /   `-%s-'\n"
	" |   / \n"
	" `--'\n",
	" .--.     .-%s-.\n"
	" | _|_    | %s |\n"
	" | O O   <  %s |\n"
	" |  ||    | %s |\n"
	" | _:|    `-%s-'\n"
	" |   |\n"
	" `---'\n",
};

enum {
	R_AVATAR_ORANGG,
	R_AVATAR_CYBCAT,
	R_AVATAR_CROCO,
	R_AVATAR_CLIPPY,
};

R_API void r_core_clippy (RCore *core, const char *msg) {
	/* choose avatar type */
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
			type = (*msg == '+')? R_AVATAR_ORANGG: (*msg == 'C')? R_AVATAR_CROCO: R_AVATAR_CYBCAT;
			msg = space + 1;
		}
		break;
	}

	/* wrap message at 50 columns */
	int w = r_cons_get_size (core->cons, NULL);
	const int WRAP_COL = (w > 50)? w - 20: 50;
	char *wrapped = r_str_wrap (msg, WRAP_COL - 1);
	if (!wrapped) {
		return;
	}

	/* split wrapped text into lines */
	int nlines = 0;
	int i;
	for (i = 0; wrapped[i]; i++) {
		if (wrapped[i] == '\n') {
			nlines++;
		}
	}
	if (i > 0 && wrapped[i - 1] != '\n') {
		nlines++;
	}
	char **tlines = NULL;
	if (nlines > 0) {
		tlines = (char **)malloc (sizeof (char *) * nlines);
	}
	int idx = 0;
	char *wp = wrapped;
	char *line = wp;
	for (; *wp; wp++) {
		if (*wp == '\n') {
			*wp = '\0';
			if (idx < nlines) {
				tlines[idx++] = line;
			}
			line = wp + 1;
		}
	}
	if (*line && idx < nlines) {
		tlines[idx++] = line;
	}

	/* compute bubble width from lines (max, capped at WRAP_COL) */
	int width = 0;
	for (i = 0; i < nlines; i++) {
		int len = (int)r_str_len_utf8 (tlines[i]);
		if (len > width) {
			width = len;
		}
	}
	if (width < 0) {
		width = 0;
	}
	if (width > WRAP_COL) {
		width = WRAP_COL;
	}

	/* choose avatar frame and border char */
	const char *f;
	char *l;
	switch (type) {
	case R_AVATAR_ORANGG:
		l = strdup (r_str_pad ('-', width));
		f = avatar_orangg[0];
		break;
	case R_AVATAR_CROCO:
		l = strdup (r_str_pad ('-', width));
		f = avatar_croco[0];
		break;
	case R_AVATAR_CYBCAT:
		l = strdup (r_str_pad ('-', width));
		f = avatar_cybcat[r_num_rand (R_ARRAY_SIZE (avatar_cybcat))];
		break;
	default:
		if (r_config_get_b (core->config, "scr.utf8")) {
			l = (char *)r_str_repeat ("─", width);
			f = avatar_clippy_utf8[r_num_rand (R_ARRAY_SIZE (avatar_clippy_utf8))];
		} else {
			l = strdup (r_str_pad ('-', width));
			f = avatar_clippy[r_num_rand (R_ARRAY_SIZE (avatar_clippy))];
		}
		break;
	}
	char *s = strdup (r_str_pad (' ', width));

	/* split avatar frame into lines and extract bubble line templates */
	char *fc = strdup (f);
	int fav_lines_n = 0;
	int flen = (int)strlen (fc);
	for (i = 0; i < flen; i++) {
		if (fc[i] == '\n') {
			fav_lines_n++;
		}
	}
	if (flen > 0 && fc[flen - 1] != '\n') {
		fav_lines_n++;
	}
	char **fav = NULL;
	if (fav_lines_n > 0) {
		fav = (char **)malloc (sizeof (char *) * fav_lines_n);
	}
	idx = 0;
	char *sp = fc;
	char *start = sp;
	for (; *sp; sp++) {
		if (*sp == '\n') {
			*sp = '\0';
			if (idx < fav_lines_n) {
				fav[idx++] = start;
			}
			start = sp + 1;
		}
	}
	if (*start && idx < fav_lines_n) {
		fav[idx++] = start;
	}

	/* collect indices of lines with %s */
	int fmt_idx[8];
	int fmt_n = 0;
	for (i = 0; i < fav_lines_n; i++) {
		if (strstr (fav[i], "%s")) {
			if (fmt_n < (int)(sizeof (fmt_idx) / sizeof (*fmt_idx))) {
				fmt_idx[fmt_n++] = i;
			}
		}
	}

	/* render: top border, top pad, text lines, bottom pad, bottom border, tail */
	if (fmt_n >= 5) {
		/* top border */
		{
			const char *tmpl = fav[fmt_idx[0]];
			const char *p = strstr (tmpl, "%s");
			if (p) {
				int prelen = (int)(p - tmpl);
				char *pre = r_str_ndup (tmpl, prelen);
				const char *post = p + 2;
				char *out = r_str_newf ("%s%s%s", pre, l, post);
				r_cons_printf (core->cons, "%s\n", out);
				free (pre);
				free (out);
			} else {
				r_cons_printf (core->cons, "%s\n", tmpl);
			}
		}
		/* top padding */
		{
			const char *tmpl = fav[fmt_idx[1]];
			const char *p = strstr (tmpl, "%s");
			if (p) {
				int prelen = (int)(p - tmpl);
				char *pre = r_str_ndup (tmpl, prelen);
				const char *post = p + 2;
				char *out = r_str_newf ("%s%s%s", pre, s, post);
				r_cons_printf (core->cons, "%s\n", out);
				free (pre);
				free (out);
			} else {
				r_cons_printf (core->cons, "%s\n", tmpl);
			}
		}
		/* text lines */
		for (i = 0; i < nlines; i++) {
			int llen = (int)r_str_len_utf8 (tlines[i]);
			int pad = width - R_MAX (0, llen);
			char *right = strdup (r_str_pad (' ', pad));
			char *payload = r_str_newf ("%s%s", tlines[i], right);
			/* use arrow line for first text row if available */
			int body_tmpl = (i == 0 && fmt_n >= 3)? fmt_idx[2]: fmt_idx[3];
			{
				const char *tmpl = fav[body_tmpl];
				const char *p = strstr (tmpl, "%s");
				if (p) {
					int prelen = (int)(p - tmpl);
					char *pre = r_str_ndup (tmpl, prelen);
					const char *post = p + 2;
					char *out = r_str_newf ("%s%s%s", pre, payload, post);
					r_cons_printf (core->cons, "%s\n", out);
					free (pre);
					free (out);
				} else {
					r_cons_printf (core->cons, "%s\n", tmpl);
				}
			}
			free (right);
			free (payload);
		}
		/* bottom padding */
		{
			const char *tmpl = fav[fmt_idx[3]];
			const char *p = strstr (tmpl, "%s");
			if (p) {
				int prelen = (int)(p - tmpl);
				char *pre = r_str_ndup (tmpl, prelen);
				const char *post = p + 2;
				char *out = r_str_newf ("%s%s%s", pre, s, post);
				r_cons_printf (core->cons, "%s\n", out);
				free (pre);
				free (out);
			} else {
				r_cons_printf (core->cons, "%s\n", tmpl);
			}
		}
		/* bottom border */
		{
			const char *tmpl = fav[fmt_idx[4]];
			const char *p = strstr (tmpl, "%s");
			if (p) {
				int prelen = (int)(p - tmpl);
				char *pre = r_str_ndup (tmpl, prelen);
				const char *post = p + 2;
				char *out = r_str_newf ("%s%s%s", pre, l, post);
				r_cons_printf (core->cons, "%s\n", out);
				free (pre);
				free (out);
			} else {
				r_cons_printf (core->cons, "%s\n", tmpl);
			}
		}
		/* tail (avatar-only) */
		for (i = fmt_idx[4] + 1; i < fav_lines_n; i++) {
			r_cons_printf (core->cons, "%s\n", fav[i]);
		}
	} else {
		/* fallback: original single-line rendering using first line of wrapped */
		const char *single = (nlines > 0)? tlines[0]: "";
		char *s1 = strdup (r_str_pad (' ', (int)r_str_len_utf8 (single)));
		r_cons_printf (core->cons, f, l, s1, single, s1, l);
		free (s1);
	}

	free (fc);
	free (fav);
	free (l);
	free (s);
	free (tlines);
	free (wrapped);
}
