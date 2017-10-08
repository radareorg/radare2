/* CPP */

static TAG_CALLBACK(pod_default) {
	do_printf (out, "DEFAULT: (%s)\n", buf);
	return 0;
}

static TAG_CALLBACK(pod_cut) {
	do_printf (out, "\n");
	state->echo[state->ifl] = 0;
	return 0;
}

static TAG_CALLBACK(pod_head1) {
	state->echo[state->ifl] = 1;
	do_printf (out, "\n");
	if (!buf) {
		return 0;
	}
	do_printf (out, "%s\n", buf);
	int i, len = strlen (buf);
	for (i = 0; i < len; i++) {
		do_printf (out, "%c", '=');
	}
	do_printf (out, "\n");
	return 0;
}

static struct Tag pod_tags[] = {
	{ "head1", pod_head1 },
	{ "cut", pod_cut },
	{ NULL, pod_default },
	{ NULL }
};

static struct Arg pod_args[] = {
	{ NULL }
};

DLL_LOCAL struct Proc pod_proc = {
	.name = "pod",
	.tags = (struct Tag **)pod_tags,
	.args = (struct Arg **)pod_args,
	.token = " ",
	.eof = NULL,
	.tag_pre = "=",
	.tag_post = "\n",
	.multiline = NULL,
	.default_echo = 0,
	.chop = 0,
	.tag_begin = 1,
};
