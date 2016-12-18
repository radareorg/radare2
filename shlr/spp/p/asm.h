TAG_CALLBACK(asm_default)
{
	do_printf (out, "%s", buf);
        return 0;
}

TAG_CALLBACK(asm_include)
{
	if (echo[ifl]) {
		spp_file(buf, out);
	}
	return 0;
}

TAG_CALLBACK(asm_arch)
{
	do_printf (out, ".arch %s\n", buf);
	return 0;
}

TAG_CALLBACK(asm_bits)
{
	do_printf (out, ".bits %s\n", buf);
	return 0;
}

TAG_CALLBACK(asm_string)
{
	do_printf (out, ".string %s\n", buf);
	return 0;
}

PUT_CALLBACK(asm_fputs)
{
	do_printf (out, "%s", buf);
	return 0;
}

struct Tag asm_tags[] = {
	{ "include", asm_include },
	{ "arch", asm_arch },
	{ "bits", asm_bits },
	{ "string", asm_string },
	{ NULL, asm_default },
	{ NULL }
};

struct Arg asm_args[] = {
	{ NULL }
};

struct Proc asm_proc = {
	.name = "asm",
	.tags = (struct Tag **)asm_tags,
	.args = (struct Arg **)asm_args,
	.token = " ",
	.eof = NULL,
	.tag_pre = ".",
	.tag_post = "\n",
	.multiline = "\\\n",
	.default_echo = 1,
	.fputs = asm_fputs,
	.chop = 0,
	.tag_begin = 0,
};