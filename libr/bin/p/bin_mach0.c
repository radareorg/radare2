static int bopen(struct r_bin_t *bin)
{
}

static int bclose(struct r_bin_t *bin)
{
	free(bin->bin_obj);
}

static u64 baddr(struct r_bin_t *bin)
{
	return -0x1000; /* huh */
}

static int check(struct r_bin_t *bin)
{
	int ret = R_FALSE;
	u8 buf[4];

	if ((bin->fd = open(bin->file, 0)) != -1) {
		lseek(bin->fd, 0, SEEK_SET);
		read(bin->fd, buf, 4);
		close(bin->fd);
		if (!memcmp(buf, "\xce\xfa\xed\xfa", 4))
			ret = R_TRUE;
	}
	return ret;
}

struct r_bin_handle_t r_bin_plugin_mach0 = {
	.name = "bin_mach0",
	.desc = "mach0 bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.check = &check,
	.baddr = &baddr,
	.entry = &entry,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach0
};
#endif
