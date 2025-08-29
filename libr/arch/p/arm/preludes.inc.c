
static RList *anal_preludes(RArchSession *as) {
	RList *l = r_list_newf ((RListFree)free);
	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config)) {
		switch (as->config->bits) {
		case 16:
			r_list_append (l, r_str_newf ("b500 ff0f"));
			r_list_append (l, r_str_newf ("b508 ff0f"));
			r_list_append (l, r_str_newf ("00482de9"));
			break;
		case 32:
			r_list_append (l, r_str_newf ("e92d0000 ffff0f0f"));
			r_list_append (l, r_str_newf ("e92d47f0 ffffffff"));
			break;
		case 64:
			r_list_append (l, r_str_newf ("f8000ff0 ff000ff0"));
			r_list_append (l, r_str_newf ("f00000d1 ff0000f0"));
			r_list_append (l, r_str_newf ("f00000a9 ff0000f0"));
			r_list_append (l, r_str_newf ("d503237f000000ff ffffffff000000ff"));
			break;
		default:
			r_list_free (l);
			l = NULL;
			break;
		}
	} else {
		switch (as->config->bits) {
		case 16:
			r_list_append (l, r_str_newf ("00b5 0fff"));
			r_list_append (l, r_str_newf ("08b5 0fff"));
			break;
		case 32:
			r_list_append (l, r_str_newf ("00002de9 0f0fffff"));
			r_list_append (l, r_str_newf ("f0472de9 ffffffff"));
			r_list_append (l, r_str_newf ("1eff2fe1 ffffffff"));
			r_list_append (l, r_str_newf ("10482de9 ffffffff")); // push {r4, fp, lr}
			break;
		case 64:
			r_list_append (l, r_str_newf ("f00f00f8 f00f00ff"));
			r_list_append (l, r_str_newf ("f00000d1 f00000ff"));
			r_list_append (l, r_str_newf ("f00000a9 f00000ff"));
			r_list_append (l, r_str_newf ("7f2303d5 ffffffff"));
			break;
		default:
			r_list_free (l);
			l = NULL;
			break;
		}
	}
	return l;
}
