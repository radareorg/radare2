static int blob_version(const char *program) {
	printf ("%s "R2_VERSION" @ "R_SYS_OS"-"R_SYS_ENDIAN"-"
			R_SYS_ARCH"-%d build "R2_BIRTH"\n",
			program, R_SYS_BITS&8?64:32);
	if (*R2_GITTIP)
		printf ("commit: %s\n", R2_GITTIP);
	return 0;
}
