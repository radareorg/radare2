#ifndef R2_GITTAP
#define R2_GITTAP ""
#endif

#ifndef R2_GITTIP
#define R2_GITTIP ""
#endif

#ifndef R2_BIRTH
#define R2_BIRTH "unknown"
#endif

static int blob_version(const char *program) {
	printf ("%s "R2_VERSION" @ "R_SYS_OS"-"R_SYS_ENDIAN"-"
			R_SYS_ARCH"-%d git.%s\n",
			program, R_SYS_BITS&8?64:32,
			*R2_GITTAP? R2_GITTAP: "");
	if (*R2_GITTIP) {
		printf ("commit: "R2_GITTIP" build: "R2_BIRTH"\n");
	}
	return 0;
}
