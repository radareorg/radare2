static struct r_asm_fastcall_t fastcall[R_ASM_FASTCALL_ARGS] = {
	{ NULL },
	{ "a0", NULL },
	{ "a0", "a1", NULL },
	{ "a0", "a1", "a2", NULL },
	{ "a0", "a1", "a2", "a3", NULL },
	NULL
};

/*
main()
{
	printf("%s\n", fastcall[3]->arg[0]);
}
*/
