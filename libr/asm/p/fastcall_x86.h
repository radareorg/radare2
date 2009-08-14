static struct r_asm_fastcall_t fastcall[R_ASM_FASTCALL_ARGS] = {
	{ NULL },
	{ "eax", NULL },
	{ "eax", "ebx", NULL },
	{ "eax", "ebx", "ecx", NULL },
	{ "eax", "ebx", "ecx", "edx", NULL },
	NULL
};

/*
main()
{
	printf("%s\n", fastcall[3]->arg[0]);
}
*/
