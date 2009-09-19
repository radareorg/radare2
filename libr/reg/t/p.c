#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE *)0)->MEMBER)

int main()
{
	struct user_regs_struct regs;
	printf("gpr\teip .32 %d 0\n", offsetof(struct user_regs_struct, eip));
	printf("gpr\toeax .32 %d 0\n", offsetof(struct user_regs_struct, orig_eax));
	printf("gpr\teax .32 %d 0\n", offsetof(struct user_regs_struct, eax));
	printf("gpr\tebx .32 %d 0\n", offsetof(struct user_regs_struct, ebx));
	printf("gpr\tecx .32 %d 0\n", offsetof(struct user_regs_struct, ecx));
	printf("gpr\tedx .32 %d 0\n", offsetof(struct user_regs_struct, edx));
	printf("gpr\tesp .32 %d 0\n", offsetof(struct user_regs_struct, esp));
	printf("gpr\tebp .32 %d 0\n", offsetof(struct user_regs_struct, ebp));
	printf("gpr\tesi .32 %d 0\n", offsetof(struct user_regs_struct, esi));
	printf("gpr\tedi .32 %d 0\n", offsetof(struct user_regs_struct, edi));
	printf("gpr\txfs .32 %d 0\n", offsetof(struct user_regs_struct, xfs));
	printf("gpr\txgs .32 %d 0\n", offsetof(struct user_regs_struct, xgs));
	printf("gpr\txcs .32 %d 0\n", offsetof(struct user_regs_struct, xcs));
	printf("gpr\txss .32 %d 0\n", offsetof(struct user_regs_struct, xcs));
	printf("gpr\teflags .32 %d 0\n", offsetof(struct user_regs_struct, eflags));
	return 0;
}
