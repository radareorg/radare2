#ifndef SP_H
#define SP_H

#define MAX_PACKET 2048

struct regs {
	unsigned int	edi;
	unsigned int	esi;
	unsigned int	ebp;
	unsigned int	xx;
	unsigned int	ebx;
	unsigned int	edx;
	unsigned int	ecx;
	unsigned int	eax;
};

struct arg {
	char *buf;
	int len;
};

#endif
