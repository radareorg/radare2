#include "r_syscall.h"

RSyscallPort sysport_x86[] = {
	{ 0x3, "HELLO WORLD" },
	{ 0x378, "lp1" },
	{ 0, NULL }
};

RSyscallPort sysport_avr[] = {
	{ 0x378, "lp1" },
	{ 0, NULL }
};
