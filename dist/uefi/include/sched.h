/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _SCHED_H
#define _SCHED_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCHED_OTHER 0
#define SCHED_FIFO 1
#define SCHED_RR 2

struct sched_param {
	int sched_priority;
};

typedef struct {
	unsigned long __bits[16];
} cpu_set_t;

#define CPU_ZERO(set) do { int __i; for (__i = 0; __i < 16; __i++) { (set)->__bits[__i] = 0; } } while (0)
#define CPU_SET(cpu, set) ((set)->__bits[(cpu) / (8 * sizeof (unsigned long))] |= (1UL << ((cpu) % (8 * sizeof (unsigned long)))))
#define CPU_ISSET(cpu, set) (((set)->__bits[(cpu) / (8 * sizeof (unsigned long))] & (1UL << ((cpu) % (8 * sizeof (unsigned long))))) != 0)

int sched_yield(void);
int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);
int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);

#ifdef __cplusplus
}
#endif

#endif /* _SCHED_H */
