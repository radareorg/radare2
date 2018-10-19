/*
 * This file is part of ptrace-wrap.
 *
 * ptrace-wrap is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ptrace-wrap is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ptrace-wrap.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PTRACE_WRAP_H
#define PTRACE_WRAP_H

#include <pthread.h>
#include <semaphore.h>
#include <sys/ptrace.h>

#ifdef __GLIBC__
typedef enum __ptrace_request ptrace_wrap_ptrace_request;
#else
typedef int ptrace_wrap_ptrace_request;
#endif

typedef enum {
	PTRACE_WRAP_REQUEST_TYPE_STOP,
	PTRACE_WRAP_REQUEST_TYPE_PTRACE,
	PTRACE_WRAP_REQUEST_TYPE_FORK
} ptrace_wrap_request_type;

typedef struct ptrace_wrap_request_t {
	ptrace_wrap_request_type type;
	union {
		struct {
			ptrace_wrap_ptrace_request request;
			pid_t pid;
			void *addr;
			void *data;
			int *_errno;
		} ptrace;
		struct {
			void (*child_callback)(void *);
			void *child_callback_user;
			int *_errno;
		} fork;
	};
} ptrace_wrap_request;

typedef struct ptrace_wrap_instance_t {
	pthread_t th;
	sem_t request_sem;
	ptrace_wrap_request request;
	sem_t result_sem;
	union {
		long ptrace_result;
		pid_t fork_result;
	};
} ptrace_wrap_instance;

int ptrace_wrap_instance_start(ptrace_wrap_instance *inst);
void ptrace_wrap_instance_stop(ptrace_wrap_instance *inst);
long ptrace_wrap(ptrace_wrap_instance *inst, ptrace_wrap_ptrace_request request, pid_t pid, void *addr, void *data);
pid_t ptrace_wrap_fork(ptrace_wrap_instance *inst, void (*child_callback)(void *), void *child_callback_user);

#endif //PTRACE_WRAP_H
