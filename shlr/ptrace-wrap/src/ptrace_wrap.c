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

#include <ptrace_wrap.h>

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

static void *th_run(ptrace_wrap_instance *inst);

int ptrace_wrap_instance_start(ptrace_wrap_instance *inst) {
	int r = sem_init (&inst->request_sem, 0, 0);
	if (r != 0) {
		return r;
	}

	r = sem_init (&inst->result_sem, 0, 0);
	if (r != 0) {
		sem_destroy (&inst->request_sem);
		return r;
	}

	r = pthread_create (&inst->th, NULL, (void *(*)(void *)) th_run, inst);
	if (r != 0) {
		sem_destroy (&inst->request_sem);
		sem_destroy (&inst->result_sem);
		return r;
	}

	return 0;
}

void ptrace_wrap_instance_stop(ptrace_wrap_instance *inst) {
	inst->request.type = PTRACE_WRAP_REQUEST_TYPE_STOP;
	sem_post (&inst->request_sem);
	pthread_join (inst->th, NULL);
	sem_destroy (&inst->request_sem);
	sem_destroy (&inst->result_sem);
}

static void wrap_ptrace(ptrace_wrap_instance *inst) {
	inst->ptrace_result = ptrace (
			inst->request.ptrace.request,
			inst->request.ptrace.pid,
			inst->request.ptrace.addr,
			inst->request.ptrace.data);
	if (inst->request.ptrace._errno) {
		*inst->request.ptrace._errno = errno;
	}
}

static void wrap_fork(ptrace_wrap_instance *inst) {
	pid_t r = fork();
	if (r == 0) {
		inst->request.fork.child_callback (inst->request.fork.child_callback_user);
	} else {
		inst->fork_result = r;
	}
}

static void wrap_func(ptrace_wrap_instance *inst) {
	inst->func_result = inst->request.func.func (inst->request.func.user);
}

static void *th_run(ptrace_wrap_instance *inst) {
	while (1) {
		sem_wait (&inst->request_sem);
		switch (inst->request.type) {
		case PTRACE_WRAP_REQUEST_TYPE_STOP:
			goto stop;
		case PTRACE_WRAP_REQUEST_TYPE_PTRACE:
			wrap_ptrace (inst);
			break;
		case PTRACE_WRAP_REQUEST_TYPE_FORK:
			wrap_fork (inst);
			break;
		case PTRACE_WRAP_REQUEST_TYPE_FUNC:
			wrap_func (inst);
			break;
		}
		sem_post (&inst->result_sem);
	}
stop:
	return NULL;
}

long ptrace_wrap(ptrace_wrap_instance *inst, ptrace_wrap_ptrace_request request, pid_t pid, void *addr, void *data) {
	if (inst->th == pthread_self ()) {
		return ptrace (request, pid, addr, data);
	}

	int _errno = 0;
	inst->request.type = PTRACE_WRAP_REQUEST_TYPE_PTRACE;
	inst->request.ptrace.request = request;
	inst->request.ptrace.pid = pid;
	inst->request.ptrace.addr = addr;
	inst->request.ptrace.data = data;
	inst->request.ptrace._errno = &_errno;
	sem_post (&inst->request_sem);
	sem_wait (&inst->result_sem);
	errno = _errno;
	return inst->ptrace_result;
}

pid_t ptrace_wrap_fork(ptrace_wrap_instance *inst, void (*child_callback)(void *), void *child_callback_user) {
	if (inst->th == pthread_self ()) {
		pid_t r = fork ();
		if (r == 0) {
			child_callback (child_callback_user);
			return 0;
		} else {
			return r;
		}
	}

	int _errno = 0;
	inst->request.type = PTRACE_WRAP_REQUEST_TYPE_FORK;
	inst->request.fork.child_callback = child_callback;
	inst->request.fork.child_callback_user = child_callback_user;
	inst->request.fork._errno = &_errno;
	sem_post (&inst->request_sem);
	sem_wait (&inst->result_sem);
	errno = _errno;
	return inst->fork_result;
}

void *ptrace_wrap_func(ptrace_wrap_instance *inst, ptrace_wrap_func_func func, void *user) {
	if (inst->th == pthread_self ()) {
		return func (user);
	}

	inst->request.type = PTRACE_WRAP_REQUEST_TYPE_FUNC;
	inst->request.func.func = func;
	inst->request.func.user = user;
	sem_post (&inst->request_sem);
	sem_wait (&inst->result_sem);
	return inst->func_result;
}