/* radare2 - MIT - Copyright 2025 - apkunpacker */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
/* Read remote process memory using process_vm APIs */
#if __linux__

#define R_LOG_ORIGIN "io.pvm"
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#define PTRACE_ENHANCED_URI "pvm://"
#define DEFAULT_BUFFER_SIZE 4096
#define MAX_LINE_LENGTH 2048
#define MAX_PATH_LENGTH 1024

// Syscall declarations if not available
#ifndef process_vm_readv
static ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
		const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
	return syscall (__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

#ifndef process_vm_writev
static ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
		const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
	return syscall (__NR_process_vm_writev, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

typedef struct {
	pid_t pid;
	FILE* maps_file;
	size_t buffer_size;
	uint8_t* buffer;
	bool initialized;
} ProcessVmData;

static void cleanup_ptrace_data(ProcessVmData* data) {
	if (!data) {
		return;
	}
	if (data->maps_file) {
		fclose (data->maps_file);
		data->maps_file = NULL;
	}
	if (data->buffer) {
		free (data->buffer);
		data->buffer = NULL;
	}
	data->initialized = false;
}

static size_t pvm_read_memory(ProcessVmData* data, uint64_t addr, void* buffer, size_t size) {
	if (!data || !data->initialized || !buffer || size == 0) {
		return 0;
	}

	struct iovec local_iov = {buffer, size};
	struct iovec remote_iov = {(void *)(uintptr_t)addr, size};
	ssize_t bytes = process_vm_readv (data->pid, &local_iov, 1, &remote_iov, 1, 0);
	return bytes < 0 ? 0 : (size_t)bytes;
}

static size_t pvm_write_memory(ProcessVmData* data, uint64_t addr, const void* buffer, size_t size) {
	if (!data || !data->initialized || !buffer || size == 0) {
		return 0;
	}
	struct iovec local_iov = {(void*)buffer, size};
	struct iovec remote_iov = {(void *)(uintptr_t)addr, size};

	ssize_t bytes = process_vm_writev (data->pid, &local_iov, 1, &remote_iov, 1, 0);
	return bytes < 0 ? 0 : (size_t)bytes;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, PTRACE_ENHANCED_URI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, 0)) {
		return NULL;
	}

	// Extract PID from URI: ptrace://1234
	pathname += strlen (PTRACE_ENHANCED_URI);
	pid_t pid = (pid_t)strtol (pathname, NULL, 10);

	if (pid <= 0 || pid > 4194304) {
		R_LOG_ERROR ("Invalid PID: %d", pid);
		return NULL;
	}

	// Initialize enhanced ptrace data
	ProcessVmData *data = R_NEW0 (ProcessVmData);
	data->pid = pid;
	data->buffer_size = DEFAULT_BUFFER_SIZE;

	// Open maps file
	char maps_path[MAX_PATH_LENGTH];
	snprintf (maps_path, sizeof (maps_path), "/proc/%d/maps", pid);
	data->maps_file = fopen (maps_path, "r");

	if (!data->maps_file) {
		R_LOG_ERROR ("Cannot open %s: %s", maps_path, strerror (errno));
		free (data);
		return NULL;
	}

	// Allocate buffer
	data->buffer = (uint8_t*)malloc (data->buffer_size);
	if (!data->buffer) {
		R_LOG_ERROR ("Buffer allocation failed");
		cleanup_ptrace_data (data);
		free (data);
		return NULL;
	}

	// Test process_vm_readv access
	char test_buffer;
	struct iovec local_iov = {&test_buffer, 1};
	struct iovec remote_iov = {(void *)(uintptr_t)1, 1};
	errno = 0;
	process_vm_readv (pid, &local_iov, 1, &remote_iov, 1, 0);

	if (errno == EPERM || errno == ESRCH) {
		R_LOG_ERROR ("Permission denied or process not found for PID %d", pid);
		cleanup_ptrace_data (data);
		free (data);
		return NULL;
	}

	data->initialized = true;

	R_LOG_INFO ("Process VM opened for PID %d", pid);
	return r_io_desc_new (io, &r_io_plugin_pvm, pathname,
			R_PERM_RW | (rw & R_PERM_X), mode, data);
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	ProcessVmData *data = desc->data;
	if (!data || !data->initialized) {
		return -1;
	}

	ut64 addr = r_io_desc_seek (desc, 0LL, R_IO_SEEK_CUR);
	return (int)pvm_read_memory (data, addr, buf, count);
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	ProcessVmData *data = desc->data;
	if (!data || !data->initialized) {
		return -1;
	}
	ut64 addr = r_io_desc_seek(desc, 0LL, R_IO_SEEK_CUR);
	return (int)pvm_write_memory (data, addr, buf, count);
}

static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
		return r_io_desc_seek (desc, offset, whence);
	case SEEK_END:
		return UT64_MAX; // The the whole address space
	}
	return offset;
}

static bool __close(RIODesc *desc) {
	ProcessVmData *data = desc->data;
	if (data) {
		cleanup_ptrace_data (data);
		free (data);
	}
	return true;
}

static int __getpid(RIODesc *desc) {
	ProcessVmData *data = desc->data;
	return data ? data->pid : -1;
}

RIOPlugin r_io_plugin_pvm = {
	.meta = {
		.name = "pvm",
		.desc = "Access remote process memory using the Linux process_vm APIs",
		.license = "MIT",
		.author = "apkunpacker",
	},
	.uris = PTRACE_ENHANCED_URI,
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.seek = __lseek,
	.check = __check,
	.getpid = __getpid,
};

#else
RIOPlugin r_io_plugin_pvm = {
	.meta = {
		.name = NULL
	},
};
#endif
