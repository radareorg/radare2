/* radare2 Enhanced Ptrace IO Plugin for Android - Based on user's Memscan.c
 * Provides advanced process memory access with game hacking capabilities
 * Copyright 2025 - MIT License
 */

#define R_LOG_ORIGIN "io.ptrace_enhanced"
#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

// Forward declarations for syscalls if not available
#ifndef process_vm_readv
ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, 
		const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
	return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

#ifndef process_vm_writev  
ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt,
		const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
	return syscall(__NR_process_vm_writev, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}
#endif

// Enhanced ptrace data structure
typedef struct {
	pid_t pid;
	FILE* maps_file;
	size_t buffer_size;
	uint8_t* buffer;
	bool initialized;
} EnhancedPtraceData;

// Plugin declaration
RIOPlugin r_io_plugin_ptrace_enhanced;

static void cleanup_ptrace_data(EnhancedPtraceData* data) {
	if (!data) {
		return;
	}

	if (data->maps_file) {
		fclose(data->maps_file);
		data->maps_file = NULL;
	}

	if (data->buffer) {
		free(data->buffer);
		data->buffer = NULL;
	}

	data->initialized = false;
}

static size_t enhanced_read_memory(EnhancedPtraceData* data, uint64_t addr, void* buffer, size_t size) {
	if (!data || !data->initialized || !buffer || size == 0) {
		return 0;
	}

	struct iovec local_iov = {buffer, size};
	struct iovec remote_iov = {(void*)addr, size};

	ssize_t bytes = process_vm_readv(data->pid, &local_iov, 1, &remote_iov, 1, 0);
	return bytes < 0 ? 0 : (size_t)bytes;
}

static size_t enhanced_write_memory(EnhancedPtraceData* data, uint64_t addr, const void* buffer, size_t size) {
	if (!data || !data->initialized || !buffer || size == 0) return 0;

	struct iovec local_iov = {(void*)buffer, size};
	struct iovec remote_iov = {(void*)addr, size};

	ssize_t bytes = process_vm_writev(data->pid, &local_iov, 1, &remote_iov, 1, 0);
	return bytes < 0 ? 0 : (size_t)bytes;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith(pathname, PTRACE_ENHANCED_URI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check(io, pathname, 0)) {
		return NULL;
	}

	// Extract PID from URI: ptrace://1234
	pathname += strlen(PTRACE_ENHANCED_URI);
	pid_t pid = (pid_t)strtol(pathname, NULL, 10);

	if (pid <= 0 || pid > 4194304) {
		R_LOG_ERROR("Invalid PID: %d", pid);
		return NULL;
	}

	// Initialize enhanced ptrace data
	EnhancedPtraceData *data = R_NEW0(EnhancedPtraceData);
	if (!data) {
		R_LOG_ERROR("Memory allocation failed");
		return NULL;
	}

	data->pid = pid;
	data->buffer_size = DEFAULT_BUFFER_SIZE;

	// Open maps file
	char maps_path[MAX_PATH_LENGTH];
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	data->maps_file = fopen(maps_path, "r");

	if (!data->maps_file) {
		R_LOG_ERROR("Cannot open %s: %s", maps_path, strerror(errno));
		free(data);
		return NULL;
	}

	// Allocate buffer
	data->buffer = (uint8_t*)malloc(data->buffer_size);
	if (!data->buffer) {
		R_LOG_ERROR("Buffer allocation failed");
		cleanup_ptrace_data(data);
		free(data);
		return NULL;
	}

	// Test process_vm_readv access
	char test_buffer;
	struct iovec local_iov = {&test_buffer, 1};
	struct iovec remote_iov = {(void*)0x1, 1};
	errno = 0;
	process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);

	if (errno == EPERM || errno == ESRCH) {
		R_LOG_ERROR("Permission denied or process not found for PID %d", pid);
		cleanup_ptrace_data(data);
		free(data);
		return NULL;
	}

	data->initialized = true;

	R_LOG_INFO("Enhanced ptrace opened for PID %d", pid);

	return r_io_desc_new(io, &r_io_plugin_ptrace_enhanced, pathname, 
			R_PERM_RW | (rw & R_PERM_X), mode, data);
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	EnhancedPtraceData *data = desc->data;
	if (!data || !data->initialized) {
		return -1;
	}

	ut64 addr = r_io_desc_seek(desc, 0LL, R_IO_SEEK_CUR);
	size_t bytes_read = enhanced_read_memory(data, addr, buf, count);

	return (int)bytes_read;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	EnhancedPtraceData *data = desc->data;
	if (!data || !data->initialized) {
		return -1;
	}

	ut64 addr = r_io_desc_seek(desc, 0LL, R_IO_SEEK_CUR);
	size_t bytes_written = enhanced_write_memory(data, addr, buf, count);

	return (int)bytes_written;
}

static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	switch (whence) {
	case SEEK_SET:
		return r_io_desc_seek(desc, offset, R_IO_SEEK_SET);
	case SEEK_CUR:
		return r_io_desc_seek(desc, offset, R_IO_SEEK_CUR);  
	case SEEK_END:
		return UT64_MAX; // Virtual memory space
	}
	return offset;
}

static bool __close(RIODesc *desc) {
	EnhancedPtraceData *data = desc->data;
	if (data) {
		cleanup_ptrace_data(data);
		free(data);
	}
	return true;
}

// Enhanced system commands for memory operations
static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	EnhancedPtraceData *data = desc->data;
	if (!data || !data->initialized) {
		return NULL;
	}

	if (r_str_startswith(cmd, "scan ")) {
		// Memory pattern scanning
		R_LOG_INFO("Pattern scan requested: %s", cmd + 5);
		// TODO: Implement pattern scanning logic
		return strdup("Pattern scanning not yet implemented\n");
	}

	if (r_str_startswith(cmd, "dump ")) {
		// Memory dumping
		R_LOG_INFO("Memory dump requested: %s", cmd + 5);
		// TODO: Implement memory dumping logic
		return strdup("Memory dumping not yet implemented\n");
	}

	if (r_str_startswith(cmd, "dex")) {
		// DEX scanning and dumping
		R_LOG_INFO("DEX scan requested");
		// TODO: Implement DEX scanning logic
		return strdup("DEX scanning not yet implemented\n");
	}

	if (r_str_startswith(cmd, "strings")) {
		// String extraction
		R_LOG_INFO("String extraction requested");
		// TODO: Implement string extraction logic
		return strdup("String extraction not yet implemented\n");
	}

	return NULL;
}

static int __getpid(RIODesc *desc) {
	EnhancedPtraceData *data = desc->data;
	return data ? data->pid : -1;
}

// Plugin definition
RIOPlugin r_io_plugin_ptrace_enhanced = {
	.meta = {
		.name = "ptrace_enhanced",
		.desc = "Enhanced ptrace with process_vm_readv for Android game hacking",
		.license = "MIT",
		.author = "Based on user's Memscan.c",
	},
	.uris = PTRACE_ENHANCED_URI,
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.seek = __lseek,
	.system = __system,
	.check = __check,
	.getpid = __getpid,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ptrace_enhanced,
	.version = R2_VERSION
};
#endif
