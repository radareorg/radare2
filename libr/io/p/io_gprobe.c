/* radare - LGPL - Copyright 2018 - Dirk Eibach, Guntermann & Drunck GmbH */

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_util/r_print.h>

#if __UNIX__
#include <errno.h>
#include <fcntl.h>
#endif

#define USE_OWNTIMER 1
#if USE_OWNTIMER
#include "io_gprobe.h"
#else
#define Timersub timersub
#define Timeradd timeradd
#define Timercmp timercmp
#endif

#if __WINDOWS__
#include <cfgmgr32.h>
#include <setupapi.h>
#include <tchar.h>
#include <windows.h>
#else

#if __linux__ ||  __APPLE__ || __OpenBSD__ || __FreeBSD__ || __NetBSD__ || __DragonFly__
#include <sys/ioctl.h>
#include <termios.h>
#else
#include <stropts.h>
#endif

#endif

#define GPROBE_SIZE (1LL << 32)
#define GPROBE_I2C_ADDR 0x6e

#define I2C_SLAVE 0x0703

/* serial port code adapted from git://sigrok.org/libserialport */
struct gport {
	const char *name;
#if __WINDOWS__
	HANDLE hdl;
	COMMTIMEOUTS timeouts;
	OVERLAPPED write_ovl;
	OVERLAPPED read_ovl;
	OVERLAPPED wait_ovl;
	DWORD events;
	BYTE pending_byte;
	BOOL writing;
	BOOL wait_running;
#else
	int fd;
#endif
	int (*send_request) (struct gport *port, RBuffer *request);
	int (*get_reply) (struct gport *port, ut8 cmd, RBuffer *reply);
	void (*frame) (RBuffer *frame);

	ut32 max_rx_size;
	ut32 max_tx_size;
};

typedef struct {
	struct gport gport;
	ut64 offset;
} RIOGprobe;

enum {
	GPROBE_DEBUGON = 0x09,
	GPROBE_DEBUGOFF = 0x0a,
	GPROBE_ACK = 0x0c,
	GPROBE_RESET = 0x20,
	GPROBE_GET_DEVICE_ID = 0x30,
	GPROBE_GET_INFORMATION = 0x40,
	GPROBE_RAM_READ_2 = 0x52,
	GPROBE_RAM_WRITE_2 = 0x53,
	GPROBE_RUN_CODE_2 = 0x54,
};

#if __UNIX__
static ut8 gprobe_checksum_i2c (const ut8 *p, unsigned int size, ut8 initial) {
	ut8 res = initial;
	unsigned int k;

	for (k = 0; k < size; ++k) {
		res ^= p[k];
	}

	return res;
}

static void gprobe_frame_i2c(RBuffer *frame) {
	ut8 size = r_buf_size (frame) + 1;
	ut8 header[] = {0x51, 0x80 + size + 3, 0xc2, 0x00, 0x00};

	r_buf_prepend_bytes (frame, &size, 1);
	r_buf_prepend_bytes (frame, header, sizeof (header));

	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (frame, &tmpsz);
	ut8 checksum = gprobe_checksum_i2c (tmp, tmpsz, GPROBE_I2C_ADDR);

	r_buf_append_bytes (frame, &checksum, 1);
}

static int gprobe_get_reply_i2c(struct gport *port, ut8 cmd, RBuffer *reply) {
	ut8 buf[131];
	int count;
	int ddc2bi3_len;
	ut8 addr = 0x50;
	ut8 checksum;

	r_sys_usleep (40000);

	count = read (port->fd, buf, sizeof (buf));

	if (count != sizeof (buf)) {
		return -1;
	}

	ddc2bi3_len = buf[1] & ~0x80;

	if (((buf[0] & 0xfe) != GPROBE_I2C_ADDR)
	    || !(buf[1] & 0x80)
	    || (buf[2] != 0xc2)
	    || (buf[3] != 0x00)
	    || (buf[4] != 0x00)
	    || (cmd != buf[6])
	    || !(buf[5] - 2)
	    || (buf[5] != ddc2bi3_len - 2)) {
		return -1;
	}

	checksum = gprobe_checksum_i2c (&addr, 1, 0);

	if (gprobe_checksum_i2c (buf, ddc2bi3_len + 2, checksum) != buf[ddc2bi3_len + 2]) {
		eprintf ("gprobe rx checksum error\n");
	}

	r_buf_append_bytes (reply, buf + 7, buf[5] - 3);

	return 0;
}

static int gprobe_send_request_i2c(struct gport *port, RBuffer *request) {
	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (request, &tmpsz);
	if (write (port->fd, tmp, tmpsz) != r_buf_size (request)) {
		return -1;
	}
	return 0;
}

static int i2c_open(struct gport *port) {
	char *end, filename[32];
	int i2cbus = strtol (port->name + 4, &end, 0);

	if (*end) {
		return -1;
	}

	snprintf (filename, sizeof (filename), "/dev/i2c/%d", i2cbus);
	filename[sizeof (filename) - 1] = '\0';
	int file = r_sandbox_open (filename, O_RDWR, 0);

	if (file < 0 && (errno == ENOENT || errno == ENOTDIR)) {
		sprintf (filename, "/dev/i2c-%d", i2cbus);
		file = r_sandbox_open (filename, O_RDWR, 0);
	}
	if (file < 0) {
		return -1;
	}
	if (ioctl (file, I2C_SLAVE, GPROBE_I2C_ADDR >> 1) < 0) {
		r_sandbox_close (file);
		port->fd = -1;
		return -1;
	}
	port->fd = file;
	return 0;
}
#endif

static int sp_close(struct gport *port) {
#if __WINDOWS__
	/* Returns non-zero upon success, 0 upon failure. */
	if (CloseHandle (port->hdl) == 0){
		return -1;
	}
	port->hdl = INVALID_HANDLE_VALUE;

	/* Close event handles for overlapped structures. */
#define CLOSE_OVERLAPPED(ovl)                                   \
	do {                                                    \
		if (port->ovl.hEvent != INVALID_HANDLE_VALUE && \
			CloseHandle (port->ovl.hEvent) == 0)    \
			return -1;                              \
	} while (0)
	CLOSE_OVERLAPPED (read_ovl);
	CLOSE_OVERLAPPED (write_ovl);
	CLOSE_OVERLAPPED (wait_ovl);
#else
	if (close (port->fd) == -1) {
		return -1;
	}

	port->fd = -1;
#endif
	return 0;
}

#if __WINDOWS__
/* To be called after port receive buffer is emptied. */
static int restart_wait (struct gport *port) {
	DWORD wait_result;

	if (port->wait_running) {
		/* Check status of running wait operation. */
		if (GetOverlappedResult (port->hdl, &port->wait_ovl,
					 &wait_result, FALSE)) {
			port->wait_running = FALSE;
		} else if (GetLastError () == ERROR_IO_INCOMPLETE) {
			return 0;
		}
		return -1;
	}
	if (!port->wait_running) {
		/* Start new wait operation. */
		if (WaitCommEvent (port->hdl, &port->events,
				   &port->wait_ovl)) {
		} else if (GetLastError () == ERROR_IO_PENDING) {
			port->wait_running = TRUE;
		}
		return -1;
	}
	return 0;
}
#endif

static int sp_open (struct gport *port) {
#if __WINDOWS__
	int ret;
	DWORD errors;
	char *escaped_port_name;
	COMSTAT status;
	DCB dcb;
	LPTSTR filename_;

	/* Prefix port name with '\\.\' to work with ports above COM9. */
	if (!(escaped_port_name = malloc (strlen (port->name) + 5))) {
		return -1;
	}
	sprintf (escaped_port_name, "\\\\.\\%s", port->name);

	filename_ = r_sys_conv_utf8_to_win (escaped_port_name);

	port->hdl = CreateFile (filename_, GENERIC_READ | GENERIC_WRITE, 0, 0,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 0);

	free (escaped_port_name);

	if (port->hdl == INVALID_HANDLE_VALUE) {
		return -1;
	}

	/* All timeouts initially disabled. */
	port->timeouts.ReadIntervalTimeout = 0;
	port->timeouts.ReadTotalTimeoutMultiplier = 0;
	port->timeouts.ReadTotalTimeoutConstant = 0;
	port->timeouts.WriteTotalTimeoutMultiplier = 0;
	port->timeouts.WriteTotalTimeoutConstant = 0;

	if (SetCommTimeouts (port->hdl, &port->timeouts) == 0) {
		sp_close (port);
		return -1;
	}

	/* Prepare OVERLAPPED structures. */
#define INIT_OVERLAPPED(ovl)                                                                             \
	do {                                                                                             \
		memset (&port->ovl, 0, sizeof (port->ovl));                                              \
		port->ovl.hEvent = INVALID_HANDLE_VALUE;                                                 \
		if ((port->ovl.hEvent = CreateEvent (NULL, TRUE, TRUE, NULL)) == INVALID_HANDLE_VALUE) { \
			sp_close (port);                                                                 \
			return -1;                                                                       \
		}                                                                                        \
	} while (0)

	INIT_OVERLAPPED (read_ovl);
	INIT_OVERLAPPED (write_ovl);
	INIT_OVERLAPPED (wait_ovl);

	/* Set event mask for RX and error events. */
	if (SetCommMask (port->hdl, EV_RXCHAR | EV_ERR) == 0) {
		sp_close (port);
		return -1;
	}

	port->writing = FALSE;
	port->wait_running = FALSE;

	ret = restart_wait (port);

	if (ret < 0) {
		sp_close (port);
		return -1;
	}

	dcb.fBinary = TRUE;
	dcb.fDsrSensitivity = FALSE;
	dcb.fErrorChar = FALSE;
	dcb.fNull = FALSE;
	dcb.fAbortOnError = FALSE;

	if (ClearCommError (port->hdl, &errors, &status) == 0) {
		return -1;
	}

	dcb.BaudRate = CBR_115200;

	dcb.ByteSize = 8;
	dcb.Parity = NOPARITY;
	dcb.StopBits = ONESTOPBIT;
	dcb.fRtsControl = RTS_CONTROL_DISABLE;
	dcb.fOutxCtsFlow = FALSE;
	dcb.fDtrControl = DTR_CONTROL_DISABLE;
	dcb.fOutxDsrFlow = FALSE;
	dcb.fInX = FALSE;
	dcb.fOutX = FALSE;

	if (!SetCommState (port->hdl, &dcb)) {
		return -1;
	}

	return 0;
#else
	struct termios tty = {0};

	if ((port->fd = r_sandbox_open (port->name, O_NONBLOCK | O_NOCTTY | O_RDWR, 0)) < 0) {
		return -1;
	}

	if (tcgetattr (port->fd, &tty) != 0) {
		sp_close (port);
		return -1;
	}

	cfsetospeed (&tty, B115200);
	cfsetispeed (&tty, B115200);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
	tty.c_iflag &= ~IGNBRK;
	tty.c_lflag = 0;
	tty.c_oflag = 0;
	tty.c_cc[VMIN] = 0;
	tty.c_cc[VTIME] = 0;
	tty.c_iflag &= ~(IXON | IXOFF | IXANY);

	tty.c_cflag |= (CLOCAL | CREAD);
	tty.c_cflag &= ~(PARENB | PARODD);
	tty.c_cflag &= ~CSTOPB;
#ifdef CRTSCTS
	tty.c_cflag &= ~CRTSCTS;
#else
	tty.c_cflag &= ~020000000000;
#endif

	if (tcsetattr (port->fd, TCSANOW, &tty) != 0) {
		return -1;
	}

	return 0;
#endif
}

#if __WINDOWS__
/* Restart wait operation if buffer was emptied. */
static int restart_wait_if_needed (struct gport *port, unsigned int bytes_read) {
	DWORD errors;
	COMSTAT comstat;

	if (bytes_read == 0) {
		return 0;
	}

	if (ClearCommError (port->hdl, &errors, &comstat) == 0) {
		return -1;
	}

	if (comstat.cbInQue == 0) {
		if (restart_wait (port)) {
			return -1;
		}
	}

	return 0;
}
#endif

static int sp_blocking_read (struct gport *port, void *buf,
			     size_t count, unsigned int timeout_ms) {
#if __WINDOWS__
	DWORD bytes_read = 0;

	/* Set timeout. */
	if (port->timeouts.ReadIntervalTimeout != 0 ||
	    port->timeouts.ReadTotalTimeoutMultiplier != 0 ||
	    port->timeouts.ReadTotalTimeoutConstant != timeout_ms) {
		port->timeouts.ReadIntervalTimeout = 0;
		port->timeouts.ReadTotalTimeoutMultiplier = 0;
		port->timeouts.ReadTotalTimeoutConstant = timeout_ms;
		if (SetCommTimeouts (port->hdl, &port->timeouts) == 0) {
			return -1;
		}
	}

	/* Start read. */
	if (ReadFile (port->hdl, buf, count, NULL, &port->read_ovl)) {
		bytes_read = count;
	} else if (GetLastError () == ERROR_IO_PENDING) {
		if (GetOverlappedResult (port->hdl, &port->read_ovl, &bytes_read, TRUE) == 0)
			return -1;
	} else {
		return -1;
	}

	if (restart_wait_if_needed (port, bytes_read)) {
		return -1;
	}

	return bytes_read;
#else
	size_t bytes_read = 0;
	unsigned char *ptr = (unsigned char *)buf;
	struct timeval start, delta, now, end = {0, 0};
	int started = 0;
	fd_set fds;
	int result;

	if (timeout_ms) {
		/* Get time at start of operation. */
		gettimeofday (&start, NULL);
		/* Define duration of timeout. */
		delta.tv_sec = timeout_ms / 1000;
		delta.tv_usec = (timeout_ms % 1000) * 1000;
		/* Calculate time at which we should give up. */
		Timeradd (&start, &delta, &end);
	}

	FD_ZERO (&fds);
	FD_SET (port->fd, &fds);

	/* Loop until we have the requested number of bytes. */
	while (bytes_read < count) {
		/*
		 * Check timeout only if we have run select() at least once,
		 * to avoid any issues if a short timeout is reached before
		 * select() is even run.
		 */
		if (timeout_ms && started) {
			gettimeofday (&now, NULL);
			if (Timercmp (&now, &end, >)) {
				/* Timeout has expired. */
				break;
			}
			Timersub (&end, &now, &delta);
		}
		result = select (port->fd + 1, &fds, NULL, NULL, timeout_ms ? &delta : NULL);
		started = 1;
		if (result < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				return -1;
			}
		} else if (result == 0) {
			/* Timeout has expired. */
			break;
		}

		/* Do read. */
		result = read (port->fd, ptr, count - bytes_read);

		if (result < 0) {
			if (errno == EAGAIN) {
				/*
				 * This shouldn't happen because we did a
				 * select() first, but handle anyway.
				 */
				continue;
			} else {
				/* This is an actual failure. */
				return -1;
			}
		}

		bytes_read += result;
		ptr += result;
	}

	return bytes_read;
#endif
}

static int sp_flush (struct gport *port) {
#if __WINDOWS__
	/* Returns non-zero upon success, 0 upon failure. */
	if (PurgeComm (port->hdl, PURGE_RXCLEAR) == 0) {
		return -1;
	}

	if (restart_wait (port)) {
		return -1;
	}
#else
	if (tcflush (port->fd, TCIFLUSH) < 0) {
		return -1;
	}
#endif

	return 0;
}

#if __WINDOWS__
static int await_write_completion (struct gport *port) {
	DWORD bytes_written;
	BOOL result;

	/* Wait for previous non-blocking write to complete, if any. */
	if (port->writing) {
		result = GetOverlappedResult (port->hdl, &port->write_ovl, &bytes_written, TRUE);
		port->writing = 0;
		if (!result) {
			return -1;
		}
	}

	return 0;
}
#endif

static int sp_blocking_write (struct gport *port, const void *buf,
			      size_t count, unsigned int timeout_ms) {
#if __WINDOWS__
	DWORD bytes_written = 0;

	if (await_write_completion (port)) {
		return -1;
	}

	/* Set timeout. */
	if (port->timeouts.WriteTotalTimeoutConstant != timeout_ms) {
		port->timeouts.WriteTotalTimeoutConstant = timeout_ms;
		if (SetCommTimeouts (port->hdl, &port->timeouts) == 0) {
			return -1;
		}
	}

	/* Start write. */
	if (WriteFile (port->hdl, buf, count, NULL, &port->write_ovl)) {
		return count;
	} else if (GetLastError () == ERROR_IO_PENDING) {
		if (GetOverlappedResult (port->hdl, &port->write_ovl, &bytes_written, TRUE) == 0) {
			if (GetLastError () == ERROR_SEM_TIMEOUT)
				return 0;
			else
				return -1;
		}
		return bytes_written;
	} else {
		return -1;
	}
#else
	size_t bytes_written = 0;
	unsigned char *ptr = (unsigned char *)buf;
	struct timeval start, delta, now, end = {0, 0};
	int started = 0;
	fd_set fds;
	int result;

	if (timeout_ms) {
		/* Get time at start of operation. */
		gettimeofday (&start, NULL);
		/* Define duration of timeout. */
		delta.tv_sec = timeout_ms / 1000;
		delta.tv_usec = (timeout_ms % 1000) * 1000;
		/* Calculate time at which we should give up. */
		Timeradd (&start, &delta, &end);
	}

	FD_ZERO (&fds);
	FD_SET (port->fd, &fds);

	/* Loop until we have written the requested number of bytes. */
	while (bytes_written < count) {
		/*
		 * Check timeout only if we have run select() at least once,
		 * to avoid any issues if a short timeout is reached before
		 * select() is even run.
		 */
		if (timeout_ms && started) {
			gettimeofday (&now, NULL);
			if (Timercmp (&now, &end, >)) {
				/* Timeout has expired. */
				break;
			}
			Timersub (&end, &now, &delta);
		}
		result = select (port->fd + 1, NULL, &fds, NULL, timeout_ms ? &delta : NULL);
		started = 1;
		if (result < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				return -1;
			}
		} else if (result == 0) {
			/* Timeout has expired. */
			break;
		}

		/* Do write. */
		result = write (port->fd, ptr, count - bytes_written);

		if (result < 0) {
			if (errno == EAGAIN) {
				/* This shouldn't happen because we did a select() first, but handle anyway. */
				continue;
			} else {
				/* This is an actual failure. */
				return -1;
			}
		}

		bytes_written += result;
		ptr += result;
	}

	return bytes_written;
#endif
}

static ut8 gprobe_checksum (const ut8 *p, unsigned int size) {
	ut8 res = 0;
	unsigned int k;

	for (k = 0; k < size; ++k) {
		res += p[k];
	}

	res = ~res + 1;

	return res;
}

static void gprobe_frame_sp(RBuffer *frame) {
	ut64 size;
	const ut8 *tmp = r_buf_data (frame, &size);
	size += 2;
	ut8 checksum;

	r_buf_prepend_bytes (frame, (const ut8 *)&size, 1);
	checksum = gprobe_checksum (tmp, size - 1);

	r_buf_append_bytes (frame, &checksum, 1);
}

static int gprobe_get_reply_sp(struct gport *port, ut8 cmd, RBuffer *reply) {
	ut8 buf[256];
	int count = sp_blocking_read (port, buf, 2, 50);

	if (count < 2) {
		return -1;
	}

	if (cmd != buf[1]) {
		return -1;
	}

	if (!(buf[0] - 2)) {
		return 0;
	}

	count = sp_blocking_read (port, buf + 2, buf[0] - 2, 50) + 2;

	if (count != buf[0]) {
		return -1;
	}

/* checksumming answers does not work reliably */
#if 0
	if (gprobe_checksum(buf, count - 1) != buf[count - 1]) {
		printf("### CHECKSUM FAILED\n");
	}
#endif

	r_buf_append_bytes (reply, buf + 2, count - 3);

	return 0;
}

static int gprobe_send_request_sp(struct gport *port, RBuffer *request) {
	sp_flush (port);

	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (request, &tmpsz);
	if (sp_blocking_write (port, tmp, tmpsz, 100) != tmpsz) {
		return -1;
	}

	return 0;
}

static int gprobe_read(struct gport *port, ut32 addr, ut8 *buf, ut32 count) {
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_RAM_READ_2;
	ut8 addr_be[4];
	ut8 count_be[4];
	int res;

	if (!request || !reply) {
		r_buf_free (request);
		r_buf_free (reply);
		return -1;
	}

	count = R_MIN (port->max_rx_size, count);

	r_write_be32 (addr_be, addr);
	r_write_be32 (count_be, count);

	r_buf_append_bytes (request, &cmd, 1);
	r_buf_append_bytes (request, addr_be, 4);
	r_buf_append_bytes (request, count_be, 4);

	port->frame (request);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, cmd, reply)) {
		goto fail;
	}

	res = r_buf_read_at (reply, 0, buf, r_buf_size (reply));

	r_buf_free (request);
	r_buf_free (reply);

	return res;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_write (struct gport *port, ut32 addr, const ut8 *buf, ut32 count) {
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_RAM_WRITE_2;
	ut8 addr_be[4];
	ut8 count_be[4];

	if (!request || !reply) {
		r_buf_free (request);
		r_buf_free (reply);
		return -1;
	}

	count = R_MIN (port->max_tx_size, count);

	r_write_be32 (addr_be, addr);
	r_write_be32 (count_be, count);

	r_buf_append_bytes (request, &cmd, 1);
	r_buf_append_bytes (request, addr_be, 4);
	r_buf_append_bytes (request, buf, count);

	port->frame (request);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, GPROBE_ACK, reply)) {
		goto fail;
	}

	r_buf_free (request);
	r_buf_free (reply);

	return count;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_reset (struct gport *port, ut8 code) {
	if (!port) {
		return -1;
	}
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_RESET;

	if (!request || !reply) {
		goto fail;
	}

	r_buf_append_bytes (request, &cmd, 1);
	r_buf_append_bytes (request, &code, 1);

	port->frame (request);

	sp_flush (port);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, GPROBE_ACK, reply)) {
		goto fail;
	}

	r_buf_free (request);
	r_buf_free (reply);

	return 0;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_debugon (struct gport *port) {
	if (!port) {
		return -1;
	}
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_DEBUGON;

	if (!request || !reply) {
		goto fail;
	}
	r_buf_append_bytes (request, &cmd, 1);

	port->frame (request);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, GPROBE_ACK, reply)) {
		goto fail;
	}

	r_buf_free (request);
	r_buf_free (reply);

	return 0;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_debugoff (struct gport *port) {
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_DEBUGOFF;

	if (!request || !reply) {
		goto fail;
	}
	r_buf_append_bytes (request, &cmd, 1);
	port->frame (request);
	if (port->send_request (port, request)) {
		goto fail;
	}
	if (port->get_reply (port, GPROBE_ACK, reply)) {
		goto fail;
	}
	r_buf_free (request);
	r_buf_free (reply);
	return 0;
fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_runcode (struct gport *port, ut32 addr) {
	if (!port) {
		return -1;
	}
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_RUN_CODE_2;
	ut8 addr_be[4];

	if (!request || !reply) {
		goto fail;
	}

	r_write_be32 (addr_be, addr);

	r_buf_append_bytes (request, &cmd, 1);
	r_buf_append_bytes (request, addr_be, 4);

	port->frame (request);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, GPROBE_ACK, reply)) {
		goto fail;
	}

	r_buf_free (request);
	r_buf_free (reply);

	return 0;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_getdeviceid (struct gport *port, ut8 index) {
	if (!port) {
		return -1;
	}
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_GET_DEVICE_ID;

	if (!request || !reply) {
		goto fail;
	}

	r_buf_append_bytes (request, &cmd, 1);
	r_buf_append_bytes (request, &index, 1);

	port->frame (request);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, cmd, reply)) {
		goto fail;
	}

	char *s = r_buf_to_string (reply);
	if (s) {
		printf ("%s\n", s);
		free (s);
	}

	r_buf_free (request);
	r_buf_free (reply);

	return 0;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int gprobe_getinformation (struct gport *port) {
	if (!port) {
		return -1;
	}
	RBuffer *request = r_buf_new ();
	RBuffer *reply = r_buf_new ();
	const ut8 cmd = GPROBE_GET_INFORMATION;
	const ut8 index = 0;

	if (!request || !reply) {
		goto fail;
	}

	r_buf_append_bytes (request, &cmd, 1);
	r_buf_append_bytes (request, &index, 1);

	port->frame (request);

	if (port->send_request (port, request)) {
		goto fail;
	}

	if (port->get_reply (port, cmd, reply)) {
		goto fail;
	}

	ut64 tmpsz;
	const ut8 *tmp = r_buf_data (reply, &tmpsz);
	r_print_hexdump (NULL, 0, tmp, tmpsz, 16, 1, 1);

	r_buf_free (request);
	r_buf_free (reply);

	return 0;

fail:
	r_buf_free (request);
	r_buf_free (reply);
	return -1;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOGprobe *gprobe;
	int res;
	int has_written = 0;

	if (!fd || !fd->data || !buf) {
		return -1;
	}

	gprobe = (RIOGprobe *)fd->data;

	if ((gprobe->offset + count) > GPROBE_SIZE) {
		count = GPROBE_SIZE - gprobe->offset;
	}

	while (has_written < count) {
		res = gprobe_write (&gprobe->gport, gprobe->offset, buf + has_written, count - has_written);
		if (res <= 0) {
			return -1;
		}
		gprobe->offset += res;
		has_written += res;
	}

	return count;
}

static int __read (RIO *io, RIODesc *fd, ut8 *buf, int count) {
	int res;
	RIOGprobe *gprobe;
	int has_read = 0;

	if (!fd || !fd->data || !buf) {
		return -1;
	}

	gprobe = (RIOGprobe *)fd->data;

	if ((gprobe->offset + count) > GPROBE_SIZE) {
		count = GPROBE_SIZE - gprobe->offset;
	}

	while (has_read < count) {
		res = gprobe_read (&gprobe->gport, gprobe->offset, buf + has_read, count - has_read);
		if (res <= 0) {
			return -1;
		}
		gprobe->offset += res;
		has_read += res;
	}

	return has_read;
}

static int __close (RIODesc *fd) {
	RIOGprobe *gprobe;

	if (!fd || !fd->data) {
		return -1;
	}
	gprobe = (RIOGprobe *)fd->data;

	sp_close (&gprobe->gport);
	R_FREE (fd->data);

	return 0;
}

static ut64 __lseek (RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOGprobe *gprobe;
	if (!fd || !fd->data) {
		return offset;
	}
	gprobe = (RIOGprobe *)fd->data;
	switch (whence) {
	case SEEK_SET:
		if (offset >= GPROBE_SIZE) {
			return gprobe->offset = GPROBE_SIZE - 1;
		}
		return gprobe->offset = offset;
	case SEEK_CUR:
		if ((gprobe->offset + offset) >= GPROBE_SIZE) {
			return gprobe->offset = GPROBE_SIZE - 1;
		}
		return gprobe->offset += offset;
	case SEEK_END:
		return gprobe->offset = GPROBE_SIZE - 1;
	}
	return offset;
}

static bool __plugin_open (RIO *io, const char *pathname, bool many) {
	return pathname && r_str_startswith (pathname, "gprobe://") && strlen (pathname + strlen ("gprobe://"));
}

static RIODesc *__open (RIO *io, const char *pathname, int rw, int mode) {
	if (__plugin_open (io, pathname, 0)) {
		RIOGprobe *gprobe = R_NEW0 (RIOGprobe);

		gprobe->offset = 0LL;
		gprobe->gport.name = pathname + strlen ("gprobe://");

		if (r_str_startswith (gprobe->gport.name, "i2c-")) {
#if __UNIX__
			gprobe->gport.send_request = gprobe_send_request_i2c;
			gprobe->gport.get_reply = gprobe_get_reply_i2c;
			gprobe->gport.frame = gprobe_frame_i2c;
			gprobe->gport.max_tx_size = 117;
			gprobe->gport.max_rx_size = 121;

			if (i2c_open (&gprobe->gport)) {
				R_FREE (gprobe);
				return NULL;
			}
#else
			R_FREE (gprobe);
			return NULL;
#endif
		} else {
			gprobe->gport.send_request = gprobe_send_request_sp;
			gprobe->gport.get_reply = gprobe_get_reply_sp;
			gprobe->gport.frame = gprobe_frame_sp;
			gprobe->gport.max_tx_size = 248;
			gprobe->gport.max_rx_size = 252;

			if (sp_open (&gprobe->gport)) {
				R_FREE (gprobe);
				return NULL;
			}
		}

		return r_io_desc_new (io, &r_io_plugin_gprobe, pathname, rw, mode, gprobe);
	}

	return NULL;
}

static char *__system (RIO *io, RIODesc *fd, const char *cmd) {
	RIOGprobe *gprobe;

	if (!fd || !fd->data) {
		return NULL;
	}
	gprobe = (RIOGprobe *)fd->data;

	if (!cmd[0] || cmd[0] == '?' || !strcmp (cmd, "help")) {
		printf ("Usage: =!cmd args\n"
			" =!reset code\n"
			" =!debugon\n"
			" =!debugoff\n"
			" =!runcode address\n"
			" =!getdeviceid\n"
			" =!getinformation\n");
		return NULL;
	}

	if (r_str_startswith (cmd, "reset") && (strlen (cmd) > 6)) {
		ut32 code = (ut32)strtoul (cmd + 6, NULL, 10);

		gprobe_reset (&gprobe->gport, code);

		return NULL;
	}

	if (r_str_startswith (cmd, "debugon")) {
		gprobe_debugon (&gprobe->gport);

		return NULL;
	}

	if (r_str_startswith (cmd, "debugoff")) {
		gprobe_debugoff (&gprobe->gport);

		return NULL;
	}

	if (r_str_startswith (cmd, "runcode") && (strlen (cmd) > 8)) {
		ut32 address = (ut32)strtoul (cmd + 8, NULL, 0);

		gprobe_runcode (&gprobe->gport, address);

		return NULL;
	}

	if (r_str_startswith (cmd, "getdeviceid")) {
		ut8 index = 0;

		while (!gprobe_getdeviceid (&gprobe->gport, index++)) {
		};

		return NULL;
	}

	if (r_str_startswith (cmd, "getinformation")) {
		gprobe_getinformation (&gprobe->gport);

		return NULL;
	}

	printf ("Try: '=!?'\n");

	return NULL;
}

RIOPlugin r_io_plugin_gprobe = {
	.name = "gprobe",
	.desc = "Open gprobe connection",
	.license = "LGPL3",
	.uris = "gprobe://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.lseek = __lseek,
	.write = __write,
	.system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_gprobe,
	.version = R2_VERSION};
#endif
