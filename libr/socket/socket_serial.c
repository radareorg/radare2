/* radare - LGPL - Copyright 2017-2022 - pancake */

#include <r_util.h>
#include <r_socket.h>
#include <r_util/r_sandbox.h>

#if R2__UNIX__ && !__wasi__

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>

static bool set_interface_attribs(int fd, int speed, int parity) {
#if 1
#if 0
	struct termios options;
	tcgetattr (fd, &options);
	cfsetispeed (&options, B115200);
	cfsetospeed (&options, B115200);
	// cfsetispeed (&options, speed);
	// cfsetospeed (&options, speed);
	options.c_cflag |= (CLOCAL | CREAD);
	options.c_cflag &= ~PARENB;
	options.c_cflag &= ~CSTOPB;
	options.c_cflag &= ~CSIZE;
	options.c_cflag |= CS8;
	options.c_cflag &= ~( ICANON | ECHO | ECHOE | ISIG );
	options.c_iflag &= ~( IXON | IXOFF | IXANY );
	options.c_oflag &= ~OPOST;
	tcsetattr (fd, TCSANOW, &options);
#else
	struct termios tty;
	tcgetattr (fd, &tty);
	cfsetispeed (&tty, speed); // B115200);
	cfsetospeed (&tty, speed); // B115200);
	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
							// disable IGNBRK for mismatched speed tests; otherwise receive break
							// as \000 chars
	tty.c_iflag &= ~IGNBRK;         // disable break processing
	tty.c_lflag = 0;                // no signaling chars, no echo,
					// no canonical processing
	tty.c_oflag = 0;                // no remapping, no delays
	tty.c_cc[VMIN]  = 0;            // read doesn't block
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
					// enable reading
	tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
#if 0
	// if this line is uncommented the writes fail
	tty.c_cflag |= parity;
#endif
	tty.c_cflag &= ~CSTOPB;
#ifdef CRTSCTS
	tty.c_cflag &= ~CRTSCTS;
#endif
	tcsetattr (fd, TCSANOW, &tty);
#endif
#else
	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (fd, &tty) != 0) {
		return false;
	}
	cfsetospeed (&tty, speed);
	cfsetispeed (&tty, speed);

	tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
							// disable IGNBRK for mismatched speed tests; otherwise receive break
							// as \000 chars
	tty.c_iflag &= ~IGNBRK;         // disable break processing
	tty.c_lflag = 0;                // no signaling chars, no echo,
					// no canonical processing
	tty.c_oflag = 0;                // no remapping, no delays
	tty.c_cc[VMIN] = 0;             // read doesn't block
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD); // ignore modem controls,
					 // enable reading
	tty.c_cflag &= ~(PARENB | PARODD); // shut off parity
	tty.c_cflag |= parity;
	tty.c_cflag &= ~CSTOPB;
#ifdef CRTSCTS
	tty.c_cflag &= ~CRTSCTS;
#endif
	if (tcsetattr (fd, TCSANOW, &tty) != 0) {
		return false;
	}
	eprintf ("done\n");
#endif
	return true;
}

#if 0
static bool set_timeout (int fd, int should_block) {
	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (fd, &tty) != 0) {
		perror ("error %d from tggetattr");
		return false;
	}

	tty.c_cc[VMIN]  = should_block ? 1 : 0;
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	return (tcsetattr (fd, TCSANOW, &tty) == 0);
}
#endif

R_API int r_socket_connect_serial(RSocket *sock, const char *path, int speed, int parity) {
	int fd = r_sandbox_open (path, O_RDWR | O_NONBLOCK | O_BINARY , 0);
	if (fd == -1) {
		return -1;
	}
	if (speed < 1) {
		speed = 9600; // 19200 or 115200
	}
	if (!set_interface_attribs (fd, speed, parity)) {
		R_LOG_WARN ("Cannot set interface settings");
	}
	sock->fd = fd;
	sock->proto = R_SOCKET_PROTO_SERIAL;
	return fd;
}

#else // R2__UNIX__

R_API int r_socket_connect_serial(RSocket *sock, const char *path, int speed, int parity) {
	return -1;
}
#endif
