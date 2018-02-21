/* radare - LGPL - Copyright 2017 - pancake */

#include <r_socket.h>
#if __UNIX__ && !defined(__MINGW32__)

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>

static int set_interface_attribs (int fd, int speed, int parity) {
	struct termios tty;
	memset (&tty, 0, sizeof tty);
	if (tcgetattr (fd, &tty) != 0) {
		return -1;
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
	tty.c_cc[VMIN]  = 0;            // read doesn't block
	tty.c_cc[VTIME] = 5;            // 0.5 seconds read timeout

	tty.c_iflag &= ~(IXON | IXOFF | IXANY); // shut off xon/xoff ctrl

	tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
	// enable reading
	tty.c_cflag &= ~(PARENB | PARODD);      // shut off parity
	tty.c_cflag |= parity;
	tty.c_cflag &= ~CSTOPB;
#ifdef CRTSCTS
	tty.c_cflag &= ~CRTSCTS;
#endif

	if (tcsetattr (fd, TCSANOW, &tty) != 0) {
		return -1;
	}
	return 0;
}

R_API int r_socket_connect_serial(RSocket *sock, const char *path, int speed, int parity) {
	int fd = open (path, O_RDWR | O_SYNC | O_BINARY, 0); // O_NOCTY
	if (fd == -1) {
		return -1;
	}
	if (speed < 1) {
		speed = 9600; // 19200
	}
	(void)set_interface_attribs (fd, speed, parity);
	sock->fd = fd;
	return fd;
}

#else // __UNIX__

R_API int r_socket_connect_serial(RSocket *sock, const char *path, int speed, int parity) {
	return -1;
}
#endif
