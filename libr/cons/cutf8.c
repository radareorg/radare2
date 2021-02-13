/* radare - LGPL - Copyright 2015-2021 - pancake */

// Copypasta from http://www.linuxquestions.org/questions/programming-9/get-cursor-position-in-c-947833/
#include <r_cons.h>

#if __UNIX__
#include <stdio.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#if R_UTF8_DETECT_LOCALE
#include <locale.h>
#endif

#define RD_EOF   (-1)
#define RD_EIO   (-2)

/* select utf8 terminal detection method */
#define R_UTF8_DETECT_ENV 1
#define R_UTF8_DETECT_LOCALE 0
#define R_UTF8_DETECT_CURSOR 0

#if R_UTF8_DETECT_CURSOR
static inline int rd(const int fd) {
	ut8 buffer[4];
	ssize_t n;

	for (;;) {
		n = read(fd, buffer, 1);
		if (n > (ssize_t)0) {
			return buffer[0];
		}
		if (n == (ssize_t)-1) {
			return RD_EOF;
		}
		if (n == (ssize_t)0) {
			return RD_EOF;
		}
		if (n != (ssize_t)-1) {
			return RD_EIO;
		}
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			return RD_EIO;
		}
	}
}
#endif

/* Return a new file descriptor to the current TTY.
 */
int current_tty(void) {
#if __WINDOWS__
	return 0;
#elif __ANDROID__
	return 1;
#else
	int fd;
	const char *dev = ttyname(STDERR_FILENO);
#if 0
	if (!dev)
		dev = ttyname(STDIN_FILENO);
	if (!dev)
		dev = ttyname(STDERR_FILENO);
#endif
	if (!dev) {
		errno = ENOTTY;
		return -1;
	}

	do {
		fd = open (dev, O_RDWR | O_NOCTTY);
	} while (fd == -1 && errno == EINTR);
	if (fd == -1) {
		return -1;
	}
	return fd;
#endif
}

#if R_UTF8_DETECT_CURSOR
/* As the tty for current cursor position.
 * This function returns 0 if success, errno code otherwise.
 * Actual errno will be unchanged.
 */
static int cursor_position(const int tty, int *const rowptr, int *const colptr) {
	struct termios  saved, temporary;
	int ret, res, rows, cols, saved_errno;

	/* Bad tty? */
	if (tty == -1)
		return ENOTTY;

	saved_errno = errno;

	/* Save current terminal settings. */
	res = tcgetattr (tty, &saved);
	if (res == -1) {
		ret = errno;
		errno = saved_errno;
		return ret;
	}

	/* Get current terminal settings for basis, too. */
	res = tcgetattr (tty, &temporary);
	if (res == -1) {
		ret = errno;
		errno = saved_errno;
		return ret;
	}

	/* Disable ICANON, ECHO, and CREAD. */
	temporary.c_lflag &= ~ICANON;
	temporary.c_lflag &= ~ECHO;
	temporary.c_cflag &= ~CREAD;

	/* This loop is only executed once. When broken out,
	 * the terminal settings will be restored, and the function
	 * will return ret to caller. It's better than goto.
	 */
	do {
		/* Set modified settings. */
		res = tcsetattr(tty, TCSANOW, &temporary);
		if (res == -1) {
			ret = errno;
			break;
		}

		/* Request cursor coordinates from the terminal. */
		ret = write (tty, "\033[6n", 4);
		if (ret)
			break;

		/* Assume coordinate response parsing fails. */
		ret = EIO;

		// Read until ESC is found. previous chars, should be
		// refeeded to the terminal after finishing
		// that makes typing a command before the prompt
		// appears results in no data in it.

		/* Expect an ESC. */
		for (;;) {
			res = rd(tty);
			if (res == 27 || res < 1)
				break;
			// else store_skipped_data_from_stdin_here
		}

		/* Expect [ after the ESC. */
		res = rd(tty);
		if (res != '[')
			break;

		/* Parse rows. */
		rows = 0;
		res = rd (tty);
		while (IS_DIGIT (res)) {
			rows = 10 * rows + res - '0';
			res = rd(tty);
		}

		if (res != ';') {
			break;
		}

		/* Parse cols. */
		cols = 0;
		res = rd (tty);
		if (res == -1) {
			break;
		}
		while (IS_DIGIT(res)) {
			cols = 10 * cols + res - '0';
			res = rd(tty);
		}

		if (res != 'R')
			break;

		/* Success! */
		if (rowptr) {
			*rowptr = rows;
		}
		if (colptr) {
			*colptr = cols;
		}
		ret = 0;

	} while (0);

	/* Restore saved terminal settings. */
	res = tcsetattr (tty, TCSANOW, &saved);
	if (res == -1 && !ret) {
		ret = errno;
	}

	/* Done. */
	return ret;
}
#endif

R_API bool r_cons_is_utf8(void) {
	bool ret = false;
#if R_UTF8_DETECT_ENV
	const char *keys[] = { "LC_ALL", "LC_CTYPE", "LANG", NULL };
	const char **key = keys;
	for (; *key; key++) {
		char *val = r_sys_getenv (*key);
		if (val) {
			r_str_case (val, false);
			ret = strstr (val, "utf-8") || strstr (val, "utf8");
			free (val);
			break;
		}
	}
#endif
#if R_UTF8_DETECT_LOCALE
	const char *ctype = setlocale (LC_CTYPE, NULL);
	if ( (ctype != NULL) && (ctype = strchr(ctype, '.')) && ctype++ &&
		(r_str_casecmp(ctype, "UTF-8") == 0 || r_str_casecmp(ctype, "UTF8") == 0)) {
		return true;
	}
#endif
#if R_UTF8_DETECT_CURSOR
	int row = 0, col = 0;
	int row2 = 0, col2 = 0;
	int fd = current_tty ();
	if (fd == -1)
		return false;
	if (cursor_position(fd, &row, &col)) {
		close (fd);
		return false;
	}
	write (1, "\xc3\x89\xc3\xa9", 4);
	if (cursor_position (fd, &row2, &col2)) {
		close (fd);
		return false;
	}
	close (fd);
	write (1, "\r    \r", 6);
	return ((col2-col)==2);
#endif
	return ret;
}
#else
R_API bool r_cons_is_utf8(void) {
#if __WINDOWS__
	return GetConsoleOutputCP () == CP_UTF8;
#else
	return true;
#endif
}
#endif
