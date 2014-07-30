/* radare - LGPL - Copyright 2007-2013 - pancake */

#include "r_print.h"
#include "r_util.h"
#if 1
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

R_API int r_print_date_dos(RPrint *p, ut8 *buf, int len) {
	ut8 _time[2] = { buf[0], buf[1] };
	ut8 _date[2] = { buf[2], buf[3] };
        ut32 t       = _time[1]<<8 | _time[0];
        ut32 d       = _date[1]<<8 | _date[0];
        ut32 year    = ((d&0xfe00)>>9)+1980;
        ut32 month   = (d&0x01e0)>>5;
        ut32 day     = (d&0x001f)>>0;
        ut32 hour    = (t&0xf800)>>11;
        ut32 minutes = (t&0x07e0)>>5;
        ut32 seconds = (t&0x001f)<<1;

        /* la data de modificacio del fitxer, no de creacio del zip */
        p->printf("%d-%02d-%02d %d:%d:%d\n",
                year, month, day, hour, minutes, seconds);
	return 4;
}

R_API int r_print_date_unix(RPrint *p, const ut8 *buf, int len) {
	time_t t;
	char s[256];
	int ret = 0;
	const struct tm* time;

	if (p != NULL && len >= sizeof(t)) {
		r_mem_copyendian ((ut8*)&t, buf, sizeof(time_t), p->big_endian);
		// "%d:%m:%Y %H:%M:%S %z",
		if (p->datefmt[0]) {
			time = (const struct tm*)gmtime((const time_t*)&t);
			if (time) {
				ret = strftime (s, sizeof (s), p->datefmt, time);
				if (ret) {
					p->printf ("%s\n", s);
					ret = sizeof (time_t);
				}
			} else p->printf ("Invalid time\n");
		}
	}
	return ret;
}

R_API int r_print_date_get_now(RPrint *p, char *str) {
	int ret = 0;
        *str = 0;
#if __UNIX__
        struct tm curt; /* current time */
        time_t l;
        char *week_str[7]= {
		"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        char *month_str[12]= {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        l = time(0);
        localtime_r (&l, &curt);

        if ((curt.tm_wday >= 0 && curt.tm_wday < 7)
        &&  (curt.tm_mon >= 0 && curt.tm_mon < 12)) {
		sprintf(str, "%s, %02d %s %d %02d:%02d:%02d GMT",
			week_str[curt.tm_wday],
			curt.tm_mday,
			month_str[curt.tm_mon],
			curt.tm_year + 1900, curt.tm_hour,
			curt.tm_min, curt.tm_sec);
		ret = sizeof(time_t);
	}
#else
#warning r_print_date_now NOT IMPLEMENTED FOR THIS PLATFORM
#endif
	return ret;
}

R_API int r_print_date_w32(RPrint *p, const ut8 *buf, int len) {
	ut64 l, L = 0x2b6109100LL;
	time_t t;
	int ret = 0;
	char datestr[256];

	if (p && len >= sizeof (ut64)) {
		r_mem_copyendian ((ut8*)&l, buf, sizeof (ut64), p->big_endian);
		l /= 10000000; // 100ns to s
		l = (l > L ? l-L : 0); // isValidUnixTime?
		t = (time_t) l; // TODO limit above!
		// "%d:%m:%Y %H:%M:%S %z",
		if (p->datefmt[0]) {
			ret = strftime(datestr, 256, p->datefmt,
				(const struct tm*) gmtime((const time_t*)&t));
			if (ret) {
				p->printf("%s\n", datestr);
				ret = R_TRUE;
			}
		}
	}

	return ret;
}
