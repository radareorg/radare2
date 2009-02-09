/* radare - LGPL - Copyright 2007-2009 pancake<nopcode.org> */

#include "r_print.h"

void print_msdos_date(unsigned char _time[2], unsigned char _date[2])
{
        unsigned int t       = _time[1]<<8 | _time[0];
        unsigned int d       = _date[1]<<8 | _date[0];
        unsigned int year    = ((d&0xfe00)>>9)+1980;
        unsigned int month   = (d&0x01e0)>>5;
        unsigned int day     = (d&0x001f)>>0;
        unsigned int hour    = (t&0xf800)>>11;
        unsigned int minutes = (t&0x07e0)>>5;
        unsigned int seconds = (t&0x001f)<<1;

        /* la data de modificacio del fitxer, no de creacio del zip */
        r_cons_printf("%d-%02d-%02d %d:%d:%d",
                year, month, day, hour, minutes, seconds);
}

void getHTTPDate(char *DATE)
{
        DATE[0]=0;
#if __UNIX__
        struct tm curt; /* current time */
        time_t l;
        char week_day[4], month[4];
        char *week_str[7]= { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        char *month_str[7]= { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                "Aug", "Sep", "Oct", "Nov", "Dec" };

        l = time(0);
        localtime_r(&l, &curt);

        if ((curt.tm_wday <0 || curt.tm_wday > 6)
        ||  (curt.tm_mon < 0 || curt.tm_mon > 11))
                return;

        sprintf(DATE, "%s, %02d %s %d %02d:%02d:%02d GMT",
                week_str[curt.tm_wday],
                curt.tm_mday,
                month_str[curt.tm_mon],
                curt.tm_year + 1900, curt.tm_hour,
                curt.tm_min, curt.tm_sec);
#endif
}

#if 0
        case FMT_TIME_UNIX: {
                time_t t;
                char datestr[256];
                const char *datefmt;
                for(i=0;!config.interrupted && i<len;i+=4) {
                        endian_memcpy((unsigned char*)&t, config.block+i, sizeof(time_t));
                        //printf("%s", (char *)ctime((const time_t*)&t));
                        datefmt = config_get("cfg.datefmt");

                        if (datefmt&&datefmt[0])
                                tmp = strftime(datestr,256,datefmt,
                                        (const struct tm*)gmtime((const time_t*)&t));
                        else    tmp = strftime(datestr,256,"%d:%m:%Y %H:%M:%S %z",
                                        (const struct tm*)gmtime((const time_t*)&t));
                        // TODO colorize depending on the distance between dates
                        if (tmp) cons_printf("%s",datestr); else printf("*failed*");
                        cons_newline();
                } } break;

----

        case FMT_TIME_FTIME: {
                unsigned long long l, L = 0x2b6109100LL;
                time_t t;
                char datestr[256];
                const char *datefmt;
                for(i=0;!config.interrupted && i<len;i+=8) {
                        endian_memcpy((unsigned char*)&l, config.block+i, sizeof(unsigned long long));
                        l /= 10000000; // 100ns to s
                        l = (l > L ? l-L : 0); // isValidUnixTime?
                        t = (time_t) l; // TODO limit above!
                        datefmt = config_get("cfg.datefmt");
                        if (datefmt&&datefmt[0])
                                tmp = strftime(datestr, 256, datefmt,
                                        (const struct tm*)gmtime((const time_t*)&t));
                        else    tmp = strftime(datestr, 256, "%d:%m:%Y %H:%M:%S %z",
                                        (const struct tm*)gmtime((const time_t*)&t));
                        if (tmp) cons_printf("%s", datestr); else cons_printf("*failed*");
                        cons_newline();
                } } break;

#endif
