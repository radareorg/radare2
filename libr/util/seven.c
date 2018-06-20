/* radare - LGPL - Copyright 2012-2013 - pancake */
#include <r_print.h>

// TODO: work in progress

#if 0
for(i=0; i<len; i++) {
	packing_7bit_character(config.block+i, buffer);
	cons_printf("%c", buffer[0]);
}
#endif

R_API int r_print_pack7bit (const char *src, char *dest) {
        int len, i, j = 0, shift = 0;
        ut8 ch1, ch2;
        char tmp[2];

        *dest = '\0';
	len = strlen (src);

        for (i=0; i<len; i++ ) {
                ch1 = src[i] & 0x7F;
                ch1 = ch1 >> shift;
                ch2 = src[(i+1)] & 0x7F;
                ch2 = ch2 << (7-shift);

                ch1 = ch1 | ch2;

                j = strlen(dest);
                sprintf (tmp, "%x", (ch1 >> 4));
                dest[j++] = tmp[0];
                sprintf (tmp, "%x", (ch1 & 0x0F));
                dest[j++] = tmp[0];
                dest[j++] = '\0';
                if (7 == ++shift) {
                        shift = 0;
                        i++;
                }
        }
        return 0;
}

R_API int r_print_unpack7bit (const char *src, char *dest) {
        int i, j, shift = 0, len = strlen (src);
        ut8 ch1, ch2 = '\0';
        char buf[8];

        *dest = '\0';

        for (i=0; i<len; i+=2) {
                sprintf (buf, "%c%c", src[i], src[i+1]);
                ch1 = strtol (buf, NULL, 16);

                j = strlen(dest);
                dest[j++] = ((ch1 & (0x7F >> shift)) << shift) | ch2;
                dest[j++] = '\0';
                ch2 = ch1 >> (7-shift);

                shift++;
        }
        return 0;
}
