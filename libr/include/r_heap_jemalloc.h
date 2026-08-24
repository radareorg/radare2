#ifndef R2_HEAP_JEMALLOC_H
#define R2_HEAP_JEMALLOC_H

#define PRINT_GA(cons, fmt, ...) r_cons_printf (cons, "%s" fmt Color_RESET, pal->args, ##__VA_ARGS__)
#define PRINT_BA(cons, fmt, ...) r_cons_printf (cons, "%s" fmt Color_RESET, pal->args, ##__VA_ARGS__)
#define PRINT_RA(cons, fmt, ...) r_cons_printf (cons, "%s" fmt Color_RESET, pal->args, ##__VA_ARGS__)
#define PRINT_YA(cons, fmt, ...) r_cons_printf (cons, "%s" fmt Color_RESET, pal->args, ##__VA_ARGS__)

#endif
