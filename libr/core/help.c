/* radare - LGPLv3 - Copyright 2014 Jody Frankowski */

#include <r_core.h>

/* Prints a coloured help message. */
R_API void r_core_cmd_help(RCore *core, RCoreHelp  help[], int sizeof_help) {
    RCons *cons = r_cons_singleton();

    int use_colors = core->print->flags & R_PRINT_FLAGS_COLOR;

    char const * help_color_start = use_colors? cons->pal.comment: "";
    char const * args_color_start = use_colors? cons->pal.prompt:"";
    char const * reset_colors     = use_colors? cons->pal.reset:"";

    int i;

    int max_length = 0;
    for ( i = 0 ; i < sizeof_help ; i++ ) {
        if( strlen(help[i].command) + strlen(help[i].args) > max_length ) {
            max_length = strlen(help[i].command) + strlen(help[i].args);
        }
    }

    char padding[256];
    for ( i = 0 ; i < sizeof_help ; i++ ) {
        int padding_length = max_length - (strlen(help[i].command) + strlen(help[i].args));
        memset(padding, ' ', padding_length);
        padding[padding_length] = '\0';

        r_cons_printf("| %s%s%s%s%s   %s%s%s\n", help[i].command,
            args_color_start, help[i].args, reset_colors, padding,
            help_color_start, help[i].help_message, reset_colors);

    }
}
