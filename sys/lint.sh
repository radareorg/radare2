#!/bin/sh

# validated and ready to go lintings
(git grep -n 'for(' libr | grep -v _for | grep -v colorfor) && exit 1
(git grep -n 'for (' libr | grep "; ++" | grep -v arch ) && exit 1
(git grep -n 'for (int' | grep -v sys/) && exit 1
(git grep -n 'for (long' | grep -v sys/) && exit 1
(git grep -n 'for (size_t' | grep -v sys/) && exit 1
(git grep -n 'R_LOG_' | grep '\\n' | grep -v sys/) && exit 1
(git grep -n 'eprintf' libr | grep 'Error:') && exit 1
(git grep -n 'x ""' libr) && exit 1
(git grep -n 'x""' libr) && exit 1
(git grep -n ';;$' libr) && exit 1
(git grep -n '\ $' libr) && exit 1 # trailing space
(git grep -n '^eprintf' libr) && exit 1
(git grep -n '4d""' libr) && exit 1
(git grep -n 'r_core_cmd' libr | grep -v /lang/ | grep '\\n') && exit 1
(git grep -n 'r_str_startswith ("' libr ) && exit 1
(git grep -n R_LOG | grep '\."' | grep -v sys/) && exit 1
(git grep -n -i 'R_LOG_ERROR ("ERROR' | grep -v sys) && exit 1
(git grep -n ^R_API libr shlr | grep ' (') && exit 1
(git grep -n ^R_API libr shlr | grep '( ') && exit 1
(git grep -n -e 'eprintf ("Could' -e 'eprintf ("Failed' -e 'eprintf ("Cannot' libr \
    | grep -v -e ^libr/core/cmd -e ^libr/main/ -e ^libr/util/syscmd \
    | grep -v -e r_cons_eprintf -e alloc) && exit 1

# pending cleanups
# ( git grep 'desc = "[A-Z]' ) && exit 1
# git grep -e "`printf '\x09static'`" libr | grep -v R_TH_LOCAL|grep -v const | grep -v '(' && exit 1
# (git grep 'TODO' libr) # && exit 1 # use r_str_startswith()
# (git grep 'XXX' libr) # && exit 1 # use r_str_startswith()
# (git grep 'strncmp' libr) # && exit 1 # use r_str_startswith()
# (git grep 'eprintf' libr | grep 'Warning:') # && exit 1
# (git grep 'eprintf' | grep 'Usage:' | grep -v sys/) # && exit 1

exit 0
