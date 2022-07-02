#!/bin/sh

# validated and ready to go lintings
(git grep 'for(' libr | grep -v _for | grep -v colorfor) && exit 1
(git grep 'for (' libr | grep "; ++" | grep -v arch ) && exit 1
(git grep 'for (int' | grep -v sys/) && exit 1
(git grep 'for (long' | grep -v sys/) && exit 1
(git grep 'for (size_t' | grep -v sys/) && exit 1
(git grep 'R_LOG_' | grep '\\n' | grep -v sys/) && exit 1
(git grep 'eprintf' libr | grep 'Error:') && exit 1
(git grep 'x ""' libr) && exit 1
(git grep 'x""' libr) && exit 1
(git grep '4d""' libr) && exit 1
(git grep 'r_core_cmd' libr | grep -v /lang/ | grep '\\n') && exit 1
(git grep 'r_str_startswith ("' libr ) && exit 1

# pending cleanups
# (git grep 'TODO' libr) # && exit 1 # use r_str_startswith()
# (git grep 'XXX' libr) # && exit 1 # use r_str_startswith()
# (git grep 'strncmp' libr) # && exit 1 # use r_str_startswith()
# (git grep 'eprintf' libr | grep 'Warning:') # && exit 1
# (git grep 'eprintf' | grep 'Usage:' | grep -v sys/) # && exit 1

exit 0
