#!/bin/sh

cd "$(dirname $0)"/..

# find calls without (
#(git grep -n -e '[a-z]('  | grep -v static | grep -v _API | grep -v shlr | grep libr/core) && exit 1
# validated and ready to go lintings
(git grep -n 'cmp(' libr | grep -v R_API | grep -v static | grep c:) && exit 1
# (git grep -n 'len(' libr | grep -v R_API | grep -v static | grep c:) && exit 1
# (git grep -n ',"' libr | grep -v R_API | grep -v static | grep c:) && exit 1
(git grep -n 'for(' libr | grep -v _for | grep -v colorfor) && exit 1
(git grep -n 'for (' libr | grep "; ++" | grep -v arch ) && exit 1
(git grep -n 'for (int' | grep -v sys/) && exit 1
(git grep -n 'for (long' | grep -v sys/) && exit 1
(git grep -n 'for (ut' | grep -v sys/) && exit 1
(git grep -n 'for (size_t' | grep -v sys/) && exit 1
(git grep -n -e '	$' | grep libr/ | grep c:) && exit 1
(git grep -n 'R_LOG_' | grep '\\n' | grep -v sys/) && exit 1
(git grep "`printf '\tfree('`" libr | grep c: ) && exit 1
(git grep '=0' libr| grep c:|grep -v '"' |grep -v '=0x') && exit 1
(git grep '=1' libr| grep c:|grep -v '"' |grep -v '//') && exit 1
(git grep -n 'eprintf' libr | grep 'Error:') && exit 1
(git grep -n 'x ""' libr) && exit 1
(git grep -n 'x""' libr) && exit 1
( git grep '){$' libr| grep if) && exit 1
(git grep -e 'sizeof(' -e 'for(' -e 'while(' -e 'if(' libr | grep -v :static | grep -v :R_API | grep c:) && exit 1
( git grep 'else$' libr | grep -v '#' | grep '}' | grep 'c:') && exit 1
# ( git grep if' (' libr| grep ')$'| grep -v '//'|grep -v '#' | grep c:) && exit 1
# ( git grep strcmp | grep '== 0') && exit 1
# ( git grep strncmp | grep '== 0') && exit 1
(git grep -n ';;$' libr) && exit 1
(git grep -n '0 ;' libr) && exit 1
(git grep -n -e 'i<' -e 'j<' -e 'k<' libr | grep -v '"') && exit 1
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

(
 # ensure c++ compat
 cd libr/include
 git grep cplusplus|cut -d : -f1|grep -v heap|grep -v userconf | grep -v sflib | grep -v r_version | sort -u > /tmp/.a
 find *| grep h$|grep -v r_version | grep -v userconf| grep -v heap|grep -v sflib | sort -u > /tmp/.b
 diff -ru /tmp/.a /tmp/.b
) || exit 1

# pending cleanups
# ( git grep 'desc = "[A-Z]' ) && exit 1
# git grep -e "`printf '\x09static'`" libr | grep -v R_TH_LOCAL|grep -v const | grep -v '(' && exit 1
# (git grep 'TODO' libr) # && exit 1 # use r_str_startswith()
# (git grep 'XXX' libr) # && exit 1 # use r_str_startswith()
# (git grep 'strncmp' libr) # && exit 1 # use r_str_startswith()
# (git grep 'eprintf' libr | grep 'Warning:') # && exit 1
# (git grep 'eprintf' | grep 'Usage:' | grep -v sys/) # && exit 1

exit 0
