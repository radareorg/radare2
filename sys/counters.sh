#!/bin/sh
echo "# Counters"

printf -- "XXX\t"
git grep XXX libr | wc -l
printf -- "TODO\t"
git grep TODO libr | wc -l
printf -- "GLOBALS\t"
git grep R_TH_LOCAL libr | grep -v include | wc -l

printf -- "strcpy\t"
git grep 'strcpy (' libr | wc -l
printf -- "sprintf\t"
git grep 'sprintf (' libr | wc -l

printf -- "eUsage\t"
git grep 'eprintf (' libr | grep Usage | wc -l
