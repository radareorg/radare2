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

printf -- "f(char)\t"
git grep 'free ((char' libr | wc -l

printf -- "IS_DIGIT\t"
git grep 'IS_DIGIT' libr | wc -l

printf -- "f(void)\t"
git grep 'free ((void' libr | wc -l

printf -- "aPlugs\t"
ls libr/anal/p/*.c |wc -l

printf -- "BROKEN\t"
git grep BROKEN=1 test/db |wc -l

printf -- "Cannot\t"
git grep eprintf libr/| grep -i cannot |wc -l

printf -- "http:/\t"
git grep 'http:/' libr/| grep -v '/io/' |wc -l
printf -- "strtok\t"
git grep 'strtok (' libr/|wc -l

printf -- "R2_580\t"
git grep 'R2_580' libr/| wc -l
printf -- "R2_590\t"
git grep 'R2_590' libr/| wc -l
