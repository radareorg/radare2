#!/bin/sh

(git grep 'for (int' | grep -v sys/) && exit 1
(git grep 'for (long' | grep -v sys/) && exit 1
(git grep 'for (size_t' | grep -v sys/) && exit 1

(git grep 'R_LOG_' | grep '\\n' | grep -v sys/) # && exit 1

exit 0
