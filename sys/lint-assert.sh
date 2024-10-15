#!/bin/sh
git grep -C1 R_API | awk '/R_API/ {getline nextLine; if (nextLine !~ /R_RETURN/) print $0}'
