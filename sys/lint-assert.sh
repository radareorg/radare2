#!/bin/sh
git grep -C1 R_API libr | awk '/R_API/ && !/NULL/ {getline nextLine; if (nextLine !~ /R_RETURN/) print $0}' | grep 'c:'
