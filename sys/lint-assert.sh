#!/bin/sh
git grep -C1 R_API libr | awk '/R_API/ && !/NULL/ && !/(void)/ {getline nextLine; if (nextLine !~ /R_RETURN/) print $0}' | grep 'c:'
