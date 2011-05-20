#!/bin/sh
if [ -n "`uname -a| grep -i darwin`" ]; then echo darwin ; elif [ -n "`echo $CC| grep -i mingw`" ]; then echo windows ; else echo linux ; fi
