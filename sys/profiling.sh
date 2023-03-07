#!/bin/sh
export CFLAGS="-pg -g -O1 -no-pie"
export LDFLAGS="$CFLAGS"
sys/install.sh
