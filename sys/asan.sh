#!/bin/sh
export CFLAGS="-fsanitize=address -lasan"
export LDFLAGS="-lasan"
sys/install.sh
