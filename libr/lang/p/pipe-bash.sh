#!/bin/bash

( cat <&${R2PIPE_IN} ) &
r2cmd() { echo "$1" >&${R2PIPE_OUT} ; }

r2cmd "x 64"
r2cmd "pd 10"
