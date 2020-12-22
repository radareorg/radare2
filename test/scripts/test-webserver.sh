#!/bin/sh

r2 -N -e http.port=9393 -qq -c=h bins/elf/arg > /dev/null 2>&1 &
CHILD=$!
curl -s --retry 30 --retry-delay 1 --retry-connrefused http://127.0.0.1:9393/ > /dev/null 2>&1
r2 -N -qc '=0 pd 10' -C http://127.0.0.1:9393/cmd
r2 -N -c 'b $s;pr~:0..11' -qcq http://127.0.0.1:9393/
kill $CHILD
