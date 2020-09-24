#!/bin/sh

r2 -N -e http.port=9393 -qq -c=h bins/elf/arg > /dev/null 2>&1 &
CHILD=$!
sleep 2
# curl -s --retry 6 --retry-connrefused http://localhost:9090/ | head -n 8
r2 -N -qc 'pd 10' -cq -C http://127.0.0.1:9393/cmd
r2 -N -c 'b $s;pr~:0..9' -qcq http://127.0.0.1:9393/
kill $CHILD
