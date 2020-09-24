#!/bin/sh

r2 -qq -c=h - &
sleep 2
curl -s --retry 6 --retry-connrefused http://localhost:9090/ | head -n 8
kill $!
