#!/bin/sh
cd `dirname $0` 2>/dev/null
cd build
ls|cut -d '-' -f 2
