#!/bin/sh
grep '{ "'|tr '{",}' '    ' |sed -e 's,NULL,,g' | awk '{ print $1"="$2","$3","$4","$5}'
