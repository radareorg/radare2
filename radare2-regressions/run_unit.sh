#!/bin/sh

# To run with kcov
# export KCOV="kcov /path/to/output"
# kcov output will be placed in the /path/to/output/index.html

EXIT_STATUS=0
for i in $(find ./unit -name 'test_*' -type f -perm -111); do
	filename=$(basename "$i")
	echo "$filename"
	${KCOV} $i
	if [ "$?" -ne 0 ] ; then
		EXIT_STATUS=1
	fi
done

exit $EXIT_STATUS
