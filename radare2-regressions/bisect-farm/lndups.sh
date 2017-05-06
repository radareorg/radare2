#!/bin/sh

DIR=build

rdfind >/dev/null
if [ $? = 0 ]; then
	exec rdfind -makesymlinks true ${DIR}
fi

find ${DIR}/ -type f | xargs sha1sum | sort > checksums.txt
PREVFILE=""
PREVHASH=""
for a in `cat checksums.txt` ; do
	if [ -n "${HASH}" ]; then
		FILE=$a
		if [ "${PREVHASH}" = "${HASH}" ]; then
			echo Symlink ${FILE}
			rm -f ${FILE}
			ln -fs ${PREVFILE} ${FILE}
		else
			PREVFILE=${FILE}
			PREVHASH=${HASH}
		fi
		# ...
		HASH=""
	else
		HASH="$a"
	fi
done
