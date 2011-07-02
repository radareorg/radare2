#!/bin/sh
echo "_=0x80"
awk -F '(=|,)' '{
	# 0x80.1=exit
	if ($1 == "_") {
		print $1"="$2
	} else {
		print $2"."$3"="$1
		# exit=0x80,1,1,i
		print $1"="$2","$3","$4","$5
	}
}'
