#!/bin/sh
awk -F '(=|,)' '{
	print $2"."$3"="$1
	# exit=0x80,1,1,i
	print $1"="$2","$3
}'
