#!/bin/sh

ID="$1"

if [ -z "$ID" ]; then
	echo "Usage: sys/xx.sh [travis-job-id]"
	exit 1
fi

curl -L "https://api.travis-ci.com/jobs/${ID}/log.txt?deansi=true"
