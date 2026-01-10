#!/bin/sh
PR="$1"
MS="$2"

if [ -z "$PR" ]; then
	echo "Usage: sys/prai.sh [pullreq-id] ([query])"
	echo "Environment: Use MAI_PROVIDER and MAI_MODEL"
	exit 1
fi

if [ -z "$MS" ]; then
	MS="review the changes, identify design issues, memory leaks, errors, bugs and things to improve, output a clean report with clear indications"
fi

curl -sL https://github.com/radareorg/radare2/pull/${PR}.diff | mai -S "${MS}"
