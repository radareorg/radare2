#!/bin/sh
EXIT=1
OUTPUT=""
cat > t.r <<EOF
main@global(128) {
	: push 1
	: mov eax, 1
	: push eax
	: int 0x80
}
EOF
. ./t.sh
