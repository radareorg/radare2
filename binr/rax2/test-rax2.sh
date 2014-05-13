#!/bin/sh

echo "Testing echo... "
O=`echo hello | ./rax2 -S | ./rax2 -s`
if [ "$O" = hello ]; then
	echo OK
else 
	echo FAIL
fi

echo "Testing cat..."
./rax2 -S <rax2 | ./rax2 -s > .rax2
A=`rahash2 -a md5 rax2 | awk '{ print $4}'`
B=`rahash2 -a md5 .rax2 | awk '{ print $4}'`
if [ "$A" = "$B" ]; then
	echo OK
else
	echo FAIL
fi
rm -f .rax2
