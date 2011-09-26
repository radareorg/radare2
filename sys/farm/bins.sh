#!/bin/sh

cd `dirname $PWD/$0`
b=log/bin
mkdir -p $b
cp ../../radare2-*.gz $b
cp ../../radare2-*.zip $b
