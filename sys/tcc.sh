#!/bin/sh

export CC="tcc"
exec sys/install.sh --with-compiler=tcc $*
