#!/bin/sh
cd "$(dirname "$PWD/$0")"
cd _work
curl -o python-2.7.9.msi http://www.python.org/ftp/python/2.7.9/python-2.7.9.msi
msiexec /i python-2.7.9.msi
