#!/usr/bin/r2 -qni portscan.r2 -
# r2 portscanner
# author: pancake
# date: 2013-11-30

f minport=1
f maxport=1024
k host=localhost

(connect host port,=+tcp://$0:`?vi $1`/ 2>/dev/null,?! ?e OPEN `?vi $1`)
(scan host min max,.(connect $0 $$) @@=`?s $1 $2`,?e Report:,=~[2],=-*)
.(scan `k host` minport maxport)

# Oneliner version:
