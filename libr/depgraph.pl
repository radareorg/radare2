#!/bin/sh
#
# Usage : perl depgraph.pl | dot -Tpng /dev/stdin > deps.png
#
grep -e DEPS */Makefile |sed -e 's,/Makefile,,' > /tmp/rdeps.txt

echo "digraph G {";
cat /tmp/rdeps.txt | perl -ne '
/(.*):(.*)=(.*)$/;
my $lib=$1;
@deps=split(/ /, $3);
foreach $dep (@deps) {
print " $dep -> r_$lib;\n";
}';
echo "}";
