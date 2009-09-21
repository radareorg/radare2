#!/bin/sh
#
# Usage : perl depgraph.pl | dot -Tpng /dev/stdin > deps.png
#
grep -e DEPS */Makefile | sed -e 's,/Makefile,,' > /tmp/rdeps.txt

MODE=dot
MODE=gml

if [ $MODE = "dot" ]; then

echo "digraph G {";
cat /tmp/rdeps.txt | perl -ne '
/(.*):(.*)=(.*)$/;
my $lib=$1;
@deps=split(/ /, $3);
foreach $dep (@deps) {
  print " $dep -> r_$lib;\n";
}';
echo "}";

else

echo "graph [";
#cat /tmp/rdeps.txt | cut -d : -f 1 | perl -ne '
#  /(.*)/
#';
cat /tmp/rdeps.txt | perl -ne '
BEGIN { $id = 0; my %libs={}; }
/(.*):(.*)=(.*)$/;
my $lib=$1;
$id++;
  unless($libs{"r_$lib"}) {
	print "node [\n  id \"r_$lib\"\n  label \"r_$lib\"\n]\n";
	print STDERR "r_$lib\n";
	$libs{"r_$lib"}=1;
  }
$libs["r_$lib"]=1;
@deps=split(/ /, $3);
foreach $dep (@deps) {
  unless ($libs{$dep}) {
print STDERR "$dep ***\n";
    print "node [\n  id \"$dep\"\n  label \"$dep\"\n]\n";
    $libs{$dep} = 1;
  }
  #print "edge [\n  source \"r_$lib\"\n  target \"$dep\"\n]\n"
  print "edge [\n  source \"$dep\"\n  target \"r_$lib\"\n]\n"
  #print " $dep -> r_$lib;\n";
}';
echo "]";

fi
