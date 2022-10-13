#!/bin/sh
#
# Usage : perl depgraph.pl dot | dot -Tpng > deps.png
#
grep -e DEPS */Makefile | sed -e 's,/Makefile,,' > /tmp/rdeps.txt

if [ -z "$1" ]; then
	MODE=dot
	#MODE=gml
	MODE=r2
else
	MODE="$1"
fi

if [ "$MODE" = "-h" ]; then

echo "Usage: depgraph [r2|dot|gml]"
exit 0

elif [ $MODE = "r2" ]; then

cat /tmp/rdeps.txt | perl -ne '
use List::MoreUtils qw(uniq);
/(.*):(.*)=(.*)$/;
my $lib=$1;
@deps=split(/ /, $3);
foreach $dep (uniq @deps) {
  print "agn $dep\n";
}
foreach $dep (@deps) {
  print "age $dep r_$lib\n";
}'
echo "agg"

elif [ $MODE = "dot" ]; then

echo "digraph G {"
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
