#!/usr/bin/perl
# vapi2vala -- pancake
my $DEBUG = 0;
while (<STDIN>) {
	next if (/const/); # XXX: constant values are ignored
	if (/\);/) {
		local $ol=$l=$_;
		$l=~s/public//;
		$l=~s/private//;
		$l=~s/unowned//;
		if (/delegate/) {
			print;
			next;
		}
		$l=~s/delegate//;
		$l=~s/static//;
		$l=~s/^\s*//g;
		$l=~s/^\t*//g;
		$l=~s/\s\(/\(/g;
print STDERR "LINE: ($l)\n" if ($DEBUG);
		@o = split (/ /, $l);
		$t=$o[0];
		$n=$o[1];
print STDERR "--->  $t : $n\n" if ($DEBUG);
		local $v = "null";
		if ($t=~/\(/ || $t eq "void") {
			$ol=~s/\);/\) {}/;
		} else {
			if ($t eq "string") {
				$v="\"\"";
			} elsif ($t eq "uint64") {
				$t = "";
				$v="0";
			} elsif ($t eq "int" or $t eq "uint") {
				$t = "";
				$v="0";
			} elsif ($t eq "bool") {
				$v="false";
			}
			if ($t eq "") {
				$ol=~s/\);/\) {return $v;}/;
			} else {
				$ol=~s/\);/\) {return $v;}/;
				#//$ol=~s/\);/\) {return ($t)$v;}/;
			}
		}
		print $ol;
	} else {
		print;
	}
}
