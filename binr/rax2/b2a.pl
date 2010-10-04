#!/usr/bin/perl
# TODO: deprecate and integrate into rax2 / r_print...
#********* sec-utils - th0rpe *********
# process input data and it´s convert to array c

print "char code[] = {";
my $first = 1;

while(<>) {
	my $l = length;

	for(my $i = 0; $i < $l; $i++) {
		if($i % 10 == 0) {
			if($first) {
				print "\n                  0x";
				$first = 0;
			} else {
				print "\n                 ,0x";
			}
			print unpack("H*", substr($_, $i, 1));
		} else {
			print ",0x".
			unpack("H*", substr($_, $i, 1));
		}	
	}
}

print "\n              };\n";
