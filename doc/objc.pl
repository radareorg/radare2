#!/usr/bin/perl
# Extract OBJC class information into a radare2 script
# author: pancake 2014

my $file = $ARGV[0] or die ("Usage: objc.pl [file]\n");
my $class = "";
my $bits = 32;

local $classdump = qx(class-dump -A "$file") or die ("Cannot open file\n");

foreach my $line (split /[\r\n]+/, $classdump) {
	if ($line=~/Arch: /) {
		if ($line=~/arm/) {
			print "e asm.arch=arm.cs\n";
			print "e anal.arch=arm.cs\n";
		}
	} elsif ($line=~/^\@interface ([^\ ]*)/) {
		$class = $1;
	} elsif ($line=~/IMP=0x(.*)$/) {
		my $addr = hex ("0x".$1);
		if ($line=~/\)([^:;]+)/) {
			my $method = $1;
			if ($addr & 1) {
				$addr--;
				$bits = 16; # enable thumb mode by default
				#$method .= "_THUMB";
			} else {
				#$method .= "_ARM";
			}
			printf ("f objc.".$class."_".$method." = 0x%x\n",$addr);
		}
	}
}
print "e asm.bits=$bits\n";
