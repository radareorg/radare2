#!/usr/bin/perl
# Extract OBJC class information into a radare2 script
# author: pancake 2014-2015

my $file = $ARGV[0] or die ("Usage: objc.pl [file] ([baddr])\n");
my $baddr = $ARGV[1] or 0;
my $class = "";
my $bits = 32;

die "Invalid base address" if ($baddr % 4);

local $classdump = qx(class-dump-z -A "$file") or die ("Cannot open file\n");

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
			$addr += $baddr;
			printf ("f objc.".$class."_".$method." = 0x%x\n",$addr);
		}
	}
}
print "e asm.bits=$bits\n";
