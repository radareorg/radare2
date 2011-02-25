#!/usr/bin/perl
# author: pancake <youterm.com>
#      MakeName        (0X804C1AF,     "the_forker");
#      MakeRptCmt      (0X804C1B6,     "comentari chachi\n");

open FD, "<".$ARGV[0] or die "Cannot open file\n";
print "fs symbols\n";
while(<FD>) {
	$str=$_;
	if ($str=~/MakeName[^X]*.([^,]*)[^"]*.([^"]*)/) {
		print "f sym.$2 @ 0x$1\n";
	}
	elsif ($str=~/MakeRptCmt[^X]*.([^,]*)[^"]*.([^"]*)/) {
		$cmt = $2;
		$off = $1;
		$cmt=~s/\\n//g;
		print "CC $cmt @ 0x$off\n";
	}
}
