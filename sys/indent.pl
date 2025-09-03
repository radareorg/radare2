#!/usr/bin/perl
use strict;
use warnings;

while (<>) {
	s/^ +/\t/g;
	if (/^[A-Za-z0-9]/) {
		s/\s*\(/(/g;
	} else {
		s/\s*\(/ (/g;
	}
	s/'\s\(/'(/g;
	s/\(\s\(/((/g;
	print;
}
