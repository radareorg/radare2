#!/usr/bin/perl
use strict;
use warnings;

if (@ARGV) {
	foreach my $file (@ARGV) {
		open my $fh, '<', $file or die "Cannot open $file: $!";
		my @lines = <$fh>;
		close $fh;

		foreach my $line (@lines) {
			$line =~ s/^ +/\t/g;
			if ($line =~ /^[A-Za-z0-9]/) {
				$line =~ s/\s*\(/(/g;
			} else {
				$line =~ s/\s*\(/ (/g;
			}
			$line =~ s/'\s\(/'(/g;
			$line =~ s/\(\s\(/((/g;
		}

		open my $out, '>', $file or die "Cannot write to $file: $!";
		print $out @lines;
		close $out;
	}
} else {
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
}
