#!/usr/bin/perl #
# ------------- #
my $level = 0;
my $path = "";
my $ofile = "";
while(<STDIN>) {
	if (/Entering directory `(.*)'/) {
		$path = $1;
		if ($level>0) {
			print "  |"x$level;
			@str=split('/', $1);
			print "- ".$str[$#str]."\n";
		}
		$level++;
	}
	--$level if (/Leaving directory `(.*)'/);
	s/warning:/\x1b[32mwarning\x1b[0m:/;
	s/error:/\x1b[31merror\x1b[0m:/;
	if (/\..:/) {
		s/:/\n\t/;
		/(.*):/;
		$file = $1;
		print "$path/$_" if ($file ne $ofile);
		$ofile = $file;
	}
 #{ print "$path/".$line; }
}
