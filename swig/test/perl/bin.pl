use r2::r_bin;

$file = ($ARGV[0] ne "")?$ARGV[0]:"/bin/ls";
$b = r_bin::RBin->new ();
$b->load ($file, undef);
$baddr = $b->get_baddr ();
$sects = $b->get_sections ();

print "-> Sections\n";
for ($i = 0; $i < $sects->size (); $i++) {
	$s = $sects->get ($i);
	printf ("offset=0x%08x va=0x%08x size=%05i %s\n",
			$s->{offset}, $baddr + $s->{rva}, $s->{size}, $s->{name});
}
