use r2::r_bin;

$b = r_bin::RBin->new ();
$b->load ("/bin/ls", undef);
$baddr = $b->get_baddr ();
printf ("baddr=0x%08x\n", $baddr);
print "-> Sections\n";
for $i (b->get_sections ()) {
	printf ("offset=0x%08x va=0x%08x size=%05i %s\n",
			$i{"offset"}, baddr+$i{"rva"}, $i{"size"}, $i{"name"});
}
