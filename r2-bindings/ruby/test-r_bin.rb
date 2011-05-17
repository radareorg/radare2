#!/usr/bin/ruby

require 'r2/r_bin'

bin = R_bin::RBin.new
bin.load("/bin/ls", nil)
baddr = bin.get_baddr
puts "-> Sections"
for i in bin.get_sections()
	printf("offset=0x%08x va=0x%08x size=%05i %s\n",
			i.offset, baddr+i.rva, i.size, i.name)
end
