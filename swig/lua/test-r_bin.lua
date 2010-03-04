-- RBin --
require "r_bin"
b = r_bin.RBin ()
b:load ("/bin/ls", "")
baddr = b:get_baddr ()
s = b:get_sections ()
nsects = s:size() - 1
for i=0,nsects do
	print (string.format ('offset=0x%08x va=0x%08x size=%05i %s',
				s[i].offset, baddr+s[i].rva, s[i].size, s[i].name))
end

-- Introspection
--m = getmetatable(s)
--table.foreach(m, print)
--table.foreach (m['.fn'], print)
