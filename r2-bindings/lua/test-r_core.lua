-- using RCore API as the unique entrypoint --
require "r_core"

a = r_core.RAsm ()
a:use ("x86.olly")
opcode = "mov eax, 33"
foo = a:massemble (opcode)
if foo ~= nil then
	print (string.format ('%s =  %s', opcode, foo.buf_hex))
else
	print "Cannot assemble opcode"
end
