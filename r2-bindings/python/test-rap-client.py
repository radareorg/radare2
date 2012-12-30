from remote import RapClient

rs = RapClient("localhost", 9999)
rs.open ("/bin/ls", 0)
print (rs.read (10))
print (rs.read (10))
print (rs.read (10))
print (rs.cmd ("x"))
print (rs.cmd ("x"))
print (rs.cmd ("pd 3"))
