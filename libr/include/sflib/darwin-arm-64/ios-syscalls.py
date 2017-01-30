import r2pipe
import json

def chk(x):
	if x[1]['opcode'] == 'svc 0x80':
		name = x[0]['flags'][0][8:]
		sysnum = int(x[0]['opcode'].split(' ')[2], 16)
		print ("%d\t%s"%(sysnum, name))
		
dev_pid = "23f88587e12c30376f8ab0b05236798fdfa4e853/4903"

r2 = r2pipe.open("frida://" + dev_pid)
print("Importing symbols from libSystem...")
r2.cmd(".=!i*")
r2.cmd(".=!ie* libSystem.B.dylib")
print("Finding syscalls...")
funcs = r2.cmd("pdj 2 @@ sym.fun.*")

for doc in funcs.split('\n'):
	if len(doc) > 1:
		chk(json.loads(doc))
r2.quit()
print("Thanks for waiting")
