#!/usr/bin/python
from r_cons import RCons, Color_RED, Color_GREEN, Color_RESET, RCons_is_html

# Get the singleton instance
con = RCons()

# init is not necessary at all ..
# the _new () should initialize the singleton
# and return the instance itself
#con.init()
size = con.get_size()
print "COLUMNS %d"%size[0]
print "ROWS    %d"%size[1]

con.printf("Hello World\n")
con.flush()

con.any_key()
con.clear()

print "IS HTML %d"%RCons_is_html
con.printf(Color_RED + "Hello "+Color_GREEN + "World\n" + Color_RESET)
con.flush();
