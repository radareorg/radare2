import sys

print("woe 0 0xff 1")
for i in range(256):
    print("f %02x @ %d" % (i, i))
