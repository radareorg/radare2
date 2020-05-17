import sys

sys.stdout.write("wx ")
for i in range(256):
    sys.stdout.write("%02x" % i)
sys.stdout.write("\n")
for i in range(256):
    print("f %02x @ %d" % (i, i))
