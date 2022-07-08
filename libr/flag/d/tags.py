import os
from sys import argv
for fname in argv[1:]:
    with open(fname) as f:
        text = ' '.join(f.read().splitlines())
    print('ft %s %s' % (os.path.basename(fname), text))
