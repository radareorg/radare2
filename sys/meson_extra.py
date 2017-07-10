# meson sucks a bit for now and they are slow on taking pull requests so
# this is a hack to do what I want

import re
import os

builddir = os.getenv('BUILDDIR', None)
builddir = 'build' if builddir == None else builddir

with open(os.path.join(builddir, 'REGEN.vcxproj'), 'r') as f:
    version = re.search('<PlatformToolset>(.*)</PlatformToolset>', f.read()).group(1)

print('Translating from %s to %s_xp' % (version, version))
newversion=version+'_xp'

for root, dirs, files in os.walk(builddir):
    for f in files:
        if f.endswith('.vcxproj'):
            with open(os.path.join(root, f), 'r') as proj:
                c = proj.read()
            c = c.replace(version, newversion)
            with open(os.path.join(root, f), 'w') as proj:
                proj.write(c)
            print("%s .. OK" % f)

