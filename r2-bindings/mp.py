#!/usr/bin/python
from distutils.sysconfig import get_python_lib;print(get_python_lib())
#import os,sys
#p='.'.join('/'.join(os.__file__.split('/')[:-1]).split('.')[:-1])
#try: print([x for x in sys.path if x.find(p)!=-1 and x[-9:]=="-packages"][0])
#except: print([x for x in sys.path if x[-9:]=="-packages"][0])
