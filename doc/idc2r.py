#!/usr/bin/env python

# radare - LGPL - Copyright 2013 - xvilka

import re
import sys

class Func(object):
# FIXME: parse ftype into params and values
	def __init__(self, name="unknown", params=[], values=[], address=0, size=0, ftype=""):
		self.name = name
		self.params = params
		self.values = values
		self.address = address
		self.size = size
		self.ftype = ftype

class Llabel(object):
	def __init__(self, name="unknown", address=0):
		self.name = name
		self.address = address

class Comm(object):
	def __init__(self, text="", address=0):
		self.text = text
		self.address = address

class Enum(object):
	def __init__(self, name="unknown", members=[]):
		self.name = name
		self.members = members

class Struct(object):
	def __init__(self, name="unknown", members=[]):
		self.name = name
		self.members = members

class Union(object):
	def __init__(self, name="unknown", members=[]):
		self.name = name
		self.members = members

class Type(object):
	def __init__(self, name="unknown"):
		self.name = name
		self.members = members

# -----------------------------------------------------------------------

functions = []
llabels = []
comments = []
structs = []
enums = []
types = []

def functions_parse(idc):

	# MakeFunction (0XF3C99,0XF3CA8);
	mkfun_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeFunction[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		(?P<fend>0[xX][\dA-Fa-f]{1,8})		# Function end
		[ \t]*\);[ \t]*$
		""", re.VERBOSE)
	mkfun_group_name = dict([(v,k) for k,v in mkfun_re.groupindex.items()])
	mkfun = mkfun_re.finditer(idc)
	for match in mkfun :
		fun = Func()
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkfun_group_name[group_index+1] == "fstart" :
					fun.address = int(group, 16)
				if mkfun_group_name[group_index+1] == "fend" :
					fun.size = int(group, 16) - fun.address

		functions.append(fun)

	# SetFunctionFlags (0XF3C99, 0x400);
	mkfunflags_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*SetFunctionFlags[ \t*]\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		(?P<flags>0[xX][\dA-Fa-f]{1,8})		# Flags
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkfunflags_group_name = dict([(v,k) for k,v in mkfunflags_re.groupindex.items()])
	mkfunflags = mkfunflags_re.finditer(idc)
	for match in mkfunflags :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkfunflags_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkfunflags_group_name[group_index+1] == "flags" :
					for fun in functions :
						if fun.address == addr :
							pass # TODO: parse flags


	# MakeFrame (0XF3C99, 0, 0, 0);
	# MakeName (0XF3C99, "SIO_port_setup_S");
	mkname_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeName[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		"(?P<fname>.*)"						# Function name
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkname_group_name = dict([(v,k) for k,v in mkname_re.groupindex.items()])
	mkname = mkname_re.finditer(idc)
	for match in mkname :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkname_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkname_group_name[group_index+1] == "fname" :
					for fun in functions :
						if fun.address == addr :
							fun.name = group

	# SetType (0XFFF72, "__int32 __cdecl PCI_ByteWrite_SL(__int32 address, __int32 value)");
	mkftype_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*SetType[ \t]*\(
		(?P<fstart>0[xX][\dA-Fa-f]{1,8})	# Function start
		[ \t]*\,[ \t]*
		"(?P<ftype>.*)"						# Function type
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkftype_group_name = dict([(v,k) for k,v in mkftype_re.groupindex.items()])
	mkftype = mkftype_re.finditer(idc)
	for match in mkftype :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkftype_group_name[group_index+1] == "fstart" :
					addr = int(group, 16)
				if mkftype_group_name[group_index+1] == "ftype" :
					for fun in functions :
						if fun.address == addr :
							fun.ftype = group

	# MakeNameEx (0xF3CA0, "return", SN_LOCAL);
	mklocal_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeNameEx[ \t]*\(
		(?P<laddr>0[xX][\dA-Fa-f]{1,8})		# Local label address
		[ \t]*\,[ \t]*
		"(?P<lname>.*)"						# Local label name
		[ \t]*\,[ \t]*SN_LOCAL
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mklocal_group_name = dict([(v,k) for k,v in mklocal_re.groupindex.items()])
	mklocal = mklocal_re.finditer(idc)
	for match in mklocal :
		lab = Llabel()
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mklocal_group_name[group_index+1] == "laddr" :
					lab.address = int(group, 16)
				if mklocal_group_name[group_index+1] == "lname" :
					lab.name = group
		llabels.append(lab)

# ----------------------------------------------------------------------

def enums_parse(idc):
	pass

# ----------------------------------------------------------------------

def structs_parse(idc):
	# id = AddStrucEx (-1, "struct_MTRR", 0);
	mkstruct_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*id[ \t]*=[ \t]*AddStrucEx[ \t]*\(
		[ \t]*-1[ \t]*,[ \t]*
		"(?P<sname>.*)"						# Structure name
		[ \t]*\,[ \t]*0
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkstruct_group_name = dict([(v,k) for k,v in mkstruct_re.groupindex.items()])
	mkstruct = mkstruct_re.finditer(idc)
	for match in mkstruct :
		s = Struct()
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkstruct_group_name[group_index+1] == "sname" :
					s.name = group
		structs.append(s)

	# Case 1: not nested structures
	# =============================
	# id = GetStrucIdByName ("struct_header");
	# mid = AddStructMember(id,"BCPNV", 0, 0x5000c500, 0, 7);
	# mid = AddStructMember(id,"_", 0X7, 0x00500, -1, 1);
	# mid = AddStructMember(id, "BCPNV_size",0X8, 0x004500, -1, 1);
	mkstruct_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*id[ \t]*=[ \t]*GetStrucIdByName[ \t]*\(
		[ \t]*-1[ \t]*,[ \t]*
		"(?P<sname>.*)"						# Structure name
		[ \t]*\,[ \t]*0
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)

# ----------------------------------------------------------------------

def comments_parse(idc):
	# MakeComm (0XFED3D, "PCI class 0x600 - Host/PCI bridge");
	mkcomm_re = re.compile("""
		(?m)								# Multiline
		^[ \t]*MakeComm[ \t]*\(
		(?P<caddr>0[xX][\dA-Fa-f]{1,8})		# Comment address
		[ \t]*\,[ \t]*
		"(?P<ctext>.*)"						# Comment
		[ \t]*\);[ \t]*$
	""", re.VERBOSE)
	mkcomm_group_name = dict([(v,k) for k,v in mkcomm_re.groupindex.items()])
	mkcomm = mkcomm_re.finditer(idc)
	for match in mkcomm :
		for group_index,group in enumerate(match.groups()) :
			if group :
				if mkcomm_group_name[group_index+1] == "caddr" :
					address = int(group, 16)
				if mkcomm_group_name[group_index+1] == "ctext" :
					com_multi = group.split('\\n')
					for a in com_multi :
						com = Comm()
						com.address = address
						com.text = a
						comments.append(com)

# ----------------------------------------------------------------------

#	print("af+ 0x%08lx %d %s" % (func.address, func.size, func.name))

def generate_r2():
	for f in functions :
		if f.name != "unknown" :
			print("af+ {0} {1} {2}".format(hex(f.address), f.size, f.name))
			print("\"CCa {0} {1}\"".format(hex(f.address), f.ftype))

	for l in llabels :
		if l.name != "unknown" :
			for f in functions :
				if (l.address > f.address) and (l.address < (f.address + f.size)) :
					print("f .{0}={1}".format(l.name, hex(l.address)))

	for c in comments :
		if c.text != "" :
			print("\"CCa {0} {1}\"".format(c.address, c.text))

# ----------------------------------------------------------------------

def idc_parse(idc):
	enums_parse(idc)
	structs_parse(idc)
	functions_parse(idc)
	comments_parse(idc)
	generate_r2()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: idc2r.py input.idc > output.r2")
		sys.exit(1)

	#print(sys.argv[1])
	idc_file = open(sys.argv[1], "r")
	idc = idc_file.read()
	idc_parse(idc)
