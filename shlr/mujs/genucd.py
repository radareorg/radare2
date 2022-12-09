# Create utfdata.h from UnicodeData.txt

tolower = []
toupper = []
isalpha = []

for line in open("UnicodeData.txt").readlines():
	line = line.split(";")
	code = int(line[0],16)
	# if code > 65535: continue # skip non-BMP codepoints
	if line[2][0] == 'L':
		isalpha.append(code)
	if line[12]:
		toupper.append((code,int(line[12],16)))
	if line[13]:
		tolower.append((code,int(line[13],16)))

def dumpalpha():
	table = []
	prev = 0
	start = 0
	for code in isalpha:
		if code != prev+1:
			if start:
				table.append((start,prev))
			start = code
		prev = code
	table.append((start,prev))

	print("")
	print("static const Rune ucd_alpha2[] = {")
	for a, b in table:
		if b - a > 0:
			print(hex(a)+","+hex(b)+",")
	print("};");

	print("")
	print("static const Rune ucd_alpha1[] = {")
	for a, b in table:
		if b - a == 0:
			print(hex(a)+",")
	print("};");

def dumpmap(name, input):
	table = []
	prev_a = 0
	prev_b = 0
	start_a = 0
	start_b = 0
	for a, b in input:
		if a != prev_a+1 or b != prev_b+1:
			if start_a:
				table.append((start_a,prev_a,start_b))
			start_a = a
			start_b = b
		prev_a = a
		prev_b = b
	table.append((start_a,prev_a,start_b))

	print("")
	print("static const Rune " + name + "2[] = {")
	for a, b, n in table:
		if b - a > 0:
			print(hex(a)+","+hex(b)+","+str(n-a)+",")
	print("};");

	print("")
	print("static const Rune " + name + "1[] = {")
	for a, b, n in table:
		if b - a == 0:
			print(hex(a)+","+str(n-a)+",")
	print("};");

print("/* This file was automatically created from UnicodeData.txt */")
dumpalpha()
dumpmap("ucd_tolower", tolower)
dumpmap("ucd_toupper", toupper)
