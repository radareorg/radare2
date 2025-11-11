#!/bin/sh
# Test shellcode assembly files against original C versions

fail=0

for rasm in asm/*.rasm; do
	base=$(basename "$rasm" .rasm)
	src_file="src/${base}.c"
	
	if [ ! -f "$src_file" ]; then
		echo "  [--] $base: No source file found, skipping"
		continue
	fi
	
	# Extract expected bytes from C file
	expected=$(awk '/^#if 0/,/^#endif/{next} /\\x/{gsub(/^\/\*.*\*\/ /, ""); print}' "$src_file" | \
		grep -o '"\\x[^"]*"' | sed 's/"//g; s/\\x//g' | tr -d '\n')
	
	# Determine architecture and bits from filename
	case "$base" in
		x86-linux-binsh)
			actual=$(rasm2 -a x86 -b 32 -f "$rasm" 2>/dev/null)
			;;
		x86_64-linux-binsh)
			actual=$(rasm2 -a x86 -b 64 -f "$rasm" 2>/dev/null)
			;;
		x86-osx-binsh|x86-osx-suidbinsh)
			actual=$(rasm2 -a x86 -b 64 -f "$rasm" 2>/dev/null)
			;;
		arm-linux-binsh)
			actual=$(rasm2 -a arm -b 32 -f "$rasm" 2>/dev/null)
			;;
		thumb-linux-binsh)
			actual=$(rasm2 -a arm -f "$rasm" 2>/dev/null)
			;;
		*)
			echo "  [--] $base: Unknown architecture, skipping"
			continue
			;;
	esac
	
	if [ "$actual" = "$expected" ]; then
		echo "  [OK] $base: PASS ($actual)"
	else
		echo "  [XX] $base: FAIL"
		echo "       Expected: $expected"
		echo "       Got:      $actual"
		fail=$((fail + 1))
	fi
done

if [ $fail -eq 0 ]; then
	echo "All tests passed!"
	exit 0
else
	echo "$fail test(s) failed"
	exit 1
fi
