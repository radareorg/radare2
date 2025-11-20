#!/usr/bin/env r2
# Test script to verify sections functionality in vmatrix

# Load the test binary
o test/bins.orig/elf/ls

# Check if sections are loaded
iS

# Try to access sections via r_bin_get_sections
# This will test if our sections integration works
?e Testing sections access...

# Exit
q