#!/bin/bash

# Script to update HTTP URLs to HTTPS in source files
# Only updates domains that are known to support HTTPS

# List of domains known to support HTTPS
HTTPS_SUPPORTED=(
  "fsf.org"
  "www.gnu.org"
  "tools.ietf.org"
  "www.apache.org"
  "apache.org"
  "developer.apple.com"
  "sourceforge.net"
  "msdn.microsoft.com"
  "code.google.com"
  "csrc.nist.gov"
  "github.com"
  "stackoverflow.com"
  "wiki.nesdev.com"
  "zlib.net"
  "graphics.stanford.edu"
  "ftp.gnu.org"
  "llvm.org"
  "java.sun.com"
  "docs.python.org"
  "webassembly.org"
  "color.smyck.org"
  "en64.shoutwiki.com"
  "vice-emu.sourceforge.net"
  "search.cpan.org"
  "marknelson.us"
  "blogs.msdn.com"
  "amiga-dev.wikidot.com"
  "dfrws.org"
  "clang.llvm.org"
  "www.tachyonsoft.com"
  "www.mrc.uidaho.edu"
  "www.winimage.com"
  "dsibrew.org"
  "www.dwarfstd.org"
  "www.intel.com"
  "www.sco.com"
  "www.emulator101.com"
  "datasheets.chipdb.org"
  "infocenter.arm.com"
)

# Function to check if a domain should be updated to HTTPS
domain_supported() {
  local domain=$1
  for supported in "${HTTPS_SUPPORTED[@]}"; do
    if [[ "$domain" == "$supported" ]]; then
      return 0  # True, domain is supported
    fi
  done
  return 1  # False, domain not in supported list
}

# Skip specific files and file types
should_skip() {
  local file=$1
  
  # Skip binary files and image files
  if file "$file" | grep -q "binary\|image\|PNG\|JPEG\|GIF"; then
    echo "Skipping binary/image file: $file"
    return 0
  fi
  
  # Skip specific files that shouldn't be modified
  if [[ "$file" == "doc/images/shot.png" ]]; then
    echo "Skipping specific file: $file"
    return 0
  fi
  
  return 1  # File should not be skipped
}

# Loop through all files containing HTTP URLs
for file in $(git grep -l "http://" | grep -v "webs.txt" | grep -v "update_urls.sh"); do
  # Skip files that shouldn't be processed
  if should_skip "$file"; then
    continue
  fi
  
  echo "Processing $file"
  # Create a temporary file
  temp_file=$(mktemp)
  
  # Read each line of the file
  while IFS= read -r line; do
    # Check if line contains an HTTP URL
    if [[ "$line" =~ http:// ]]; then
      # Extract all HTTP URLs from the line
      urls=$(echo "$line" | grep -o 'http://[^ "'\''<>)]*')
      modified_line="$line"
      
      # Process each URL in the line
      for url in $urls; do
        # Extract domain from URL
        domain=$(echo "$url" | sed -E 's|http://([^/]+).*|\1|')
        
        # Skip URLs with variable substitutions or placeholders
        if [[ "$url" == *"%s"* || "$url" == *"%d"* || "$url" == *"%%s"* || "$url" == "http://" ]]; then
          continue
        fi
        
        # Check if domain should be updated
        if domain_supported "$domain"; then
          https_url=$(echo "$url" | sed 's|http://|https://|')
          modified_line=$(echo "$modified_line" | sed "s|$url|$https_url|g")
          echo "  Updated: $url -> $https_url"
        fi
      done
      
      # Write the modified line to the temp file
      echo "$modified_line" >> "$temp_file"
    else
      # Write the original line to the temp file
      echo "$line" >> "$temp_file"
    fi
  done < "$file"
  
  # Replace original file with modified content
  mv "$temp_file" "$file"
done

echo "URL update complete."