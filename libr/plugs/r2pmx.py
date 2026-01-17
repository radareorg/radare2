#!/usr/bin/env python3
"""
r2pmx - radare2 package manager (downloader only)

This is a Python implementation of r2pm focused only on downloading packages
from the radare2 package manager database.
"""

import os
import sys
import json
import urllib.request
import urllib.error
import argparse

R2PM_DB_URL = 'https://api.github.com/repos/radareorg/radare2-pm/contents/db'

def fetch_package_list():
    """Fetch the list of available packages from r2pm database."""
    try:
        with urllib.request.urlopen(R2PM_DB_URL) as response:
            data = json.loads(response.read().decode())
            packages = [item['name'] for item in data if item['type'] == 'file']
            return sorted(packages)
    except urllib.error.URLError as e:
        print(f"Error fetching package list: {e}", file=sys.stderr)
        return []

def download_package(package_name):
    """Download a package file from r2pm database."""
    url = f"https://raw.githubusercontent.com/radareorg/radare2-pm/master/db/{package_name}"
    try:
        with urllib.request.urlopen(url) as response:
            return response.read().decode()
    except urllib.error.URLError as e:
        print(f"Error downloading package {package_name}: {e}", file=sys.stderr)
        return None

def list_packages():
    """List all available packages."""
    packages = fetch_package_list()
    if packages:
        print("Available packages:")
        for pkg in packages:
            print(f"  {pkg}")
    else:
        print("Unable to fetch package list", file=sys.stderr)

def show_package(package_name):
    """Show the contents of a package."""
    content = download_package(package_name)
    if content:
        print(content)
    else:
        print(f"Package {package_name} not found", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description='radare2 package manager (downloader)')
    parser.add_argument('command', choices=['list', 'show'], help='Command to execute')
    parser.add_argument('package', nargs='?', help='Package name for show command')

    args = parser.parse_args()

    if args.command == 'list':
        list_packages()
    elif args.command == 'show':
        if not args.package:
            parser.error("Package name required for show command")
        show_package(args.package)

if __name__ == '__main__':
    main()