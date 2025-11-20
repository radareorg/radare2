#!/usr/bin/env python3
import os
import sys
import shlex
import argparse
import difflib

from subprocess import Popen, PIPE

TEST_CASE_DIRECTORY = os.path.join('.', 'cases')

def get_exitcode_stdout_stderr(path, cmd):
    """
    Executes an external command and returns the exitcode, stdout and stderr.
    """
    args = [path]
    args.extend(shlex.split(cmd))
    proc = Popen(args, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    exitcode = proc.returncode

    return exitcode, out, err

parser = argparse.ArgumentParser(description="Regression testing.")
parser.add_argument(dest="operation", choices=["test", "rebase"])
parser.add_argument(dest="zydis_info_path", type=str)
args = parser.parse_args()

has_failed = False

for case in os.listdir(TEST_CASE_DIRECTORY):
    if not case.endswith(".in"):
        continue

    path = os.path.join(TEST_CASE_DIRECTORY, case)
    print(path)

    with open(path, mode="r") as f:
        payload = f.read()

    exitcode, out, err = get_exitcode_stdout_stderr(args.zydis_info_path, payload)

    pre, ext = os.path.splitext(case)
    path = os.path.join(TEST_CASE_DIRECTORY, pre + ".out")

    if args.operation == "rebase":
        with open(path, mode="wb") as f:
            f.write(out)
        continue

    try:
        with open(path, mode="rb") as f:
            expected = f.read().decode().replace('\r\n', '\n')

        out = out.decode().replace('\r\n', '\n')
        if expected != out:
            print(f"FAILED: '{case}' [{payload}]")
            print('\n'.join(difflib.unified_diff(
                expected.split('\n'),
                out.split('\n'),
                fromfile='expected',
                tofile='got',
            )))
            has_failed = True
    except FileNotFoundError:
        print(f"FAILED: '{case}' [Output file missing]")
        has_failed = True

if has_failed:
    print("\nSOME TESTS FAILED.")
    sys.exit(-1)
else:
    print("\nALL TESTS PASSED.")
    sys.exit(0)