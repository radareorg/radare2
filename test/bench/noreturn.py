#!/usr/bin/env python3
"""Time aanr after aa and aaa in fresh r2 processes; report per-process peak RSS."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


def response(proc, timeout):
    chunks = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
            raise TimeoutError('r2 command timed out')
        chunk = os.read(proc.stdout.fileno(), 65536)
        if not chunk:
            raise RuntimeError('r2 exited before completing the command')
        chunks.append(chunk)
        if chunk.endswith(b'\0'):
            return b''.join(chunks)[:-1]


def command(proc, text, timeout):
    proc.stdin.write((text + '\n').encode())
    proc.stdin.flush()
    return response(proc, timeout)


def measure(prefix, binary, phase, timeout, setup="", aanr_setup="aa"):
    env = os.environ.copy()
    env.update(R2_NOPLUGINS='1', R2_LIBR_PLUGINS=str(prefix / 'lib' / 'radare2'))
    for key in ('DYLD_LIBRARY_PATH', 'LD_LIBRARY_PATH'):
        env[key] = str(prefix / 'lib')
    started = time.perf_counter()
    proc = subprocess.Popen([str(prefix / 'bin' / 'r2'), '-N', '-2', '-q0', str(binary)],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env)
    try:
        response(proc, timeout)
        if setup:
            command(proc, setup, timeout)
        setup_s = 0.0
        if phase == 'aanr':
            before = time.perf_counter()
            command(proc, aanr_setup, timeout)
            setup_s = time.perf_counter() - before
        before = time.perf_counter()
        command(proc, phase, timeout)
        wall_s = time.perf_counter() - before
        functions = json.loads(command(proc, 'aflj', timeout))
        summary = sorted((f['addr'], f['size'], f['nbbs'], f['ninstrs'], f['noreturn'])
                         for f in functions)
        fingerprint = hashlib.sha256(json.dumps(summary).encode()).hexdigest()
        proc.stdin.write(b'q!\n')
        proc.stdin.flush()
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = os.waitstatus_to_exitcode(status)
        if proc.returncode:
            raise RuntimeError(f'r2 exited with status {proc.returncode}')
        rss_bytes = usage.ru_maxrss * (1 if sys.platform == 'darwin' else 1024)
        return dict(wall_s=f'{wall_s:.9f}', setup_s=f'{setup_s:.9f}',
                    process_s=f'{time.perf_counter() - started:.9f}',
                    peak_rss_mib=f'{rss_bytes / 1048576:.3f}', functions=len(functions),
                    blocks=sum(f['nbbs'] for f in functions),
                    noreturn_functions=sum(bool(f['noreturn']) for f in functions),
                    analysis_sha256=fingerprint)
    finally:
        if proc.returncode is None:
            proc.kill()
            proc.wait()
        proc.stdin.close()
        proc.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='append', required=True, metavar='LABEL=PREFIX')
    parser.add_argument('--repeat', type=int, default=5)
    parser.add_argument('--warmup', type=int, default=1)
    parser.add_argument('--timeout', type=float, default=600)
    parser.add_argument('--commands', nargs='+', choices=['aanr', 'aaa'], default=['aanr', 'aaa'])
    parser.add_argument('--setup', default='', help='Untimed setup for both commands')
    parser.add_argument('--aanr-setup', default='aa', help='Untimed analysis before aanr')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('binaries', nargs='+', type=Path)
    args = parser.parse_args()
    if args.repeat < 1 or args.warmup < 0 or args.timeout <= 0:
        parser.error('repeat and timeout must be positive; warmup must be nonnegative')
    builds = [(label, Path(prefix).resolve()) for label, prefix in
              (build.split('=', 1) for build in args.build)]
    fields = ['binary', 'command', 'build', 'trial', 'wall_s', 'setup_s', 'process_s',
              'peak_rss_mib', 'functions', 'blocks', 'noreturn_functions', 'analysis_sha256']
    with args.output.open('w', newline='') as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for binary in args.binaries:
            binary_label = str(binary)
            binary = binary.resolve(strict=True)
            for phase in args.commands:
                for trial in range(-args.warmup, args.repeat):
                    offset = (trial + args.warmup) % len(builds)
                    for label, prefix in builds[offset:] + builds[:offset]:
                        result = measure(prefix, binary, phase, args.timeout, args.setup, args.aanr_setup)
                        print(f'{binary.name} {phase} {label} trial={trial + 1}: '
                              f"{result['wall_s']} s, {result['peak_rss_mib']} MiB", flush=True)
                        if trial >= 0:
                            writer.writerow(dict(binary=binary_label, command=phase,
                                                 build=label, trial=trial + 1, **result))
                            output.flush()


if __name__ == '__main__':
    main()
