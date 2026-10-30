from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import shutil
import subprocess
import threading
import time

root = Path.cwd()
exe = root / 'build/subprojects/sdb/sdb.exe'
source = root / 'diagnostics/shared-input'
output = root / 'diagnostics/shared-output'
source.mkdir(exist_ok=True)
output.mkdir(exist_ok=True)
for number in range(3):
    file = source / f'symclass{number}.sdb.txt'
    shutil.copyfile(root / 'libr/bin/d/symclass.sdb.txt', file)
    os.utime(file, (time.time() + 3600, time.time() + 3600))
start = threading.Barrier(8)
stop = threading.Event()
env = dict(os.environ, SDB_OUTPUT_DIR=str(output))

def worker(number):
    start.wait()
    for iteration in range(300):
        if stop.is_set():
            return True
        result = subprocess.run([str(exe), '-r', str(source)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            stop.set()
            print(f'FAIL worker={number} iteration={iteration} exit={result.returncode}', flush=True)
            print(result.stdout.decode(errors='replace'), flush=True)
            (root / 'diagnostics' / f'crash-{number}.log').write_bytes(result.stdout)
            return False
        if iteration % 50 == 0:
            print(f'worker={number} completed={iteration + 1}', flush=True)
    return True

with ThreadPoolExecutor(max_workers=8) as pool:
    passed = all(list(pool.map(worker, range(8))))
print(f'shared-file generation passed={passed}', flush=True)
if not passed:
    raise SystemExit(1)

if passed:
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    target = output / 'symclass0.c'
    handle = kernel.CreateFileW(str(target), 0x80000000, 1, None, 3, 128, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        print('OUTPUT HELD OPEN BY ANOTHER READER', flush=True)
        result = subprocess.run([str(exe), '-r', str(source)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        print(result.stdout.decode(errors='replace'), flush=True)
        print(f'locked-output exit={result.returncode}', flush=True)
        (root / 'diagnostics/locked-output.log').write_bytes(result.stdout)
        raise SystemExit(0 if result.returncode == 0 else 1)
    finally:
        kernel.CloseHandle(handle)
