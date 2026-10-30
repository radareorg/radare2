from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import subprocess

root = Path.cwd()
exe = root / 'build/subprojects/sdb/sdb.exe'
source = root / 'libr/bin/d'

def worker(number):
    output = root / 'diagnostics' / f'worker-{number}'
    output.mkdir(exist_ok=True)
    env = dict(os.environ, SDB_OUTPUT_DIR=str(output))
    for iteration in range(250):
        for file in output.iterdir():
            file.unlink()
        result = subprocess.run([str(exe), '-r', str(source)], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            print(f'FAIL worker={number} iteration={iteration} exit={result.returncode}', flush=True)
            print(result.stdout.decode(errors='replace'), flush=True)
            (root / 'diagnostics' / f'crash-{number}.log').write_bytes(result.stdout)
            return False
        if iteration % 50 == 0:
            print(f'worker={number} completed={iteration + 1}', flush=True)
    return True

with ThreadPoolExecutor(max_workers=8) as pool:
    passed = all(list(pool.map(worker, range(8))))
print(f'2000 fresh generations passed={passed}', flush=True)
raise SystemExit(0 if passed else 1)
