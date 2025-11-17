#!/usr/bin/env python3
from crash_tool import *
from subprocess import Popen, PIPE


def run_test(binary, payload=None):
    proc = Popen(binary, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    proc.communicate(input=payload)
    return proc.returncode == 0


def run_test_collection(test_db_file, binary, converter):
    with open(test_db_file, 'r') as f:
        cases = json.loads(f.read())
    tests_passed = True
    for i, case in enumerate(cases):
        test_result = run_test(binary, converter(case, True))
        tests_passed &= test_result
        description = 'Case #%d: ' % i
        if 'description' in case:
            description += case['description']
        else:
            description += case['mnemonic'][case['mnemonic'].rfind('_') + 1:].lower()
        print('[%s] %s' % ('PASSED' if test_result else 'FAILED', description))
    return tests_passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Runs regression tests for encoder')
    parser.add_argument('zydis_fuzz_re_enc_path')
    parser.add_argument('zydis_fuzz_enc_path')
    parser.add_argument('zydis_test_tool_path')
    args = parser.parse_args()

    print('Running re-encoding tests:')
    all_passed = run_test_collection('re_enc_test_cases.json', args.zydis_fuzz_re_enc_path, convert_re_enc_json_to_crash)
    print()
    print('Running encoding tests:')
    all_passed &= run_test_collection('enc_test_cases.json', args.zydis_fuzz_enc_path, convert_enc_json_to_crash)
    print()
    print('Running encoding tests (absolute address mode):')
    result = run_test(args.zydis_test_tool_path)
    all_passed &= result
    print('Success' if result else 'FAILED')
    print()

    if all_passed:
        print('ALL TESTS PASSED')
        sys.exit(0)
    else:
        print('SOME TESTS FAILED')
        sys.exit(1)
