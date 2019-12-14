module main

import (
	os
	sync
	time
	term
	flag
	filepath
	radare.r2
)

const (
	default_threads = 1
	default_timeout = 3
	default_asm_bits = 32
	default_radare2 = 'r2'
	r2r_version = '0.1'
)

pub fn main() {
	mut r2r := R2R{}
	mut fp := flag.new_flag_parser(os.args)
	fp.application(os.filename(os.executable()))
	// fp.version(r2r_version)
	show_norun := fp.bool_('norun', `n`, false, 'Dont run the tests')
	run_tests := !show_norun
	show_help := fp.bool_('help', `h`, false, 'Show this help screen')
	r2r.threads = fp.int_('threads', `j`, default_threads, 'Spawn N threads in parallel to run tests')
	show_version := fp.bool_('version', `v`, false, 'Show version information')
	if show_help {
		println(fp.usage())
		return
	}
	if show_version {
		println(r2r_version)
		return
	}
	if r2r.threads < 1 {
		eprintln('Invalid number of thread selected with -j')
		exit(1)
	}
	r2r.targets = fp.finalize() or { eprintln('Error: ' + err) exit(1) }
	for target in r2r.targets {
		println(target)
	}

	println('Loading tests')
	os.chdir('..')
	r2r.load_tests()
	// TODO: support specifying json, asm, fuzz tests to run and multiple specific tests, globbing
	if run_tests {
		if r2r.targets.len < 2 {  // WIP
			r2r.run_jsn_tests()
			r2r.run_asm_tests()
			r2r.run_fuz_tests()
		}
		r2r.run_cmd_tests()
	}
}

// make a PR for V to have this in os.mktmpdir()
fn C.mkdtemp(template charptr) byteptr

fn mktmpdir(template string) string {
	tp := if template == '' {
		'temp.XXXXXX'
	} else {
		template
	}
	dir := filepath.join(os.tmpdir(),tp)
	res := C.mkdtemp(dir.str)
	return tos_clone(res)
}

/////////////////

struct R2R {
mut:
	cmd_tests []R2RCmdTest
	asm_tests []R2RAsmTest
	targets []string
	r2 &r2.R2
	threads int
	wg sync.WaitGroup
	failed int
	fixed int
	broken int
}

struct R2RCmdTest {
mut:
	name string
	file string
	args string
	source string
	cmds string
	expect string
	expect_err string
	// mutable
	broken bool
	failed bool
	fixed bool
}

struct R2RAsmTest {
mut:
	arch string
	bits int
	mode string
	inst string
	data string
	offs u64
	bige bool
	cpu  string
}

fn (test R2RCmdTest) parse_slurp(v string) (string, string) {
	mut res := ''
	mut slurp_token := ''
	if v.starts_with("'") || v.starts_with("'") {
		eprintln('Warning: Deprecated syntax, use <<EOF in ${test.source} @ ${test.name}')
	} else if v.starts_with('<<') {
		slurp_token = v[2 .. v.len]
		if slurp_token == 'RUN' {
			eprintln('Warning: Deprecated <<RUN, use <<EOF in ${test.source} @ ${test.name}')
		}
	} else {
		res = v[0 .. v.len]
	}
	return res, slurp_token
}

fn (r2r mut R2R) load_cmd_test(testfile string) {
	if r2r.targets.len > 1 && !testfile.ends_with('/${r2r.targets[1]}') {  // WIP
		return
	}
	mut test := R2RCmdTest{}
	lines := os.read_lines(testfile) or { panic(err) }
	mut slurp_target := &test.cmds
	mut slurp_token := ''
	mut slurp_data := ''
	test.source = testfile
	for line in lines {
		if line.len == 0 {
			continue
		}
		if slurp_token.len > 0 {
			if line == slurp_token {
				*slurp_target = slurp_data
				slurp_data = ''
				slurp_token = ''
			} else {
				slurp_data += '${line}\n'
			}
			continue
		}
		kv := line.split_nth('=', 2)
		if kv.len == 0 {
			continue
		}
		match kv[0] {
			'CMDS' {
				if kv.len > 1 {
					a, b := test.parse_slurp(kv[1])
					test.cmds = a
					slurp_token = b
					if slurp_token.len > 0 {
						slurp_target = &test.cmds
					}
				} else {
					panic('Missing arg to cmds')
				}
			}
			'EXPECT' {
				if kv.len > 1 {
					a, b := test.parse_slurp(kv[1])
					test.expect = a
					slurp_token = b
					if slurp_token.len > 0 {
						slurp_target = &test.expect
					}
				} else {
					eprintln('Missing arg to cmds')
				}
			}
			'EXPECT_ERR' {
				if kv.len > 1 {
					a, b := test.parse_slurp(kv[1])
					test.expect_err = a
					slurp_token = b
					if slurp_token.len > 0 {
						slurp_target = &test.expect_err
					}
				} else {
					eprintln('Missing arg to cmds')
				}
			}
			'BROKEN' {
				if kv.len > 1 {
					test.broken = kv[1].len > 0 && kv[1] == '1'
				} else {
					eprintln('Warning: Missing value for BROKEN in ${test.source}')
				}
			}
			'ARGS' {
				if kv.len > 0 {
					test.args = line[5 .. line.len]
				} else {
					eprintln('Warning: Missing value for ARGS in ${test.source}')
				}
			}
			'FILE' {
				test.file = line[5..]
			}
			'NAME' {
				test.name = line[5..]
			}
			'RUN' {
				if test.name.len == 0 {
					eprintln('Invalid test name in ${test.source}')
				} else {
					if test.name == '' {
						eprintln('No test name to run')
					} else {
						if test.file == '' {
							test.file = '-'
						}
						r2r.cmd_tests << test
					}
					test = R2RCmdTest{}
					test.source = testfile
				}
			}
			else { }
		}
	}
}

/*
fn (r2r R2R)run_commands(test R2RCmdTest) string {
	res := ''
	for cmd in cmds {
		if isnil(cmd) {
			continue
		}
		res += r2r.r2.cmd(cmd)
	}
	return res
}
*/

fn (r2r mut R2R)test_failed(test R2RCmdTest, a string, b string) string {
	if test.broken {
		r2r.broken++
		return 'BR'
	}
	println(test.file)
	println(term.ok_message(test.cmds))
	println(term.fail_message(a))
	println(term.ok_message(b))
	r2r.failed++
	return term.red('XX')
}

fn (r2r mut R2R)test_fixed(test R2RCmdTest) string {
	r2r.fixed++
	return 'FX'
}

fn (r2r mut R2R)run_asm_test_native(test R2RAsmTest, dismode bool) {
	test_expect := if dismode {
		test.inst.trim_space()
	} else {
		test.data.trim_space()
	}
	time_start := time.ticks()
	r2r.r2.cmd('e asm.arch=${test.arch}')
	r2r.r2.cmd('e asm.bits=${test.bits}')
	if test.cpu != '' {
		r2r.r2.cmd('e asm.cpu=${test.cpu}')
	}
	if test.offs != 0 {
		r2r.r2.cmd('s ${test.offs}')
	} else {
		r2r.r2.cmd('s 0')
	}
	if test.mode.contains('E') {
		r2r.r2.cmd('e cfg.bigendian=true')
	} else {
		r2r.r2.cmd('e cfg.bigendian=false')
	}
	res := if dismode {
		r2r.r2.cmd('"pad ${test.data}"')
	} else {
		r2r.r2.cmd('"pa ${test.inst}"')
	}
	mut mark := term.green('OK')
	if res.trim_space() == test_expect {
		if test.mode.contains('B') {
			mark = term.yellow('FX')
		}
	} else {
		if test.mode.contains('B') {
			mark = term.blue('BR')
		} else {
			mark = term.red('XX')
		}
	}
	time_end := time.ticks()
	times := time_end - time_start
	println('[${mark}] ${test.mode} (time ${times}) ${test.arch} ${test.bits} : ${test.data} ${test.inst}')
	r2r.wg.done()
}

fn (r2r mut R2R)run_asm_test(test R2RAsmTest, dismode bool) {
	if !isnil(r2r.r2) {
		r2r.run_asm_test_native(test, dismode)
		return
	}
	// TODO: use the r2 api instead of spawning all the time
	mut args := []string
	args << '-a ${test.arch}'
	args << '-b ${test.bits}'
	if test.cpu != '' {
		args << '-c ${test.cpu}'
	}
	if test.offs != 0 {
		args << '-o ${test.offs}'
	}
	if test.mode.contains('E') {
		args << '-e'
	}
	if dismode {
		args << '-d'
		args << test.data
	} else {
		args << '"${test.inst}"'
	}
	rasm2_flags := args.join(' ')

	time_start := time.ticks()
	tmp_dir := mktmpdir('')
	tmp_output := filepath.join(tmp_dir, 'output.txt')
	os.system('rasm2 ${rasm2_flags} > ${tmp_output}')
	res := os.read_file(tmp_output) or { panic(err) }
	os.rm(tmp_output)
	os.rmdir(tmp_dir)

	mut mark := term.green('OK')
	test_expect := if dismode {
		test.inst.trim_space()
	} else {
		test.data.trim_space()
	}
	if res.trim_space() == test_expect {
		if test.mode.contains('B') {
			mark = term.yellow('FX')
		}
	} else {
		if test.mode.contains('B') {
			mark = term.blue('BR')
		} else {
			mark = term.red('XX')
		}
	}
	time_end := time.ticks()
	times := time_end - time_start
	println('[${mark}] ${test.mode} (time ${times}) ${test.arch} ${test.bits} : ${test.data} ${test.inst}')
	r2r.wg.done()
}

fn (r2r mut R2R)run_cmd_test(test R2RCmdTest) {
	time_start := time.ticks()
	// eprintln(test)
	tmp_dir := mktmpdir('')
	tmp_script := filepath.join(tmp_dir, 'script.r2')
	tmp_stderr := filepath.join(tmp_dir, 'stderr.txt')
	tmp_output := filepath.join(tmp_dir, 'output.txt')

	os.write_file(tmp_script, test.cmds)
	// TODO: handle timeout
	os.system('radare2 -e scr.utf8=0 -e scr.interactive=0 -e scr.color=0 -NQ -i ${tmp_script} ${test.args} ${test.file} 2> ${tmp_stderr} > ${tmp_output}')
	res := os.read_file(tmp_output) or { panic(err) }
	errstr := os.read_file(tmp_stderr) or { panic(err) }

	os.rm(tmp_script)
	os.rm(tmp_output)
	os.rm(tmp_stderr)
	os.rmdir(tmp_dir)

	mut mark := term.green('OK')
	test_expect := test.expect.trim_space()
	if res.trim_space() != test_expect {
		mark = r2r.test_failed(test, test_expect, res)
	} else {
		if test.broken {
			mark = r2r.test_fixed(test)
		} else if test.expect_err != '' && errstr.trim_space() != test.expect_err {
			mark = r2r.test_failed(test, test.expect_err, errstr)
		}
	}
	time_end := time.ticks()
	times := time_end - time_start
	println('[${mark}] (time ${times}) ${test.source} : ${test.name}')
	// count results
	r2r.wg.done()
}

fn (r2r R2R)run_fuz_test(fuzzfile string) bool {
	// cmd := '${default_radare2} -qq -A "${fuzzfile}"'
	cmd := 'rarun2 timeout=${default_timeout} system="${default_radare2} -qq -A ${fuzzfile}"'
	// TODO: support timeout
	res := os.system(cmd)
	return res == 0
}

fn (r2r R2R)run_fuz_tests() {
	fuzz_path := '../bins/fuzzed'
	// open and analyze all the files in bins/fuzzed
	if !os.is_dir(fuzz_path) {
		os.system('make -C .. bins')
	}
	files := os.ls(fuzz_path) or { panic(err) }
	for file in files {
		ff := filepath.join(fuzz_path, file)
		mark := if r2r.run_fuz_test(ff) { term.green('OK') } else { term.red('XX') }
		println('[${mark}] ${ff}')
	}
}

fn (r2r mut R2R)load_asm_test(testfile string) {
	lines := os.read_lines(testfile) or { panic(err) }
	for line in lines {
		if line.starts_with('#') {
			continue
		}
		words := line.split('"')
		if words.len == 3 {
			mut at := R2RAsmTest{}
			at.mode = words[0].trim_space()
			at.inst = words[1].trim_space()
			data := words[2].trim_space()
			if data.contains(' ') {
				w := data.split(' ')
				at.data = w[0].trim_space()
				at.offs = w[1].trim_space().u64()
			} else {
				at.data = data
			}
			abs := testfile.split('/')
			values := abs[abs.len-1].split('_')
			if values.len == 1 {
				at.arch = values[0]
				at.bits = default_asm_bits
			} else if values.len == 2 {
				at.arch = values[0]
				at.bits = values[1].int()
			} else if values.len == 3 {
				at.arch = values[0]
				at.cpu = values[1]
				at.bits = values[2].int()
			} else {
				eprintln('Warning: Invalid asm/cpu/bits filename ${abs}')
			}
			if at.bits == 0 {
				eprintln('Warning: Invalid asm.bits settings in ${abs}')
				at.bits = default_asm_bits
			}
			r2r.asm_tests << at
		} else {
			eprintln('Warning: Invalid asm test for ${testfile} in ${line}')
		}
	}
}

fn (r2r mut R2R)load_asm_tests(testpath string) {
	r2r.wg = sync.new_waitgroup()
	files := os.ls(testpath) or { panic(err) }
	for file in files {
		if file.starts_with('.') {
			continue
		}
		f := filepath.join(testpath, file)
		if os.is_dir (f) {
			r2r.load_asm_tests(f)
		} else {
			r2r.load_asm_test(f)
		}
	}
	r2r.wg.wait()
}

fn (r2r mut R2R)run_asm_tests() {
	mut c := r2r.threads
	r2r.r2 = r2.new()
	// assemble/disassemble and compare
	for at in r2r.asm_tests {
		if at.mode.contains('a') {
			r2r.wg.add(1)
			if isnil(r2r.r2) {
				go r2r.run_asm_test(at, false)
			} else {
				r2r.run_asm_test(at, false)
			}
			c--
			if c < 1 {
				r2r.wg.wait()
				c = r2r.threads
			}
		}
		if at.mode.contains('d') {
			r2r.wg.add(1)
			if isnil(r2r.r2) {
				go r2r.run_asm_test(at, true)
			} else {
				r2r.run_asm_test(at, true)
			}
			c--
			if c < 1 {
				r2r.wg.wait()
				c = r2r.threads
			}
		}
	}
	r2r.wg.wait()
}

fn (r2r mut R2R)run_jsn_tests() {
	json_path := 'db/json'
	files := os.ls(json_path) or { panic(err) }
	for file in files {
		f := filepath.join(json_path, file)
		lines := os.read_lines(f) or { panic(err) }
		for line in lines {
			mark := if r2r.run_jsn_test(line) { term.green('OK') } else { term.red('XX') }
			println('[${mark}] json ${line}')
		}
	}
}

fn (r2r mut R2R)run_cmd_tests() {
	println('Running tests')
	// r2r.r2 = r2.new()
	// TODO: use lock
	r2r.wg = sync.new_waitgroup()
	println('Adding ${r2r.cmd_tests.len} watchgooses')
	// r2r.wg.add(r2r.cmd_tests.len)
	mut c := r2r.threads
	for t in r2r.cmd_tests {
		r2r.wg.add(1)
		go r2r.run_cmd_test(t)
		c--
		if c < 1 {
			r2r.wg.wait()
			c = r2r.threads
		}
	}
	r2r.wg.wait()

	println('')
	success := r2r.cmd_tests.len - r2r.failed
	println('Broken: ${r2r.broken} / ${r2r.cmd_tests.len}')
	println('Fixxed: ${r2r.fixed} / ${r2r.cmd_tests.len}')
	println('Succes: ${success} / ${r2r.cmd_tests.len}')
	println('Failed: ${r2r.failed} / ${r2r.cmd_tests.len}')
}

fn (r2r mut R2R)load_cmd_tests(testpath string) {
	files := os.ls(testpath) or { panic(err) }
	for file in files {
		if file.starts_with('.') {
			continue
		}
		f := filepath.join(testpath, file)
		if os.is_dir (f) {
			r2r.load_cmd_tests(f)
		} else {
			r2r.load_cmd_test(f)
		}
	}
}

fn (r2r mut R2R)run_jsn_test(cmd string) bool {
	r2r.r2 = r2.new()
	jsonstr := r2r.r2.cmd(cmd)
	return os.system("echo '${jsonstr}' | jq . > /dev/null") == 0
	// r2r.r2.free()
}

fn (r2r R2R)load_jsn_tests(testpath string) {
	// implementation is in run_jsn_tests
	// nothing to load for now
}

fn (r2r mut R2R)load_tests() {
	r2r.cmd_tests = []
	db_path := 'db'
	dirs := os.ls(db_path) or { panic(err) }
	for dir in dirs {
		if dir == 'archos' {
			$if x64 {
				$if linux {
					r2r.load_cmd_tests('${db_path}/${dir}/linux-x64/')
				} $else {
					$if macos {
						r2r.load_cmd_tests('${db_path}/${dir}/darwin-x64/')
					} $else {
						eprintln('Warning: archos tests not supported for current platform')
					}
				}
			} $else {
				eprintln('Warning: archos tests not supported for current platform')
			}
		} else if dir == 'json' && r2r.targets.len < 2 {
			r2r.load_jsn_tests('${db_path}/${dir}')
		} else if dir == 'asm' && r2r.targets.len < 2 {
			r2r.load_asm_tests('${db_path}/${dir}')
		} else {
			r2r.load_cmd_tests('${db_path}/${dir}')
		}
	}
}
