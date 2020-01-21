module main

import (
	os
	sync
	time
	term
	json
	flag
	filepath
	radare.r2
)

const (
	default_jobs = 2
	default_targets = 'arch json asm fuzz cmd unit'
	default_timeout = 3
	default_asm_bits = 32
	default_radare2 = 'radare2'
	default_dbpath = 'new/db' // XXX use execpath as relative reference to it
	cmd_test_paths = ['cmd', 'extras'] // all dirs under db/ that contain regular command tests
	r2r_version = '0.2'
)

fn autodetect_dbpath() string {
	return filepath.join(r2r_home(),default_dbpath)
}

fn r2r_home() string {
	home := filepath.basedir(os.realpath(os.executable()))
	return filepath.join(home,'..')
}

pub fn main() {
	mut r2r := R2R{}
	mut fp := flag.new_flag_parser(os.args)
	fp.application(filepath.filename(os.executable()))
	// fp.version(r2r_version)
	show_norun := fp.bool_('norun', `n`, false, 'Dont run the tests')
	show_help := fp.bool_('help', `h`, false, 'Show this help screen')
	r2r.jobs = fp.int_('jobs', `j`, default_jobs, 'Spawn N jobs in parallel to run tests ($default_jobs).' +
	                                              ' Set to 0 for 1 job per test.')
	r2r.timeout = fp.int_('timeout', `t`, default_timeout, 'How much time to wait to consider a fail ($default_timeout}')
	show_version := fp.bool_('version', `v`, false, 'Show version information')
	r2r.r2r_home = r2r_home()
	r2r.show_quiet = fp.bool_('quiet', `q`, false, 'Silent output of OK tests')
	r2r.interactive = fp.bool_('interactive', `i`, false, 'Prompt to manually fix failing tests (TODO)')
	r2r.db_path = fp.string_('dbpath', `d`, autodetect_dbpath(), 'Set database path db/')
	r2r.r2_path = fp.string_('r2', `r`, default_radare2, 'Set path/name to radare2 executable')
	if show_help {
		println(fp.usage())
		println('ARGS:')
		println('  ${default_targets}')
		println('\nExamples:')
		println('  \$ r2r cmd /write       run only the cmd tests in the /write file')
		println('  \$ time r2r -n          benchmark time spent parsing test files')
		println('  \$ r2r -j 4 json asm    run json and asm tests using 4 jobs in parallel')
		return
	}
	if show_version {
		println(r2r_version)
		return
	}
	if r2r.jobs < 0 {
		eprintln('Invalid number of thread selected with -j')
		exit(1)
	}
	args := fp.finalize() or {
		eprintln('Error: ' + err)
		exit(1)
	}
	r2r.targets = args[1..]
	if r2r.interactive {
		eprintln('Warning: interactive mode not yet implemented in V. Use the node testsuite for this')
		p := filepath.join(r2r.r2r_home,'new')
		if !os.is_dir(filepath.join(p,'node_modules')) {
			exit(1)
		}
		a := r2r.targets.join(' ')
		_ = os.system('cd $p && npm i')
		r := os.system('cd $p && node_modules/.bin/r2r -i $a')
		exit(r)
	}
	if r2r.targets.index('help') != -1 {
		eprintln(default_targets)
		exit(0)
	}
	println('[r2r] Loading tests')
	// os.chdir('..')
	r2r.load_tests()
	if !show_norun {
		r2r.run_tests()
		r2r.show_report()
	}
}

fn (r2r mut R2R) run_tests() {
	if r2r.wants('json') {
		r2r.run_jsn_tests()
	}
	if r2r.wants('unit') {
		r2r.run_unit_tests()
	}
	if r2r.wants('asm') {
		r2r.run_asm_tests()
	}
	if r2r.wants('fuzz') {
		r2r.run_fuz_tests()
	}
	if r2r.wants_any_cmd_tests() {
		r2r.run_cmd_tests()
	}
}

// make a PR for V to have this in os.mktmpdir()
fn C.mkdtemp(template charptr) byteptr


fn mktmpdir(template string) string {
	tp := if template == '' { 'temp.XXXXXX' } else { template }
	dir := filepath.join(os.tmpdir(),tp)
	res := C.mkdtemp(dir.str)
	return tos_clone(res)
}

// ///////////////
struct R2R {
mut:
	cmd_tests   []R2RCmdTest
	asm_tests   []R2RAsmTest
	targets     []string
	r2          &r2.R2
	jobs        int
	timeout     int
	wg          &sync.WaitGroup
	success     int
	failed      int
	fixed       int
	broken      int
	db_path     string
	r2_path     string
	show_quiet  bool
	interactive bool
	r2r_home    string
}

struct R2RCmdTest {
mut:
	name       string
	file       string
	args       string
	source     string
	cmds       string
	expect     string
	expect_err string
	// mutable
	broken     bool
	failed     bool
	fixed      bool
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

// TODO: not yet used
struct R2JsonTest {
mut:
	name string
}

fn (test R2RCmdTest) parse_slurp(v string) (string,string) {
	mut res := ''
	mut slurp_token := ''
	if v.starts_with("'") || v.starts_with("'") {
		eprintln('Warning: Deprecated syntax, use <<EOF in ${test.source} @ ${test.name}')
	}
	else if v.starts_with('<<') {
		slurp_token = v[2..v.len]
		if slurp_token == 'RUN' {
			eprintln('Warning: Deprecated <<RUN, use <<EOF in ${test.source} @ ${test.name}')
		}
	}
	else {
		res = v[0..v.len]
	}
	return res,slurp_token
}

fn (r2r mut R2R) load_cmd_test(testfile string) {
	mut haspaz := false
	mut found := false
	for target in r2r.targets {
		if target.contains('/') {
			haspaz = true
			if testfile.contains(target) {
				found = true
				break
			}
		}
	}
	if haspaz && !found {
		return
	}
	mut test := R2RCmdTest{}
	lines := os.read_lines(testfile) or {
		panic(err)
	}
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
			}
			else {
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
					a,b := test.parse_slurp(kv[1])
					test.cmds = a
					slurp_token = b
					if slurp_token.len > 0 {
						slurp_target = &test.cmds
					}
				}
				else {
					panic('Missing arg to cmds')
				}
			}
			'EXPECT' {
				if kv.len > 1 {
					a,b := test.parse_slurp(kv[1])
					test.expect = a
					slurp_token = b
					if slurp_token.len > 0 {
						slurp_target = &test.expect
					}
				}
				else {
					eprintln('Missing arg to cmds')
				}
			}
			'EXPECT_ERR' {
				if kv.len > 1 {
					a,b := test.parse_slurp(kv[1])
					test.expect_err = a
					slurp_token = b
					if slurp_token.len > 0 {
						slurp_target = &test.expect_err
					}
				}
				else {
					eprintln('Missing arg to cmds')
				}
			}
			'BROKEN' {
				if kv.len > 1 {
					test.broken = kv[1].len > 0 && kv[1] == '1'
				}
				else {
					eprintln('Warning: Missing value for BROKEN in ${test.source}')
				}
			}
			'ARGS' {
				if kv.len > 0 {
					test.args = line[5..line.len]
				}
				else {
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
				}
				else {
					if test.name == '' {
						eprintln('No test name to run')
					}
					else {
						if test.file == '' {
							test.file = '-'
						}
						r2r.cmd_tests << test
					}
					test = R2RCmdTest{}
					test.source = testfile
				}
			}
			else {}
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


fn (r2r mut R2R) test_failed(test R2RCmdTest, a string, b string) string {
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

fn (r2r R2R) wants(s string) bool {
	// eprintln('want ${s}')
	if s.contains('/') {
		return true
	}
	if r2r.targets.len < 1 {
		return true
	}
	return r2r.targets.index(s) != -1
}

fn (r2r R2R) wants_any_cmd_tests() bool {
	if r2r.wants('arch') {
		return true
	}
	for cmd_test_path in cmd_test_paths {
		if r2r.wants(cmd_test_path) {
			return true
		}
	}
	return false
}

fn (r2r mut R2R) test_fixed(test R2RCmdTest) string {
	r2r.fixed++
	return 'FX'
}

fn (r2r mut R2R) run_asm_test_native(test R2RAsmTest, dismode bool) {
	test_expect := if dismode { test.inst.trim_space() } else { test.data.trim_space() }
	time_start := time.ticks()
	r2r.r2.cmd('e asm.arch=${test.arch}')
	r2r.r2.cmd('e asm.bits=${test.bits}')
	if test.cpu != '' {
		r2r.r2.cmd('e asm.cpu=${test.cpu}')
	}
	if test.offs != 0 {
		r2r.r2.cmd('s ${test.offs}')
	}
	else {
		r2r.r2.cmd('s 0')
	}
	if test.mode.contains('E') {
		r2r.r2.cmd('e cfg.bigendian=true')
	}
	else {
		r2r.r2.cmd('e cfg.bigendian=false')
	}
	res := if dismode { r2r.r2.cmd('"pad ${test.data}"') } else { r2r.r2.cmd('"pa ${test.inst}"') }
	mut mark := term.green('OK')
	if res.trim_space() == test_expect {
		if test.mode.contains('B') {
			mark = term.yellow('FX')
			r2r.fixed++
		} else {
			r2r.success++
		}
	}
	else {
		if test.mode.contains('B') {
			mark = term.blue('BR')
			r2r.broken++
		}
		else {
			mark = term.red('XX')
			r2r.failed++
		}
	}
	time_end := time.ticks()
	times := time_end - time_start
	if !r2r.show_quiet || !mark.contains('OK') {
		println('[${mark}] ${test.mode} (time ${times}) ${test.arch} ${test.bits} : ${test.data} ${test.inst}')
	}
	r2r.wg.done()
}

fn (r2r mut R2R) run_asm_test(test R2RAsmTest, dismode bool) {
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
	}
	else {
		args << '"${test.inst}"'
	}
	rasm2_flags := args.join(' ')
	time_start := time.ticks()
	tmp_dir := mktmpdir('')
	tmp_output := filepath.join(tmp_dir,'output.txt')
	os.system('rasm2 ${rasm2_flags} > ${tmp_output}')
	res := os.read_file(tmp_output) or {
		panic(err)
	}
	os.rm(tmp_output)
	os.rmdir(tmp_dir)
	mut mark := term.green('OK')
	test_expect := if dismode { test.inst.trim_space() } else { test.data.trim_space() }
	if res.trim_space() == test_expect {
		if test.mode.contains('B') {
			mark = term.yellow('FX')
		}
	}
	else {
		if test.mode.contains('B') {
			mark = term.blue('BR')
		}
		else {
			mark = term.red('XX')
		}
	}
	time_end := time.ticks()
	times := time_end - time_start
	println('[${mark}] ${test.mode} (time ${times}) ${test.arch} ${test.bits} : ${test.data} ${test.inst}')
	r2r.wg.done()
}

fn (r2r mut R2R) run_cmd_test(test R2RCmdTest) {
	time_start := time.ticks()
	// eprintln(test)
	tmp_dir := mktmpdir('')
	tmp_script := filepath.join(tmp_dir,'script.r2')
	tmp_stderr := filepath.join(tmp_dir,'stderr.txt')
	tmp_output := filepath.join(tmp_dir,'output.txt')
	os.write_file(tmp_script, test.cmds)
	// TODO: handle timeout
	r2 := '${r2r.r2_path} -e scr.utf8=0 -e scr.interactive=0 -e scr.color=0 -NQ'
	os.system('${r2} -i ${tmp_script} ${test.args} ${test.file} 2> ${tmp_stderr} > ${tmp_output}')
	res := os.read_file(tmp_output) or {
		panic(err)
	}
	errstr := os.read_file(tmp_stderr) or {
		panic(err)
	}
	os.rm(tmp_script)
	os.rm(tmp_output)
	os.rm(tmp_stderr)
	os.rmdir(tmp_dir)
	mut mark := term.green('OK')
	test_expect := test.expect.trim_space()
	if res.trim_space() != test_expect {
		mark = r2r.test_failed(test, test_expect, res)
	}
	else {
		if test.broken {
			mark = r2r.test_fixed(test)
		}
		else if test.expect_err != '' && errstr.trim_space() != test.expect_err {
			mark = r2r.test_failed(test, test.expect_err, errstr)
		}
	}
	time_end := time.ticks()
	times := time_end - time_start
	println('[${mark}] (time ${times}) ${test.source} : ${test.name}')
	// count results
	r2r.wg.done()
}

fn (r2r R2R) run_fuz_test(fuzzfile string) bool {
	// cmd := 'rarun2 timeout=${default_timeout} system="${r2r.r2_path} -qq -n ${fuzzfile}"'
	// TODO: support timeout
	res := os.system('true') // cmd)
	return res == 0
}

fn (r2r R2R) git_clone(ghpath, localpath string) {
	os.system('cd ${r2r.db_path}/.. ; git clone --depth 1 https://github.com/${ghpath} ${localpath}')
}

fn (r2r mut R2R) run_fuz_tests() {
	fuzz_path := '../bins/fuzzed'
	// open and analyze all the files in bins/fuzzed
	if !os.is_dir(fuzz_path) {
		r2r.git_clone('radareorg/radare2-testbins', 'bins')
		r2r.git_clone('radareorg/radare2-fuzztargets', 'fuzz/targets')
	}
	files := os.ls(fuzz_path) or {
		panic(err)
	}
	mut n := 0
	t := files.len
	for file in files {
		ff := filepath.join(fuzz_path,file)
		res := r2r.run_fuz_test(ff)
		mark := if res { term.green('OK') } else { term.red('XX') }
		if res {
			r2r.success++
		} else {
			r2r.failed++
		}
		pc := n * 100 / t
		if !r2r.show_quiet || !res {
			println('[${mark}] ${pc}% ${ff}')
		}
		n++
	}
}

fn (r2r mut R2R) load_asm_test(testfile string) {
	lines := os.read_lines(testfile) or {
		panic(err)
	}
	for line in lines {
		if line.len == 0 || line.starts_with('#') {
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
			}
			else {
				at.data = data
			}
			abs := testfile.split('/')
			values := abs[abs.len - 1].split('_')
			if values.len == 1 {
				at.arch = values[0]
				at.bits = default_asm_bits
			}
			else if values.len == 2 {
				at.arch = values[0]
				at.bits = values[1].int()
			}
			else if values.len == 3 {
				at.arch = values[0]
				at.cpu = values[1]
				at.bits = values[2].int()
			}
			else {
				eprintln('Warning: Invalid asm/cpu/bits filename ${abs}')
			}
			if at.bits == 0 {
				eprintln('Warning: Invalid asm.bits settings in ${abs}')
				at.bits = default_asm_bits
			}
			r2r.asm_tests << at
		}
		else {
			eprintln('Warning: Invalid asm test for ${testfile} in ${line}')
		}
	}
}

fn (r2r mut R2R) load_asm_tests(testpath string) {
	r2r.wg = sync.new_waitgroup()
	files := os.ls(testpath) or {
		panic(err)
	}
	for file in files {
		if file.starts_with('.') {
			continue
		}
		f := filepath.join(testpath,file)
		if os.is_dir(f) {
			r2r.load_asm_tests(f)
		}
		else {
			r2r.load_asm_test(f)
		}
	}
	r2r.wg.wait()
}

fn (r2r mut R2R) run_unit_tests() bool {
	wd := os.getwd()
	_ = os.system('make -C ${r2r.r2r_home}/unit') // TODO: rewrite in V instead of depending on a makefile
	unit_path := '${r2r.db_path}/../../unit/bin'
	unit_home := '${r2r.db_path}/../..'
	if !os.is_dir(unit_path) {
		eprintln('Cannot open unit_path')
		return false
	}
	os.chdir(unit_home)
	println('[r2r] Running unit tests from ${unit_path}')
	files := os.ls(unit_path) or {
		return false
	}
	for file in files {
		fpath := filepath.join(unit_path, file)
		if is_executable(fpath, file) {
			// TODO: filter OK
			cmd := if r2r.show_quiet { '(${fpath} ;echo \$? > .a) | grep -v OK || [ "\$(shell cat .a)" = 0 ]' } else { '$fpath' }
			if os.system(cmd) == 0 {
				r2r.success++
			}
			else {
				r2r.failed++
			}
		}
	}
	os.chdir(wd)
	return true
}

fn is_executable(abspath, filename string) bool {
	if filename.starts_with('r2-') {
		return false
	}
	if os.is_dir(abspath) {
		return false
	}
	return os.is_executable(abspath)
}

fn (r2r mut R2R) run_asm_tests() {
	mut c := r2r.jobs
	r2r.r2 = r2.new()
	// assemble/disassemble and compare
	for at in r2r.asm_tests {
		if at.mode.contains('a') {
			r2r.wg.add(1)
			if isnil(r2r.r2) {
				go r2r.run_asm_test(at,false)
			}
			else {
				r2r.run_asm_test(at, false)
			}
			if r2r.jobs > 0 {
				c--
				if c < 1 {
					r2r.wg.wait()
					c = r2r.jobs
				}
			}
		}
		if at.mode.contains('d') {
			r2r.wg.add(1)
			if isnil(r2r.r2) {
				go r2r.run_asm_test(at,true)
			}
			else {
				r2r.run_asm_test(at, true)
			}
			if r2r.jobs > 0 {
				c--
				if c < 1 {
					r2r.wg.wait()
					c = r2r.jobs
				}
			}
		}
	}
	r2r.wg.wait()
}

fn (r2r mut R2R) run_jsn_tests() {
	json_path := '${r2r.db_path}/json'
	files := os.ls(json_path) or {
		panic(err)
	}
	for file in files {
		f := filepath.join(json_path,file)
		lines := os.read_lines(f) or {
			panic(err)
		}
		for line in lines {
			if line.trim_space().len == 0 {
				continue
			}
			ok := r2r.run_jsn_test(line)
			mut mark := term.green('OK')
			if ok {
				r2r.success++
			}
			else {
				if line.contains('BROKEN') {
					mark = term.blue('BR')
					r2r.broken++
				}
				else {
					mark = term.red('XX')
					r2r.failed++
				}
			}
			if !ok || !r2r.show_quiet {
				println('[${mark}] json ${line}')
			}
		}
	}
}

fn (r2r mut R2R) run_cmd_tests() {
	println('[r2r] Running cmd tests')
	// r2r.r2 = r2.new()
	// TODO: use lock
	r2r.wg = sync.new_waitgroup()
	println('Adding ${r2r.cmd_tests.len} watchgooses')
	// r2r.wg.add(r2r.cmd_tests.len)
	mut c := r2r.jobs
	for t in r2r.cmd_tests {
		r2r.wg.add(1)
		go r2r.run_cmd_test(t)
		if r2r.jobs > 0 {
			c--
			if c < 1 {
				r2r.wg.wait()
				c = r2r.jobs
			}
		}
	}
	r2r.wg.wait()
}

fn (r2r R2R) show_report() {
	total := r2r.broken + r2r.fixed + r2r.failed + r2r.success
	println('')
	println('Broken: ${r2r.broken}')
	println('Fixxed: ${r2r.fixed}')
	println('Succes: ${r2r.success}')
	println('Failed: ${r2r.failed}')
	println('Tottal: ${total}')
}

fn (r2r mut R2R) load_cmd_tests(testpath string) {
	files := os.ls(testpath) or {
		panic(err)
	}
	for file in files {
		if file.starts_with('.') {
			continue
		}
		f := filepath.join(testpath,file)
		if os.is_dir(f) {
			r2r.load_cmd_tests(f)
		}
		else {
			r2r.load_cmd_test(f)
		}
	}
}

struct DummyStruct {
	no string
}

fn (r2r mut R2R) run_jsn_test(cmd string) bool {
	if isnil(r2r.r2) {
		r2r.r2 = r2.new()
		// _ = r2r.r2.cmd('o /bin/ls')
	}
	jsonstr := r2r.r2.cmd(cmd)
	if jsonstr.trim_space() == '' {
		return true
	}
	// verify json
	_ = json.decode(DummyStruct,jsonstr) or {
		eprintln('[r2r] json ${cmd} = ${jsonstr}')
		return false
	}
	return true
	// return os.system("echo '${jsonstr}' | jq . > /dev/null") == 0
}

fn (r2r R2R) load_jsn_tests(testpath string) {
	// implementation is in run_jsn_tests
	// nothing to load for now
}

fn (r2r mut R2R) load_tests() {
	r2r.cmd_tests = []
	if !os.is_dir(r2r.db_path) {
		eprintln('Cannot open -d ${r2r.db_path}')
		return
	}
	if r2r.wants('json') {
		r2r.load_jsn_tests('${r2r.db_path}/json')
	}
	if r2r.wants('asm') {
		r2r.load_asm_tests('${r2r.db_path}/asm')
	}
	for cmd_test_path in cmd_test_paths {
		if r2r.wants(cmd_test_path) {
			r2r.load_cmd_tests('${r2r.db_path}/${cmd_test_path}')
		}
	}
	if r2r.wants('arch') {
		$if x64 {
			p := '${r2r.db_path}/archos'
			$if linux {
				r2r.load_cmd_tests('$p/linux-x64/')
			} $else {
				$if macos {
					r2r.load_cmd_tests('$p/darwin-x64/')
				} $else {
					eprintln('Warning: archos tests not supported for current platform')
				}
			}
		} $else {
			eprintln('Warning: archos tests not supported for current platform')
		}
	}
}
