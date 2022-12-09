/*
 * Runs one test file from the ES5 test suite test-262
 * Usage: mujs <this-file> [-s ] [-f] [-l file1.js -l ...] suit-root test-file
 * -s: print test source on failure
 * -f: print full paths/stacktraces if possible
 * -l: load a js file after the harness and before the test (to override things)
 *
 * If there are errors, print them and exits with code 1, else exit code is 0.
 *
 * The test suite is at: https://github.com/tc39/test262.git
 * The ES5 suite is at branch "es5-tests"
 *
 * - The test suite throws on any error, possibly with info at ex.message .
 * - Some tests make irreversible changes to global attrubutes, therefore it's
 *   required to run each test file in a new mujs instance.
 */

(function(global) {
	"use strict";

	// clean the global environment
	var mujs = {};

	["gc", "load", "compile", "print", "write", "read", "readline", "quit", "scriptArgs"]
	.forEach(function(a) {
		mujs[a] = global[a];
		delete global[a];
	});

	// restore the original Error.toString behavior - it's being tested too
	Error.prototype.toString = function() {
		return this.name + ': ' + this.message;
	}

	function die_usage(str) {
		if (str)
			mujs.print(str);
		mujs.print("Usage: mujs <this-file> [-f] [-l file1.js -l ...] suit-root test-file");
		mujs.quit(1);
	}

	// our file loader
	function load(str, as_filename) {
		try {
			var runtime_err = false;
			var compiled = mujs.compile(str, as_filename);
			runtime_err = true;
			compiled();
			return false;
		} catch (e) {
			return {err: e, runtime: runtime_err};
		}
	}

	var args = mujs.scriptArgs;
	var full_mode = false;
	var print_src = false;
	var overrides = [];
	while ((""+args[0])[0] == "-") {
		switch (args[0]) {
			case "-f": full_mode = true;
				   break;
			case "-s": print_src = true;
				   break;
			case "-l": args.shift();
				   overrides.push(args[0]);
				   break;
			default: die_usage("Unknown option " + args[0]);
		}
		args.shift();
	}
	if (args.length != 2)
		die_usage("Exactly 2 paths are expected");
	var root_path = args[0];
	var test_path = args[1];

	// load suite utils
	["sta.js", "testBuiltInObject.js", "testIntl.js"]
	.forEach(function(u) {
		var path = root_path + "/test/harness/" + u;
		var as_file = full_mode ? path : "test/harness/" + u;
		var err = load(mujs.read(path), as_file);
		if (err) throw (err.err);
	});

	// load user overrides (e.g. reduced getPrecision), with a global mujs
	if (overrides.length) {
		global.mujs = mujs
		overrides.forEach(function(f) {
			var err = load(mujs.read(f), f);
			if (err) throw (err.err);
		});
		delete global.mujs;
	}

	// the actual test
	var source = mujs.read(test_path);
	var negative = !!source.match(/@negative/);
	if (negative)
		var neg_str = (source.match(/@negative (.*)/) || [])[1];
	var as_file = test_path;
	if (!full_mode) {
		as_file = test_path.replace(/\\/g, "/");
		var sub = as_file.indexOf("/suite/");
		if (sub >= 0)
			as_file = "test" + as_file.substring(sub);
	}

	var result = load(mujs.read(test_path), as_file);
	if (!!result == negative) {
		// The docs don't really help about matching str, but this covers all cases
		if (neg_str)
			var err_for_match =  /NotEarlyError/.test(neg_str) ? result.err.message : result.err.name;
		if (!negative || !neg_str || RegExp(neg_str).exec(err_for_match))
			mujs.quit(0);
	}

	// failed
	// FIXME: @description can span lines. E.g. test/suite/bestPractice/Sbp_A3_T2.js
	var desc = source.match(/@description (.*)/);
	var info = "[File]  " + as_file +
		   (desc ? "\n[Desc]  " + desc[1] : "") +
		   "\n";

	if (result) {
		var err = result.err;
		var msg = !neg_str ? err : "[Mismatch @negative " + neg_str + "]" + "\n        " + err;

		info += (result.runtime ? "[run]   " : "[load]  ") + msg;
		if (err && err.stackTrace && (result.runtime || full_mode)) {
			if (full_mode) {
				info += err.stackTrace;
			} else {
				// trim the internal loader from the trace
				var internal = err.stackTrace.indexOf("\n" + load("mujs_blahblah()").err.stackTrace.trim().split("\n")[1]);
				if (internal >= 0)
					info += err.stackTrace.substring(0, internal);
				else
					info += err.stackTrace;
			}
		}
	} else {
		info += "[run]   [Error expected but none thrown]";
	}

	if (print_src)
		info += "\n[Source]\n" + source;

	mujs.print(info);
	mujs.quit(1);

})(this)
