local ffi = require ("ffi")
ffi.R = ffi.load ("r_core")
ffi.cdef([[
	typedef struct r_core_t {
	} RCore;
	RCore *r_core_new ();
	int r_core_cmd (RCore *, const char *cmd, int n);
	int r_core_file_open (RCore *, const char *file, int mode);
	int r_core_bin_load (RCore *, const char *file);
	void r_core_free (RCore *);
	void r_cons_flush ();
]])
local core = require ("core")
local RCore = core.Object:extend ()
function RCore:initialize ()
	self.core = ffi.R.r_core_new ()
end
function RCore:cmd (c, log)
	if not log then log = false end
	ffi.R.r_core_cmd (self.core, c, log)
	ffi.R.r_cons_flush ()
end

function RCore:open (f,m)
	if not m then m = false end
	ffi.R.r_core_file_open (self.core, f, m)
	ffi.R.r_core_bin_load (self.core, f)
end

function RCore:close()
p("closin")
	-- XXX leak
	ffi.R.r_core_free (self.core)
	self.core = nil
end

local c = RCore:new()
c:open ("/bin/ls", true)
c:cmd ("wx 9191")
c:cmd ("px")
c:close()
--c:free ()
