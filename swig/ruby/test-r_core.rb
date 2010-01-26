#!/usr/bin/ruby

require 'libr'

core = Libr::RCore.new
core.file_open("/bin/ls", 0);
print core.cmd_str("pd 20");
