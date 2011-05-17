#!/usr/bin/ruby

require 'libr'

bp = Libr::RBreakpoint.new
bp.use('x86');
bp.add_hw(0x8048400,0,0);
bp.list(0)
