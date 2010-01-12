#!/usr/bin/ruby

require 'r_bp'

bp = R_bp::RBreakpoint.new
bp.use('x86');
bp.add_hw(0x8048400,0,0);
bp.list(0)
