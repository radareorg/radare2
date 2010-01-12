#!/usr/bin/perl

require 'r_bp.pm';

$a = new r_bp::rBreakpoint ();
$a->use ("x86");
$a->add_hw (0x8048000, 10, 0);
$a->add_sw (0x8048000, 10, 0);
$a->list (0);
