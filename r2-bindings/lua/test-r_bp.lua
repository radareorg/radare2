-- RBreakpoint --
require "r_bp"

print ("Type_SW: "..r_bp.Type_SW)
print ("Type_HW: "..r_bp.Type_HW)
print "-->"
a = r_bp.RBreakpoint()
a:use ('x86')
a:add_hw (0x8048000, 10, 0)
a:add_sw (0x9540000, 16, 0)
a:list (true)
print "--"
