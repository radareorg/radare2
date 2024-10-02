# https://gist.github.com/thestr4ng3r/403fecffc081a899618b1500ba6d1156
# https://github.com/radareorg/radare2/issues/12070

import r2pipe

r = r2pipe.open()
ptr_size = int(r.cmd("e asm.bits").strip()) // 8

addr_stackptr = {}

blocks = r.cmdj("afbj")

def sp_delta_for_fcn_call(fcn):
    cc = fcn["calltype"]
    if cc == "stdcall":
        nargs = fcn["nargs"]
        return -nargs * ptr_size
    return 0

def sp_delta_for_instr(instr):
    if instr["type"] == "call" or instr["type"] == "ucall":
        if "jump" in instr:
            call_fcn = r.cmdj("afij@{}".format(instr["jump"]))
            if len(call_fcn) > 0:
                return sp_delta_for_fcn_call(call_fcn[0])
        else:
            print("WARNING: Target not known for jump at {:#x}!".format(instr["addr"]))
    return 0 if "stackptr" not in instr else instr["stackptr"]

def block_at(addr):
    for block in blocks:
        if block["addr"] == addr:
            return block
    return None

def trace_block(block, stackptr):
    instrs = r.cmdj("aoj {}@{}".format(block["ninstr"], block["addr"]))
    for instr in instrs:
        addr = instr["addr"]
        if addr in addr_stackptr:
            if addr_stackptr[addr] != stackptr:
                print("WARNING: mismatch at {:#x}: {} != {}".format(addr, stackptr, addr_stackptr[addr]))
            return
        addr_stackptr[addr] = stackptr
        stackptr -= sp_delta_for_instr(instr)
    if "jump" in block:
        trace_block(block_at(block["jump"]), stackptr)
    if "fail" in block:
        trace_block(block_at(block["fail"]), stackptr)

trace_block(blocks[0], 0)

for addr, stackptr in addr_stackptr.items():
    r.cmd("CC sp: {}@{}".format(stackptr, addr))
