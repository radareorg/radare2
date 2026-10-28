#!/usr/bin/env python3
"""V850E1 integer/exception vectors, independent of the SE5000 device hooks.

Reference: Renesas U14559EJ3V1UM, chapters 2, 5 and 6; E2 branch forms use
R01US0001EJ0100. Select the executable and its libraries with R2/environment.
"""
import json
import os
import struct
import subprocess
import unittest

R2 = os.environ.get('R2', 'r2')
PC, DATA = 0x1000, 0x2000
MASK = 0xffffffff
VECTORS = 0


def words(*values):
    return struct.pack('<'+'H'*len(values), *values).hex()


def signed(value, bits=32):
    value &= (1 << bits)-1
    return value-(1 << bits) if value & (1 << (bits-1)) else value


def condition(cc, psw):
    z,s,ov,cy=[bool(psw&(1<<bit)) for bit in range(4)]
    return [ov,cy,z,cy or z,s,True,s!=ov,s!=ov or z,
            not ov,not cy,not z,not (cy or z),not s,False,s==ov,s==ov and not z][cc]


def run(commands, cpu='e1'):
    result = subprocess.run([R2, '-NN', '-q', '-a', 'v850', '-b', '32',
        '-e', 'scr.color=0', '-c', ';'.join([f'e asm.cpu={cpu}', 'e esil.skipself=false', 'aei']+commands),
        'malloc://0x10000'], capture_output=True, text=True, timeout=60)
    if result.returncode or 'ERROR:' in result.stderr:
        raise AssertionError(result.stdout[-3000:]+result.stderr[-3000:])
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]


class Instructions(unittest.TestCase):
    def vectors(self, cases, cpu='e1'):
        global VECTORS
        VECTORS += len(cases)
        for start in range(0, len(cases), 32):
            commands = []
            batch = cases[start:start+32]
            for case in batch:
                code, initial, expected, setup = case[:4]
                regs = dict(r0=0, r1=0, r2=0, sp=0x8000, gp=0, tp=0, r6=0,
                    ep=DATA, lp=0x12345678, pc=PC, psw=0x30, ecr=0xabcd1234,
                    eipc=0x4000, eipsw=0x15, fepc=0x5000, fepsw=0x28,
                    dbpc=0x6000, dbpsw=0x13, ctpc=0x7000, ctpsw=0x18, dir=0x40)
                regs.update(initial)
                commands += [f'wx {code} @{regs["pc"]}', f'wx 00000000 @{DATA}']+list(setup)
                commands += [f'aer {reg}={value}' for reg,value in regs.items()]
                commands += ['aes']+(case[4] if len(case)>4 else [])+['ae r0,r11,:=', 'aerj']
            actual = run(commands,cpu)
            self.assertEqual(len(actual),len(batch))
            for case,snapshot in zip(batch,actual):
                code,initial,expected=case[:3]
                with self.subTest(code=code,initial=initial,cpu=cpu):
                    self.assertEqual({reg:((snapshot['psw'] >> {'z':0,'s':1,'ov':2,'cy':3}[reg])&1
                        if reg in ('z','s','ov','cy') else snapshot[reg]) for reg in expected},expected)
                    self.assertEqual(snapshot['r11'],0)

    def test_logical_register_and_immediate_aliases(self):
        cases=[]
        for op,opcode in [('and',0xa),('or',8),('xor',9),('not',1),('tst',0xb)]:
            for dst in (0,1,2):
                for lhs,rhs in [(0,0),(0xffffffff,0x12345678),(0x80000000,0xffffffff),(0,0x80000000)]:
                    regs=dict(r1=rhs,r2=lhs,psw=0xfb)
                    a,b=regs.get('r'+str(dst),0),rhs
                    value={'and':a&b,'or':a|b,'xor':a^b,'not':b^MASK,'tst':a&b}[op]
                    expected=dict(psw=0xf8|int(value==0)|(value>>31)<<1)
                    if dst:
                        expected['r'+str(dst)]=a if op=='tst' else value
                    cases.append((words(dst<<11|opcode<<5|1),regs,expected,[]))
        for op,opcode in [('andi',0x36),('ori',0x34),('xori',0x35)]:
            for dst in (0,1,2):
                for imm in (0,0x8000,0xffff):
                    value={'andi':0x80008001&imm,'ori':0x80008001|imm,'xori':0x80008001^imm}[op]
                    expected=dict(psw=0xf8|int(value==0)|(value>>31)<<1)
                    if dst: expected['r'+str(dst)]=value
                    cases.append((words(dst<<11|opcode<<5|1,imm),dict(r1=0x80008001,psw=0xff),expected,[]))
        self.vectors(cases)

    def test_sign_and_zero_extension_preserve_all_flags(self):
        cases=[]
        for opcode,bits,extend in [(0xa0,8,True),(0xe0,16,True),(0x80,8,False),(0xc0,16,False)]:
            for value in (0,0x12345678,0x87654321,0x8000,0xff,0xffff,0xffffffff):
                result=(signed(value,bits) if extend else value&((1<<bits)-1))&MASK
                cases.append((words(opcode|1),dict(r1=value,psw=0xff),dict(r1=result,psw=0xff),[]))
        self.vectors(cases)

    def test_halfword_multiply_forms_ignore_high_halves(self):
        cases=[]
        for value in (0,0x8000,0xffff,0x12348001,0xabcd7fff):
            for operand in (-32768,-16,-1,0,1,15,32767):
                for dst in (1,2):
                    result=(signed(value,16)*operand)&MASK
                    cases.append((words(dst<<11|0x6e1,operand&65535),dict(r1=value,r2=9,psw=0xff),
                                  {'r'+str(dst):result,'psw':0xff},[]))
                if -16<=operand<=15:
                    cases.append((words(0x12e0|operand&31),dict(r2=value,psw=0xff),dict(r2=result,psw=0xff),[]))
                cases.append((words(0x10e1),dict(r1=operand&MASK,r2=value,psw=0xff),dict(r2=result,psw=0xff),[]))
        self.vectors(cases)

    def test_add_immediate_boundaries(self):
        cases=[]
        for value in (0,1,0x7fffffff,0x80000000,0xffffffff):
            for imm in (-32768,-16,-1,0,1,15,32767):
                result=(value+imm)&MASK
                ov=not -0x80000000<=signed(value)+imm<=0x7fffffff
                cy=value+(imm&MASK)>MASK
                flags=int(result==0)|(result>>31)<<1|int(ov)<<2|int(cy)<<3
                for dst in (0,1,2):
                    expected=dict(psw=0xf0|flags)
                    if dst: expected['r'+str(dst)]=result
                    cases.append((words(dst<<11|0x601,imm&65535),dict(r1=value,psw=0xff),expected,[]))
                if -16<=imm<=15:
                    cases.append((words(0x1240|imm&31),dict(r2=value,psw=0xff),dict(r2=result,psw=0xf0|flags),[]))
        self.vectors(cases)

    def test_divh_short_form_and_aliased_division_results(self):
        cases=[]
        for dividend,divisor in [(100,3),(-100,3),(100,-3),(-100,-3),(-0x80000000,-1),(0,-1),(17,0)]:
            d=signed(divisor,16)
            q=(abs(dividend)//abs(d))*(-1 if (dividend<0)!=(d<0) else 1) if d else 0
            remainder=dividend-q*d
            ov=not d or not -0x80000000<=q<=0x7fffffff
            flags=0x38|int(ov)<<2
            if d: flags|=int(q==0)|(q&MASK)>>31<<1
            expected=dict(ov=int(ov)) if not d else dict(r2=q&MASK,psw=flags)
            cases.append((words(0x1041),dict(r1=divisor&MASK,r2=dividend&MASK,psw=0x38),expected,[]))
            for reg3 in (0,1,2,3):
                expected=dict(ov=int(ov)) if not d else dict(r2=q&MASK,psw=flags)
                if d and reg3: expected['sp' if reg3==3 else 'r'+str(reg3)]=remainder&MASK
                cases.append((words(0x17e1,reg3<<11|0x280),dict(r1=divisor&MASK,r2=dividend&MASK,psw=0x38),expected,[]))
        self.vectors(cases)

    def test_memory_width_sign_aliases_and_wrapping_addresses(self):
        cases=[]
        for first,second,width,extend in [(0x700,0,1,True),(0x780,1,1,False),
                                          (0x720,0,2,True),(0x7e0,1,2,False),(0x720,1,4,False)]:
            for offset in (-16,0,16):
                for dst in (1,2):
                    value=int.from_bytes(bytes.fromhex('81fedcba')[:width],'little')
                    if extend: value=signed(value,width*8)&MASK
                    cases.append((words(dst<<11|first|1,(offset&65535)|second),
                        dict(r1=DATA-offset,psw=0xff),{'r'+str(dst):value,'psw':0xff},[f'wx 81fedcba @{DATA}']))
            value=int.from_bytes(bytes.fromhex('81fedcba')[:width],'little')
            if extend: value=signed(value,width*8)&MASK
            cases.append((words(0x1000|first|1,2|second),dict(r1=0xfffffffe,psw=0xff),
                          dict(r2=value,psw=0xff),['wx 81fedcba @0']))
        self.vectors(cases)

    def test_memory_bit_immediate_and_register_forms(self):
        cases=[]
        for op,first,second in [('set1',0x7c0,0xe0),('not1',0x47c0,0xe2),('clr1',0x87c0,0xe4),('tst1',0xc7c0,0xe6)]:
            for bit in range(8):
                for value in (0,1<<bit,0xff):
                    expected_value={'set1':value|1<<bit,'not1':value^1<<bit,'clr1':value&~(1<<bit),'tst1':value}[op]
                    expected=dict(psw=0xfe|int(not value&(1<<bit)),r10=expected_value)
                    setup=[f'wx {value:02x} @{DATA}']
                    # Read back the byte after the instruction without changing PSW.
                    for register in (False,True):
                        code=words(0x17e1,second) if register else words(first|bit<<11|1,0)
                        commands=[f'wx {code} @{PC}',*setup,'aer pc=4096',f'aer r1={DATA}',
                                  f'aer r2={bit+248}','aer psw=255','aes',f'ae {DATA},[1],r10,:=','aerj']
                        snapshot=run(commands)[0]
                        with self.subTest(op=op,bit=bit,value=value,register=register):
                            self.assertEqual({r:snapshot[r] for r in expected},expected)

    def test_system_register_roundtrip_and_readonly_ecr(self):
        cases=[]
        for regid,name in [(0,'eipc'),(1,'eipsw'),(2,'fepc'),(3,'fepsw'),(5,'psw'),
                           (16,'ctpc'),(17,'ctpsw'),(18,'dbpc'),(19,'dbpsw'),(20,'ctbp'),(21,'dir')]:
            value=0x95 if name.endswith('psw') or name=='dir' else 0x1234
            cases.append((words(regid<<11|0x7e1,0x20),dict(r1=value),{name:value},[]))
            cases.append((words(0x17e0|regid,0x40),{name:value},dict(r2=value),[]))
        cases.append((words(0x27e1,0x20),dict(r1=0x12345678),dict(ecr=0xabcd1234),[]))
        self.vectors(cases)

    def test_all_trap_vectors_and_reti_control_flag_combinations(self):
        cases=[]
        for vector in range(32):
            for psw in range(0,256,0x20):
                psw|=0x15
                cases.append((words(0x7e0|vector,0x100),dict(psw=psw),
                    dict(pc=0x40 if vector<16 else 0x50,eipc=PC+4,eipsw=psw,
                         ecr=0xabcd0000|0x40+vector,psw=psw|0x60,fepc=0x5000,fepsw=0x28),[]))
        for psw in range(256):
            fe=psw&0xc0==0x80
            cases.append((words(0x7e0,0x140),dict(psw=psw),
                          dict(pc=0x5000 if fe else 0x4000,psw=0x28 if fe else 0x15),[]))
        self.vectors(cases)

    def test_trap_inside_nmi_debug_trap_and_both_returns(self):
        snapshots=run([f'wx {words(0x7e1,0x100)} @{PC}','wx 40f8 @0x40',
            'wx e0074601 @0x60','wx e0074001 @0x42','wx e0074001 @0x1004',
            f'aer pc={PC}','aer psw=0x95','aer fepc=0x5000','aer fepsw=0x15',
            'aer ecr=0xabcd1234','aer dir=0x40',*(['aes','aerj']*5)])
        self.assertEqual([(s['pc'],s['psw']) for s in snapshots],
                         [(0x40,0xf5),(0x60,0xf5),(0x42,0xf5),(PC+4,0x95),(0x5000,0x15)])
        self.assertEqual((snapshots[-1]['dir'],snapshots[-1]['ecr']),(0x40,0xabcd0041))

    def test_defined_e1_illegal_opcode_traps_and_returns(self):
        cases=[]
        for code in (words(0x7e0,0x380),words(0xffe0,0x7fe),words(0x7ff,0xffff&~1)):
            cases.append((code,dict(psw=0x95),dict(pc=0x60,dbpc=PC+4,dbpsw=0x95,psw=0xf5,dir=0x41),[]))
        self.vectors(cases)

    def test_e2_long_calls_link_to_selected_register_and_jumps_add_displacement(self):
        cases=[]
        for displacement in (-16,0,16):
            for link in (1,2,31):
                value=displacement&MASK
                cases.append((words(0x2e0|link,value&65535,value>>16),{},
                    {'lp' if link==31 else 'r'+str(link):PC+6,'pc':PC+displacement},[]))
            value=displacement&MASK
            cases.append((words(0x6e1,value&65535,value>>16),dict(r1=DATA+1),dict(pc=DATA+displacement),[]))
        self.vectors(cases,'e2')

    def test_compact_load_store_widths_and_ep_aliases(self):
        cases=[]
        for opcode,scale,width,extend,limit in [(0x300,1,1,True,127),(0x60,1,1,False,15),
                (0x400,2,2,True,127),(0x70,2,2,False,15),(0x500,2,4,False,126)]:
            for displacement in (0,limit):
                for dst in (2,30):
                    value=int.from_bytes(bytes.fromhex('81fedcba')[:width],'little')
                    if extend: value=signed(value,width*8)&MASK
                    cases.append((words(dst<<11|opcode|displacement),dict(ep=DATA-displacement*scale,psw=0xff),
                        {'r2' if dst==2 else 'ep':value,'psw':0xff},[f'wx 81fedcba @{DATA}']))
        for opcode,width,displacement,scale in [(0x380,1,127,1),(0x480,2,127,2),(0x501,4,126,2)]:
            mask=(1<<(8*width))-1
            cases.append((words(0x1000|opcode|displacement),dict(ep=DATA-displacement*scale,r2=0x12345678,psw=0xff),
                dict(r10=(0xbadcfe81&~mask)|(0x12345678&mask),psw=0xff),[f'wx 81fedcba @{DATA}'],[f'ae {DATA},[4],r10,:=']))
        for first,second,width in [(0x740,0,1),(0x760,0,2),(0x760,1,4)]:
            mask=(1<<(8*width))-1
            cases.append((words(0x1000|first|1,2|second),dict(r1=0xfffffffe,r2=0x12345678,psw=0xff),
                dict(r10=(0xbadcfe81&~mask)|(0x12345678&mask),psw=0xff),['wx 81fedcba @0'],['ae 0,[4],r10,:=']))
        self.vectors(cases)

    def test_e2_bit_search_all_positions_and_no_match(self):
        cases=[]
        for opcode,zero,left in [(0x364,True,True),(0x360,True,False),(0x366,False,True),(0x362,False,False)]:
            for position in range(33):
                match=1<<position if position<32 else 0
                value=match^MASK if zero else match
                index=(32-position if left else position+1) if match else 0
                for dst in (0,2,3):
                    expected=dict(psw=0xf0|(8 if match else 1))
                    if dst: expected['r2' if dst==2 else 'sp']=index
                    cases.append((words(0x17e0,dst<<11|opcode),dict(r2=value,psw=0xff),expected,[]))
        self.vectors(cases,'e2')

    def test_e2_hsh_flags_and_aliases(self):
        cases=[]
        for value in (0,0xffffffff,0x80000000,0x12340000,0x00008000):
            for dst in (0,2,3):
                expected=dict(psw=0xf0|int(value&65535==0)*9|(value>>31)<<1)
                if dst: expected['r2' if dst==2 else 'sp']=value
                cases.append((words(0x17e0,dst<<11|0x346),dict(r2=value,psw=0xff),expected,[]))
        self.vectors(cases,'e2')

    def test_e2_caxi_flags_memory_and_all_operand_aliases(self):
        cases=[]
        for compare,token in [(0,0),(7,7),(0x80000000,0x7fffffff),(0x7fffffff,0xffffffff),(0xffffffff,1)]:
            for replacement in (0,1,2,3):
                regs=dict(r1=DATA+3,r2=compare,sp=0x12345678,psw=0xff)
                source=regs.get('r'+str(replacement),0) if replacement!=3 else regs['sp']
                result=(compare-token)&MASK
                overflow=not -0x80000000<=signed(compare)-signed(token)<=0x7fffffff
                expected=dict(psw=0xf0|int(result==0)|(result>>31)<<1|int(overflow)<<2|int(compare<token)<<3,
                              r10=source if compare==token else token)
                if replacement: expected['sp' if replacement==3 else 'r'+str(replacement)]=token
                cases.append((words(0x17e1,replacement<<11|0xee),regs,expected,
                    [f'wx {struct.pack("<I",token).hex()} @{DATA}'],[f'ae {DATA},[4],r10,:=']))
        self.vectors(cases,'e2')

    def test_e2_multiply_accumulate_even_pairs_and_overlaps(self):
        cases=[]
        for unsigned in (False,True):
            for lhs,rhs,accumulator in [(0xffffffff,3,0),(0x80000000,0xffffffff,0xffffffffffffffff),
                    (0x7fffffff,0x7fffffff,0x7fffffffffffffff),(0,0,1)]:
                for acc in (0,2,4):
                    for dst in (0,2,4,30):
                        regs=dict(r1=rhs,r2=lhs,gp=accumulator&MASK,tp=accumulator>>32,psw=0xff)
                        names={0:'r0',1:'r1',2:'r2',3:'sp',4:'gp',5:'tp',30:'ep',31:'lp'}
                        values=dict(r0=0,r1=rhs,r2=lhs,sp=0x8000,gp=regs['gp'],tp=regs['tp'])
                        total_acc=values[names[acc]]|(values[names[acc+1]]<<32)
                        product=(lhs*rhs) if unsigned else signed(lhs)*signed(rhs)
                        result=(product+total_acc)&0xffffffffffffffff
                        expected={names[dst+1]:result>>32,'psw':0xff}
                        if dst: expected[names[dst]]=result&MASK
                        # reg3 pair occupies bits31..28; reg4 pair bits20..17.
                        cases.append((words(0x17e1,(acc//2)<<12|(dst//2)<<1|(0x3e0 if unsigned else 0x3c0)),
                                      regs,expected,[]))
        self.vectors(cases,'e2')

    def test_e2_conditional_add_subtract_flags_and_aliased_destinations(self):
        cases=[]
        for subtract in (False,True):
            for cc in [value for value in range(16) if value!=13]:
                for psw in (0x30,0x31,0x32,0x34,0x38,0x3f):
                    carry=condition(cc,psw)
                    for lhs,rhs in [(0,0),(MASK,0),(0x7fffffff,0),(0x80000000,MASK),(0x80000000,0x7fffffff)]:
                        for dst in (0,1,2,3):
                            total=(signed(lhs)-signed(rhs)-carry) if subtract else (signed(lhs)+signed(rhs)+carry)
                            value=total&MASK
                            overflow=not -0x80000000<=total<=0x7fffffff
                            cy=lhs<rhs+carry if subtract else lhs+rhs+carry>MASK
                            flags=0x30|int(not value)|(value>>31)<<1|int(overflow)<<2|int(cy)<<3
                            expected=dict(psw=flags)
                            if dst: expected['sp' if dst==3 else 'r'+str(dst)]=value
                            cases.append((words(0x17e1,dst<<11|(0x380 if subtract else 0x3a0)|cc<<1),
                                          dict(r1=rhs,r2=lhs,psw=psw),expected,[]))
        self.vectors(cases,'e2')

    def test_e2_fe_software_exceptions_and_dedicated_returns(self):
        cases=[]
        for vector in range(1,16):
            for psw in (0x15,0x95,0xf5):
                cases.append((words(0x40|vector<<11),dict(psw=psw),
                    dict(pc=0x30,fepc=PC+2,fepsw=psw,feic=0x30+vector,ecr=(0x30+vector)<<16|0x1234,
                         psw=psw|0xe0,eipc=0x4000,eipsw=0x15),[]))
        for psw in range(0,256,0x20):
            cases.append((words(0x7e0,0x148),dict(psw=psw),dict(pc=0x4000,psw=0x15),[]))
            cases.append((words(0x7e0,0x14a),dict(psw=psw),dict(pc=0x5000,psw=0x28),[]))
        self.vectors(cases,'e2')
        cases=[]
        for code in (words(0x40),words(0x7f0,0),words(0xfff7,0)):
            cases.append((code,dict(psw=0x95),dict(pc=0x30,fepc=PC,fepsw=0x95,feic=0x130,
                                                ecr=0x1301234,psw=0xf5),[]))
        self.vectors(cases,'e2v3')

    def test_e2_trap_cause_and_e3_indirect_call_alias(self):
        self.vectors([(words(0x7ff,0x100),{},dict(eiic=0x5f,ecr=0xabcd005f),[])],'e2')
        self.vectors([(words(0xc7e1,0x960),dict(r1=DATA+1),dict(r1=PC+4,pc=DATA),[])],'e3v5')

    def test_e2_ei_trap_nested_inside_fe_trap_restores_both_contexts(self):
        snapshots=run([f'wx {words(0x840)} @{PC}','wx f1070001 @0x30',
            'wx e0074801 @0x50','wx e0074a01 @0x34',f'aer pc={PC}',
            'aer psw=0x15','aer ecr=0xabcd1234',*(['aes','aerj']*4)],'e2')
        self.assertEqual([(s['pc'],s['psw']) for s in snapshots],
                         [(0x30,0xf5),(0x50,0xf5),(0x34,0xf5),(PC+2,0x15)])
        self.assertEqual((snapshots[-1]['feic'],snapshots[-1]['eiic'],snapshots[-1]['ecr']),
                         (0x31,0x51,0x00310051))

    def test_nine_bit_multiply_immediates_and_result_aliases(self):
        cases=[]
        for unsigned in (False,True):
            for encoded in range(512):
                imm=encoded if unsigned else signed(encoded,9)
                for dst in (0,2,3):
                    product=(0x80000001*imm if unsigned else signed(0x80000001)*imm)&0xffffffffffffffff
                    expected=dict(r2=product&MASK,psw=0xff)
                    if dst: expected['r2' if dst==2 else 'sp']=product>>32
                    cases.append((words(0x17e0|encoded&31,dst<<11|(0x242 if unsigned else 0x240)|(encoded>>5)<<2),
                                  dict(r2=0x80000001,psw=0xff),expected,[]))
        self.vectors(cases)

    def test_pc_widths_apply_to_saved_contexts_links_and_absolute_targets(self):
        for cpu,mask in [('e1',0x03fffffe),('e2',0x1ffffffe),('e2v3',0xfffffffe)]:
            target=0xffffa011&mask
            initial=dict(r1=0xffffa011,eipc=0xffffa011,fepc=0xffffa011,
                         ctpc=0xffffa011,dbpc=0xffffa011)
            cases=[(words(0x61),initial,dict(pc=target),[]),
                   (words(0x7e0,0x140),initial,dict(pc=target),[]),
                   (words(0x7e0,0x144),initial,dict(pc=target),[]),
                   (words(0x7e0,0x146),initial,dict(pc=target),[])]
            self.vectors(cases,cpu)
        for cpu,base in [('e1',0x03fffffc),('e2',0x1ffffffc),('e2v3',0xfffffffc)]:
            for code,expected in [(words(0xf80,8),dict(r1=0,pc=4)),
                                  (words(0x7e1,0x100),dict(eipc=0,pc=0x40))]:
                snapshots=run([f'omv 1 {base}',f's {base}',f'wx {code}',
                               f'aer pc={base}','aes','aerj'],cpu)
                with self.subTest(cpu=cpu,base=base,code=code):
                    self.assertEqual({r:snapshots[0][r] for r in expected},expected)


if __name__=='__main__':
    result=unittest.main(exit=False,verbosity=2)
    print(f'{VECTORS} batched instruction vectors checked')
    raise SystemExit(not result.result.wasSuccessful())
