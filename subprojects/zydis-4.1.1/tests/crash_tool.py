#!/usr/bin/env python3
import re
import sys
import json
import argparse
import functools
from struct import pack, unpack
from binary_reader import BinaryReader
from binary_writer import BinaryWriter
from subprocess import Popen, PIPE
from zydis_encoder_types import *


def to_json(obj):
    return json.dumps(obj, indent=4)


def get_width_from_enum(enum_value):
    return enum_value.name[enum_value.name.rfind('_') + 1:]


def get_enum_max(enum_class):
    if issubclass(enum_class, IntEnum):
        return max([v.value for v in enum_class])
    elif issubclass(enum_class, IntFlag):
        return functools.reduce(lambda x, y: x | y, [v.value for v in enum_class])
    else:
        raise RuntimeError('Invalid type passed to get_enum_max: ' + enum_class.__name__)


def get_sanitized_enum(reader, enum_class):
    raw_value = reader.read_uint32()
    if issubclass(enum_class, IntEnum):
        return enum_class(raw_value % (get_enum_max(enum_class) + 1))
    elif issubclass(enum_class, IntFlag):
        return enum_class(raw_value & get_enum_max(enum_class))
    else:
        raise RuntimeError('Invalid type passed to get_sanitized_enum: ' + enum_class.__name__)


def get_decomposed_flags(combined_flags):
    enum_class = type(combined_flags)
    flag_str = '|'.join([v.name for v in enum_class if v in combined_flags and v.value != 0])
    if flag_str == '':
        return enum_class(0).name
    return flag_str


def get_combined_flags(flag_str, enum_class):
    return functools.reduce(lambda x, y: x | y, [enum_class[v] for v in flag_str.split('|')])


def get_disasm(zydis_info, machine_mode, stack_width, payload):
    if not zydis_info:
        return ''
    arg_machine_mode = '-' + get_width_from_enum(machine_mode)
    arg_stack_width = '-' + get_width_from_enum(stack_width)
    proc = Popen([zydis_info, arg_machine_mode, arg_stack_width, payload[:30]], stdout=PIPE, stderr=PIPE)
    out = proc.communicate()[0].decode('utf-8')
    if proc.returncode != 0:
        return ''
    match = re.search(r"INTEL[^A]+ABSOLUTE: ([^\r\n]+)", out)
    return match.group(1)


def convert_enc_crash_to_json(crash, return_dict=False):
    reader = BinaryReader(crash)
    machine_mode = get_sanitized_enum(reader, ZydisMachineMode)
    allowed_encoding = get_sanitized_enum(reader, ZydisEncodableEncoding)
    mnemonic = get_sanitized_enum(reader, ZydisMnemonic)
    reader.read_bytes(4)
    prefixes = ZydisInstructionAttributes(reader.read_uint64() & ZYDIS_ENCODABLE_PREFIXES)
    branch_type = get_sanitized_enum(reader, ZydisBranchType)
    branch_width = get_sanitized_enum(reader, ZydisBranchWidth)
    address_size_hint = get_sanitized_enum(reader, ZydisAddressSizeHint)
    operand_size_hint = get_sanitized_enum(reader, ZydisOperandSizeHint)
    operand_count = reader.read_uint8() % (ZYDIS_ENCODER_MAX_OPERANDS + 1)
    reader.read_bytes(7)
    operands = []
    for i in range(ZYDIS_ENCODER_MAX_OPERANDS):
        if i >= operand_count:
            reader.read_bytes(SIZE_OF_ZYDIS_ENCODER_OPERAND)
            continue

        op_type = ZydisOperandType(ZydisOperandType.ZYDIS_OPERAND_TYPE_REGISTER.value +
                                   (reader.read_uint32() % get_enum_max(ZydisOperandType)))
        reg_value = get_sanitized_enum(reader, ZydisRegister)
        reg_is4 = bool(reader.read_uint8())
        reader.read_bytes(7)
        mem_base = get_sanitized_enum(reader, ZydisRegister)
        mem_index = get_sanitized_enum(reader, ZydisRegister)
        mem_scale = reader.read_uint8()
        reader.read_bytes(7)
        mem_displacement = reader.read_int64()
        mem_size = reader.read_uint16()
        reader.read_bytes(6)
        ptr_segment = reader.read_uint16()
        reader.read_bytes(2)
        ptr_offset = reader.read_uint32()
        imm = reader.read_uint64()
        op = {'operand_type': op_type.name}
        if op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_REGISTER:
            op['reg'] = {
                'value': reg_value.name,
                'is4': reg_is4,
            }
        elif op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_MEMORY:
            op['mem'] = {
                'base': mem_base.name,
                'index': mem_index.name,
                'scale': mem_scale,
                'displacement': str(mem_displacement),
                'size': mem_size,
            }
        elif op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_POINTER:
            op['ptr'] = {
                'segment': ptr_segment,
                'offset': ptr_offset,
            }
        elif op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_IMMEDIATE:
            op['imm'] = {
                'value': str(imm)
            }
        else:
            raise RuntimeError('Invalid operand type: ' + op_type.name)
        operands.append(op)
    evex_broadcast = get_sanitized_enum(reader, ZydisBroadcastMode)
    evex_rounding = get_sanitized_enum(reader, ZydisRoundingMode)
    evex_sae = bool(reader.read_uint8())
    evex_zeroing_mask = bool(reader.read_uint8())
    reader.read_bytes(2)
    mvex_broadcast = get_sanitized_enum(reader, ZydisBroadcastMode)
    mvex_conversion = get_sanitized_enum(reader, ZydisConversionMode)
    mvex_rounding = get_sanitized_enum(reader, ZydisRoundingMode)
    mvex_swizzle = get_sanitized_enum(reader, ZydisSwizzleMode)
    mvex_sae = bool(reader.read_uint8())
    mvex_eviction_hint = bool(reader.read_uint8())
    reader.read_bytes(2)
    test_case = {
        'machine_mode': machine_mode.name,
        'allowed_encodings': get_decomposed_flags(allowed_encoding),
        'mnemonic': mnemonic.name,
        'prefixes': get_decomposed_flags(prefixes),
        'branch_type': branch_type.name,
        'branch_width': branch_width.name,
        'address_size_hint': address_size_hint.name,
        'operand_size_hint': operand_size_hint.name,
        'operands': operands,
        'evex': {
            'broadcast': evex_broadcast.name,
            'rounding': evex_rounding.name,
            'sae': evex_sae,
            'zeroing_mask': evex_zeroing_mask,
        },
        'mvex': {
            'broadcast': mvex_broadcast.name,
            'conversion': mvex_conversion.name,
            'rounding': mvex_rounding.name,
            'swizzle': mvex_swizzle.name,
            'sae': mvex_sae,
            'eviction_hint': mvex_eviction_hint,
        },
    }
    if return_dict:
        return test_case
    return to_json(test_case)


def convert_re_enc_crash_to_json(crash, zydis_info, return_dict=False):
    reader = BinaryReader(crash)
    machine_mode = ZydisMachineMode(reader.read_uint32())
    stack_width = ZydisStackWidth(reader.read_uint32())
    payload = reader.read_bytes().hex().upper()
    test_case = {
        'machine_mode': machine_mode.name,
        'stack_width': stack_width.name,
        'payload': payload,
        'description': get_disasm(zydis_info, machine_mode, stack_width, payload),
    }
    if return_dict:
        return test_case
    return to_json(test_case)


def convert_enc_json_to_crash(test_case_json, from_dict=False):
    if from_dict:
        test_case = test_case_json
    else:
        test_case = json.loads(test_case_json)
    writer = BinaryWriter()
    writer.write_uint32(ZydisMachineMode[test_case['machine_mode']])
    writer.write_uint32(get_combined_flags(test_case['allowed_encodings'], ZydisEncodableEncoding))
    writer.write_uint32(ZydisMnemonic[test_case['mnemonic']])
    writer.write_padding(4)
    writer.write_uint64(get_combined_flags(test_case['prefixes'], ZydisInstructionAttributes))
    writer.write_uint32(ZydisBranchType[test_case['branch_type']])
    writer.write_uint32(ZydisBranchWidth[test_case['branch_width']])
    writer.write_uint32(ZydisAddressSizeHint[test_case['address_size_hint']])
    writer.write_uint32(ZydisOperandSizeHint[test_case['operand_size_hint']])
    operand_count = len(test_case['operands'])
    writer.write_uint8(operand_count)
    writer.write_padding(7)
    for i in range(ZYDIS_ENCODER_MAX_OPERANDS):
        if i >= operand_count:
            writer.write_padding(SIZE_OF_ZYDIS_ENCODER_OPERAND)
            continue

        op = test_case['operands'][i]
        op_type = ZydisOperandType[op['operand_type']]
        writer.write_uint32(op_type - ZydisOperandType.ZYDIS_OPERAND_TYPE_REGISTER.value)
        if op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_REGISTER:
            writer.write_uint32(ZydisRegister[op['reg']['value']])
            writer.write_uint8(int(op['reg']['is4']))
            writer.write_padding(7)
            writer.write_padding(SIZE_OF_ZYDIS_ENCODER_OPERAND - 16)
        elif op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_MEMORY:
            writer.write_padding(12)
            writer.write_uint32(ZydisRegister[op['mem']['base']])
            writer.write_uint32(ZydisRegister[op['mem']['index']])
            writer.write_uint8(op['mem']['scale'])
            writer.write_padding(7)
            writer.write_int64(int(op['mem']['displacement']))
            writer.write_uint16(op['mem']['size'])
            writer.write_padding(6)
            writer.write_padding(SIZE_OF_ZYDIS_ENCODER_OPERAND - 48)
        elif op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_POINTER:
            writer.write_padding(44)
            writer.write_uint16(op['ptr']['segment'])
            writer.write_padding(2)
            writer.write_uint32(op['ptr']['offset'])
            writer.write_padding(SIZE_OF_ZYDIS_ENCODER_OPERAND - 56)
        elif op_type == ZydisOperandType.ZYDIS_OPERAND_TYPE_IMMEDIATE:
            writer.write_padding(52)
            writer.write_uint64(int(op['imm']['value']))
        else:
            raise RuntimeError('Invalid operand type: ' + op_type.name)
    writer.write_uint32(ZydisBroadcastMode[test_case['evex']['broadcast']])
    writer.write_uint32(ZydisRoundingMode[test_case['evex']['rounding']])
    writer.write_uint8(int(test_case['evex']['sae']))
    writer.write_uint8(int(test_case['evex']['zeroing_mask']))
    writer.write_padding(2)
    writer.write_uint32(ZydisBroadcastMode[test_case['mvex']['broadcast']])
    writer.write_uint32(ZydisConversionMode[test_case['mvex']['conversion']])
    writer.write_uint32(ZydisRoundingMode[test_case['mvex']['rounding']])
    writer.write_uint32(ZydisSwizzleMode[test_case['mvex']['swizzle']])
    writer.write_uint8(int(test_case['mvex']['sae']))
    writer.write_uint8(int(test_case['mvex']['eviction_hint']))
    writer.write_padding(2)
    return writer.get_data()


def convert_re_enc_json_to_crash(test_case_json, from_dict=False):
    if from_dict:
        test_case = test_case_json
    else:
        test_case = json.loads(test_case_json)
    writer = BinaryWriter()
    writer.write_uint32(ZydisMachineMode[test_case['machine_mode']])
    writer.write_uint32(ZydisStackWidth[test_case['stack_width']])
    writer.write_bytes(bytes.fromhex(test_case['payload']))
    return writer.get_data()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Provides two-way conversion between crash files and human-readable test cases')
    parser.add_argument('input_type', choices=['enc', 're-enc'])
    parser.add_argument('input_format', choices=['crash', 'json'])
    parser.add_argument('input_file')
    parser.add_argument('output_file', help='Pass "stdout" to print result to stdout')
    parser.add_argument('--zydis-info')
    parser.add_argument('--extract-single', type=int, default=-1)
    parser.add_argument('--append', action='store_true')
    args = parser.parse_args()

    if args.input_format == 'crash':
        read_mode = 'rb'
        write_mode = 'w'
    else:
        read_mode = 'r'
        write_mode = 'wb'
    with open(args.input_file, read_mode) as f:
        content = f.read()

    if args.input_format == 'crash':
        if args.input_type == 'enc':
            result = convert_enc_crash_to_json(content)
        else:
            result = convert_re_enc_crash_to_json(content, args.zydis_info)
    else:
        if args.extract_single >= 0:
            content = to_json(json.loads(content)[args.extract_single])
        if args.input_type == 'enc':
            result = convert_enc_json_to_crash(content)
        else:
            result = convert_re_enc_json_to_crash(content)

    if args.output_file == 'stdout':
        if write_mode == 'wb':
            sys.stdout.buffer.write(bytes(result))
        else:
            print(result)
    else:
        if args.append and write_mode == 'w':
            with open(args.output_file, 'r') as f:
                existing_db = json.loads(f.read())
            existing_db.append(json.loads(result))
            result = to_json(existing_db)
        with open(args.output_file, write_mode) as f:
            f.write(result)
