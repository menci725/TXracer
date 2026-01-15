#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import shlex
import solcx
import logging
import eth_utils
import subprocess

from solcx.install import _convert_and_validate_version
from web3 import Web3
from .settings import LOGGING_LEVEL


def initialize_logger(name):
    logger = logging.getLogger(name)
    logger.title = lambda *a: logger.info(*[bold(x) for x in a])
    logger_error = logger.error
    logger.error = lambda *a: logger_error(*[red(bold(x)) for x in a])
    logger_warning = logger.warning
    logger.warning = lambda *a: logger_warning(*[red(bold(x)) for x in a])
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logger


def bold(x):
    return "".join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x


def red(x):
    return "".join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x


def code_bool(value: bool):
    return str(int(value)).zfill(64)


def code_uint(value):
    return hex(value).replace("0x", "").zfill(64)


def code_int(value):
    return hex(value).replace("0x", "").zfill(64)


def code_address(value):
    return value.zfill(64)


def code_bytes(value):
    return value.ljust(64, "0")


def code_type(value, type):
    if type == "bool":
        return code_bool(value)
    elif type.startswith("uint"):
        return code_uint(value)
    elif type.startswith("int"):
        return code_int(value)
    elif type == "address":
        return code_address(value)
    elif type.startswith("bytes"):
        return code_bytes(value)
    else:
        raise Exception()


def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return p.communicate()[0]


def compile(solc_version, evm_version, source_code_file):
    out = None
    source_code = ""
    with open(source_code_file, 'r') as file:
        source_code = file.read()
    try:
        if not str(solc_version).startswith("v"):
            solc_version = "v" + str(solc_version.truncate())
        solc_version = _convert_and_validate_version(solc_version)
        if not solc_version in solcx.get_installed_solc_versions():
            solcx.install_solc(solc_version)
        solcx.set_solc_version(solc_version, True)
        out = solcx.compile_standard({
            'language': 'Solidity',
            'sources': {source_code_file: {'content': source_code}},
            'settings': {
                # "optimizer": {
                #     "enabled": True,
                #     "runs": 200
                # },
                "evmVersion": evm_version,
                "outputSelection": {
                    source_code_file: {
                        "*":
                            [
                                "abi",
                                "evm.deployedBytecode",
                                "evm.bytecode.object",
                                "evm.legacyAssembly",
                            ],
                    }
                }
            }
        }, allow_paths='.')
    except Exception as e:
        print("Error: Solidity compilation failed!")
        print(e.message)
    return out


def get_interface_from_abi(abi):
    interface = {}
    interface_mapper = {}  # 记录函数名和函数签名的映射
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[hash] = function_inputs
            interface_mapper[signature] = hash
        elif field['type'] == 'constructor':
            function_inputs = []
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            interface['constructor'] = function_inputs
    if not "fallback" in interface:
        interface["fallback"] = []
    return interface, interface_mapper


def get_function_signature_mapping(abi):
    mapping = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            mapping[hash] = signature
    if not "fallback" in mapping:
        mapping["fallback"] = "fallback"
    return mapping

# from web3 import Web3 # 确保导入

# def _get_canonical_abi_type(component):
#     base_type = component['type']
    
#     if base_type.startswith('tuple'):
#         # 如果是元组 (struct)，则递归地处理其内部组件，并用括号包裹
#         internal_types = ",".join(_get_canonical_abi_type(c) for c in component.get('components', []))
#         # 处理数组情况，例如 tuple[] -> (T1,T2)[]
#         return f"({internal_types}){base_type.replace('tuple', '')}"
    
#     # 检查 internalType 是否明确指出了这是一个 contract 或 interface
#     # 这是从 ABI 中获取语义信息的、更可靠的方式
#     internal_type = component.get('internalType', '')
#     if internal_type.startswith('contract ') or internal_type.startswith('interface '):
#         # 如果是合约或接口类型，必须规范化为 address
#         # 同时保留数组标记，例如 contract IMyContract[] -> address[]
#         is_array = "[]" if "[]" in base_type else ""
#         return 'address' + is_array
        
#     # 对于其他情况 (uint, string 等)，直接返回
#     return base_type

# def get_function_signature_mapping(abi):
#     mapping = {} # { hash: signature }
    
#     for field in abi:
#         if field.get('type') == 'function':
#              try:
#                 function_name = field['name']
#                 # 使用我们的新辅助函数来正确地构建签名
#                 input_types_str_list = [_get_canonical_abi_type(inp) for inp in field.get('inputs', [])]
#                 signature = f"{function_name}({','.join(input_types_str_list)})"
                
#                 # 使用标准的 keccak 计算哈希
#                 try:
#                     hash_bytes = Web3.keccak(text=signature)
#                 except TypeError: # 捕获 text= 不被支持的旧版本错误
#                     hash_bytes = Web3.keccak(signature.encode('utf-8'))
                
#                 hash_hex = "0x" + hash_bytes[0:4].hex()
                
#                 mapping[hash_hex] = signature
#              except Exception as e:
#                 print(f"!! WARNING: Could not process ABI for function '{field.get('name')}': {e}")
    
#     return mapping

# def remove_swarm_hash(bytecode):
#     if isinstance(bytecode, str):
#         if bytecode.endswith("0029"):
#             bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
#         if bytecode.endswith("0033"):
#             bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
#     return bytecode

def remove_swarm_hash(bytecode: str) -> str:
    if not isinstance(bytecode, str):
        return bytecode

    try:
        # 1. 获取末尾的 4 个十六进制字符 (2个字节)
        metadata_length_hex = bytecode[-4:]
        # 2. 将其转换为整数，这就是元数据部分的字节长度
        metadata_length_bytes = int(metadata_length_hex, 16)
        
        # 3. 计算需要从十六进制字符串中移除的总字符数
        #    (元数据本身 * 2 + 长度编码本身 * 2)
        total_chars_to_remove = (metadata_length_bytes * 2) + 4
        
        # 4. 安全检查：确保要移除的长度不超过总长度
        if total_chars_to_remove <= len(bytecode):
            # 5. 精确地、外科手术式地切除元数据部分
            clean_bytecode = bytecode[:-total_chars_to_remove]
            # print(f"DEBUG: Successfully removed metadata of length {metadata_length_bytes} bytes.")
            return clean_bytecode
        else:
            # 如果计算出的长度不合理，说明末尾的可能不是元数据
            # print("DEBUG: Calculated metadata length is invalid. Returning original bytecode.")
            return bytecode

    except (ValueError, IndexError):
        # 如果末尾的 4 个字符不是有效的十六进制，或者字节码太短，
        # 那么它很可能不包含元数据。安全地返回原始字节码。
        # print("DEBUG: No valid metadata length found at the end of bytecode.")
        return bytecode


def get_pcs_and_jumpis(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
    i = 0
    pcs = []
    jumpis = []
    while i < len(bytecode):
        opcode = bytecode[i]
        pcs.append(i)
        if opcode == 87:  # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127:  # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:
        pcs = [0]
    return (pcs, jumpis)


def convert_stack_value_to_int(stack_value):
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], "big")
    else:
        raise Exception("Error: Cannot convert stack value to int. Unknown type: " + str(stack_value[0]))


def convert_stack_value_to_hex(stack_value):
    if stack_value[0] == int:
        return hex(stack_value[1]).replace("0x", "").zfill(64)
    elif stack_value[0] == bytes:
        return stack_value[1].hex().zfill(64)
    else:
        raise Exception("Error: Cannot convert stack value to hex. Unknown type: " + str(stack_value[0]))


def is_fixed(value):
    return isinstance(value, int)


def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]


def print_individual_solution_as_transaction(logger, individual_solution, color="", function_signature_mapping={}, transaction_index=None):
    for index, input in enumerate(individual_solution):
        transaction = input["transaction"]
        if not transaction["to"] == None:
            if transaction["data"].startswith("0x"):
                hash = transaction["data"][0:10]
            else:
                hash = transaction["data"][0:8]
            if len(individual_solution) == 1 or (transaction_index != None and transaction_index == 0):
                if hash in function_signature_mapping:
                    logger.title(color + "Transaction - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color + "Transaction:")
            else:
                if hash in function_signature_mapping:
                    logger.title(color + "Transaction " + str(index + 1) + " - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color + "Transaction " + str(index + 1) + ":")
            logger.title(color + "-----------------------------------------------------")
            logger.title(color + "From:      " + transaction["from"])
            logger.title(color + "To:        " + str(transaction["to"]))
            logger.title(color + "Value:     " + str(transaction["value"]) + " Wei")
            logger.title(color + "Gas Limit: " + str(transaction["gaslimit"]))
            i = 0
            for data in split_len("0x" + transaction["data"].replace("0x", ""), 42):
                if i == 0:
                    logger.title(color + "Input:     " + str(data))
                else:
                    logger.title(color + "           " + str(data))
                i += 1
            logger.title(color + "-----------------------------------------------------")
            if transaction_index != None and index + 1 > transaction_index:
                break


def normalize_32_byte_hex_address(value):
    as_bytes = eth_utils.to_bytes(hexstr=value)
    return eth_utils.to_normalized_address(as_bytes[-20:])
