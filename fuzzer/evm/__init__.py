#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import random
import string
import sys
import pickle
import logging
from typing import List

from eth import Chain, constants
from eth.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    HOMESTEAD_MAINNET_BLOCK,
    TANGERINE_WHISTLE_MAINNET_BLOCK,
    SPURIOUS_DRAGON_MAINNET_BLOCK,
    BYZANTIUM_MAINNET_BLOCK,
    PETERSBURG_MAINNET_BLOCK
)
from eth.constants import ZERO_ADDRESS, CREATE_CONTRACT_ADDRESS
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.rlp.accounts import Account
from eth.rlp.headers import BlockHeader
from eth.tools.logging import DEBUG2_LEVEL_NUM
from eth.validation import validate_uint256
from eth.vm.spoof import SpoofTransaction
from eth_utils import to_canonical_address, decode_hex, encode_hex, to_bytes
from web3 import HTTPProvider
from web3 import Web3
# from eth_keys.datatypes import PublicKey, Signature
# try:
#     from eth.vm.computation import MessageComputation
# except ImportError:
#     from eth.vm.logic.message import MessageComputation

from .storage_emulation import (
    FrontierVMForFuzzTesting,
    HomesteadVMForFuzzTesting,
    TangerineWhistleVMForFuzzTesting,
    SpuriousDragonVMForFuzzTesting,
    ByzantiumVMForFuzzTesting,
    PetersburgVMForFuzzTesting
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/../'
sys.path.append(BASE_DIR)
from fuzzer.utils import settings
from fuzzer.utils.utils import initialize_logger
from eth_abi import encode_abi


class InstrumentedEVM:
    def __init__(self, eth_node_ip=None, eth_node_port=None) -> None:
        chain_class = Chain.configure(
            __name__='Blockchain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, FrontierVMForFuzzTesting),
                (HOMESTEAD_MAINNET_BLOCK, HomesteadVMForFuzzTesting),
                (TANGERINE_WHISTLE_MAINNET_BLOCK, TangerineWhistleVMForFuzzTesting),
                (SPURIOUS_DRAGON_MAINNET_BLOCK, SpuriousDragonVMForFuzzTesting),
                (BYZANTIUM_MAINNET_BLOCK, ByzantiumVMForFuzzTesting),
                (PETERSBURG_MAINNET_BLOCK, PetersburgVMForFuzzTesting),
            ),
        )

        class MyMemoryDB(MemoryDB):
            def __init__(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}

            def rst(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}

        if eth_node_ip and eth_node_port and settings.REMOTE_FUZZING:
            self.w3 = Web3(HTTPProvider('http://%s:%s' % (eth_node_ip, eth_node_port)))
        else:
            self.w3 = None
        self.chain = chain_class.from_genesis_header(AtomicDB(MyMemoryDB()), MAINNET_GENESIS_HEADER)
        self.logger = initialize_logger("EVM")
        self.accounts = list()
        self.snapshot = None
        self.vm = None


    def safe_read_call(self, sender_str, to_str, data_hex):
        
        # 1. 记录下调用前的确切状态
        local_snapshot_handle = self.storage_emulator.record()
        
        output = None
        try:
            # 2. 构建输入
            read_only_input = {
                'transaction': {
                    'from': sender_str,
                    'to': to_str,
                    'value': 0,
                    'data': data_hex,
                    'gaslimit': settings.GAS_LIMIT
                },
                'block': {}, 'global_state': {}, 'environment': {}
            }
            
            # 3. 查询
            result = self.deploy_transaction(read_only_input, gas_price=0)
            
            if not result.is_error:
                output = result.output

        except Exception as e:
            self.logger.error(f"An exception occurred during safe_read_call: {e}")
            output = None
            
        finally:
            # 4.恢复到调用这个函数之前
            self.storage_emulator.discard(local_snapshot_handle)
            
        return output
        
    def get_block_by_blockid(self, block_identifier):
        validate_uint256(block_identifier)
        return self.w3.eth.getBlock(block_identifier)

    def get_cached_block_by_id(self, block_number):
        block = None
        with open(os.path.dirname(os.path.abspath(__file__)) + "/" + ".".join([str(block_number), "block"]), "rb") as f:
            block = pickle.load(f)
        return block

    @property
    def storage_emulator(self):
        return self.vm.state._account_db

    def set_vm(self, block_identifier='latest'):
        _block = None
        if self.w3:
            if block_identifier == 'latest':
                block_identifier = self.w3.eth.blockNumber
            validate_uint256(block_identifier)
            _block = self.w3.eth.getBlock(block_identifier)
        if not _block:
            if block_identifier in [HOMESTEAD_MAINNET_BLOCK, BYZANTIUM_MAINNET_BLOCK, PETERSBURG_MAINNET_BLOCK]:
                _block = self.get_cached_block_by_id(block_identifier)
            else:
                self.logger.error("Unknown block identifier.")
                sys.exit(-4)
        block_header = BlockHeader(difficulty=_block.difficulty,
                                   block_number=_block.number,
                                   gas_limit=_block.gasLimit,
                                   timestamp=_block.timestamp,
                                   coinbase=ZERO_ADDRESS,  # default value
                                   parent_hash=_block.parentHash,
                                   uncles_hash=_block.uncles,
                                   state_root=_block.stateRoot,
                                   transaction_root=_block.transactionsRoot,
                                   receipt_root=_block.receiptsRoot,
                                   bloom=0,  # default value
                                   gas_used=_block.gasUsed,
                                   extra_data=_block.extraData,
                                   mix_hash=_block.mixHash,
                                   nonce=_block.nonce)
        self.vm = self.chain.get_vm(block_header)

    def execute(self, tx, debug=True):  # debug默认是False
        if debug:
            logging.getLogger('eth.vm.computation.Computation')
            logging.basicConfig(level=DEBUG2_LEVEL_NUM)
        return self.vm.state.apply_transaction(tx)
        # self.touched_storage_slots = []
        
        # computation = self.vm.state.apply_transaction(tx)
        
        # # 在函数返回之前，从 computation 的轨迹中提取 SSTORE 信息
        # for instruction in computation.trace:
        #     if instruction['op'] == 'SSTORE':
        #         # SSTORE 的第一个栈参数是 slot key
        #         slot_key = convert_stack_value_to_int(instruction['stack'][-1])
        #         self.touched_storage_slots.append(slot_key)
        
        # return computation

    def reset(self):
        self.storage_emulator._raw_store_db.wrapped_db.rst()

    def create_fake_account(self, address, nonce=0, balance=settings.ACCOUNT_BALANCE, code='', storage=None):
        if storage is None:
            storage = {}
        address = to_canonical_address(address)
        account = Account(nonce=nonce, balance=balance)
        self.vm.state._account_db._set_account(address, account)
        if code and code != '':
            self.vm.state._account_db.set_code(address, code)
        if storage:
            for k, v in storage.items():
                self.vm.state._account_db.set_storage(address, int.from_bytes(decode_hex(k), byteorder="big"),
                                                      int.from_bytes(decode_hex(v), byteorder="big"))
        self.logger.debug("Created account %s with balance %s", encode_hex(address), account.balance)
        return encode_hex(address)

    def has_account(self, address):
        address = to_canonical_address(address)
        return self.vm.state._account_db._has_account(address)

    def deploy_contract(self, creator, bin_code, amount=0, gas=settings.GAS_LIMIT, gas_price=settings.GAS_PRICE,
                        debug=False, deploy_args: List[str] = None, deploy_mode=1):
        """
        部署合约
        """
        # if deploy_args is not None:
        #     assert len(deploy_args) % 3 == 0, "deploy_args必须是3的倍数, [name, type, name对应的contract或者YA_DO_NOT_KNOW]"
        #     encode_types = []
        #     encode_values = []
        #     for i in range(0, len(deploy_args), 3):
        #         param_name, param_type, param_value = deploy_args[i:i + 3]
        #         if (param_type == "address" or param_type == "contract") and param_value != "YA_DO_NOT_KNOW":
        #             encode_types.append("address")
        #             if deploy_mode == 1:
        #                 encode_values.append(settings.TRANS_INFO[param_value])
        #             if deploy_mode == 2:
        #                 encode_values.append(random.choice(self.accounts))
        #             if deploy_mode == 3:
        #                 encode_values.append(0x0000000000000000000000000000000000000000)
        #         elif param_type == "address" and param_value == "YA_DO_NOT_KNOW":
        #             encode_types.append(param_type)
        #             if deploy_mode == 1:
        #                 encode_values.append(creator)
        #             if deploy_mode == 2:
        #                 encode_values.append(random.choice(self.accounts))
        #             if deploy_mode == 3:
        #                 encode_values.append(0x0000000000000000000000000000000000000000)
        #         elif param_type.startswith("uint") and param_value == "YA_DO_NOT_KNOW":
        #             encode_types.append(param_type)
        #             encode_values.append(0)
        #         elif param_type == "bool" and param_value == "YA_DO_NOT_KNOW":
        #             encode_types.append(param_type)
        #             # encode_values.append(random.choice([True, False]))
        #             encode_values.append(False)
        #         elif param_type == "string" and param_value == "YA_DO_NOT_KNOW":
        #             encode_types.append(param_type)
        #             # encode_values.append("".join(random.sample(string.ascii_letters + string.digits, 8)))
        #             encode_values.append("")
        #         elif param_type.startswith("bytes") and param_value == "YA_DO_NOT_KNOW":
        #             if param_type == "bytes":
        #                 bytes_size = random.randint(1, 32)
        #             else:
        #                 bytes_size = int(param_type[5:])
        #             encode_types.append(param_type)
        #             encode_values.append(bytearray(0 for _ in range(bytes_size)))
        #         elif param_type.startswith("int") and param_value == "YA_DO_NOT_KNOW":
        #             encode_types.append(param_type)
        #             encode_values.append(0)
        #     self.logger.info(f"encode_values: {encode_values}")
        #     bin_code += encode_abi(encode_types, encode_values).hex()
        if deploy_args: # 注意：原始代码的 deploy_args=None 检查有误，我们假设它总是一个列表
            assert len(deploy_args) % 3 == 0, "deploy_args必须是3的倍数"
            
            encode_types = []
            encode_values = []
            
            i = 0
            while i < len(deploy_args):
                param_name, param_type, param_value_str = deploy_args[i], deploy_args[i+1], deploy_args[i+2]
                
                encode_types.append(param_type)
                
                try:
                    # --- 情况 1: 这是一个合约依赖 ---
                    if param_type == 'contract' or (param_type == 'address' and param_value_str in settings.TRANS_INFO):
                        encode_values.append(settings.TRANS_INFO[param_value_str])
                    
                    # --- 情况 2: 这是一个需要自动生成的 "YA_DO_NOT_KNOW" 值 ---
                    elif param_value_str == "YA_DO_NOT_KNOW":
                        if 'uint' in param_type or 'int' in param_type: encode_values.append(0)
                        elif 'bool' in param_type: encode_values.append(False)
                        elif 'string' in param_type: encode_values.append("")
                        elif 'address' in param_type: encode_values.append(creator)
                        else: encode_values.append(b'') # 其他 bytes 类型的默认值
                    
                    # --- 情况 3 : 这是一个具体的、需要类型转换的值 ---
                    else:
                        if 'uint' in param_type or 'int' in param_type:
                            if '[]' in param_type: values.append([int(v) for v in param_value_str.split(',')])
                            else: encode_values.append(int(param_value_str))
                        elif 'bool' in param_type:
                            if '[]' in param_type: values.append([str(v).lower() in ['true','1'] for v in param_value_str.split(',')])
                            else: encode_values.append(str(param_value_str).lower() in ['true','1'])
                        elif 'address[]' in param_type:
                            # address 数组是一个特例
                            encode_values.append(param_value_str.split(','))
                        else: # string, address 等，保持为字符串
                            encode_values.append(param_value_str)

                except Exception as e:
                    self.logger.error(f"Error processing constructor argument '{param_name}': {e}")
                    # 如果处理失败，添加一个可能导致错误的占位符
                    encode_values.append(param_value_str)
                
                i += 3
            # ===================================================================

            self.logger.info(f"encode_values: {encode_values}")
            bin_code += encode_abi(encode_types, encode_values).hex()





        nonce = self.vm.state.get_nonce(decode_hex(creator))
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=CREATE_CONTRACT_ADDRESS,
            value=amount,
            data=decode_hex(bin_code),
        )
        tx = SpoofTransaction(tx, from_=decode_hex(creator))
        result = self.execute(tx, debug=debug)
        address = to_canonical_address(encode_hex(result.msg.storage_address))
        self.storage_emulator.set_balance(address, 1)
        return result

    def deploy_transaction(self, input, gas_price=settings.GAS_PRICE, debug=False):
        transaction = input["transaction"]
        from_account = decode_hex(transaction["from"])
        nonce = self.vm.state.get_nonce(from_account)
        try:
            to = decode_hex(transaction["to"])
        except:
            to = transaction["to"]
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=transaction["gaslimit"],
            to=to,
            value=transaction["value"],
            data=decode_hex(transaction["data"]),
        )
        tx = SpoofTransaction(tx, from_=from_account)

        block = input["block"]
        if "timestamp" in block and block["timestamp"] is not None:
            self.vm.state.fuzzed_timestamp = block["timestamp"]
        else:
            self.vm.state.fuzzed_timestamp = None
        if "blocknumber" in block and block["blocknumber"] is not None:
            self.vm.state.fuzzed_blocknumber = block["blocknumber"]
        else:
            self.vm.state.fuzzed_blocknumber = None

        global_state = input["global_state"]
        if "balance" in global_state and global_state["balance"] is not None:
            self.vm.state.fuzzed_balance = global_state["balance"]
        else:
            self.vm.state.fuzzed_balance = None

        if "call_return" in global_state and global_state["call_return"] is not None \
                and len(global_state["call_return"]) > 0:
            self.vm.state.fuzzed_call_return = global_state["call_return"]
        if "extcodesize" in global_state and global_state["extcodesize"] is not None \
                and len(global_state["extcodesize"]) > 0:
            self.vm.state.fuzzed_extcodesize = global_state["extcodesize"]

        environment = input["environment"]
        if "returndatasize" in environment and environment["returndatasize"] is not None:
            self.vm.state.fuzzed_returndatasize = environment["returndatasize"]

        self.storage_emulator.set_balance(from_account, settings.ACCOUNT_BALANCE)
        return self.execute(tx, debug=debug)

    def get_balance(self, address):
        return self.storage_emulator.get_balance(address)

    def static_call(self, sender_str, to_str, data_hex):
        """
        执行一个只读的 'staticcall'，不改变状态，只返回输出结果。
        这对于调用 view/pure 函数 (如 balanceOf, ownerOf) 非常有用。
        """
        try:
            # 1. 将输入的字符串地址和数据，转换为 EVM 需要的字节格式
            sender_canon = to_canonical_address(sender_str)
            to_canon = to_canonical_address(to_str)
            data_bytes = to_bytes(hexstr=data_hex)

            # 2. 获取当前的 gas limit
            #    我们可以使用 settings 中的全局值，或者从 vm 状态中获取
            gas = settings.GAS_LIMIT 
            
            # 3. 使用底层的 vm.state.execute_message 来模拟一个 staticcall
            #    这是 py-evm 库提供的核心功能
            computation = self.vm.state.execute_message(
                origin=sender_canon,
                to=to_canon,
                sender=sender_canon,
                value=0, # staticcall 的 value 永远是 0
                data=data_bytes,
                gas=gas,
                code_address=to_canon,
                is_static=True # !! 关键：将 is_static 设为 True !!
            )

            # 4. 处理执行结果
            if computation.is_error:
                # 如果调用失败 (revert)，就返回 None
                self.logger.debug(f"Static call to {to_str} failed: {computation.error}")
                return None
            
            # 如果成功，返回输出的字节数据
            return computation.output

        except Exception as e:
            self.logger.error(f"An exception occurred during static_call to {to_str}: {e}")
            return None
        
        
    def get_code(self, address):
        return self.storage_emulator.get_code(address)

    def set_code(self, address, code):
        return self.storage_emulator.set_code(address, code)

    def create_snapshot(self):
        self.snapshot = self.storage_emulator.record()
        self.storage_emulator.set_snapshot(self.snapshot)

    def restore_from_snapshot(self):
        self.storage_emulator.discard(self.snapshot)

    def get_accounts(self):
        return [encode_hex(x) for x in self.storage_emulator._raw_store_db.wrapped_db["account"].keys()]

    def set_vm_by_name(self, EVM_VERSION):
        if EVM_VERSION == "homestead":
            self.set_vm(HOMESTEAD_MAINNET_BLOCK)
        elif EVM_VERSION == "byzantium":
            self.set_vm(BYZANTIUM_MAINNET_BLOCK)
        elif EVM_VERSION == "petersburg":
            self.set_vm(PETERSBURG_MAINNET_BLOCK)
        else:
            raise Exception("Unknown EVM version, please choose either 'homestead', 'byzantium' or 'petersburg'.")

    def create_fake_accounts(self):
        self.accounts.append(self.create_fake_account("0xcafebabecafebabecafebabecafebabecafebabe"))
        for address in settings.ATTACKER_ACCOUNTS:
            self.accounts.append(self.create_fake_account(address))
