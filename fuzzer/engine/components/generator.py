#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import collections
from typing import List
from typing import Tuple
from fuzzer.utils import settings
from fuzzer.utils.transaction_seq_utils import gen_trans
from fuzzer.utils.utils import *

KNOWLEDGE_BASE_FILE = "knowledge_base.json"

UINT_MAX = {
    1: int("0xff", 16),
    2: int("0xffff", 16),
    3: int("0xffffff", 16),
    4: int("0xffffffff", 16),
    5: int("0xffffffffff", 16),
    6: int("0xffffffffffff", 16),
    7: int("0xffffffffffffff", 16),
    8: int("0xffffffffffffffff", 16),
    9: int("0xffffffffffffffffff", 16),
    10: int("0xffffffffffffffffffff", 16),
    11: int("0xffffffffffffffffffffff", 16),
    12: int("0xffffffffffffffffffffffff", 16),
    13: int("0xffffffffffffffffffffffffff", 16),
    14: int("0xffffffffffffffffffffffffffff", 16),
    15: int("0xffffffffffffffffffffffffffffff", 16),
    16: int("0xffffffffffffffffffffffffffffffff", 16),
    17: int("0xffffffffffffffffffffffffffffffffff", 16),
    18: int("0xffffffffffffffffffffffffffffffffffff", 16),
    19: int("0xffffffffffffffffffffffffffffffffffffff", 16),
    20: int("0xffffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0xffffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0xffffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0xffffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0xffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0xffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MAX = {
    1: int("0x7f", 16),
    2: int("0x7fff", 16),
    3: int("0x7fffff", 16),
    4: int("0x7fffffff", 16),
    5: int("0x7fffffffff", 16),
    6: int("0x7fffffffffff", 16),
    7: int("0x7fffffffffffff", 16),
    8: int("0x7fffffffffffffff", 16),
    9: int("0x7fffffffffffffffff", 16),
    10: int("0x7fffffffffffffffffff", 16),
    11: int("0x7fffffffffffffffffffff", 16),
    12: int("0x7fffffffffffffffffffffff", 16),
    13: int("0x7fffffffffffffffffffffffff", 16),
    14: int("0x7fffffffffffffffffffffffffff", 16),
    15: int("0x7fffffffffffffffffffffffffffff", 16),
    16: int("0x7fffffffffffffffffffffffffffffff", 16),
    17: int("0x7fffffffffffffffffffffffffffffffff", 16),
    18: int("0x7fffffffffffffffffffffffffffffffffff", 16),
    19: int("0x7fffffffffffffffffffffffffffffffffffff", 16),
    20: int("0x7fffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0x7fffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0x7fffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0x7fffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0x7fffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MIN = {
    1: int("-0x80", 16),
    2: int("-0x8000", 16),
    3: int("-0x800000", 16),
    4: int("-0x80000000", 16),
    5: int("-0x8000000000", 16),
    6: int("-0x800000000000", 16),
    7: int("-0x80000000000000", 16),
    8: int("-0x8000000000000000", 16),
    9: int("-0x800000000000000000", 16),
    10: int("-0x80000000000000000000", 16),
    11: int("-0x8000000000000000000000", 16),
    12: int("-0x800000000000000000000000", 16),
    13: int("-0x80000000000000000000000000", 16),
    14: int("-0x8000000000000000000000000000", 16),
    15: int("-0x800000000000000000000000000000", 16),
    16: int("-0x80000000000000000000000000000000", 16),
    17: int("-0x8000000000000000000000000000000000", 16),
    18: int("-0x800000000000000000000000000000000000", 16),
    19: int("-0x80000000000000000000000000000000000000", 16),
    20: int("-0x8000000000000000000000000000000000000000", 16),
    21: int("-0x800000000000000000000000000000000000000000", 16),
    22: int("-0x80000000000000000000000000000000000000000000", 16),
    23: int("-0x8000000000000000000000000000000000000000000000", 16),
    24: int("-0x800000000000000000000000000000000000000000000000", 16),
    25: int("-0x80000000000000000000000000000000000000000000000000", 16),
    26: int("-0x8000000000000000000000000000000000000000000000000000", 16),
    27: int("-0x800000000000000000000000000000000000000000000000000000", 16),
    28: int("-0x80000000000000000000000000000000000000000000000000000000", 16),
    29: int("-0x8000000000000000000000000000000000000000000000000000000000", 16),
    30: int("-0x800000000000000000000000000000000000000000000000000000000000", 16),
    31: int("-0x80000000000000000000000000000000000000000000000000000000000000", 16),
    32: int("-0x8000000000000000000000000000000000000000000000000000000000000000", 16)
}

MAX_RING_BUFFER_LENGTH = 10
MAX_ARRAY_LENGTH = 2


class CircularSet:
    def __init__(self, set_size=MAX_RING_BUFFER_LENGTH, initial_set=None):
        self._q = collections.deque(maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self):
        return len(self._q) == 0

    def add(self, value):
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self):
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value):
        if value in self._q:
            self._q.remove(value)

    def __repr__(self):
        return repr(self._q)


class Generator:
    """
    测试用例生成器
    里面有一个函数, 能够提供一条事务序列

    """

    def __init__(self, interface, bytecode, accounts, contract, abi, other_generators=None, interface_mapper=None,
                 contract_name=None, sol_path=None,sequence_template=None):
        self.logger = initialize_logger("Generator")
        self.interface = interface
        self.interface_mapper = interface_mapper
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract  # 合约部署的地址
        self.contract_name = contract_name  # 合约名称
        self.abi = abi
        self.sol_path = sol_path  # 合约文件地址, 用于跨合约分析
        self.other_generators = other_generators if other_generators is not None else []  # type:List[Generator]

        # Pools
        self.function_circular_buffer = CircularSet(set_size=len(self.interface), initial_set=set(self.interface))
        self.accounts_pool = {}
        self.amounts_pool = {}
        self.arguments_pool = {}
        self.timestamp_pool = {}
        self.blocknumber_pool = {}
        self.balance_pool = {}
        self.callresult_pool = {}
        self.gaslimit_pool = {}
        self.extcodesize_pool = {}
        self.returndatasize_pool = {}
        self.argument_array_sizes_pool = {}
        self.strings_pool = CircularSet()
        self.bytes_pool = CircularSet()

        # 总体的interface_mapper
        self.total_interface_mapper = {self.contract_name: self.interface_mapper}
        for o_g in self.other_generators:
            self.total_interface_mapper[o_g.contract_name] = o_g.total_interface_mapper[o_g.contract_name]
        
        self.sequence_template = sequence_template
        self.template_index = 0 # 用于追踪剧本的执行位置
        if self.sequence_template:
            print("Generator initialized in template-guided mode.")


        self.logger.info(f"Generator for {self.contract_name} initializing...")
        if os.path.exists(KNOWLEDGE_BASE_FILE):
            self.logger.info(f"Found knowledge base. Pre-seeding parameter pools...")
            try:
                with open(KNOWLEDGE_BASE_FILE, 'r') as f:
                    knowledge_base = json.load(f)
                
                # 只读取属于自己的那一章
                my_chapter = knowledge_base.get(self.contract_name)
                if my_chapter:
                    self.logger.debug(f"Loading chapter '{self.contract_name}'...")
                    for func_hash, params in my_chapter.items():
                        for param_index, values in params.items():
                            for value in values:
                                # 在加载时，对大整数进行必要的类型转换
                                final_value = value
                                try:
                                    # 这是一个简化的假设，更完整的实现会检查类型
                                    final_value = int(value)
                                except (ValueError, TypeError):
                                    pass
                                self.add_argument_to_pool(func_hash, int(param_index), final_value)
                    self.logger.info("Parameter pools successfully pre-seeded.")
            except Exception as e:
                self.logger.error(f"Failed to load knowledge base: {e}")

    def _load_global_seed_pool(self):
        global_pool_path = "global_seed_pool.json"
        if os.path.exists(global_pool_path):
            self.logger.info(f"Loading knowledge from global seed pool: {global_pool_path}")
            try:
                with open(global_pool_path, 'r') as f:
                    global_pool = json.load(f)
                
                # 将加载的种子，注入到自己的参数池中
                # global_pool 的结构: { "function_hash": { "arg_index": [value1, value2] } }
                for func_hash, args_data in global_pool.items():
                    for arg_index, values in args_data.items():
                        for value in values:
                            # 注意：arg_index 需要是整数
                            self.add_argument_to_pool(func_hash, int(arg_index), value)

            except Exception as e:
                self.logger.warning(f"Failed to load global seed pool: {e}")

    def update_other_generators(self, _other_generators, _total_interface_mapper):
        self.other_generators = _other_generators
        self.total_interface_mapper = _total_interface_mapper

    def generate_individual_by_cross(self):
        """
        根据指定的序列, 生成一个含有参数的序列
        """
        individual = []
        for o_g in self.other_generators:
            individual.extend(o_g.generate_constructor())
        real_individual = []
        if self.sol_path is not None:
            target_trans = settings.TRANS_CROSS_BAD_INDVS.pop()
            if len(target_trans[0].chromosome) >= settings.MAX_INDIVIDUAL_LENGTH:
                return target_trans[0].chromosome
            ret = gen_trans(target_trans, self.total_interface_mapper)
            for supply_func in ret:
                if supply_func is None:
                    break
                c_name, f_name = supply_func.split(".")
                if c_name == self.contract_name:
                    function, argument_types = self.get_specific_function_with_argument_types_without_arg_support(
                        f_name)
                    real_individual.extend(self.generate_individual(function, argument_types))
                else:
                    for o_g in self.other_generators:
                        if c_name == o_g.contract_name:
                            function, argument_types = o_g.get_specific_function_with_argument_types_without_arg_support(
                                f_name)
                            real_individual.extend(o_g.generate_individual(function, argument_types))
                            break
        if len(real_individual) == 0:  # 如果没有生成序列, 则随机生成
            individual.extend(self.generate_randon_individual_without_constructor())
        else:
            individual.extend(real_individual)
        return individual

    def generate_constructor(self):
        """
        仅生成构造函数的事务序列
        """
        individual = []
        if "constructor" in self.interface and self.bytecode:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_random_argument(self.interface["constructor"][index], "constructor", index))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })
        return individual

    def generate_individual(self, function, argument_types, default_value=False):
        """
        生成一个含有参数的序列
        """
        individual = []
        arguments = [function]  # 参数的第一个, 一定是这个函数的hash
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        individual.append({
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "call_return": dict(),
            "extcodesize": dict(),
            "returndatasize": dict()
        })

        address, call_return_value = self.get_random_callresult_and_address(function)
        individual[-1]["call_return"] = {address: call_return_value}

        address, extcodesize_value = self.get_random_extcodesize_and_address(function)
        individual[-1]["extcodesize"] = {address: extcodesize_value}

        address, value = self.get_random_returndatasize_and_address(function)
        individual[-1]["returndatasize"] = {address: value}
        return individual

    def generate_randon_individual_without_constructor(self, func_hash=None, func_args_types=None, default_value=False):
        individual = []
        if func_hash is not None and func_args_types is not None:
            individual.extend(self.generate_individual(func_hash, func_args_types, default_value))
            return individual
        else:
            function, argument_types = self.get_random_function_with_argument_types()  # 随机选择一个函数, 并获得他的参数类型
            individual.extend(self.generate_individual(function, argument_types))
            return individual

    def generate_random_individual(self, func_hash=None, func_args_types=None, default_value=False):
        """
        生成一条事务序列
        """
        individual = []  # 一条事务序列, 里面是很多个函数调用

        # 添加主合约的函数调用
        # 首先是构造器
        individual.extend(self.generate_constructor())

        # 随机选择一个函数, 并获得他的参数类型
        individual.extend(
            self.generate_randon_individual_without_constructor(func_hash, func_args_types, default_value))

        return individual

    def generate_random_input(self):
        input = {}

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        input = {
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "returndatasize": dict()
        }

        address, value = self.get_random_returndatasize_and_address(function)
        input["returndatasize"] = {address: value}

        return input

    def get_random_function_with_argument_types(self):
        # if self.sequence_template:
        #     target_sig = self.sequence_template[self.template_index]
        #     self.template_index = (self.template_index + 1) % len(self.sequence_template)
        #     try:
        #         function_hash, argument_types = self.get_specific_function_with_argument_types(target_sig)
        #         self.logger.debug(f"Template step {self.template_index}: Returning function '{target_sig}' ({function_hash})")
        #         print(f"Template step {self.template_index}: Returning function '{target_sig}' ({function_hash})\n\n\n\n")
        #         return function_hash, argument_types
        #     except KeyError:
        #         self.logger.error(f"FATAL: Signature '{target_sig}' from template not found in interface! Exiting.")
        #         sys.exit(1)
        # else:
            # print("Generating with no templates\n\n\n")
            function_hash = self.function_circular_buffer.head_and_rotate()
            if function_hash == "constructor":
                function_hash = self.function_circular_buffer.head_and_rotate()
            return function_hash, self.interface[function_hash]

    def get_specific_function_with_argument_types(self, function_signature):
        return self.interface_mapper[function_signature], self.interface[self.interface_mapper[function_signature]]

    def get_specific_function_with_argument_types_without_arg_support(self, function_name):
        for f_name_args, f_sign in self.interface_mapper.items():
            if f_name_args.startswith(function_name):
                return self.get_specific_function_with_argument_types(f_name_args)

    #
    # TIMESTAMP
    #

    def add_timestamp_to_pool(self, function, timestamp):
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function):
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function, timestamp):
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    #
    # BLOCKNUMBER
    #

    def add_blocknumber_to_pool(self, function, blocknumber):
        if not function in self.blocknumber_pool:
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function):
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function, blocknumber):
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    #
    # BALANCE
    #

    def add_balance_to_pool(self, function, balance):
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function):
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    #
    # CALL RESULT
    #

    def add_callresult_to_pool(self, function, address, result):
        if not function in self.callresult_pool:
            self.callresult_pool[function] = dict()
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function):
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function, address):
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function, address, result):
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    #
    # EXTCODESIZE
    #

    def add_extcodesize_to_pool(self, function, address, size):
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = dict()
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function):
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function, address):
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function, address, size):
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    #
    # RETURNDATASIZE
    #

    def add_returndatasize_to_pool(self, function, address, size):
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = dict()
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function):  # 这是在模拟return data size?
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function, address):
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function, address, size):
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    #
    # GASLIMIT
    #

    def add_gaslimit_to_pool(self, function, gaslimit):
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function, gaslimit):
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function):
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function):
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return settings.GAS_LIMIT

    #
    # ACCOUNTS
    #

    def add_account_to_pool(self, function, account):
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function, account):
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function):
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function):
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function):
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    #
    # AMOUNTS
    #

    def add_amount_to_pool(self, function, amount):
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function, amount):
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function):
        return self.amounts_pool[function].head_and_rotate()

    # def get_random_amount(self, function):
    #     if function in self.amounts_pool:
    #         amount = self.get_random_amount_from_pool(function)
    #     else:
    #         # # 原版get_random_amount
    #         amount = random.randint(0,1)
    #         self.add_amount_to_pool(function, amount)
    #         self.add_amount_to_pool(function, 1 - amount)
    #         # 为了覆盖ether级别金钱的情况, 上述情况最大为1wei
    #         # if random.choice([True, True, False]):
    #         #     for level, multiply in [("Ether", 10 ** 18), ("Wei", 1)]:
    #         #         MAX_AMOUNT = 10 * multiply
    #         #         amount = random.randint(0, MAX_AMOUNT)
    #         #         self.add_amount_to_pool(function, amount)
    #     return amount

    def get_random_amount(self, function):
        if function in self.amounts_pool and not self.amounts_pool[function].empty:
            return self.amounts_pool[function].head_and_rotate()
        
        common_values = [
            0,                          # 最常见的非 payable 调用
            1,                          # 最小的非零值
        ]
        
        ether_values = [
            10**18,                     # 1 Ether
            10**17,                     # 0.1 Ether
            5 * 10**17,                 # 0.5 Ether
            Web3.toWei(1.1, 'ether'),   # 刚好大于 1 Ether
            Web3.toWei(0.9, 'ether'),   # 刚好小于 1 Ether
        ]
        
        if hasattr(settings, 'ACCOUNT_BALANCE'):
            high_values = [
                settings.ACCOUNT_BALANCE // 100, # 初始余额的 1%
                settings.ACCOUNT_BALANCE // 10,  # 初始余额的 10%
                settings.ACCOUNT_BALANCE // 2,   # 初始余额的一半
                settings.ACCOUNT_BALANCE,        # 全部余额
                settings.ACCOUNT_BALANCE + 1,    # 刚好超过余额
            ]
            common_values.extend(high_values)

        common_values.extend(ether_values)
        amount = random.choice(common_values)
        if function not in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        
        self.amounts_pool[function].add(amount)
        if amount > 0:
            self.amounts_pool[function].add(amount - 1)
        self.amounts_pool[function].add(amount + 1)
            
        return amount

    #
    # STRINGS
    #

    def add_string_to_pool(self, string):
        self.strings_pool.add(string)

    def get_random_string_from_pool(self):
        return self.strings_pool.head_and_rotate()

    #
    # BYTES
    #

    def add_bytes_to_pool(self, string):
        self.bytes_pool.add(string)

    def get_random_bytes_from_pool(self):
        return self.bytes_pool.head_and_rotate()

    #
    # FUNCTION ARGUMENTS
    #

    def add_parameter_array_size(self, function, parameter_index, array_size):
        if function not in self.argument_array_sizes_pool:
            self.argument_array_sizes_pool[function] = dict()
        if parameter_index not in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index] = CircularSet()
        self.argument_array_sizes_pool[function][parameter_index].add(min(array_size, MAX_ARRAY_LENGTH))

    def _get_parameter_array_size_from_pool(self, function, argument_index):
        return self.argument_array_sizes_pool[function][argument_index].head_and_rotate()

    def remove_parameter_array_size_from_pool(self, function, parameter_index, array_size):
        if function in self.argument_array_sizes_pool and parameter_index in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index].discard(array_size)
            if self.argument_array_sizes_pool[function][parameter_index].empty:
                del self.argument_array_sizes_pool[function][parameter_index]
                if len(self.argument_array_sizes_pool[function]) == 0:
                    del self.argument_array_sizes_pool[function]

    def add_argument_to_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.add_argument_to_pool(function, argument_index, element)
            return
        if function not in self.arguments_pool:
            self.arguments_pool[function] = {}
        if argument_index not in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index] = CircularSet()
        self.arguments_pool[function][argument_index].add(argument)

    def remove_argument_from_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.remove_argument_from_pool(function, argument_index, element)
            return
        if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index].discard(argument)
            if self.arguments_pool[function][argument_index].empty:
                del self.arguments_pool[function][argument_index]
                if len(self.arguments_pool[function]) == 0:
                    del self.arguments_pool[function]

    def _get_random_argument_from_pool(self, function, argument_index):
        print(f"function: {function}, argument_index: {self.arguments_pool[function][argument_index].head_and_rotate()}")
        return self.arguments_pool[function][argument_index].head_and_rotate()


    
    def _is_type_compatible(required_type, provided_type):
    # 简化的兼容性检查
        if required_type == provided_type:
            return True
        # 允许将一个更“大”的类型的值，用于一个更“小”的类型（需要范围检查）
        if required_type.startswith('uint') and provided_type.startswith('uint'):
            return True # 暂时允许所有 uint 互通，在后面进行范围检查
        # ...
        return False

    def get_random_argument(self, type, function, argument_index):
        true_type = type
        max_value = None
        min_value = None
        is_integer = False
        # print(f"function: {function}, argument_index: {argument_index}, type: {type}")
        try:
            # 1. 在 ABI 中找到对应的函数定义
            function_abi = next((item for item in self.abi if item.get('type') == 'function' and self.interface_mapper.get(item['name']+'(...)') == function), None)
            
            # 一个更简单的查找方式
            func_sig = self.interface_mapper.get(function)
            if func_sig:
                # signature 是 "myFunc(uint128,address)"
                # 我们需要找到 ABI 中 name 是 "myFunc" 的条目
                func_name = func_sig.split('(')[0]
                function_abi = next((item for item in self.abi if item.get('type') == 'function' and item.get('name') == func_name), None)
                
                if function_abi and 'inputs' in function_abi and len(function_abi['inputs']) > argument_index:
                    # 2. 从 ABI 中，获取这个参数的、100%正确的真实类型！
                    true_type = function_abi['inputs'][argument_index]['type']
                    if true_type != type_from_interface:
                        self.logger.debug(f"Type mismatch detected for {func_sig} arg {argument_index}. "
                                          f"Interface said '{type_from_interface}', but ABI says '{true_type}'. Using ABI.")
        except Exception as e:
            self.logger.warning(f"Could not get true type from ABI for {function_hash}, falling back. Error: {e}")
        
        type = true_type

        if function in self.arguments_pool and argument_index in self.arguments_pool[function] and \
           not self.arguments_pool[function][argument_index].empty: # 确保池子不为空
            
            # ===================================================================
            # !! 核心修改：使用 .head_and_rotate() 来安全地取值 
            # ===================================================================
            
            # a. 先从池子里取出一个值
            #    .head_and_rotate() 会返回一个值，并将指针移到下一个
            #    这自带了我们想要的“多样性”，不再需要 shuffle
            value_from_pool = self._get_random_argument_from_pool(function, argument_index)
            
            # b. !! 安全阀：对取出的值进行类型和范围检查 !!
            #    (这部分逻辑与我们之前的最终版本完全相同)
            if isinstance(value_from_pool, dict) and 'type' in value_from_pool:
                # 这是我们带标签的“知识”
                knowledge_type = value_from_pool['type']
                knowledge_value = value_from_pool['value']
                
                if _is_type_compatible(type, knowledge_type):
                    if type.startswith('uint'):
                        try:
                            bits = int(type.replace("uint", "").split("[")[0] or 256)
                            max_value = (2 ** bits) - 1
                            if 0 <= int(knowledge_value) <= max_value:
                                return int(knowledge_value)
                        except: pass
                    else:
                        return knowledge_value
            else:
                # (这里可以处理来自旧版 CrossFuzz 的、不带标签的值)
                pass


        # Boolean
        if type.startswith("bool"):
            # Array
            if "[" in type and "]" in type:  # 如果是数组
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        if self._get_random_argument_from_pool(function, argument_index) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                    else:
                        if random.randint(0, 1) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                if len(sizes) > 1:  # 啥意思, 多维数组?
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    if self._get_random_argument_from_pool(function, argument_index) == 0:
                        return False
                    return True
                else:
                    if random.randint(0, 1) == 0:
                        return False
                    return True

        # Unsigned integer
        elif type.startswith("uint"):
            # print(f"type: {type}")
            # 1. 精确地提取位数
            # 1. 使用正则表达式，精确地提取位数
            match = re.search(r'\d+', type)
            bits = int(match.group(0)) if match else 256
            
            if bits % 8 != 0 or bits > 256 or bits == 0: # 基本的健全性检查
                self.logger.warning(f"Invalid bit size '{bits}' in type '{type}'. Defaulting to 256.")
                bits = 256

            # print(f"bits: {bits}")

            # 2. 获取正确的最大/最小值
            max_value = (2 ** bits) - 1
            min_value = 0
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        # 4. 使用正确的最大值来生成随机数！
                        array.append(self.get_random_unsigned_integer(0, max_value))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value 
            else:
                value_from_pool = None
                # a. 优先尝试从池中取值
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    value_from_pool = self._get_random_argument_from_pool(function, argument_index)

                # b. !! 安全阀：检查池中取出的值是否合法 !!
                if value_from_pool is not None:
                    try:
                        # 尝试将其转换为整数，并检查范围
                        int_value = int(value_from_pool)
                        if 0 <= int_value <= max_value:
                            # 如果合法，就使用它
                            return int_value
                        else:
                            # 如果不合法，就打印警告并抛弃它
                            self.logger.warning(f"Value '{int_value}' from pool is out of range for type '{type}'. Discarding.")
                    except (ValueError, TypeError):
                        self.logger.warning(f"Value '{value_from_pool}' from pool is not a valid int for type '{type}'. Discarding.")
                
                # c. 如果池中没有值，或者值不合法，才进行随机生成
                return self.get_random_unsigned_integer(0, max_value)

        # Signed integer
        elif type.startswith("int"):
            try:
                bits_str = type.replace("int", "").split("[")[0]
                bits = int(bits_str) if bits_str else 256
                bytes_len = bits // 8
            except (ValueError, IndexError):
                bytes_len = 32
            bytes = int(int(type.replace("int", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])  # 生成有符号整型

        # Address
        elif type.startswith("address"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(random.choice(self.accounts))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return random.choice(self.accounts)  # 从账号库中, 随机挑选一个

        # String
        elif type.startswith("string"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))  # 随机生成长度为0的字符串, 添加到pool中
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()  # 从pool中随机挑选一个字符串

        # Bytes1 ... Bytes32
        elif type.startswith("bytes1") or \
                type.startswith("bytes2") or \
                type.startswith("bytes3") or \
                type.startswith("bytes4") or \
                type.startswith("bytes5") or \
                type.startswith("bytes6") or \
                type.startswith("bytes7") or \
                type.startswith("bytes8") or \
                type.startswith("bytes9") or \
                type.startswith("bytes10") or \
                type.startswith("bytes11") or \
                type.startswith("bytes12") or \
                type.startswith("bytes13") or \
                type.startswith("bytes14") or \
                type.startswith("bytes15") or \
                type.startswith("bytes16") or \
                type.startswith("bytes17") or \
                type.startswith("bytes18") or \
                type.startswith("bytes19") or \
                type.startswith("bytes20") or \
                type.startswith("bytes21") or \
                type.startswith("bytes22") or \
                type.startswith("bytes23") or \
                type.startswith("bytes24") or \
                type.startswith("bytes25") or \
                type.startswith("bytes26") or \
                type.startswith("bytes27") or \
                type.startswith("bytes28") or \
                type.startswith("bytes29") or \
                type.startswith("bytes30") or \
                type.startswith("bytes31") or \
                type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith("bytes"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()

        # Unknown type
        else:
            self.logger.error("Unsupported type: " + str(type))  # 不支持其他类型

    def _get_array_sizes(self, argument_index, function, type):
        sizes = []
        for size in re.compile(r"\[(.*?)\]").findall(type):
            # Dynamic array
            if size == "":
                if function in self.argument_array_sizes_pool \
                        and argument_index in self.argument_array_sizes_pool[function]:
                    sizes.append(self._get_parameter_array_size_from_pool(function, argument_index))
                else:
                    sizes.append(random.randint(0, MAX_ARRAY_LENGTH))
            # Fixed size array
            else:
                sizes.append(int(size))
        return sizes

    @staticmethod
    def get_random_unsigned_integer(min, max):
        # seed = int(random.uniform(-2, 2))
        # if seed == -1:
        #     return random.choice([min, min + 1, min + 2])
        # elif seed == 1:
        #     return random.choice([max, max - 1, max - 2])
        # else:
        #     return random.randint(min, max)

        # 1. 决定生成策略 (80%小数字, 15%边界值, 5%纯随机)
        strategy = random.choices(
            ['small_number', 'boundary_value', 'full_random'], 
            weights=[100, 0, 0], 
            k=1
        )[0]

        # print(f"strategy: {strategy}")

        # 2. 根据策略生成值
        if strategy == 'small_number':
            # 在一个“合理”的上限内生成一个数。
            # 我们可以假设大多数代币操作不会超过 1,000,000 * 10**18
            reasonable_max = 10
            # reasonable_max = 10**6 * 10**18 
            # 确保我们的上限不超过该类型的最大值
            if max > reasonable_max:
                effective_max = reasonable_max
            else:
                effective_max = max
            return random.randint(min, effective_max)

        elif strategy == 'boundary_value':
            # 返回一些经典的、有测试价值的边界值
            boundary_values = {min, min + 1, max, max - 1}
            # 过滤掉超出范围的值
            valid_boundaries = [v for v in boundary_values if min <= v <= max]
            return random.choice(valid_boundaries)

        else: # full_random
            # 保留原始的、完全随机的探索能力
            return random.randint(min, max)

    @staticmethod
    def get_random_signed_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, min, min + 1])
        elif seed == 1:
            return random.choice([0, 1, max, max - 1])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_string(length):  # 随机生成一个指定长度的字符串
        return ''.join('A' for _ in range(length))

    @staticmethod
    def get_random_bytes(length):
        """
        随机获得length长度的字节序列
        """
        return bytearray(random.getrandbits(8) for _ in range(length))

    def generate_individual_from_template(self, sequence_template):
        """
        根据一个函数签名模板，精确地构建一个完整的、带随机参数的 chromosome。
        """
        self.logger.info(f"Generating individual from template...")
        new_chromosome = []
        
        # sequence_template 现在是一个对象列表
        for task in sequence_template:
            # ===================================================================
            # !! 核心修改：从 task 字典中，提取出 'signature' 字符串 !!
            # ===================================================================
            func_sig = task['signature'] # <-- 我们需要的是这个字符串！
            
            try:
                # 1. 使用已有的辅助函数，并传入正确的字符串签名
                func_hash, arg_types = self.get_specific_function_with_argument_types(func_sig)
                
                # 2. 调用底层的 "gene" 锻造函数
                gene_list = self.generate_individual(func_hash, arg_types)
                if gene_list:
                    # 3. 将锻造出的“基因”添加到我们的新 chromosome 中
                    new_chromosome.extend(gene_list)
            except KeyError:
                self.logger.warning(f"Signature '{func_sig}' from template not found in interface. Skipping.")
            except Exception as e:
                self.logger.error(f"Error generating gene for template task '{task}': {e}")
                
        return new_chromosome