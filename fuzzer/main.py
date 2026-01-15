#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
from datetime import datetime

import solcx
import random
import argparse
from eth.vm.spoof import SpoofTransaction
from z3 import Solver
from eth_utils import to_canonical_address, decode_hex, encode_hex, to_bytes

from evm import InstrumentedEVM
from detectors import DetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Individual, Population
from engine.analysis import SymbolicTaintAnalyzer
from engine.analysis import ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function
from fuzzer.utils.transaction_seq_utils import check_cross_init, gen_trans, init_func
from web3 import Web3

# 获取根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 将根目录添加到path中
sys.path.append(BASE_DIR)
from fuzzer.utils import settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_pcs_and_jumpis, \
    get_function_signature_mapping
from utils.control_flow_graph import ControlFlowGraph
from eth_abi import encode_abi
from crytic_compile import CryticCompile
from utils.source_map import SourceMap

def create_population_from_template(template_path, main_generator, other_generators, population_size, logger):
    """
    根据模板文件，预先构建好一个完整的 Individual 列表
    """
    logger.info(f"Creating population from template: {template_path}")
    
    with open(template_path, 'r') as f:
        sequence_template = json.load(f)

    # a. 创建一个从“合约名 -> Generator对象”的快速查找字典
    generator_map = {main_generator.contract_name: main_generator}
    for g in other_generators:
        generator_map[g.contract_name] = g
    logger.debug(f"Generator map created with keys: {list(generator_map.keys())}")

    individuals_list = []
    # b. 循环创建每一个 Individual
    for _ in range(population_size):
        new_indv = Individual(generator=main_generator, other_generators=other_generators)
        new_chromosome = []
        
        # c. 遍历模板中的每一个“任务”，为 Individual 构建 chromosome
        for task in sequence_template:
            target_contract_name = task.get('contract')
            func_sig = task.get('signature')

            if not target_contract_name or not func_sig: continue

            target_generator = generator_map.get(target_contract_name)
            if not target_generator:
                logger.warning(f"Could not find generator for '{target_contract_name}'. Skipping.")
                continue
            
            try:
                func_hash, arg_types = target_generator.get_specific_function_with_argument_types(func_sig)
                gene_list = target_generator.generate_individual(func_hash, arg_types)
                if gene_list: new_chromosome.extend(gene_list)
            except KeyError:
                logger.warning(f"Sig '{func_sig}' not found in '{target_contract_name}' generator. Skipping.")
            except Exception as e:
                logger.error(f"Error generating gene for task '{task}': {e}")
        
        new_indv.init(chromosome=new_chromosome)
        individuals_list.append(new_indv)
    
    return individuals_list

class Fuzzer:
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm,
                 blockchain_state, solver, args, seed, source_map=None, whole_compile_info=None):
        global logger

        logger = initialize_logger("Fuzzer  ")
        logger.title("Fuzzing contract %s", contract_name)

        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        function_map = get_function_signature_mapping(abi) #modify
        function_map_reversed = {h: sig for sig, h in function_map.items()} #modify
        self.contract_name = contract_name
        self.interface, self.interface_mapper = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args
        # 该合约依赖的其他合约
        self.depend_contracts = args.depend_contracts if args.depend_contracts is not None else []
        print(f"Received depend_contracts in order: {self.depend_contracts}")

        self.full_constructor_config = {}
        if args.full_constructor_config and os.path.exists(args.full_constructor_config):
            with open(args.full_constructor_config, 'r') as f: self.full_constructor_config = json.load(f)





        self.whole_compile_info = whole_compile_info

        # Get some overall metric on the code
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)

        # Initialize results
        self.results = {"errors": {}}

        # Initialize fuzzing environment
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=DetectorExecutor(source_map,
                                                                         get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts=list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi,
                                      function_map=function_map,
                                      function_map_reversed=function_map_reversed) #modify
        init_func(args.source)  # 初始化分析跨合约序列
        assert check_cross_init(), "跨合约初始化失败"  # 检查是否初始化成功
        print("跨合约初始化成功......")

    # def deploy_depend_contracts(self):
    #     generators = []
    #     if self.whole_compile_info is None:
    #         logger.error("没有找到编译信息, 退出程序!")
    #         sys.exit(-1)
    #     for depend_contract in self.depend_contracts:
    #         # 得到这个合约的interface
    #         interface, interface_mapper = get_interface_from_abi(self.whole_compile_info[depend_contract]['abi'])
    #         deployement_bytecode = self.whole_compile_info[depend_contract]['evm']['bytecode']['object']
    #         if "constructor" in interface:
    #             del interface['constructor']
    #         if "constructor" not in interface:
    #             result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],
    #                                                            deployement_bytecode)  # 将依赖合约部署
    #             if result.is_error:
    #                 logger.error("Problem while deploying contract %s using account %s. Error message: %s",
    #                              depend_contract, self.instrumented_evm.accounts[0], result._error)
    #                 # 这里原本是退出程序, 但依赖合约部署失败可以不退出, 不影响主程序的大部分fuzz
    #             else:
    #                 contract_address = encode_hex(result.msg.storage_address)
    #                 self.instrumented_evm.accounts.append(contract_address)
    #                 self.env.nr_of_transactions += 1
    #                 logger.info(
    #                     f"依赖合约 {depend_contract} deployed at\t%s, 由{self.instrumented_evm.accounts[0]}创建",
    #                     contract_address)
    #                 # 存储部署信息
    #                 settings.TRANS_INFO[depend_contract] = contract_address
    #                 settings.DEPLOYED_CONTRACT_ADDRESS[depend_contract] = contract_address
    #                 generator = Generator(interface=interface, bytecode=deployement_bytecode,
    #                                       accounts=self.instrumented_evm.accounts, contract=contract_address,
    #                                       interface_mapper=interface_mapper, contract_name=depend_contract,
    #                                       sol_path=self.args.source)
    #                 generators.append(generator)
    #     return generators


    def deploy_depend_contracts(self):
        generators = []
        if self.whole_compile_info is None:
            logger.error("没有找到编译信息, 退出程序!")
            sys.exit(-1)
            
        # for depend_contract in self.depend_contracts:
        #     abi = self.whole_compile_info[depend_contract]['abi']
        #     interface, interface_mapper = get_interface_from_abi(abi)
        #     bytecode_base = self.whole_compile_info[depend_contract]['evm']['bytecode']['object']
        #     final_bytecode = bytecode_base
            
        #     if depend_contract in self.full_constructor_config and 'args' in self.full_constructor_config[depend_contract]:
        #         constructor_config = self.full_constructor_config[depend_contract]['args']
        #         if constructor_config:
        #             logger.info(f"为依赖合约 {depend_contract} 从配置文件加载并编码参数...")
        #             try:
        #                 arg_types = []
        #                 arg_values = []
                        
        #                 for arg in constructor_config:
        #                     arg_type = arg['type']
        #                     arg_value_template = arg['value']
                            
        #                     final_type = 'address' if arg_type == 'contract' else arg_type
        #                     arg_types.append(final_type)
                            
        #                     final_value = None
        #                     if arg_type == 'contract':
        #                         # 1. 查找地址
        #                         raw_address = settings.DEPLOYED_CONTRACT_ADDRESS.get(str(arg_value_template))
        #                         if not raw_address:
        #                             raise ValueError(f"Could not find deployed address for contract '{arg_value_template}'")
        #                         # 2. 进行校验和编码！
        #                         final_value = Web3.toChecksumAddress(raw_address)
        #                     elif 'uint' in arg_type or 'int' in arg_type:
        #                         final_value = int(arg_value_template)
        #                     elif 'bool' in arg_type:
        #                         final_value = str(arg_value_template).lower() in ['true', '1']
        #                     else:
        #                         final_value = arg_value_template # string, bytes, etc.
                            
        #                     arg_values.append(final_value)

        #                 logger.debug(f"  -> Final types for encoding: {arg_types}")
        #                 logger.debug(f"  -> Final values for encoding: {arg_values}")

        #                 encoded_arguments = encode_abi(arg_types, arg_values)
        #                 final_bytecode += encoded_arguments.hex()
        #                 logger.debug(f"  -> Successfully encoded arguments.")

        #             except Exception as e:
        #                 logger.error(f"为 {depend_contract} 编码构造函数参数时出错: {e}")
        #                 sys.exit(f"无法为 {depend_contract} 编码构造函数参数。")
            
        #     result = self.instrumented_evm.deploy_contract(
        #         self.instrumented_evm.accounts[0],
        #         final_bytecode,
        #         deploy_args=[]
        #     )
        for depend_contract in self.depend_contracts:
            abi = self.whole_compile_info[depend_contract]['abi']
            interface, interface_mapper = get_interface_from_abi(abi)
            bytecode_base = self.whole_compile_info[depend_contract]['evm']['bytecode']['object']
            final_bytecode = bytecode_base
            
            if depend_contract in self.full_constructor_config and 'args' in self.full_constructor_config[depend_contract]:
                constructor_config = self.full_constructor_config[depend_contract]['args']
                if constructor_config:
                    logger.info(f"为依赖合约 {depend_contract} 从配置文件加载、转换并编码参数...")
                    try:
                        arg_types = [arg['type'] for arg in constructor_config]
                        arg_values = []
                        

                        for arg in constructor_config:
                            arg_type = arg['type']
                            arg_value_from_json = arg['value'] # 这是从 JSON 读出的原始值

                            if arg_type == 'contract':
                                # 1. 翻译类型
                                arg_types.append('address') # 翻译回 ABI 认识的类型
                                
                                # 2. 翻译值
                                deployed_address = settings.DEPLOYED_CONTRACT_ADDRESS.get(str(arg_value_from_json))
                                if not deployed_address:
                                    raise ValueError(f"Could not find deployed address for contract '{arg_value_from_json}' needed by '{depend_contract}'")
                                print(f"  -> Resolved dependency '{arg_value_from_json}' to address {deployed_address}")
                                arg_values.append(deployed_address)

                            # if isinstance(arg_value_from_json, str) and arg_value_from_json in settings.DEPLOYED_CONTRACT_ADDRESS:
                            #     # 如果是，就用它已部署的真实地址来替换
                            #     final_value = settings.DEPLOYED_CONTRACT_ADDRESS[arg_value_from_json]
                            #     print(f"  -> Replacing placeholder '{arg_value_from_json}' with deployed address {final_value}")
                            # else:
                            #     final_value = arg_value_from_json

                            if 'bytes' in arg_type:
                                # 对于所有 bytesN 类型，都将十六进制字符串转换为字节对象
                                arg_values.append(to_bytes(hexstr=arg_value_from_json))
                            elif 'uint' in arg_type or 'int' in arg_type:
                                # 对于所有整数类型，都转换为 Python int
                                arg_values.append(int(arg_value_from_json))
                            elif 'bool' in arg_type:
                                # 对于布尔类型，进行转换
                                arg_values.append(str(arg_value_from_json).lower() in ['true', '1'])
                            elif 'address' in arg_type:
                                # 地址类型在 eth_abi 中可以直接接收十六进制字符串，无需转换
                                arg_values.append(arg_value_from_json)
                            else:
                                # 其他类型（如 string）直接使用
                                arg_values.append(arg_value_from_json)
                        
                        logger.debug(f"  -> Types for encoding: {arg_types}")
                        logger.debug(f"  -> Values for encoding (with correct Python types): {arg_values}")

                        encoded_arguments = encode_abi(arg_types, arg_values)
                        final_bytecode += encoded_arguments.hex()
                        logger.debug(f"  -> Successfully encoded arguments.")

                    except Exception as e:
                        logger.error(f"为 {depend_contract} 编码构造函数参数时出错: {e}")
                        sys.exit(f"无法为 {depend_contract} 编码构造函数参数。")
            
            # 使用我们最终构建的、包含了参数的完整字节码进行部署
            result = self.instrumented_evm.deploy_contract(
                self.instrumented_evm.accounts[0],
                final_bytecode,
                deploy_args=[] # !! 明确传递一个空的 deploy_args，避免任何干扰 !!
            )

            if result.is_error:
                logger.error("部署依赖合约 %s 失败。错误信息: %s", depend_contract, result._error)
                sys.exit(f"无法部署依赖合约 {depend_contract}，Fuzzing 终止。")
            else:
                if "constructor" in interface: del interface['constructor']
                contract_address = encode_hex(result.msg.storage_address)
                self.instrumented_evm.accounts.append(contract_address)
                logger.info(f"依赖合约 {depend_contract} 部署成功于: %s", contract_address)
                settings.TRANS_INFO[depend_contract] = contract_address
                settings.DEPLOYED_CONTRACT_ADDRESS[depend_contract] = contract_address
                generator = Generator(interface=interface, bytecode=bytecode_base,
                                      accounts=self.instrumented_evm.accounts, contract=contract_address,
                                      interface_mapper=interface_mapper, contract_name=depend_contract,
                                      sol_path=self.args.source,abi=abi)
                generators.append(generator)
                
        return generators
    



    def run(self):
        print("Starting Fuzzer")
        contract_address = None
        self.instrumented_evm.create_fake_accounts()
        if self.args.cross_contract == 1:  # 若开启了跨合约模式
            generators = self.deploy_depend_contracts()  # 先部署依赖合约
        else:
            generators = []
        if self.args.source:
            for transaction in self.blockchain_state:  # 如果块内有初始事务, 执行他们
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(
                        self.instrumented_evm.create_fake_account(transaction['from']))

                if not transaction['to']:
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'],
                                                                   int(transaction['value']), int(transaction['gas']),
                                                                   int(transaction['gasPrice']))
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                     self.contract_name, transaction['from'], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        cc, _ = get_pcs_and_jumpis(
                            self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    input = {}
                    input["block"] = {}
                    input["transaction"] = {
                        "from": transaction["from"],
                        "to": transaction["to"],
                        "gaslimit": int(transaction["gas"]),
                        "value": int(transaction["value"]),
                        "data": transaction["input"]
                    }
                    input["global_state"] = {}
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))

            if "constructor" in self.interface:
                del self.interface["constructor"]

            if not contract_address:
                if "constructor" not in self.interface:
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],
                                                                   self.deployement_bytecode,
                                                                   deploy_args=self.args.constructor_args,
                                                                   deploy_mode=settings.CROSS_INIT_MODE)
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s",
                                     self.contract_name, self.instrumented_evm.accounts[0], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.info("主Contract deployed at %s", contract_address)
                        # 将合约的部署情况存储起来
                        settings.TRANS_INFO[self.contract_name] = contract_address
                        settings.DEPLOYED_CONTRACT_ADDRESS[self.contract_name] = contract_address

            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(
                self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        if self.args.abi:
            contract_address = self.args.contract

        sequence_template = None
        # print(f"Loading contract and creating bytecode:{self.sequence_template}\n\n\n")
        if self.args.sequence_template and os.path.exists(self.args.sequence_template):
            logger.info(f"Loading sequence template from {self.args.sequence_template}")
            with open(self.args.sequence_template, 'r') as f:
                sequence_template = json.load(f)



        logger.info("--- Performing Automated Initial Airdrop ---")
        
        # 1. 找到合约的 owner (通常是部署者)
        #    我们假设 owner 是账户列表中的第一个非合约地址
        owner_account = self.instrumented_evm.accounts[0]

        # 2. 遍历所有已部署的合约
        for contract_name, contract_address in settings.DEPLOYED_CONTRACT_ADDRESS.items():
            # a. 找到这个合约的 ABI
            abi = self.whole_compile_info.get(contract_name, {}).get('abi')
            if not abi: continue
            
            # b. 检查它是否有一个典型的 mint 函数
            #    这是一个简化的启发式，你可以根据需要扩展它
            mint_function = next((f for f in abi if f.get('name', '').lower() == 'mint' and f.get('type') == 'function'), None)
            
            if mint_function:
                logger.info(f"Found mint function in {contract_name}. Attempting airdrop...")
                # 1. 准备工作，在循环外进行
                owner_account = self.instrumented_evm.accounts[0] # 假设 owner 是第一个
                if len(self.instrumented_evm.accounts) > 2:
                    targets = self.instrumented_evm.accounts[0:3] # 给前三个人空投
                else:
                    targets = self.instrumented_evm.accounts

                # 2. 开始一个“坚韧不拔”的循环
                for target_account in targets:
                    # a. 每一个账户的空投，都是一个独立的、受保护的操作
                    try:
                        print(f"[*] Attempting to airdrop {contract_name} tokens to {target_account}...")
                        
                        # b. 构建 mint 交易的参数
                        mint_amount = 1000 * (10**18)
                        # (这里需要一个智能的方法来获取正确的 mint 签名)
                        # 为了演示，我们硬编码一个常见的
                        mint_selector = "0x40c10f19" # mint(address,uint256)
                        encoded_args = encode_abi(['address', 'uint256'], [target_account, mint_amount]).hex()
                        tx_data = mint_selector + encoded_args

                        # c. 以 owner 的身份，执行 mint 交易
                        sender_addr_canon = to_canonical_address(owner_account)
                        nonce = self.instrumented_evm.vm.state.get_nonce(sender_addr_canon)
                        tx = self.instrumented_evm.vm.create_unsigned_transaction(
                            nonce=nonce, gas_price=0, gas=settings.GAS_LIMIT,
                            to=to_canonical_address(contract_address), value=0,
                            data=decode_hex(tx_data)
                        )
                        spoofed_tx = SpoofTransaction(tx, from_=sender_addr_canon)
                        result, _ = self.instrumented_evm.vm.state.apply_transaction(spoofed_tx)
                        
                        if not result.is_error:
                            logger.info(f"  -> SUCCESS: Airdropped {mint_amount} {contract_name} tokens to {target_account}")
                        else:
                            # 即使交易失败，也不会崩溃
                            logger.warning(f"  -> FAILED: Airdrop tx for {target_account} reverted with: {result._error}")

                    except Exception as e:
                        # d. 如果在为某个特定账户空投时发生任何意外（比如 Python 异常），
                        #    只会打印错误，然后循环会继续到下一个账户！
                        logger.error(f"  -> CRITICAL FAILURE during airdrop for {target_account}: {e}")
                        # 使用 continue 明确地进入下一次循环
                        continue

        self.instrumented_evm.create_snapshot()  # 部署所有合约后, 创建快照

        generator = Generator(interface=self.interface,
                              bytecode=self.deployement_bytecode,
                              accounts=self.instrumented_evm.accounts,
                              contract=contract_address,
                              abi = self.env.abi,
                              other_generators=generators,
                              interface_mapper=self.interface_mapper,
                              contract_name=self.contract_name,
                              sol_path=self.args.source,
                              sequence_template=sequence_template)

        # update the generator with the interface of the other contracts
        all_generators = [generator] + generators
        for gen in generators:
            gen.update_other_generators(all_generators, generator.total_interface_mapper)

        # Create initial population
        # size = 2 * len(self.interface)
        # population = Population(indv_template=Individual(generator=generator, other_generators=generators),
        #                         indv_generator=generator,
        #                         size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size,
        #                         other_generators=generators).init(init_seed=False)
        

        size = settings.POPULATION_SIZE if settings.POPULATION_SIZE else 2 * len(self.interface)
        population = Population(
            indv_template=Individual(generator=generator, other_generators=generators),
            indv_generator=generator,
            size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else 2 * len(self.interface),
            other_generators=generators
        )
        
        
        template_filepath = self.args.sequence_template
        if template_filepath and os.path.exists(template_filepath):
            with open(template_filepath, 'r') as f:
                sequence_template = json.load(f)
            # 调用我们新的、类型安全的方法
            population.init_from_template(sequence_template)
        else:
            # 如果没有模板，则使用原始的随机初始化
            logger.info("No sequence template found. Using default random initialization.")
            population.init(init_seed=False)

        # Create genetic operators
        if self.args.data_dependency:
            selection = DataDependencyLinearRankingSelection(env=self.env)  # 基于Read After Write关系的种子选择
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)  # 基于数据流的交叉策略
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        else:
            selection = LinearRankingSelection()
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        # print("Create genetic operators")

        # Create and run our evolutionary fuzzing engine
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover,
                                           mutation=mutation,
                                           mapping=get_function_signature_mapping(self.env.abi))
        engine.fitness_register(lambda x: fitness_function(x, self.env))  # 计算x的适应度, x是individual
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))  # 注册了执行器

        # print("Create engine")

        self.env.execution_begin = time.time()
        self.env.population = population
        settings.GLOBAL_ENV = self.env
        # print("ready")
        engine.run(ng=settings.GENERATIONS)

        # print("run")

        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_control_flow_graph(
                    os.path.splitext(self.env.args.source)[0] + '-' + self.contract_name, 'pdf')
            elif self.env.args.abi:
                self.env.cfg.save_control_flow_graph(
                    os.path.join(os.path.dirname(self.env.args.abi), self.contract_name), 'pdf')

        self.instrumented_evm.reset()
        settings.TRANS_INFO["end_time"] = str(datetime.now())


def main():
    args = launch_argument_parser()

    logger = initialize_logger("Main    ")

    # Check if contract has already been analyzed
    if args.results and os.path.exists(args.results):
        os.remove(args.results)
        logger.info("Contract " + str(args.source) + " has already been analyzed: " + str(args.results))
        logger.info(f"原始的测试输出文件{args.results}已被删除")

    # Initializing random
    if args.seed:
        seed = args.seed
        if not "PYTHONHASHSEED" in os.environ:
            logger.debug("Please set PYTHONHASHSEED to '1' for Python's hash function to behave deterministically.")
    else:
        seed = random.random()
    random.seed(seed)
    logger.title("Initializing seed to %s", seed)

    # Initialize EVM
    instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)

    # Create Z3 solver instance
    solver = Solver()
    solver.set("timeout", settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    blockchain_state = []
    if args.blockchain_state:
        if args.blockchain_state.endswith(".json"):
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    blockchain_state.append(json.loads(line))
        elif args.blockchain_state.isnumeric():
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error("Unsupported input file: " + args.blockchain_state)
            sys.exit(-1)

    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    if args.source:
        if args.source.endswith(".sol"):

            compiler_output = compile(args.solc_version, settings.EVM_VERSION, args.source)
            if not compiler_output:
                logger.error("No compiler output for: " + args.source)
                sys.exit(-1)
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                if args.contract and contract_name != args.contract:
                    continue
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode'][
                    'object']:
                    source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'],
                           contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver,
                           args, seed, source_map, compiler_output['contracts'][args.source]).run()
        else:
            logger.error("Unsupported input file: " + args.source)
            sys.exit(-1)


    if args.abi:
        with open(args.abi) as json_file:
            abi = json.load(json_file)
            runtime_bytecode = instrumented_evm.get_code(to_canonical_address(args.contract)).hex()
            Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args,
                   seed).run()


def launch_argument_parser():
    parser = argparse.ArgumentParser()

    # Contract parameters
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-s", "--source", type=str,
                        help="Solidity smart contract source code file (.sol).")
    group1.add_argument("-a", "--abi", type=str,
                        help="Smart contract ABI file (.json).")

    # group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--contract", type=str,
                        help="Contract name to be fuzzed (if Solidity source code file provided) or blockchain contract address (if ABI file provided).")

    parser.add_argument("-b", "--blockchain-state", type=str,
                        help="Initialize fuzzer with a blockchain state by providing a JSON file (if Solidity source code file provided) or a block number (if ABI file provided).")

    # Compiler parameters
    parser.add_argument("--solc", help="Solidity compiler version (default '" + str(
        solcx.get_solc_version()) + "'). Installed compiler versions: " + str(
        solcx.get_installed_solc_versions()) + ".",
                        action="store", dest="solc_version", type=str)
    parser.add_argument("--evm", help="Ethereum VM (default '" + str(
        settings.EVM_VERSION) + "'). Available VM's: 'homestead', 'byzantium' or 'petersburg'.", action="store",
                        dest="evm_version", type=str)

    # Evolutionary parameters
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument("-g", "--generations",
                        help="Number of generations (default " + str(settings.GENERATIONS) + ").", action="store",
                        dest="generations", type=int)
    group3.add_argument("-t", "--timeout",
                        help="Number of seconds for fuzzer to stop.", action="store",
                        dest="global_timeout", type=int)
    parser.add_argument("-n", "--population-size",
                        help="Size of the population.", action="store",
                        dest="population_size", type=int)
    parser.add_argument("-pc", "--probability-crossover",
                        help="Size of the population.", action="store",
                        dest="probability_crossover", type=float)
    parser.add_argument("-pm", "--probability-mutation",
                        help="Size of the population.", action="store",
                        dest="probability_mutation", type=float)

    # Miscellaneous parameters
    parser.add_argument("-r", "--results", type=str, help="Folder or JSON file where results should be stored.")
    parser.add_argument("--seed", type=float, help="Initialize the random number generator with a given seed.")
    parser.add_argument("--cfg", help="Build control-flow graph and highlight code coverage.", action="store_true")
    parser.add_argument("--rpc-host", help="Ethereum client RPC hostname.", action="store", dest="rpc_host", type=str)
    parser.add_argument("--rpc-port", help="Ethereum client RPC port.", action="store", dest="rpc_port", type=int)

    parser.add_argument("--data-dependency",
                        help="Disable/Enable data dependency analysis: 0 - Disable, 1 - Enable (default: 1)",
                        action="store",
                        dest="data_dependency", type=int)
    parser.add_argument("--constraint-solving",
                        help="Disable/Enable constraint solving: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="constraint_solving", type=int)
    parser.add_argument("--environmental-instrumentation",
                        help="Disable/Enable environmental instrumentation: 0 - Disable, 1 - Enable (default: 1)",
                        action="store",
                        dest="environmental_instrumentation", type=int)
    parser.add_argument("--max-individual-length",
                        help="Maximal length of an individual (default: " + str(settings.MAX_INDIVIDUAL_LENGTH) + ")",
                        action="store",
                        dest="max_individual_length", type=int)
    parser.add_argument("--max-symbolic-execution",
                        help="Maximum number of symbolic execution calls before restting population (default: " + str(
                            settings.MAX_SYMBOLIC_EXECUTION) + ")", action="store",
                        dest="max_symbolic_execution", type=int)

    # cross contract fuzz parameters
    parser.add_argument("--cross-contract", type=int, help="open cross contract mode, open -- 1, close -- 2 (default)",
                        action="store", dest="cross_contract", default=2)
    parser.add_argument("--depend-contracts", type=str, nargs="*",
                        help="main fuzzed contract depend those contracts, you should give some names.",
                        dest="depend_contracts")
    parser.add_argument("--trans-json-path", type=str, help="location to save trans info to json",
                        dest="trans_json_path")
    parser.add_argument("--solc-path-cross", type=str, help="solc path, used by cross-slither", dest="solc_path_cross")
    parser.add_argument("--constructor-args", type=str, nargs="*",
                        help="constructor args, like: [address, uint, .....]", dest="constructor_args")
    parser.add_argument("--open-trans-comp", type=int, help="open cross trans mode, open -- 1 (default), close -- 2",
                        action="store", dest="trans_comp", default=1)
    parser.add_argument("--trans-mode", type=int, help="trans support mode, open other -- 1, no exec other -- 2",
                        default=1, dest="trans_mode")
    parser.add_argument("--p-open-cross", type=int, help="use cross trans probability: (1~8)", default=5,
                        dest="p_open_cross")
    parser.add_argument("--cross-init-mode", type=int, help="cross init mode: 1 -- specify, 2 -- random, 3 -- close",
                        default=1, dest="cross_init_mode")
    
    parser.add_argument("--full-constructor-config", type=str,
                        help="Path to the JSON file with constructor args for all contracts.",
                        dest="full_constructor_config")   #modify

    parser.add_argument("--duplication", type=str, help="duplication mode: 0 -- close, 1 -- open", default='0',
                        dest="duplication")
    
    parser.add_argument("--sequence-template", type=str,
                        help="Path to the JSON file with the function sequence template.",
                        dest="sequence_template")


    version = "ConFuzzius - Version 0.0.2 - "
    version += "\"By three methods we may learn wisdom:\n"
    version += "First, by reflection, which is noblest;\n"
    version += "Second, by imitation, which is easiest;\n"
    version += "And third by experience, which is the bitterest.\"\n"
    parser.add_argument("-v", "--version", action="version", version=version)

    args = parser.parse_args()

    if not args.contract:
        args.contract = ""

    if args.source and args.contract.startswith("0x"):
        parser.error("--source requires --contract to be a name, not an address.")
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error("--source requires --blockchain-state to be a file, not a number.")

    if args.abi and not args.contract.startswith("0x"):
        parser.error("--abi requires --contract to be an address, not a name.")
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error("--abi requires --blockchain-state to be a number, not a file.")

    if args.evm_version:
        settings.EVM_VERSION = args.evm_version
    if not args.solc_version:
        args.solc_version = solcx.get_solc_version()
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency is None:
        args.data_dependency = 1
    if args.constraint_solving is None:
        args.constraint_solving = 1
    if args.environmental_instrumentation is None:
        args.environmental_instrumentation = 1

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_host:
        settings.RPC_HOST = args.rpc_host
    if args.rpc_port:
        settings.RPC_PORT = args.rpc_port

    # cross contract
    if args.contract is None or args.contract == "" or args.cross_contract == 2:
        args.cross_contract = 2  # close
        args.depend_contracts = []
        args.trans_json_path = None
    else:
        if args.contract is None or args.contract == "":
            print(
                '\033[42;31m!!!!!!if open cross contract mode, you need specify a main contract which will be fuzzed!!!!!!\033[0m')
            print('\033[42;31m!!!!!!use --contract [Example]!!!!!!\033[0m')
            sys.exit(-1)
        # if args.depend_contracts is None:
        #     print(
        #         '\033[42;31m!!!!!!if open cross contract mode, you need specify some contract names which depended by main contract!!!!!!\033[0m')
        #     print('\033[42;31m!!!!!!use --depend-contracts [A B C]!!!!!!\033[0m')
        #     sys.exit(-1)
        # if args.constructor_args is None:
        #     print('\033[42;31m!!!!!!if open cross contract mode, you need specify some constructor args!!!!!!\033[0m')
        #     print('\033[42;31m!!!!!!use --constructor-args [address, uint, .....]!!!!!!\033[0m')
        #     sys.exit(-1)
    if args.trans_json_path is not None:
        settings.TRANS_INFO_JSON_PATH = args.trans_json_path
        print(f'\033[42;31m!!!!!!设置用于存储事务序列信息的json地址{settings.TRANS_INFO_JSON_PATH}!!!!!!\033[0m')
        if os.path.exists(settings.TRANS_INFO_JSON_PATH):
            print(
                f'\033[42;31m!!!!!!用于存储事务序列信息的json地址{settings.TRANS_INFO_JSON_PATH}已经存在了, 现已覆盖!!!!!!\033[0m')
    if args.trans_comp == 1:
        settings.TRANS_COMP_OPEN = True  # 是否开启反馈机制
    elif args.trans_comp == 2:
        settings.TRANS_COMP_OPEN = False
    settings.MAIN_CONTRACT_NAME = args.contract
    settings.SOLC_PATH_CROSS = args.solc_path_cross
    settings.P_OPEN_CROSS = args.p_open_cross
    settings.CROSS_INIT_MODE = args.cross_init_mode
    settings.TRANS_SUPPORT_MODE = args.trans_mode
    if args.duplication == '0':
        settings.DUPLICATION = True
    else:
        settings.DUPLICATION = False
    if settings.SOLC_PATH_CROSS is None:
        print('\033[42;31m!!!!!!you need specify a solc path!!!!!!\033[0m')
        sys.exit(-1)

    return args


if '__main__' == __name__:
    main()
