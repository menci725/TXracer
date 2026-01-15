import os
import json
import random
import sys
import shutil
import argparse
from copy import deepcopy

PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))

# 2. 检查这个根目录是否已经在 sys.path 中，如果不在，就添加进去
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
    print(f"[*] Project root '{PROJECT_ROOT}' added to sys.path.")
# ===================================================================

# --- 1. 导入所有需要的组件 ---
from fuzzer.utils import settings
from fuzzer.evm import InstrumentedEVM
from fuzzer.engine.environment import FuzzingEnvironment
from fuzzer.engine.components import Generator, Individual
from fuzzer.utils.utils import initialize_logger, compile, get_function_signature_mapping
from comp import analysis_depend_contract, analysis_main_contract_constructor
from eth_utils import encode_hex, to_canonical_address
from eth_abi import encode_abi
from z3 import Solver


import binascii
from pprint import pprint, pformat
from datetime import datetime



# ===================================================================
#  文件位置: ultimate_fuzzer.py (一个全新的主入口点)
# ===================================================================

# --- 2. 移植我们所有的自定义逻辑 ---

# --- 2.1 我们的 fitness_function ---
def _get_user_state(env, user_address_str):
    try:
        canonical_addr = to_canonical_address(user_address_str)
        eth_balance = env.instrumented_evm.get_balance(canonical_addr)
        return {'eth': eth_balance}
    except Exception as e:
        print(f"!! ERROR in _get_user_state for '{user_address_str}': {e}"); return {'eth': 0}

def _compare_scenarios(initial_state_alice, initial_state_bob, state_A_alice, state_A_bob, state_B_alice, state_B_bob):
    profit_A_alice = state_A_alice['eth'] - initial_state_alice['eth']
    profit_B_alice = state_B_alice['eth'] - initial_state_alice['eth']
    profit_B_bob = state_B_bob['eth'] - initial_state_bob['eth']
    # print(f"sssssss:{state_A_alice['eth'],state_B_alice['eth'],state_B_bob['eth']}")
    if profit_B_alice < profit_A_alice and profit_B_bob > 0:
        score = (profit_A_alice - profit_B_alice) + profit_B_bob
        return score
    if profit_A_alice > 0 and profit_B_alice < 0:
        return profit_A_alice - profit_B_alice
    if profit_B_bob > 0 and profit_B_alice > 0 and profit_B_bob > profit_B_alice : 
        return profit_B_bob - profit_B_alice

    return 0

def fitness_function(indv, env, sequence_template=None):
    print("\n" + "="*80)
    print(f"DEBUG: Analyzing Individual with hash: {indv.hash}")

    final_sequence = indv.decode()
    if not final_sequence: return 0.0

    try:
        alice_addr_str = env.instrumented_evm.accounts[0]
        if len(env.instrumented_evm.accounts) > 3: bob_addr_str = env.instrumented_evm.accounts[3]
        else:
            random_bytes = os.urandom(20); bob_addr_str = '0x' + binascii.hexlify(random_bytes).decode('ascii')
            env.instrumented_evm.create_fake_account(bob_addr_str); env.instrumented_evm.accounts.append(bob_addr_str)
        initial_state_alice = _get_user_state(env, alice_addr_str)
        initial_state_bob = _get_user_state(env, bob_addr_str)
    except Exception as e:
        print(f"!! ERROR: Failed to set up accounts: {e}"); return 0.0

    # --- 序列生成 ---
    template_filepath = "./current_fuzz_sequence.json"
    final_sequence = []
    
    if sequence_template is not None:
        print(f"!!! DEBUG: Engaging template-based Fuzzing with provided sequence (length {len(sequence_template)}). !!!")
        try:

            
            # 1. 创建一个临时的 Individual，用于构建和解码我们自己的序列
            template_indv = type(indv)(generator=indv.generator)
            new_chromosome = []            # 遍历模板中的每一个函数签名
            for item in sequence_template:
                func_sig = item['signature']
                print(f"DEBUG:   -> Generating gene for template: {func_sig}")
                
                # ===================================================================
                # !! 核心修改：使用正确的 Generator API !!
                # ===================================================================
                try:
                    # 2. 从 Generator 的 interface_mapper 中查找函数哈希和参数类型
                    #    get_specific_function_with_argument_types 正是为此设计的
                    func_hash, arg_types = indv.generator.get_specific_function_with_argument_types(func_sig)

                    # 3. 命令 generator 为我们“锻造”一个交易基因
                    #    generate_individual 返回的是一个包含单个 gene 的列表
                    gene_list = indv.generator.generate_individual(func_hash, arg_types)
                    if gene_list:
                        new_chromosome.append(gene_list[0])
                    else:
                        print(f"!! WARNING: Generator returned empty list for '{func_sig}'.")

                except KeyError:
                    print(f"!! WARNING: Signature '{func_sig}' not found in generator's interface. Skipping.")
                except Exception as e:
                    print(f"!! ERROR generating gene for '{func_sig}': {e}")
            
            # 4. 一次性解码整个序列
            if new_chromosome:
                template_indv.init(chromosome=new_chromosome)
                final_sequence = template_indv.decode()

        except Exception as e:
            print(f"!! FATAL ERROR while processing sequence template: {e}"); return 0.0
    else:
        # 完全随机模式 (保持不变)
        print("DEBUG: No sequence template found. Running in standard Fuzzing mode.")
        final_sequence = indv.decode()
    
    if not final_sequence:
        print("DEBUG: No valid sequence to test. Skipping."); return 0.0
    # --- 场景 A ---
    env.instrumented_evm.restore_from_snapshot()
    for i, execution_input in enumerate(final_sequence):
        current_input = deepcopy(execution_input)
        current_input['transaction']['from'] = alice_addr_str
        tx_data = current_input['transaction']['data']
        selector = tx_data[:10] if tx_data.startswith("0x") else "0x" + tx_data[:8]
        func_name = env.function_map.get(selector, f"Unknown/Fallback({selector})")
        result = env.instrumented_evm.deploy_transaction(current_input, gas_price=0)
        status = "SUCCESS" if not result.is_error else f"FAILED ({result._error})"
        print(f"DEBUG: [A-{i}] Tx from Alice, func: {func_name}, Status: {status}")
    state_A_alice = _get_user_state(env, alice_addr_str); state_A_bob = _get_user_state(env, bob_addr_str)

    # --- 场景 B ---
    env.instrumented_evm.restore_from_snapshot()
    alice_tasks = [deepcopy(x) for x in final_sequence]; [t['transaction'].update({'from': alice_addr_str}) for t in alice_tasks]
    bob_tasks = [deepcopy(x) for x in final_sequence]; [t['transaction'].update({'from': bob_addr_str}) for t in bob_tasks]
    merged_sequence = []
    while alice_tasks or bob_tasks:
        chosen_list = random.choice([l for l in [alice_tasks, bob_tasks] if l])
        merged_sequence.append(chosen_list.pop(0))
    for i, execution_input in enumerate(merged_sequence):
        user_name = "Alice" if execution_input['transaction']['from'] == alice_addr_str else "Bob"
        tx_data = execution_input['transaction']['data']
        selector = tx_data[:10] if tx_data.startswith("0x") else "0x" + tx_data[:8]
        func_name = env.function_map.get(selector, f"Unknown/Fallback({selector})")
        result = env.instrumented_evm.deploy_transaction(execution_input, gas_price=0)
        status = "SUCCESS" if not result.is_error else f"FAILED ({result._error})"
        print(f"DEBUG: [B-{i}] Tx from {user_name}, func: {func_name}, Status: {status}")
    state_B_alice = _get_user_state(env, alice_addr_str); state_B_bob = _get_user_state(env, bob_addr_str)
    print(f"DEBUG: Scenario B Final States -> Alice: {state_B_alice}, Bob: {state_B_bob}")
    
    vulnerability_score = _compare_scenarios(initial_state_alice, initial_state_bob, state_A_alice, state_A_bob, state_B_alice, state_B_bob)
    print(f"DEBUG: Vulnerability Score = {vulnerability_score}")

    if vulnerability_score > 0:
        print("\n" + "="*80)
        print(f"DEBUG: Analyzing Individual with hash: {indv.hash}")
        print(f"DEBUG: Scenario A Final States -> Alice: {state_A_alice}, Bob: {state_A_bob}")
        print(f"DEBUG: Scenario B Final States -> Alice: {state_B_alice}, Bob: {state_B_bob}")
        print(f"DEBUG: Vulnerability Score = {vulnerability_score}")
    
    if vulnerability_score > 0:
        with open("vulnerabilities.log", "a") as f:
            f.write("="*50 + "\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(f"Individual Hash: {indv.hash}\n")
            f.write(f"Vulnerability Score: {vulnerability_score}\n")
            
            # --- 1. 记录解码后的函数序列 ---
            f.write("Decoded Function Sequence:\n")
            readable_sequence = []
            for execution_input in final_sequence:
                tx_data = execution_input['transaction']['data']
                selector = tx_data[:10] if tx_data.startswith("0x") else "0x" + tx_data[:8]
                # 使用我们之前创建的 function_map 来翻译
                func_name = env.function_map.get(selector, f"Unknown/Fallback({selector})")
                readable_sequence.append(func_name)
            f.write(pformat(readable_sequence) + "\n")
            
            # --- 2. (可选) 记录原始的、底层的 chromosome ---
            f.write("Underlying Chromosome (Gene):\n")
            f.write(pformat(indv.chromosome) + "\n")
            
            # --- 3. 记录状态变化 ---
            f.write(f"Initial States: Alice={initial_state_alice}, Bob={initial_state_bob}\n")
            f.write(f"Scenario A States: Alice={state_A_alice}, Bob={state_A_bob}\n")
            f.write(f"Scenario B States: Alice={state_B_alice}, Bob={state_B_bob}\n\n")

            print("\n" + "!"*20 + " VULNERABILITY DETECTED! Logged to vulnerabilities.log " + "!"*20)
    
    return float(vulnerability_score)


# --- 2.2 我们的进化算子 ---
# --- 遗传算子 ---
def crossover(parent1, parent2):
    """单点交叉"""
    if len(parent1) < 2 or len(parent2) < 2:
        return parent1, parent2
    point = random.randint(1, min(len(parent1), len(parent2)) - 1)
    child1 = parent1[:point] + parent2[point:]
    child2 = parent2[:point] + parent1[point:]
    return child1, child2

def mutate(sequence, master_sequence):
    """
    新版：智能变异，能够从“基因库”(master_sequence)中添加新基因。
    """
    if not sequence or random.random() > MUTATION_RATE:
        return sequence
    
    # 优先尝试添加新函数，以打破局部最优
    mutation_type = random.choices(['add', 'delete', 'swap'], weights=[0.5, 0.25, 0.25], k=1)[0]
    
    # --- ADD (新能力) ---
    if mutation_type == 'add':
        # 找出 master_sequence 中存在，但当前 sequence 中不存在的函数
        current_signatures = {item['signature'] for item in sequence}
        candidates_to_add = [item for item in master_sequence if item['signature'] not in current_signatures]
        
        if candidates_to_add:
            new_gene = random.choice(candidates_to_add)
            insert_pos = random.randint(0, len(sequence))
            sequence.insert(insert_pos, new_gene)
            # print(f"  - MUTATION(ADD): Added '{new_gene['signature']}' at position {insert_pos}")
            return sequence
    
    # 如果无法添加 (或随机到其他类型)，则执行删除或交换
    if len(sequence) > 1:
        if mutation_type == 'delete':
            del_index = random.randint(0, len(sequence) - 1)
            removed = sequence.pop(del_index)
            # print(f"  - MUTATION(DELETE): Removed '{removed['signature']}'")
        elif mutation_type == 'swap':
            idx1, idx2 = random.sample(range(len(sequence)), 2)
            sequence[idx1], sequence[idx2] = sequence[idx2], sequence[idx1]
            # print(f"  - MUTATION(SWAP): Swapped positions {idx1} and {idx2}")
            
    return sequence


# --- 3. 创建一个主 Fuzzing 类来封装所有逻辑 ---
class UltimateFuzzer:
    def __init__(self, args):
        self.args = args
        self.logger = initialize_logger("UltimateFuzzer")
        self.full_constructor_config = {}
        if args.constructor_config and os.path.exists(args.constructor_config):
            with open(args.constructor_config, 'r') as f:
                self.full_constructor_config = json.load(f)

    def deploy(self):
        """
        这个方法整合了 fuzzer/main.py 的所有初始化和部署逻辑。
        它只执行一次，并返回一个完全准备好的 FuzzingEnvironment 对象。
        """
        self.logger.title("--- Initializing EVM and Deploying Contracts (ONCE) ---")

        # --- Part 1: 从 fuzzer/main.py 的 main() 中移植初始化逻辑 ---
        
        # 1.1 初始化 EVM 和 Solver
        instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
        instrumented_evm.set_vm_by_name("byzantium")
        solver = Solver()
        solver.set("timeout", settings.SOLVER_TIMEOUT)

        # 1.2 编译合约
        self.logger.info(f"Compiling {self.args.sol_file}...")
        compiler_output = compile(f"v{self.args.solc_version}", "byzantium", self.args.sol_file)
        if not compiler_output:
            raise RuntimeError(f"Compilation failed for {self.args.sol_file}")
        
        self.whole_compile_info = compiler_output['contracts'][self.args.sol_file]
        main_contract_info = self.whole_compile_info[self.args.contract_name]
        
        main_abi = main_contract_info["abi"]
        main_deployment_bytecode = main_contract_info['evm']['bytecode']['object']
        main_runtime_bytecode = main_contract_info['evm']['deployedBytecode']['object']

        # --- Part 2: 从 fuzzer/main.py 的 Fuzzer 类中移植部署逻辑 ---

        # 2.1 分析和部署依赖合约
        self.logger.info("Analyzing contract dependencies...")
        depend_contracts, slither_instance = analysis_depend_contract(
            file_path=self.args.sol_file, _contract_name=self.args.contract_name,
            _solc_version=self.args.solc_version, _solc_path=self.args.solc_path
        )
        if depend_contracts is None: depend_contracts = []
        
        self._deploy_depend_contracts(instrumented_evm, depend_contracts)

        # 2.2 部署主合约
        self.logger.info(f"Deploying main contract '{self.args.contract_name}'...")
        # (这里的构造函数参数处理逻辑，与我们最终的 CrossFuzz.py 完全一样)
        _constructor_args = []
        # ... (此处省略了从 config 或 auto-analysis 获取 _constructor_args 的逻辑)
        # 为简化，我们先假设主合约无参数，你可以把 CrossFuzz.py 的逻辑粘贴过来
        
        result = instrumented_evm.deploy_contract(
            instrumented_evm.accounts[0], main_deployment_bytecode, deploy_args=_constructor_args
        )
        if result.is_error:
            raise RuntimeError(f"Failed to deploy main contract: {result._error}")
        
        main_contract_address = encode_hex(result.msg.storage_address)
        self.logger.info(f"Main contract deployed at {main_contract_address}")

        # 2.3 创建快照
        instrumented_evm.create_snapshot()
        self.logger.info("Initial state snapshot created.")
        
        # --- Part 3: 创建并返回 FuzzingEnvironment 对象 ---

        self.logger.info("Creating Fuzzing Environment...")
        env = FuzzingEnvironment(
            instrumented_evm=instrumented_evm,
            contract_name=self.args.contract_name,
            contract_address=main_contract_address, # 传入主合约地址
            solver=solver,
            results={}, # 初始化一个空的结果字典
            symbolic_taint_analyzer=None, # 简化，暂不使用
            detector_executor=None, # 简化，暂不使用
            interface=get_interface_from_abi(main_abi)[0],
            overall_pcs=None, # 简化
            overall_jumpis=None, # 简化
            len_overall_pcs_with_children=0,
            other_contracts=[],
            args=self.args,
            seed=random.random(),
            cfg=None, # 简化
            abi=main_abi,
            function_map=get_function_signature_mapping(main_abi)
        )
        
        return env

    def _deploy_depend_contracts(self, instrumented_evm, depend_contracts):
        """
        一个辅助方法，移植了我们最终版的依赖部署逻辑。
        """       
        for depend_contract in depend_contracts:
            abi = self.whole_compile_info[depend_contract]['abi']
            bytecode_base = self.whole_compile_info[depend_contract]['evm']['bytecode']['object']
            final_bytecode = bytecode_base
            
            if depend_contract in self.full_constructor_config and 'args' in self.full_constructor_config[depend_contract]:
                config_args = self.full_constructor_config[depend_contract]['args']
                if config_args:
                    self.logger.info(f"Encoding constructor args for dependency '{depend_contract}'...")
                    arg_types = [arg['type'] for arg in config_args]
                    arg_values = [int(arg['value']) if 'int' in arg['type'] else arg['value'] for arg in config_args]
                    encoded_args = encode_abi(arg_types, arg_values).hex()
                    final_bytecode += encoded_args
            
            result = instrumented_evm.deploy_contract(instrumented_evm.accounts[0], final_bytecode)
            if result.is_error:
                raise RuntimeError(f"Failed to deploy dependency {depend_contract}: {result._error}")
            
            contract_address = encode_hex(result.msg.storage_address)
            instrumented_evm.accounts.append(contract_address)
            self.logger.info(f"Dependency '{depend_contract}' deployed at {contract_address}")
            settings.DEPLOYED_CONTRACT_ADDRESS[depend_contract] = contract_address
        
    def evolve(self, env):
        """
        这个方法整合了 evolutionary_sequencer.py 的所有进化逻辑。
        它在一个已经部署好的 env 对象上，高效地进行 Fuzzing。
        """
        self.logger.title("--- Starting Evolutionary Fuzzing ---")

        # --- Part 1: 获取初始“基因库” ---
        self.logger.info("Generating initial master sequence (gene pool)...")
        master_sequence_file = "master_sequence.json"
        
        # 为了健壮性，我们检查 sequence_generator.py 是否存在
        if not os.path.exists("sequence_generator.py"):
            raise FileNotFoundError("sequence_generator.py not found. Please ensure it's in the root directory.")
            
        subprocess.run([
            "python", "sequence_generator.py", 
            self.args.sol_file, 
            "--solc", self.args.solc_path, 
            "-o", master_sequence_file
        ])
        
        with open(master_sequence_file, "r") as f:
            master_sequence = json.load(f)
            master_sequence.sort(key=lambda x: x['score'], reverse=True)
        
        # --- Part 2: 阶段一 -> 二分探索，快速找到“核心序列” ---
        self.logger.title("--- STAGE 1: BINARY SEARCH FOR CORE SEQUENCE ---")
        best_runnable_sequence = []
        best_runnable_fitness = -1.0
        
        # 我们需要一个临时的 Individual，只为了调用 fitness_function
        # (Generator 的创建可以在 deploy 方法中完成，并存储在 env 中)
        if not hasattr(env, 'main_generator'): # 检查 env 中是否已经有 generator
             env.main_generator = Generator(
                 interface=get_function_signature_mapping(env.abi),
                 accounts=env.instrumented_evm.accounts,
                 contract=env.contract_address,
                 interface_mapper=get_function_signature_mapping(env.abi),
                 contract_name=env.contract_name
             )
        
        temp_indv = Individual(generator=env.main_generator)

        low, high = 0, len(master_sequence)
        for i in range(6): # 最多6次二分查找
            if low >= high: break
            mid = (low + high) // 2
            if mid == low and mid < high: mid += 1
            
            current_sequence = master_sequence[:mid]
            print(f"\n--- Binary Search Iteration {i+1}: Testing sequence of length {len(current_sequence)} ---")
            
            # 直接在内存中调用 fitness_function，不再有进程开销！
            fitness = fitness_function(temp_indv, env, sequence_template=current_sequence)
            
            if fitness >= 0:
                print(f"--- SUCCESS: Sequence of length {mid} is runnable with fitness {fitness}. Trying longer...")
                if fitness > best_runnable_fitness:
                    best_runnable_fitness = fitness
                    best_runnable_sequence = current_sequence
                low = mid
            else: # 超时 (我们让 fitness_function 在超时时返回 -1)
                print(f"--- TIMEOUT: Sequence of length {mid} is too long. Trying shorter...")
                high = mid

        if not best_runnable_sequence:
            self.logger.error("Could not find any runnable sequence. Exiting.")
            sys.exit(1)

        # --- Part 3: 阶段二 -> 爬山优化 ---
        self.logger.title(f"--- STAGE 2: EVOLUTION FROM CORE SEQUENCE (length {len(best_runnable_sequence)}) ---")
        
        population = [best_runnable_sequence]
        while len(population) < settings.POPULATION_SIZE:
            mutated_seed = mutate(deepcopy(best_runnable_sequence), master_sequence)
            population.append(mutated_seed)

        for generation in range(settings.GENERATIONS):
            self.logger.info(f"--- GENERATION {generation} ---")
            
            # 评估种群
            fitness_scores = []
            for i, seq in enumerate(population):
                print(f"  - Evaluating individual {i+1}/{len(population)}...")
                fitness = fitness_function(temp_indv, env, sequence_template=seq)
                fitness_scores.append((seq, fitness))

            fitness_scores.sort(key=lambda x: x[1], reverse=True)
            
            best_seq_info = fitness_scores[0]
            best_fitness = best_seq_info[1]
            best_sequence_signatures = [item['signature'] for item in best_seq_info[0]]
            self.logger.info(f"Generation {generation} Best Fitness: {best_fitness}")
            self.logger.info(f"Best sequence (len {len(best_sequence_signatures)}): {best_sequence_signatures[:5]}...")

            if best_fitness >= 1000:
                self.logger.info("VULNERABILITY LIKELY FOUND! Optimal sequence logged. Halting evolution.")
                break

            # 繁殖
            next_generation = [best_seq_info[0]] # 精英主义，保留最好的
            while len(next_generation) < settings.POPULATION_SIZE:
                # (这里的繁殖逻辑与 evolutionary_sequencer.py 相同)
                parent1 = random.choices(fitness_scores, weights=[max(0.01, f[1]) for f in fitness_scores], k=1)[0][0]
                parent2 = random.choices(fitness_scores, weights=[max(0.01, f[1]) for f in fitness_scores], k=1)[0][0]
                if random.random() < 0.7: child1, child2 = crossover(deepcopy(parent1), deepcopy(parent2))
                else: child1, child2 = deepcopy(parent1), deepcopy(parent2)
                next_generation.append(mutate(child1, master_sequence))
                if len(next_generation) < settings.POPULATION_SIZE:
                    next_generation.append(mutate(child2, master_sequence))
            
            population = next_generation

    def run(self):
        env = self.deploy()
        self.evolve(env)


def main():
    parser = argparse.ArgumentParser(description="Evolutionary Sequencer for CrossFuzz.")
    parser.add_argument("sol_file", help="Path to the Solidity source file.")
    parser.add_argument("contract_name", help="Name of the main contract to fuzz.")
    parser.add_argument("solc_version", help="Solidity compiler version.")
    parser.add_argument("max_seq_len", type=int, help="Maximum length of a transaction sequence.")
    parser.add_argument("result_path", help="Path to save the temporary results JSON file.")
    parser.add_argument("solc_path", help="Absolute path to the solc binary.")
    parser.add_argument("duplication", choices=['0', '1'], help="Duplication mode.")
    parser.add_argument("--constructor_config", help="Path to the constructor config JSON file. (optional)")
    parser.add_argument(
        "-o", "--output", 
        default="master_sequence.json", # !! 核心修改：输出到 master_sequence.json !!
        help="Path to the output master sequence JSON file (default: master_sequence.json)."
    )
    args = parser.parse_args()
    
    fuzzer = UltimateFuzzer(args)
    fuzzer.run()

if __name__ == "__main__":
    main()