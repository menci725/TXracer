import os
import binascii
from pprint import pprint, pformat
from datetime import datetime
from copy import deepcopy
import random
import json
import traceback
from eth_utils import to_canonical_address, to_bytes,function_signature_to_4byte_selector, decode_hex
from fuzzer.utils import settings 
from eth_abi import encode_abi, decode_abi
from web3 import Web3
from eth.vm.spoof import SpoofTransaction
import sys
from fuzzer.utils.utils import convert_stack_value_to_int
from collections import defaultdict
ASSET_VALUES = {
    "ETH": {"_DEFAULT_": 1}, 
    "ERC165": {
         "_DEFAULT_": 55,
    },
    "ERC20": {
        "_DEFAULT_": 666,
        # "0x...WETH_ADDRESS...": 1
    },
    "ERC721": {
        "_DEFAULT_": 7777,
        # "0x...BAYC_ADDRESS...": 50
    }
}

def get_revert_reason(result):
    if not result.is_error:
        return "SUCCESS"
    
    # a. 检查是否存在 revert data
    revert_data = result.output
    if not revert_data or len(revert_data) < 4:
        return f"FAILED ({result._error})" # 如果没有 output，返回底层错误

    # b. 检查是否是标准的 Error(string) 编码 (0x08c379a0)
    error_selector = revert_data[:4]
    if error_selector == b'\x08\xc3y\xa0':
        try:
            # c. 解码
            # 跳过 4 字节的 selector
            unpacked_reason = decode_abi(['string'], revert_data[4:])
            # decode_abi 返回一个元组，我们取第一个元素
            return f"REVERT: {unpacked_reason[0]}"
        except Exception:
            # 如果解码失败，返回原始的 output
            return f"FAILED (Malformed Revert Data: {revert_data.hex()})"
            
    # d. 对于其他类型的错误（如 assert, custom error），返回底层错误
    return f"FAILED ({result._error})"

def get_storage_value(evm, address, slot):
    return evm.vm.state.get_storage(to_canonical_address(address), slot)

def _get_user_state(env, user_address_str, contracts_to_check):
    state = {'assets': {}}
    try:
        state['assets']['ETH'] = env.instrumented_evm.get_balance(to_canonical_address(user_address_str))
    except Exception: state['assets']['ETH'] = 0

    for contract_address, contract_type in contracts_to_check.items():
        try:
            balance_of_data = "0x70a08231" + encode_abi(['address'], [user_address_str]).hex()
            
            output = env.instrumented_evm.safe_read_call(user_address_str, contract_address, balance_of_data)
            
            if output and int.from_bytes(output, 'big') > 0:
                balance = int.from_bytes(output, 'big')
                state['assets'][f"{contract_type}@{contract_address}"] = balance
        except Exception:
            pass
    return state

def calculate_total_value(state):
    total_value = 0
    for asset_key, balance in state['assets'].items():
        try:
            value_per_unit_eth = 0
            
            if asset_key == 'ETH':
                value_per_unit_eth = ASSET_VALUES['ETH']['_DEFAULT_']
            else:
                asset_type, asset_address = asset_key.split('@')
                
                # 1. 在 ASSET_VALUES 中查找对应的资产类型
                if asset_type in ASSET_VALUES:
                    # 2. 在该类型的子字典中，优先查找特定地址的价值
                    #    如果找不到，就使用该类型的 '_DEFAULT_' 价值
                    value_per_unit_eth = ASSET_VALUES[asset_type].get(
                        asset_address, 
                        ASSET_VALUES[asset_type]['_DEFAULT_']
                    )

            # 乘以余额/数量，并转换为 Wei
            total_value += balance * Web3.toWei(value_per_unit_eth, 'ether')
        except (KeyError, ValueError) as e:
            print(f"!! WARNING: Could not calculate value for asset '{asset_key}': {e}")
            continue
            
    return total_value
def _compare_scenarios(initial_state_alice, initial_state_bob, state_A_alice, state_A_bob, state_B_alice, state_B_bob):
    initial_value_alice = calculate_total_value(initial_state_alice)
    initial_value_bob = calculate_total_value(initial_state_bob)
    final_value_A_alice = calculate_total_value(state_A_alice)
    final_value_A_bob = calculate_total_value(state_A_bob)
    final_value_B_alice = calculate_total_value(state_B_alice)
    final_value_B_bob = calculate_total_value(state_B_bob)

    # print(f"DEBUG: Alice's initial value: {initial_value_alice} Bob's initial value: {initial_value_bob} Alice's final value: {final_value_A_alice} Alice's final b :{final_value_B_alice} Bob's final value: {final_value_B_bob}")
    
    profit_A_alice = final_value_A_alice - initial_value_alice
    profit_A_bob = final_value_A_bob - initial_value_bob
    profit_B_alice = final_value_B_alice - initial_value_alice
    profit_B_bob = final_value_B_bob - initial_value_bob
    
    value_based_score = 0
    # if profit_B_alice < profit_A_alice and profit_B_bob > 0:
    # if profit_B_alice < profit_A_alice:
    # value_based_score = max(-1 * (profit_B_alice == profit_A_alice), -1 *  (profit_B_bob == profit_A_alice) , -1 * (profit_B_alice == profit_B_bob)) + 1
    value_based_score =( profit_A_alice - profit_B_alice ) * (profit_B_bob > 0)
    # print(f"Alice:{profit_A_alice}  Bob:{profit_A_bob} B Alice:{profit_B_alice} Bob:{profit_B_bob} value_score:{value_based_score}")



    intent_based_score = 0
    # 1. 识别出 Alice 在场景 A 中新获得的非ETH资产
    initial_assets_alice = set(k for k in initial_state_alice['assets'].keys())
    final_assets_A_alice = set(k for k in state_A_alice['assets'].keys())
    target_assets = final_assets_A_alice - initial_assets_alice
    
    if target_assets:
        print(f"DEBUG: Alice's target assets identified from Scenario A: {target_assets}")
        print(f"DEBUG: Bob's target assets identified from Scenario B: {set(state_B_bob['assets']) - set(initial_state_bob['assets'])}")
    
    if target_assets:
        final_assets_B_alice = set(k for k in state_B_alice['assets'].keys() if k != 'ETH')
        final_assets_B_bob = set(k for k in state_B_bob['assets'].keys() if k != 'ETH')
        initial_assets_bob = set(k for k in initial_state_bob['assets'].keys() if k != 'ETH')

        assets_bob = final_assets_B_alice - initial_assets_bob
        # print(f"DEBUG: Bob's target assets identified from Scenario B: {assets_bob}")

        # if assets_bob and assets_bob not in target_assets:
        #     intent_based_score = 10**21
        #     print(f"DEBUG: Bob's target assets identified from Scenario B: {assets_bob}")
        #     print(f"DEBUG: alice's target assets identified from Scenario B: {target_assets}")

        for asset in state_A_alice['assets'].keys():
            # print(asset)
            if asset == 'ETH':
                 continue

            # if asset in target_assets and asset in assets_bob:
            if state_B_alice['assets'].get(asset) != state_B_bob['assets'].get(asset):
                intent_based_score = 2**21
                print(f"!!! INTENT VIOLATION DETECTED1: Alice lost target asset '{asset}' which was gained by Bob. !!!")
                print(f"Alice:{initial_state_alice['assets']} Bob:{initial_state_bob['assets']}\nALice:{state_B_alice['assets']} Bob:{state_B_bob['assets']}")

            asset_lost_by_alice_in_B = asset not in final_assets_B_alice
            asset_gained_by_bob_in_B = asset in final_assets_B_bob and asset not in initial_assets_bob
            
            if asset_lost_by_alice_in_B and asset_gained_by_bob_in_B or target_assets != final_assets_B_alice:
                print(f"!!! INTENT VIOLATION DETECTED2: Alice lost target asset '{asset}' which was gained by Bob. !!!")
                intent_based_score = 9**21 
                break 

    # 返回两个分数中的最大值
    return max(value_based_score, intent_based_score)

def _run_and_record_rw_sets(env, solution, user_addr_str):
    """
    在一个干净的快照上，有状态地执行一个序列，
    并通过分析执行轨迹，返回每个交易的精确读写集。
    """
    print(f"[*] Scout Run: Recording R/W sets for {user_addr_str}...")
    rw_sets = []
    
    # 1. 准备序列
    user_solution = deepcopy(solution)
    for tx_input in user_solution:
        tx_input['transaction']['from'] = user_addr_str
    
    # 2. 恢复快照，确保起点干净
    env.instrumented_evm.restore_from_snapshot()
    
    # 3. 逐一执行交易，并在每次执行后分析其轨迹
    for i, tx_input in enumerate(user_solution):
        reads = set()
        writes = set()
        
        tx_data = tx_input['transaction']
        
        try:
            # a. 执行交易 (使用你提供的、100%可工作的代码)
            sender_addr_canon = to_canonical_address(user_addr_str)
            nonce = env.instrumented_evm.vm.state.get_nonce(sender_addr_canon)
            tx = env.instrumented_evm.vm.create_unsigned_transaction(
                nonce=nonce, gas_price=0, gas=tx_data['gaslimit'],
                to=to_canonical_address(tx_data['to']), value=tx_data['value'],
                data=decode_hex(tx_data['data'])
            )
            spoofed_tx = SpoofTransaction(tx, from_=sender_addr_canon)
            result_computation = env.instrumented_evm.vm.state.apply_transaction(spoofed_tx)

            # b. 如果交易成功，就分析它的轨迹来提取读写集
            if not result_computation.is_error:
                for instruction in result_computation.trace:
                    if instruction["op"] == "SLOAD":
                        # 栈顶是存储槽位的地址
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                        reads.add(storage_slot)
                    elif instruction["op"] == "SSTORE":
                        # 栈顶是存储槽位的地址
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                        writes.add(storage_slot)
            # else:
            #      print(f"  -> Scout Run Tx #{i} reverted. R/W sets will be empty.")

        except Exception as e:
            # print(f"  -> Scout Run Tx #{i} failed with exception: {e}")
            pass
            # 失败的交易没有读写集
        
        rw_sets.append({"reads": reads, "writes": writes})

    print(f"[*] Finished recording. Found R/W sets: {rw_sets}")
    return rw_sets, user_solution

def _find_preemption_pairs(alice_rw_sets, bob_rw_sets):
    # print("\n[*] Conflict Analysis: Finding Preemption Pairs (PPs)...")
    preemption_pairs = []
    for i, rw_A in enumerate(alice_rw_sets):
        for j, rw_B in enumerate(bob_rw_sets):
            # 检查写-读、读-写、写-写冲突
            if not rw_A['writes'].isdisjoint(rw_B['reads']) or \
               not rw_A['reads'].isdisjoint(rw_B['writes']) or \
               not rw_A['writes'].isdisjoint(rw_B['writes']):
                # 为了避免重复，我们只添加唯一的冲突点
                if not any(p['A_idx'] == i or p['B_idx'] == j for p in preemption_pairs):
                    pp = {'A_idx': i, 'B_idx': j, 'A_func': alice_rw_sets[i]['func_hash'], 'B_func': bob_rw_sets[j]['func_hash']}
                    preemption_pairs.append(pp)
                    # print(f"  -> Found PP: Alice's Tx #{i} ({pp['A_func']}) conflicts with Bob's Tx #{j} ({pp['B_func']})")
    return preemption_pairs

def _calculate_state_distance(initial_state, final_state):
    """
    计算一个序列执行前后，资产状态的“距离”。
    """
    distance = 0
    initial_assets = {k: v for k, v in initial_state['assets'].items() if k != 'ETH'}
    final_assets = {k: v for k, v in final_state['assets'].items() if k != 'ETH'}
    
    all_asset_keys = set(initial_assets.keys()) | set(final_assets.keys())
    
    for key in all_asset_keys:
        initial_balance = initial_assets.get(key, 0)
        final_balance = final_assets.get(key, 0)
        # 计算每个资产的变化绝对值，并相加
        distance += abs(final_balance - initial_balance) * 10^18

    distance += abs(final_state['assets']['ETH'] - initial_state['assets']['ETH'])
        
    return distance

def fitness_function(indv, env):
    # print("\n" + "="*80)
    # print(f"DEBUG: Analyzing Individual with hash: {indv.hash}")

    # final_sequence = indv.decode()
    # if not final_sequence: return 0.0
    solution_sequence = indv.decode()
    chromosome = indv.chromosome

    if not solution_sequence or len(chromosome) != len(solution_sequence):
        print("!! WARNING: Chromosome and Solution mismatch or empty. Running with raw fuzzer sequence.")
        # 如果长度不匹配，我们无法安全配对，只能回退到纯随机模式
        final_paired_sequence = [(None, sol) for sol in solution_sequence] if solution_sequence else []
    else:
        paired_sequence = list(zip(chromosome, solution_sequence))
        # paired_sequence = list(zip(chromosome, alice_solution))

        # --- 2. 为日志打印，提前构建“电话本” ---
        generator_function_maps = {gen.contract_name: {h: sig for sig, h in gen.interface_mapper.items()} 
                                   for gen in [indv.generator] + indv.other_generators if gen.interface_mapper}
        
        # --- 3. 创建一个“零件仓库” (现在存储的是配对好的“器官”) ---
        parts_warehouse = {}
        for gene, solution in paired_sequence:
            try:
                # 我们从 gene 中获取哈希，从 solution 中获取地址，这是最可靠的
                func_hash = gene['arguments'][0]
                target_address = solution['transaction']['to']
                target_contract_name = next((name for name, addr in settings.DEPLOYED_CONTRACT_ADDRESS.items() if addr.lower() == target_address.lower()), None)
                if not target_contract_name: continue
                
                func_sig = generator_function_maps.get(target_contract_name, {}).get(func_hash)
                if not func_sig: continue
                    
                # 仓库的钥匙是函数签名，值是这个配对好的 (gene, solution) 元组
                parts_warehouse[func_sig] = (gene, solution)
            except:
                continue

        # --- 4. 序列生成：结合“建筑蓝图”和“零件仓库” ---
        template_filepath = "./current_fuzz_sequence.json"
        final_paired_sequence = []
        
        if os.path.exists(template_filepath):
            # print(f"!!! DEBUG: Found sequence template. Engaging template-based RECOMBINATION. !!!")
            try:
                with open(template_filepath, 'r') as f:
                    sequence_template = json.load(f)
                
                for task in sequence_template:
                    func_sig = task.get('signature')
                    required_part = parts_warehouse.get(func_sig)
                    
                    if required_part:
                        # print(f"DEBUG:   -> Found required part for '{func_sig}' in fuzzer's output.")
                        final_paired_sequence.append(required_part)
                    else:
                        print(f"!! WARNING: Could not find part for '{func_sig}' in this individual's sequence. Skipping step.")
            except Exception as e:
                print(f"!! FATAL ERROR while processing sequence template: {e}"); return 0.0
        else:
            final_paired_sequence = paired_sequence
            
    if not final_paired_sequence:
        print("DEBUG: No valid sequence to test. Skipping."); return 0.0

    try:
        if len(env.instrumented_evm.accounts) < 2:
            raise RuntimeError("Not enough pre-set accounts for simulation. Need at least 2.")

        alice_addr_str = env.instrumented_evm.accounts[0]
        bob_addr_str = env.instrumented_evm.accounts[1]
        # print(f"Alice: {alice_addr_str}\nBob: {bob_addr_str}")
        # print(f"DEBUG: Injecting Alice ({alice_addr_str}) and Bob ({bob_addr_str}) into all generators...")
        all_generators = [indv.generator] + indv.other_generators
        for gen in all_generators:
            # 去重
            extended_accounts = set(gen.accounts)
            extended_accounts.add(alice_addr_str)
            extended_accounts.add(bob_addr_str)
            gen.accounts = list(extended_accounts)
        
        # a. 恢复到干净快照
        env.instrumented_evm.restore_from_snapshot()

        # b. 手动执行一笔 Alice -> Bob 的转账
        genesis_transfer_amount = Web3.toWei(1, 'ether')
        try:
             genesis_tx_input = {
                 'transaction': {
                     'from': alice_addr_str, 'to': bob_addr_str,
                     'value': genesis_transfer_amount, 'data': '0x',
                     'gaslimit': settings.GAS_LIMIT
                 }, 'block': {}, 'global_state': {}, 'environment': {}
             }
             result = env.instrumented_evm.deploy_transaction(genesis_tx_input, gas_price=0)
             if result.is_error:
                 raise RuntimeError(f"Genesis transaction failed: {result._error}")

        except Exception as e:
            print(f"!! FATAL ERROR during genesis transaction: {e}"); return 0.0

        # c. 转账成功后
        env.instrumented_evm.create_snapshot()
        contracts_to_check = {}

        env.instrumented_evm.restore_from_snapshot()



        if hasattr(settings, 'DEPLOYED_CONTRACT_ADDRESS'):
            for name, address in settings.DEPLOYED_CONTRACT_ADDRESS.items():
                contracts_to_check[address] = "ERC20" 

    except Exception as e:
        print(f"!! ERROR: Failed to set up: {e}"); return 0.0

    generator_map = {indv.generator.contract_name: indv.generator}
    for g in indv.other_generators:
        generator_map[g.contract_name] = g
        
    final_sequence = []

    for i, gene in enumerate(indv.chromosome):
        # print(f"DEBUG: Processing gene {i}...")
        try:
            # a. 从基因中找出目标合约地址
            target_address = gene['contract']
            
            # b. 根据地址，反向查找是哪个合约，以及它的 Generator
            target_generator = None
            target_contract_name = None
            for name, address in settings.DEPLOYED_CONTRACT_ADDRESS.items():
                if address.lower() == target_address.lower():
                    target_contract_name = name
                    target_generator = generator_map.get(name)
                    break


            # print(f"DEBUG: {target_address} -> {target_contract_name} -> {target_generator}")
            
            if not target_generator:
                print(f"!! WARNING: Could not find generator for address {target_address} in gene {i}. Skipping.")
                continue

            # c. 编码 data 字段
            func_hash = gene['arguments'][0]
            arg_values = gene['arguments'][1:]
            arg_types = target_generator.interface.get(func_hash)
            # print(f"DEBUG: function selector '{func_hash}' has argument types: {arg_types}")
            if arg_types is None:
                print(f"!! WARNING: Could not find arg_types for hash {func_hash} in {target_contract_name}'s interface. Skipping.")
                continue
            if len(arg_values) != len(arg_types):
                print(f"!! WARNING: Arg count mismatch for {func_hash}. Skipping gene {i}.")
                continue

            encoded_args = encode_abi(arg_types, arg_values).hex()
            tx_data = func_hash + encoded_args

            # d. 构建最终的可执行交易
            execution_input = {
                'transaction': {
                    'from': '0xPLACEHOLDER', # from 会在场景模拟中被覆盖
                    'to': target_address,
                    'value': gene['amount'],
                    'data': tx_data,
                    'gaslimit': gene['gaslimit']
                }, 'block': {}, 'global_state': {}, 'environment': {}
            }
            final_sequence.append(execution_input)
            # print(f"DEBUG: Successfully decoded gene {i}.")
        except Exception as e:
            print(f"!! WARNING: failed to decode gene {i}: {e}")

        except Exception as e:
            print(f"!! FATAL ERROR while manually decoding gene {i}: {e}")
            pprint(gene)

    if not final_sequence:
        print("DEBUG: No valid sequence was decoded. Skipping."); return 0.0


    generator_function_maps = {}
    all_generators = [indv.generator] + indv.other_generators
    for gen in all_generators:
        if gen.interface_mapper:
            gen_map = {h: sig for sig, h in gen.interface_mapper.items()}
            generator_function_maps[gen.contract_name] = gen_map
        else:
            generator_function_maps[gen.contract_name] = {}
    def execute_and_log(tx_input, user_name, tx_index_str):
        tx = tx_input['transaction']
        target_address = tx['to']
        
        target_contract_name = next((name for name, addr in settings.DEPLOYED_CONTRACT_ADDRESS.items() if addr.lower() == target_address.lower()), "UnknownContract")
        
        func_name = "UnknownFunc"
        params_str = "N/A"
        
        if target_contract_name in generator_function_maps:
            contract_map = generator_function_maps.get(target_contract_name, {})
            selector = tx['data'][:10]
            func_sig = contract_map.get(selector)
            
            if func_sig:
                func_name = func_sig
                try:
                    _, _, arg_types_str = func_sig.partition('(')
                    arg_types_str = arg_types_str.rpartition(')')[0]
                    arg_types = arg_types_str.split(',') if arg_types_str and arg_types_str.strip() else []
                    
                    encoded_args_hex = tx['data'][10:]
                    decoded_args = decode_abi(arg_types, bytes.fromhex(encoded_args_hex))
                    params_str = str(decoded_args)
                except Exception as e:
                    params_str = f"DECODING_ERROR: {e}"

        result = env.instrumented_evm.deploy_transaction(tx_input, gas_price=0)
        status = "SUCCESS" if not result.is_error else f"FAILED ({result._error})"
        print(f"DEBUG: [{tx_index_str}] Tx from {user_name} to {target_contract_name}, func: {func_name}, params: {params_str}, Status: {status}")
        
        # 即时状态反馈
        current_alice_state = _get_user_state(env, alice_addr_str, contracts_to_check)
        current_bob_state = _get_user_state(env, bob_addr_str, contracts_to_check)
        # print(f"  -> Alice's assets: {current_alice_state['assets']}")
        # print(f"  -> Bob's assets:   {current_bob_state['assets']}")
    

    asset_map_filepath = "/root/pri/asset_variable_list.json"
    asset_variable_slots = set()
    if os.path.exists(asset_map_filepath):
        # print(f"[*] Loading asset map from {asset_map_filepath}...")
        try:
            with open(asset_map_filepath, 'r') as f:
                asset_map = json.load(f)
            # 我们只关心存储槽位的 ID
            for var_info in asset_map.values():
                if "slot" in var_info and not var_info.get("is_mapping"):
                     asset_variable_slots.add(var_info["slot"])
            # print(f"[*] Loaded {len(asset_variable_slots)} asset-related storage slots.")
        except Exception as e:
            print(f"[!] Warning: Failed to load or parse asset map: {e}")


    # Scout Run
    # alice_rw_sets, alice_solution = _run_and_record_rw_sets(env, final_sequence, alice_addr_str)
    alice_solution = deepcopy(final_sequence)
    for tx in alice_solution: tx['transaction']['from'] = alice_addr_str
    bob_solution = deepcopy(final_sequence)
    for tx in bob_solution: tx['transaction']['from'] = bob_addr_str

    rw_sets = []
    user_solution = deepcopy(solution)
    env.instrumented_evm.restore_from_snapshot()
    env.data_dependencies.clear()
    user_addr_str = alice_addr_str
    
    for i, (gene, execution_input) in enumerate(final_paired_sequence):
        tx_data = execution_input['transaction']
        reads = set()
        writes = set()
        try:
            sender_addr_canon = to_canonical_address(alice_addr_str)
            nonce = env.instrumented_evm.vm.state.get_nonce(sender_addr_canon)
            tx = env.instrumented_evm.vm.create_unsigned_transaction(
                nonce=nonce, gas_price=0, gas=tx_data['gaslimit'],
                to=to_canonical_address(tx_data['to']), value=tx_data['value'],
                data=decode_hex(tx_data['data'])
            )
            spoofed_tx = SpoofTransaction(tx, from_=sender_addr_canon)
            result_computation = env.instrumented_evm.vm.state.apply_transaction(spoofed_tx)
            status = get_revert_reason(result_computation)
            func_hash = gene['arguments'][0]

            if not result_computation.is_error:
                for instruction in result_computation.trace:
                    if instruction["op"] == "SLOAD":
                        # 栈顶是存储槽位的地址
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                        if storage_slot in asset_variable_slots:
                            reads.add(storage_slot)
                    elif instruction["op"] == "SSTORE":
                        # 栈顶是存储槽位的地址
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                        if storage_slot in asset_variable_slots:
                            writes.add(storage_slot)

        except Exception as e:
            pass
            # 失败的交易没有读写集
        rw_sets.append({"reads": reads, "writes": writes, "func_hash": func_hash})
    # if rw_sets:
    #     print(f"[*] Finished alice recording. Found R/W sets: {rw_sets}")
    alice_rw_sets =  rw_sets
    # alice_solution = user_solution

    # bob_rw_sets, bob_solution = _run_and_record_rw_sets(env, final_sequence, bob_addr_str)
    rw_sets = []
    user_solution = deepcopy(solution)
    env.instrumented_evm.restore_from_snapshot()
    env.data_dependencies.clear()
    user_addr_str = alice_addr_str
    
    for i, (gene, execution_input) in enumerate(final_paired_sequence):
        tx_data = execution_input['transaction']
        reads = set()
        writes = set()
        try:
            sender_addr_canon = to_canonical_address(alice_addr_str)
            nonce = env.instrumented_evm.vm.state.get_nonce(sender_addr_canon)
            tx = env.instrumented_evm.vm.create_unsigned_transaction(
                nonce=nonce, gas_price=0, gas=tx_data['gaslimit'],
                to=to_canonical_address(tx_data['to']), value=tx_data['value'],
                data=decode_hex(tx_data['data'])
            )
            spoofed_tx = SpoofTransaction(tx, from_=sender_addr_canon)
            result_computation = env.instrumented_evm.vm.state.apply_transaction(spoofed_tx)
            status = get_revert_reason(result_computation)
            func_hash = gene['arguments'][0]
            if not result_computation.is_error:
                for instruction in result_computation.trace:
                    if instruction["op"] == "SLOAD":
                        # 栈顶是存储槽位的地址
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                        if storage_slot in asset_variable_slots:
                            reads.add(storage_slot)
                    elif instruction["op"] == "SSTORE":
                        # 栈顶是存储槽位的地址
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])
                        if storage_slot in asset_variable_slots:
                            writes.add(storage_slot)


        except Exception as e:
            pass
            # 失败的交易没有读写集
        rw_sets.append({"reads": reads, "writes": writes, "func_hash": func_hash})
    # if rw_sets:
    #     print(f"[*] Finished bob recording. Found R/W sets: {rw_sets}")
    bob_rw_sets =  rw_sets
    # bob_solution = user_solution

    # 冲突分析
    preemption_pairs = _find_preemption_pairs(alice_rw_sets, bob_rw_sets)
    # print(f"DEBUG: Found {len(preemption_pairs)} preemption pairs.")

    # A
    # print("\n--- Starting Scenario A (Alice sequential execution) ---")
    env.instrumented_evm.restore_from_snapshot()
    env.data_dependencies.clear() # 清空记录
    initial_state_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
    initial_state_bob = _get_user_state(env, bob_addr_str, contracts_to_check)
    ideal_trajectory_map = {} # { func_hash -> state }
    for i, (gene, execution_input) in enumerate(final_paired_sequence):
        tx_data = execution_input['transaction']
        try:
            # 执行交易
            sender_addr_canon = to_canonical_address(alice_addr_str)
            nonce = env.instrumented_evm.vm.state.get_nonce(sender_addr_canon)
            tx = env.instrumented_evm.vm.create_unsigned_transaction(
                nonce=nonce, gas_price=0, gas=tx_data['gaslimit'],
                to=to_canonical_address(tx_data['to']), value=tx_data['value'],
                data=decode_hex(tx_data['data'])
            )
            spoofed_tx = SpoofTransaction(tx, from_=sender_addr_canon)
            result_computation = env.instrumented_evm.vm.state.apply_transaction(spoofed_tx)
            status = get_revert_reason(result_computation)

            # a. 从 gene 中获取函数哈希和可读参数
            func_hash = gene['arguments'][0]
            readable_args = gene['arguments'][1:] if gene else "N/A (raw fuzzer sequence)"

            # b. 根据地址和哈希，查找可读的函数名
            target_address = tx_data['to']
            target_contract_name = next((name for name, addr in settings.DEPLOYED_CONTRACT_ADDRESS.items() if addr.lower() == target_address.lower()), "UnknownContract")
            func_name = generator_function_maps.get(target_contract_name, {}).get(func_hash, f"UnknownFunc({func_hash})")

            if hasattr(settings, 'DEPLOYED_CONTRACT_ADDRESS'):
                for name, address in settings.DEPLOYED_CONTRACT_ADDRESS.items():
                    if address.lower() == target_address.lower():
                        target_contract_name = name
                        break
            event_stamp = (func_hash, len([h for h,s in ideal_trajectory_map.keys() if h == func_hash]))
            current_state_A_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
            ideal_trajectory_map[event_stamp] = current_state_A_alice
        except Exception as e:
            # print(f"DEBUG: [A-{i}] Tx from Alice. Status: FAILED (Exception: {e})")
            pass

    state_A_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
    # env.instrumented_evm.restore_from_snapshot()

    state_A_bob = _get_user_state(env, bob_addr_str, contracts_to_check)

    # B
    env.instrumented_evm.restore_from_snapshot()

    merged_sequence = []
    alice_event_counter = defaultdict(int)
    flag = 0

    if preemption_pairs and random.random() < 0.8: # 80% 概率
        # print("DEBUG:   -> Engaging 'Precise Front-run' simulation model...")
        
        k = min(len(preemption_pairs), 2) 
        selected_pps = sorted(preemption_pairs, key=lambda p: (p['A_idx'], p['B_idx']))[:k]
        
        alice_conflict_indices = [pp['A_idx'] for pp in selected_pps]
        bob_conflict_indices = [pp['B_idx'] for pp in selected_pps]

        def segment_sequence(solution, indices):
            segments = []
            last_idx = -1
            for idx in indices:
                segments.append(solution[last_idx+1 : idx+1]) # 将冲突点本身包含在段的末尾
                last_idx = idx
            segments.append(solution[last_idx+1:])
            return segments

        alice_segments = segment_sequence(alice_solution, alice_conflict_indices)
        bob_segments = segment_sequence(bob_solution, bob_conflict_indices)

        num_segments = k + 1
        for i in range(num_segments):
            if i < len(bob_segments) and bob_segments[i]:
                merged_sequence.extend(bob_segments[i])
            if i < len(alice_segments) and alice_segments[i]:
                merged_sequence.extend(alice_segments[i])

    else:
        # print("DEBUG:   -> Engaging 'Random Interleaving' simulation model...")
        
        alice_tasks = [deepcopy(x) for x in final_sequence] # 注意：final_sequence 需要在这里可见
        for task in alice_tasks: task['transaction']['from'] = alice_addr_str
        bob_tasks = [deepcopy(x) for x in final_sequence]
        for task in bob_tasks: task['transaction']['from'] = bob_addr_str
        
        while alice_tasks or bob_tasks:
            available_lists = [l for l in [alice_tasks, bob_tasks] if l]
            if not available_lists: break
            chosen_list = random.choice(available_lists)
            merged_sequence.append(chosen_list.pop(0))
    
    # # 1.任务列表
    # alice_tasks = [deepcopy(x) for x in final_sequence]
    # for task in alice_tasks:
    #     task['transaction']['from'] = alice_addr_str
        
    # bob_tasks = [deepcopy(x) for x in final_sequence]
    # for task in bob_tasks:
    #     task['transaction']['from'] = bob_addr_str
        
    # # 2.随机合并
    # merged_sequence = []
    # while alice_tasks or bob_tasks:
    #     available_lists = []
    #     if alice_tasks: available_lists.append(alice_tasks)
    #     if bob_tasks: available_lists.append(bob_tasks)
    #     if not available_lists: break
            
    #     chosen_list = random.choice(available_lists)
    #     merged_sequence.append(chosen_list.pop(0))
        
    # 3.执行序列
    for i, execution_input in enumerate(merged_sequence):
        tx_data = execution_input['transaction']
        user_addr_str = tx_data['from']
        user_name = "Alice" if user_addr_str == alice_addr_str else "Bob"
        
        try:
            # execute_and_log(execution_input, user_name, f"B-{i}")
            sender_addr_canon = to_canonical_address(user_addr_str)
            nonce = env.instrumented_evm.vm.state.get_nonce(sender_addr_canon)
            tx = env.instrumented_evm.vm.create_unsigned_transaction(
                nonce=nonce, gas_price=0, gas=tx_data['gaslimit'],
                to=to_canonical_address(tx_data['to']), value=tx_data['value'],
                data=decode_hex(tx_data['data'])
            )
            spoofed_tx = SpoofTransaction(tx, from_=sender_addr_canon)
            target_address = tx_data['to']
            target_contract_name = "UnknownContract"
            for name, address in settings.DEPLOYED_CONTRACT_ADDRESS.items():
                if address.lower() == target_address.lower():
                    target_contract_name = name
                    break
            
            func_name = "UnknownFunction"
            if target_contract_name in generator_function_maps:
                contract_map = generator_function_maps.get(target_contract_name, {})
                selector = tx_data['data'][:10]
                func_name = contract_map.get(selector, f"UnknownFuncIn_{target_contract_name}({selector})")

            
            result_computation = env.instrumented_evm.vm.state.apply_transaction(spoofed_tx)
            status = get_revert_reason(result)
            # if status == "FAILURE":
            # print(f"DEBUG: [B-{i}] Tx from {user_name}. Status: {status},function: {func_name},profit:{_get_user_state(env, user_addr_str, contracts_to_check)}")
            if user_name ==  "Alice":
                tx_data = task['transaction']
                func_hash = tx_data.get('data', '')[:10]
                
                # 构建当前事件戳
                event_stamp = (func_hash, alice_event_counter[func_hash])
                alice_event_counter[func_hash] += 1
                # 从“理想地图”中，查找同一个事件戳对应的“理想状态”
                ideal_state_alice = ideal_trajectory_map.get(event_stamp)
                actual_state_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
                actual_state_bob = _get_user_state(env, bob_addr_str, contracts_to_check)
                if ideal_state_alice:
                    step_score =  _compare_scenarios(initial_state_bob, ideal_state_alice, actual_state_alice, actual_state_bob)
                    if step_score > 0:
                        vulnerability_score = step_score
                        flag = 1
                        print("[*] Vulnerability found, terminating scenario B early.")
                        break 

        except Exception as e:
            pass
            # print(f"DEBUG: [B-{i}] Tx from {user_name}. Status: FAILED (Exception: {e})")

    if flag == 0:
        state_B_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
        state_B_bob = _get_user_state(env, bob_addr_str, contracts_to_check)
        vulnerability_score = _compare_scenarios(initial_state_alice, initial_state_bob, state_A_alice, state_A_bob, state_B_alice, state_B_bob)

    flag = 0
    # print("\n")

    # print(f"DEBUG: Vulnerability Score = {vulnerability_score}")
    state_distance = _calculate_state_distance(initial_state_alice, state_A_alice)
    # print(f"DEBUG: State Distance calculated: {state_distance}")
    env.results['state_distance'] = state_distance

    if vulnerability_score > 0:
        print("\n" + "="*80)
        print(f"DEBUG: Analyzing Individual with hash: {indv.hash}")
        print(f"DEBUG: Initial States -> Alice: {initial_state_alice}, Bob: {initial_state_bob}")
        print(f"DEBUG: Scenario A Final States -> Alice: {state_A_alice}, Bob: {state_A_bob}")
        print(f"DEBUG: Scenario B Final States -> Alice: {state_B_alice}, Bob: {state_B_bob}")
        print(f"DEBUG: Vulnerability Score = {vulnerability_score}")
    
    if vulnerability_score > 0:
        env.results['vulnerability_score'] = vulnerability_score 
        
        with open("vulnerabilities.log", "w") as f: 
            print("\n" + "!"*20 + " VULNERABILITY DETECTED! Logging to vulnerabilities.log and exiting... " + "!"*20)
            
            f.write("="*50 + "\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write(f"Individual Hash: {indv.hash}\n")
            f.write(f"Vulnerability Score: {vulnerability_score}\n")

            generator_function_maps = {}
            all_generators = [indv.generator] + indv.other_generators
            for gen in all_generators:
                if gen.interface_mapper:
                    gen_map = {h: sig for sig, h in gen.interface_mapper.items()}
                    generator_function_maps[gen.contract_name] = gen_map

            f.write("Decoded Function Sequence (executed in Scenario A):\n")
            readable_sequence = []
            for execution_input in final_sequence:
                tx = execution_input['transaction']
                target_address = tx['to']
                
                target_contract_name = "UnknownContract"
                if hasattr(settings, 'DEPLOYED_CONTRACT_ADDRESS'):
                    for name, address in settings.DEPLOYED_CONTRACT_ADDRESS.items():
                        if address.lower() == target_address.lower():
                            target_contract_name = name
                            break
                
                func_name = "UnknownFunction"
                if target_contract_name in generator_function_maps:
                    contract_map = generator_function_maps.get(target_contract_name, {})
                    selector = tx['data'][:10]
                    func_name = contract_map.get(selector, f"UnknownFunc({selector})")
                

                readable_sequence.append(f"{target_contract_name}.{func_name}")
            
            f.write(pformat(readable_sequence) + "\n")
            f.write("Underlying Chromosome (Gene):\n")
            f.write(pformat(indv.chromosome) + "\n")      
            f.write(f"Initial States:\n  Alice: {initial_state_alice}\n  Bob:   {initial_state_bob}\n")
            f.write(f"Scenario A Final States:\n  Alice: {state_A_alice}\n  Bob:   {state_A_bob}\n")
            f.write(f"Scenario B Final States:\n  Alice: {state_B_alice}\n  Bob:   {state_B_bob}\n\n")

        sys.exit(0)
    
    return float(vulnerability_score)


    # # 场景A 
    # env.instrumented_evm.restore_from_snapshot()
    # for i, execution_input in enumerate(final_sequence):
    #     current_input = deepcopy(execution_input)
    #     current_input['transaction']['from'] = alice_addr_str
    #     tx_data = current_input['transaction']['data']
    #     selector = tx_data[:10] if tx_data.startswith("0x") else "0x" + tx_data[:8]
    #     func_name = env.function_map.get(selector, f"Unknown/Fallback({selector})")
    #     result = env.instrumented_evm.deploy_transaction(current_input, gas_price=0)
    #     status = "SUCCESS" if not result.is_error else f"FAILED ({result._error})"
    #     # print(f"DEBUG: [A-{i}] Tx from Alice, func: {func_name}, Status: {status}")
    # state_A_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
    # state_A_bob = _get_user_state(env, bob_addr_str, contracts_to_check)
    # # print("\n--- Scenario A Final Asset States ---")
    # # print(f"Alice's Final Assets (Scenario A):{state_A_alice['assets']}")
    # # print(f"Bob's Final Assets (Scenario A):{state_A_bob['assets']}")
    # # print("-------------------------------------\n")
    # # 场景B
    # env.instrumented_evm.restore_from_snapshot()
    # alice_tasks = [deepcopy(x) for x in final_sequence]; [t['transaction'].update({'from': alice_addr_str}) for t in alice_tasks]
    # bob_tasks = [deepcopy(x) for x in final_sequence]; [t['transaction'].update({'from': bob_addr_str}) for t in bob_tasks]
    # merged_sequence = []
    # while alice_tasks or bob_tasks:
    #     chosen_list = random.choice([l for l in [alice_tasks, bob_tasks] if l])
    #     merged_sequence.append(chosen_list.pop(0))
    # for i, execution_input in enumerate(merged_sequence):
    #     user_name = "Alice" if execution_input['transaction']['from'] == alice_addr_str else "Bob"
    #     tx_data = execution_input['transaction']['data']
    #     selector = tx_data[:10] if tx_data.startswith("0x") else "0x" + tx_data[:8]
    #     func_name = env.function_map.get(selector, f"Unknown/Fallback({selector})")
    #     result = env.instrumented_evm.deploy_transaction(execution_input, gas_price=0)
    #     status = "SUCCESS" if not result.is_error else f"FAILED ({result._error})"
    #     # print(f"DEBUG: [B-{i}] Tx from {user_name}, func: {func_name}, Status: {status}")
    # state_B_alice = _get_user_state(env, alice_addr_str, contracts_to_check)
    # state_B_bob = _get_user_state(env, bob_addr_str, contracts_to_check)
    # # print(f"DEBUG: Scenario B Final States -> Alice: {state_B_alice}, Bob: {state_B_bob}")
    # # print("\n--- Scenario B Final Asset States ---")
    # # print("Alice's Final Assets (Scenario B):")
    # # pprint(state_B_alice['assets'])
    # # print("Bob's Final Assets (Scenario B):")
    # # pprint(state_B_bob['assets'])
    # # print("-------------------------------------\n")



        # template_filepath = "./current_fuzz_sequence.json"
    # final_sequence = []

    # if os.path.exists(template_filepath):
    #     # print(f"!!! DEBUG: Found sequence template. Engaging context-aware template-based Fuzzing. !!!")
    #     try:
    #         with open(template_filepath, 'r') as f:
    #             sequence_template = json.load(f)
            
    #         template_indv = type(indv)(generator=indv.generator, other_generators=indv.other_generators)
    #         new_chromosome = []
            
    #         for task in sequence_template:
    #             target_contract_name = task['contract']
    #             func_sig = task['signature']
                
    #             # print(f"DEBUG:   -> Generating gene for task: {target_contract_name}.{func_sig}")
    #             target_generator = None
    #             # 1. 首先检查主合约的 generator
    #             if target_contract_name == indv.generator.contract_name:
    #                 target_generator = indv.generator
    #             else:
    #                 # 2. 如果不是主合约，就去依赖合约的 generator 列表中查找
    #                 target_generator = next((g for g in indv.other_generators if g.contract_name == target_contract_name), None)

    #             if not target_generator:
    #                 print(f"!! WARNING: Could not find a generator for contract '{target_contract_name}'. Skipping.")
    #                 continue
                
    #             # 3. 使用我们找到的、正确的 Generator 来创建交易
    #             try:
    #                 func_hash, arg_types = target_generator.get_specific_function_with_argument_types(func_sig)
    #                 gene_list = target_generator.generate_individual(func_hash, arg_types)
    #                 if gene_list:
    #                     new_chromosome.append(gene_list[0])
    #             except KeyError:
    #                 print(f"!! WARNING: Signature '{func_sig}' not found in '{target_contract_name}' generator's interface. Skipping.")
    #             except Exception as e:
    #                 print(f"!! ERROR generating gene for '{func_sig}': {e}")

    #         if new_chromosome:
    #             template_indv.init(chromosome=new_chromosome)
    #             final_sequence = template_indv.decode()
    #     except Exception as e:
    #         print(f"!! FATAL ERROR while processing sequence template: {e}"); return 0.0
            
    # else: # 完全随机模式
    #     final_sequence = indv.decode()
    
    # if not final_sequence:
    #     print("DEBUG: No valid sequence to test. Skipping."); return 0.0
    # fuzzer_sequence = indv.decode()
    # if fuzzer_sequence is None: fuzzer_sequence = []
    # golden_seed_filepath = "./golden_seed.json"
    # final_sequence = []
    
    # if os.path.exists(golden_seed_filepath):
    #     # print(f"!!! DEBUG: Found Golden Seed file. Injecting seed sequence. !!!")
    #     try:
    #         with open(golden_seed_filepath, 'r') as f:
    #             seed_template = json.load(f)
            
    #         # 将 JSON 模板编码为 Fuzzer 的 solution 格式
    #         seed_sequence = []
    #         for call in seed_template:
    #             # a. 获取目标合约的真实地址
    #             target_contract_name = call['contract']
    #             target_address = settings.DEPLOYED_CONTRACT_ADDRESS.get(target_contract_name)
    #             if not target_address:
    #                 print(f"!! WARNING: Could not find deployed address for '{target_contract_name}' in seed. Skipping.")
    #                 continue

    #             # b. 编码交易
    #             func_sig = call['function']
    #             selector = "0x" + function_signature_to_4byte_selector(func_sig).hex()
    #             arg_types = call.get('arg_types', [])
    #             args_template = call.get('args', [])
                
    #             # c. 智能替换占位符 (例如，将合约名替换为地址)
    #             args = []
    #             for arg_template in args_template:
    #                 if isinstance(arg_template, str) and arg_template in settings.DEPLOYED_CONTRACT_ADDRESS:
    #                     args.append(settings.DEPLOYED_CONTRACT_ADDRESS[arg_template])
    #                 else:
    #                     args.append(arg_template)

    #             typed_args = [int(arg) if 'int' in arg_types[i] else arg for i, arg in enumerate(args)]
    #             encoded_args = encode_abi(arg_types, typed_args).hex()
    #             tx_data = selector + encoded_args
    #             value_str = call.get('value', "0 wei"); value_in_wei = Web3.toWei(value_str.split()[0], value_str.split()[1])
                
    #             seed_sequence.append({'transaction':{'from':'0xPLACEHOLDER','to':target_address,'value':value_in_wei,'data':tx_data,'gaslimit':settings.GAS_LIMIT}, 'block': {}, 'global_state': {}, 'environment': {}})
            
    #         final_sequence = seed_sequence + fuzzer_sequence
    #     except Exception as e:
    #         print(f"!! WARNING: Failed to process golden seed: {e}. Falling back.")
    #         final_sequence = fuzzer_sequence
    # else:
    #     final_sequence = fuzzer_sequence
        
    # if not final_sequence: return 0.0
    # else:
    #     final_sequence = indv.decode()
    
    # if not final_sequence: return 0.0