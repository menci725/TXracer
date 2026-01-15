import sys
import json
import argparse
import shutil
from collections import defaultdict
from slither import Slither
from slither.exceptions import SlitherError
from slither.core.declarations import Function

HIGH_VALUE_KEYWORDS = [
    'burn', 'mint', 'swap', 'deposit', 'withdraw', 'claim', 'stake', 
    'unstake', 'redeem', 'borrow', 'repay', 'liquidate', 'purchase','approve','addLiquidity'
]

KNOWN_SOLIDITY_BASE_TYPES = {
    'uint', 'uint8', 'uint16', 'uint32', 'uint64', 'uint128', 'uint256',
    'int', 'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
    'bytes', 'bytes1', 'bytes2', 'bytes4', 'bytes8', 'bytes16', 'bytes32',
    'string', 'bool', 'address'
}


class SequenceGenerator:
    def __init__(self, slither_instance):
        self.slither = slither_instance
        self.functions = []
        self.all_fuzzable_contracts = [c.name for c in self.slither.contracts if c.contract_kind == 'contract']
        self._analysis_cache = {}


    def _get_recursive_reads_and_writes(self, func_obj):
        cache_key = func_obj.full_name
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]

        # 1. 获取当前函数的直接读写
        reads = {var.canonical_name for var in func_obj.state_variables_read}
        writes = {var.canonical_name for var in func_obj.state_variables_written}

        # 2. 递归分析内部调用 (internal_calls)
        if hasattr(func_obj, 'internal_calls'):
            for internal_callee in func_obj.internal_calls:
                if isinstance(internal_callee, Function):
                    callee_reads, callee_writes = self._get_recursive_reads_and_writes(internal_callee)
                    reads.update(callee_reads)
                    writes.update(callee_writes)

        # 3. 分析外部调用 (high_level_calls)
        if hasattr(func_obj, 'high_level_calls'):
            for contract_called, function_called, _ in func_obj.high_level_calls:
                # function_called 可能是 Function 对象或类似对象
                if hasattr(function_called, 'state_variables_read') and function_called.state_variables_read:
                    # 如果外部调用读取了状态变量，将其归类为一次读取
                    # 使用 contract.function 格式来表示外部读取
                    for var in function_called.state_variables_read:
                         reads.add(f"{contract_called.name}.{var.name}")
                
                if hasattr(function_called, 'state_variables_written') and function_called.state_variables_written:
                    # 如果外部调用写入了状态变量，将其归类为一次写入
                    for var in function_called.state_variables_written:
                         writes.add(f"{contract_called.name}.{var.name}")

        self._analysis_cache[cache_key] = (reads, writes)
        return reads, writes

    def analyze_contracts(self):
        print("[*] Step 1: Analyzing functions and assigning initial scores...")
        self._analysis_cache = {}
        
        for contract in self.slither.contracts:
            if contract.is_interface:
                continue
                
            for function in contract.functions:
                if function.is_constructor or function.visibility not in ["public", "external"]:
                    continue
                
                # 1. 获取函数名
                func_name = function.name
                abi_compatible_param_types = []
                # 2. 获取与 ABI 完全一致的参数类型字符串列表
                param_types = [str(p.type) for p in function.parameters]

                for param in function.parameters:
                    param_type_str = str(param.type) # e.g., "IHegicPool" or "uint256[]"
                    
                    # b. 检查其“基础类型”是否在我们的白名单中
                    base_type = param_type_str.split('[')[0] # 提取数组的基础类型
                    
                    if base_type in KNOWN_SOLIDITY_BASE_TYPES:
                        # 如果是已知的基础类型，就直接使用
                        abi_compatible_param_types.append(param_type_str)
                    else:
                        # c. 如果是未知的复杂类型 (接口, 合约, 结构体), 就默认它是 address
                        print(f"  - INFO: Unrecognized type '{param_type_str}' for param '{param.name}'. Defaulting to 'address'.")
                        # 保持数组结构，例如 "MyStruct[]" -> "address[]"
                        abi_compatible_param_types.append(param_type_str.replace(base_type, 'address'))

                
                # 3. 手动构建一个与 CrossFuzz 内部 get_function_signature_mapping
                #    *完全一致* 的签名字符串
                clean_signature = f"{func_name}({','.join(abi_compatible_param_types)})"
                
                
                has_tuple_param = False
                for param_type in param_types:
                    if "tuple" in param_type:
                        has_tuple_param = True
                        break
                if has_tuple_param:
                    print(f"  - Skipping complex function with tuple/struct parameter: {function.canonical_name}")
                    continue

                # 逻辑增强
                
                # 1. 获取Slither的直接分析结果（这保留了你原始策略的核心）
                direct_reads = {var.canonical_name for var in function.state_variables_read}
                direct_writes = {var.canonical_name for var in function.state_variables_written}
                
                # 2. 调用辅助函数，获取所有通过内部调用产生的间接读写
                indirect_reads, indirect_writes = self._get_indirect_reads_writes_from_internal_calls(function)
                
                # 3. 合并两个集合，得到最终的、最全的读写集合
                all_reads = direct_reads.union(indirect_reads)
                all_writes = direct_writes.union(indirect_writes)
                

                # 使用合并后的集合，应用原始的评分规则 
                intrinsic_score = 0.0
                if function.payable: intrinsic_score += 20.0
                if any(isinstance(c, tuple) and len(c) > 3 and isinstance(c[3], dict) and c[3].get('value') for c in function.high_level_calls):
                    intrinsic_score += 15.0
                
                # 使用 all_writes 和 all_reads 来计算分数
                intrinsic_score += 5.0 * len(all_writes)
                intrinsic_score += 1.0 * len(all_reads)

                func_name_lower = function.name.lower()
                for keyword in HIGH_VALUE_KEYWORDS:
                    if keyword in func_name_lower:
                        intrinsic_score += 5 
                        # print(f"  - Found high-value keyword '{keyword}' in: {function.canonical_name} (+5 score)")
                        break

                self.functions.append({
                    "obj": function, "signature": clean_signature, "canonical_name": function.canonical_name,
                    "intrinsic_score": intrinsic_score,
                    "score": intrinsic_score,
                    "writes": all_writes, 
                    "reads": all_reads,  
                    "contract": contract.name
                })

        # 价值传播
        print("\n[*]   - Phase 2: Propagating scores through the call graph (Value Propagation)...")
        DECAY_FACTOR = 0.5
        MAX_ITERATIONS = 5
        
        func_obj_map = {f['obj']: f for f in self.functions}

        for iteration in range(MAX_ITERATIONS):
            updated_in_pass = False
            for caller_func_info in self.functions:
                caller_func_obj = caller_func_info["obj"]
                
                propagated_score_from_callees = 0
                if hasattr(caller_func_obj, 'high_level_calls'):
                    # 遍历 high_level_calls 列表中的每个元组
                    for call_tuple in caller_func_obj.high_level_calls:
                        # 检查元组是否足够长并且第二个元素是我们需要的 Function 对象
                        if len(call_tuple) > 1 and isinstance(call_tuple[1], Function):
                            callee_func_obj = call_tuple[1] # 安全地提取函数对象
                            
                            callee_func_info = func_obj_map.get(callee_func_obj)
                            
                            if callee_func_info:
                                propagated_score_from_callees += callee_func_info["score"] * DECAY_FACTOR
                
                potential_new_score = caller_func_info["intrinsic_score"] + propagated_score_from_callees
                
                if potential_new_score > caller_func_info["score"]:
                    caller_func_info["score"] = potential_new_score
                    updated_in_pass = True

            if not updated_in_pass:
                print(f"[*]     - Score propagation converged after {iteration + 1} iterations.")
                break
        
        print("\n[*] --- Final Function Scores (after propagation) ---")
        sorted_by_final_score = sorted(self.functions, key=lambda x: x['score'], reverse=True)
        for func_info in sorted_by_final_score[:15]:
            print(f"  - {func_info['canonical_name']:<40} Final Score: {func_info['score']:.2f} (Intrinsic: {func_info['intrinsic_score']:.2f})")

    def _get_indirect_reads_writes_from_internal_calls(self, func_obj):
        """
        仅递归分析内部调用链，获取所有间接的读写。
        """
        # 使用 full_name 作为更可靠的缓存键
        cache_key = f"internal_{func_obj.full_name}"
        if cache_key in self._analysis_cache:
            return self._analysis_cache[cache_key]

        indirect_reads = set()
        indirect_writes = set()

        if hasattr(func_obj, 'internal_calls'):
            for internal_callee in func_obj.internal_calls:
                # 确保我们只递归进入真正的合约函数
                if isinstance(internal_callee, Function):
                    # 1. 获取被调用函数本身的直接读写
                    callee_direct_reads = {var.canonical_name for var in internal_callee.state_variables_read}
                    callee_direct_writes = {var.canonical_name for var in internal_callee.state_variables_written}
                    
                    indirect_reads.update(callee_direct_reads)
                    indirect_writes.update(callee_direct_writes)

                    # 2. 递归获取被调用函数的间接读写
                    deeper_reads, deeper_writes = self._get_indirect_reads_writes_from_internal_calls(internal_callee)
                    indirect_reads.update(deeper_reads)
                    indirect_writes.update(deeper_writes)

        self._analysis_cache[cache_key] = (indirect_reads, indirect_writes)
        return indirect_reads, indirect_writes

    def generate_sequence(self):
        """
        根据数据依赖关系（写后读）和分数，生成最终的函数调用序列。
        """
        print("\n[*] Step 2: Generating sequence based on scores and data dependencies...")
        
        # 1. 按分数从高到低对函数进行初始排序
        sorted_functions = sorted(self.functions, key=lambda x: x['score'], reverse=True)
        
        final_sequence_objects = []
        satisfied_writes = set()
        stuck_counter = 0

        while sorted_functions:
            function_added_in_pass = False
            
            for func_info in list(sorted_functions):
                # 检查此函数的“读”依赖是否已满足
                if func_info["reads"].issubset(satisfied_writes):
                    # 依赖满足，将完整的函数信息对象添加到最终序列
                    final_sequence_objects.append({
                        "contract": func_info['contract'],
                        "signature": func_info['signature'],
                        "score": func_info['score']
                    })
                    print(f"  - Adding to sequence: {func_info['canonical_name']} (Dependencies met)")
                    
                    satisfied_writes.update(func_info["writes"])
                    sorted_functions.remove(func_info)
                    function_added_in_pass = True

            # 防止死循环的“打破僵局”逻辑
            if not function_added_in_pass and sorted_functions:
                stuck_counter += 1
                if stuck_counter > 1:
                    highest_score_func = sorted_functions.pop(0)
                    final_sequence_objects.append({
                        "contract": highest_score_func['contract'],
                        "signature": highest_score_func['signature'],
                        "score": highest_score_func['score']
                    })
                    satisfied_writes.update(highest_score_func["writes"])
                    print(f"  - Breaking dependency cycle by force-adding: {highest_score_func['canonical_name']}")
                    stuck_counter = 0

        return final_sequence_objects

def main():
    parser = argparse.ArgumentParser(
        description="Generate an intelligent function sequence template for CrossFuzz based on data dependencies and heuristics."
    )
    parser.add_argument("solidity_file", help="Path to the Solidity source file (.sol).")
    parser.add_argument(
        "-o", "--output", 
        default="sequence_template.json", 
        help="Path to the output JSON file (default: sequence_template.json)."
    )
    parser.add_argument(
        "--solc",
        dest="solc_path",
        help="Path to the solc binary. If not provided, it will try to find a default one."
    )
    args = parser.parse_args()
    
    solc_path = args.solc_path
    if not solc_path:
        solc_path_found = shutil.which("solc")
        if solc_path_found:
            print(f"[*] --solc path not provided. Using found solc at: {solc_path_found}")
            solc_path = solc_path_found
        else:
            print("[!] --solc path not provided and could not be found automatically.", file=sys.stderr)
            sys.exit(1)

    try:
        slither = Slither(args.solidity_file, solc=solc_path)
        
        # 1. 提取所有真正的、可被 Fuzzing 的合约的名字
        all_fuzzable_contracts = [c.name for c in slither.contracts if c.contract_kind == 'contract']

        # 2. 生成序列 
        generator = SequenceGenerator(slither) 
        generator.analyze_contracts()
        sequence = generator.generate_sequence()
        
        # 3. 将所有信息打包到一个统一的配置文件中
        output_data = { "fuzz_universe": all_fuzzable_contracts, "master_sequence": sequence }
        
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2)
            
        print(f"\n[*] Successfully generated full context template at: {args.output}")


    except SlitherError as e:
        print(f"\n[!] Slither analysis failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
