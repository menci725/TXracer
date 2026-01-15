import json
from collections import Counter
import sys

def summarize_missed_contracts(results_filepath):
    """
    读取分析结果文件，并统计漏报合约的出现频率。
    """
    try:
        with open(results_filepath, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: Results file not found at '{results_filepath}'", file=sys.stderr)
        return
    except json.JSONDecodeError:
        print(f"[!] Error: Could not decode JSON from '{results_filepath}'. Is the file valid?", file=sys.stderr)
        return

    missed_cases = data.get("missed_cases_details")
    if not isinstance(missed_cases, list):
        print("[!] 'missed_cases_details' key not found or is not a list in the JSON file.")
        return

    if not missed_cases:
        print("[+] Congratulations! No missed cases found.")
        return

    # 使用 Counter 来自动计数
    contract_counts = Counter()

    # 遍历所有漏报的案例
    for case in missed_cases:
        involved_contracts = case.get("involved_contracts", [])
        
        # 提取合约的基础名称 (去掉可能存在的 "-0x...")
        base_contract_names = set()
        for contract_name_with_address in involved_contracts:
            base_name = contract_name_with_address.split('-')[0]
            base_contract_names.add(base_name)
        
        # 为这个案例中涉及的每个唯一的合约名，计数+1
        # 使用 set 可以避免在同一个案例中（例如跨合约调用自己）重复计数
        for name in base_contract_names:
            contract_counts[name] += 1
            
    # --- 结果汇报 ---
    print("=" * 60)
    print("      Frequency Analysis of Missed Contracts")
    print("=" * 60)
    
    total_missed_contracts = len(contract_counts)
    print(f"\n[*] Found {total_missed_contracts} unique contracts involved in missed cases.")
    
    print("\n--- Missed Contract Frequency (Most frequent first) ---")
    
    # 按出现次数从高到低排序并打印
    # most_common() 返回一个 (元素, 次数) 的元组列表
    for contract, count in contract_counts.most_common():
        print(f"{contract:<40} | Appears in {count} missed cases")
        
    print("\n" + "=" * 60)


if __name__ == "__main__":
    # 默认的分析结果文件名
    DEFAULT_RESULTS_FILE = "benchmark_analysis_results.json"
    
    # 允许从命令行传入文件名
    filepath = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RESULTS_FILE
    
    summarize_missed_contracts(filepath)