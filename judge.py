import os
import sys
import json
import argparse
from pprint import pprint

def parse_command_file(filepath):
    print(f"[*] Parsing command file: {filepath}...")
    command_results = {}
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # 按空行或连续的等号分割成案例块
        case_blocks = content.split('\n\n')
        if len(case_blocks) < 2:
             # 尝试用其他分隔符
             if '===' in content:
                 case_blocks = content.split('='*80)
             else: 
                 lines = content.splitlines()
                 current_commands = []
                 for line in lines:
                     line = line.strip()
                     if not line: continue
                     current_commands.append(line)
                     if line in ["solve", "unsolve", "timeout", "error","overtime"]:
                         if len(current_commands) > 2:
                             case_name = current_commands[1]
                             result = current_commands[-1]
                             command_results[case_name] = result
                         current_commands = []
                 print(f"[*] Parsed {len(command_results)} cases from command file.")
                 return command_results


        for block in case_blocks:
            lines = [line.strip() for line in block.split('\n') if line.strip()]
            if len(lines) > 2:
                # 假设第二行总是合约名，最后一行总是结果
                case_name = lines[1]
                result = lines[-1]
                if result in ["solve", "unsolve", "timeout", "error","too large","overtime"]:
                    command_results[case_name] = result

    except FileNotFoundError:
        print(f"[!] FATAL: Command file not found at '{filepath}'", file=sys.stderr)
        return None
    
    print(f"[*] Parsed {len(command_results)} cases from command file.")
    return command_results

def analyze_benchmark(command_results, attack_dir):
    """
    遍历 attack/ 目录，与 command.txt 的结果进行比对。
    """
    print(f"[*] Analyzing benchmark results against attack directory: {attack_dir}...")
    
    if not os.path.isdir(attack_dir):
        print(f"[!] FATAL: Attack directory not found at '{attack_dir}'", file=sys.stderr)
        return None

    total_json_files = 0
    detected_cases_count = 0
    missed_cases = []
    i = 0
    
    toolarge_cases = []
    overtime_cases = []
    # ---

    for filename in os.listdir(attack_dir):
        if not filename.endswith(".json"):
            continue
            
        total_json_files += 1
        filepath = os.path.join(attack_dir, filename)
        
        is_detected = False
        is_toolarge = False 
        is_overtime = False
        
        contracts_in_this_case = []
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            metadata = data.get("contractMetadatas", {})
            for contract_info in metadata.values():
                name = contract_info.get("name")
                if name:
                    contracts_in_this_case.append(name)
            
            # 检查这个案例是否被检测出，或者是否因为过大而被跳过
            for command_case_name, result in command_results.items():
                command_contract_name = command_case_name.split('-')[0]
                if command_contract_name in contracts_in_this_case:
                    if 'solve' in result:
                        is_detected = True
                        # i = i + 1
                        # print(i)
                        break # 只要有一个solve，就判定为检出
                    if 'too large' in result:
                        is_toolarge = True
                    
                    if "overtime" in result:
                        is_overtime = True
            
        except Exception as e:
            print(f"[!] Warning: Could not process file '{filepath}': {e}", file=sys.stderr)

        if is_detected:
            detected_cases_count += 1
        elif is_toolarge:
            # 如果没有被solve，但至少有一个合约被标记为too_large，则归类到这里
            toolarge_cases.append({
                "json_file": filename,
                "involved_contracts": contracts_in_this_case,
            })
        elif is_overtime:
            overtime_cases.append({
                "json_file": filename,
                "involved_contracts": contracts_in_this_case,
            })

        else:
            # 只有在既没有被solve，也没有被标记为too_large时，才算作真正的漏报
            missed_case_info = {
                "json_file": filename,
                "involved_contracts": contracts_in_this_case,
                "command_results_for_these_contracts": {}
            }
            for contract_name in contracts_in_this_case:
                found = False
                for command_case_name, result in command_results.items():
                    if command_case_name.startswith(contract_name):
                        missed_case_info["command_results_for_these_contracts"][command_case_name] = result
                        found = True
                if not found:
                    missed_case_info["command_results_for_these_contracts"][contract_name] = "NOT_FOUND_IN_COMMAND_TXT"

            missed_cases.append(missed_case_info)
            
    return total_json_files, detected_cases_count, missed_cases, toolarge_cases,overtime_cases


def main():
    parser = argparse.ArgumentParser(description="Analyze CrossFuzz results against a benchmark.")
    parser.add_argument("command_file", help="Path to the command.txt file.")
    parser.add_argument("attack_dir", help="Path to the directory containing attack JSON files.")
    
    args = parser.parse_args()

    command_results = parse_command_file(args.command_file)
    if command_results is None: sys.exit(1)

    analysis_result = analyze_benchmark(command_results, args.attack_dir)
    if analysis_result is None: sys.exit(1)
        
    total_files, detected_files, missed_cases, toolarge_cases, overtime_cases = analysis_result
    
    total_analyzable_files = total_files - len(toolarge_cases) - len(overtime_cases)
    
    recall_over_total = (detected_files / total_files) * 100 if total_files > 0 else 0
    recall_over_analyzable = (detected_files / total_analyzable_files) * 100 if total_analyzable_files > 0 else 0
    
    # print("\n" + "="*80)
    # print("[*] BENCHMARK ANALYSIS COMPLETE")
    # print("="*80)
    
    # print(f"\n[+] --- SUMMARY ---")
    # print(f"Total Attack Cases (JSON files): {total_files}")
    # print(f"Detected Cases ('solve' status matched): {detected_files}")
    # print(f"Skipped due to size ('too_large' status): {len(toolarge_cases)}")
    # print(f"Missed Cases (unsolve/error/timeout): {len(missed_cases)}")
    # print("-" * 30)
    # print(f"DETECTION RATE (RECALL) over ALL cases: {recall_over_total:.2f}%")
    # print(f"DETECTION RATE (RECALL) over ANALYZABLE cases: {recall_over_analyzable:.2f}%")

    # if missed_cases:
    #     print("\n\n[+] --- DETAILED ANALYSIS OF MISSED CASES ---")
    #     pprint(missed_cases)
        
    # if toolarge_cases:
    #     print("\n\n[+] --- LIST OF CASES SKIPPED DUE TO SIZE ---")
    #     pprint(toolarge_cases)
        
    # print("\n" + "="*80)
    
    output_data = {
        "summary": {
            "total_cases": total_files,
            "detected_cases": detected_files,
            "missed_cases_count": len(missed_cases),
            "toolarge_cases_count": len(toolarge_cases),
            "overtime_cases_count": len(overtime_cases),
            "total_analyzable_cases": total_analyzable_files,
            "recall_over_total": f"{recall_over_total:.2f}%",
            "recall_over_analyzable": f"{recall_over_analyzable:.2f}%"
        },
        "missed_cases_details": missed_cases,
        "toolarge_cases_details": toolarge_cases
    }
    output_file = "benchmark_analysis_results.json"
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=4)
    print(f"[*] Detailed analysis saved to {output_file}")


if __name__ == "__main__":
    main()