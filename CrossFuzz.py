# import json
# import shutil
# import sys
# import os

# import config
# from comp import analysis_depend_contract, analysis_main_contract_constructor


# def run(_file_path: str, _main_contract, solc_vers
# ion: str, evm_version: str, timeout: int, _depend_contracts: list,
#         max_individual_length: int, _constructor_args: list, _solc_path: str, _duplication: str = '0'):
#     depend_contracts_str = " ".join(_depend_contracts)
#     constructor_str = " ".join(_constructor_args)
#     cmd = (f"{PYTHON} {FUZZER}"
#            f" -s {_file_path}"
#            f" -c {_main_contract}"
#            f" --solc v{solc_version}"
#            f" --evm {evm_version}"
#            f" -t {timeout}"
#            f" --result fuzzer/result/res.json"
#            f" --cross-contract 1"
#            f" --open-trans-comp 1"
#            f" --depend-contracts {depend_contracts_str}"
#            f" --constructor-args {constructor_str}"
#            f" --constraint-solving 1"
#            f" --max-individual-length {max_individual_length}"
#            f" --solc-path-cross {_solc_path}"
#            f" --p-open-cross 80"
#            f" --cross-init-mode 1"
#            f" --trans-mode 1"
#            f" --duplication {_duplication}")
#     print(cmd)
#     # os.popen(cmd).readlines()  # run CrossFuzz.py
#     os.system(cmd)
#     return "fuzzer/result/res.json"


# def test_run():
#     # absolute path
#     _file_path = "./examples/T.sol"
#     _main_contract = "E"
#     solc_version = "0.4.26"
#     evm_version = "byzantium"
#     timeout = 10
#     solc_path = config.SOLC_BIN_PATH
#     _depend_contracts, _sl = analysis_depend_contract(file_path=_file_path, _contract_name=_main_contract,
#                                                       _solc_version=solc_version, _solc_path=solc_path)
#     max_individual_length = 10
#     _constructor_args = analysis_main_contract_constructor(file_path=_file_path, _contract_name=_main_contract, sl=_sl)
#     run(_file_path, _main_contract, solc_version, evm_version, timeout, _depend_contracts, max_individual_length,
#         _constructor_args, _solc_path=config.SOLC_BIN_PATH)


# def cli():
#     p = sys.argv[1]  # sol file path, which is the file path to be fuzzed
#     c_name = sys.argv[2]  # contract name, which is the contract to be fuzzed
#     solc_version = sys.argv[3]  # only support 0.4.24, 0.4.26, 0.6.12, 0.8.4
#     max_trans_length = int(sys.argv[4])  # max transaction length, e.g., 10
#     fuzz_time = int(sys.argv[5])  # fuzz time, e.g., 60(s)
#     res_saved_path = sys.argv[6]  # e.g., ./xxxx.json
#     solc_path = sys.argv[7]  # solc path
#     constructor_params_path = sys.argv[8]  # e.g., Auto or "examples/p.json"
#     trans_duplication = sys.argv[9]  # e.g., 0 if you don't want to duplicate transactions, otherwise 1

#     _depend_contracts, _sl = analysis_depend_contract(file_path=p, _contract_name=c_name, _solc_version=solc_version,
#                                                       _solc_path=solc_path)
#     if len(_depend_contracts) <= 0:
#         print("No depend contracts")
#         sys.exit(-1)
#     if constructor_params_path != "auto":
#         _constructor_args = []
#         for p_name, p_detail in json.load(open(constructor_params_path, "r", encoding="utf-8")).items():
#             _constructor_args.append(f"{p_name} {p_detail['type']} {p_detail['value']}")
#     else:
#         _constructor_args = analysis_main_contract_constructor(file_path=p, _contract_name=c_name, sl=_sl)
#     if _constructor_args is None:
#         print("No constructor")
#         sys.exit(-2)
#     res = run(p, c_name, solc_version, "byzantium",
#               fuzz_time, _depend_contracts, max_trans_length, _constructor_args, _solc_path=solc_path,
#               _duplication=trans_duplication)
#     shutil.copyfile(res, res_saved_path)  # move result json file to the specified path


# if __name__ == "__main__":
#     PYTHON = "python3"  # your python3 path
#     FUZZER = "fuzzer/main.py"  # your fuzzer path in this repo
#     cli()
#     # test_run()

import json
import shutil
import sys
import os
import argparse 
from web3 import Web3

import config
from comp import analysis_depend_contract, analysis_main_contract_constructor

SOLC_TO_EVM_VERSION = {
    '0.8': 'london', 
    '0.7': 'istanbul',
    '0.6': 'istanbul',
    #  '0.5': 'byzantium',
     '0.5':'petersburg',
    '0.4': 'byzantium',
}

SUPPORTED_EVM_VERSIONS = {'homestead', 'byzantium', 'petersburg'}

def get_evm_version_for_solc(solc_version_str):
    """
    根据 solc 版本，返回一个 CrossFuzz 底层支持的、最合适的 EVM 版本。
    """
    if not solc_version_str: return 'byzantium'
    
    major_minor = ".".join(solc_version_str.split('.')[:2])
    ideal_evm = SOLC_TO_EVM_VERSION.get(major_minor, 'byzantium')
    
    # !! 核心修改：检查兼容性并进行优雅降级 !!
    if ideal_evm in SUPPORTED_EVM_VERSIONS:
        return ideal_evm
    else:
        # 如果理想版本太新，就降级到支持的最新版本
        print(f"[*] Warning: Ideal EVM version '{ideal_evm}' is not supported by the underlying py-evm.")
        print(f"[*] Gracefully degrading to the latest supported version: 'petersburg'.")
        return 'petersburg'

def run(_file_path: str, _main_contract: str, solc_version: str, timeout: int, _depend_contracts: list,
        max_individual_length: int, _constructor_args: list, _solc_path: str,
        _full_config_path: str = "",_sequence_template_path: str = "",
        _duplication: str = '0'):
    
    evm_version = get_evm_version_for_solc(solc_version) # 假设这个函数存在
    template_arg = f"--sequence-template {_sequence_template_path}" if _sequence_template_path and os.path.exists(_sequence_template_path) else ""

    # 构建一个命令列表，这是最健壮的方式
    command = [
        PYTHON, FUZZER,
        '-s', _file_path,
        '-c', _main_contract,
        '--solc', f'v{solc_version}',
        '--evm', evm_version,
        '-t', str(timeout),
        '--result', 'fuzzer/result/res.json',
        '--cross-contract', '1',
        '--open-trans-comp', '1',
        '--constraint-solving', '1',
        '--max-individual-length', str(max_individual_length),
        '--solc-path-cross', _solc_path,
        '--p-open-cross', '80',
        '--cross-init-mode', '1',
        '--trans-mode', '1',
        '--duplication', _duplication
    ]
    
    # 动态地、正确地添加列表类型的参数
    if _depend_contracts:
        command.append('--depend-contracts')
        command.extend(_depend_contracts) # extend 会将列表中的每个元素作为独立项添加

    if _constructor_args:
        command.append('--constructor-args')
        command.extend(_constructor_args)
        
    if _full_config_path and os.path.exists(_full_config_path):
        command.extend(['--full-constructor-config', _full_config_path])

    if _sequence_template_path and os.path.exists(_sequence_template_path):
        command.extend(['--sequence-template', _sequence_template_path])
        
    cmd_str = ' '.join(command)
    print("="*50); print("Executing Fuzzer Command:"); print(cmd_str); print("="*50)
    os.system(cmd_str)
    # os.popen(cmd_str).readlines()  # run CrossFuzz.py
    return "fuzzer/result/res.json"


# def test_run():
#     """
#     一个简单的默认测试用例，用于快速验证。
#     """
#     _file_path = "./examples/T.sol"
#     _main_contract = "E"
#     solc_version = "0.4.26"
#     evm_version = "byzantium"
#     timeout = 10
#     # 注意：这里的 solc_path 需要从 config.py 中正确获取
#     solc_path = config.SOLC_BIN_PATH.get(solc_version, "") 
#     if not solc_path:
#         print(f"Error: solc version {solc_version} not configured in config.py")
#         sys.exit(1)

#     _depend_contracts, _sl = analysis_depend_contract(file_path=_file_path, _contract_name=_main_contract,
#                                                       _solc_version=solc_version, _solc_path=solc_path)
#     if _depend_contracts is None: # 确保分析结果不为空
#         print("Error during dependency analysis in test_run. Exiting.")
#         sys.exit(1)
        
#     max_individual_length = 10
#     _constructor_args = analysis_main_contract_constructor(file_path=_file_path, _contract_name=_main_contract, sl=_sl)
#     if _constructor_args is None: # 确保构造函数参数不为空
#         _constructor_args = []
        
#     run(_file_path, _main_contract, solc_version, evm_version, timeout, _depend_contracts, max_individual_length,
#         _constructor_args, _solc_path=solc_path)


def cli():
    # 1. 使用 argparse 进行健壮的命令行解析
    parser = argparse.ArgumentParser(description="CrossFuzz - A cross-contract fuzzer for smart contracts.")
    parser.add_argument("sol_file", help="Path to the Solidity source file.")
    parser.add_argument("contract_name", help="Name of the main contract to fuzz.")
    parser.add_argument("solc_version", help="Solidity compiler version (e.g., 0.8.4).")
    parser.add_argument("max_seq_len", type=int, help="Maximum length of a transaction sequence.")
    parser.add_argument("fuzz_time", type=int, help="Fuzzing duration in seconds.")
    parser.add_argument("result_path", help="Path to save the final results JSON file.")
    parser.add_argument("solc_path", help="Absolute path to the solc binary.")
    parser.add_argument("duplication", choices=['0', '1'], help="Duplication mode (0 for off, 1 for on).")
    parser.add_argument("--constructor_config", default="auto",
                        help="Path to the constructor config JSON file. (default: 'auto')")
    parser.add_argument("--depend-contracts", nargs='+', default=[], 
                        help="A space-separated list of dependent contracts in deployment order.")
    parser.add_argument("--sequence-template",
                        help="Path to the JSON file with the function sequence template.")
    args = parser.parse_args()
    
    # 初始化汇报给元 Fuzzer 的最终分数
    final_fitness = 0.0
    res_path = "fuzzer/result/res.json" # Fuzzer 核心的默认输出路径

    try:
        print("[*] Bypassing internal dependency analysis. Relying on external context from fuzz_context.json.")
        _depend_contracts = []
        try:
            with open("fuzz_context.json", "r") as f:
                fuzz_context = json.load(f)
            fuzz_universe = fuzz_context.get("fuzz_universe", [])
            _depend_contracts = [c for c in fuzz_universe if c != args.contract_name]
            print(f"[*] Successfully loaded fuzz universe. Dependent contracts: {_depend_contracts}")
        except FileNotFoundError:
            print("[!] Warning: fuzz_context.json not found. Falling back to old internal analysis.")
            # 保留原始分析作为备用方案，增加健壮性
            _depend_contracts, _ = analysis_depend_contract(
                file_path=args.sol_file, _contract_name=args.contract_name,
                _solc_version=args.solc_version, _solc_path=args.solc_path
            )
        except Exception as e:
             print(f"[!] Error loading fuzz_context.json: {e}. Falling back to old internal analysis.")
             _depend_contracts, _ = analysis_depend_contract(
                file_path=args.sol_file, _contract_name=args.contract_name,
                _solc_version=args.solc_version, _solc_path=args.solc_path
            )

        if _depend_contracts is None:
            _depend_contracts = [] # 确保是一个列表

        # 构造函数参数处理
        print("\n[*] Step 2: Analyzing main contract constructor...")
        # 1. 依赖合约直接从命令行获取
        _depend_contracts = args.depend_contracts
        print(f"[*] Received dependent contracts from command line: {_depend_contracts}")

        # 2. 主合约的构造函数参数也完全依赖外部配置
        # full_config_path = "constructor_config.json"
        # # _constructor_args = analysis_main_contract_constructor(
        # #     file_path=args.sol_file, _contract_name=args.contract_name, sl=_sl
        # # )
        # # if _constructor_args is None: _constructor_args = []
        # _constructor_args = []

        # final_constructor_args = []
        # for i in range(0, len(_constructor_args), 3):
        #     name, type, value = _constructor_args[i:i+3]
        #     if "YA_DO_NOT_KNOW" in value:
        #         print(f"[*] Auto-analysis could not determine value for '{name}' ({type}). Replacing with default.")
        #         if 'uint' in type or 'int' in type: value = '0'
        #         elif 'bool' in type: value = 'false'
        #         elif 'string' in type: value = ''
        #         # 如果是 address/contract，comp.py 应该能正确识别，
        #         # 但以防万一，我们不能提供默认地址，而是抛出错误
        #         else:
        #             raise ValueError(f"Cannot provide a default value for complex type '{type}' for parameter '{name}'. Please use a constructor_config.json.")
        #     final_constructor_args.extend([name, type, value])


        _constructor_args = []
        if args.constructor_config.lower() != "auto":
            full_config_path = args.constructor_config
            try:
                with open(full_config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                if args.contract_name in config and 'args' in config[args.contract_name]:
                    # for arg in config[args.contract_name]['args']:
                    #     arg_type = arg['type']
                    #     arg_value = arg['value']
                    #     if arg_type == 'contract':
                    #         _constructor_args.append(f"{arg.get('name', '_')} address {arg_value}")
                    #     else:
                    #         _constructor_args.append(f"{arg.get('name', '_')} {arg_type} {arg_value}")
                    main_contract_config = config[args.contract_name]['args']
                    for arg in main_contract_config:
                        arg_name = arg.get('name', '_')
                        arg_type_from_json = arg['type']
                        arg_value = arg['value']

                        value_str = ""
                        if isinstance(arg_value, list):
                            # e.g., ["0x...", "0x..."] -> "0x...,0x..."
                            # 不带方括号，只用逗号连接
                            value_str = ",".join(map(str, arg_value))
                        else:
                            value_str = str(arg_value)
                        
                        # 这就是“翻译”的核心！
                        if arg_type_from_json == 'contract':
                            # 如果类型是 'contract'，我们告诉下游工具这是一个 'address'
                            # 并将合约名作为 'value'
                            _constructor_args.append(f"{arg_name} address {value_str}")
                        else:
                            # 对于所有其他普通类型，直接传递
                            _constructor_args.append(f"{arg_name} {arg_type_from_json} {value_str}")
            except Exception as e:
                print(f"Warning: Could not parse constructor config file: {e}")
        
        print(f"[*] Using constructor arguments for main contract: {_constructor_args}")
        
        # 3. 调用 run 函数
        res_path = run(
            args.sol_file, args.contract_name, args.solc_version,
            args.fuzz_time,
            _depend_contracts,
            args.max_seq_len,
            _constructor_args = _constructor_args,
            _solc_path=args.solc_path,
            _full_config_path=full_config_path,
             _sequence_template_path=args.sequence_template,
            _duplication=args.duplication
        )
        
        if os.path.exists(res_path):
            with open(res_path, 'r') as f:
                results = json.load(f)
            main_contract_results = results.get(args.contract_name, {})
            coverage = main_contract_results.get('code_coverage', {}).get('percentage', 0.0)
            vulnerability_score = main_contract_results.get('vulnerability_score', 0.0) 
            # final_fitness = coverage + vulnerability_score * 1000
            # shutil.copyfile(res_path, args.result_path)

            state_distance = main_contract_results.get('state_distance', 0.0)
            import math
            state_distance_score = math.log1p(state_distance) # log1p(x) = log(1+x)
            final_fitness = coverage + (vulnerability_score * 1000) + (state_distance_score * 0.1) 
            # final_fitness = coverage + (vulnerability_score * 1000)
            
            shutil.copyfile(res_path, args.result_path)
            print(f"[*] Results saved. Final Fitness (Coverage+Vuln+Distance) = {final_fitness}")
            print(f"[*] Results successfully saved to {args.result_path}")
        else:
            print(f"[!] Warning: Fuzzer did not produce a result file at {res_path}")

    except Exception as e:
        print(f"[!!!] CrossFuzz.py encountered a fatal error: {e}", file=sys.stderr)
    
    finally:
        # --- 5. 最终汇报 (保持不变) ---
        print(f"FINAL_FITNESS: {final_fitness}")

if __name__ == "__main__":

    PYTHON = "python3 -u"
    
    FUZZER = "fuzzer/main.py"
    cli()
    # test_run() # 可以通过注释 cli() 并取消注释 test_run() 来运行默认测试