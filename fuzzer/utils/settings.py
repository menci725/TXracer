#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from datetime import datetime

# Ethereum VM ('homestead', 'byzantium' or 'petersburg')
EVM_VERSION = "petersburg"
# Size of population
POPULATION_SIZE = 10
# POPULATION_SIZE = None
# Number of generations
GENERATIONS = 10
# GENERATIONS = 10
# Global timeout in seconds
GLOBAL_TIMEOUT = None
# Probability of crossover
PROBABILITY_CROSSOVER = 0.9
# Probability of mutation
PROBABILITY_MUTATION = 0.1
# Maximum number of symbolic execution calls before restting population
MAX_SYMBOLIC_EXECUTION = 2
# MAX_SYMBOLIC_EXECUTION = 10
# Solver timeout in milliseconds
SOLVER_TIMEOUT = 100
# List of attacker accounts
ATTACKER_ACCOUNTS = ["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
# Default gas limit for sending transactions
# GAS_LIMIT = 4500000
GAS_LIMIT = 2000000000
# Default gas price for sending transactions
GAS_PRICE = 1
# Default account balance
ACCOUNT_BALANCE = 100000000 * (10 ** 18)
# Maximum length of individuals
MAX_INDIVIDUAL_LENGTH = 5
# Logging level
LOGGING_LEVEL = logging.INFO
# Block height
BLOCK_HEIGHT = 'latest'
# RPC Host
RPC_HOST = 'localhost'
# RPC Port
RPC_PORT = 8545
# True = Remote fuzzing, False = Local fuzzing
REMOTE_FUZZING = False
# True = Environmental instrumentation enabled, False = Environmental instrumentation disabled
ENVIRONMENTAL_INSTRUMENTATION = True
# trans_info存储的位置, 默认为/tmp/ConFuzzius_trans.json
TRANS_INFO_JSON_PATH = "/tmp/ConFuzzius_trans.json"
# 在内存中加载trans_info, 避免重复I/O
TRANS_INFO = {"start_time": str(datetime.now())}
DEPLOYED_CONTRACT_ADDRESS = {}
# 主合约名称
MAIN_CONTRACT_NAME = ""
# 是否输出trans_info
OUTPUT_TRANS_INFO = False
# SOLC地址, 用于cross slither
SOLC_PATH_CROSS = ""
# 记录跨合约事务的执行数量
CROSS_TRANS_EXEC_COUNT = 0
# 控制事务序列的生成策略
TRANS_MODE = "origin"
# 是否开启跨合约事务
TRANS_COMP_OPEN = True
TRANS_SUPPORT_MODE = 1
TRANS_CROSS_BAD_INDVS = []
TRANS_CROSS_BAD_INDVS_HASH = set()
GLOBAL_DATA_INFO = dict()
P_OPEN_CROSS = 5
CROSS_INIT_MODE = 1
DUPLICATION = 0


# 在启动符号执行前，允许覆盖率停滞多少代
SYMBOLIC_EXECUTION_PATIENCE = 2


SYMBOLIC_EXECUTION_TARGETS = [
    "claim(uint256)",

    "claimForLoot(uint256)",
    "setApprovalForAll(address,bool)",
    
    "approve(address, uint256)" ,
    "ownerClaim(uint256)",
    "transferOwnership(address)",
    "swap(IERC20, IERC20, uint256, uint256, Utils.Route[] calldata)",
    "burnToken(address,uint256[],string)",
    "burnToken(address,uint256[],string,address)",
    "setRateEngine(address)",
    "increaseAllowance(address,uint256)",
    "burn(uint256)",
    "allowance(address,address)",
    "setTreasury(address,uint128)",
    "renounceOwnership()",
    "burnFrom(address,uint256)",
    # --- 主要目标 (NFT2ERC20 的核心价值逻辑) ---
    "burnToken(address,uint256[],string)",
    "burnToken(address,uint256[],string,address)",

    # --- 次要目标 (关键的、受访问控制的设置函数) ---
    "setRateEngine(address)",

    "setTransferFunction(string,bytes4)",
    "approveAdmin(address)",
    "revokeAdmin(address)",
    "transferOwnership(address)",

    # --- 基础目标 (ERC20 的核心复杂逻辑) ---
    "transferFrom(address,address,uint256)",
    "approve(address,uint256)",

    "mint(address,uint256)",
    "mintFREE(address , uint256)",

    # --- 高价值次要目标 ---
    # 探索是否存在任何可以绕过 onlyOwner 的路径
    "withdraw()",
    
    # 其他 onlyOwner 函数也是很好的目标，因为它们都依赖于同一个状态
    "setCost(uint256)",
    "pause(bool)",
    "whitelistUser(address)",

     "setSale()",
    "setWhitelistState()",

    # --- 终极挑战目标 ---
    # 我们可以把这个目标加进去，看看我们的引擎能否创造奇迹
    "whitelistClaim(uint256,uint256,bytes32[])",
    
    "short(uint256,uint256,uint256,address[],uint256)",
    "close(uint256,uint256,uint256,address[],uint256)",


    # --- 主要目标：合约的核心价值与复杂逻辑 ---
    "breedWith(uint256,uint256)",
    "mintGen0Egg()",
    "bid(uint256)",

    # --- 次要目标：关键的前置条件和状态转换 ---
    "createSale(uint256,uint256,address)",
    "hatchFish(uint256,uint256,uint256)",

    "mintPresale(uint256)",
    "mint(uint256)",
    "upgrade(uint256)",

    # --- 次要目标 (用于解锁前置条件) ---
    "addToPresaleList1(address[])",
    "addToPresaleList2(address[])",
    "setKATz(address)",
    "togglePresaleStatus()",
    "togglePublicSaleStatus()",
    "toggleUpgradeStatus()"

]