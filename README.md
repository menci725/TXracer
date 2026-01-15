python evolutionary_sequencer.py \
    path/to/MyComplexContract.sol \
    YourMainContractName \
    0.8.17 \
    10 \
    ./results/my_results.json \
    /path/to/your/solc \
    0 \
    --constructor_config ./constructor_config.json
    
命令参数解释:
evolutionary_sequencer.py: 我们的主入口点。
MyComplexContract.sol: 目标 Solidity 文件。
YourMainContractName: 你要 Fuzz 的主合约的名字。
0.8.17: 编译该文件所需的 solc 版本。
10: CrossFuzz 内部使用的最大序列长度 (max_seq_len)。
./results/my_results.json: 最终结果的保存路径。
/path/to/your/solc: solc 二进制文件的绝对路径。
0: CrossFuzz 的 duplication 模式。
--constructor_config: (可选) 我们刚刚配置好的部署文件路径。

e.g.
python3 generate_sequence.py benchmark/contracts/AbilityScores-0x41C54F3248947102a7D1125D264896dDc4727D25/flattened.sol --solc /root/myenv/bin/solc
python3 generate_config.py benchmark/contracts/AbilityScores-0x41C54F3248947102a7D1125D264896dDc4727D25/flattened.sol --solc /root/myenv/bin/solc
python3 evolutionary_sequencer.py benchmark/contracts/AbilityScores-0x41C54F3248947102a7D1125D264896dDc4727D25/flattened.sol AbilityScores 0.8.4 20  /root/CrossFuzz/res.json /root/myenv/bin/solc 0 --constructor_config ./constructor_config.json --depend-contracts ERC721Enumerable ReentrancyGuard Ownable ERC721 IERC721Enumerable Context ERC165 IERC721Metadata 
 
