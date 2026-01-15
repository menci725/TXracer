#!/bin/bash

# --- 配置 ---
# 把你的Etherscan API密钥粘贴在这里 (V1和V2通用)
ETHERSCAN_API_KEY="JQNYMRHP2DIKWBN9157TUC9B8JZYWWJITW"

# 临时工作目录的名称
TEMP_PROJECT_DIR="temp_hardhat_project"
# 最终输出扁平化合约的目录
OUTPUT_DIR="fetched_contracts"

# --- 脚本开始 ---

# 检查输入参数
CONTRACT_ADDRESS="0xBA12222222228d8Ba445958a75a0704d566BF2C8"

# 检查API密钥是否已设置
if [ "$ETHERSCAN_API_KEY" == "YOUR_API_KEY_HERE" ]; then
    echo "[!] Error: Please set your ETHERSCAN_API_KEY in the script."
    exit 1
fi

echo "======================================================"
echo "      Fetching and Flattening Contract (Mainnet API V2 ONLY)"
echo "======================================================"
echo "[*] Target Address: $CONTRACT_ADDRESS"

# --- 【核心：严格使用 Etherscan API V2 的 URL 格式】 ---
API_URL="https://api.etherscan.io/v2/api?module=contract&action=getsourcecode&address=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2&apikey=JQNYMRHP2DIKWBN9157TUC9B8JZYWWJITW&chainid=1"

echo "[*] Fetching source code from Etherscan (V2)..."
api_response=$(curl -s "$API_URL")

# V2 API 在成功时返回 'message': 'OK'，状态码在 'status' 中
status=$(echo "$api_response" | jq -r '.status')
message=$(echo "$api_response" | jq -r '.message')

if [ "$status" != "1" ] || [ "$message" != "OK" ]; then
    error_detail=$(echo "$api_response" | jq -r '.result')
    echo "[!] FATAL: Etherscan API request failed."
    echo "    - Reason: $error_detail"
    exit 1
fi
# --- 【修改结束】 ---

# (后续的解析、创建项目、Flatten和清理逻辑与之前版本相同)
source_code_json=$(echo "$api_response" | jq -r '.result[0].SourceCode')

if [ -z "$source_code_json" ] || [ "$source_code_json" == "" ]; then
    echo "[!] FATAL: Source code is not verified or is empty on Etherscan."
    exit 1
fi

echo "[*] Parsing source code and creating temporary project..."
rm -rf "$TEMP_PROJECT_DIR"
mkdir -p "${TEMP_PROJECT_DIR}/contracts"

if [[ $source_code_json == \{\{* ]]; then
    echo "  - Multi-file project detected. Reconstructing directory structure..."
    if [[ $source_code_json == \{\{* ]]; then
        source_code_json=${source_code_json:1:${#source_code_json}-2}
    fi
    echo "$source_code_json" | jq -r '.sources | keys[] as $path | "\($path)\u0000\(.[$path].content)"' | while IFS= read -r -d '' path && IFS= read -r -d '' content; do
        mkdir -p "${TEMP_PROJECT_DIR}/contracts/$(dirname "$path")"
        echo -e "$content" > "${TEMP_PROJECT_DIR}/contracts/$path"
        echo "    - Created file: contracts/$path"
    done
else
    echo "  - Single-file project detected."
    contract_name=$(echo "$api_response" | jq -r '.result[0].ContractName')
    echo -e "$source_code_json" > "${TEMP_PROJECT_DIR}/contracts/${contract_name}.sol"
    echo "    - Created file: contracts/${contract_name}.sol"
fi

echo "[*] Running 'hardhat flatten'..."
(
    cd "$TEMP_PROJECT_DIR" || exit
    
    npm init -y > /dev/null 2>&1
    npm install --save-dev hardhat > /dev/null 2>&1
    
    main_contract_file=$(find ./contracts -type f -name "*.sol" -printf "%s %p\n" | sort -nr | head -n 1 | awk '{print $2}')
    
    if [ -z "$main_contract_file" ]; then
        echo "[!] FATAL: Could not determine main contract file to flatten."
        exit 1
    fi
    echo "  - Determined main file for flattening: $main_contract_file"

    mkdir -p "../${OUTPUT_DIR}"
    output_filename="../${OUTPUT_DIR}/${CONTRACT_ADDRESS}_flattened.sol"
    npx hardhat flatten "$main_contract_file" > "$output_filename"
)

output_file="${OUTPUT_DIR}/${CONTRACT_ADDRESS}_flattened.sol"
if [ -s "$output_file" ]; then
    echo "[+] Successfully flattened contract!"
    echo "    - Output saved to: $output_file"
else
    echo "[!] FATAL: Hardhat flatten failed. Check for compilation errors inside '$TEMP_PROJECT_DIR'."
    echo "    - Temporary project directory kept for debugging: $TEMP_PROJECT_DIR"
    exit 1
fi

echo "[*] Cleaning up temporary files..."
rm -rf "$TEMP_PROJECT_DIR"
echo "  - Temporary project directory removed."

echo "======================================================"
echo "          Process Complete!"
echo "======================================================"