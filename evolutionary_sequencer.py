import os
import json
import random
import subprocess
import shutil
import argparse
import sys
from copy import deepcopy
import time

POPULATION_SIZE = 2   #modify 10
NUM_GENERATIONS = 2    #modify 20
CROSSOVER_RATE = 0.7
MUTATION_RATE = 0.2
FUZZ_TIME_PER_SEQUENCE = 10

VULNERABILITY_THRESHOLD = 100.0 # 漏洞分数的阈值
PATIENCE_THRESHOLD = 2        # 停滞阈值


def crossover(parent1, parent2):
    if len(parent1) < 2 or len(parent2) < 2:
        return parent1, parent2
    point = random.randint(1, min(len(parent1), len(parent2)) - 1)
    child1 = parent1[:point] + parent2[point:]
    child2 = parent2[:point] + parent1[point:]
    return child1, child2

def mutate(sequence, elite_pool, potential_pool):
    if not sequence or random.random() > MUTATION_RATE:
        return sequence
    
    # mutation_type = random.choices(['add', 'delete', 'swap'], weights=[0.6, 0.2, 0.2], k=1)[0]

    mutation_type = random.choices(['add', 'delete', 'swap', 'repeat'], weights=[0.4, 0.15, 0.15, 0.3], k=1)[0]
    
    if mutation_type == 'repeat':
        if not all(isinstance(item, dict) and 'score' in item for item in sequence):
             print("!! WARNING: Sequence item is not a dict with score. Falling back to random repeat.")
             gene_to_repeat = random.choice(sequence)
        else:
             # 按分数排序，找到最高的那个
             sequence.sort(key=lambda x: x['score'], reverse=True)
             # 从分数最高的前 20% 中随机选一个
             top_tier_index = max(1, len(sequence) // 5)
             gene_to_repeat = random.choice(sequence[:top_tier_index])
        
        # 2. 将它的一个副本，随机插入到序列的另一个位置
        insert_pos = random.randint(0, len(sequence))
        sequence.insert(insert_pos, deepcopy(gene_to_repeat))
        
        # 3. 重新打乱序列，避免高分函数总是扎堆
        random.shuffle(sequence)
        
        print(f"  - MUTATION(REPEAT): Duplicated high-score function '{gene_to_repeat['signature']}'")
        return sequence

    
    # ADD
    if mutation_type == 'add':
        # 1
        source_pool = elite_pool
        if random.random() < 0.1 and potential_pool: # 10% 的概率去探索
            source_pool = potential_pool
            # print("  - MUTATION(EXPLORE): Venturing into the potential pool...")

        # 2.当前序列里还没有的函数
        current_signatures = {item['signature'] for item in sequence}
        candidates_to_add = [item for item in source_pool if item['signature'] not in current_signatures]
        
        if candidates_to_add:
            new_gene = random.choice(candidates_to_add)
            insert_pos = random.randint(0, len(sequence))
            sequence.insert(insert_pos, new_gene)
            print(f"  - MUTATION(ADD): Added '{new_gene['signature']}' from {'elite' if source_pool==elite_pool else 'potential'} pool.")
            return sequence
    
    # 如果无法添加执行删除或交换
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

def run_fuzzer_for_sequence(sequence_with_scores, cli_args):
    current_task_file = "current_fuzz_sequence.json"
    sequence_signatures = [item['signature'] for item in sequence_with_scores]

    with open(current_task_file, "w") as f:
        json.dump(sequence_with_scores, f)

    command = [
        "python", "CrossFuzz.py",
        cli_args.sol_file, cli_args.contract_name, cli_args.solc_version,
        str(cli_args.max_seq_len), str(FUZZ_TIME_PER_SEQUENCE),
        cli_args.result_path, cli_args.solc_path, cli_args.duplication
    ]
    if cli_args.constructor_config:
        command.append("--constructor_config")
        command.append(cli_args.constructor_config)

    if cli_args.depend_contracts: # 检查列表是否非空
        command.append("--depend-contracts")
        command.extend(cli_args.depend_contracts)

    command.extend(["--sequence-template", "current_fuzz_sequence.json"])
    
    print(f"\n--- Running Fuzzer for sequence (length {len(sequence_signatures)}): {sequence_signatures[:3]}... ---")
    print(f"--- Command: {' '.join(command)} ---")
    
    fitness = 0.0
    try:
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1, 
            universal_newlines=True
        )
        
        print("\n--- CrossFuzz Real-time Output (stdout + stderr) ---")
        for line in iter(process.stdout.readline, ''):
            print(line, end='') # 实时打印所有输出
            if line.strip().startswith("FINAL_FITNESS:"):
                try:
                    fitness = float(line.strip().split(":")[1].strip())
                except (ValueError, IndexError): pass
        
        process.stdout.close()
        return_code = process.wait(timeout=FUZZ_TIME_PER_SEQUENCE + 20)
        
        if return_code != 0:
            print(f"\n--- Fuzzer exited with non-zero code: {return_code} ---")

        print(f"\n--- Fitness found: {fitness} ---")
        return fitness

    except subprocess.TimeoutExpired:
        print("--- Fuzzer run timed out. Assuming fitness -1.0. ---")
        process.kill()
        return -1.0
    except Exception as e:
        print(f"--- Error running fuzzer: {e} ---")
        return 0.0
def main():
    # 解析所有必要的命令行参数
    parser = argparse.ArgumentParser(description="Evolutionary Sequencer for CrossFuzz.")
    parser.add_argument("sol_file", help="Path to the Solidity source file.")
    parser.add_argument("contract_name", help="Name of the main contract to fuzz.")
    parser.add_argument("solc_version", help="Solidity compiler version.")
    parser.add_argument("max_seq_len", type=int, help="Maximum length of a transaction sequence (for CrossFuzz).")
    parser.add_argument("result_path", help="Path to save the temporary results JSON file.")
    parser.add_argument("solc_path", help="Absolute path to the solc binary.")
    parser.add_argument("duplication", choices=['0', '1'], help="Duplication mode for CrossFuzz.")
    parser.add_argument("--constructor_config", help="Path to the constructor config JSON file. (optional)")
    parser.add_argument("--depend-contracts", nargs='+', 
                        help="A space-separated list of dependent contracts in deployment order.")
    parser.add_argument("--debug-sequence", 
                        help="Run in debug mode. Directly test the sequence from the specified JSON file instead of evolving.")
    parser.add_argument("--sequence-template", type=str,
                        help="Path to the JSON file with the function sequence template.",
                        dest="sequence_template")
    args = parser.parse_args()

    if args.debug_sequence:
        print("\n==================== RUNNING IN DEBUG MODE ====================")
        print(f"[*] Loading fixed sequence from: {args.debug_sequence}")
        with open(args.debug_sequence, "r") as f:
            sequence_to_test = json.load(f) 
        
        fitness = run_fuzzer_for_sequence(sequence_to_test, args)
        print(f"\n--- DEBUG RUN FINISHED ---")
        print(f"Fitness for the provided sequence: {fitness}")
        sys.exit(0)

    else:
        total_start_time = time.time()
    # 初始基因库
        print("[*] Generating master sequence (gene pool) using sequence_generator.py...")
        master_sequence_file = "master_sequence.json"
        subprocess.run(["python", "generate_sequence.py", args.sol_file, "--solc", args.solc_path, "-o", master_sequence_file])
        try:
            with open(master_sequence_file, "r") as f:
                context_data = json.load(f)
                master_sequence = context_data['master_sequence']
                fuzz_universe = context_data['fuzz_universe']
                elite_gene_pool = [item for item in master_sequence if item['score'] > 0]
                potential_gene_pool = [item for item in master_sequence if item['score'] == 0]
            
            master_sequence = elite_gene_pool if elite_gene_pool else master_sequence
            master_sequence.sort(key=lambda x: x['score'], reverse=True)

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!!!] FATAL: Could not generate or load master sequence: {e}. Exiting.")
            sys.exit(1)

        # 二分
        print("\n==================== STAGE 1: BINARY SEARCH FOR CORE SEQUENCE ====================")
        best_runnable_sequence = []
        best_runnable_fitness = -2.0 # -2.0 区分未运行和超时
        stage1_start_time = time.time()

        print(f"\n--- Pre-check: Testing the full master sequence of length {len(master_sequence)} ---")
        full_sequence_fitness = run_fuzzer_for_sequence(master_sequence, args)

        if full_sequence_fitness >= 0:
            print(f"--- SUCCESS: Full sequence is runnable with fitness {full_sequence_fitness}. Skipping binary search. ---")
            best_runnable_sequence = master_sequence
            best_runnable_fitness = full_sequence_fitness

        else:
        
            low = 0
            high = len(master_sequence)
            
            for i in range(2): 
                if low >= high: break
                
                mid = (low + high) // 2
                if mid == low and mid < high: mid += 1

                current_sequence = master_sequence[:mid]
                if not current_sequence: continue
                
                print(f"\n--- Binary Search Iteration {i+1}: Testing sequence of length {len(current_sequence)} ---")
                
                fitness = run_fuzzer_for_sequence(current_sequence, args)
                
                if fitness >= 0: # 成功运行 (包括0)
                    print(f"--- SUCCESS: Sequence of length {mid} is runnable with fitness {fitness}. Trying longer...")
                    if fitness > best_runnable_fitness:
                        best_runnable_fitness = fitness
                        best_runnable_sequence = current_sequence
                    low = mid
                    if fitness > 100:
                        print(f"\n[*] Total execution time: {time.time() - total_start_time:.2f} seconds.")
                        exit(0)

                else: # 超时 (-1.0)
                    print(f"--- TIMEOUT: Sequence of length {mid} is too long. Trying shorter...")
                    high = mid

        print(f"\n[*] Stage 1 (Binary Search) completed in {time.time() - stage1_start_time:.2f} seconds.")

        if not best_runnable_sequence:
            print("\n[!!!] FATAL: Could not find any runnable sequence even after binary search. The contract might be too complex for the given fuzz time per sequence. Exiting.")
            sys.exit(1)


        # 爬山优化
        print("\n==================== STAGE 2: EVOLUTION FROM CORE SEQUENCE ====================")
        print(f"[*] Starting evolution from best core sequence (length {len(best_runnable_sequence)})")
        stage2_start_time = time.time()

        population = [best_runnable_sequence]
        while len(population) < POPULATION_SIZE:
            mutated_seed = mutate(deepcopy(best_runnable_sequence), elite_gene_pool, potential_gene_pool)
            if mutated_seed not in population:
                population.append(mutated_seed)
                
        best_fitness_overall = best_runnable_fitness # 最高分
        best_sequence_overall = best_runnable_sequence # 最佳序列
        generations_without_improvement = 0 # 停滞代数

        for generation in range(NUM_GENERATIONS):
            print(f"\n==================== GENERATION {generation + 1}/{NUM_GENERATIONS} ====================")
            gen_start_time = time.time()
            fitness_scores = [(seq, run_fuzzer_for_sequence(seq, args)) for seq in population]
            fitness_scores.sort(key=lambda x: x[1], reverse=True)
            
            current_best_sequence = fitness_scores[0][0]
            current_best_fitness = fitness_scores[0][1]

            print(f"\n--- Generation {generation + 1} Results ---")
            best_sequence_signatures = [item['signature'] for item in current_best_sequence]
            print(f"Best fitness in this generation: {current_best_fitness}")
            print(f"Best sequence (length {len(best_sequence_signatures)}): {best_sequence_signatures}")

            if current_best_fitness >= VULNERABILITY_THRESHOLD:
                print(f"\n\n[!!!] SUCCESS! Vulnerability found with score {current_best_fitness} >= {VULNERABILITY_THRESHOLD}.")
                print("[*] Evolution terminated early.")
                best_sequence_overall = current_best_sequence 
                break 

            if current_best_fitness > best_fitness_overall:
                best_fitness_overall = current_best_fitness
                best_sequence_overall = current_best_sequence
                generations_without_improvement = 0 
                print(f"[*] New all-time best fitness found: {best_fitness_overall}")
            else:
                generations_without_improvement += 1
                print(f"[*] No improvement in this generation. Stagnation counter: {generations_without_improvement}/{PATIENCE_THRESHOLD}")
            
            if generations_without_improvement >= PATIENCE_THRESHOLD:
                print(f"\n\n[!!!] STAGNATION! Evolution has not improved for {PATIENCE_THRESHOLD} generations.")
                print("[*] Evolution terminated early.")
                break 

            next_generation = [fitness_scores[0][0], fitness_scores[1][0]] 
            while len(next_generation) < POPULATION_SIZE:
                # 避免所有分数为0时权重列表为空
                parent1 = random.choices(fitness_scores, weights=[max(0.01, f[1]) for f in fitness_scores], k=1)[0][0]
                parent2 = random.choices(fitness_scores, weights=[max(0.01, f[1]) for f in fitness_scores], k=1)[0][0]
                
                if random.random() < CROSSOVER_RATE:
                    child1, child2 = crossover(deepcopy(parent1), deepcopy(parent2))
                else:
                    child1, child2 = deepcopy(parent1), deepcopy(parent2)
                
                next_generation.append(mutate(child1, elite_gene_pool, potential_gene_pool))
                if len(next_generation) < POPULATION_SIZE:
                    next_generation.append(mutate(child2, elite_gene_pool, potential_gene_pool))

            population = next_generation
            print(f"--- Generation {generation} finished in {time.time() - gen_start_time:.2f} seconds. ---")

        print(f"\n[*] Stage 2 (Evolution) completed in {time.time() - stage2_start_time:.2f} seconds.")

        print(f"\n[*] Total execution time: {time.time() - total_start_time:.2f} seconds.")

if __name__ == "__main__":
    main()