#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import random

from fuzzer.utils import settings
from fuzzer.engine.components.individual import Individual

from eth_utils import to_canonical_address, function_signature_to_4byte_selector
from fuzzer.utils import settings 
from eth_abi import encode_abi
from web3 import Web3

class Individuals(object):
    '''
    Descriptor for all individuals in population.
    '''

    def __init__(self, name):
        self.name = '_{}'.format(name)

    def __get__(self, instance, owner):
        return instance.__dict__[self.name]

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value
        # Update flag.
        instance.update_flag()


class Population(object):
    """
    用于生成一组测试用例
    individuals就是很多条事务序列
    """
    # All individuals.
    individuals = Individuals('individuals')

    def __init__(self, indv_template, indv_generator, size=100, other_generators=None):
        '''
        Class for representing population in genetic algorithm.

        :param indv_template: A template individual to clone all the other
                              individuals in current population.

        :param size: The size of population, number of individuals in population.
        :type size: int

        '''
        # Population size.
        if size % 2 != 0:
            raise ValueError('Population size must be an even number')
        self.size = size

        # Template individual.
        self.indv_template = indv_template

        # Generator individual.
        self.indv_generator = indv_generator

        # Flag for monitoring changes of population.
        self._updated = False

        # Container for all individuals.
        class IndvList(list):
            '''
            A proxy class inherited from built-in list to contain all
            individuals which can update the population._updated flag
            automatically when its content is changed.
            '''

            # NOTE: Use 'this' here to avoid name conflict.
            def __init__(this, *args):
                super(this.__class__, this).__init__(*args)

            """def __setitem__(this, key, value):
                '''
                Override __setitem__ in built-in list type.
                '''
                old_value = this[key]
                if old_value == value:
                    return
                super(this.__class__, self).__setitem__(key, value)
                # Update population flag.
                self.update_flag()"""

            def append(this, item):
                '''
                Override append method of built-in list type.
                '''
                super(this.__class__, this).append(item)
                # Update population flag.
                self.update_flag()

            def extend(this, iterable_item):
                if not iterable_item:
                    return
                super(this.__class__, this).extend(iterable_item)
                # Update population flag.
                self.update_flag()
            # }}}

        self._individuals = IndvList()

        self.other_generators = other_generators if other_generators is not None else []

    def init(self, indvs=None, init_seed=False, no_cross=False):
        '''
        Initialize current population with individuals.

        :param indvs: Initial individuals in population, randomly initialized
                      individuals are created if not provided.
        :param init_seed:
        :param no_cross:
        :type indvs: list of Individual object
        '''
        IndvType = self.indv_template.__class__

        if indvs is None:
            if init_seed:
                for g in self.other_generators + [self.indv_generator]:
                    for func_hash, func_args_types in g.interface.items():
                        indv = IndvType(generator=g, other_generators=g.other_generators).init(func_hash=func_hash, func_args_types=func_args_types, default_value=True)
                        if len(indv.chromosome) == 0:  # 生成的事务序列为空, 跨合约事务用完了
                            if len(self.individuals) % 2 != 0:
                                indv_single = IndvType(generator=g, other_generators=g.other_generators).init(single=True, func_hash=func_hash, func_args_types=func_args_types, default_value=True)
                                self.individuals.append(indv_single)
                            else:
                                break
                        else:
                            self.individuals.append(indv)
            else:
                while len(self.individuals) < self.size:
                    chosen_generator = self.indv_generator
                    indv = IndvType(generator=chosen_generator, other_generators=chosen_generator.other_generators).init(no_cross=no_cross)
                    if len(indv.chromosome) == 0:  # 生成的事务序列为空, 跨合约事务用完了
                        if len(self.individuals) % 2 != 0:
                            indv_single = IndvType(generator=chosen_generator, other_generators=chosen_generator.other_generators).init(single=True, no_cross=no_cross)
                            self.individuals.append(indv_single)
                        else:
                            break
                    else:
                        self.individuals.append(indv)
        else:
            # Check individuals.
            if len(indvs) != self.size:
                raise ValueError('Invalid individuals number')
            for indv in indvs:
                # if not isinstance(indv, SessionIndividual):
                #     raise ValueError('individual class must be Individual or a subclass of Individual')
                if not isinstance(indv, Individual):                                                            #modify
                    raise ValueError('individual class must be Individual or a subclass of Individual')
            self.individuals = indvs

        self._updated = True
        self.size = len(self.individuals)
        return self

    def update_flag(self):
        '''
        Interface for updating individual update flag to True.
        '''
        self._updated = True

    @property
    def updated(self):
        '''
        Query function for population updating flag.
        '''
        return self._updated

    def new(self):
        '''
        Create a new emtpy population.
        '''
        return self.__class__(indv_template=self.indv_template, size=self.size, indv_generator=self.indv_generator, other_generators=self.other_generators)

    def __getitem__(self, key):
        '''
        Get individual by index.
        '''
        if key < 0 or key >= self.size:
            raise IndexError('Individual index({}) out of range'.format(key))
        return self.individuals[key]

    def __len__(self):
        '''
        Get length of population.
        '''
        return len(self.individuals)

    def best_indv(self, fitness):
        '''
        The individual with the best fitness.

        '''
        all_fits = self.all_fits(fitness)
        return max(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def worst_indv(self, fitness):
        '''
        The individual with the worst fitness.
        '''
        all_fits = self.all_fits(fitness)
        return min(self.individuals, key=lambda indv: all_fits[self.individuals.index(indv)])

    def max(self, fitness):
        '''
        Get the maximum fitness value in population.
        '''
        return max(self.all_fits(fitness))

    def min(self, fitness):
        '''
        Get the minimum value of fitness in population.
        '''
        return min(self.all_fits(fitness))

    def mean(self, fitness):
        '''
        Get the average fitness value in population.
        '''
        all_fits = self.all_fits(fitness)
        return sum(all_fits) / len(all_fits)

    def all_fits(self, fitness):
        '''
        Get all fitness values in population.
        '''
        return [fitness(indv) for indv in self.individuals]
    
    # def init_from_template(self, sequence_template):
    #     print(f"Initializing population from template using Generator's internal mappers...")
    #     self.individuals = []
        
    #     IndvType = self.indv_template.__class__
        
    #     # 1. 创建 Generator 地图
    #     generator_map = {self.indv_generator.contract_name: self.indv_generator}
    #     for g in self.other_generators:
    #         generator_map[g.contract_name] = g

    #     # 2. 循环创建每一个 Individual
    #     for _ in range(self.size):
    #         new_indv = IndvType(generator=self.indv_generator, other_generators=self.other_generators)
    #         new_chromosome = []
            
    #         for task in sequence_template:
    #             target_contract_name = task.get('contract')
    #             func_sig = task.get('signature')
    #             if not target_contract_name or not func_sig: continue

    #             target_generator = generator_map.get(target_contract_name)
    #             if not target_generator:
    #                 print(f"Could not find generator for '{target_contract_name}'. Skipping.")
    #                 continue
                
    #             try:
    #                 func_hash = target_generator.interface_mapper.get(func_sig)
    #                 # print(f"  - Sig '{func_sig}' found in '{target_generator.contract_name}' interface_mapper")
                    
    #                 if not func_hash:
    #                     # print(f"Sig '{func_sig}' not found in '{target_generator.contract_name}' interface_mapper. Skipping.")
    #                     continue

    #                 arg_types = target_generator.interface.get(func_hash, [])
                    
    #                 gene_list = target_generator.generate_individual(func_hash, arg_types)

    #                 if gene_list:
    #                     # forged_gene = gene_list[0]
    #                     # print("\n" + "--- GENE FORGED ---")
    #                     # print(f"  - Task       : {task['contract']}.{task['signature']}")
    #                     # print(f"  - Using Gen  : {target_generator.contract_name}")
    #                     # print(f"  - Target Addr: {forged_gene['contract']}")
    #                     # print(f"  - Func Hash  : {forged_gene['arguments'][0]}")
    #                     # print("-------------------")
                        
    #                     new_chromosome.extend(gene_list)

    #             except Exception as e:
    #                 print(f"Error forging gene for task '{task}': {e}")
            
    #         new_indv.init(chromosome=new_chromosome)
    #         self.individuals.append(new_indv)

    #     return self
    def init_from_template(self, sequence_template):
        print(f"Initializing population from template by manually forging genes...")
        self.individuals = []
        
        IndvType = self.indv_template.__class__
        generator_map = {self.indv_generator.contract_name: self.indv_generator}
        for g in self.other_generators:
            generator_map[g.contract_name] = g

        for _ in range(self.size):
            new_indv = IndvType(generator=self.indv_generator, other_generators=self.other_generators)
            new_chromosome = []
            
            for task in sequence_template:
                target_contract_name = task.get('contract')
                func_sig = task.get('signature')
                if not target_contract_name or not func_sig: continue

                target_generator = generator_map.get(target_contract_name)
                if not target_generator:
                    print(f"Could not find generator for '{target_contract_name}'. Skipping.")
                    continue
                
                try:
                    # ===================================================================
                    # !! 核心修改：不再调用 generate_individual，我们亲自锻造 !!
                    # ===================================================================
                    
                    # 1. 查找函数哈希和参数类型
                    func_hash, arg_types = target_generator.get_specific_function_with_argument_types(func_sig)
                    
                    # 2. 构建 arguments 列表
                    arguments = [func_hash]
                    for index, arg_type in enumerate(arg_types):
                        # 调用 Generator 底层的、可靠的随机参数生成器
                        arguments.append(target_generator.get_random_argument(arg_type, func_hash, index))
                    
                    # 3. 从全局“地址簿”中，获取正确的合约地址
                    correct_contract_address = settings.DEPLOYED_CONTRACT_ADDRESS.get(target_contract_name)
                    if not correct_contract_address:
                        print(f"Could not find DEPLOYED address for '{target_contract_name}'. Skipping.")
                        continue
                    
                    # 4. 构建完整的“基因”字典
                    gene = {
                        "account": target_generator.get_random_account(func_hash),
                        "contract": correct_contract_address, # <-- 使用我们找到的、正确的地址！
                        "amount": target_generator.get_random_amount(func_hash),
                        "arguments": arguments,
                        "blocknumber": target_generator.get_random_blocknumber(func_hash),
                        "timestamp": target_generator.get_random_timestamp(func_hash),
                        "gaslimit": target_generator.get_random_gaslimit(func_hash),
                        "call_return": {}, "extcodesize": {}, "returndatasize": {}
                    }
                    new_chromosome.append(gene)

                except KeyError:
                    print(f"Sig '{func_sig}' not in '{target_generator.contract_name}' generator. Skipping.")
                except Exception as e:
                    print(f"Error forging gene for task '{task}': {e}")
            
            new_indv.init(chromosome=new_chromosome)
            self.individuals.append(new_indv)
        
        return self