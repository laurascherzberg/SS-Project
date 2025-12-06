#!/bin/python3

import sys, json
import argparse


class bcolors:
    # https://stackoverflow.com/questions/4842424/list-of-ansi-color-escape-sequences
    GREEN =     '\033[92m'
    YELLOW =    '\033[93m'
    RED =       '\033[91m'
    ENDC =      '\033[0m'
    BOLD =      '\033[1m'
    UNDERLINE = '\033[4m'


#######################################################
################# AUXILIARY FUNCTIONS #################
#######################################################

### check if json_object has exactly the keys in keys list
def match_keys(keys: list, json_object: list) -> bool:
    return len(keys) == len(json_object.keys()) and \
        set(keys) == set(json_object.keys())


### check if ll is a list of strings
def is_list_of_strings(ll: list) -> bool:
    return all(map(lambda x: isinstance(x, str), ll))


#######################################################
################ INSTRUCTION FUNCTIONS ################
#######################################################

### an instruction is a list [string, int]
def is_instruction(pp: list) -> bool:
    return isinstance(pp, list) and \
        len(pp) == 2 and \
        isinstance(pp[0], str) and \
        isinstance(pp[1], int)


### 2 instructions are equal if they match in both function name and line number, 
# unless ignore_lines is set in which case only function name matters
def is_same_instruction(i1: list, i2: list) -> bool:
    if args.ignore_lines:
        return i1[0] == i2[0]
    else:
        return i1 == i2


#######################################################
################# SANITIZER FUNCTIONS #################
#######################################################

def is_sanitizer(sanitizer: list) -> bool:
    return is_instruction(sanitizer)


def is_list_of_sanitizers(ll: list) -> bool:
    return isinstance(ll, list) and \
        all(map(lambda x: is_sanitizer(x), ll))


### 2 sanitizers are the same if they match in both function name and line number,
# unless ignore_lines is set in which case only function name matters
def is_same_sanitizer(s1: list, s2: list) -> bool:
    return is_same_instruction(s1, s2)


### 2 lists of sanitizers are the same if they contain the same sanitizers, regardless of order
def is_same_list_of_sanitizers(l1: list, l2: list) -> bool:
    if args.ignore_sanitizers:
        return True
    
    if l1 == [] and l2 == []:
        return True
    elif l1 == [] and l2 != []:
        return False
    elif l1 != [] and l2 == []:
        return False
    else:
        f1 = l1[0]
        for i, f2 in enumerate(l2):
            if is_same_sanitizer(f1, f2):
                return is_same_list_of_sanitizers(l1[1:], l2[:i] + l2[i+1:])    
        return False


#######################################################
################### FLOW FUNCTIONS ####################
#######################################################
 
### a flow is a list of tuples (implicit/explicit, list_of_sanitizers)
def is_flow(flow) -> bool:
    return isinstance(flow, list) and \
        len(flow) == 2 and \
        flow[0] in ['implicit', 'explicit'] and \
        is_list_of_sanitizers(flow[1])


def is_non_empty_list_of_flows(ll: list) -> bool:
    return len(ll) > 0 and \
        all(map(lambda x: is_flow(x), ll))


### 2 flows are the same if they match in implicit/explicit tag and list of sanitizers, regardless of order
def is_same_flow(flow1: list, flow2: list) -> bool:
    return (args.ignore_implicit or flow1[0] == flow2[0]) and \
        is_same_list_of_sanitizers(flow1[1], flow2[1])


### 2 lists of flows are the same if they contain the same flows, regardless of order
def is_same_list_of_flows(l1: list, l2: list) -> bool:
    if l1 == [] and l2 == []:
        return True
    elif l1 == [] and l2 != []:
        return False
    elif l1 != [] and l2 == []:
        return False
    else:
        f1 = l1[0]
        for i, f2 in enumerate(l2):
            if is_same_flow(f1, f2):
                return is_same_list_of_flows(l1[1:], l2[:i] + l2[i+1:])
        return False


#######################################################
################### GLOBAL FUNCTIONS ##################
#######################################################

### Check if json object is a valid pattern
'''
  {"vulnerability": "SQL injection A",
  "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
  "sanitizers": ["mogrify", "escape_string"],
  "sinks": ["execute"],
  "implicit": "no"},
'''
def is_pattern(json_obj) -> bool:
    assert match_keys(['vulnerability', 'sources', 'sanitizers', 'sinks', 'implicit'], json_obj), f"pattern keys are incorrect: {json_obj.keys()}"
        
    assert isinstance(json_obj['vulnerability'], str), f"vulnerability attribute is of wrong type: {json_obj['vulnerability']}"
        
    assert isinstance(json_obj['sources'], list), f"sources attribute is of wrong type: {json_obj['sources']}"
    assert is_list_of_strings(json_obj['sources']), f"sources attribute is of wrong type: {json_obj['sources']}"

    assert isinstance(json_obj['sanitizers'], list), f"sanitizers attribute is of wrong type: {json_obj['sanitizers']}"
    assert is_list_of_strings(json_obj['sanitizers']), f"sanitizers attribute is of wrong type: {json_obj['sanitizers']}"

    assert isinstance(json_obj['sinks'], list), f"sinks attribute is of wrong type: {json_obj['sinks']}"
    assert is_list_of_strings(json_obj['sinks']), f"sinks attribute is of wrong type: {json_obj['sinks']}"

    assert isinstance(json_obj['implicit'], str), f"implicit attribute is of wrong type: {json_obj['implicit']}"
    assert json_obj['implicit'] in ["yes", "no"], f"implicit attribute is of wrong type: {json_obj['implicit']}"

    return True


### Check if json object is a valid vulnerability output
'''
    <OUTPUT> ::= [ <VULNERABILITIES> ]
    <VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>, <VULNERABILITIES>
    <VULNERABILITY> ::= { "vulnerability": "<STRING>",
                        "source": [ "<STRING>", <INT> ]
                        "sink": [ "<STRING>", <INT> ],
                        "flows": [ <FLOWS> ] }
    <FLOWS> ::= <FLOW> | <FLOW>, <FLOWS>
    <FLOW> ::= [ <IMPEXP>, [] ] | [ <IMPEXP>, [<SANITIZERS>] ]
    <IMPEXP> ::= "implicit" | "explicit"
    <SANITIZERS> ::= <SANITIZER> | <SANITIZER>, <SANITIZERS>
    <SANITIZER> ::= [ <STRING>, <INT> ]
'''
def is_vulnerability(json_obj) -> bool:     
    assert match_keys(['vulnerability', 'source', 'sink', 'flows'], json_obj), f"vulnerability keys are incorrect: {json_obj.keys()}"

    assert isinstance(json_obj['vulnerability'], str), f"vulnerability attribute is of wrong type: {json_obj['vulnerability']}"
        
    assert is_instruction(json_obj['source']), f"source attribute is of wrong type: {json_obj['source']}"

    assert is_instruction(json_obj['sink']), f"sink attribute is of wrong type: {json_obj['sink']}"

    assert isinstance(json_obj['flows'], list), f"flows attribute is of wrong type: {json_obj['flows']}"
    assert is_non_empty_list_of_flows(json_obj['flows']), f"flows attribute is of wrong type: {json_obj['flows']}"

    return True
    

### 2 vulnerabilities have the same name if they differ in their numbering
##  v == v_3
##  v_1 == v_2
##  v_1_1 == v_1_2
##  v_1_1 != v_1
##  v_1_1 != v_2_1
def is_same_vulnerability_name(name1, name2):
    pos1 = name1.rfind('_')
    pos2 = name2.rfind('_')
    rname1 = name1[:pos1] if pos1 != -1 else name1
    rname2 = name2[:pos2] if pos2 != -1 else name2
    return rname1 == rname2

# assert is_same_vulnerability_name('v', 'v_3') == True
# assert is_same_vulnerability_name('v_1', 'v_2') == True
# assert is_same_vulnerability_name('v_1_1', 'v_1_2') == True
# assert is_same_vulnerability_name('v_1_1', 'v_1') == False
# assert is_same_vulnerability_name('v_1_1', 'v_2_1') == False


### 2 vulnerabilities are the same if they match in everything, 
##  regardless of the order of the flows and sanitizers
def is_same_vulnerability(v1, v2) -> bool:
    return is_same_vulnerability_name(v1['vulnerability'], v2['vulnerability']) and \
        is_same_instruction(v1['source'] ,v2['source']) and \
        is_same_instruction(v1['sink'] ,v2['sink']) and \
        is_same_list_of_flows(v1['flows'], v2['flows'])


def is_vulnerability_in_target(vulnerability, target_list):
    for t in target_list:
        if is_same_vulnerability(vulnerability, t):
            target_list.remove(t)
            return True, target_list

    return False, target_list


### Check if output in output file is the same as in intended output (target)
def check_output(output: str, target: str):
    good = []
    extra = []

    with open(output, 'r') as f:
        output_list = json.loads(f.read())
    
    with open(target, 'r') as f:
        target_list = json.loads(f.read())

    for o in output_list:
        res, target_list = is_vulnerability_in_target(o, target_list)
        if res:
            good.append(o)
        else:
            extra.append(o)

    print(f"\nGOOD FLOWS\n{good}")
    if target_list != []:
        print(f"\n{bcolors.RED}\nMISSING FLOWS\n{target_list}{bcolors.ENDC}")
    if extra != []:
        print(f"\n{bcolors.YELLOW}\nWRONG FLOWS\n{extra}{bcolors.ENDC}")
        
        
### Check if all patterns in filename are valid patterns
def validate_patterns_file(filename: str) -> bool:
    with open(filename, 'r') as f:
        patterns_list = json.loads(f.read())
    assert isinstance(patterns_list, list)

    for json_obj in patterns_list:
        try:
            assert is_pattern(json_obj)
        except Exception as e:
            print(f"\n{bcolors.RED}[-] Incorrect Pattern in file {filename}:\n{e}\n{json_obj}{bcolors.ENDC}\n")
            exit(1)

    print(f"{bcolors.GREEN}[+] All patterns of file {filename} are well defined{bcolors.ENDC}")
   

### Check if all outputs in filename are valid vulnerability outputs
def validate_output_file(filename: str):
    with open(filename, 'r') as f:
        output_list = json.loads(f.read())
    assert isinstance(output_list, list)

    for json_obj in output_list:
        try:
            assert is_vulnerability(json_obj)
        except Exception as e:
            print(f"\n{bcolors.RED}[-] Incorrect Output in file {filename}:\n{e}\n{json_obj}{bcolors.ENDC}\n")
            exit(1)

    print(f"{bcolors.GREEN}[+] All outputs of file {filename} are well defined{bcolors.ENDC}")




parser = argparse.ArgumentParser()
parser.add_argument("--pattern", '-p', help="Validate <pattern> file", default = False)
### group's output
parser.add_argument("--output", '-o', help="Validate <output> file", default = False)
### intended output
parser.add_argument("--target", '-t', help="Check <output> vs <target_file>", default = False)

parser.add_argument("--ignore_lines", action="store_true", help="allows for mismatch in line numbers")
parser.add_argument("--ignore_implicit", action="store_true", help="allows for mismatch in the \"IMPEXP\" tag")
parser.add_argument("--ignore_sanitizers", action="store_true", help="allows for mismatch in the \"SANITIZERS\" list")

args=parser.parse_args()

if args.ignore_lines:
    print(f"{bcolors.YELLOW}[-]WARNING: Not validating if line numbers are correct!{bcolors.ENDC}")
if args.ignore_implicit:
    print(f"{bcolors.YELLOW}[-]WARNING: Not validating if the implicit/explicit tags in flows are correct!{bcolors.ENDC}")
if args.ignore_sanitizers:
    print(f"{bcolors.YELLOW}[-]WARNING: Not validating if the list of sanitizers is correct!{bcolors.ENDC}")


print("\n" + "*"*80)
if vars(args)['pattern']:
    validate_patterns_file(vars(args)['pattern'])
if vars(args)['output']:
    validate_output_file(vars(args)['output'])
if vars(args)['output'] and vars(args)['target']:
    validate_output_file(vars(args)['target'])
    check_output(vars(args)['output'], vars(args)['target'])
