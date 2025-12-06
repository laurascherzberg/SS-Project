#!/usr/bin/env python3
"""
py_analyser.py - Fixed for 1b-basic-flow (Variable Sources & Variable Sinks)
"""
import ast
import sys
import os
import json

class Pattern:
    def __init__(self, name: str, sources: list, sanitizers: list, sinks: list, implicit: bool):
        self.name = name
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)
        self.implicit = implicit
    
    def get_name(self): return self.name
    def get_sources(self): return self.sources.copy()
    def get_sanitizers(self): return self.sanitizers.copy()
    def get_sinks(self): return self.sinks.copy()
    def is_source(self, name): return name in self.sources
    def is_sink(self, name): return name in self.sinks

class TaintLabel:
    def __init__(self):
        self.sources = {}  # source -> (first_line, sanitizers)
    
    def add_source(self, source: str, line: int):
        if source not in self.sources:
            self.sources[source] = (line, [])
    
    def add_sanitizer(self, source: str, sanitizer: str, line: int):
        if source in self.sources:
            line_num, sants = self.sources[source]
            if not any(s[0] == sanitizer for s in sants):
                sants.append([sanitizer, line])
    
    def get_sources(self):
        return list(self.sources.keys())
    
    def get_sanitizers(self, source):
        if source in self.sources:
            return self.sources[source][1][:]
        return []
    
    def combine(self, other):
        result = TaintLabel()
        for src, (line, sants) in self.sources.items():
            result.add_source(src, line)
            for sant in sants:
                result.add_sanitizer(src, sant[0], sant[1])
        for src, (line, sants) in other.sources.items():
            result.add_source(src, line)
            for sant in sants:
                result.add_sanitizer(src, sant[0], sant[1])
        return result

class MultiLabel:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        self.labels = {name: TaintLabel() for name in self.patterns}
    
    def add_source(self, pattern_name, source, line):
        if pattern_name in self.patterns:
            self.labels[pattern_name].add_source(source, line)
    
    def combine(self, other):
        result = MultiLabel(list(self.patterns.values()))
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].combine(other.labels[p_name])
        return result

class Policy:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        self.source_to_patterns = {}
        self.sink_to_patterns = {}
        for name, pattern in self.patterns.items():
            for src in pattern.get_sources():
                self.source_to_patterns.setdefault(src, set()).add(name)
            for snk in pattern.get_sinks():
                self.sink_to_patterns.setdefault(snk, set()).add(name)
    
    def get_sink_patterns(self, sink_name):
        return self.sink_to_patterns.get(sink_name, set())

class Vulnerability:
    def __init__(self, vuln_name, source, sink, is_implicit, sanitizers):
        self.vuln_name = vuln_name
        self.source = source
        self.sink = sink
        self.is_implicit = is_implicit
        self.sanitizers = sanitizers

class Analyser(ast.NodeVisitor):
    def __init__(self, patterns):
        self.policy = Policy(patterns)
        self.labelling = {}  # var -> MultiLabel
        self.vulnerabilities = []
        self.source_lines = {}  # source -> first_use_line
        self.uninstantiated_sources = set()  # vars used before definition
    
    def get_line_number(self, node):
        return getattr(node, 'lineno', 1)
    
    def get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None
    
    def mark_uninstantiated_source(self, var_name, line):
        """Mark vars used before definition as sources (project requirement)"""
        if var_name not in self.labelling:
            self.uninstantiated_sources.add(var_name)
            self.source_lines[var_name] = line
    
    def analyze_expression(self, node):
        patterns = list(self.policy.patterns.values())
        empty_label = MultiLabel(patterns)
        
        if isinstance(node, ast.Name):
            var_name = node.id
            line = self.get_line_number(node)

            # Get existing taint or empty
            current_taint = self.labelling.get(var_name, empty_label)
            
            # --- FIX 1 START: Explicit Variable Sources ---
            # If the variable ITSELF is defined as a source in patterns (like 'c' in 1b)
            # we must add it as a new source to the taint label
            if var_name in self.policy.source_to_patterns:
                # We combine existing taint with the new source taint
                new_taint = current_taint.combine(empty_label) # Clone effectively
                self.source_lines[var_name] = line
                for pattern_name in self.policy.source_to_patterns[var_name]:
                    new_taint.add_source(pattern_name, var_name, line)
                current_taint = new_taint
            # --- FIX 1 END ---

            # Mark uninstantiated vars as sources at FIRST USE
            self.mark_uninstantiated_source(var_name, line)
            return current_taint
        
        elif isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            return empty_label
        
        elif isinstance(node, ast.BinOp):
            left = self.analyze_expression(node.left)
            right = self.analyze_expression(node.right)
            result = MultiLabel(patterns)
            for p_name in result.labels:
                result.labels[p_name] = left.labels[p_name].combine(right.labels[p_name])
            return result
        
        elif isinstance(node, ast.Call):
            func_name = self.get_func_name(node.func)
            line = self.get_line_number(node)
            
            # Mark function calls as sources
            if func_name and func_name in self.policy.source_to_patterns:
                self.source_lines[func_name] = line
                for pattern_name in self.policy.source_to_patterns[func_name]:
                    empty_label.add_source(pattern_name, func_name, line)
            
            # Check sink (Function Call Sinks) + analyze args
            sink_patterns = self.policy.get_sink_patterns(func_name)
            arg_taint = empty_label
            
            for arg in node.args:
                arg_label = self.analyze_expression(arg)
                arg_taint = arg_taint.combine(arg_label)
            
            # Report vulnerabilities for function sinks
            for pattern_name in sink_patterns:
                label = arg_taint.labels[pattern_name]
                for source in label.get_sources():
                    sanitizers = label.get_sanitizers(source)
                    source_line = self.source_lines.get(source, line)
                    self.vulnerabilities.append(Vulnerability(
                        pattern_name,
                        [source, source_line],
                        [func_name, line],
                        False,  # explicit
                        sanitizers
                    ))
            return arg_taint
        
        return empty_label
    
    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            line = self.get_line_number(node)
            
            # Clear from uninstantiated sources when defined
            if target in self.uninstantiated_sources:
                self.uninstantiated_sources.discard(target)
            
            value_taint = self.analyze_expression(node.value)
            self.labelling[target] = value_taint

            # --- FIX 2 START: Variable Sinks (Assignment Targets) ---
            # Check if the variable being assigned TO is a sink (like 'd' in 1b)
            if target in self.policy.sink_to_patterns:
                sink_patterns = self.policy.get_sink_patterns(target)
                for pattern_name in sink_patterns:
                    label = value_taint.labels[pattern_name]
                    for source in label.get_sources():
                        sanitizers = label.get_sanitizers(source)
                        source_line = self.source_lines.get(source, line)
                        self.vulnerabilities.append(Vulnerability(
                            pattern_name,
                            [source, source_line],
                            [target, line],
                            False, # explicit
                            sanitizers
                        ))
            # --- FIX 2 END ---

        self.generic_visit(node)
    
    def visit_Expr(self, node):
        self.analyze_expression(node.value)
        self.generic_visit(node)

def load_patterns(patterns_data):
    return [Pattern(p["vulnerability"], p["sources"], p["sanitizers"], 
                   p["sinks"], p["implicit"] == "yes") for p in patterns_data]

def main():
    if len(sys.argv) != 3:
        print("Usage: python py_analyser.py <slice_path> <patterns_path>")
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]

    if not os.path.exists(slice_path) or not os.path.exists(patterns_path):
        print("Error: File not found.")
        sys.exit(1)

    with open(patterns_path, 'r') as f:
        try:
            patterns = json.load(f)
        except json.JSONDecodeError:
            print("Error: Invalid JSON.")
            sys.exit(1)

    with open(slice_path, 'r') as f:
        source_code = f.read()
    
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        print(f"Error parsing slice: {e}")
        sys.exit(1)

    analyser = Analyser(load_patterns(patterns))
    analyser.visit(tree)

    # Grouping + deduplication
    grouped_vulns = {}
    for v in analyser.vulnerabilities:
        key = (v.vuln_name, v.source[0], v.source[1], v.sink[0], v.sink[1])
        flow_entry = ["implicit" if v.is_implicit else "explicit", v.sanitizers]
        
        if key not in grouped_vulns:
            grouped_vulns[key] = []
        if flow_entry not in grouped_vulns[key]:
            grouped_vulns[key].append(flow_entry)

    final_output = []
    for key, flows in grouped_vulns.items():
        vuln_name, src_name, src_line, sink_name, sink_line = key
        final_output.append({
            "vulnerability": vuln_name,
            "source": [src_name, src_line],
            "sink": [sink_name, sink_line],
            "flows": flows
        })
    
    # Numbering A -> A_1, A_2, etc.
    vuln_counts = {}
    for entry in final_output:
        base = entry["vulnerability"]
        vuln_counts[base] = vuln_counts.get(base, 0) + 1
        entry["vulnerability"] = f"{base}_{vuln_counts[base]}"

    os.makedirs("output", exist_ok=True)
    slice_filename = os.path.splitext(os.path.basename(slice_path))[0]
    output_filename = f"output/{slice_filename}.output.json"

    with open(output_filename, 'w') as f:
        json.dump(final_output if final_output else ["none"], f, indent=4)

    print(f"Analysis complete. Output: {output_filename}")

if __name__ == "__main__":
    main()