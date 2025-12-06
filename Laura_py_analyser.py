#!/usr/bin/env python3
import ast
import sys
import os
import json
import copy

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

class TaintLabel:
    def __init__(self):
        # source -> list of (source_line, [ (sanitizer_name, sanitizer_line), ... ], implicit_bool)
        self.sources = {}
    
    def add_source(self, source: str, line: int, implicit: bool = False):
        if source not in self.sources:
            self.sources[source] = []
        # Add a path if it doesn't exist (checking line, sanitizers, and implicit flag)
        if not any((l == line and path == [] and imp == implicit) for l, path, imp in self.sources[source]):
            self.sources[source].append((line, [], implicit))
    
    def apply_sanitizer(self, sanitizer: str, line: int):
        for source in self.sources:
            new_paths = []
            for src_line, path, implicit in self.sources[source]:
                new_path = list(path) 
                new_path.append([sanitizer, line])
                new_paths.append((src_line, new_path, implicit))
            self.sources[source] = new_paths
            
    def get_paths(self, source):
        return self.sources.get(source, [])
        
    def get_sources(self):
        return list(self.sources.keys())

    def combine(self, other):
        result = TaintLabel()
        # Deep copy self sources
        for src, paths in self.sources.items():
            result.sources[src] = []
            for l, path, imp in paths:
                result.sources[src].append((l, list(path), imp))
        
        # Merge other sources
        for src, paths in other.sources.items():
            if src not in result.sources:
                result.sources[src] = []
            for l, path, imp in paths:
                if (l, path, imp) not in result.sources[src]:
                    result.sources[src].append((l, list(path), imp))
        return result

    def force_implicit(self):
        """Returns a new TaintLabel where all paths are marked as implicit."""
        result = TaintLabel()
        for src, paths in self.sources.items():
            result.sources[src] = []
            for l, path, _ in paths:
                # Force implicit=True
                result.sources[src].append((l, list(path), True))
        return result

class MultiLabel:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        self.labels = {name: TaintLabel() for name in self.patterns}
    
    def add_source(self, pattern_name, source, line, implicit=False):
        if pattern_name in self.patterns:
            self.labels[pattern_name].add_source(source, line, implicit)
            
    def apply_sanitizer(self, pattern_name, sanitizer, line):
        if pattern_name in self.labels:
            self.labels[pattern_name].apply_sanitizer(sanitizer, line)
    
    def combine(self, other):
        result = MultiLabel(list(self.patterns.values()))
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].combine(other.labels[p_name])
        return result

    def force_implicit(self):
        result = MultiLabel(list(self.patterns.values()))
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].force_implicit()
        return result

class Policy:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        self.source_to_patterns = {}
        self.sink_to_patterns = {}
        self.sanitizer_to_patterns = {}
        
        for name, pattern in self.patterns.items():
            for src in pattern.get_sources():
                self.source_to_patterns.setdefault(src, set()).add(name)
            for snk in pattern.get_sinks():
                self.sink_to_patterns.setdefault(snk, set()).add(name)
            for san in pattern.get_sanitizers():
                self.sanitizer_to_patterns.setdefault(san, set()).add(name)
    
    def get_sink_patterns(self, sink_name):
        return self.sink_to_patterns.get(sink_name, set())
        
    def get_sanitizer_patterns(self, sanitizer_name):
        return self.sanitizer_to_patterns.get(sanitizer_name, set())

class Analyser(ast.NodeVisitor):
    def __init__(self, patterns):
        self.policy = Policy(patterns)
        self.labelling = {}  # var -> MultiLabel
        self.vulnerabilities = []
        self.source_lines = {}
        self.uninstantiated_sources = set()
        
        # Tracks the taint of the current control flow context (Program Counter)
        self.pc_taint = MultiLabel(patterns)
    
    def get_line_number(self, node):
        return getattr(node, 'lineno', 1)
    
    def get_func_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None
        
    def mark_uninstantiated_source(self, var_name, line):
        if var_name not in self.labelling:
            self.uninstantiated_sources.add(var_name)
            self.source_lines[var_name] = line
            
    def analyze_expression(self, node):
        patterns = list(self.policy.patterns.values())
        empty_label = MultiLabel(patterns)
        
        if isinstance(node, ast.Name):
            var_name = node.id
            line = self.get_line_number(node)
            
            current_taint = self.labelling.get(var_name, empty_label)
            
            # 1. Explicit Sources
            if var_name in self.policy.source_to_patterns:
                explicit_taint = MultiLabel(patterns)
                self.source_lines[var_name] = line
                for pattern_name in self.policy.source_to_patterns[var_name]:
                    explicit_taint.add_source(pattern_name, var_name, line)
                current_taint = current_taint.combine(explicit_taint)
                
            # 2. Uninstantiated Sources
            if var_name not in self.labelling:
                self.mark_uninstantiated_source(var_name, line)
                implicit_taint = MultiLabel(patterns)
                for p in patterns:
                    implicit_taint.add_source(p.get_name(), var_name, line)
                current_taint = current_taint.combine(implicit_taint)
                
            return current_taint
        
        elif isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            return empty_label
        
        elif isinstance(node, ast.BinOp):
            left = self.analyze_expression(node.left)
            right = self.analyze_expression(node.right)
            return left.combine(right)

        # IMPORTANT: Added support for Compare (==, !=) and Boolean operators (and, or)
        elif isinstance(node, ast.Compare):
            left = self.analyze_expression(node.left)
            total = left
            for comparator in node.comparators:
                comp_taint = self.analyze_expression(comparator)
                total = total.combine(comp_taint)
            return total

        elif isinstance(node, ast.BoolOp):
            total = self.analyze_expression(node.values[0])
            for val in node.values[1:]:
                total = total.combine(self.analyze_expression(val))
            return total
            
        elif isinstance(node, ast.UnaryOp):
            return self.analyze_expression(node.operand)
            
        elif isinstance(node, ast.Call):
            func_name = self.get_func_name(node.func)
            line = self.get_line_number(node)
            
            # 1. Function as Source
            call_taint = empty_label
            if func_name and func_name in self.policy.source_to_patterns:
                call_taint = MultiLabel(patterns)
                self.source_lines[func_name] = line
                for pattern_name in self.policy.source_to_patterns[func_name]:
                    call_taint.add_source(pattern_name, func_name, line)
            
            # 2. Function Arguments Taint
            arg_taint = empty_label
            for arg in node.args:
                arg_label = self.analyze_expression(arg)
                arg_taint = arg_taint.combine(arg_label)
            
            # 3. Check for Sinks
            sink_patterns = self.policy.get_sink_patterns(func_name)
            for pattern_name in sink_patterns:
                pattern = self.policy.patterns[pattern_name]
                
                # Check Direct Taint
                total_sink_taint = arg_taint
                
                # Check Implicit Taint (if pattern allows)
                if pattern.implicit:
                    # Merge PC taint into the taint checked at the sink
                    total_sink_taint = total_sink_taint.combine(self.pc_taint)

                label = total_sink_taint.labels[pattern_name]
                for source in label.get_sources():
                    paths = label.get_paths(source)
                    for src_line, sanitizers, is_implicit in paths:
                        self.vulnerabilities.append({
                            "vulnerability": pattern_name,
                            "source": [source, src_line],
                            "sink": [func_name, line],
                            "implicit": is_implicit,
                            "sanitizers": sanitizers
                        })

            # 4. Apply Sanitizers
            result_taint = arg_taint.combine(call_taint)
            
            sanitizer_patterns = self.policy.get_sanitizer_patterns(func_name)
            for pattern_name in sanitizer_patterns:
                result_taint.apply_sanitizer(pattern_name, func_name, line)
                
            return result_taint
        
        return empty_label
    
    def visit_Assign(self, node):
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0].id
            line = self.get_line_number(node)
            
            value_taint = self.analyze_expression(node.value)
            
            # If the assignment happens in a tainted context (Implicit Flow)
            # we merge the PC taint into the value, but ONLY for patterns that support implicit flows.
            pc_implicit = self.pc_taint 
            
            # We need to selectively merge PC taint only for implicit=yes patterns
            final_taint = value_taint
            
            # To do this safely, we iterate patterns
            for pname, pat in self.policy.patterns.items():
                if pat.implicit:
                    # Merge PC label for this pattern
                    final_taint.labels[pname] = final_taint.labels[pname].combine(pc_implicit.labels[pname])

            if target in self.uninstantiated_sources:
                self.uninstantiated_sources.discard(target)
            
            self.labelling[target] = final_taint
            
            # Check for Variable Sinks
            sink_patterns = self.policy.get_sink_patterns(target)
            for pattern_name in sink_patterns:
                pattern = self.policy.patterns[pattern_name]
                label = final_taint.labels[pattern_name]
                
                for source in label.get_sources():
                    paths = label.get_paths(source)
                    for src_line, sanitizers, is_implicit in paths:
                        self.vulnerabilities.append({
                            "vulnerability": pattern_name,
                            "source": [source, src_line],
                            "sink": [target, line],
                            "implicit": is_implicit,
                            "sanitizers": sanitizers
                        })
                        
        self.generic_visit(node)
    
    def visit_Expr(self, node):
        self.analyze_expression(node.value)
        self.generic_visit(node)

    def visit_If(self, node):
        self.handle_control_flow(node)

    def visit_While(self, node):
        self.handle_control_flow(node)

    def handle_control_flow(self, node):
        # 1. Analyze condition
        cond_taint = self.analyze_expression(node.test)
        
        # 2. Save previous PC taint
        prev_pc_taint = self.pc_taint
        
        # 3. Convert condition taint to implicit and merge into PC taint
        #    We force implicit flag=True on the condition taint.
        implicit_cond = cond_taint.force_implicit()
        self.pc_taint = self.pc_taint.combine(implicit_cond)
        
        # 4. Visit body
        for stmt in node.body:
            self.visit(stmt)
            
        # 5. Handle orelse (for If loops, or While else)
        if hasattr(node, 'orelse'):
            for stmt in node.orelse:
                self.visit(stmt)
        
        # 6. Restore PC taint
        self.pc_taint = prev_pc_taint

def load_patterns(patterns_data):
    return [Pattern(p["vulnerability"], p["sources"], p["sanitizers"], 
                   p["sinks"], p["implicit"] == "yes") for p in patterns_data]

def main():
    if len(sys.argv) != 3:
        sys.exit(1)

    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]

    if not os.path.exists(slice_path) or not os.path.exists(patterns_path):
        sys.exit(1)

    with open(patterns_path, 'r') as f:
        try:
            patterns = json.load(f)
        except:
            sys.exit(1)

    with open(slice_path, 'r') as f:
        source_code = f.read()
    
    try:
        tree = ast.parse(source_code)
    except:
        sys.exit(1)

    analyser = Analyser(load_patterns(patterns))
    analyser.visit(tree)

    # Group vulnerabilities
    grouped_vulns = {}
    for v in analyser.vulnerabilities:
        key = (v["vulnerability"], v["source"][0], v["source"][1], v["sink"][0], v["sink"][1])
        flow_type = "implicit" if v["implicit"] else "explicit"
        sanitizers = v["sanitizers"]
        flow_entry = [flow_type, sanitizers]
        
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
    
    final_output.sort(key=lambda x: (x["vulnerability"], x["source"][0], x["sink"][0]))

    # Add numeric suffixes
    vuln_counters = {}
    for item in final_output:
        original_name = item["vulnerability"]
        if original_name not in vuln_counters:
            vuln_counters[original_name] = 1
        else:
            vuln_counters[original_name] += 1
        item["vulnerability"] = f"{original_name}_{vuln_counters[original_name]}"

    os.makedirs("output", exist_ok=True)
    slice_filename = os.path.splitext(os.path.basename(slice_path))[0]
    output_filename = f"output/{slice_filename}.output.json"

    with open(output_filename, 'w') as f:
        json.dump(final_output, f, indent=4)

if __name__ == "__main__":
    main()