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
        self.sources = {}
    
    def add_source(self, source: str, line: int, implicit: bool = False):
        if source not in self.sources:
            self.sources[source] = []
        if not any((l == line and path == [] and imp == implicit) for l, path, imp in self.sources[source]):
            self.sources[source].append((line, [], implicit))
    
    def apply_sanitizer(self, sanitizer: str, line: int):
        for source in self.sources:
            new_paths = []
            for src_line, path, implicit in self.sources[source]:
                entry = [sanitizer, line]
                if entry not in path:
                    new_path = list(path) 
                    new_path.append(entry)
                    new_paths.append((src_line, new_path, implicit))
                else:
                    new_paths.append((src_line, path, implicit))
            self.sources[source] = new_paths
            
    def get_paths(self, source):
        # Sort sanitizers by line to ensure deterministic output
        paths = self.sources.get(source, [])
        for i in range(len(paths)):
            # path is (line, sanitizer_list, implicit)
            sanitizers = sorted(paths[i][1], key=lambda x: x[1])
            paths[i] = (paths[i][0], sanitizers, paths[i][2])
        return paths
        
    def get_sources(self):
        return list(self.sources.keys())

    def combine(self, other):
        result = TaintLabel()
        for src, paths in self.sources.items():
            result.sources[src] = []
            for l, path, imp in paths:
                result.sources[src].append((l, list(path), imp))
        
        for src, paths in other.sources.items():
            if src not in result.sources:
                result.sources[src] = []
            for l, path, imp in paths:
                if (l, path, imp) not in result.sources[src]:
                    result.sources[src].append((l, list(path), imp))
        return result

    def force_implicit(self):
        result = TaintLabel()
        for src, paths in self.sources.items():
            result.sources[src] = []
            for l, path, _ in paths:
                result.sources[src].append((l, list(path), True))
        return result
    
    def clone(self):
        new_label = TaintLabel()
        for src, paths in self.sources.items():
            new_label.sources[src] = []
            for l, path, imp in paths:
                new_path = [list(san) for san in path]
                new_label.sources[src].append((l, new_path, imp))
        return new_label

class MultiLabel:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        self.labels = {name: TaintLabel() for name in self.patterns}
        self.partial = False
    
    def add_source(self, pattern_name, source, line, implicit=False):
        if pattern_name in self.patterns:
            self.labels[pattern_name].add_source(source, line, implicit)
            
    def apply_sanitizer(self, pattern_name, sanitizer, line):
        if pattern_name in self.labels:
            self.labels[pattern_name].apply_sanitizer(sanitizer, line)
    
    def combine(self, other):
        result = MultiLabel(list(self.patterns.values()))
        result.partial = self.partial or other.partial
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].combine(other.labels[p_name])
        return result

    def force_implicit(self):
        result = MultiLabel(list(self.patterns.values()))
        result.partial = self.partial
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].force_implicit()
        return result
        
    def clone(self):
        new_ml = MultiLabel(list(self.patterns.values()))
        new_ml.labels = {name: lbl.clone() for name, lbl in self.labels.items()}
        new_ml.partial = self.partial
        return new_ml

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
            
    def create_uninstantiated_label(self, var_name, line):
        patterns = list(self.policy.patterns.values())
        implicit_taint = MultiLabel(patterns)
        self.mark_uninstantiated_source(var_name, line)
        for p in patterns:
            implicit_taint.add_source(p.get_name(), var_name, line)
        return implicit_taint

    def get_label(self, var_name, line):
        patterns = list(self.policy.patterns.values())
        empty_label = MultiLabel(patterns)
        current_taint = self.labelling.get(var_name, empty_label)
        
        if var_name in self.policy.source_to_patterns:
            explicit_taint = MultiLabel(patterns)
            self.source_lines[var_name] = line
            for pattern_name in self.policy.source_to_patterns[var_name]:
                explicit_taint.add_source(pattern_name, var_name, line)
            current_taint = current_taint.combine(explicit_taint)
            
        if var_name not in self.labelling:
             uninst = self.create_uninstantiated_label(var_name, line)
             current_taint = current_taint.combine(uninst)
        elif current_taint.partial:
             uninst = self.create_uninstantiated_label(var_name, line)
             current_taint = current_taint.combine(uninst)
            
        return current_taint

    def analyze_expression(self, node):
        patterns = list(self.policy.patterns.values())
        empty_label = MultiLabel(patterns)
        
        if isinstance(node, ast.Name):
            return self.get_label(node.id, self.get_line_number(node))
        
        elif isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            return empty_label
        
        elif isinstance(node, ast.BinOp):
            left = self.analyze_expression(node.left)
            right = self.analyze_expression(node.right)
            return left.combine(right)

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

        elif isinstance(node, ast.Attribute):
            obj_taint = self.analyze_expression(node.value)
            attr_taint = empty_label
            if node.attr in self.policy.source_to_patterns:
                 attr_taint = MultiLabel(patterns)
                 self.source_lines[node.attr] = self.get_line_number(node)
                 for pattern_name in self.policy.source_to_patterns[node.attr]:
                     attr_taint.add_source(pattern_name, node.attr, self.get_line_number(node))
            return obj_taint.combine(attr_taint)

        elif isinstance(node, ast.Subscript):
            obj_taint = self.analyze_expression(node.value)
            idx_taint = self.analyze_expression(node.slice)
            return obj_taint.combine(idx_taint)

        elif isinstance(node, ast.Call):
            func_name = self.get_func_name(node.func)
            line = self.get_line_number(node)
            
            call_taint = empty_label
            if func_name and func_name in self.policy.source_to_patterns:
                call_taint = MultiLabel(patterns)
                self.source_lines[func_name] = line
                for pattern_name in self.policy.source_to_patterns[func_name]:
                    call_taint.add_source(pattern_name, func_name, line)
            
            arg_taint = empty_label
            for arg in node.args:
                arg_label = self.analyze_expression(arg)
                arg_taint = arg_taint.combine(arg_label)
            
            if isinstance(node.func, ast.Attribute):
                obj_taint = self.analyze_expression(node.func.value)
                arg_taint = arg_taint.combine(obj_taint)

            self.check_sinks(func_name, arg_taint, line)

            result_taint = arg_taint.combine(call_taint)
            
            sanitizer_patterns = self.policy.get_sanitizer_patterns(func_name)
            for pattern_name in sanitizer_patterns:
                result_taint.apply_sanitizer(pattern_name, func_name, line)
                
            return result_taint
        
        return empty_label

    def check_sinks(self, sink_name, taint_label, line):
        if not sink_name: return
        sink_patterns = self.policy.get_sink_patterns(sink_name)
        for pattern_name in sink_patterns:
            pattern = self.policy.patterns[pattern_name]
            
            total_sink_taint = taint_label
            if pattern.implicit:
                total_sink_taint = total_sink_taint.combine(self.pc_taint)

            label = total_sink_taint.labels[pattern_name]
            for source in label.get_sources():
                paths = label.get_paths(source)
                for src_line, sanitizers, is_implicit in paths:
                    self.vulnerabilities.append({
                        "vulnerability": pattern_name,
                        "source": [source, src_line],
                        "sink": [sink_name, line],
                        "implicit": is_implicit,
                        "sanitizers": sanitizers
                    })

    def analyze_target(self, node):
        patterns = list(self.policy.patterns.values())
        empty = MultiLabel(patterns)
        
        if isinstance(node, ast.Name):
            return node.id, False, empty, None
        elif isinstance(node, ast.Attribute):
            root, _, _, _ = self.analyze_target(node.value)
            return root, True, empty, node.attr
        elif isinstance(node, ast.Subscript):
            root, _, _, _ = self.analyze_target(node.value)
            idx_taint = self.analyze_expression(node.slice)
            return root, True, idx_taint, None
            
        return None, False, empty, None

    def visit_Assign(self, node):
        line = self.get_line_number(node)
        value_taint = self.analyze_expression(node.value)
        
        final_value_taint = value_taint
        pc_implicit = self.pc_taint
        for pname, pat in self.policy.patterns.items():
            if pat.implicit:
                 final_value_taint.labels[pname] = final_value_taint.labels[pname].combine(pc_implicit.labels[pname])

        for target in node.targets:
            root_name, is_weak, structure_taint, attr_name = self.analyze_target(target)
            
            if root_name:
                total_incoming_taint = final_value_taint.combine(structure_taint)
                
                if root_name not in self.labelling:
                    if is_weak:
                        is_incoming_tainted = False
                        for label in total_incoming_taint.labels.values():
                            if label.get_sources():
                                is_incoming_tainted = True
                                break
                        if not is_incoming_tainted:
                            continue 
                        self.labelling[root_name] = MultiLabel(list(self.policy.patterns.values()))
                
                old_taint = self.labelling.get(root_name, MultiLabel(list(self.policy.patterns.values())))
                
                if is_weak:
                    new_taint = old_taint.combine(total_incoming_taint)
                else:
                    new_taint = total_incoming_taint
                    new_taint.partial = False
                
                self.labelling[root_name] = new_taint
                
                if not is_weak and root_name in self.uninstantiated_sources:
                     self.uninstantiated_sources.discard(root_name)
                
                self.check_sinks(root_name, new_taint, line)
                if attr_name:
                    self.check_sinks(attr_name, total_incoming_taint, line)

        self.generic_visit(node)
    
    def visit_Expr(self, node):
        self.analyze_expression(node.value)
        self.generic_visit(node)

    def merge_states(self, state1, state2):
        all_keys = set(state1.keys()) | set(state2.keys())
        merged = {}
        for k in all_keys:
            if k in state1 and k in state2:
                merged[k] = state1[k].combine(state2[k])
            elif k in state1:
                merged[k] = state1[k].clone()
                merged[k].partial = True
            else:
                merged[k] = state2[k].clone()
                merged[k].partial = True
        return merged
    
    def merge_all_states(self, state_list):
        if not state_list: return {}
        if len(state_list) == 1: return state_list[0]
        final_state = state_list[0]
        for next_state in state_list[1:]:
            final_state = self.merge_states(final_state, next_state)
        return final_state

    def extract_explicit_sanitizers(self, multilabel):
        # Only extract sanitizers from paths that are NOT implicit
        sanitizers = set()
        for label in multilabel.labels.values():
             for src, paths in label.sources.items():
                 for l, path, imp in paths:
                     if not imp: # Check implicit flag
                         for san in path:
                             sanitizers.add(tuple(san))
        return sanitizers

    def apply_sanitizers_to_all_patterns(self, pc_taint, sanitizers):
        if not sanitizers: return pc_taint
        new_pc = pc_taint.clone()
        for san_name, san_line in sanitizers:
            target_patterns = self.policy.get_sanitizer_patterns(san_name)
            for p_name in target_patterns:
                new_pc.apply_sanitizer(p_name, san_name, san_line)
        return new_pc

    def visit_If(self, node):
        cond_taint = self.analyze_expression(node.test)
        
        prev_pc_taint = self.pc_taint
        implicit_cond = cond_taint.force_implicit()
        
        base_branch_pc = self.pc_taint.combine(implicit_cond)
        
        # Region Guard: Cross-apply sanitizers found in If condition
        # Filter to only explicit ones to avoid implicit noise from loops
        cond_sanitizers = self.extract_explicit_sanitizers(cond_taint)
        
        state_before = {k: v.clone() for k, v in self.labelling.items()}
        uninstantiated_before = self.uninstantiated_sources.copy()
        
        # --- BRANCH 1 (Body/Then) - GUARDED ---
        self.pc_taint = self.apply_sanitizers_to_all_patterns(base_branch_pc, cond_sanitizers)
        for stmt in node.body:
            self.visit(stmt)
        state_after_body = self.labelling
        uninstantiated_after_body = self.uninstantiated_sources
        
        # --- BRANCH 2 (Else) - UNGUARDED ---
        self.labelling = {k: v.clone() for k, v in state_before.items()}
        self.uninstantiated_sources = uninstantiated_before.copy()
        
        self.pc_taint = base_branch_pc
        if node.orelse:
            for stmt in node.orelse:
                self.visit(stmt)
        
        state_after_else = self.labelling
        
        # --- MERGE ---
        self.labelling = self.merge_states(state_after_body, state_after_else)
        self.uninstantiated_sources = uninstantiated_after_body | self.uninstantiated_sources
        self.pc_taint = prev_pc_taint

    def visit_While(self, node):
        prev_pc_taint = self.pc_taint
        
        state_0 = {k: v.clone() for k, v in self.labelling.items()}
        uninst_0 = self.uninstantiated_sources.copy()
        
        collected_labels = [state_0]
        collected_uninst = [uninst_0]
        
        for _ in range(3):
            cond_taint = self.analyze_expression(node.test)
            implicit_cond = cond_taint.force_implicit()
            
            # Loop Condition: Only implicit flow, NO cross-application of sanitizers
            loop_pc_taint = prev_pc_taint.combine(implicit_cond)
            self.pc_taint = loop_pc_taint
            
            for stmt in node.body:
                self.visit(stmt)
            
            state_i = {k: v.clone() for k, v in self.labelling.items()}
            uninst_i = self.uninstantiated_sources.copy()
            collected_labels.append(state_i)
            collected_uninst.append(uninst_i)
        
        self.labelling = self.merge_all_states(collected_labels)
        
        final_uninst = set()
        for s in collected_uninst:
            final_uninst.update(s)
        self.uninstantiated_sources = final_uninst
        
        self.pc_taint = prev_pc_taint
        
        if hasattr(node, 'orelse') and node.orelse:
            pass 

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