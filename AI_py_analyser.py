import ast
import sys
import json
import os
import copy

class TaintObject:
    def __init__(self, source_name, source_line, sanitizers=None, is_implicit=False):
        self.source_name = source_name
        self.source_line = source_line
        self.sanitizers = sanitizers if sanitizers is not None else []
        self.is_implicit = is_implicit

    def copy(self):
        new_sanitizers = [s[:] for s in self.sanitizers]
        return TaintObject(self.source_name, self.source_line, new_sanitizers, self.is_implicit)

    def add_sanitizer(self, name, line):
        self.sanitizers.append([name, line])

    def mark_implicit(self):
        self.is_implicit = True

    def __eq__(self, other):
        return (self.source_name == other.source_name and
                self.source_line == other.source_line and
                self.is_implicit == other.is_implicit and
                self.sanitizers == other.sanitizers)

    def __hash__(self):
        san_tuple = tuple(tuple(s) for s in self.sanitizers)
        return hash((self.source_name, self.source_line, self.is_implicit, san_tuple))

class VulnerabilityReport:
    def __init__(self, vuln_name, source, sink, is_implicit, sanitizers):
        self.vuln_name = vuln_name
        self.source = source
        self.sink = sink
        self.is_implicit = is_implicit
        self.sanitizers = sanitizers

class Analyser(ast.NodeVisitor):
    def __init__(self, patterns):
        self.patterns = patterns
        # State: var_name -> list of TaintObjects
        self.taints = {}
        self.implicit_stack = []
        self.vulnerabilities = []

    def get_taint(self, var_name):
        return [t.copy() for t in self.taints.get(var_name, [])]

    def set_taint(self, var_name, taint_list):
        self.taints[var_name] = taint_list

    def extend_taint(self, var_name, taint_list):
        """Merges new taints into existing variable state (for attributes/subscripts)"""
        current = self.get_taint(var_name)
        for t in taint_list:
            if t not in current:
                current.append(t)
        self.taints[var_name] = current

    def merge_states(self, state_a, state_b):
        """Merges two taint states (dictionaries) returning the Union."""
        merged = {}
        all_keys = set(state_a.keys()) | set(state_b.keys())
        for k in all_keys:
            list_a = state_a.get(k, [])
            list_b = state_b.get(k, [])
            # Union and deduplicate
            combined = list_a + list_b
            unique = []
            for t in combined:
                if t not in unique:
                    unique.append(t)
            merged[k] = unique
        return merged

    def visit_Assign(self, node):
        rhs_taints = self.evaluate_expr(node.value)

        # Apply Implicit Context
        if self.implicit_stack:
            for t in rhs_taints:
                t.mark_implicit()
            for implicit_source in self.implicit_stack:
                t_impl = implicit_source.copy()
                t_impl.mark_implicit()
                rhs_taints.append(t_impl)

        for target in node.targets:
            self.assign_to_target(target, rhs_taints, node.lineno)

        self.generic_visit(node)

    def assign_to_target(self, target, taints, lineno):
        """Recursively handles assignment targets (Name, Attribute, Subscript, Tuple)"""
        if isinstance(target, ast.Name):
            target_name = target.id
            self.check_if_sink(target_name, lineno, taints)
            # Overwrite for simple assignment
            self.set_taint(target_name, taints)
        
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # For complex assignments (x.y = ...), we MERGE taint into the base object 'x'
            target_name = self.get_complex_target_name(target)
            if target_name:
                self.check_if_sink(target_name, lineno, taints)
                self.extend_taint(target_name, taints)

        elif isinstance(target, (ast.Tuple, ast.List)):
            # Handle unpacking: a, b = c
            # (Simplified: we assign the WHOLE taint to ALL targets in unpacking)
            for elt in target.elts:
                self.assign_to_target(elt, taints, lineno)

    def get_complex_target_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self.get_complex_target_name(node.value)
        elif isinstance(node, ast.Subscript):
            return self.get_complex_target_name(node.value)
        return None

    def visit_If(self, node):
        condition_taints = self.evaluate_expr(node.test)
        self.implicit_stack.extend(condition_taints)

        # Snapshot state before branching
        before_state = {k: [t.copy() for t in v] for k, v in self.taints.items()}

        # Branch 1: If Body
        for stmt in node.body:
            self.visit(stmt)
        after_if_state = self.taints

        # Restore state for Else Branch
        self.taints = {k: [t.copy() for t in v] for k, v in before_state.items()}

        # Branch 2: Else Body
        if node.orelse:
            for stmt in node.orelse:
                self.visit(stmt)
        after_else_state = self.taints

        # Merge Branches
        self.taints = self.merge_states(after_if_state, after_else_state)

        # Pop implicit context
        for _ in range(len(condition_taints)):
            self.implicit_stack.pop()

    def visit_While(self, node):
        # Fixed-point iteration with State Merging
        # We assume the loop can execute 0 times (skip) or N times.
        # So we merge the result of the body with the state before the body.
        
        max_iterations = 10
        
        for _ in range(max_iterations):
            start_state = {k: [t.copy() for t in v] for k, v in self.taints.items()}
            
            condition_taints = self.evaluate_expr(node.test)
            self.implicit_stack.extend(condition_taints)

            for stmt in node.body:
                self.visit(stmt)

            if node.orelse:
                for stmt in node.orelse:
                    self.visit(stmt)
            
            for _ in range(len(condition_taints)):
                self.implicit_stack.pop()

            end_state = self.taints
            
            # Merge End state with Start state (Accumulate taints)
            merged_state = self.merge_states(start_state, end_state)
            
            # Check for convergence
            # If merged state is effectively same as start_state, we are stable
            if self.states_are_equal(start_state, merged_state):
                self.taints = merged_state
                break
            
            self.taints = merged_state

    def states_are_equal(self, state_a, state_b):
        if set(state_a.keys()) != set(state_b.keys()):
            return False
        for k in state_a:
            if len(state_a[k]) != len(state_b[k]):
                return False
            # Deep check using set of hashes for order independence
            hashes_a = {hash(t) for t in state_a[k]}
            hashes_b = {hash(t) for t in state_b[k]}
            if hashes_a != hashes_b:
                return False
        return True

    def visit_Expr(self, node):
        self.evaluate_expr(node.value)
        self.generic_visit(node)  
         

    def evaluate_expr(self, node):
        taints = []
        if isinstance(node, ast.Name):
            if node.id in self.taints:
                taints.extend(self.get_taint(node.id))
            else:
                # Uninstantiated = Source
                taints.append(TaintObject(node.id, node.lineno))
            
            # Pattern Source Check (Generates new taint if variable is a source pattern)
            for p in self.patterns:
                if node.id in p['sources']:
                    new_taint = TaintObject(node.id, node.lineno)
                    if new_taint not in taints:
                        taints.append(new_taint)

        elif isinstance(node, ast.BinOp):
            taints.extend(self.evaluate_expr(node.left))
            taints.extend(self.evaluate_expr(node.right))
        elif isinstance(node, ast.BoolOp):
            for val in node.values:
                taints.extend(self.evaluate_expr(val))
        elif isinstance(node, ast.Compare):
            taints.extend(self.evaluate_expr(node.left))
            for comp in node.comparators:
                taints.extend(self.evaluate_expr(comp))
        elif isinstance(node, ast.Call):
            taints.extend(self.handle_call(node))
        elif isinstance(node, ast.Attribute):
            taints.extend(self.evaluate_expr(node.value))
            for p in self.patterns:
                if node.attr in p['sources']:
                     taints.append(TaintObject(node.attr, node.lineno))
        elif isinstance(node, ast.Subscript):
            taints.extend(self.evaluate_expr(node.value))
            taints.extend(self.evaluate_expr(node.slice))
        elif isinstance(node, (ast.List, ast.Tuple)):
             for elt in node.elts:
                 taints.extend(self.evaluate_expr(elt))

        # Deduplicate
        unique_taints = []
        for t in taints:
            if t not in unique_taints:
                unique_taints.append(t)
        return unique_taints

    def handle_call(self, node):
        func_name = self.get_func_name(node.func)
        args_taints = []
        for arg in node.args:
            args_taints.extend(self.evaluate_expr(arg))
        for keyword in node.keywords:
            args_taints.extend(self.evaluate_expr(keyword.value))

        # Check Sink
        self.check_if_sink(func_name, node.lineno, args_taints)

        # Handle Returns
        return_taints = []
        if args_taints:
            for t in args_taints:
                t_new = t.copy()
                is_sanitizer = False
                for p in self.patterns:
                    if func_name in p['sanitizers']:
                        is_sanitizer = True
                        break
                if is_sanitizer:
                    t_new.add_sanitizer(func_name, node.lineno)
                return_taints.append(t_new)

        for p in self.patterns:
            if func_name in p['sources']:
                return_taints.append(TaintObject(func_name, node.lineno))

        return return_taints

    def check_if_sink(self, sink_name, lineno, incoming_taints):
        if not incoming_taints: return
        for p in self.patterns:
            if sink_name in p['sinks']:
                for taint in incoming_taints:
                    # Match Source
                    is_declared = taint.source_name in p['sources']
                    is_generic = True
                    for any_p in self.patterns:
                        if taint.source_name in any_p['sources']:
                            is_generic = False
                            break
                    
                    if not (is_declared or is_generic):
                        continue

                    # Match Implicit
                    if taint.is_implicit and p['implicit'] == 'no':
                        continue

                    # Sanitizers
                    relevant_sanitizers = []
                    for s_name, s_line in taint.sanitizers:
                        if s_name in p['sanitizers']:
                            relevant_sanitizers.append([s_name, s_line])
                    
                    self.vulnerabilities.append(
                        VulnerabilityReport(
                            p['vulnerability'],
                            (taint.source_name, taint.source_line),
                            (sink_name, lineno),
                            taint.is_implicit,
                            relevant_sanitizers
                        )
                    )

    def get_func_name(self, node):
        if isinstance(node, ast.Name): return node.id
        elif isinstance(node, ast.Attribute): return node.attr
        return "unknown"

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

    analyser = Analyser(patterns)
    analyser.visit(tree)

    # Grouping
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
    
    # Numbering
    vuln_counts = {}
    for entry in final_output:
        base = entry["vulnerability"]
        vuln_counts[base] = vuln_counts.get(base, 0) + 1
        entry["vulnerability"] = f"{base}_{vuln_counts[base]}"

    output_dir = "./output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    slice_filename = os.path.basename(slice_path)
    output_filename = os.path.join(output_dir, f"{slice_filename}.output.json")

    with open(output_filename, 'w') as f:
        json.dump(final_output, f, indent=4)

if __name__ == "__main__":
    main()