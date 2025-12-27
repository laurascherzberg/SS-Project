#!/usr/bin/env python3

# Import necessary libraries for AST parsing, system operations, and JSON handling
import ast
import sys
import os
import json

# ============================================================================
# PATTERN CLASS: Defines a security vulnerability pattern to track
# ============================================================================
# Think of this as a blueprint for "what we're looking for"
# Example: SQL Injection pattern has sources (user_input), sinks (execute_query),
# and sanitizers (escape_string) that can clean the taint

class Pattern:
    def __init__(self, name: str, sources: list, sanitizers: list, sinks: list, implicit: bool):
        """
        name: vulnerability type (e.g., "SQL Injection")
        sources: where untrusted data enters (e.g., request.args)
        sanitizers: functions that clean data (e.g., escape_sql)
        sinks: dangerous functions that shouldn't receive tainted data (e.g., execute)
        implicit: whether data can be tainted implicitly (e.g., through control flow)
        """
        self.name = name
        self.sources = set(sources)
        self.sanitizers = set(sanitizers)
        self.sinks = set(sinks)
        self.implicit = implicit

    def get_name(self):
        return self.name

    def get_sources(self):
        # Return a copy to prevent external modification
        return self.sources.copy()

    def get_sanitizers(self):
        return self.sanitizers.copy()

    def get_sinks(self):
        return self.sinks.copy()

# ============================================================================
# TAINTLABEL CLASS: Tracks taint information for a single pattern
# ============================================================================
# Think of this as a "tracking record" for one variable's contamination
# It records: where the taint came from, what cleaning functions were applied,
# and the path the taint took through the code

class TaintLabel:
    def __init__(self):
        # Dictionary mapping source names to lists of (line_number, sanitizer_path, is_implicit)
        # Example: {"user_input": [(5, [["escape", 10]], False)]}
        self.sources = {}

    def add_source(self, source: str, line: int, implicit: bool = False):
        """
        Mark that a variable is tainted by a source at a specific line.
        implicit=True means the taint came from control flow, not direct assignment.
        """
        if source not in self.sources:
            self.sources[source] = []
        # Avoid duplicates: check if this exact entry already exists
        if not any((l == line and path == [] and imp == implicit) for l, path, imp in self.sources[source]):
            self.sources[source].append((line, [], implicit))

    def apply_sanitizer(self, sanitizer: str, line: int):
        """
        Record that a sanitizer function was applied to clean the taint.
        Example: if "escape_sql" is called at line 10, record it in the sanitizer path.
        """
        for source in self.sources:
            new_paths = []
            for src_line, path, implicit in self.sources[source]:
                entry = [sanitizer, line]
                # Only add sanitizer if it's not already in the path (avoid infinite loops)
                if entry not in path:
                    new_path = list(path)
                    new_path.append(entry)
                    new_paths.append((src_line, new_path, implicit))
                else:
                    new_paths.append((src_line, path, implicit))
            self.sources[source] = new_paths

    def get_paths(self, source):
        """
        Get all taint paths for a specific source, sorted by sanitizer line number.
        Returns: [(source_line, [sanitizers], is_implicit), ...]
        """
        paths = self.sources.get(source, [])
        for i in range(len(paths)):
            sanitizers = sorted(paths[i][1], key=lambda x: x[1])
            paths[i] = (paths[i][0], sanitizers, paths[i][2])
        return paths

    def get_sources(self):
        """Return all sources that taint this variable."""
        return list(self.sources.keys())

    def combine(self, other):
        """
        Merge two taint labels together.
        Used when combining taints from multiple branches or operations.
        """
        result = TaintLabel()
        # Copy all sources from self
        for src, paths in self.sources.items():
            result.sources[src] = []
            for l, path, imp in paths:
                result.sources[src].append((l, list(path), imp))
        # Add new sources from other (avoiding duplicates)
        for src, paths in other.sources.items():
            if src not in result.sources:
                result.sources[src] = []
            for l, path, imp in paths:
                if (l, path, imp) not in result.sources[src]:
                    result.sources[src].append((l, list(path), imp))
        return result

    def force_implicit(self):
        """Mark all taint paths as implicit (e.g., from control flow)."""
        result = TaintLabel()
        for src, paths in self.sources.items():
            result.sources[src] = []
            for l, path, _ in paths:
                result.sources[src].append((l, list(path), True))
        return result

    def clone(self):
        """Create a deep copy of this label."""
        new_label = TaintLabel()
        for src, paths in self.sources.items():
            new_label.sources[src] = []
            for l, path, imp in paths:
                new_path = [list(san) for san in path]
                new_label.sources[src].append((l, new_path, imp))
        return new_label

# ============================================================================
# MULTILABEL CLASS: Tracks taint for multiple patterns simultaneously
# ============================================================================
# Instead of tracking one vulnerability type, this tracks ALL patterns at once.
# Imagine a variable that could be vulnerable to SQL Injection AND XSS simultaneously.
# This class maintains one TaintLabel for each pattern.

class MultiLabel:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        # One TaintLabel per pattern
        self.labels = {name: TaintLabel() for name in self.patterns}
        # partial=True means the variable might have additional sources we haven't tracked yet
        self.partial = False

    def add_source(self, pattern_name, source, line, implicit=False):
        """Add a source to a specific pattern's taint label."""
        if pattern_name in self.patterns:
            self.labels[pattern_name].add_source(source, line, implicit)

    def apply_sanitizer(self, pattern_name, sanitizer, line):
        """Apply a sanitizer to a specific pattern's taint label."""
        if pattern_name in self.labels:
            self.labels[pattern_name].apply_sanitizer(sanitizer, line)

    def combine(self, other):
        """Merge two MultiLabels together (for all patterns)."""
        result = MultiLabel(list(self.patterns.values()))
        result.partial = self.partial or other.partial
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].combine(other.labels[p_name])
        return result

    def force_implicit(self):
        """Mark all taints across all patterns as implicit."""
        result = MultiLabel(list(self.patterns.values()))
        result.partial = self.partial
        for p_name in result.labels:
            result.labels[p_name] = self.labels[p_name].force_implicit()
        return result

    def clone(self):
        """Create a deep copy of this MultiLabel."""
        new_ml = MultiLabel(list(self.patterns.values()))
        new_ml.labels = {name: lbl.clone() for name, lbl in self.labels.items()}
        new_ml.partial = self.partial
        return new_ml

# ============================================================================
# POLICY CLASS: Maps sources/sinks/sanitizers to their patterns
# ============================================================================
# This is an index that answers questions like:
# "If I see source X, which patterns are affected?"
# "If I see sink Y, which patterns should I check?"

class Policy:
    def __init__(self, patterns):
        self.patterns = {p.get_name(): p for p in patterns}
        # Maps: source_name -> {pattern_names}
        self.source_to_patterns = {}
        # Maps: sink_name -> {pattern_names}
        self.sink_to_patterns = {}
        # Maps: sanitizer_name -> {pattern_names}
        self.sanitizer_to_patterns = {}
        
        # Build these indices for quick lookup
        for name, pattern in self.patterns.items():
            for src in pattern.get_sources():
                self.source_to_patterns.setdefault(src, set()).add(name)
            for snk in pattern.get_sinks():
                self.sink_to_patterns.setdefault(snk, set()).add(name)
            for san in pattern.get_sanitizers():
                self.sanitizer_to_patterns.setdefault(san, set()).add(name)

    def get_sink_patterns(self, sink_name):
        """Return which patterns are affected by this sink."""
        return self.sink_to_patterns.get(sink_name, set())

    def get_sanitizer_patterns(self, sanitizer_name):
        """Return which patterns are affected by this sanitizer."""
        return self.sanitizer_to_patterns.get(sanitizer_name, set())

# ============================================================================
# ANALYSER CLASS: Main taint analysis engine (using AST visitor pattern)
# ============================================================================
# This walks through the Python code (as an Abstract Syntax Tree) and tracks
# how data flows from sources to sinks. It's like following breadcrumbs through
# the code to see if untrusted data reaches dangerous functions.

class Analyser(ast.NodeVisitor):
    def __init__(self, patterns):
        self.policy = Policy(patterns)
        # Maps variable names to their current taint state
        self.labelling = {}
        # Records found vulnerabilities
        self.vulnerabilities = []
        # Maps source names to the lines where they were introduced
        self.source_lines = {}
        # Tracks variables that might have sources but aren't explicitly assigned
        self.uninstantiated_sources = set()
        # Program counter taint (for implicit flows through control flow)
        self.pc_taint = MultiLabel(patterns)

    def get_line_number(self, node):
        """Extract line number from an AST node."""
        return getattr(node, 'lineno', 1)

    def get_func_name(self, node):
        """Extract function name from either a Name or Attribute node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None

    def mark_uninstantiated_source(self, var_name, line):
        """Record that a variable might be a source even though it's never assigned."""
        if var_name not in self.labelling:
            self.uninstantiated_sources.add(var_name)
            self.source_lines[var_name] = line

    def create_uninstantiated_label(self, var_name, line):
        """
        Create taint label for a variable that might be implicitly sourced.
        Example: a function parameter that could be untrusted user input.
        """
        patterns = list(self.policy.patterns.values())
        implicit_taint = MultiLabel(patterns)
        self.mark_uninstantiated_source(var_name, line)
        for p in patterns:
            implicit_taint.add_source(p.get_name(), var_name, line)
        return implicit_taint

    def get_label(self, var_name, line):
        """
        Get the taint label for a variable.
        Checks: explicit sources, implicit sources, and uninstantiated sources.
        """
        patterns = list(self.policy.patterns.values())
        empty_label = MultiLabel(patterns)
        current_taint = self.labelling.get(var_name, empty_label)
        
        # Check if this variable name is an explicit source
        if var_name in self.policy.source_to_patterns:
            explicit_taint = MultiLabel(patterns)
            self.source_lines[var_name] = line
            for pattern_name in self.policy.source_to_patterns[var_name]:
                explicit_taint.add_source(pattern_name, var_name, line)
            current_taint = current_taint.combine(explicit_taint)
        
        # If variable was never assigned, treat it as potentially sourced
        if var_name not in self.labelling:
            uninst = self.create_uninstantiated_label(var_name, line)
            current_taint = current_taint.combine(uninst)
        # If variable has partial taint (from branching), assume unknown sources too
        elif current_taint.partial:
            uninst = self.create_uninstantiated_label(var_name, line)
            current_taint = current_taint.combine(uninst)
        
        return current_taint

    def analyze_expression(self, node):
        """
        Recursively analyze an expression to determine its taint.
        Works for: variables, constants, binary operations, comparisons, etc.
        """
        patterns = list(self.policy.patterns.values())
        empty_label = MultiLabel(patterns)
        
        if isinstance(node, ast.Name):
            # Variable reference: look up its taint
            return self.get_label(node.id, self.get_line_number(node))
        
        elif isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            # Literal constants are not tainted
            return empty_label
        
        elif isinstance(node, ast.BinOp):
            # Binary operation (e.g., a + b): combine taint from both sides
            left = self.analyze_expression(node.left)
            right = self.analyze_expression(node.right)
            return left.combine(right)
        
        elif isinstance(node, ast.Compare):
            # Comparison (e.g., a > b): combine all operands
            left = self.analyze_expression(node.left)
            total = left
            for comparator in node.comparators:
                comp_taint = self.analyze_expression(comparator)
                total = total.combine(comp_taint)
            return total
        
        elif isinstance(node, ast.BoolOp):
            # Boolean operation (and/or): combine all values
            total = self.analyze_expression(node.values[0])
            for val in node.values[1:]:
                total = total.combine(self.analyze_expression(val))
            return total
        
        elif isinstance(node, ast.UnaryOp):
            # Unary operation (not, -): taint from the operand
            return self.analyze_expression(node.operand)
        
        elif isinstance(node, ast.Attribute):
            # Attribute access (e.g., obj.attr): check if attr itself is a source
            obj_taint = self.analyze_expression(node.value)
            attr_taint = empty_label
            if node.attr in self.policy.source_to_patterns:
                attr_taint = MultiLabel(patterns)
                self.source_lines[node.attr] = self.get_line_number(node)
                for pattern_name in self.policy.source_to_patterns[node.attr]:
                    attr_taint.add_source(pattern_name, node.attr, self.get_line_number(node))
            return obj_taint.combine(attr_taint)
        
        elif isinstance(node, ast.Subscript):
            # Subscript (e.g., arr[i]): combine taint from array and index
            obj_taint = self.analyze_expression(node.value)
            idx_taint = self.analyze_expression(node.slice)
            return obj_taint.combine(idx_taint)
        
        elif isinstance(node, ast.Call):
            # Function call: check for sources, sinks, and sanitizers
            func_name = self.get_func_name(node.func)
            line = self.get_line_number(node)
            
            # Check if function itself is a source (e.g., input())
            call_taint = empty_label
            if func_name and func_name in self.policy.source_to_patterns:
                call_taint = MultiLabel(patterns)
                self.source_lines[func_name] = line
                for pattern_name in self.policy.source_to_patterns[func_name]:
                    call_taint.add_source(pattern_name, func_name, line)
            
            # Analyze all arguments
            arg_taint = empty_label
            for arg in node.args:
                arg_label = self.analyze_expression(arg)
                arg_taint = arg_taint.combine(arg_label)
            
            # If it's a method call, include the object's taint
            if isinstance(node.func, ast.Attribute):
                obj_taint = self.analyze_expression(node.func.value)
                arg_taint = arg_taint.combine(obj_taint)
            
            # Check if this is a sink (dangerous function)
            self.check_sinks(func_name, arg_taint, line)
            
            # Result: combine argument taint with any source taint
            result_taint = arg_taint.combine(call_taint)
            
            # Apply sanitizers if this function cleans data
            sanitizer_patterns = self.policy.get_sanitizer_patterns(func_name)
            for pattern_name in sanitizer_patterns:
                result_taint.apply_sanitizer(pattern_name, func_name, line)
            
            return result_taint
        
        return empty_label

    def check_sinks(self, sink_name, taint_label, line):
        """
        Check if tainted data reaches a sink (dangerous function).
        If so, record a vulnerability.
        """
        if not sink_name:
            return
        
        sink_patterns = self.policy.get_sink_patterns(sink_name)
        for pattern_name in sink_patterns:
            pattern = self.policy.patterns[pattern_name]
            total_sink_taint = taint_label
            
            # For implicit patterns, include program counter taint
            if pattern.implicit:
                total_sink_taint = total_sink_taint.combine(self.pc_taint)
            
            label = total_sink_taint.labels[pattern_name]
            
            # For each source that taints this sink...
            for source in label.get_sources():
                paths = label.get_paths(source)
                for src_line, sanitizers, is_implicit in paths:
                    # Record the vulnerability
                    self.vulnerabilities.append({
                        "vulnerability": pattern_name,
                        "source": [source, src_line],
                        "sink": [sink_name, line],
                        "implicit": is_implicit,
                        "sanitizers": sanitizers
                    })

    def analyze_target(self, node):
        """
        Analyze an assignment target (left side of =).
        Determines: variable name, whether it's a weak update, and any sub-taints.
        """
        patterns = list(self.policy.patterns.values())
        empty = MultiLabel(patterns)
        
        if isinstance(node, ast.Name):
            # Simple variable: x = ...
            return node.id, False, empty, None
        
        elif isinstance(node, ast.Attribute):
            # Attribute: obj.attr = ...
            # Weak update: we're modifying a field, not the whole object
            root, _, _, _ = self.analyze_target(node.value)
            return root, True, empty, node.attr
        
        elif isinstance(node, ast.Subscript):
            # Subscript: arr[i] = ...
            # Weak update: we're modifying an element, not the whole array
            root, _, _, _ = self.analyze_target(node.value)
            idx_taint = self.analyze_expression(node.slice)
            return root, True, idx_taint, None
        
        return None, False, empty, None

    def visit_Assign(self, node):
        """
        Handle assignment statements (x = value).
        Propagate taint from right side to left side.
        """
        line = self.get_line_number(node)
        value_taint = self.analyze_expression(node.value)
        final_value_taint = value_taint
        
        # Implicit patterns: include program counter taint
        pc_implicit = self.pc_taint
        for pname, pat in self.policy.patterns.items():
            if pat.implicit:
                final_value_taint.labels[pname] = final_value_taint.labels[pname].combine(pc_implicit.labels[pname])
        
        # Process each assignment target
        for target in node.targets:
            root_name, is_weak, structure_taint, attr_name = self.analyze_target(target)
            if root_name:
                total_incoming_taint = final_value_taint.combine(structure_taint)
                
                # Weak update to untainted variable: skip if no taint incoming
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
                
                # Get the old taint (if any)
                old_taint = self.labelling.get(root_name, MultiLabel(list(self.policy.patterns.values())))
                
                # Weak update: combine old and new; Strong update: replace
                if is_weak:
                    new_taint = old_taint.combine(total_incoming_taint)
                else:
                    new_taint = total_incoming_taint
                
                new_taint.partial = False
                self.labelling[root_name] = new_taint
                
                # If we explicitly assigned to an uninstantiated source, mark it as instantiated
                if not is_weak and root_name in self.uninstantiated_sources:
                    self.uninstantiated_sources.discard(root_name)
                
                # Check if the assigned value reaches a sink
                self.check_sinks(root_name, new_taint, line)
                
                # For attribute assignments, check the attribute too
                if attr_name:
                    self.check_sinks(attr_name, total_incoming_taint, line)
        
        self.generic_visit(node)

    def visit_Expr(self, node):
        """
        Handle expression statements (standalone expressions like function calls).
        """
        self.analyze_expression(node.value)
        self.generic_visit(node)

    def merge_states(self, state1, state2):
        """
        Merge two execution states (e.g., from different branches).
        If variable is in both: combine taints.
        If variable is in only one: mark as partial (uncertain).
        """
        all_keys = set(state1.keys()) | set(state2.keys())
        merged = {}
        for k in all_keys:
            if k in state1 and k in state2:
                # Both branches have the variable: combine taints
                merged[k] = state1[k].combine(state2[k])
            elif k in state1:
                # Only in state1: might not exist in state2
                merged[k] = state1[k].clone()
                merged[k].partial = True
            else:
                # Only in state2: might not exist in state1
                merged[k] = state2[k].clone()
                merged[k].partial = True
        return merged

    def merge_all_states(self, state_list):
        """Merge a list of states together."""
        if not state_list:
            return {}
        if len(state_list) == 1:
            return state_list[0]
        final_state = state_list[0]
        for next_state in state_list[1:]:
            final_state = self.merge_states(final_state, next_state)
        return final_state

    def states_equal(self, state1, state2):
        """Check if two states are identical (for cycle detection in loops)."""
        if set(state1.keys()) != set(state2.keys()):
            return False
        for var_name in state1.keys():
            label1 = state1[var_name]
            label2 = state2[var_name]
            for pattern_name in label1.patterns:
                sources1 = label1.labels[pattern_name].sources
                sources2 = label2.labels[pattern_name].sources
                if sources1 != sources2:
                    return False
        return True

    def extract_explicit_sanitizers(self, multilabel):
        """Extract sanitizers that are explicitly applied (not implicit)."""
        sanitizers = set()
        for label in multilabel.labels.values():
            for src, paths in label.sources.items():
                for l, path, imp in paths:
                    if not imp:
                        for san in path:
                            sanitizers.add(tuple(san))
        return sanitizers

    def apply_sanitizers_to_all_patterns(self, pc_taint, sanitizers):
        """Apply a set of sanitizers to the program counter taint."""
        if not sanitizers:
            return pc_taint
        new_pc = pc_taint.clone()
        for san_name, san_line in sanitizers:
            target_patterns = self.policy.get_sanitizer_patterns(san_name)
            for p_name in target_patterns:
                new_pc.apply_sanitizer(p_name, san_name, san_line)
        return new_pc

    def visit_If(self, node):
        """
        Handle if statements (if/else branches).
        Analyzes both branches and merges their results.
        """
        # Analyze the condition to get its taint
        cond_taint = self.analyze_expression(node.test)
        prev_pc_taint = self.pc_taint
        
        # Condition taint is implicit (from control flow)
        implicit_cond = cond_taint.force_implicit()
        base_branch_pc = self.pc_taint.combine(implicit_cond)
        
        # Extract explicit sanitizers from condition
        cond_sanitizers = self.extract_explicit_sanitizers(cond_taint)
        
        # Save state before branching
        state_before = {k: v.clone() for k, v in self.labelling.items()}
        uninstantiated_before = self.uninstantiated_sources.copy()
        
        # === ANALYZE IF BODY ===
        self.pc_taint = self.apply_sanitizers_to_all_patterns(base_branch_pc, cond_sanitizers)
        for stmt in node.body:
            self.visit(stmt)
        state_after_body = self.labelling
        uninstantiated_after_body = self.uninstantiated_sources
        
        # === ANALYZE ELSE BODY ===
        # Restore state and analyze else branch
        self.labelling = {k: v.clone() for k, v in state_before.items()}
        self.uninstantiated_sources = uninstantiated_before.copy()
        self.pc_taint = base_branch_pc
        if node.orelse:
            for stmt in node.orelse:
                self.visit(stmt)
        state_after_else = self.labelling
        
        # === MERGE RESULTS ===
        self.labelling = self.merge_states(state_after_body, state_after_else)
        self.uninstantiated_sources = uninstantiated_after_body | self.uninstantiated_sources
        self.pc_taint = prev_pc_taint

    def visit_While(self, node):
        """
        Handle while loops.
        Iterates until a fixed point is reached (cycle detection).
        """
        prev_pc_taint = self.pc_taint
        
        # Initial state
        state_0 = {k: v.clone() for k, v in self.labelling.items()}
        uninst_0 = self.uninstantiated_sources.copy()
        
        # Track all states to detect cycles
        collected_labels = [state_0]
        collected_uninst = [uninst_0]
        max_iterations = 100
        iteration_count = 0
        
        # Iterate until fixed point or max iterations
        while iteration_count < max_iterations:
            # Analyze loop condition
            cond_taint = self.analyze_expression(node.test)
            implicit_cond = cond_taint.force_implicit()
            loop_pc_taint = prev_pc_taint.combine(implicit_cond)
            self.pc_taint = loop_pc_taint
            
            # Execute loop body once
            for stmt in node.body:
                self.visit(stmt)
            
            # Save state after this iteration
            state_i = {k: v.clone() for k, v in self.labelling.items()}
            uninst_i = self.uninstantiated_sources.copy()
            
            # Check if we've seen this state before (cycle detected)
            cycle_detected = False
            for previous_state in collected_labels:
                if self.states_equal(state_i, previous_state):
                    cycle_detected = True
                    break
            
            if cycle_detected:
                collected_labels.append(state_i)
                collected_uninst.append(uninst_i)
                break
            
            collected_labels.append(state_i)
            collected_uninst.append(uninst_i)
            iteration_count += 1
        
        # Merge all iteration states
        self.labelling = self.merge_all_states(collected_labels)
        final_uninst = set()
        for s in collected_uninst:
            final_uninst.update(s)
        self.uninstantiated_sources = final_uninst
        self.pc_taint = prev_pc_taint
        
        # Handle else clause (executed if loop completes normally)
        if hasattr(node, 'orelse') and node.orelse:
            pass

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_patterns(patterns_data):
    """Convert JSON pattern data into Pattern objects."""
    return [Pattern(p["vulnerability"], p["sources"], p["sanitizers"],
                    p["sinks"], p["implicit"] == "yes") for p in patterns_data]

def main():
    """
    Main entry point.
    Usage: python script.py <path_to_code> <path_to_patterns.json>
    """
    # Validate command line arguments
    if len(sys.argv) != 3:
        sys.exit(1)
    
    slice_path = sys.argv[1]
    patterns_path = sys.argv[2]
    
    # Validate file existence
    if not os.path.exists(slice_path) or not os.path.exists(patterns_path):
        sys.exit(1)
    
    # Load vulnerability patterns
    with open(patterns_path, 'r') as f:
        try:
            patterns = json.load(f)
        except:
            sys.exit(1)
    
    # Load source code
    with open(slice_path, 'r') as f:
        source_code = f.read()
    
    # Parse code into AST
    try:
        tree = ast.parse(source_code)
    except:
        sys.exit(1)
    
    # Run analysis
    analyser = Analyser(load_patterns(patterns))
    analyser.visit(tree)
    
    # Group vulnerabilities by key (avoid reporting duplicates)
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
    
    # Format output
    final_output = []
    for key, flows in grouped_vulns.items():
        vuln_name, src_name, src_line, sink_name, sink_line = key
        final_output.append({
            "vulnerability": vuln_name,
            "source": [src_name, src_line],
            "sink": [sink_name, sink_line],
            "flows": flows
        })
    
    # Sort for consistent output
    final_output.sort(key=lambda x: (x["vulnerability"], x["source"][0], x["sink"][0]))
    
    # Add numeric suffix to vulnerability names
    vuln_counters = {}
    for item in final_output:
        original_name = item["vulnerability"]
        if original_name not in vuln_counters:
            vuln_counters[original_name] = 1
        else:
            vuln_counters[original_name] += 1
        item["vulnerability"] = f"{original_name}_{vuln_counters[original_name]}"
    
    # Write results to JSON file
    os.makedirs("output", exist_ok=True)
    slice_filename = os.path.splitext(os.path.basename(slice_path))[0]
    output_filename = f"output/{slice_filename}.output.json"
    with open(output_filename, 'w') as f:
        json.dump(final_output, f, indent=4)

if __name__ == "__main__":
    main()
