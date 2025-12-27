#!/usr/bin/env python3

# Import ast module for parsing Python code into Abstract Syntax Trees
import ast
# Import sys module for system-specific parameters and functions
import sys
# Import os module for operating system interactions like file operations
import os
# Import json module for reading and writing JSON data
import json

# ============================================================================
# PATTERN CLASS: Defines a security vulnerability pattern to track
# ============================================================================
# Think of this as a blueprint for "what we're looking for"
# Example: SQL Injection pattern has sources (user_input), sinks (execute_query),
# and sanitizers (escape_string) that can clean the taint

# Define the Pattern class to represent a vulnerability pattern
class Pattern:
    # Define the constructor that initializes a Pattern object with 5 parameters
    def __init__(self, name: str, sources: list, sanitizers: list, sinks: list, implicit: bool):
        """
        name: vulnerability type (e.g., "SQL Injection")
        sources: where untrusted data enters (e.g., request.args)
        sanitizers: functions that clean data (e.g., escape_sql)
        sinks: dangerous functions that shouldn't receive tainted data (e.g., execute)
        implicit: whether data can be tainted implicitly (e.g., through control flow)
        """
        # Store the vulnerability name (e.g., "SQL Injection")
        self.name = name
        # Convert sources list to set for O(1) lookup time
        self.sources = set(sources)
        # Convert sanitizers list to set for O(1) lookup time
        self.sanitizers = set(sanitizers)
        # Convert sinks list to set for O(1) lookup time
        self.sinks = set(sinks)
        # Store whether implicit flows (control flow) can taint data
        self.implicit = implicit

    # Define method to return the vulnerability name
    def get_name(self):
        # Return the name of this pattern
        return self.name

    # Define method to return a copy of sources to prevent external modification
    def get_sources(self):
        # Return a copy of the sources set to prevent external modification
        return self.sources.copy()

    # Define method to return a copy of sanitizers to prevent external modification
    def get_sanitizers(self):
        # Return a copy of the sanitizers set to prevent external modification
        return self.sanitizers.copy()

    # Define method to return a copy of sinks to prevent external modification
    def get_sinks(self):
        # Return a copy of the sinks set to prevent external modification
        return self.sinks.copy()

# ============================================================================
# TAINTLABEL CLASS: Tracks taint information for a single pattern
# ============================================================================
# Think of this as a "tracking record" for one variable's contamination
# It records: where the taint came from, what cleaning functions were applied,
# and the path the taint took through the code

# Define the TaintLabel class to track taint for one vulnerability pattern
class TaintLabel:
    # Define the constructor that initializes an empty TaintLabel
    def __init__(self):
        # Initialize an empty dictionary to map source names to taint paths
        # Dictionary maps: source_name -> [(line_number, [sanitizers], is_implicit), ...]
        self.sources = {}

    # Define method to mark a variable as tainted by a source at a specific line
    def add_source(self, source: str, line: int, implicit: bool = False):
        """
        Mark that a variable is tainted by a source at a specific line.
        implicit=True means the taint came from control flow, not direct assignment.
        """
        # Check if this source is not yet in the sources dictionary
        if source not in self.sources:
            # Create an empty list for this source
            self.sources[source] = []
        # Check if this exact entry (line, empty path, implicit flag) does not already exist
        if not any((l == line and path == [] and imp == implicit) for l, path, imp in self.sources[source]):
            # Append a tuple: (line_number, empty_sanitizer_path, implicit_flag)
            self.sources[source].append((line, [], implicit))

    # Define method to record that a sanitizer was applied to clean the taint
    def apply_sanitizer(self, sanitizer: str, line: int):
        """
        Record that a sanitizer function was applied to clean the taint.
        Example: if "escape_sql" is called at line 10, record it in the sanitizer path.
        """
        # Iterate over each source in the sources dictionary
        for source in self.sources:
            # Create an empty list to store updated paths
            new_paths = []
            # Iterate over each taint path for this source
            for src_line, path, implicit in self.sources[source]:
                # Create an entry for this sanitizer: [name, line_number]
                entry = [sanitizer, line]
                # Check if this sanitizer entry is not already in the path (avoid infinite loops)
                if entry not in path:
                    # Create a copy of the current sanitizer path
                    new_path = list(path)
                    # Add the new sanitizer entry to the copied path
                    new_path.append(entry)
                    # Append the updated path to new_paths
                    new_paths.append((src_line, new_path, implicit))
                else:
                    # Keep the old path unchanged if sanitizer is already there
                    new_paths.append((src_line, path, implicit))
            # Replace the old paths with the newly updated paths
            self.sources[source] = new_paths

    # Define method to retrieve all taint paths for a specific source
    def get_paths(self, source):
        """
        Get all taint paths for a specific source, sorted by sanitizer line number.
        Returns: [(source_line, [sanitizers], is_implicit), ...]
        """
        # Get the list of paths for this source (empty list if not found)
        paths = self.sources.get(source, [])
        # Iterate over each path by index to allow in-place modification
        for i in range(len(paths)):
            # Sort sanitizers in the path by their line numbers (second element)
            sanitizers = sorted(paths[i][1], key=lambda x: x[1])
            # Replace the path tuple with sanitizers sorted by line number
            paths[i] = (paths[i][0], sanitizers, paths[i][2])
        # Return the updated paths list with sorted sanitizers
        return paths

    # Define method to return all sources that taint this variable
    def get_sources(self):
        """Return all sources that taint this variable."""
        # Convert dictionary keys to a list and return
        return list(self.sources.keys())

    # Define method to merge two TaintLabel objects together
    def combine(self, other):
        """
        Merge two taint labels together.
        Used when combining taints from multiple branches or operations.
        """
        # Create a new empty TaintLabel to store the merged result
        result = TaintLabel()
        # Iterate over each source and its paths in self
        for src, paths in self.sources.items():
            # Initialize empty list for this source in the result
            result.sources[src] = []
            # Iterate over each path for this source
            for l, path, imp in paths:
                # Append a tuple with deep copies of the path components
                result.sources[src].append((l, list(path), imp))
        # Iterate over each source and its paths in the other label
        for src, paths in other.sources.items():
            # Check if this source is not already in the result
            if src not in result.sources:
                # Initialize empty list for this new source
                result.sources[src] = []
            # Iterate over each path for this source in the other label
            for l, path, imp in paths:
                # Check if this exact path is not already in the result
                if (l, path, imp) not in result.sources[src]:
                    # Append the new path to the result
                    result.sources[src].append((l, list(path), imp))
        # Return the merged TaintLabel
        return result

    # Define method to mark all taint paths as implicit
    def force_implicit(self):
        """Mark all taint paths as implicit (e.g., from control flow)."""
        # Create a new empty TaintLabel for the result
        result = TaintLabel()
        # Iterate over each source and its paths
        for src, paths in self.sources.items():
            # Initialize empty list for this source in the result
            result.sources[src] = []
            # Iterate over each path for this source
            for l, path, _ in paths:
                # Append tuple with implicit flag set to True, ignoring old flag
                result.sources[src].append((l, list(path), True))
        # Return the TaintLabel with all paths marked as implicit
        return result

    # Define method to create a deep copy of this TaintLabel
    def clone(self):
        """Create a deep copy of this label."""
        # Create a new empty TaintLabel
        new_label = TaintLabel()
        # Iterate over each source and its paths
        for src, paths in self.sources.items():
            # Initialize empty list for this source in the new label
            new_label.sources[src] = []
            # Iterate over each path for this source
            for l, path, imp in paths:
                # Create a list of lists (deep copy of sanitizers)
                new_path = [list(san) for san in path]
                # Append the deep-copied path to the new label
                new_label.sources[src].append((l, new_path, imp))
        # Return the new cloned label
        return new_label

# ============================================================================
# MULTILABEL CLASS: Tracks taint for multiple patterns simultaneously
# ============================================================================
# Instead of tracking one vulnerability type, this tracks ALL patterns at once.
# Imagine a variable that could be vulnerable to SQL Injection AND XSS simultaneously.
# This class maintains one TaintLabel for each pattern.

# Define the MultiLabel class to track taint for all vulnerability patterns
class MultiLabel:
    # Define the constructor that initializes a MultiLabel with a list of patterns
    def __init__(self, patterns):
        # Convert patterns list to dictionary: pattern_name -> Pattern object
        self.patterns = {p.get_name(): p for p in patterns}
        # Create one empty TaintLabel for each pattern
        self.labels = {name: TaintLabel() for name in self.patterns}
        # Initialize partial flag to False (no uncertainty yet)
        # partial=True means the variable might have additional sources we haven't tracked
        self.partial = False

    # Define method to add a source to a specific pattern's taint label
    def add_source(self, pattern_name, source, line, implicit=False):
        """Add a source to a specific pattern's taint label."""
        # Check if this pattern name is recognized
        if pattern_name in self.patterns:
            # Add the source to this pattern's TaintLabel
            self.labels[pattern_name].add_source(source, line, implicit)

    # Define method to apply a sanitizer to a specific pattern's taint label
    def apply_sanitizer(self, pattern_name, sanitizer, line):
        """Apply a sanitizer to a specific pattern's taint label."""
        # Check if this pattern name exists in the labels dictionary
        if pattern_name in self.labels:
            # Apply the sanitizer to this pattern's TaintLabel
            self.labels[pattern_name].apply_sanitizer(sanitizer, line)

    # Define method to merge two MultiLabels together
    def combine(self, other):
        """Merge two MultiLabels together (for all patterns)."""
        # Create a new MultiLabel with the same patterns
        result = MultiLabel(list(self.patterns.values()))
        # Set partial flag to True if either label is partial
        result.partial = self.partial or other.partial
        # Iterate over each pattern name
        for p_name in result.labels:
            # Combine the TaintLabels for this pattern from both sources
            result.labels[p_name] = self.labels[p_name].combine(other.labels[p_name])
        # Return the combined MultiLabel
        return result

    # Define method to mark all taints across all patterns as implicit
    def force_implicit(self):
        """Mark all taints across all patterns as implicit."""
        # Create a new MultiLabel with the same patterns
        result = MultiLabel(list(self.patterns.values()))
        # Preserve the partial flag from the original
        result.partial = self.partial
        # Iterate over each pattern name
        for p_name in result.labels:
            # Mark all taints for this pattern as implicit
            result.labels[p_name] = self.labels[p_name].force_implicit()
        # Return the MultiLabel with all taints marked implicit
        return result

    # Define method to create a deep copy of this MultiLabel
    def clone(self):
        """Create a deep copy of this MultiLabel."""
        # Create a new MultiLabel with the same patterns
        new_ml = MultiLabel(list(self.patterns.values()))
        # Clone each TaintLabel for each pattern
        new_ml.labels = {name: lbl.clone() for name, lbl in self.labels.items()}
        # Preserve the partial flag
        new_ml.partial = self.partial
        # Return the new cloned MultiLabel
        return new_ml

# ============================================================================
# POLICY CLASS: Maps sources/sinks/sanitizers to their patterns
# ============================================================================
# This is an index that answers questions like:
# "If I see source X, which patterns are affected?"
# "If I see sink Y, which patterns should I check?"

# Define the Policy class to map sources, sinks, and sanitizers to patterns
class Policy:
    # Define the constructor that initializes Policy with a list of patterns
    def __init__(self, patterns):
        # Convert patterns list to dictionary: pattern_name -> Pattern object
        self.patterns = {p.get_name(): p for p in patterns}
        # Initialize empty dictionary: source_name -> {pattern_names}
        self.source_to_patterns = {}
        # Initialize empty dictionary: sink_name -> {pattern_names}
        self.sink_to_patterns = {}
        # Initialize empty dictionary: sanitizer_name -> {pattern_names}
        self.sanitizer_to_patterns = {}
        
        # Build these indices for quick lookup
        # Iterate over each pattern name and pattern object
        for name, pattern in self.patterns.items():
            # Iterate over each source in this pattern
            for src in pattern.get_sources():
                # Use setdefault to create a set if not exists, then add pattern name
                self.source_to_patterns.setdefault(src, set()).add(name)
            # Iterate over each sink in this pattern
            for snk in pattern.get_sinks():
                # Use setdefault to create a set if not exists, then add pattern name
                self.sink_to_patterns.setdefault(snk, set()).add(name)
            # Iterate over each sanitizer in this pattern
            for san in pattern.get_sanitizers():
                # Use setdefault to create a set if not exists, then add pattern name
                self.sanitizer_to_patterns.setdefault(san, set()).add(name)

    # Define method to return which patterns are affected by a sink
    def get_sink_patterns(self, sink_name):
        """Return which patterns are affected by this sink."""
        # Return the set of patterns for this sink (empty set if not found)
        return self.sink_to_patterns.get(sink_name, set())

    # Define method to return which patterns are affected by a sanitizer
    def get_sanitizer_patterns(self, sanitizer_name):
        """Return which patterns are affected by this sanitizer."""
        # Return the set of patterns for this sanitizer (empty set if not found)
        return self.sanitizer_to_patterns.get(sanitizer_name, set())

# ============================================================================
# ANALYSER CLASS: Main taint analysis engine (using AST visitor pattern)
# ============================================================================
# This walks through the Python code (as an Abstract Syntax Tree) and tracks
# how data flows from sources to sinks. It's like following breadcrumbs through
# the code to see if untrusted data reaches dangerous functions.

# Define the Analyser class that extends ast.NodeVisitor to walk the AST
class Analyser(ast.NodeVisitor):
    # Define the constructor that initializes the analyser with patterns
    def __init__(self, patterns):
        # Create a Policy object from the patterns to map sources/sinks/sanitizers
        self.policy = Policy(patterns)
        # Initialize dictionary to map variable names to their current MultiLabel taint state
        self.labelling = {}
        # Initialize empty list to record found vulnerabilities
        self.vulnerabilities = []
        # Initialize dictionary to map source names to the lines where they were introduced
        self.source_lines = {}
        # Initialize set to track variables that might be sources but aren't explicitly assigned
        self.uninstantiated_sources = set()
        # Initialize program counter taint (for implicit flows through control flow)
        # PC taint tracks contamination from conditional branches
        self.pc_taint = MultiLabel(patterns)

    # Define method to extract line number from an AST node
    def get_line_number(self, node):
        """Extract line number from an AST node."""
        # Return the line number attribute (default to 1 if not found)
        return getattr(node, 'lineno', 1)

    # Define method to extract function name from a node
    def get_func_name(self, node):
        """Extract function name from either a Name or Attribute node."""
        # Check if node is a simple Name node (e.g., "foo()")
        if isinstance(node, ast.Name):
            # Return the identifier name
            return node.id
        # Check if node is an Attribute node (e.g., "obj.method()")
        elif isinstance(node, ast.Attribute):
            # Return the attribute name
            return node.attr
        # If neither, return None
        return None

    # Define method to record that a variable might be an uninstantiated source
    def mark_uninstantiated_source(self, var_name, line):
        """Record that a variable might be a source even though it's never assigned."""
        # Check if this variable is not yet in the labelling dictionary
        if var_name not in self.labelling:
            # Add the variable name to the uninstantiated_sources set
            self.uninstantiated_sources.add(var_name)
            # Record the line number where this source was first referenced
            self.source_lines[var_name] = line

    # Define method to create taint label for implicitly sourced variables
    def create_uninstantiated_label(self, var_name, line):
        """
        Create taint label for a variable that might be implicitly sourced.
        Example: a function parameter that could be untrusted user input.
        """
        # Get all patterns as a list
        patterns = list(self.policy.patterns.values())
        # Create a new MultiLabel initialized with all patterns
        implicit_taint = MultiLabel(patterns)
        # Mark this variable as an uninstantiated source
        self.mark_uninstantiated_source(var_name, line)
        # Add the variable name as a source for each pattern
        for p in patterns:
            # Add this variable as a source at this line for this pattern
            implicit_taint.add_source(p.get_name(), var_name, line)
        # Return the MultiLabel with implicit taint
        return implicit_taint

    # Define method to retrieve the taint label for a variable
    def get_label(self, var_name, line):
        """
        Get the taint label for a variable.
        Checks: explicit sources, implicit sources, and uninstantiated sources.
        """
        # Get all patterns as a list
        patterns = list(self.policy.patterns.values())
        # Create an empty MultiLabel (no taint)
        empty_label = MultiLabel(patterns)
        # Get the current taint for this variable (or empty if not found)
        current_taint = self.labelling.get(var_name, empty_label)
        
        # Check if this variable name is an explicit source in the policy
        if var_name in self.policy.source_to_patterns:
            # Create a new MultiLabel for explicit taint
            explicit_taint = MultiLabel(patterns)
            # Record the line number for this source
            self.source_lines[var_name] = line
            # Add this source to each pattern that tracks it
            for pattern_name in self.policy.source_to_patterns[var_name]:
                # Add the variable as a source for this pattern at this line
                explicit_taint.add_source(pattern_name, var_name, line)
            # Combine explicit taint with the current taint
            current_taint = current_taint.combine(explicit_taint)
        
        # Check if variable was never assigned explicitly
        if var_name not in self.labelling:
            # Create implicit taint for this uninstantiated variable
            uninst = self.create_uninstantiated_label(var_name, line)
            # Combine it with the current taint
            current_taint = current_taint.combine(uninst)
        # Check if variable has partial taint (from branching, uncertain state)
        elif current_taint.partial:
            # Create implicit taint for this potentially incomplete variable
            uninst = self.create_uninstantiated_label(var_name, line)
            # Combine it with the current taint
            current_taint = current_taint.combine(uninst)
        
        # Return the accumulated taint label
        return current_taint

    # Define method to recursively analyze an expression's taint
    def analyze_expression(self, node):
        """
        Recursively analyze an expression to determine its taint.
        Works for: variables, constants, binary operations, comparisons, etc.
        """
        # Get all patterns as a list
        patterns = list(self.policy.patterns.values())
        # Create an empty MultiLabel (no taint)
        empty_label = MultiLabel(patterns)
        
        # Check if node is a simple variable name
        if isinstance(node, ast.Name):
            # Look up and return the taint label for this variable
            return self.get_label(node.id, self.get_line_number(node))
        
        # Check if node is a constant value (Str, Num, or Constant in Python 3.8+)
        elif isinstance(node, (ast.Constant, ast.Str, ast.Num)):
            # Literal constants are not tainted, return empty label
            return empty_label
        
        # Check if node is a binary operation (e.g., a + b)
        elif isinstance(node, ast.BinOp):
            # Analyze taint of the left operand
            left = self.analyze_expression(node.left)
            # Analyze taint of the right operand
            right = self.analyze_expression(node.right)
            # Return combination of both operands' taints
            return left.combine(right)
        
        # Check if node is a comparison operation (e.g., a > b)
        elif isinstance(node, ast.Compare):
            # Analyze taint of the left operand
            left = self.analyze_expression(node.left)
            # Start accumulating taint with the left operand
            total = left
            # Iterate over each comparator in the comparison (e.g., in "a > b > c")
            for comparator in node.comparators:
                # Analyze taint of this comparator
                comp_taint = self.analyze_expression(comparator)
                # Combine it with the accumulated taint
                total = total.combine(comp_taint)
            # Return the combined taint from all operands
            return total
        
        # Check if node is a boolean operation (and/or)
        elif isinstance(node, ast.BoolOp):
            # Analyze taint of the first value
            total = self.analyze_expression(node.values[0])
            # Iterate over remaining values
            for val in node.values[1:]:
                # Analyze taint of this value
                val_taint = self.analyze_expression(val)
                # Combine it with accumulated taint
                total = total.combine(val_taint)
            # Return the combined taint from all values
            return total
        
        # Check if node is a unary operation (e.g., not x, -x)
        elif isinstance(node, ast.UnaryOp):
            # Analyze and return taint of the operand
            return self.analyze_expression(node.operand)
        
        # Check if node is an attribute access (e.g., obj.attr)
        elif isinstance(node, ast.Attribute):
            # Analyze taint of the object being accessed
            obj_taint = self.analyze_expression(node.value)
            # Create empty label for the attribute itself
            attr_taint = empty_label
            # Check if the attribute name itself is a source
            if node.attr in self.policy.source_to_patterns:
                # Create a new MultiLabel for this source
                attr_taint = MultiLabel(patterns)
                # Record the line number for this source
                self.source_lines[node.attr] = self.get_line_number(node)
                # Add this attribute as a source to each affected pattern
                for pattern_name in self.policy.source_to_patterns[node.attr]:
                    # Add the attribute as a source for this pattern
                    attr_taint.add_source(pattern_name, node.attr, self.get_line_number(node))
            # Return combination of object taint and attribute taint
            return obj_taint.combine(attr_taint)
        
        # Check if node is a subscript access (e.g., arr[i])
        elif isinstance(node, ast.Subscript):
            # Analyze taint of the array/object being subscripted
            obj_taint = self.analyze_expression(node.value)
            # Analyze taint of the index expression
            idx_taint = self.analyze_expression(node.slice)
            # Return combination of both taints
            return obj_taint.combine(idx_taint)
        
        # Check if node is a function call
        elif isinstance(node, ast.Call):
            # Extract the function name from the call node
            func_name = self.get_func_name(node.func)
            # Get the line number of this call
            line = self.get_line_number(node)
            
            # Initialize empty MultiLabel for call result taint
            call_taint = empty_label
            # Check if the function name itself is a source (e.g., input())
            if func_name and func_name in self.policy.source_to_patterns:
                # Create a new MultiLabel for this source
                call_taint = MultiLabel(patterns)
                # Record the line number for this source
                self.source_lines[func_name] = line
                # Add this function as a source to each affected pattern
                for pattern_name in self.policy.source_to_patterns[func_name]:
                    # Add the function as a source for this pattern
                    call_taint.add_source(pattern_name, func_name, line)
            
            # Initialize empty MultiLabel for argument taints
            arg_taint = empty_label
            # Iterate over each argument to the function
            for arg in node.args:
                # Analyze taint of this argument
                arg_label = self.analyze_expression(arg)
                # Combine it with accumulated argument taint
                arg_taint = arg_taint.combine(arg_label)
            
            # Check if this is a method call (function is an attribute)
            if isinstance(node.func, ast.Attribute):
                # Analyze taint of the object the method is called on
                obj_taint = self.analyze_expression(node.func.value)
                # Include object taint in the argument taint
                arg_taint = arg_taint.combine(obj_taint)
            
            # Check if this function is a sink (dangerous function)
            self.check_sinks(func_name, arg_taint, line)
            
            # Combine argument taint with any source taint from the function itself
            result_taint = arg_taint.combine(call_taint)
            
            # Get patterns that treat this function as a sanitizer
            sanitizer_patterns = self.policy.get_sanitizer_patterns(func_name)
            # Apply sanitizer to each affected pattern
            for pattern_name in sanitizer_patterns:
                # Apply the sanitizer to this pattern in the result taint
                result_taint.apply_sanitizer(pattern_name, func_name, line)
            
            # Return the resulting taint after sources, sinks, and sanitizers
            return result_taint
        
        # For any other expression type, return empty (not tainted)
        return empty_label

    # Define method to check if tainted data reaches a sink
    def check_sinks(self, sink_name, taint_label, line):
        """
        Check if tainted data reaches a sink (dangerous function).
        If so, record a vulnerability.
        """
        # Check if sink_name is actually a function name (not None)
        if not sink_name:
            # Return early if no sink name provided
            return
        
        # Get all patterns that have this function as a sink
        sink_patterns = self.policy.get_sink_patterns(sink_name)
        # Iterate over each pattern affected by this sink
        for pattern_name in sink_patterns:
            # Get the Pattern object for this pattern name
            pattern = self.policy.patterns[pattern_name]
            # Start with the provided taint label
            total_sink_taint = taint_label
            
            # Check if this pattern tracks implicit flows (control flow tainting)
            if pattern.implicit:
                # Combine the sink taint with program counter taint
                total_sink_taint = total_sink_taint.combine(self.pc_taint)
            
            # Get the TaintLabel for this specific pattern
            label = total_sink_taint.labels[pattern_name]
            
            # For each source that contributes to the taint...
            for source in label.get_sources():
                # Get all taint paths for this source
                paths = label.get_paths(source)
                # Iterate over each taint path
                for src_line, sanitizers, is_implicit in paths:
                    # Record a vulnerability with all the taint path information
                    self.vulnerabilities.append({
                        # Name of the vulnerability pattern
                        "vulnerability": pattern_name,
                        # Source location: [source_name, line_number]
                        "source": [source, src_line],
                        # Sink location: [sink_name, line_number]
                        "sink": [sink_name, line],
                        # Whether the taint path includes implicit flows
                        "implicit": is_implicit,
                        # List of sanitizers applied: [[san_name, line], ...]
                        "sanitizers": sanitizers
                    })

    # Define method to analyze assignment targets (left side of =)
    def analyze_target(self, node):
        """
        Analyze an assignment target (left side of =).
        Determines: variable name, whether it's a weak update, and any sub-taints.
        """
        # Get all patterns as a list
        patterns = list(self.policy.patterns.values())
        # Create an empty MultiLabel for sub-taints
        empty = MultiLabel(patterns)
        
        # Check if target is a simple variable name
        if isinstance(node, ast.Name):
            # Return: variable name, not a weak update, no sub-taint, no attribute
            return node.id, False, empty, None
        
        # Check if target is an attribute assignment (obj.attr = ...)
        elif isinstance(node, ast.Attribute):
            # Recursively analyze the object part
            root, _, _, _ = self.analyze_target(node.value)
            # This is a weak update (modifying a field, not the whole object)
            # Return: root variable, weak update=True, no sub-taint, attribute name
            return root, True, empty, node.attr
        
        # Check if target is a subscript assignment (arr[i] = ...)
        elif isinstance(node, ast.Subscript):
            # Recursively analyze the array/object part
            root, _, _, _ = self.analyze_target(node.value)
            # Analyze taint of the index expression
            idx_taint = self.analyze_expression(node.slice)
            # This is a weak update (modifying an element, not the whole array)
            # Return: root variable, weak update=True, index taint, no attribute
            return root, True, idx_taint, None
        
        # For any other target type, return None values (assignment not tracked)
        return None, False, empty, None

    # Define method to handle assignment statements
    def visit_Assign(self, node):
        """
        Handle assignment statements (x = value).
        Propagate taint from right side to left side.
        """
        # Get the line number of this assignment
        line = self.get_line_number(node)
        # Analyze taint of the right side (value being assigned)
        value_taint = self.analyze_expression(node.value)
        # Start with the value taint
        final_value_taint = value_taint
        
        # Check for implicit patterns that can be tainted through control flow
        # Get the program counter taint (from control flow)
        pc_implicit = self.pc_taint
        # Iterate over each pattern in the policy
        for pname, pat in self.policy.patterns.items():
            # Check if this pattern tracks implicit flows
            if pat.implicit:
                # Combine the value taint with PC taint for this pattern
                final_value_taint.labels[pname] = final_value_taint.labels[pname].combine(pc_implicit.labels[pname])
        
        # Process each assignment target (left side)
        # Iterate over each variable being assigned to (multiple targets in "a = b = c")
        for target in node.targets:
            # Analyze the assignment target to get variable and update type
            root_name, is_weak, structure_taint, attr_name = self.analyze_target(target)
            # Check if we successfully analyzed the target
            if root_name:
                # Combine the value taint with any structure (subscript/attribute) taint
                total_incoming_taint = final_value_taint.combine(structure_taint)
                
                # Special case: weak update to an uninitialized variable
                if root_name not in self.labelling:
                    # Check if this is a weak update (modifying a field or element)
                    if is_weak:
                        # Check if there's any taint coming in
                        is_incoming_tainted = False
                        # Iterate over all patterns
                        for label in total_incoming_taint.labels.values():
                            # Check if this pattern has any sources (tainted)
                            if label.get_sources():
                                # Mark as tainted
                                is_incoming_tainted = True
                                # Exit the loop early
                                break
                        # If no taint is incoming for a weak update, skip initialization
                        if not is_incoming_tainted:
                            # Continue to next target
                            continue
                    # Initialize this variable with an empty MultiLabel
                    self.labelling[root_name] = MultiLabel(list(self.policy.patterns.values()))
                
                # Get the old taint label for this variable (if any)
                old_taint = self.labelling.get(root_name, MultiLabel(list(self.policy.patterns.values())))
                
                # Decide between weak and strong update
                # Weak update: combine old and new taints
                if is_weak:
                    # Merge old and new taints for weak update
                    new_taint = old_taint.combine(total_incoming_taint)
                # Strong update: replace old taint with new taint
                else:
                    # Use only the new taint for strong update
                    new_taint = total_incoming_taint
                
                # Mark the new label as non-partial (certain state)
                new_taint.partial = False
                # Update the labelling with the new taint
                self.labelling[root_name] = new_taint
                
                # Check if we explicitly assigned to an uninstantiated source
                # If so, mark it as now instantiated
                if not is_weak and root_name in self.uninstantiated_sources:
                    # Remove from uninstantiated sources set
                    self.uninstantiated_sources.discard(root_name)
                
                # Check if the assigned value reaches a sink (dangerous function)
                self.check_sinks(root_name, new_taint, line)
                
                # For attribute assignments, also check if the attribute is a sink
                if attr_name:
                    # Check if attribute access is a dangerous sink
                    self.check_sinks(attr_name, total_incoming_taint, line)
        
        # Continue visiting child nodes (generic AST traversal)
        self.generic_visit(node)

    # Define method to handle expression statements
    def visit_Expr(self, node):
        """
        Handle expression statements (standalone expressions like function calls).
        """
        # Analyze the expression to process any side effects (sources, sinks, sanitizers)
        self.analyze_expression(node.value)
        # Continue visiting child nodes
        self.generic_visit(node)

    # Define method to merge two execution states from branches
    def merge_states(self, state1, state2):
        """
        Merge two execution states (e.g., from different branches).
        If variable is in both: combine taints.
        If variable is in only one: mark as partial (uncertain).
        """
        # Get all variable names from both states
        all_keys = set(state1.keys()) | set(state2.keys())
        # Initialize empty dictionary for merged state
        merged = {}
        # Iterate over all variables
        for k in all_keys:
            # Check if variable exists in both states
            if k in state1 and k in state2:
                # Both branches have the variable: combine their taints
                merged[k] = state1[k].combine(state2[k])
            # Check if variable exists only in state1
            elif k in state1:
                # Variable exists only in first branch: might not exist in second
                # Clone the state and mark it as potentially incomplete
                merged[k] = state1[k].clone()
                # Set partial flag to indicate uncertainty
                merged[k].partial = True
            # Otherwise variable exists only in state2
            else:
                # Variable exists only in second branch: might not exist in first
                # Clone the state and mark it as potentially incomplete
                merged[k] = state2[k].clone()
                # Set partial flag to indicate uncertainty
                merged[k].partial = True
        # Return the merged state
        return merged

    # Define method to merge multiple execution states together
    def merge_all_states(self, state_list):
        """Merge a list of states together."""
        # Check if the list is empty
        if not state_list:
            # Return empty state
            return {}
        # Check if there's only one state
        if len(state_list) == 1:
            # Return that single state
            return state_list[0]
        # Start with the first state
        final_state = state_list[0]
        # Iterate over remaining states
        for next_state in state_list[1:]:
            # Merge the next state with the accumulated result
            final_state = self.merge_states(final_state, next_state)
        # Return the fully merged state
        return final_state

    # Define method to check if two states are identical
    def states_equal(self, state1, state2):
        """Check if two states are identical (for cycle detection in loops)."""
        # Check if both states have the same variable names
        if set(state1.keys()) != set(state2.keys()):
            # Return False if variable sets differ
            return False
        # Iterate over all variables in the first state
        for var_name in state1.keys():
            # Get the MultiLabel from both states
            label1 = state1[var_name]
            label2 = state2[var_name]
            # Iterate over all patterns
            for pattern_name in label1.patterns:
                # Get the taint sources for both labels
                sources1 = label1.labels[pattern_name].sources
                sources2 = label2.labels[pattern_name].sources
                # Compare the sources dictionaries
                if sources1 != sources2:
                    # Return False if any sources differ
                    return False
        # Return True if all variables and sources are identical
        return True

    # Define method to extract explicitly applied sanitizers
    def extract_explicit_sanitizers(self, multilabel):
        """Extract sanitizers that are explicitly applied (not implicit)."""
        # Initialize empty set for sanitizers
        sanitizers = set()
        # Iterate over all patterns' labels in the MultiLabel
        for label in multilabel.labels.values():
            # Iterate over all sources in this label
            for src, paths in label.sources.items():
                # Iterate over all paths for this source
                for l, path, imp in paths:
                    # Check if this path is not implicit (explicitly applied)
                    if not imp:
                        # Iterate over all sanitizers in the path
                        for san in path:
                            # Add this sanitizer (as tuple) to the set
                            sanitizers.add(tuple(san))
        # Return the set of explicit sanitizers
        return sanitizers

    # Define method to apply sanitizers to program counter taint
    def apply_sanitizers_to_all_patterns(self, pc_taint, sanitizers):
        """Apply a set of sanitizers to the program counter taint."""
        # Check if there are any sanitizers to apply
        if not sanitizers:
            # Return the PC taint unchanged
            return pc_taint
        # Clone the PC taint to create a new copy
        new_pc = pc_taint.clone()
        # Iterate over each sanitizer [name, line] in the set
        for san_name, san_line in sanitizers:
            # Get patterns that are affected by this sanitizer
            target_patterns = self.policy.get_sanitizer_patterns(san_name)
            # Apply the sanitizer to each affected pattern
            for p_name in target_patterns:
                # Apply the sanitizer to this pattern in the new PC taint
                new_pc.apply_sanitizer(p_name, san_name, san_line)
        # Return the updated PC taint
        return new_pc

    # Define method to handle if statements
    def visit_If(self, node):
        """
        Handle if statements (if/else branches).
        Analyzes both branches and merges their results.
        """
        # Analyze the condition expression to get its taint
        cond_taint = self.analyze_expression(node.test)
        # Save the current program counter taint before branching
        prev_pc_taint = self.pc_taint
        
        # Mark condition taint as implicit (from control flow)
        implicit_cond = cond_taint.force_implicit()
        # Combine base PC taint with the implicit condition taint
        base_branch_pc = self.pc_taint.combine(implicit_cond)
        
        # Extract explicit sanitizers from the condition (e.g., if escape(x))
        cond_sanitizers = self.extract_explicit_sanitizers(cond_taint)
        
        # Save the execution state before the branch
        # Clone all variables in the current labelling
        state_before = {k: v.clone() for k, v in self.labelling.items()}
        # Clone the uninstantiated sources set
        uninstantiated_before = self.uninstantiated_sources.copy()
        
        # === ANALYZE IF BODY ===
        # Apply condition sanitizers to the PC taint for the if branch
        self.pc_taint = self.apply_sanitizers_to_all_patterns(base_branch_pc, cond_sanitizers)
        # Visit each statement in the if body
        for stmt in node.body:
            # Visit this statement (which may update labelling and pc_taint)
            self.visit(stmt)
        # Save the state after the if body
        state_after_body = self.labelling
        # Save the uninstantiated sources after the if body
        uninstantiated_after_body = self.uninstantiated_sources
        
        # === ANALYZE ELSE BODY ===
        # Restore the state to before the if statement
        # Clone all variables back to their pre-if state
        self.labelling = {k: v.clone() for k, v in state_before.items()}
        # Restore uninstantiated sources to their pre-if state
        self.uninstantiated_sources = uninstantiated_before.copy()
        # Reset PC taint to base branch PC (without condition sanitizers)
        self.pc_taint = base_branch_pc
        # Check if there's an else clause
        if node.orelse:
            # Visit each statement in the else body
            for stmt in node.orelse:
                # Visit this statement (which may update labelling and pc_taint)
                self.visit(stmt)
        # Save the state after the else body
        state_after_else = self.labelling
        
        # === MERGE RESULTS ===
        # Merge the states from both branches
        self.labelling = self.merge_states(state_after_body, state_after_else)
        # Merge uninstantiated sources from both branches
        self.uninstantiated_sources = uninstantiated_after_body | self.uninstantiated_sources
        # Restore the previous program counter taint
        self.pc_taint = prev_pc_taint

    # Define method to handle while loops
    def visit_While(self, node):
        """
        Handle while loops.
        Iterates until a fixed point is reached (cycle detection).
        """
        # Save the program counter taint before entering the loop
        prev_pc_taint = self.pc_taint
        
        # Save the initial state before the loop
        # Clone all variables in the current labelling
        state_0 = {k: v.clone() for k, v in self.labelling.items()}
        # Clone the uninstantiated sources set
        uninst_0 = self.uninstantiated_sources.copy()
        
        # Initialize list to track states across loop iterations
        # This is used for cycle detection
        collected_labels = [state_0]
        # Initialize list to track uninstantiated sources across iterations
        collected_uninst = [uninst_0]
        # Set maximum iterations to prevent infinite loops in analysis
        max_iterations = 100
        # Initialize iteration counter
        iteration_count = 0
        
        # Iterate until fixed point or maximum iterations
        while iteration_count < max_iterations:
            # Analyze the loop condition to get its taint
            cond_taint = self.analyze_expression(node.test)
            # Mark condition taint as implicit (from control flow)
            implicit_cond = cond_taint.force_implicit()
            # Combine base PC taint with implicit condition taint
            loop_pc_taint = prev_pc_taint.combine(implicit_cond)
            # Update PC taint with the loop condition's implicit taint
            self.pc_taint = loop_pc_taint
            
            # Execute the loop body once
            # Visit each statement in the loop body
            for stmt in node.body:
                # Visit this statement (which may update labelling)
                self.visit(stmt)
            
            # Save the state after this loop iteration
            # Clone all variables in the labelling
            state_i = {k: v.clone() for k, v in self.labelling.items()}
            # Clone the uninstantiated sources set
            uninst_i = self.uninstantiated_sources.copy()
            
            # Check if we've reached a fixed point (cycle detected)
            # Initialize cycle detection flag
            cycle_detected = False
            # Iterate over all previously collected states
            for previous_state in collected_labels:
                # Check if current state is identical to a previous state
                if self.states_equal(state_i, previous_state):
                    # Cycle detected: state has repeated
                    cycle_detected = True
                    # Exit the comparison loop
                    break
            
            # Check if we detected a cycle
            if cycle_detected:
                # Add the current state to collected states
                collected_labels.append(state_i)
                # Add the current uninstantiated sources to collected
                collected_uninst.append(uninst_i)
                # Exit the iteration loop
                break
            
            # Add the current state to collected states (no cycle yet)
            collected_labels.append(state_i)
            # Add the current uninstantiated sources to collected
            collected_uninst.append(uninst_i)
            # Increment the iteration counter
            iteration_count += 1
        
        # Merge all states from all iterations
        self.labelling = self.merge_all_states(collected_labels)
        # Initialize empty set for final uninstantiated sources
        final_uninst = set()
        # Iterate over all collected uninstantiated source sets
        for s in collected_uninst:
            # Add all uninstantiated sources from this iteration to final set
            final_uninst.update(s)
        # Update labelling with merged uninstantiated sources
        self.uninstantiated_sources = final_uninst
        # Restore the original program counter taint
        self.pc_taint = prev_pc_taint
        
        # Handle else clause (executed if loop completes without break)
        # Check if the loop has an else clause
        if hasattr(node, 'orelse') and node.orelse:
            # For now, we don't analyze the else clause separately
            pass

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Define function to load patterns from JSON data
def load_patterns(patterns_data):
    """Convert JSON pattern data into Pattern objects."""
    # List comprehension: create Pattern object for each pattern in JSON
    # Iterate over each pattern dictionary in patterns_data
    return [Pattern(p["vulnerability"], p["sources"], p["sanitizers"],
                    p["sinks"], p["implicit"] == "yes") for p in patterns_data]

# Define the main function entry point
def main():
    """
    Main entry point.
    Usage: python script.py <path_to_code> <path_to_patterns.json>
    """
    # Validate command line arguments: need exactly 3 (script name + 2 args)
    if len(sys.argv) != 3:
        # Exit with error code if wrong number of arguments
        sys.exit(1)
    
    # Get the first command line argument: path to Python code to analyze
    slice_path = sys.argv[1]
    # Get the second command line argument: path to patterns JSON file
    patterns_path = sys.argv[2]
    
    # Validate that both files exist before proceeding
    # Check if the code file exists
    if not os.path.exists(slice_path) or not os.path.exists(patterns_path):
        # Exit with error code if files don't exist
        sys.exit(1)
    
    # Load vulnerability patterns from the JSON file
    # Open the patterns JSON file in read mode
    with open(patterns_path, 'r') as f:
        # Try to parse JSON data
        try:
            # Parse JSON data from file
            patterns = json.load(f)
        # Catch any JSON parsing errors
        except:
            # Exit with error code if JSON is invalid
            sys.exit(1)
    
    # Load the Python source code to analyze
    # Open the source code file in read mode
    with open(slice_path, 'r') as f:
        # Read entire file contents into string
        source_code = f.read()
    
    # Parse the source code into an Abstract Syntax Tree (AST)
    # Try to parse the code
    try:
        # Parse Python source code into AST
        tree = ast.parse(source_code)
    # Catch any syntax errors during parsing
    except:
        # Exit with error code if code is invalid Python
        sys.exit(1)
    
    # Run the taint analysis on the AST
    # Create an Analyser instance with the loaded patterns
    analyser = Analyser(load_patterns(patterns))
    # Visit the AST to perform the taint analysis
    analyser.visit(tree)
    
    # Group vulnerabilities by key to avoid reporting duplicates
    # Initialize empty dictionary for grouped vulnerabilities
    grouped_vulns = {}
    # Iterate over each found vulnerability
    for v in analyser.vulnerabilities:
        # Create a unique key from vulnerability attributes
        key = (v["vulnerability"], v["source"][0], v["source"][1], v["sink"][0], v["sink"][1])
        # Determine if the flow is implicit or explicit
        flow_type = "implicit" if v["implicit"] else "explicit"
        # Get the list of sanitizers applied
        sanitizers = v["sanitizers"]
        # Create a flow entry: [flow_type, sanitizers]
        flow_entry = [flow_type, sanitizers]
        # Check if this key hasn't been seen before
        if key not in grouped_vulns:
            # Initialize empty list for flows with this key
            grouped_vulns[key] = []
        # Check if this flow entry isn't already recorded for this key
        if flow_entry not in grouped_vulns[key]:
            # Add this flow entry to the list for this key
            grouped_vulns[key].append(flow_entry)
    
    # Format output as list of dictionaries
    # Initialize empty list for final output
    final_output = []
    # Iterate over each unique vulnerability key and its flows
    for key, flows in grouped_vulns.items():
        # Unpack the key tuple into individual components
        vuln_name, src_name, src_line, sink_name, sink_line = key
        # Create a dictionary for this vulnerability
        final_output.append({
            # Vulnerability name
            "vulnerability": vuln_name,
            # Source information: [name, line]
            "source": [src_name, src_line],
            # Sink information: [name, line]
            "sink": [sink_name, sink_line],
            # List of flows for this vulnerability
            "flows": flows
        })
    
    # Sort output for consistent results across runs
    # Sort by (vulnerability name, source name, sink name)
    final_output.sort(key=lambda x: (x["vulnerability"], x["source"][0], x["sink"][0]))
    
    # Add numeric suffix to vulnerability names for uniqueness
    # Initialize empty dictionary to count vulnerabilities by name
    vuln_counters = {}
    # Iterate over each vulnerability in the output
    for item in final_output:
        # Get the original vulnerability name
        original_name = item["vulnerability"]
        # Check if we've seen this vulnerability name before
        if original_name not in vuln_counters:
            # First occurrence: set counter to 1
            vuln_counters[original_name] = 1
        # Otherwise we've seen it before
        else:
            # Increment the counter for this vulnerability name
            vuln_counters[original_name] += 1
        # Update the vulnerability name with numeric suffix
        item["vulnerability"] = f"{original_name}_{vuln_counters[original_name]}"
    
    # Write results to output JSON file
    # Create the output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    # Extract filename without extension from the input path
    slice_filename = os.path.splitext(os.path.basename(slice_path))[0]
    # Create output filename: output/{input_filename}.output.json
    output_filename = f"output/{slice_filename}.output.json"
    # Open output file in write mode
    with open(output_filename, 'w') as f:
        # Write the final output as formatted JSON with indentation
        json.dump(final_output, f, indent=4)

# Check if this script is being run directly (not imported as module)
if __name__ == "__main__":
    # Call the main function to start execution
    main()
