#!/usr/bin/env python3
"""
Test runner for py_analyser.py
Runs the analyzer on all slices and validates against expected outputs
"""

import os
import subprocess
import sys
import json
from pathlib import Path
from typing import List, Tuple


def run_analyser(slice_path: str, patterns_path: str) -> bool:
    """Run py_analyser.py on a slice and patterns file"""
    try:
        result = subprocess.run(
            [sys.executable, "py_analyser.py", slice_path, patterns_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"  ❌ CRASH: {result.stderr.strip()}")
            return False
        
        return True
    
    except subprocess.TimeoutExpired:
        print(f"  ❌ TIMEOUT")
        return False
    except Exception as e:
        print(f"  ❌ ERROR: {e}")
        return False


def validate_output(generated_path: str, expected_path: str) -> Tuple[bool, str]:
    """Run validator and return (passed, output)"""
    try:
        result = subprocess.run(
            [sys.executable, "validate.py", "-o", generated_path, "-t", expected_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        output = result.stdout
        print(output)
        # Check for failures
        has_missing = "MISSING FLOWS" in output
        has_wrong = "WRONG FLOWS" in output
        passed = not (has_missing or has_wrong)
        
        return passed, output
    
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT during validation"
    except Exception as e:
        return False, f"ERROR: {e}"


def load_json_safe(path: str) -> dict:
    """Safely load JSON file"""
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}


def run_test(slice_path: str, patterns_path: str, expected_output_path: str) -> Tuple[bool, dict]:
    """Run a single test and return (passed, info)"""
    slice_filename = os.path.basename(slice_path)
    base_name = os.path.splitext(slice_filename)[0]
    
    info = {
        'slice': slice_filename,
        'passed': False,
        'run_error': None,
        'validation_error': None,
        'generated_vulns': 0,
        'expected_vulns': 0,
        'output': ''
    }
    
    # Step 1: Run analyzer
    if not run_analyser(slice_path, patterns_path):
        info['run_error'] = "Analyzer failed"
        return False, info
    
    # Step 2: Check generated output
    generated_output = os.path.join("output", f"{slice_filename}.output.json")
    
    if not os.path.exists(generated_output):
        info['run_error'] = f"Output file not created: {generated_output}"
        return False, info
    
    # Count vulnerabilities
    gen_vulns = load_json_safe(generated_output)
    info['generated_vulns'] = len(gen_vulns)
    
    exp_vulns = load_json_safe(expected_output_path)
    info['expected_vulns'] = len(exp_vulns)
    
    # Step 3: Validate
    passed, output = validate_output(generated_output, expected_output_path)
    info['output'] = output
    info['passed'] = passed
    
    if not passed:
        # Extract error messages
        errors = []
        for line in output.splitlines():
            if "MISSING FLOWS" in line or "WRONG FLOWS" in line:
                errors.append(line.strip())
        info['validation_error'] = "; ".join(errors) if errors else output[:200]
    
    return passed, info


def main():
    """Main test runner"""
    slices_dir = "slices"
    
    if not os.path.exists(slices_dir):
        print("❌ Slices directory not found")
        return
    
    # Collect all tests
    tests: List[Tuple[str, str, str]] = []
    
    for root, dirs, files in os.walk(slices_dir):
        for file in files:
            if file.endswith(".py"):
                slice_path = os.path.join(root, file)
                base_name = os.path.splitext(file)[0]
                
                patterns_path = os.path.join(root, f"{base_name}.patterns.json")
                expected_output_path = os.path.join(root, f"{base_name}.output.json")
                
                if os.path.exists(patterns_path) and os.path.exists(expected_output_path):
                    tests.append((slice_path, patterns_path, expected_output_path))
    
    if not tests:
        print("❌ No test cases found")
        return
    
    print(f"\n{'='*70}")
    print(f"Running {len(tests)} test cases...")
    print(f"{'='*70}\n")
    
    results: List[Tuple[str, bool, dict]] = []
    passed_count = 0
    failed_count = 0
    
    for i, (slice_path, patterns_path, expected_output_path) in enumerate(tests, 1):
        slice_name = os.path.basename(slice_path)
        category = os.path.basename(os.path.dirname(slice_path))
        
        print(f"[{i}/{len(tests)}] {category}/{slice_name} ... ", end="", flush=True)
        
        passed, info = run_test(slice_path, patterns_path, expected_output_path)
        results.append((f"{category}/{slice_name}", passed, info))
        
        if passed:
            print("✅ PASS")
            passed_count += 1
        else:
            print("❌ FAIL")
            failed_count += 1
            if info['run_error']:
                print(f"    Error: {info['run_error']}")
            elif info['validation_error']:
                print(f"    Validation: {info['validation_error']}")
    
    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY: {passed_count} passed, {failed_count} failed out of {len(tests)}")
    print(f"{'='*70}\n")
    
    # Detailed results
    if failed_count > 0:
        print("Failed Tests Details:\n")
        for test_name, passed, info in results:
            if not passed:
                print(f"❌ {test_name}")
                print(f"   Expected: {info['expected_vulns']} vulns | Generated: {info['generated_vulns']} vulns")
                if info['run_error']:
                    print(f"   Error: {info['run_error']}")
                elif info['validation_error']:
                    print(f"   Issue: {info['validation_error']}")
                print()
    
    # Stats table
    print("\nDetailed Results:\n")
    print(f"{'Test Name':<40} {'Status':<8} {'Expected':<10} {'Generated':<10}")
    print("-" * 70)
    
    for test_name, passed, info in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name:<40} {status:<8} {info['expected_vulns']:<10} {info['generated_vulns']:<10}")
    
    print(f"\n{'='*70}\n")
    
    # Exit code
    sys.exit(0 if failed_count == 0 else 1)


if __name__ == "__main__":
    main()