#!/usr/bin/env python3
"""
run_all_tests.py - Automatically discovers and tests all slices in subdirectories
"""
import os
import sys
import subprocess
from pathlib import Path

def run_analyser(slice_path, patterns_path, analyser_path):
    """Run analyser and return True if successful."""
    cmd = [sys.executable, analyser_path, slice_path, patterns_path]
    try:
        # Run the analyser
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            print(f"❌ Analyser failed for {slice_path}:\n{result.stderr}")
            return False
        # print(f"  ✓ Ran analyser on {os.path.basename(slice_path)}")
        return True
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout running analyser on {slice_path}")
        return False

def validate_with_your_tool(output_file, expected_file, validate_path):
    """Run YOUR validate.py to compare output with expected."""
    cmd = [sys.executable, validate_path, "-o", output_file, "-t", expected_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        
        # Check if validation passed based on output keywords or return code
        if "MISSING FLOWS" in stdout or "BAD FLOWS" in stdout or result.returncode != 0:
            print(f"❌ VALIDATION FAILED")
            # Indent the output for readability
            print("   " + stdout.replace("\n", "\n   "))
            if stderr:
                print("   Errors: " + stderr.replace("\n", "\n   "))
            return False
        
        # If we get here, it likely passed
        print(f"✅ VALIDATED")
        return True
        
    except subprocess.TimeoutExpired:
        print(f"❌ Validation timeout")
        return False

def run_test(slice_path, patterns_path, expected_path, analyser_path, validate_path):
    """Executes a single test case."""
    
    # Calculate where the output should go. 
    # Your analyser (Laura_py_analyser.py) saves to 'output/<filename>.output.json'
    slice_filename = os.path.basename(slice_path)
    output_filename = slice_filename.replace('.py', '.output.json')
    output_path = os.path.join("output", output_filename)
    
    print(f"\n🔍 Testing {slice_filename}...")
    
    # 1. Clean previous output
    if os.path.exists(output_path):
        os.remove(output_path)
    
    # 2. Run the analyser
    if not run_analyser(slice_path, patterns_path, analyser_path):
        return False
    
    # 3. Check if output was created
    if not os.path.exists(output_path):
        print(f"❌ Output file not found: {output_path}")
        return False
    
    # 4. Validate results
    return validate_with_your_tool(output_path, expected_path, validate_path)

def discover_tests(base_dir):
    """Walks through directories to find matching .py, .patterns.json, and .output.json files."""
    test_cases = []
    
    # Walk through the directory tree
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".py"):
                # Construct full paths
                slice_path = os.path.join(root, file)
                base_name = os.path.splitext(file)[0]
                
                # Check for companion files (patterns and expected output)
                patterns_file = base_name + ".patterns.json"
                output_file = base_name + ".output.json"
                
                patterns_path = os.path.join(root, patterns_file)
                expected_path = os.path.join(root, output_file)
                
                # If both companion files exist, we have a valid test case
                if os.path.exists(patterns_path) and os.path.exists(expected_path):
                    test_cases.append((slice_path, patterns_path, expected_path))
                    
    return sorted(test_cases)

def main():
    print("🚀 Scanning for tests...")
    
    ANALYSER = "py_analyser.py"
    VALIDATE = "validate.py"
    SLICES_DIR = "slices"
    
    # Check requirements
    if not os.path.exists(ANALYSER):
        print(f"❌ {ANALYSER} not found!")
        sys.exit(1)
    if not os.path.exists(VALIDATE):
        print(f"❌ {VALIDATE} not found!")
        sys.exit(1)
    if not os.path.exists(SLICES_DIR):
        print(f"❌ '{SLICES_DIR}' directory not found!")
        sys.exit(1)

    # Auto-discover tests
    tests = discover_tests(SLICES_DIR)
    
    if not tests:
        print("❌ No valid tests found (checked for .py + .patterns.json + .output.json triplets).")
        sys.exit(1)
        
    print(f"📋 Found {len(tests)} tests.")
    
    passed = 0
    total = len(tests)
    
    # Run all discovered tests
    for slice_path, patterns_path, expected_path in tests:
        if run_test(slice_path, patterns_path, expected_path, ANALYSER, VALIDATE):
            passed += 1
    
    print("\n" + "="*70)
    print(f"📊 SUMMARY: {passed}/{total} PASSED")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! 🎉")
        sys.exit(0)
    else:
        print("❌ Some tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()