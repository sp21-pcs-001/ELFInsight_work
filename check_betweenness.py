#!/usr/bin/env python3
"""
Scan all *_raw.txt files in a directory and report files where Betweenness is non-zero.
Usage: python3 check_raw_betweenness.py --dir /path/to/raw_txt_folder
"""

import os
import glob
import argparse
import re

def check_raw_file(filepath, verbose=False):
    """Return True if any Betweenness line is non-zero."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return False

    # Find all Betweenness lines (format: "Betweenness: value")
    # Use regex to capture the numeric value after Betweenness:
    pattern = r'Betweenness:\s*([\d\.eE+-]+)'
    matches = re.findall(pattern, content)
    
    if not matches:
        return False  # No Betweenness line? Should not happen.
    
    for match in matches:
        try:
            val = float(match)
            if abs(val) > 1e-9:  # treat as non-zero if greater than 1e-9
                if verbose:
                    print(f"  Found non-zero: Betweenness: {match}")
                return True
        except ValueError:
            if verbose:
                print(f"  Could not parse value: {match}")
            return True  # treat as potential problem
    
    return False

def main():
    parser = argparse.ArgumentParser(description="Check raw .txt files for non-zero Betweenness")
    parser.add_argument("--dir", required=True, help="Directory containing *_raw.txt files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show details")
    parser.add_argument("--output", "-o", help="Optional output file to list bad files")
    args = parser.parse_args()

    raw_files = glob.glob(os.path.join(args.dir, "*_raw.txt"))
    if not raw_files:
        print(f"No *_raw.txt files found in {args.dir}")
        return

    bad_files = []
    for f in raw_files:
        if check_raw_file(f, args.verbose):
            bad_files.append(f)
        elif args.verbose:
            print(f"✅ {os.path.basename(f)}: all Betweenness zero")

    print("\n" + "="*60)
    if bad_files:
        print(f"❌ Found {len(bad_files)} files with non‑zero Betweenness:")
        for f in bad_files:
            print(f"   {f}")
        if args.output:
            with open(args.output, 'w') as out:
                for f in bad_files:
                    out.write(f + "\n")
            print(f"   List saved to {args.output}")
    else:
        print("✅ All raw files have Betweenness = 0.0 for all basic blocks.")

if __name__ == "__main__":
    main()
