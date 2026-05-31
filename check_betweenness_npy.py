#!/usr/bin/env python3
"""
Check all .npy files in a directory for non-zero betweenness (column index 1).
Usage: python3 check_npy_betweenness.py --dir /path/to/npy/folder
"""

import numpy as np
import glob
import argparse
import os

def check_npy_file(filepath, verbose=False):
    """Return True if any betweenness value is non-zero."""
    try:
        data = np.load(filepath)
        # data shape: (num_blocks, features). We need at least 2 columns (index 0 and 1)
        if data.ndim != 2:
            if verbose:
                print(f"  Skipping: not 2D array (shape {data.shape})")
            return False
        if data.shape[1] <= 1:
            if verbose:
                print(f"  Skipping: only {data.shape[1]} column(s), no betweenness column")
            return False
        betweenness = data[:, 1]
        if np.any(betweenness != 0):
            if verbose:
                max_val = np.max(betweenness)
                print(f"  Non-zero betweenness found! max = {max_val:.6f}")
            return True
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return False
    return False

def main():
    parser = argparse.ArgumentParser(description="Check .npy files for non-zero betweenness")
    parser.add_argument("--dir", required=True, help="Directory containing .npy files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show details")
    parser.add_argument("--output", "-o", help="Optional output file to list bad files")
    args = parser.parse_args()

    npy_files = glob.glob(os.path.join(args.dir, "*.npy"))
    if not npy_files:
        print(f"No .npy files found in {args.dir}")
        return

    bad_files = []
    good_count = 0
    for f in npy_files:
        if check_npy_file(f, args.verbose):
            bad_files.append(f)
        else:
            good_count += 1
            if args.verbose:
                print(f"✅ {os.path.basename(f)}: all betweenness zero")

    print("\n" + "="*60)
    print(f"Checked {len(npy_files)} .npy files")
    print(f"Good (all betweenness zero): {good_count}")
    print(f"Bad (non-zero betweenness): {len(bad_files)}")
    if bad_files:
        print("\n❌ Files with non‑zero betweenness:")
        for f in bad_files:
            print(f"   {f}")
        if args.output:
            with open(args.output, 'w') as out:
                for f in bad_files:
                    out.write(f + "\n")
            print(f"   List saved to {args.output}")
    else:
        print("\n✅ All .npy files have betweenness = 0 for all basic blocks.")

if __name__ == "__main__":
    main()
