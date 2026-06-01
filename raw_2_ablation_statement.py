#!/usr/bin/env python3
"""
Ablation Study: Zero out specific feature groups in raw.txt files
Supports: no_instruction, no_structural, no_api
"""

import os
import glob
import argparse
from pathlib import Path


def zero_out_features(input_file, output_file, mode='no_instruction'):
    """
    Read raw.txt file and zero out specific features based on ablation mode
    
    Args:
        input_file: Path to original *_raw.txt file
        output_file: Path to output modified *_raw.txt file
        mode: 'no_instruction', 'no_structural', or 'no_api'
    """
    
    with open(input_file, 'r') as f:
        lines = f.readlines()
    
    modified_lines = []
    
    for line in lines:
        # Check what type of line this is
        if mode == 'no_instruction' and line.strip().startswith('Insts:'):
            # Zero out instruction features
            modified_lines.append('    Insts: \n')
        elif mode == 'no_statement' and line.strip().startswith('Statements:'):
            # Zero out instruction features
            modified_lines.append('    Statements: \n')
            
        elif mode == 'no_structural':
            # Zero out structural features
            if 'Num offspring:' in line:
                modified_lines.append('    Num offspring: 0\n')
            elif 'Betweenness:' in line:
                modified_lines.append('    Betweenness: 0.000000\n')
            else:
                modified_lines.append(line)
        
        elif mode == 'no_api' and line.strip().startswith('APIs:'):
            # Zero out API features
            modified_lines.append('    APIs: \n')
        
        else:
            # Keep line as-is
            modified_lines.append(line)
    
    # Write modified content
    with open(output_file, 'w') as f:
        f.writelines(modified_lines)


def process_directory(input_dir, output_dir, mode='no_instruction', verbose=False):
    """
    Process all *_raw.txt files in input directory
    
    Args:
        input_dir: Directory containing original raw.txt files
        output_dir: Directory to save modified raw.txt files
        mode: Ablation mode
        verbose: Print progress
    """
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Find all *_raw.txt files
    pattern = os.path.join(input_dir, '*_raw.txt')
    raw_files = glob.glob(pattern)
    
    if not raw_files:
        print(f"[!] No *_raw.txt files found in {input_dir}")
        return
    
    print(f"[+] Found {len(raw_files)} raw.txt files")
    print(f"[+] Ablation mode: {mode}")
    print(f"[+] Output directory: {output_dir}")
    print()
    
    # Process each file
    for i, input_file in enumerate(raw_files, 1):
        filename = os.path.basename(input_file)
        output_file = os.path.join(output_dir, filename)
        
        zero_out_features(input_file, output_file, mode)
        
        if verbose or i % 100 == 0:
            print(f"[{i}/{len(raw_files)}] Processed: {filename}")
    
    print()
    print(f"[✓] DONE! Modified {len(raw_files)} files")
    print(f"[✓] Output: {output_dir}")


def process_single_file(input_file, output_file, mode='no_instruction'):
    """Process a single file"""
    
    zero_out_features(input_file, output_file, mode)
    print(f"[✓] Modified: {input_file}")
    print(f"[✓] Saved to: {output_file}")


def verify_ablation(file_path, mode):
    """
    Verify that ablation was applied correctly
    """
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    if mode == 'no_instruction':
        # Check that all Insts: lines are empty
        for line in content.split('\n'):
            if line.strip().startswith('Insts:'):
                if line.strip() != 'Insts:':
                    print(f"[!] ERROR: Found non-empty Insts line: {line}")
                    return False
        print(f"[✓] Verification passed: All instruction features zeroed")
        return True
    if mode == 'no_statement':
        # Check that all Insts: lines are empty
        for line in content.split('\n'):
            if line.strip().startswith('Statements:'):
                if line.strip() != 'Statements:':
                    print(f"[!] ERROR: Found non-empty Statements line: {line}")
                    return False
        print(f"[✓] Verification passed: All instruction features zeroed")
        return True
        
    elif mode == 'no_structural':
        # Check that offspring and betweenness are 0
        for line in content.split('\n'):
            if 'Num offspring:' in line:
                if '0' not in line or any(c.isdigit() and c != '0' for c in line.split(':')[1]):
                    print(f"[!] ERROR: Non-zero offspring: {line}")
                    return False
            elif 'Betweenness:' in line:
                value = line.split(':')[1].strip()
                if float(value) != 0.0:
                    print(f"[!] ERROR: Non-zero betweenness: {line}")
                    return False
        print(f"[✓] Verification passed: All structural features zeroed")
        return True
    
    elif mode == 'no_api':
        # Check that all APIs: lines are empty
        for line in content.split('\n'):
            if line.strip().startswith('APIs:'):
                if line.strip() != 'APIs:':
                    print(f"[!] ERROR: Found non-empty APIs line: {line}")
                    return False
        print(f"[✓] Verification passed: All API features zeroed")
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Zero out feature groups in raw.txt files for ablation study',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process directory - remove instruction features
  python3 ablation_zero_features.py --input-dir features/benign --output-dir ablation/no_instruction --mode no_instruction
  
  # Process directory - remove structural features
  python3 ablation_zero_features.py --input-dir features/benign --output-dir ablation/no_structural --mode no_structural
  
  # Process directory - remove API features
  python3 ablation_zero_features.py --input-dir features/benign --output-dir ablation/no_api --mode no_api
  
  # Process single file
  python3 ablation_zero_features.py --input md5_raw.txt --output md5_no_instruction_raw.txt --mode no_instruction
  
  # Verify ablation was applied correctly
  python3 ablation_zero_features.py --verify ablation/no_instruction/md5_raw.txt --mode no_instruction
        """
    )
    
    # Mutually exclusive: directory or single file
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--input-dir', help='Directory containing *_raw.txt files')
    group.add_argument('--input', help='Single raw.txt file to process')
    group.add_argument('--verify', help='Verify ablation in a file')
    
    parser.add_argument('--output-dir', help='Output directory (required with --input-dir)')
    parser.add_argument('--output', help='Output file (required with --input)')
    
    parser.add_argument('--mode', 
                       choices=['no_instruction', 'no_statement', 'no_structural', 'no_api'],
                       default='no_instruction',
                       help='Which features to zero out (default: no_instruction)')
    
    parser.add_argument('--verbose', action='store_true',
                       help='Print progress for each file')
    
    args = parser.parse_args()
    
    # Verify mode
    if args.verify:
        verify_ablation(args.verify, args.mode)
        return
    
    # Directory processing
    if args.input_dir:
        if not args.output_dir:
            parser.error("--output-dir required when using --input-dir")
        process_directory(args.input_dir, args.output_dir, args.mode, args.verbose)
    
    # Single file processing
    elif args.input:
        if not args.output:
            parser.error("--output required when using --input")
        process_single_file(args.input, args.output, args.mode)


if __name__ == '__main__':
    main()
