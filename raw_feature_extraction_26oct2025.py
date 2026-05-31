#!/usr/bin/env python3
"""
Enhanced DeepReflect VEX-IR Feature Extractor (Linux ELF, Cross-Architecture)
============================================================================

Extracts:
  1. Instruction-level semantics (VEX Iop_* operators)
  2. Structural graph metrics (offspring count, betweenness)
  3. API/Call-site resolution via ELF symbol table
  4. BOTH IROps (Iop_*) AND Statements (Ist_*) for complete feature coverage

Usage:
  Single file: python3 extract_features.py --input /path/to/binary --output /path/to/features.txt
  Multiple files: python3 extract_features.py --input-dir /path/to/binaries --output-dir /path/to/features [--debug true]

Dependencies:
  pip install angr pyvex networkx pyelftools
"""

import os
import sys
import time
import argparse
import glob
from pathlib import Path
import networkx as nx
import angr
import pyvex
from elftools.elf.elffile import ELFFile


# === Basic Block Representation ===
class BasicBlockFeatures:
    def __init__(self, addr):
        self.addr = addr
        self.insts = []        # VEX Iop_* tokens (semantic ops)
        self.statements = []   # VEX Ist_* tokens (structural ops)
        self.api_calls = []    # resolved function calls (symbols)
        self.offspring = 0
        self.betweenness = 0.0

    def __str__(self):
        s = f"Basic Block Addr: {hex(self.addr)}\n"
        s += "    ++++++ Instruction Features ++++++\n"
        s += f"    Insts: {';'.join(self.insts)}\n\n"
        s += "    ++++++ Statement Features ++++++\n"
        s += f"    Statements: {';'.join(self.statements)}\n\n"
        s += "    ++++++ Structural Features ++++++\n"
        s += f"    Num offspring: {self.offspring}\n"
        s += f"    Betweenness: {self.betweenness:.6f}\n\n"
        s += "    ++++++ API Features ++++++\n"
        s += f"    APIs: {';'.join(self.api_calls)}\n"
        return s


# === ELF Symbol Resolver (Linux ELF only) ===
def build_symbol_map(binary_path, debug=False):
    """Collect symbols from ELF symtab + dynsym for resolving API calls."""
    sym_map = {}
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            for secname in (".symtab", ".dynsym"):
                sec = elf.get_section_by_name(secname)
                if not sec:
                    continue
                for sym in sec.iter_symbols():
                    if sym.entry.st_value and sym.name:
                        addr = sym.entry.st_value
                        size = sym.entry.st_size or 0
                        sym_map[addr] = (sym.name, size)
        if debug:
            print(f"[+] Extracted {len(sym_map)} ELF symbols")
    except Exception as e:
        if debug:
            print(f"[!] Symbol map build failed: {e}")
    return sym_map


def resolve_symbol(sym_map, addr):
    """Find closest matching symbol for an address."""
    if not sym_map or addr is None:
        return None
    if addr in sym_map:
        return sym_map[addr][0]
    lowers = [(a, v) for a, v in sym_map.items() if a <= addr]
    if lowers:
        lowers.sort(key=lambda x: x[0], reverse=True)
        a, (name, size) = lowers[0]
        if addr < a + size:
            return name
    return None

def extract_vex_features(irsb):
    """Extract both IROps and Statements from VEX IR - FIXED VERSION"""
    irops = set()
    statements = set()

    def recurse_expr(expr):
        """Recursively extract IROps from expressions"""
        if hasattr(expr, "op"):
            op_str = str(expr.op)
            if op_str.startswith("Iop_"):
                irops.add(op_str)
        # recurse through children
        for attr in ["args", "expr", "kid", "kids", "left", "right"]:
            if hasattr(expr, attr):
                val = getattr(expr, attr)
                if isinstance(val, (list, tuple)):
                    for c in val:
                        recurse_expr(c)
                elif val is not None:
                    recurse_expr(val)

    # Extract Statements (Ist_*) - FIXED APPROACH
    for stmt in irsb.statements:
        # Get the statement type directly from the statement object
        if hasattr(stmt, "tag"):
            # This is the correct way to get statement type
            stmt_tag = stmt.tag
            if "Ist_" in stmt_tag:
                statements.add(stmt_tag)
        
        # Extract IROps from statement data
        if hasattr(stmt, "data"):
            recurse_expr(stmt.data)

    # Extract IROps from the next expression (control flow)
    if hasattr(irsb, "next"):
        recurse_expr(irsb.next)

    # Debug: Print what we found
    if statements:
        print(f"[DEBUG] Found statements: {statements}")

    return sorted(irops), sorted(statements)

# === Extract BOTH IROps (Iop_*) AND Statements (Ist_*) ===
def extract_vex_features1(irsb):
    """Extract both IROps and Statements from VEX IR"""
    irops = set()
    statements = set()

    def recurse_expr(expr):
        """Recursively extract IROps from expressions"""
        if hasattr(expr, "op"):
            op_str = str(expr.op)
            if op_str.startswith("Iop_"):
                irops.add(op_str)
        # recurse through children
        for attr in ["args", "expr", "kid", "kids", "left", "right"]:
            if hasattr(expr, attr):
                val = getattr(expr, attr)
                if isinstance(val, (list, tuple)):
                    for c in val:
                        recurse_expr(c)
                elif val is not None:
                    recurse_expr(val)

    # Extract Statements (Ist_*)
    for stmt in irsb.statements:
        stmt_str = str(stmt.__class__.__name__)
        if stmt_str.startswith("IRStmt_"):
            # Convert "IRStmt_Store" to "Ist_Store"
            stmt_name = stmt_str.replace("IRStmt_", "Ist_")
            statements.add(stmt_name)
        
        # Extract IROps from statement data
        if hasattr(stmt, "data"):
            recurse_expr(stmt.data)

    # Extract IROps from the next expression (control flow)
    if hasattr(irsb, "next"):
        recurse_expr(irsb.next)

    return sorted(irops), sorted(statements)


# === Enhanced Feature Extraction with Version Compatibility ===
def extract_features(binary_path, debug=False):
    start = time.time()
    results = []

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        if debug:
            print(f"[+] Loaded project for {os.path.basename(binary_path)}")

        cfg = proj.analyses.CFGFast(normalize=True)
        if debug:
            print(f"[+] Built CFG for {os.path.basename(binary_path)}")

        sym_map = build_symbol_map(binary_path, debug)

        # --- Build Address-Level Graph with Version Compatibility ---
        addr_graph = nx.DiGraph()
        
        # Handle different angr versions for CFG nodes
        try:
            # Newer angr versions (>= 9.0)
            cfg_nodes = list(cfg.graph.nodes())
            if debug:
                print(f"[+] Using new angr API (cfg.graph.nodes())")
        except AttributeError:
            try:
                # Older angr versions (< 9.0)
                cfg_nodes = list(cfg.nodes())
                if debug:
                    print(f"[+] Using old angr API (cfg.nodes())")
            except AttributeError:
                if debug:
                    print(f"[!] Could not access CFG nodes for {binary_path}")
                return []
        
        if debug:
            print(f"[+] Processing {len(cfg_nodes)} CFG nodes")

        # Build the graph
        for node in cfg_nodes:
            try:
                # Get successors with version compatibility
                try:
                    # Newer angr versions
                    successors = list(node.successors)
                except AttributeError:
                    # Older angr versions
                    try:
                        successors = list(cfg.get_successors(node))
                    except AttributeError:
                        # Fallback - try to get any successors
                        successors = []
                
                for succ in successors:
                    try:
                        addr_graph.add_edge(node.addr, succ.addr)
                    except AttributeError:
                        if debug:
                            print(f"[!] Could not add edge for node {node}")
                        continue
            except Exception as e:
                if debug:
                    print(f"[!] Error building graph edge: {e}")
                continue

        # --- Compute Betweenness Centrality ---
        try:
            if len(addr_graph.nodes()) > 0:
                bet = nx.betweenness_centrality(addr_graph, normalized=True)
                if debug:
                    print(f"[+] Computed betweenness for {len(bet)} nodes")
            else:
                bet = {}
                if debug:
                    print(f"[!] Empty graph for {binary_path}")
        except Exception as e:
            if debug:
                print(f"[!] Betweenness calculation failed: {e}")
            bet = {}

        # --- Extract features for each basic block ---
        processed_blocks = 0
        
        for node in cfg_nodes:
            try:
                bb = BasicBlockFeatures(node.addr)
                
                # Get offspring count with version compatibility
                try:
                    # Newer angr versions
                    bb.offspring = len(list(node.successors))
                except AttributeError:
                    # Older angr versions
                    try:
                        bb.offspring = len(list(cfg.get_successors(node)))
                    except AttributeError:
                        bb.offspring = 0
                
                bb.betweenness = bet.get(node.addr, 0.0)

                # Get basic block IR
                try:
                    block = proj.factory.block(node.addr)
                    irsb = block.vex

                    # Extract BOTH IROps and Statements
                    bb.insts, bb.statements = extract_vex_features(irsb)

                    # Detect function/API calls
                    jk = getattr(irsb, "jumpkind", "")
                    if "Call" in jk:
                        target = None
                        if isinstance(irsb.next, pyvex.IRExpr.Const):
                            target = int(irsb.next.con.value)
                        else:
                            # Get successors for call target with version compatibility
                            try:
                                successors = list(node.successors)
                            except AttributeError:
                                try:
                                    successors = list(cfg.get_successors(node))
                                except AttributeError:
                                    successors = []
                            if successors:
                                target = successors[0].addr

                        if target:
                            sym = resolve_symbol(sym_map, target)
                            if sym:
                                bb.api_calls.append(sym)
                            else:
                                bb.api_calls.append(f"call_{hex(target)}")

                except Exception as e:
                    if debug:
                        print(f"[!] Error processing block IR {hex(node.addr)}: {e}")
                    # Continue with basic features even if IR extraction fails

                results.append(bb)
                processed_blocks += 1

                if debug and processed_blocks % 500 == 0:
                    print(f"[+] Processed {processed_blocks} blocks...")

            except Exception as e:
                if debug:
                    print(f"[x] Error at node {hex(node.addr) if hasattr(node, 'addr') else 'unknown'}: {e}")

        if debug:
            total_insts = sum(len(bb.insts) for bb in results)
            total_stmts = sum(len(bb.statements) for bb in results)
            total_apis = sum(len(bb.api_calls) for bb in results)
            print(f"[✓] Extracted {len(results)} blocks in {time.time()-start:.2f}s")
            if results:
                print(f"[📊] Summary: {total_insts} IROps, {total_stmts} Statements, {total_apis} API calls")
            else:
                print(f"[📊] No blocks extracted")

    except Exception as e:
        print(f"[❌] Failed to analyze {binary_path}: {e}")
        if debug:
            import traceback
            traceback.print_exc()

    return results


# === Output Writer ===
def dump_results(output_path, data):
    """Write features to output file with proper directory creation"""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        for d in data:
            f.write(f"{d}\n")
    print(f"[✓] Features written to {output_path}")


# === Batch Processing ===
def process_directory(input_dir, output_dir, debug=False):
    """Process all ELF binaries in a directory"""
    # Find all ELF binaries (common extensions)
    elf_patterns = ["*.elf", "*.bin", "*", "*.so", "*.o"]
    binary_files = []
    
    for pattern in elf_patterns:
        binary_files.extend(glob.glob(os.path.join(input_dir, pattern)))
    
    # Filter out directories and non-ELF files (basic check)
    binary_files = [f for f in binary_files if os.path.isfile(f)]
    
    if not binary_files:
        print(f"[!] No binary files found in {input_dir}")
        return 0
    
    print(f"[🔄] Found {len(binary_files)} files to process in {input_dir}")
    
    successful = 0
    failed = 0
    
    for i, binary_path in enumerate(binary_files, 1):
        try:
            print(f"\n[{i}/{len(binary_files)}] Processing: {os.path.basename(binary_path)}")
            
            # Generate output filename: inputfile_raw.txt
            input_filename = Path(binary_path).stem
            output_filename = f"{input_filename}_raw.txt"
            output_path = os.path.join(output_dir, output_filename)
            
            # Skip if output already exists
            if os.path.exists(output_path):
                print(f"[⏭️] Skipping {binary_path} - output already exists")
                continue
            
            features = extract_features(binary_path, debug)
            
            if features:
                dump_results(output_path, features)
                successful += 1
            else:
                print(f"[❌] No features extracted from {binary_path}")
                failed += 1
                
        except KeyboardInterrupt:
            print(f"\n[⚠️] Processing interrupted by user")
            break
        except Exception as e:
            print(f"[❌] Failed to process {binary_path}: {e}")
            failed += 1
            if debug:
                import traceback
                traceback.print_exc()
    
    print(f"\n[🎉] BATCH PROCESSING COMPLETE")
    print(f"    Successful: {successful}")
    print(f"    Failed: {failed}")
    print(f"    Total: {len(binary_files)}")
    
    return successful


# === Enhanced CLI ===
def main():
    parser = argparse.ArgumentParser(
        description="DeepReflect VEX-IR Feature Extractor for Linux ELF binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Mutually exclusive: single file vs directory processing
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--input", help="Path to single ELF binary")
    group.add_argument("--input-dir", help="Directory containing ELF binaries")
    
    parser.add_argument("--output", help="Output feature file for single file processing")
    parser.add_argument("--output-dir", help="Output directory for batch processing")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output")
    
    args = parser.parse_args()

    # Single file processing
    if args.input:
        if not args.output:
            print("[!] --output required when using --input")
            sys.exit(1)
            
        binary_path = args.input
        output_path = args.output
        
        if not os.path.exists(binary_path):
            print(f"[!] File not found: {binary_path}")
            sys.exit(1)
            
        features = extract_features(binary_path, args.debug)
        dump_results(output_path, features)
    
    # Batch directory processing
    elif args.input_dir:
        if not args.output_dir:
            print("[!] --output-dir required when using --input-dir")
            sys.exit(1)
            
        input_dir = args.input_dir
        output_dir = args.output_dir
        
        if not os.path.exists(input_dir):
            print(f"[!] Input directory not found: {input_dir}")
            sys.exit(1)
            
        os.makedirs(output_dir, exist_ok=True)
        process_directory(input_dir, output_dir, args.debug)


if __name__ == "__main__":
    main()
