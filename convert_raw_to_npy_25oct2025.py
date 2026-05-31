import os
import numpy as np
import re
from collections import defaultdict
import glob

# =============================
# CONFIGURATION
# =============================
TYPE_DIR = "type"
OUTPUT_DIR = "features_npy"
DEBUG = True  # Set to False for production
BATCH_PROCESSING = True  # Process multiple files efficiently

# =============================
# EXPANDED DEEPREFLECT FEATURES (19 features)
# =============================
FEATURE_NAMES = [
    "offspring", "betweenness", 
    "arith_basic_math", "arith_logic_ops", "arith_bit_shift",
    "trans_register", "trans_memory", "control_flow",
    "mem_read", "mem_write", "fp_ops", "vector_ops",
    "api_network", "api_file", "api_process", "api_memory", 
    "api_sysinfo", "api_crypto", "api_threads"
]

# ======================================================
# OPTIMIZED FEATURE MAPPINGS LOADING
# ======================================================
def load_feature_mappings():
    """Optimized loading of feature mappings with caching"""
    inst_map = {}
    api_map = {}
    
    # Load instruction types with error handling
    inst_dir = os.path.join(TYPE_DIR, "inst")
    if os.path.exists(inst_dir):
        for fname in glob.glob(os.path.join(inst_dir, "*.txt")):
            category = os.path.splitext(os.path.basename(fname))[0]
            try:
                with open(fname, 'r', encoding='utf-8') as f:
                    for line in f:
                        token = line.strip()
                        if token and not token.startswith('#'):  # Skip comments
                            inst_map[token] = category
            except Exception as e:
                if DEBUG:
                    print(f"[WARNING] Could not load {fname}: {e}")
    
    # Load API types with normalization
    api_dir = os.path.join(TYPE_DIR, "api")
    if os.path.exists(api_dir):
        for fname in glob.glob(os.path.join(api_dir, "*.txt")):
            category = os.path.splitext(os.path.basename(fname))[0]
            try:
                with open(fname, 'r', encoding='utf-8') as f:
                    for line in f:
                        token = line.strip().lower()
                        if token and not token.startswith('#'):
                            api_map[token] = category
            except Exception as e:
                if DEBUG:
                    print(f"[WARNING] Could not load {fname}: {e}")
    
    if DEBUG:
        print(f"[LOADED] {len(inst_map)} instruction mappings, {len(api_map)} API mappings")
        # Show loaded categories
        all_categories = set(inst_map.values())
        print(f"[CATEGORIES] Loaded: {', '.join(sorted(all_categories))}")
    
    return inst_map, api_map

# ======================================================
# UPDATED PARSING WITH STATEMENTS SUPPORT
# ======================================================
def parse_raw_file(raw_file, inst_map, api_map):
    """Updated parsing to handle BOTH IROps and Statements"""
    try:
        with open(raw_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        if DEBUG:
            print(f"[ERROR] Could not read {raw_file}: {e}")
        return np.array([])

    # Updated regex pattern to capture Statements
    pattern = r'Basic Block Addr:\s*(0x[0-9a-fA-F]+|\d+)\s*\n.*?Insts:\s*(.*?)\s*\n.*?Statements:\s*(.*?)\s*\n.*?Num offspring:\s*(\d+)\s*\n.*?Betweenness:\s*([\d.]+)\s*\n.*?APIs:\s*(.*?)\s*\n'
    matches = re.findall(pattern, content, re.DOTALL)
    
    if not matches:
        if DEBUG:
            print(f"[WARNING] No basic blocks found in {raw_file}")
        return np.array([])
    
    if DEBUG:
        print(f"[PARSE] Found {len(matches)} basic blocks in {os.path.basename(raw_file)}")
    
    feature_vectors = []
    
    for addr, insts_str, stmts_str, offspring_str, betweenness_str, apis_str in matches:
        features = np.zeros(19, dtype=np.float32)
        
        # 1. Structural features
        try:
            features[0] = float(offspring_str)
            features[1] = float(betweenness_str)
        except ValueError:
            features[0] = 0
            features[1] = 0.0
        
        # 2. Process IROps (Insts)
        inst_tokens = [t.strip() for t in insts_str.split(';') if t.strip()]
        for token in inst_tokens:
            if token in inst_map:
                category = inst_map[token]
                # Map to feature index
                category_index_map = {
                    "arith-basic-math": 2, "arith-logic-ops": 3, "arith-bit-shift": 4,
                    "trans-register": 5, "trans-memory": 6, "control-flow": 7,
                    "fp-ops": 10, "vector-ops": 11
                }
                idx = category_index_map.get(category)
                if idx is not None:
                    features[idx] += 1
                    if DEBUG and features[idx] == 1:
                        print(f"[IROP] {token} -> {category} (feature {idx})")
        
        # 3. Process Statements (NEW!)
        stmt_tokens = [t.strip() for t in stmts_str.split(';') if t.strip()]
        for token in stmt_tokens:
            if token in inst_map:
                category = inst_map[token]
                # Map statements to features
                stmt_category_map = {
                    "statements-control": 7,    # control_flow
                    "statements-memory": 9,     # mem_write  
                    "statements-register": 5,   # trans_register
                }
                idx = stmt_category_map.get(category)
                if idx is not None:
                    features[idx] += 1
                    if DEBUG and features[idx] == 1:
                        print(f"[STMT] {token} -> {category} (feature {idx})")
        
        # 4. Manual memory operation detection (fallback)
        features[8] = sum(1 for t in inst_tokens if t.startswith("Iop_Load"))
        features[9] += sum(1 for t in inst_tokens if t.startswith("Iop_Store"))
        
        # 5. Manual FP and vector detection (fallback)
        features[10] += sum(1 for t in inst_tokens if any(x in t for x in ["Iop_F", "F32", "F64"]))
        features[11] += sum(1 for t in inst_tokens if any(x in t for x in ["x4", "x8", "x16", "Vec"]))
        
        # 6. API features with call pattern enhancement
        api_tokens = [t.strip().lower() for t in apis_str.split(';') if t.strip()]
        for token in api_tokens:
            if token.startswith('call_0x') or token.startswith('call_weak_fn'):
                features[7] += 1  # control_flow
                if DEBUG:
                    print(f"[CALL] {token} -> control_flow")
            elif token in ['deregister_tm_clones', 'register_tm_clones', '_init', '_fini']:
                features[7] += 1  # control_flow
                if DEBUG:
                    print(f"[INIT] {token} -> control_flow")
            elif token in api_map:
                category = api_map[token]
                api_index_map = {
                    "network": 12, "file": 13, "process": 14, 
                    "memory": 15, "system-info": 16, "crypto": 17, "threads": 18
                }
                idx = api_index_map.get(category)
                if idx is not None:
                    features[idx] += 1
                    if DEBUG and features[idx] == 1:
                        print(f"[API] {token} -> {category}")
        
        feature_vectors.append(features)
    
    return np.array(feature_vectors)

# ======================================================
# ENHANCED NORMALIZATION WITH BETTER STATISTICS
# ======================================================
def enhanced_normalize_features(feature_matrix, filename=""):
    """Enhanced normalization with detailed statistics"""
    if feature_matrix.size == 0:
        return feature_matrix, {}
    
    normalized = np.zeros_like(feature_matrix)
    stats = {}
    
    for i in range(feature_matrix.shape[1]):
        col = feature_matrix[:, i]
        col_max = np.max(col)
        
        if col_max > 0:
            normalized[:, i] = col / col_max
        else:
            normalized[:, i] = 0.0
        
        non_zero_count = np.count_nonzero(col)
        total_elements = len(col)
        sparsity_percent = (non_zero_count / total_elements * 100) if total_elements > 0 else 0
        
        stats[FEATURE_NAMES[i]] = {
            'max': float(col_max),
            'mean': float(np.mean(col)),
            'std': float(np.std(col)),
            'non_zero': int(non_zero_count),
            'sparsity': "{:.1f}%".format(sparsity_percent),
            'total_elements': total_elements
        }
    
    return normalized, stats

# ======================================================
# ENHANCED STATISTICS DISPLAY
# ======================================================
def print_enhanced_stats(overall_stats):
    """Print much more informative statistics"""
    print("\n=== ENHANCED DATASET STATISTICS ===")
    print("{:<20} {:<10} {:<10} {:<10} {:<12} {:<10}".format(
        "Feature", "Max", "Mean", "Std", "Non-Zero", "Sparsity"
    ))
    print("-" * 75)
    
    for feature in FEATURE_NAMES:
        if feature in overall_stats and overall_stats[feature]:
            max_vals = [s['max'] for s in overall_stats[feature]]
            mean_vals = [s['mean'] for s in overall_stats[feature]]
            std_vals = [s['std'] for s in overall_stats[feature]]
            non_zero_vals = [s['non_zero'] for s in overall_stats[feature]]
            sparsity_vals = [float(s['sparsity'].rstrip('%')) for s in overall_stats[feature]]
            
            print("{:<20} {:<10.3f} {:<10.3f} {:<10.3f} {:<12} {:<10.1f}%".format(
                feature,
                max(max_vals) if max_vals else 0,
                np.mean(mean_vals) if mean_vals else 0,
                np.mean(std_vals) if std_vals else 0,
                max(non_zero_vals) if non_zero_vals else 0,
                np.mean(sparsity_vals) if sparsity_vals else 0
            ))

# ======================================================
# ENHANCED BATCH PROCESSING WITH DETAILED STATS
# ======================================================
def process_files_batch(inst_map, api_map):
    """Process all raw files with enhanced progress tracking and statistics"""
    raw_files = glob.glob("*.txt")
    raw_files = [f for f in raw_files if "train" not in f and "test" not in f]
    
    if not raw_files:
        print("[WARNING] No raw .txt files found in current directory")
        return 0, {}
    
    if DEBUG:
        print(f"[BATCH] Processing {len(raw_files)} files...")
    
    processed_count = 0
    overall_stats = defaultdict(list)
    file_shapes = []
    
    for i, raw_file in enumerate(raw_files):
        if DEBUG:
            print(f"\n[{i+1}/{len(raw_files)}] Processing: {raw_file}")
        
        try:
            feature_matrix = parse_raw_file(raw_file, inst_map, api_map)
            
            if feature_matrix.size == 0:
                if DEBUG:
                    print(f"[SKIP] No features in {raw_file}")
                continue
            
            normalized_matrix, stats = enhanced_normalize_features(feature_matrix, raw_file)
            
            out_name = os.path.splitext(os.path.basename(raw_file))[0] + ".npy"
            out_path = os.path.join(OUTPUT_DIR, out_name)
            np.save(out_path, normalized_matrix)
            
            for feature, stat in stats.items():
                overall_stats[feature].append(stat)
            
            file_shapes.append(normalized_matrix.shape)
            
            print(f"[SAVE] {out_path} → Shape: {normalized_matrix.shape}")
            
            if DEBUG:
                print(f"[SUMMARY] {raw_file}")
                print(f"  Blocks: {normalized_matrix.shape[0]}, Features: {normalized_matrix.shape[1]}")
                print(f"  Non-zero features: {sum(stat['non_zero'] for stat in stats.values())}")
                
                active_features = [(feat, stat['non_zero']) for feat, stat in stats.items() if stat['non_zero'] > 0]
                active_features.sort(key=lambda x: x[1], reverse=True)
                if active_features:
                    print(f"  Top features: {', '.join([f'{feat}({count})' for feat, count in active_features[:3]])}")
            
            processed_count += 1
            
        except Exception as e:
            print(f"[ERROR] Failed to process {raw_file}: {e}")
            if DEBUG:
                import traceback
                traceback.print_exc()
    
    return processed_count, overall_stats, file_shapes

# ======================================================
# ENHANCED MAIN EXECUTION
# ======================================================
def main():
    print("=== DeepReflect Feature Converter (UPDATED - IROps + Statements) ===")
    print("Features: 19 features with enhanced IROp and Statement mapping")
    print("NEW: Statements support for control_flow, mem_write, trans_register")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    inst_map, api_map = load_feature_mappings()
    
    if not inst_map and not api_map:
        print("[ERROR] No feature mappings loaded. Check type/ directory structure.")
        return
    
    processed_count, overall_stats, file_shapes = process_files_batch(inst_map, api_map)
    
    print(f"\n" + "="*50)
    print("PROCESSING COMPLETE - ENHANCED SUMMARY")
    print("="*50)
    print(f"Successfully processed: {processed_count} files")
    print(f"Output directory: {OUTPUT_DIR}")
    
    if file_shapes:
        unique_shapes = set(file_shapes)
        shape_counts = {shape: file_shapes.count(shape) for shape in unique_shapes}
        print(f"\n📊 SHAPE DISTRIBUTION:")
        for shape, count in sorted(shape_counts.items()):
            print(f"  {shape}: {count} files")
    
    print(f"Feature vector shape: (N, 19) where N = basic blocks per file")
    
    if overall_stats and DEBUG:
        print_enhanced_stats(overall_stats)
        
        total_blocks = sum(shape[0] for shape in file_shapes)
        total_features = total_blocks * 19 if file_shapes else 0
        print(f"\n📈 OVERALL DATASET STATS:")
        print(f"  Total basic blocks: {total_blocks}")
        print(f"  Total feature vectors: {total_features}")
        print(f"  Average blocks per file: {total_blocks/len(file_shapes) if file_shapes else 0:.1f}")

    print(f"\n🎯 DEEPREFLECT READY: All .npy files are autoencoder-compatible!")

# ======================================================
# ENHANCED VERIFICATION FUNCTION
# ======================================================
def verify_deepreflect_compatibility():
    """Enhanced verification that all .npy files are DeepReflect ready"""
    npy_dir = "features_npy"
    
    if not os.path.exists(npy_dir):
        print("❌ features_npy directory not found!")
        return False
    
    npy_files = [f for f in os.listdir(npy_dir) if f.endswith('.npy')]
    
    if not npy_files:
        print("❌ No .npy files found in features_npy directory!")
        return False
    
    print("\n" + "="*60)
    print("ENHANCED DEEPREFLECT COMPATIBILITY VERIFICATION")
    print("="*60)
    
    all_valid = True
    compatibility_report = []
    
    for npy_file in npy_files:
        file_path = os.path.join(npy_dir, npy_file)
        try:
            data = np.load(file_path)
            
            checks = {
                "Shape correct (N,19)": data.shape[1] == 19,
                "All values finite": np.all(np.isfinite(data)),
                "Range [0,1]": np.all(data >= 0) and np.all(data <= 1),
                "No NaN values": not np.any(np.isnan(data))
            }
            
            all_passed = all(checks.values())
            status = "✅ PASS" if all_passed else "❌ FAIL"
            
            compatibility_report.append({
                'file': npy_file,
                'shape': data.shape,
                'status': status,
                'checks': checks
            })
            
            if not all_passed:
                all_valid = False
            
        except Exception as e:
            print(f"❌ ERROR loading {npy_file}: {e}")
            all_valid = False
    
    for report in compatibility_report:
        print(f"\n{report['status']} {report['file']}:")
        print(f"   Shape: {report['shape']}")
        for check_name, check_passed in report['checks'].items():
            symbol = "✅" if check_passed else "❌"
            print(f"   {symbol} {check_name}")
    
    print(f"\n" + "="*60)
    if all_valid:
        print("🎉 ALL FILES ARE DEEPREFLECT-COMPATIBLE! 🎉")
        print("🚀 Ready for autoencoder training!")
    else:
        print("⚠️  Some files have compatibility issues. Check above.")
    
    return all_valid

if __name__ == "__main__":
    main()
    
    print("\n" + "="*60)
    verify_deepreflect_compatibility()
