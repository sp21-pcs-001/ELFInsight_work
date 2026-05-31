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
DEBUG = True
BATCH_PROCESSING = True

# =============================
# FEATURE NAMES (20 total: address + 19 features)
# Column 0 = address (NOT used in training, used for ROC mapping)
# Columns 1-19 = actual features (used in training)
# =============================
FEATURE_NAMES = [
    "address",          # Column 0 - raw BB address, NOT normalized
    "offspring",        # Column 1
    "betweenness",      # Column 2
    "arith_basic_math", # Column 3
    "arith_logic_ops",  # Column 4
    "arith_bit_shift",  # Column 5
    "trans_register",   # Column 6
    "trans_memory",     # Column 7
    "control_flow",     # Column 8
    "mem_read",         # Column 9
    "mem_write",        # Column 10
    "fp_ops",           # Column 11
    "vector_ops",       # Column 12
    "api_network",      # Column 13
    "api_file",         # Column 14
    "api_process",      # Column 15
    "api_memory",       # Column 16
    "api_sysinfo",      # Column 17
    "api_crypto",       # Column 18
    "api_threads"       # Column 19
]

# ======================================================
# FEATURE MAPPINGS LOADING
# ======================================================
def load_feature_mappings():
    """Load instruction and API category mappings from type/ directory"""
    inst_map = {}
    api_map = {}

    inst_dir = os.path.join(TYPE_DIR, "inst")
    if os.path.exists(inst_dir):
        for fname in glob.glob(os.path.join(inst_dir, "*.txt")):
            category = os.path.splitext(os.path.basename(fname))[0]
            try:
                with open(fname, 'r', encoding='utf-8') as f:
                    for line in f:
                        token = line.strip()
                        if token and not token.startswith('#'):
                            inst_map[token] = category
            except Exception as e:
                if DEBUG:
                    print(f"[WARNING] Could not load {fname}: {e}")

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
        print(f"[LOADED] {len(inst_map)} instruction mappings, "
              f"{len(api_map)} API mappings")
        all_categories = set(inst_map.values())
        print(f"[CATEGORIES] {', '.join(sorted(all_categories))}")

    return inst_map, api_map

# ======================================================
# PARSING - NOW PRESERVES ADDRESS IN COLUMN 0
# ======================================================
def parse_raw_file(raw_file, inst_map, api_map):
    """
    Parse raw.txt file and return feature matrix.

    Output shape: (num_basic_blocks, 20)
      Column  0   : raw BB address as decimal integer (NOT normalized)
      Columns 1-2 : structural features (offspring, betweenness)
      Columns 3-12: instruction/statement features
      Columns 13-19: API features
    """
    try:
        with open(raw_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        if DEBUG:
            print(f"[ERROR] Could not read {raw_file}: {e}")
        return np.array([])

    pattern = (
        r'Basic Block Addr:\s*(0x[0-9a-fA-F]+|\d+)\s*\n'
        r'.*?Insts:\s*(.*?)\s*\n'
        r'.*?Statements:\s*(.*?)\s*\n'
        r'.*?Num offspring:\s*(\d+)\s*\n'
        r'.*?Betweenness:\s*([\d.]+)\s*\n'
        r'.*?APIs:\s*(.*?)\s*\n'
    )
    matches = re.findall(pattern, content, re.DOTALL)

    if not matches:
        if DEBUG:
            print(f"[WARNING] No basic blocks found in {raw_file}")
        return np.array([])

    if DEBUG:
        print(f"[PARSE] Found {len(matches)} basic blocks in "
              f"{os.path.basename(raw_file)}")

    # Instruction category -> column index (within columns 3-12)
    inst_category_index = {
        "arith-basic-math": 3,
        "arith-logic-ops":  4,
        "arith-bit-shift":  5,
        "trans-register":   6,
        "trans-memory":     7,
        "control-flow":     8,
        "fp-ops":           11,
        "vector-ops":       12,
    }

    # Statement category -> column index
    stmt_category_index = {
        "statements-control":  8,   # control_flow
        "statements-memory":   10,  # mem_write
        "statements-register": 6,   # trans_register
    }

    # API category -> column index (within columns 13-19)
    api_category_index = {
        "network":     13,
        "file":        14,
        "process":     15,
        "memory":      16,
        "system-info": 17,
        "crypto":      18,
        "threads":     19,
    }

    feature_vectors = []

    for (addr_str, insts_str, stmts_str,
         offspring_str, betweenness_str, apis_str) in matches:

        # 20 features: [address, offspring, betweenness, ...17 more...]
        features = np.zeros(20, dtype=np.float32)

        # ----------------------------------------------------------
        # Column 0: Raw address (decimal) - NOT normalized, used for
        #           ROC curve mapping only, stripped before training
        # ----------------------------------------------------------
        try:
            if addr_str.startswith('0x') or addr_str.startswith('0X'):
                features[0] = float(int(addr_str, 16))
            else:
                features[0] = float(int(addr_str))
        except ValueError:
            features[0] = 0.0

        # ----------------------------------------------------------
        # Columns 1-2: Structural features
        # ----------------------------------------------------------
        try:
            features[1] = float(offspring_str)
        except ValueError:
            features[1] = 0.0

        try:
            features[2] = float(betweenness_str)
        except ValueError:
            features[2] = 0.0

        # ----------------------------------------------------------
        # Columns 3-12: Instruction (IROp) features
        # ----------------------------------------------------------
        inst_tokens = [t.strip() for t in insts_str.split(';') if t.strip()]
        for token in inst_tokens:
            if token in inst_map:
                idx = inst_category_index.get(inst_map[token])
                if idx is not None:
                    features[idx] += 1

        # Fallback: explicit prefix matching for mem/fp/vector
        features[9]  += sum(1 for t in inst_tokens
                            if t.startswith("Iop_Load"))          # mem_read
        features[10] += sum(1 for t in inst_tokens
                            if t.startswith("Iop_Store"))         # mem_write
        features[11] += sum(1 for t in inst_tokens
                            if any(x in t
                                   for x in ["Iop_F", "F32", "F64"]))  # fp_ops
        features[12] += sum(1 for t in inst_tokens
                            if any(x in t
                                   for x in ["x4", "x8", "x16", "Vec"])) # vector

        # ----------------------------------------------------------
        # Statement features (mapped into same columns)
        # ----------------------------------------------------------
        stmt_tokens = [t.strip() for t in stmts_str.split(';') if t.strip()]
        for token in stmt_tokens:
            if token in inst_map:
                idx = stmt_category_index.get(inst_map[token])
                if idx is not None:
                    features[idx] += 1

        # ----------------------------------------------------------
        # Columns 13-19: API features
        # ----------------------------------------------------------
        api_tokens = [t.strip().lower() for t in apis_str.split(';')
                      if t.strip()]
        for token in api_tokens:
            # Internal/unknown calls -> control_flow
            if (token.startswith('call_0x') or
                    token.startswith('call_weak_fn') or
                    token in {'deregister_tm_clones', 'register_tm_clones',
                              '_init', '_fini'}):
                features[8] += 1  # control_flow
            elif token in api_map:
                idx = api_category_index.get(api_map[token])
                if idx is not None:
                    features[idx] += 1

        feature_vectors.append(features)

    return np.array(feature_vectors)  # shape: (num_blocks, 20)


# ======================================================
# NORMALIZATION - SKIPS COLUMN 0 (address)
# ======================================================
def normalize_features(feature_matrix):
    """
    Min-max normalize columns 1-19 only.
    Column 0 (address) is preserved as-is.

    Returns:
        normalized: same shape as input, col 0 unchanged
        stats: per-feature statistics dict
    """
    if feature_matrix.size == 0:
        return feature_matrix, {}

    normalized = np.zeros_like(feature_matrix)

    # Column 0: copy address unchanged
    normalized[:, 0] = feature_matrix[:, 0]

    stats = {}

    # Columns 1-19: normalize
    for i in range(1, feature_matrix.shape[1]):
        col = feature_matrix[:, i]
        col_max = np.max(col)

        if col_max > 0:
            normalized[:, i] = col / col_max
        else:
            normalized[:, i] = 0.0

        non_zero = int(np.count_nonzero(col))
        total = len(col)
        stats[FEATURE_NAMES[i]] = {
            'max':      float(col_max),
            'mean':     float(np.mean(col)),
            'std':      float(np.std(col)),
            'non_zero': non_zero,
            'sparsity': f"{non_zero / total * 100:.1f}%" if total > 0 else "0.0%"
        }

    return normalized, stats


# ======================================================
# STATISTICS DISPLAY
# ======================================================
def print_stats(overall_stats):
    print("\n=== DATASET STATISTICS (columns 1-19, excluding address) ===")
    print(f"{'Feature':<20} {'Max':>8} {'Mean':>8} {'Std':>8} "
          f"{'NonZero':>10} {'Sparsity':>10}")
    print("-" * 70)

    for feature in FEATURE_NAMES[1:]:   # skip "address"
        if feature in overall_stats and overall_stats[feature]:
            s = overall_stats[feature]
            max_v  = max(x['max']  for x in s)
            mean_v = np.mean([x['mean'] for x in s])
            std_v  = np.mean([x['std']  for x in s])
            nz_v   = max(x['non_zero'] for x in s)
            sp_v   = np.mean([float(x['sparsity'].rstrip('%')) for x in s])
            print(f"{feature:<20} {max_v:>8.3f} {mean_v:>8.3f} {std_v:>8.3f} "
                  f"{nz_v:>10} {sp_v:>9.1f}%")


# ======================================================
# BATCH PROCESSING
# ======================================================
def process_files_batch(inst_map, api_map):
    raw_files = glob.glob("*.txt")
    raw_files = [f for f in raw_files
                 if "train" not in f and "test" not in f]

    if not raw_files:
        print("[WARNING] No raw .txt files found in current directory")
        return 0, {}, []

    print(f"[BATCH] Processing {len(raw_files)} files...")

    processed_count = 0
    overall_stats   = defaultdict(list)
    file_shapes     = []

    for i, raw_file in enumerate(raw_files):
        if DEBUG:
            print(f"\n[{i+1}/{len(raw_files)}] {raw_file}")

        try:
            feature_matrix = parse_raw_file(raw_file, inst_map, api_map)

            if feature_matrix.size == 0:
                print(f"[SKIP] No features extracted from {raw_file}")
                continue

            normalized, stats = normalize_features(feature_matrix)

            out_name = os.path.splitext(os.path.basename(raw_file))[0] + ".npy"
            out_path = os.path.join(OUTPUT_DIR, out_name)
            np.save(out_path, normalized)

            for feat, stat in stats.items():
                overall_stats[feat].append(stat)

            file_shapes.append(normalized.shape)

            print(f"[SAVE] {out_path}  shape={normalized.shape}  "
                  f"(col0=address preserved)")

            if DEBUG:
                # Spot-check: print first block's address
                first_addr = int(normalized[0, 0])
                print(f"  First BB address: 0x{first_addr:x} ({first_addr})")
                nz = sum(s['non_zero'] for s in stats.values())
                print(f"  Non-zero feature entries: {nz}")

            processed_count += 1

        except Exception as e:
            print(f"[ERROR] {raw_file}: {e}")
            if DEBUG:
                import traceback
                traceback.print_exc()

    return processed_count, overall_stats, file_shapes


# ======================================================
# VERIFICATION
# ======================================================
def verify_output():
    """
    Check that all .npy files have correct shape and that
    column 0 looks like real addresses (large integers).
    """
    npy_dir = OUTPUT_DIR

    if not os.path.exists(npy_dir):
        print("❌ Output directory not found!")
        return False

    npy_files = [f for f in os.listdir(npy_dir) if f.endswith('.npy')]
    if not npy_files:
        print("❌ No .npy files found!")
        return False

    print("\n=== VERIFICATION ===")
    all_ok = True

    for nf in npy_files:
        path = os.path.join(npy_dir, nf)
        try:
            data = np.load(path)

            addr_col   = data[:, 0]
            feat_cols  = data[:, 1:]

            checks = {
                "Shape (N,20)":          data.shape[1] == 20,
                "Feat cols finite":      np.all(np.isfinite(feat_cols)),
                "Feat cols in [0,1]":    (np.all(feat_cols >= 0) and
                                          np.all(feat_cols <= 1)),
                "No NaN":                not np.any(np.isnan(data)),
                "Addresses look real":   addr_col.max() > 1000,  # sanity check
            }

            ok  = all(checks.values())
            sym = "✅" if ok else "❌"
            all_ok = all_ok and ok

            print(f"\n{sym} {nf}  shape={data.shape}")
            print(f"   Address range: 0x{int(addr_col.min()):x} "
                  f"– 0x{int(addr_col.max()):x}")
            for k, v in checks.items():
                print(f"   {'✅' if v else '❌'} {k}")

        except Exception as e:
            print(f"❌ ERROR loading {nf}: {e}")
            all_ok = False

    print("\n" + ("🎉 ALL OK" if all_ok else "⚠️  Issues found"))
    return all_ok


# ======================================================
# MAIN
# ======================================================
def main():
    print("=== DeepReflect VEX-IR Feature Converter ===")
    print("Output: 20 columns  (col0=address | cols1-19=features)")
    print("Note:   col0 is NOT normalized and NOT used in model training")
    print("        dr.py strips it automatically via bytez[:,1:]")
    print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    inst_map, api_map = load_feature_mappings()

    if not inst_map and not api_map:
        print("[ERROR] No feature mappings loaded. Check type/ directory.")
        return

    processed, overall_stats, file_shapes = process_files_batch(
        inst_map, api_map)

    print(f"\n{'='*50}")
    print(f"DONE: {processed} files processed")
    print(f"Output: {OUTPUT_DIR}/")

    if file_shapes:
        total_blocks = sum(s[0] for s in file_shapes)
        print(f"Total basic blocks: {total_blocks}")
        print(f"Average per file:   {total_blocks/len(file_shapes):.0f}")

    if overall_stats and DEBUG:
        print_stats(overall_stats)

    verify_output()


if __name__ == "__main__":
    main()
