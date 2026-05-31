import numpy as np

# Load feature file (contains basic block addresses in first column)
feat = np.load("/home/firmfuzz/Desktop/deepreflect_elf_vex_ablation/grader/malware/rbot/output/rbot_feature.npy")
bb_addrs = feat[:, 0].astype(int)
print("Unique basic block addresses in feature file (first 10):", np.unique(bb_addrs)[:10])

# Load function mapping file (parse manually)
func_map = {}
with open("/home/firmfuzz/Desktop/deepreflect_elf_vex_ablation/grader/malware/rbot/rbot_function.txt", 'r') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 2:
            func_addr = int(parts[0])   # decimal
            bb_addr = int(parts[1])
            func_map[bb_addr] = func_addr

# Check if any basic block address from feature is a key in func_map
matches = [addr for addr in bb_addrs if addr in func_map]
print(f"Number of basic block addresses that match function mapping: {len(matches)}")
if len(matches) == 0:
    print("❌ No match! Address spaces are incompatible.")
    print("Example feature address:", bb_addrs[0])
    print("Example function mapping key (first few):", list(func_map.keys())[:5])
