import numpy as np

# Path to your feature .npy file (the one used as input to mse.py)
npy_path = "/home/firmfuzz/Desktop/deepreflect_elf_vex_ablation/grader/malware/rbot/output/rbot_feature.npy"

data = np.load(npy_path)
print("Shape of .npy file:", data.shape)
print("First 10 rows (first 5 columns):")
for i in range(min(10, data.shape[0])):
    print(data[i, :5])

# Check unique values in first column (assumed to be addresses)
unique_first = np.unique(data[:, 0])
print("\nUnique values in first column (first 20):", unique_first[:20])
print("Number of unique addresses:", len(unique_first))
