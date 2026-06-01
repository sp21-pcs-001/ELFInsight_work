import numpy as np

m = np.load("/home/firmfuzz/Desktop/deepreflect_elf_vex_ablation/autoencoder/normalize_elf_benign_1june2026_no_inst.npy")

print("Total features:", len(m))
print("Zero-max features:", np.sum(m == 0))

print("\nIndices with zero max:")
print(np.where(m == 0)[0])

print("\nNormalization vector:")
print(m)
