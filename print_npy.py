import numpy as np
data = np.load('/home/firmfuzz/Documents/ablation_24may26/elf_benign_1_raw_ab/features_npy/72a685d768b60e078385813209140879_raw.npy')
print(data[0, :10])  # Look at first few columns
