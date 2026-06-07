ELFInsight is based on the DeepReflect project. We extended the work for IoT platforms such as ARM and MIPS binaries and further we implemented it on the Intermeidated Representation (IR) using (Angr-VEX) tool for the both architectures.

All information related to Cross architecture work for IoT's ELF binaries
Steps
1. Dataset collection
2. RAW feature extraction using VEX-IR and for specific Assemblies Architectures (like ARM)
3. Converstion to NPY Format
4. AE model training (changes int he DR model with respect to VEX-IR and ARM/MIPS feature sets)
5. Generation of MSE scores and validation of Results
   
Last updated: 25Dec2025

Link to Download Codes: 
https://drive.google.com/file/d/1X4eHw1_AKdkKGkIo6lJNhT8oR-wmDzHa/view?usp=drive_link
