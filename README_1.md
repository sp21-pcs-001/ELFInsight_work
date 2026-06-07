ELFInsight is based on the DeepReflect project. We extended the work for IoT platforms such as ARM and MIPS binaries and further we implemented it on the Intermeidated Representation (IR) using (Angr-VEX) tool for the both architectures.

Flow of the implementation. 
-----------------------------
1-a. Complete Training and validation of the DR work using provided material by the Author. We successfully produced the results and also performed more test on our new samples.
1-b. Implementation of the DR work using our own Dataset (collection of benign windows PE files and) featrue extractions script using IDA Pro (IDAPython scripts and networkx). Because free "Binary Ninja" version does not support python scripts. We developed our own scripts to perform raw features extraction, conversion into NPY format and finally extraction of the basic blocks/functions. We used our developed IDAPython scripts for Windows (PE for x86) and Linux (ELF for x86, ARM and MIPS) binaries.     


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
