#!/bin/bash

# --- Configuration ---
BIN_DIR="/home/firmfuzz/Downloads/caimp/extracted"
HASH_DIR="/home/firmfuzz/Downloads/caimp/ASM_EXTRACTED_MIPS"

# --- Execution ---
echo "Starting MD5 Lookup comparison..."
echo "-----------------------------------------------"

for file_path in "$BIN_DIR"/*; do
    # Skip if it's a directory or doesn't exist
    [ -e "$file_path" ] || continue
    [ -d "$file_path" ] && continue

    # Get the filename for display
    filename=$(basename "$file_path")
    
    # 1. Calculate the MD5 of the current binary
    current_md5=$(md5sum "$file_path" | awk '{print $1}')

    # 2. Construct the expected path: HASH_DIR/hash.asm
    # Based on your example: .../ASM_EXTRACTED_MIPS/75cda1bc0ed9dd98b792b7b9ab33a2e9.asm
    expected_asm_file="$HASH_DIR/${current_md5}.asm"

    # 3. Check if that specific MD5-named file exists
    if [ -f "$expected_asm_file" ]; then
        echo "[  OK  ] Found ASM for $filename ($current_md5)"
        mv "/home/firmfuzz/Downloads/caimp/extracted/$filename" "/home/firmfuzz/Downloads/caimp/extracted_1/"
    else
        echo "[ MISS ] No ASM file matches MD5 of: $filename"
        echo "         Hash looked for: $current_md5"
    fi
done

echo "-----------------------------------------------"
echo "Check complete."

