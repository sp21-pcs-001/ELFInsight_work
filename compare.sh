#!/bin/bash

# --- Configuration ---
BIN_DIR="/home/firmfuzz/Downloads/caimp/extracted"        # Folder containing your binary files
HASH_DIR="/home/firmfuzz/Downloads/caimp/ASM_EXTRACTED_MIPS/"      # Folder containing the .asm files

# --- Execution ---
echo "Starting MD5 comparison..."
echo "-----------------------------------------------"

for file_path in "$BIN_DIR"/*; do
    # Skip if it's a directory
    
    [ -e "$file_path" ] || continue
    [ -d "$file_path" ] && continue

    # Get the filename only (e.g., "program.bin")
    filename=$(basename "$file_path")
    
    # Define the expected checksum file name (e.g., "program.bin.asm")
    # Adjust the suffix if your files are named differently (e.g., "${filename}.asm")
    checksum_file="$HASH_DIR/${filename}.asm"

    if [ ! -f "$checksum_file" ]; then
        echo "[ SKIP ] No checksum file found for: $filename"
        continue
    fi

    # Generate current MD5 (extracts only the hash part)
    current_md5=$(md5sum "$file_path" | awk '{print $1}')

    # Read the expected MD5 from the .asm file (extracts first word/string)
    expected_md5=$(cat "$checksum_file" | awk '{print $1}')

    # Compare
    if [ "$current_md5" = "$expected_md5" ]; then
        echo "[  OK  ] $filename matches."
    else
        echo "[ FAIL ] $filename does NOT match!"
        echo "         Found:    $current_md5"
        echo "         Expected: $expected_md5"
    fi
done

echo "-----------------------------------------------"
echo "Check complete."

