#!/bin/bash
# Test benign exe files and count matches
for file in ./benign/binaries/*.exe; do
    echo "Testing: $(basename "$file")"
    yara malware_detection.yar "$file"
done
