#!/usr/bin/env python3
"""
Compression Level Tuning Script
This script helps you find the best compression level to achieve ~70% compression ratio.
Run this on your data.txt file before running the actual server/client.
"""

import zlib
import sys

def test_compression_levels(filename):
    """Test different compression levels and report their ratios."""
    
    try:
        with open(filename, 'rb') as f:
            original_data = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    
    original_size = len(original_data)
    print(f"Original file: {filename}")
    print(f"Original size: {original_size} bytes ({original_size/1024:.2f} KB)")
    print(f"\nTarget: ~70% compression ratio (compressed size = 70% of original)\n")
    print("=" * 70)
    print(f"{'Level':<8} {'Compressed Size':<18} {'Ratio':<10} {'Reduction':<12} {'Target?'}")
    print("=" * 70)
    
    best_level = 1
    best_diff = float('inf')
    target_ratio = 70.0
    
    for level in range(0, 10):  # zlib levels 0-9
        compressed = zlib.compress(original_data, level=level)
        compressed_size = len(compressed)
        ratio = (compressed_size / original_size) * 100
        reduction = 100 - ratio
        diff = abs(ratio - target_ratio)
        
        is_target = "  ✓ BEST" if diff < best_diff else ""
        if diff < best_diff:
            best_diff = diff
            best_level = level
        
        print(f"{level:<8} {compressed_size:<10} bytes  {ratio:>5.2f}%    {reduction:>5.2f}%       {is_target}")
    
    print("=" * 70)
    print(f"\nRECOMMENDATION:")
    print(f"  Use compression level {best_level} for closest to 70% ratio")
    
    # Test the recommended level
    compressed = zlib.compress(original_data, level=best_level)
    compressed_size = len(compressed)
    ratio = (compressed_size / original_size) * 100
    
    print(f"\nWith level {best_level}:")
    print(f"  Original:   {original_size} bytes")
    print(f"  Compressed: {compressed_size} bytes")
    print(f"  Ratio:      {ratio:.2f}%")
    print(f"  Saved:      {original_size - compressed_size} bytes ({100-ratio:.2f}% reduction)")
    
    # Verify decompression works
    try:
        decompressed = zlib.decompress(compressed)
        if decompressed == original_data:
            print(f"\n✓ Decompression test: SUCCESS (data intact)")
        else:
            print(f"\n✗ Decompression test: FAILED (data corruption!)")
    except Exception as e:
        print(f"\n✗ Decompression test: FAILED ({e})")
    
    return best_level

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 test_compression.py <filename>")
        print("Example: python3 test_compression.py data.txt")
        sys.exit(1)
    
    filename = sys.argv[1]
    recommended_level = test_compression_levels(filename)
    
    print(f"\nTo use this in your code, set:")
    print(f"  COMPRESSION_LEVEL = {recommended_level}")