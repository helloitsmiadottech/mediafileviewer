#!/usr/bin/env python3
"""
Create simple PNG icon files without external dependencies
Author: mia
"""

import struct
import zlib

def create_simple_png(width, height, r, g, b):
    """Create a minimal valid PNG file with solid color"""
    def write_chunk(data, chunk_type):
        crc = zlib.crc32(chunk_type + data) & 0xffffffff
        return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)
    
    # PNG signature
    png = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    png += write_chunk(ihdr_data, b'IHDR')
    
    # Create image data (RGB, one row at a time)
    row_data = bytes([r, g, b] * width)
    # Add filter byte (0 = none) at start of each row
    image_data = b''
    for _ in range(height):
        image_data += b'\x00' + row_data
    
    # Compress image data
    compressed = zlib.compress(image_data, level=9)
    png += write_chunk(compressed, b'IDAT')
    
    # IEND chunk
    png += write_chunk(b'', b'IEND')
    
    return png

def create_gradient_png(width, height):
    """Create a gradient PNG (purple to violet)"""
    def write_chunk(data, chunk_type):
        crc = zlib.crc32(chunk_type + data) & 0xffffffff
        return struct.pack('>I', len(data)) + chunk_type + data + struct.pack('>I', crc)
    
    # PNG signature
    png = b'\x89PNG\r\n\x1a\n'
    
    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    png += write_chunk(ihdr_data, b'IHDR')
    
    # Create gradient image data
    image_data = b''
    for y in range(height):
        ratio = y / height
        # Gradient from #667eea (102, 126, 234) to #764ba2 (118, 75, 162)
        r = int(102 + (118 - 102) * ratio)
        g = int(126 + (75 - 126) * ratio)
        b = int(234 + (162 - 234) * ratio)
        row = bytes([r, g, b] * width)
        image_data += b'\x00' + row  # Filter byte + row data
    
    # Compress image data
    compressed = zlib.compress(image_data, level=9)
    png += write_chunk(compressed, b'IDAT')
    
    # IEND chunk
    png += write_chunk(b'', b'IEND')
    
    return png

def main():
    sizes = [16, 48, 128]
    
    for size in sizes:
        # Create gradient icon
        png_data = create_gradient_png(size, size)
        filename = f'icon{size}.png'
        with open(filename, 'wb') as f:
            f.write(png_data)
        print(f'Created {filename} ({size}x{size})')
    
    print("\nAll icons created successfully!")

if __name__ == '__main__':
    main()
