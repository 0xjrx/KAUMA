#!/usr/bin/env python3
import base64

def gfmul(element_1: str, element_2: str, irr_poly: str):
    """
    Fixed multiplication in GF(2^128)
    """
    byte_arr1 = base64.b64decode(element_1)
    uint1 = int.from_bytes(byte_arr1, byteorder='little')
    byte_arr2 = base64.b64decode(element_2)
    uint2 = int.from_bytes(byte_arr2, byteorder='little')
    byte_arr_poly = base64.b64decode(irr_poly)
    poly = int.from_bytes(byte_arr_poly, byteorder='little')
    
    field_size = len(byte_arr1) * 8
    mask = (1 << field_size) - 1  # Create mask for the field size
    
    result = 0
    temp = uint1
    
    for _ in range(field_size):
        if uint2 & 1:
            result ^= temp
        
        carry = temp & (1 << (field_size - 1))  # Check highest bit
        temp = (temp << 1) & mask  # Keep temp within bounds
        
        if carry:
            temp ^= poly
            
        uint2 >>= 1
        if uint2 == 0:
            break
    
    result &= mask  # Ensure final result is within bounds
    byte_arr_res = result.to_bytes(len(byte_arr1), byteorder='little')
    return base64.b64encode(byte_arr_res).decode('utf-8')

# Test values
a = "ARIAAAAAAAAAAAAAAAAAgA=="
b = "AgAAAAAAAAAAAAAAAAAAAA=="
irr_poly = "AgAAAAAAAAAAAAAAAAAAAA=="

res = gfmul(a, b, irr_poly)
print(f"Result: {res}")

def print_binary(base64_str):
    bytes_val = base64.b64decode(base64_str)
    int_val = int.from_bytes(bytes_val, byteorder='little')
    binary = bin(int_val)[2:].zfill(len(bytes_val) * 8)
    print(binary)
    return binary

print("\nBinary representations:")
print("a:   ", end="")
a_bin = print_binary(a)
print("b:   ", end="")
b_bin = print_binary(b)
print("res: ", end="")
res_bin = print_binary(res)
