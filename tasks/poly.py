#!/usr/bin/env python3
import base64


class poly2block:
    def __init__(self, coefficients: list):
        self.coefficients = coefficients
    def p2b(self):
        uint_128 = 0
        for x in self.coefficients:
         uint_128 ^= (1 << x)
        byte_arr = uint_128.to_bytes(16, byteorder='little')
        b64_enc = base64.b64encode(byte_arr).decode('utf-8')
        return b64_enc


class block2poly:
    def __init__(self,block: str):
        self.block = block
    def b2p(self):
        byte_arr = base64.b64decode(self.block)
        uint = int.from_bytes(byte_arr, byteorder='little')
        coefficients = []
        for i in range (0,128):
            if uint & (1<<i):
                coefficients.append(i)
        return coefficients

def reverse_bit(byte):
    result = 0
    for _ in range(8):
        result = (result << 1) | (byte & 1)
        byte >>= 1
    return result

def gcm_sem(byte):
        # Padd the the base64 string if necessary
        while len(byte) % 4 != 0:
            byte += '='
        elem_bytes = base64.b64decode(byte)
        byte_list = []
        
        for i in range(len(elem_bytes)):
            byte_list.append(elem_bytes[i])
        # Reverse bits in each byte
        reversed_bytes = [reverse_bit(byte) for byte in byte_list]
    
        reversed_bytes_arr = bytes(reversed_bytes)
        return base64.b64encode(reversed_bytes_arr).decode('utf-8')
    


def poly2block_gcm(input):
    p2b_instance = poly2block(input)
    poly = p2b_instance.p2b()
    poly_gcm = gcm_sem(poly)
    return poly_gcm
def block2poly_gcm(input):
    gcm_poly = gcm_sem(input)
    b2p_instance = block2poly(gcm_poly)
    return b2p_instance.b2p()
