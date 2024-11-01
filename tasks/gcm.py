#!/usr/bin/env python3

import base64


def gcm_sem(input):
    elem_bytes = base64.b64decode(input)
    byte_list = []
    
    for i in range(len(elem_bytes)):
        byte_list.append(elem_bytes[i])
    
    reversed_bytes = [reverse_bit(byte) for byte in byte_list]
    
    reversed_bytes_arr = bytes(reversed_bytes)
    return base64.b64encode(reversed_bytes_arr).decode('utf-8')

def reverse_bit(byte):
    result = 0
    for _ in range(8):
        result = (result << 1) | (byte & 1)
        byte >>= 1
    return result


