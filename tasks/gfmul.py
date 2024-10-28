#!/usr/bin/env python3
import base64


def gfmul(element_1: str, element_2: str):
    irr_poly = "hwAAAAAAAAAAAAAAAAAAAAE="      
    byte_arr1 = base64.b64decode(element_1)
    uint1 = int.from_bytes(byte_arr1, byteorder = 'little')
    byte_arr2 = base64.b64decode(element_2)
    uint2 = int.from_bytes(byte_arr2, byteorder = 'little')
    byte_arr_poly = base64.b64decode(irr_poly)
    poly = int.from_bytes(byte_arr_poly, byteorder = 'little')
    result = 0
    if uint2 & 1:
        result^=uint1
    uint2>>=1
    for _ in range((len(byte_arr2)*8)-1):
        uint1<<=1
        if uint1.bit_length()>=129:
            uint1 ^= poly
        if uint2 & 1:
            result ^= uint1
        uint2 >>= 1
    byte_arr_res = result.to_bytes(16, byteorder = 'little')
    res = base64.b64encode(byte_arr_res).decode('ascii')
    return(res)
