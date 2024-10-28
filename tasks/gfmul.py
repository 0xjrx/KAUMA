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
    # print(len(byte_arr1))  -> 16
    result = 0
    x = 1 
    if uint2 & 1:
        result^=uint1
    uint2>>=1
    for _ in range((len(byte_arr2)*8)-1):
        uint1<<=1
        #print(f"uint1 after {x} try: {uint1.bit_length()}")
        #print(uint1.bit_length())
        if uint1.bit_length()>=129:
            uint1 ^= poly
        #print(uint1.bit_length())
        if uint2 & 1:
            result ^= uint1
            #print(result.bit_length())
        uint2 >>= 1
        #print(uint1.bit_length())
    #print(result.bit_length())
    byte_arr_res = result.to_bytes(16, byteorder = 'little')
    res = base64.b64encode(byte_arr_res).decode('ascii')
    #print(result.bit_length())
    return(res)
