#!/usr/bin/env python3
import base64




def poly2block(coefficients: list)->str:
    uint_128 = sum(1<<x for x in coefficients)
    byte_arr = uint_128.to_bytes(16, byteorder='little')
    return base64.b64encode(byte_arr).decode('utf-8')

def block2poly(block: str)-> list:
    byte_arr = base64.b64decode(block)
    uint = int.from_bytes(byte_arr, byteorder='little')
    return [i for i in range(128)if uint & (1<<i)]

BIT_REVERSE_TABLE = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]


def poly2block_gcm(coefficients: list) -> str:
    uint_128 = sum(1 << x for x in coefficients)
    byte_arr = uint_128.to_bytes(16, byteorder='little')
    reversed_bytes = bytes(BIT_REVERSE_TABLE[b] for b in byte_arr)
    return base64.b64encode(reversed_bytes).decode('utf-8')


def block2poly_gcm(block: str) -> list:
    byte_arr = base64.b64decode(block)
    reversed_bytes = bytes(BIT_REVERSE_TABLE[b] for b in byte_arr)
    uint = int.from_bytes(reversed_bytes, byteorder='little')
    return [i for i in range(128) if uint & (1 << i)]
