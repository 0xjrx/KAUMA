#!/usr/bin/env python3
class Helper:
    def __init__(self, block1, block2):
        self.block1 = block1
        self.block2 = block2
    def xor_buf(self, block1, block2):
        return bytes(a ^ b for a, b in zip(block1, block2))
