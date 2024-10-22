#!/usr/bin/env python3

from tasks.poly import block2poly, poly2block
import json

class parse_json:
    def __init__(self, filename):
        self.filename = filename

    def parse(self):
        with open(self.filename, 'r') as file:
            data = json.load(file)
            if data["action"] == "poly2block": 
                coefficients = data["arguments"]["coefficients"]
                p2b = poly2block(coefficients)
                block = p2b.p2b()
                print(block)
            elif data["action"] == "block2poly":
                b2p = block2poly(data["arguments"]["block"])  # Assuming the block is under "arguments"
                poly = b2p.b2p()
                print(poly)



