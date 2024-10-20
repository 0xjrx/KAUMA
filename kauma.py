#!/usr/bin/env python3

from tasks.poly import block2poly, poly2block


coefficients = [12, 127, 9, 0]
p2b = poly2block(coefficients)
block = p2b.p2b()
print(block)
b2p = block2poly(block)
poly=b2p.b2p()
print(poly)


