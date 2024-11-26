#!/usr/bin/env python3
import base64


def gfmul(element_1: str, element_2: str) -> str:
    """
    Perform Galois field multiplication of two elements given and represented
    as base64 strings.

    This function implements the multiplication in GF(2^128) using the irreducible polynomial
    defined in IRR_POLY. The reduction is performed bit by bit with reduction by the 
    irreducible polynomial when necessary.

    Args:
        element_1: First element, encoded in base64
        element_2: Second element, encoded in base64

    Returns:
        str: Result of the multiplication encoded in base64

    Notes:
        - Elements are interpreted as little endian
        - The irreducible polynomial is hardcoded, this may be subject to change
    """

    # Base64 encoded representation of x^128 + x^7 + x^2 + x + 1
    IRR_POLY = "hwAAAAAAAAAAAAAAAAAAAAE="
    
    # To be able to easily work with these values and do such things as bit shifts
    # we need to convert the base64 string to its byte representation and then into an integer
    multiplicant = int.from_bytes(base64.b64decode(element_1), byteorder='little')
    multiplier = int.from_bytes(base64.b64decode(element_2), byteorder='little')
    reduction_polynomial = int.from_bytes(base64.b64decode(IRR_POLY), byteorder='little')

    # We need to initialize our result
    product = 0

    # We handle the first bit of the loop outside
    if multiplier & 1:
        product^=multiplicant
    multiplier>>=1

    # Main multiplication loop
    for _ in range(127):    
        # Left shift as equivalent of multiplication by x
        multiplicant<<=1

        # Reduction of the polynomial if it becomes too large
        if multiplicant.bit_length()>=129:
            multiplicant ^= reduction_polynomial
       
        # Add to result if the corresponding bit in second element is 1 
        if multiplier & 1:
            product ^= multiplicant
        
        # Right shift to process next bit
        multiplier >>= 1
    
    # Convert the result back to base64
    product_bytes = product.to_bytes(16, byteorder = 'little')
    return base64.b64encode(product_bytes).decode()

