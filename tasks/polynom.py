#!/usr/bin/env python3
import base64






class FieldElement:
    """
    Represents a field element for its base64 representation.

    This class provides arithmetic operations (addition and multiplication)
    for field elements, with automatic modular reduction using GCM's
    irreducible polynomial.
    """
    def __init__(self, element: int):
        """
        Initialize a field element from an integer

        Args:
            element: int representing the field element
        """
        self.element = element    
    
    def reverse_bit(self,byte: bytes) -> int:
        """
        Reverses the bits of a given byte.

        This is required for GCM's bit representation in Galois Field operations, which differ from 
        the standard representation.

        Args:
            byte: Single byte to reverse

        Returns:
            Integer representing the byte with reversed bit order
        """
        result = 0
        for _ in range(8):
            result = (result << 1) | (byte[0] & 1)
            byte = bytes([byte[0] >> 1])
        return result
    def gcm_sem(self, element) -> int:
        """ 
        Transform a field element to GCM's semantic.

        Performs bit reversal on individual bytes as required by GCM's
        field arithmetic implementation

        Args:
            element: Field element as int

        Returns:
            transformed element
        """
        # Pad the the base64 string if necessary
        element = element.to_bytes(16, 'little') 
        reversed_bytes = [self.reverse_bit(bytes([byte])) for byte in element]
        reversed_bytes_arr = bytes(reversed_bytes)
        return int.from_bytes(reversed_bytes_arr, 'little')
    
    def __mul__(self, other):
        """
        Multiply two field elements in GF(2^128).

        Implements russian peasant multiplication algorithm with
        modular reduction using GCM's irreducible polynomial.

        Args:
            other: Another field element instance

        Returns:
            New FieldElementGCM instance representing the product of the multiplication
        """
        # irreducible polynomial for GF(2^128)
        IRR_POLY = b"hwAAAAAAAAAAAAAAAAAAAAE="
    
        # Convert our operants to GCM's semantic
        multiplicant = self.gcm_sem(int(self))
        
        multiplier = self.gcm_sem(int(other))
        
        # Convert the reduction polynomial
        poly_bytes = base64.b64decode(IRR_POLY)
        reduction_polynomial = int.from_bytes(poly_bytes, byteorder='little')

        product = 0

        # We handle the first bit of the loop outside
        if multiplier & 1:
            product ^= multiplicant
        multiplier >>= 1

        # Main multiplication loop
        for _ in range((multiplier.bit_length() * 8) - 1):    
            # Left shift as equivalent of multiplication by x
            multiplicant <<= 1

            # Reduction of the polynomial if it becomes too large
            if multiplicant.bit_length() >= 129:
                multiplicant ^= reduction_polynomial
        
            # Add to result if the corresponding bit in second element is 1 
            if multiplier & 1:
                product ^= multiplicant
            
            # Right shift to process next bit
            multiplier >>= 1
        
        # Convert the result back to normal semantic
        gcm_encoded_product = self.gcm_sem(product)
        return FieldElement(gcm_encoded_product)
    
    def __add__(self, other: 'FieldElement'):
        xor = int(self) ^ int(other)    
        return FieldElement(xor)
        
    def _sqmul(self, divisor):
        base = divisor
        
        exponent = (1 << 128) - 2
        
        res = int(FieldElement(1))
        result = FieldElement(self.gcm_sem(res))
        while exponent > 0:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        
        return result
    
    def __truediv__(self, other):
        if int(other) == 0:
            raise ValueError("Division by zero")
        dividend = self 
        inverse = self._sqmul(other)
        result = dividend * inverse
        return result

    def __int__(self):
        return self.element

class Polynom:
    def __init__(self, polynomials: list):
        self.polynomials = polynomials
        self.polynomials_int = self._base64poly_to_int()

    def _base64poly_to_int(self):
        integer_list = []
        for b46str in self.polynomials:
            bytes = base64.b64decode(b46str)
            integer_list.append(int.from_bytes(bytes, 'little'))
        return integer_list
    
    def __add__(self, other):
        if self.polynomials == other.polynomials:
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])
        if self.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]:
            return other
        if other.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]:
            return self
        max_len = max(len(self.polynomials_int), len(other.polynomials_int))
        self_int = self.polynomials_int + [0] * (max_len - len(self.polynomials_int))
        other_int = other.polynomials_int + [0] * (max_len - len(other.polynomials_int))

        result_poly = [s ^ o for s, o in zip(self_int, other_int)]        
        return Polynom([base64.b64encode(int.to_bytes(res, 16, 'little')).decode() for res in result_poly])
    
    def __mul__(self, other):
        result_poly = [0] * (len(self.polynomials_int) + len(other.polynomials_int) - 1)
        if self.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]:
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])
        if other.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]:
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])

        for i, a in enumerate(self.polynomials_int):
            for j,b in enumerate(other.polynomials_int):
                fe_a = FieldElement(a)
                fe_b = FieldElement(b)
                result_poly[i+j] ^= (fe_a * fe_b).element
        return Polynom([base64.b64encode(int.to_bytes(res, 16, 'little')).decode() for res in result_poly])
    
    def __pow__(self, exponent):
        if exponent ==0:
            neutral_field_element = FieldElement(1)
            gcm_semantic_neutral = neutral_field_element.gcm_sem(neutral_field_element.element)
            neutral_polynom = Polynom([base64.b64encode(int.to_bytes(gcm_semantic_neutral, 16, 'little')).decode()])
            return neutral_polynom
        if exponent ==1:
            return self
        
        base = self
        result = base
        exponent -=1
        while exponent>0:
            result = result * base
            exponent -=1
        return result
     
    def display_polys(self):
        print(self.polynomials)
