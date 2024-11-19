#!/usr/bin/env python3
import base64


from common.common import stderr_write





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
    def sqrt(self):
        base = self
        result = FieldElement(0)
        exponent = (1 << 127)
        
        res = int(FieldElement(1))
        result = FieldElement(self.gcm_sem(res))
        while exponent > 0:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        return result   

    def __int__(self):
        return self.element

class Polynom:
    def __init__(self, polynomials: list):
        self.polynomials = polynomials
        self.polynomials_int = self._base64poly_to_int()
        self.polynomials_int_gcm = self._base64poly_to_int_gcm()
    def _base64poly_to_int_gcm(self):
        integer_list = []
        field_element = FieldElement(0)  # Create a FieldElement instance to use gcm_sem
    
        for b46str in self.polynomials:
            bytes_val = base64.b64decode(b46str)
            int_val = int.from_bytes(bytes_val, 'little')
            # Convert to GCM semantic using the FieldElement's gcm_sem method
            gcm_val = field_element.gcm_sem(int_val)
            integer_list.append(gcm_val)
        return integer_list
    
    def _base64poly_to_int(self):
        integer_list = []
        for b46str in self.polynomials:
            bytes = base64.b64decode(b46str)
            integer_list.append(int.from_bytes(bytes, 'little'))
        return integer_list

    def _normalize(self):
        # Only remove trailing zeros, not leading zeros
        while self.polynomials_int and self.polynomials_int[-1] == 0:
            self.polynomials_int.pop()  # Remove trailing zeros
        self.polynomials = [
            base64.b64encode(int.to_bytes(val, 16, "little")).decode()
            for val in self.polynomials_int
        ]

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
        result = Polynom(
            [base64.b64encode(int.to_bytes(res, 16, "little")).decode() for res in result_poly]
        )
        result._normalize()
        return result    

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

    def __truediv__(self, divisor):
        # Check for division by zero
        if divisor.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]:
            return Polynom(["AAAAAAAAAAAAAAAAAAAAAA=="]), self
            
        # If dividend is zero, return zero
        if len(self.polynomials_int) == 0 or (len(self.polynomials_int) == 1 and self.polynomials_int[0] == 0):
            return (
                Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()]),
                Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])
            )
        
        # Create a copy of the dividend
        remainder = Polynom(self.polynomials.copy())
        remainder.polynomials_int = self.polynomials_int.copy()
        
        # Get the degrees
        dividend_degree = len(self.polynomials_int) - 1
        divisor_degree = len(divisor.polynomials_int) - 1
        
        # If dividend degree is less than divisor degree, quotient is 0 and remainder is dividend
        if dividend_degree < divisor_degree:
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()]), remainder
        
        # Initialize quotient coefficients with zeros
        quotient_coeffs = [0] * (dividend_degree - divisor_degree + 1)
        
        # Create working copy to preserve zero coefficients
        work_remainder = remainder.polynomials_int.copy()
        
        # Continue as there arre emough terms
        while len(work_remainder) >= len(divisor.polynomials_int):
            # Skip if leading coefficient is zero
            if work_remainder[-1] == 0:
                work_remainder.pop()
                continue
                
            # Calculate degrees for current step
            curr_remainder_degree = len(work_remainder) - 1
            curr_divisor_degree = len(divisor.polynomials_int) - 1
            
            # Calculate quotient coefficient
            lead_remainder = FieldElement(work_remainder[-1])
            lead_divisor = FieldElement(divisor.polynomials_int[-1])
            curr_quotient = lead_remainder / lead_divisor
            
            # Store quotient coefficient
            pos = curr_remainder_degree - curr_divisor_degree
            quotient_coeffs[pos] = int(curr_quotient)
            
            # Create subtrahend with preserved zeros
            subtrahend_coeffs = [0] * pos
            for coeff in divisor.polynomials_int:
                mult_result = int(FieldElement(coeff) * curr_quotient)
                subtrahend_coeffs.append(mult_result)
                
            # Ensure subtrahend and work_remainder have same length
            while len(subtrahend_coeffs) < len(work_remainder):
                subtrahend_coeffs.insert(0, 0)
                
            # Subtract (XOR) term by term
            for i in range(len(work_remainder)):
                work_remainder[i] ^= subtrahend_coeffs[i]
                
            # Remove leading zero while preserving internal zeros
            while work_remainder and work_remainder[-1] == 0:
                work_remainder.pop()
        
        # Create remainder polynomial preserving zero coefficients
        remainder = Polynom([
            base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode()
            for coeff in work_remainder
        ])
        
        # Create quotient polynomial
        quotient = Polynom([
            base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode()
            for coeff in quotient_coeffs
        ])
        if remainder.polynomials ==[]:
            remainder = Polynom(["AAAAAAAAAAAAAAAAAAAAAA=="])
        return quotient, remainder

    def poly_powmod(self, modulus, exponent):

        if exponent == 0:
            return Polynom(["gAAAAAAAAAAAAAAAAAAAAA=="])
            
        if exponent == 1:
            result, remainder = self / modulus
            return remainder
            
        result = Polynom(["gAAAAAAAAAAAAAAAAAAAAA=="])
        base = self
        
        _, base = base / modulus
        
        while exponent > 0:
            if exponent & 1:
                result = result * base
                _, result = result / modulus
                
            base = base * base
            _, base = base / modulus
                
            exponent >>= 1
            
        return result
    def gfpoly_sort(self, *others):
        all_poly = [self] + list(others)
        
        def compare_polys(poly):
            # We need degree as primary sorting factor
            key = []
            key.append(len(poly.polynomials_int_gcm) - 1)
            
            for item in poly.polynomials_int_gcm[::-1]:
                key.append(item)
            key_tuple = tuple(key)
            
            # Pack our values into a tuple and let python handle the rest 
            return key_tuple
        # Sort our polynomials based on all criteria
        sorted_polys = sorted(all_poly, key=compare_polys)
        return sorted_polys

    def gfpoly_makemonic(self):
        highest_coefficient = FieldElement(self.polynomials_int[-1])
        new_poly = []
        for coeff in self.polynomials_int :
            coeff = FieldElement(coeff)
            res = coeff / highest_coefficient
            new_poly.append(res.element)

        result_poly = [base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode() for coeff in new_poly] 
        return result_poly
    def sqrt(self):
        result = []
        for degree, coeff in enumerate(self.polynomials_int):
            if (degree+1)%2:
                coeff_fe = FieldElement(coeff)
                sqrt_coeff = coeff_fe.sqrt()
                result.append(sqrt_coeff.element)

        result_poly = Polynom([base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode() for coeff in result])
        return result_poly
