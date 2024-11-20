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
        """
        This function adds to FieldElements. Addititon in GF2^128 is defined as XOR.

        Args:
            self: Instance of a field element
            other: Another instance of a field element
        Returns:
            FieldElement(xor): The result of the addition as a field element instance
        """
        xor = int(self) ^ int(other)    
        return FieldElement(xor)
        
    def invert(self, divisor):
        """
        This function calculates the inverse of a FielElement instance
        through exponentiation by 2^128 -2
        
        """
        base = divisor
        # Set the exponent
        exponent = (1 << 128) - 2
        
        # Set our result 
        res = int(FieldElement(1))
        result = FieldElement(self.gcm_sem(res))
        
        # Use square multiply
        while exponent > 0:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        
        return result
    
    def __truediv__(self, other):
        """
        Divides a FieldElement by another FieldElement using inversion
        as the division is multiplication by the inverted element.
        """

        if int(other) == 0:
            raise ValueError("Division by zero")
        dividend = self 
        inverse = self.invert(other)
        result = dividend * inverse
        return result
    
    def sqrt(self):
        """
        Calculates the squareroot of a FieldElement. In GF2^128 the sqrt is defined as
        the FieldElement^2^m-1, whith m as the order of the field, so 128
        """
        base = self
        result = FieldElement(0)
        exponent = (1 << 127)
        
        res = int(FieldElement(1))
        result = FieldElement(self.gcm_sem(res))
        
        # Take the FieldElement to the power of 2^127
        while exponent > 0:
            if exponent & 1:
                result = result * base
            base = base * base
            exponent >>= 1
        return result   

    def __int__(self):
        return self.element

class Polynom:
    """
    Represents polynomials over GF(2^128) with coefficients encoded in base64.
    
    This class implements polynomial arithmetic operations where each coefficient
    is a field element in GF(2^128). The polynomials are represented as lists
    of base64-encoded coefficients, where each coefficient is a 16-byte value.
    
    The class supports standard polynomial operations including addition,
    multiplication, division, and modular exponentiation, all performed
    according to finite field arithmetic rules.
    """

    def __init__(self, polynomials: list):
        """
        Initialize a polynomial from a list of base64-encoded coefficients.
        
        Args:
            polynomials: List of base64 strings representing coefficients
        """
        self.polynomials = polynomials
        # Store coefficients as integers for efficient computation
        self.polynomials_int = self._base64poly_to_int()
        # Store coefficients as integers in converted from gcm semantic
        self.polynomials_int_gcm = self._base64poly_to_int_gcm()
    def _base64poly_to_int_gcm(self):
        """
        Convert base64-encoded coefficients to integers in GCM semantic.
        
        Transforms each coefficient into the bit representation required
        for GCM's field arithmetic implementation.
        
        Returns:
            List of integers representing coefficients in GCM semantic
        """
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
        """
        Convert base64-encoded coefficients to integers.
        
        Returns:
            List of integers representing polynomial coefficients
        """
        integer_list = []
        for b46str in self.polynomials:
            bytes = base64.b64decode(b46str)
            integer_list.append(int.from_bytes(bytes, 'little'))
        return integer_list

    def _normalize(self):
        """
        Remove trailing zero coefficients from the polynomial.
        
        Updates both the integer and base64 representations of the polynomial.
        Preserves leading zeros as they represent significant terms.
        """
        while self.polynomials_int and self.polynomials_int[-1] == 0:
            self.polynomials_int.pop()
        self.polynomials = [
            base64.b64encode(int.to_bytes(val, 16, "little")).decode()
            for val in self.polynomials_int
        ]

    def __add__(self, other):
        """
        Add two polynomials in GF(2^128).
        
        Addition in GF(2^128) is performed coefficient-wise using XOR.
        Special cases:
        - Adding identical polynomials results in zero
        - Adding zero to a polynomial returns the original polynomial
        
        Args:
            other: Another Polynom instance
            
        Returns:
            New Polynom instance representing the sum
        """
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
        """
        Multiply two polynomials in GF(2^128).
        
        Implements standard polynomial multiplication where coefficient
        multiplication is performed in GF(2^128) using FieldElement class.
        
        Args:
            other: Another Polynom instance
            
        Returns:
            New Polynom instance representing the product
        """
        result_poly = [0] * (len(self.polynomials_int) + len(other.polynomials_int) - 1)
        if self.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]: # Zero polynomial
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])
        if other.polynomials == ["AAAAAAAAAAAAAAAAAAAAAA=="]: # Zero polynomial
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])

        for i, a in enumerate(self.polynomials_int):
            for j,b in enumerate(other.polynomials_int):
                fe_a = FieldElement(a)
                fe_b = FieldElement(b)
                result_poly[i+j] ^= (fe_a * fe_b).element
        return Polynom([base64.b64encode(int.to_bytes(res, 16, 'little')).decode() for res in result_poly])
    
    def __pow__(self, exponent):
        """
        Raise polynomial to a non-negative integer power.
        
        Args:
            exponent: Non-negative integer power
            
        Returns:
            New Polynom instance representing the result of exponentiation
        """

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
        """Display the polynomial's coefficients in base64 representation."""
        print(self.polynomials)

    def __truediv__(self, divisor):
        """
        Divide polynomial by another polynomial using polynomial long division.
        
        Implements polynomial long division in GF(2^128), returning both
        quotient and remainder.
        
        Args:
            divisor: Polynom instance to divide by
            
        Returns:
            Tuple of (quotient, remainder) as Polynom instances
            
        Raises:
            ValueError: If divisor is zero
        """

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
        """
        Compute polynomial exponentiation modulo another polynomial.
        
        Uses square-and-multiply algorithm for efficient modular exponentiation.
        
        Args:
            modulus: Polynom instance to use as modulus
            exponent: Integer exponent
            
        Returns:
            Polynom instance representing result of modular exponentiation
        """
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
        """
        Sort polynomials by degree and coefficient values.
        
        Args:
            *others: Additional Polynom instances to sort with self
            
        Returns:
            List of Polynom instances sorted by degree and coefficient values
        """
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
        """
        Convert polynomial to monic form by dividing all coefficients
        by the leading coefficient.
        
        Returns:
            List of base64-encoded coefficients representing monic polynomial
        """
        highest_coefficient = FieldElement(self.polynomials_int[-1])
        new_poly = []
        for coeff in self.polynomials_int :
            coeff = FieldElement(coeff)
            res = coeff / highest_coefficient
            new_poly.append(res.element)

        result_poly = [base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode() for coeff in new_poly] 
        return result_poly
    def sqrt(self):
        """
        Compute the square root of the polynomial.
        
        Computes square root by taking square root of coefficients
        at odd-numbered positions.
        
        Returns:
            New Polynom instance representing square root
        """
        result = []
        for degree, coeff in enumerate(self.polynomials_int):
            if (degree+1)%2:
                coeff_fe = FieldElement(coeff)
                sqrt_coeff = coeff_fe.sqrt()
                result.append(sqrt_coeff.element)

        result_poly = Polynom([base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode() for coeff in result])
        return result_poly
    def derivative(self):
        """
        Calculates the derivative of a given polynomial in GF(2^128)

        Sets all even exponent coefficients to 0 and removes the 0 degree coefficient

        Returns:
            New polynom instance representing the derivative
        """
        if len(self.polynomials_int) == 1:
            return Polynom([base64.b64encode(int.to_bytes(0, 16, 'little')).decode()])
        
        derivative = []
        base_poly = self.polynomials_int
        for degree, coeff in enumerate(base_poly):
            if (degree+1)%2:
                coeff = 0
                derivative.append(coeff)
            else:
                derivative.append(coeff)
        derivative.pop(0)
        result_poly = Polynom([base64.b64encode(int.to_bytes(coeff, 16, 'little')).decode() for coeff in derivative])
        result_poly._normalize()
        return result_poly

    def gcd(self, other):
        """
        Calculates the greates common divisor for two given polynomials in GF(2^128)

        Uses the euclidian algorithm to calculate the result and makes it monic

        Returns:
            New polynom instance representing the greates common divisor of the two polys
            in monic form
        """
        f = self
        g = other
        if len(other.polynomials_int_gcm)>len(self.polynomials_int_gcm):
            f,g = g,f
        if self.polynomials_int[0] == 0:
            return other
        if other.polynomials_int[0] == 0:
            return self
        while g.polynomials_int_gcm != [0]:
            q, r = f / g
            f = g
            g = r
        if f.polynomials_int[-1] !=1:
            g = Polynom(f.gfpoly_makemonic())
        return g

