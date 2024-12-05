#!/usr/bin/env python3
import base64

BIT_REVERSE_TABLE = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]


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


    _IRR_POLY = base64.b64decode("hwAAAAAAAAAAAAAAAAAAAAE=")
    _REDUCTION_POLYNOMIAL = int.from_bytes(_IRR_POLY, byteorder='little')

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
        element = element.to_bytes(16, 'little') 
        reversed_element = bytes(BIT_REVERSE_TABLE[b] for b in element)
        return int.from_bytes(reversed_element, 'little')

    def __mul__(self, other) -> 'FieldElement':
        """
        Multiply two field elements in GF(2^128).

        Implements russian peasant multiplication algorithm with
        modular reduction using GCM's irreducible polynomial.

        Args:
            other: Another field element instance

        Returns:
            New FieldElementGCM instance representing the product of the multiplication
        """
    
        # Convert our operants to GCM's semantic
        multiplicant = int(self) #.gcm_sem(int(self))
        
        multiplier = int(other) #.gcm_sem(int(other))
        
        # Convert the reduction polynomial
        reduction_polynomial = self._REDUCTION_POLYNOMIAL

        product = 0

        while multiplier:
            # If least significant bit is 1, XOR with current multiplicant
            if multiplier & 1:
                product ^= multiplicant
            
            # Left shift multiplicant (equivalent to multiplication by x)
            multiplicant <<= 1
            
            # Polynomial reduction if bit length exceeds 128
            if multiplicant.bit_length() >= 129:
                multiplicant ^= reduction_polynomial
            
            # Right shift multiplier
            multiplier >>= 1
        
        # Convert result back to normal semantic
        return FieldElement(product)    

    def __add__(self, other: 'FieldElement') -> 'FieldElement':
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
        
    
    def inv(self, Element):
        mod = self._REDUCTION_POLYNOMIAL
        a = int(Element)
        u, v = a, mod
        g1, g2 = 1,0
        while u!=1:
            if u.bit_length()<v.bit_length():
                u,v = v,u
                g1, g2 = g2, g1
            shift = u.bit_length()-v.bit_length()
            u^=v<<shift
            g1 ^=g2<<shift
        return FieldElement(g1)

    def __truediv__(self, other) -> 'FieldElement':
        """
        Divides a FieldElement by another FieldElement using inversion
        as the division is multiplication by the inverted element.
        """
        if int(other) == 0:
            raise ValueError("Division by zero")
        return self * self.inv(other)
    
    def sqrt(self) -> 'FieldElement':
        """
        Calculates the squareroot of a FieldElement. In GF2^128 the sqrt is defined as
        the FieldElement^2^m-1, whith m as the order of the field, so 128
        """
        base = self
        result = FieldElement(0)
        exponent = (1 << 127)
        
        result = FieldElement(1)
        
        # Take the FieldElement to the power of 2^127
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
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
        self.int = polynomials
        # Store coefficients as integers for efficient computation
        # Store coefficients as integers in converted from gcm semantic
    def degree(self):
        return len(self.int)-1

    def _normalize(self):
        """
        Remove trailing zero coefficients from the polynomial.
        
        Updates both the integer and base64 representations of the polynomial.
        Preserves leading zeros as they represent significant terms.
        """
        while self.int and self.int[-1] == 0:
            self.int.pop()
        return Polynom(self.int)
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
        
        if self.int == other.int:
            return Polynom([0])
        
        if self.int == [0]:
            return other
        
        if other.int == [0]:
            return self
        
        max_len = max(len(self.int), len(other.int))
        
        self_int = self.int + [0] * (max_len - len(self.int))
        
        other_int = other.int + [0] * (max_len - len(other.int))

        result_poly = [s ^ o for s, o in zip(self_int, other_int)]
        
        result = Polynom(
            [res for res in result_poly]
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
        result_poly = [0] * (len(self.int) + len(other.int) - 1)
        
        if self.int == [0]: # Zero polynomial
            return Polynom([0])
        
        if other.int == [0]: # Zero polynomial
            return Polynom([0])

        for i, a in enumerate(self.int):
            for j,b in enumerate(other.int):
                fe_a = FieldElement(a)
                fe_b = FieldElement(b)
                result_poly[i+j] ^= (fe_a * fe_b).element
        return Polynom([res for res in result_poly])
    
    def __pow__(self, exponent) -> 'Polynom':
        """
        Raise polynomial to a non-negative integer power.
        
        Args:
            exponent: Non-negative integer power
            
        Returns:
            New Polynom instance representing the result of exponentiation
        """

        if exponent ==0:
            return Polynom([1])
        if exponent ==1:
            return self
        
        base = self
        result = base
        exponent -=1
        while exponent:
            result = result * base
            exponent -=1
        return result
     
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
        

        if len(divisor.int) == 0:
            return Polynom([0]), self
            
        # If dividend is zero, return zero
        if len(self.int) == 0 or len(self.int) == 1 and self.int[0] == 0:
            return (
                Polynom([0]),
                Polynom([0]),
            )
        
        # Create a copy of the dividend
        remainder = Polynom(self.int.copy())
        remainder.int = self.int.copy()
        
        # Get the degrees
        dividend_degree = self.degree()
        divisor_degree = divisor.degree()
        
        # If dividend degree is less than divisor degree, quotient is 0 and remainder is dividend
        if dividend_degree < divisor_degree:
            return Polynom([0]), remainder
        
        # Initialize quotient coefficients with zeros
        quotient_coeffs = [0] * (dividend_degree - divisor_degree + 1)
        
        # Create working copy to preserve zero coefficients
        work_remainder = remainder.int.copy()
        
        # Continue as there arre emough terms
        while len(work_remainder) >= len(divisor.int):
            # Skip if leading coefficient is zero
            if work_remainder[-1] == 0:
                work_remainder.pop()
                continue
                
            # Calculate degrees for current step
            curr_remainder_degree = len(work_remainder) - 1
            curr_divisor_degree = len(divisor.int) - 1
            
            # Calculate quotient coefficient
            lead_remainder = FieldElement(work_remainder[-1])
            lead_divisor = FieldElement(divisor.int[-1])
            curr_quotient = lead_remainder / lead_divisor
            
            # Store quotient coefficient
            pos = curr_remainder_degree - curr_divisor_degree
            quotient_coeffs[pos] = int(curr_quotient)
            
            # Create subtrahend with preserved zeros
            subtrahend_coeffs = [0] * pos
            for coeff in divisor.int:
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
        remainder = Polynom([coeff
            for coeff in work_remainder
        ])
        
        # Create quotient polynomial
        quotient = Polynom([coeff
            for coeff in quotient_coeffs
        ])
        if remainder.int ==[]:

            remainder = Polynom([0])
        return quotient, remainder

    def poly_powmod(self, modulus: 'Polynom', exponent) -> 'Polynom':
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
            return Polynom([1])
        

        if exponent == 1:
            result, remainder = self / modulus
            return remainder
            
        result = Polynom([1])
        base = self
        _, base = base / modulus
        
        while exponent > 0:
            if exponent & 1:
                result *= base
                _, result = result / modulus
            base *= base
            _, base = base/ modulus
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
            key.append(poly.degree())
            
            for item in poly.int[::-1]:
                key.append(item)
            key_tuple = tuple(key)

            # Pack our values into a tuple and let python handle the rest 
            return key_tuple
        # Sort our polynomials based on all criteria
        sorted_polys = sorted(all_poly, key=compare_polys)
        return sorted_polys

    def gfpoly_makemonic(self) -> list:
        """
        Convert polynomial to monic form by dividing all coefficients
        by the leading coefficient.
        
        Returns:
            List of base64-encoded coefficients representing monic polynomial
        """
        highest_coefficient = int(FieldElement(self.int[-1]))
    
        # Preallocate list to avoid repeated list resizing
        new_poly = [0] * len(self.int)
        
        # Use list comprehension with direct division for efficiency
        for i, coeff in enumerate(self.int):
            # Perform field division directly
            res = int(FieldElement(coeff) / FieldElement(highest_coefficient))

            new_poly[i] = res
        
        # Combine encoding in a single list comprehension
        return [
        coeff   for coeff in new_poly
        ]
    def sqrt(self) -> 'Polynom':
        """
        Compute the square root of the polynomial.
        
        Computes square root by taking square root of coefficients
        at odd-numbered positions.
        
        Returns:
            New Polynom instance representing square root
        """
        result = []
        for degree, coeff in enumerate(self.int):
            if (degree+1)%2:
                coeff_fe = FieldElement(coeff)
                sqrt_coeff = coeff_fe.sqrt()
                result.append(sqrt_coeff.element)

        result_poly = Polynom([coeff for coeff in result])
        return result_poly

    def derivative(self) -> 'Polynom':
        """
        Calculates the derivative of a given polynomial in GF(2^128)

        Sets all even exponent coefficients to 0 and removes the 0 degree coefficient

        Returns:
            New polynom instance representing the derivative
        """
        if self.degree() == 1:
            return Polynom([0])
        
        derivative = []
        base_poly = self.int
        for degree, coeff in enumerate(base_poly):
            if (degree+1)%2:
                coeff = 0
                derivative.append(coeff)
            else:
                derivative.append(coeff)
        derivative.pop(0)
        result_poly = Polynom([coeff for coeff in derivative])
        result_poly._normalize()
        return result_poly

    def gcd(self, other) -> 'Polynom':
        """
        Calculates the greates common divisor for two given polynomials in GF(2^128)

        Uses the euclidian algorithm to calculate the result and makes it monic

        Returns:
            New polynom instance representing the greates common divisor of the two polys
            in monic form
        """
        f = self
        g = other
        if len(other.int)>len(self.int):
            f,g = g,f
        if self.int[0] == [0]:
            return other
        if other.int[0] == [0]:
            return self
        while g.int != [0]:
            q, r = f / g
            f = g
            g = r
        if f.int[-1] !=1:
            f = Polynom(f.gfpoly_makemonic())
        return f

    def __int__(self):
        return self.int



