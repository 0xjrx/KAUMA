#!/usr/bin/env python3
import base64
from cffi import FFI

ffi = FFI()

ffi.cdef("""
    void gf2_128_mul(
        const uint64_t a[2],
        const uint64_t b[2],
        const uint64_t reduction[2],
        uint64_t result[2]
    );
""")

lib = ffi.verify(r"""
    #include <stdint.h>
    #include <string.h>

    static inline void shift_left_128(uint64_t out[2]) {
        uint64_t carry = out[0] >> 63;
        out[0] <<= 1;
        out[1] = (out[1] << 1) | carry;
    }

    static inline void shift_right_128(uint64_t out[2]) {
        uint64_t carry = out[1] & 1;
        out[1] >>= 1;
        out[0] = (out[0] >> 1) | (carry << 63);
    }

    static inline void xor_128(uint64_t out[2], const uint64_t in[2]) {
        out[0] ^= in[0];
        out[1] ^= in[1];
    }

    static inline int get_lsb(const uint64_t x[2]) {
        return (int)(x[0] & 1ULL);
    }

    static inline int overflow_bit(const uint64_t x[2]) {
        return (x[1] & (1ULL << 63)) ? 1 : 0;
    }

    void gf2_128_mul(
        const uint64_t a[2],
        const uint64_t b[2],
        const uint64_t reduction[2],
        uint64_t result[2]
    ) {
        uint64_t A[2], B[2], P[2];
        A[0] = a[0]; A[1] = a[1];
        B[0] = b[0]; B[1] = b[1];
        P[0] = 0;    P[1] = 0; 

        while (B[0] != 0 || B[1] != 0) {
            if (get_lsb(B)) {
                xor_128(P, A);
            }

            int ovf = overflow_bit(A);
            shift_left_128(A);
            if (ovf) {
                xor_128(A, reduction);
            }

            shift_right_128(B);
        }

        result[0] = P[0];
        result[1] = P[1];
    }
""", extra_compile_args=["-O3", "-std=c99"])

BIT_REVERSE_TABLE = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]

# Precompute the reduction polynomial parts to avoid repeated calls
_IRR_POLY = base64.b64decode("hwAAAAAAAAAAAAAAAAAAAAE=")
REDUCTION_POLYNOMIAL = int.from_bytes(_IRR_POLY, byteorder='little')
R_LO = REDUCTION_POLYNOMIAL & 0xFFFFFFFFFFFFFFFF
R_HI = (REDUCTION_POLYNOMIAL >> 64) & 0xFFFFFFFFFFFFFFFF

def gf2mul_int(x: int, y: int, r_lo=R_LO, r_hi=R_HI) -> int:
    """
    Multiply two 128-bit integers x and y in GF(2^128) using the C function.
    """
    x_lo = x & 0xFFFFFFFFFFFFFFFF
    x_hi = (x >> 64) & 0xFFFFFFFFFFFFFFFF
    y_lo = y & 0xFFFFFFFFFFFFFFFF
    y_hi = (y >> 64) & 0xFFFFFFFFFFFFFFFF

    a_arr = ffi.new("uint64_t[2]", [x_lo, x_hi])
    b_arr = ffi.new("uint64_t[2]", [y_lo, y_hi])
    r_arr = ffi.new("uint64_t[2]", [r_lo, r_hi])
    p_arr = ffi.new("uint64_t[2]", [0, 0])

    lib.gf2_128_mul(a_arr, b_arr, r_arr, p_arr)
    product = p_arr[0] | (p_arr[1] << 64)
    return product

class FieldElement:
    """
    Represents a field element for its base64 representation.
    Provides arithmetic in GF(2^128).
    """

    _IRR_POLY = _IRR_POLY
    _REDUCTION_POLYNOMIAL = REDUCTION_POLYNOMIAL

    def __init__(self, element: int):
        self.element = element

    def gcm_sem(self, element) -> int:
        element = element.to_bytes(16, 'little') 
        reversed_element = bytes(BIT_REVERSE_TABLE[b] for b in element)
        return int.from_bytes(reversed_element, 'little')

    def __mul__(self, other: 'FieldElement') -> 'FieldElement':
        # Directly use gf2mul_int to multiply
        product = gf2mul_int(self.element, other.element)
        return FieldElement(product)

    def __add__(self, other: 'FieldElement') -> 'FieldElement':
        # Addition is XOR in GF(2)
        xor = self.element ^ other.element    
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
        if int(other) == 0:
            raise ValueError("Division by zero")
        return self * self.inv(other)
    
    def sqrt(self) -> 'FieldElement':
        base = self
        result = FieldElement(1)
        exponent = (1 << 127)
        
        # Take the FieldElement to the power of 2^127
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
            exponent >>= 1
        return result   

    def __int__(self):
        return self.element

    def __repr__(self):
        return f"FieldElement(0x{self.element:032x})"


class Polynom:
    """
    Represents polynomials over GF(2^128) with coefficients encoded as integers.
    """

    def __init__(self, polynomials: list):
        self.int = polynomials

    def degree(self):
        return len(self.int)-1

    def _normalize(self):
        while self.int and self.int[-1] == 0:
            self.int.pop()
        return Polynom(self.int)

    def __add__(self, other):
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
        
        result = Polynom(result_poly)
        result._normalize()
        
        return result    

    def __mul__(self, other):
        if self.int == [0] or other.int == [0]:
            return Polynom([0])

        # Direct integer multiplication using gf2mul_int
        result_poly = [0] * (len(self.int) + len(other.int) - 1)

        for i, a in enumerate(self.int):
            if a == 0:
                continue
            for j, b in enumerate(other.int):
                if b == 0:
                    continue
                # Directly multiply ints in GF(2^128)
                result_poly[i+j] ^= gf2mul_int(a, b)

        return Polynom(result_poly)

    def __pow__(self, exponent) -> 'Polynom':
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
        if len(divisor.int) == 0:
            return Polynom([0]), self
            
        if len(self.int) == 0 or (len(self.int) == 1 and self.int[0] == 0):
            return (Polynom([0]), Polynom([0]))
        
        remainder = Polynom(self.int.copy())
        remainder.int = self.int.copy()
        
        dividend_degree = self.degree()
        divisor_degree = divisor.degree()
        
        if dividend_degree < divisor_degree:
            return Polynom([0]), remainder
        
        quotient_coeffs = [0] * (dividend_degree - divisor_degree + 1)
        
        work_remainder = remainder.int.copy()
        
        while len(work_remainder) >= len(divisor.int):
            if work_remainder and work_remainder[-1] == 0:
                work_remainder.pop()
                continue
            
            if not work_remainder:
                break
            
            curr_remainder_degree = len(work_remainder) - 1
            curr_divisor_degree = len(divisor.int) - 1
            
            lead_remainder = FieldElement(work_remainder[-1])
            lead_divisor = FieldElement(divisor.int[-1])
            curr_quotient = lead_remainder / lead_divisor
            
            pos = curr_remainder_degree - curr_divisor_degree
            quotient_coeffs[pos] = int(curr_quotient)
            
            subtrahend_coeffs = [0]*pos
            for coeff in divisor.int:
                mult_result = int(FieldElement(coeff) * curr_quotient)
                subtrahend_coeffs.append(mult_result)
                
            while len(subtrahend_coeffs) < len(work_remainder):
                subtrahend_coeffs.insert(0, 0)
                
            for i in range(len(work_remainder)):
                work_remainder[i] ^= subtrahend_coeffs[i]
                
            while work_remainder and work_remainder[-1] == 0:
                work_remainder.pop()        
        remainder = Polynom(work_remainder)
        if remainder.int ==[]:
            remainder = Polynom([0])
        quotient = Polynom(quotient_coeffs)
        return quotient, remainder

    def poly_powmod(self, modulus: 'Polynom', exponent) -> 'Polynom':
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
            _, base = base / modulus
            exponent >>= 1
        return result

    def gfpoly_sort(self, *others):
        all_poly = [self] + list(others)
        def compare_polys(poly):
            key = [poly.degree()]
            for item in poly.int[::-1]:
                key.append(item)
            return tuple(key)
        sorted_polys = sorted(all_poly, key=compare_polys)
        return sorted_polys

    def gfpoly_makemonic(self) -> list:
        highest_coefficient = int(FieldElement(self.int[-1]))
        new_poly = [0] * len(self.int)
        
        for i, coeff in enumerate(self.int):
            res = int(FieldElement(coeff) / FieldElement(highest_coefficient))
            new_poly[i] = res
        
        return [coeff for coeff in new_poly]

    def sqrt(self) -> 'Polynom':
        result = []
        for degree, coeff in enumerate(self.int):
            if (degree+1)%2:
                coeff_fe = FieldElement(coeff)
                sqrt_coeff = coeff_fe.sqrt()
                result.append(sqrt_coeff.element)
        return Polynom(result)

    def derivative(self) -> 'Polynom':
        if self.degree() == 0:
            return Polynom([0])
        
        derivative = []
        base_poly = self.int
        for degree, coeff in enumerate(base_poly):
            if (degree+1)%2:
                coeff = 0
            derivative.append(coeff)
        derivative.pop(0)
        result_poly = Polynom(derivative)
        result_poly._normalize()
        return result_poly

    def gcd(self, other) -> 'Polynom':
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

