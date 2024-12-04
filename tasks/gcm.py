#!/usr/bin/env python3

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tasks.sea import sea_enc
from common import slice_input

from tasks.poly import BIT_REVERSE_TABLE

#FIX:THIS IS TEMPORARY------------->

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
        multiplicant = self.gcm_sem(int(self))
        
        multiplier = self.gcm_sem(int(other))
        
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
        return FieldElement(self.gcm_sem(product))    

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
        
    def invert(self, divisor) -> 'FieldElement':
        """
        This function calculates the inverse of a FielElement instance
        through exponentiation by 2^128 -2
        
        """
        base = divisor
        # Set the exponent
        exponent = (1 << 128) - 2
        
        # Set our result 
        result = FieldElement(self.gcm_sem(1))
        
        # Use square multiply
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
            exponent >>= 1
        
        return result
    
    def inv(self, Element):
        mod = self._REDUCTION_POLYNOMIAL
        a = self.gcm_sem(int(Element))
        u, v = a, mod
        g1, g2 = 1,0
        while u!=1:
            if u.bit_length()<v.bit_length():
                u,v = v,u
                g1, g2 = g2, g1
            shift = u.bit_length()-v.bit_length()
            u^=v<<shift
            g1 ^=g2<<shift
        return FieldElement(self.gcm_sem(g1))

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
        
        result = FieldElement(self.gcm_sem(1))
        
        # Take the FieldElement to the power of 2^127
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
            exponent >>= 1
        return result   

    def __int__(self):
        return self.element

#FIX: THIS IS TEMPORARY------------->


"""
Galois Counter Mode (GCM) Encryption implementation

This module implements the GCM encryption, providing confidentiality and authenticity.
GCM combines the counter mode with Galois Field multiplication for authentication and generates a tag.

The implementation includes both standard AES-GCM and a variant using SEA (Simple Encryption Algorithm),
as the underlying block cipher.

Key components:
- Field Arithmetics in GF(2^128) using FieldElementGCM class 
- GHASH authentication
- Counter mode encryption
- Tag generation
"""


 


def ghash_associated_data(associated_data_blocks, h_field_elem):
    """
    Calculate GHASH for associated data (authenticated but not encrypted data).
    
    Args:
        associated_data_block: List of data blocks to authenticate
        h_field_elem: Authentication key H as a field element

    Returns:
        FieldElementGCM representing the initial GHASH value
    """
    bytes = bytearray(16)
    ghash_result = FieldElement(int.from_bytes(bytes, 'little'))
    for block in associated_data_blocks:
        if len(block) < 16:  # Pad last block if necessary
            block = block + b'\x00' * (16 - len(block))
        block_fe = FieldElement(int.from_bytes(block, 'little') )
        ghash_result = (ghash_result + block_fe) * h_field_elem
    return ghash_result


def GCM_encrypt(nonce, key, plaintext, associated_data, mode):
    """
    Perform GCM encryption using AES or SEA as the underlying block cipher.

    Args:
        nonce: Base64 encoded nonce (should be kept unique for each encryption)
        key: Base64 encoded key
        plaintext: Base64 encoded data to encrypt
        associated_data: Base64 encoded data to authenticate but not encrypt

    Returns:
        Dictionary containing ciphertext, authentication tag, length field and Authentication Key H
    """
    plaintext_blocks = slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    null_array = bytes(16)


    # Generate the authentication key H = AES_K(0)
    if mode =="aes":
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        auth_key = encryptor.update(null_array) + encryptor.finalize()
    else:
        auth_key = base64.b64decode(sea_enc(key, base64.b64encode(null_array).decode('utf-8')))
    h_field_elem = FieldElement(int.from_bytes(auth_key, 'little'))
   
    # Process associated data
    associated_data_blocks = []
    for i in range(0, len(associated_data_bytes), 16):
        block = associated_data_bytes[i:i + 16]
        associated_data_blocks.append(block)
    
    # Initial GHASH calculation with the associated data
    ghash_result = ghash_associated_data(associated_data_blocks, h_field_elem)

    # Encrypt using counter mode starting at 2 (1 is reserved for tag)
    ctr = 2
    ghash_blocks = []
    for block in plaintext_blocks:
        
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        if mode =="aes": 
            # Encrypt Y
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            encryptor = cipher.encryptor()
            encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        else:
             encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
             encrypted_Y = base64.b64decode(encrypted_Y)
        # XOR with plaintext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y[:len(block)], block))
        ciphertext.extend(ct)
        
        # Pad ciphertext for ghash if necessary
        if len(ct) < 16:
            ct = ct + b'\x00' * (16 - len(ct))
        ghash_blocks.append(ct)
        ctr += 1
    # Update and calculate GHASH
    for ct_block in ghash_blocks:
        ct_fe = FieldElement(int.from_bytes(ct_block, 'little'))
        ghash_result =(ghash_result + ct_fe) * h_field_elem

    # Add length block to GHASH
    len_a = len(associated_data_bytes) * 8
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    l_fe = FieldElement(int.from_bytes(L, 'little'))
    ghash_result = (ghash_result + l_fe)* h_field_elem   

    # Generate Authentication Tag
    y_0 = nonce_bytes + b'\x00\x00\x00\x01'
    if mode == "aes":
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        y_0_enc = encryptor.update(y_0) + encryptor.finalize()
    else:
        y_0_enc = base64.b64decode(sea_enc(key, base64.b64encode(y_0).decode()))
    
    tag_b64 = FieldElement(int.from_bytes(y_0_enc, 'little'))
    tag = (tag_b64 + ghash_result)
   
    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":base64.b64encode(int.to_bytes(tag.element,16, 'little')).decode(),"L":base64.b64encode(int.to_bytes(l_fe.element,16, 'little')).decode(),"H":base64.b64encode(int.to_bytes(h_field_elem.element,16, 'little')).decode()}

def GCM_decrypt(nonce, key, ciphertext, associated_data, tag, mode):
    """
    Decrypt GCM ciphertext and verify the authentication tag using AES.

    Args:
        nonce: Base64 encoded nonce (must match encryption nonce)
        key: Base64 encoded encryption key
        ciphertext: Base64 encoded ciphertext to decrypt
        associated_data: Base64 encoded authenticated data
        tag: Authentication tag to verify
        
    Returns:
        Dictionary containing authentication status and decrypted plaintext    
    """
    ciphertext_blocks = slice_input(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    plaintext = bytearray()
    
    # Counter starts at 2 (1 is reserved for tag)
    ctr = 2

    # Decrypt ciphertext using a counter
    for block in ciphertext_blocks:
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        if mode =="aes":
            # Encrypt Y
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
            encryptor = cipher.encryptor()
            encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        else: 
            encrypted_Y = base64.b64decode(sea_enc(key, base64.b64encode(Y).decode('utf-8')))

        # XOR with ciphertext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y, block))
        
        plaintext.extend(ct)
        ctr += 1
    
    # Check authenticity of tag
    if mode =="aes":
        computed_tag =  GCM_encrypt(nonce, key, base64.b64encode(plaintext), associated_data, "aes")
    else:
        computed_tag =  GCM_encrypt(nonce, key, base64.b64encode(plaintext), associated_data, "sea")

    computed_tag = computed_tag["tag"]
    if computed_tag == tag:
        return {"authentic": True,"plaintext":base64.b64encode(plaintext).decode('utf-8')}

    else:
        return {"authentic":False, "plaintext":base64.b64encode(plaintext).decode('utf-8')}



