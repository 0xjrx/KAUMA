#!/usr/bin/env python3

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tasks.sea import sea_enc

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


def reverse_bit(byte) -> int:
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
        result = (result << 1) | (byte & 1)
        byte >>= 1
    return result

class FieldElementGCM:
    """
    Represents a field element for its base64 representation.

    This class provides arithmetic operations (addition and multiplication)
    for field elements, with automatic modular reduction using GCM's
    irreducible polynomial.
    """
    def __init__(self, element):
        """
        
        Initialize a field element from its base64 representation.

        Args:
            element: Base64 encoded string representing the field element
        """
        self.element = element
    
    def _gcm_sem(self, element) -> str:
        """ 
        Transform a field element to GCM's semantic.

        Performs bit reversal on individual bytes as required by GCM's
        field arithmetic implementation

        Args:
            element: Base64 encoded field element

        Returns:
            Base64 encoded transformed element
        """
        # Padd the the base64 string if necessary
        while len(element) % 4 != 0:
            element += '='
        elem_bytes = base64.b64decode(element)
        byte_list = []
        
        for i in range(len(elem_bytes)):
            byte_list.append(elem_bytes[i])
        # Reverse bits in each byte
        reversed_bytes = [reverse_bit(byte) for byte in byte_list]
    
        reversed_bytes_arr = bytes(reversed_bytes)
        return base64.b64encode(reversed_bytes_arr).decode('utf-8')
    
    def test(self, element):
        return self._gcm_sem(element)
    
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
        IRR_POLY = "hwAAAAAAAAAAAAAAAAAAAAE="
        # Convert our operants to GCM's semantic and then integers for easy bit manipulation
        
        first = base64.b64decode(self._gcm_sem(self.element))
        multiplicant = int.from_bytes(first, byteorder = 'little')
        
        second = base64.b64decode(other._gcm_sem(other.element))
        multiplier = int.from_bytes(second, byteorder = 'little')
        
        # Convert the reduction polynomial
        poly_bytes = base64.b64decode(IRR_POLY)
        reduction_polynomial = int.from_bytes(poly_bytes, byteorder = 'little')

        product = 0

        # We handle the first bit of the loop outside
        if multiplier & 1:
            product^=multiplicant
        multiplier>>=1

        # Main multiplication loop
        for _ in range((len(second)*8)-1):    
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
        
        # Convert the result back to normal semantic and then base64
        product_bytes = product.to_bytes(16, byteorder = 'little')
        encoded_product = base64.b64encode(product_bytes).decode('utf-8')
        gcm_encoded_product = self._gcm_sem(encoded_product)
        return FieldElementGCM(gcm_encoded_product)
    
    def __add__(self, other):
        """
        Add two field elements in GF(2^128)

        In GF(2^128), addition is simply bitwise XOR of the elements.

        Args:
            other: Another FieldElementGCM instance

        Returns:
            New FieldElementGCM instance representing the sum
        """
        first = base64.b64decode(self.element)
        second = base64.b64decode(other.element)
        xor = bytes(a^b for a,b in zip(first, second))
        return FieldElementGCM(base64.b64encode(xor).decode('utf-8'))
  

def _slice_input(input) -> list:
    """
    Slice input data into 16-byte blocks for cipher operation.

    Args:
        input: Base64 encoded input
    
    Returns:
        List of 16-byte blocks
    """
    bytes = base64.b64decode(input)
    input_block = []
    for i in range (0, len(bytes), 16):        
        input_block.append(bytes[i:i + 16])
    return input_block

def ghash_associated_data(associated_data_blocks, h_field_elem):
    """
    Calculate GHASH for associated data (authenticated but not encrypted data).
    
    Args:
        associated_data_block: List of data blocks to authenticate
        h_field_elem: Authentication key H as a field element

    Returns:
        FieldElementGCM representing the initial GHASH value
    """
    ghash_result = FieldElementGCM(base64.b64encode(bytes(16)).decode('utf-8'))
    for block in associated_data_blocks:
        #print(f"associated data blocks: {associated_data_blocks}")
        if len(block) < 16:  # Pad last block if necessary
            block = block + b'\x00' * (16 - len(block))
        block_fe = FieldElementGCM(base64.b64encode(block).decode('utf-8'))
        ghash_result = (ghash_result + block_fe) * h_field_elem
        #print(f"GHASH Res with AD {int.from_bytes(base64.b64decode(ghash_result.element), 'little')}")
    return ghash_result


def GCM_encrypt(nonce, key, plaintext, associated_data):
    """
    Perform GCM encryption using AES as the underlying block cipher.

    Args:
        nonce: Base64 encoded nonce (should be kept unique for each encryption)
        key: Base64 encoded key
        plaintext: Base64 encoded data to encrypt
        associated_data: Base64 encoded data to authenticate but not encrypt

    Returns:
        Dictionary containing ciphertext, authentication tag, length field and Authentication Key H
    """
    plaintext_blocks = _slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    # Generate the authentication key H = AES_K(0)
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    null_array = bytes(16)
    auth_key = encryptor.update(null_array) + encryptor.finalize()
    h_field_elem = FieldElementGCM(base64.b64encode(auth_key).decode('utf-8'))
   
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
        
        # Encrypt Y
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        
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
        ct_fe = FieldElementGCM(base64.b64encode(ct_block).decode('utf-8'))
        ghash_result =(ghash_result + ct_fe) * h_field_elem

    # Add length block to GHASH
    len_a = len(associated_data_bytes) * 8
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    l_fe = FieldElementGCM(base64.b64encode(L).decode('utf-8'))
    ghash_result = (ghash_result + l_fe)* h_field_elem   


    # Generate Authentication Tag
    y_0 = nonce_bytes + b'\x00\x00\x00\x01'
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    encryptor = cipher.encryptor()
    tag_bytes = encryptor.update(y_0) + encryptor.finalize()
    tag_b64 = FieldElementGCM(base64.b64encode(tag_bytes).decode('utf-8'))
    
    tag = (tag_b64 + ghash_result).element
    
    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":tag,"L":l_fe.element,"H":h_field_elem.element}
    
def GCM_encrypt_sea(nonce, key, plaintext, associated_data):
    """
    Perform GCM Encryption using SEA (Simple Encryption Algorithm) as the block cipher.

    Implementation follows the same structure as standard GCM but uses SEA128
    instead of AES128 for encryption.

    Args and return match those of GCM_encrypt().
    """
    plaintext_blocks = _slice_input(plaintext)
    nonce_bytes = base64.b64decode(nonce)
    associated_data_bytes = base64.b64decode(associated_data)
    ciphertext = bytearray()
    #print(f"Associated Data in little: {int.from_bytes(associated_data_bytes, 'big')}") 
 
    # Generate H using SEA128
    null_array = bytes(16)
    h = sea_enc(key, base64.b64encode(null_array).decode('utf-8'))
    h_field_elem = FieldElementGCM(h)
    print(f"Authentication Key H is: {int.from_bytes(base64.b64decode(h), 'little')}") 
    # Process associated data
    associated_data_blocks = []
    for i in range(0, len(associated_data_bytes), 16):
        block = associated_data_bytes[i:i + 16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        associated_data_blocks.append(block)
    
    
    ghash_result = ghash_associated_data(associated_data_blocks, h_field_elem) 
    
    # encrypt using counter initialized at 2
    ctr = 2
    ghash_blocks = []
    for block in plaintext_blocks:
        
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
        encrypted_Y_bytes = base64.b64decode(encrypted_Y)
        
        ct = bytes(a ^ b for a, b in zip(encrypted_Y_bytes[:len(block)], block))
        ciphertext.extend(ct)

        if len(ct) < 16:
            ct = ct + b'\x00' * (16 - len(ct))
        ghash_blocks.append(ct)
        ctr += 1
    
    # Update GHASH with ciphertext
    for ct_block in ghash_blocks:
        ct_fe = FieldElementGCM(base64.b64encode(ct_block).decode('utf-8'))
        ghash_result =(ghash_result + ct_fe) * h_field_elem
        #print(f"GHASH round result with ciphertext blocks: {int.from_bytes(base64.b64decode(ghash_result.element), 'big')}")
    
    # Add length block
    len_a = len(associated_data_bytes) * 8
    len_b = len(ciphertext) * 8
    L = len_a.to_bytes(8, 'big') + len_b.to_bytes(8, 'big')
    l_fe = FieldElementGCM(base64.b64encode(L).decode('utf-8'))
    ghash_result = (ghash_result + l_fe)* h_field_elem   
    #print(f"GHASH res after adding of L: {int.from_bytes(base64.b64decode(ghash_result.element), 'big')}")
    
    # Generate Tag
    y_0 = nonce_bytes + b'\x00\x00\x00\x01'
    tag_b64 = sea_enc(key, base64.b64encode(y_0).decode('utf-8'))
    #print(f"Block ciphert encrypt with nonce 0 is: {int.from_bytes(base64.b64decode(tag_b64), 'big')}")

    tag_fe = FieldElementGCM(tag_b64)
    tag = (tag_fe + ghash_result).element

    return {"ciphertext": base64.b64encode(ciphertext).decode('utf-8'),"tag":tag,"L":l_fe.element,"H":h_field_elem.element}

def GCM_decrypt(nonce, key, ciphertext, associated_data, tag):
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
    ciphertext_blocks = _slice_input(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    key_bytes = base64.b64decode(key)
    plaintext = bytearray()
    
    # Counter starts at 2 (1 is reserved for tag)
    ctr = 2

    # Decrypt ciphertext using a counter
    for block in ciphertext_blocks:
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_Y = encryptor.update(Y) + encryptor.finalize()
        
        # XOR with ciphertext
        ct = bytes(a ^ b for a, b in zip(encrypted_Y, block))
        
        plaintext.extend(ct)
        ctr += 1
    
    # Check authenticity of tag
    computed_tag =  GCM_encrypt(nonce, key, base64.b64encode(plaintext), associated_data)
    computed_tag = computed_tag["tag"]
    if computed_tag == tag:
        return {"authentic": True,"plaintext":base64.b64encode(plaintext).decode('utf-8')}

    else:
        return {"authentic":False, "plaintext":base64.b64encode(plaintext).decode('utf-8')}

def GCM_decrypt_sea(nonce, key, ciphertext, associated_data, tag):
    """
    Decrypt GCM ciphertext and authenticate using SEA.

    Args and Returns match those of GCM_decrypt().
    """
    ciphertext_blocks = _slice_input(ciphertext)
    nonce_bytes = base64.b64decode(nonce)
    plaintext = bytearray()
    
    # Counter starts at 2 (1 is reserved for tag)
    ctr = 2
    # Encrypt plaintext blocks using a counter
    for block in ciphertext_blocks:
       
        counter = ctr.to_bytes(4, 'big')
        Y = nonce_bytes + counter
        
        # Encrypt Y
        encrypted_Y = sea_enc(key, base64.b64encode(Y).decode('utf-8'))
        # XOR with plaintext and update GHASH
        ct = bytes(a ^ b for a, b in zip(base64.b64decode(encrypted_Y), block))
        
        plaintext.extend(ct)
        ctr += 1

    # Check authenticity
    computed_tag =  GCM_encrypt_sea(nonce, key, base64.b64encode(plaintext), associated_data)
    computed_tag = computed_tag["tag"]
    if computed_tag == tag:
        return {"authentic": True,"plaintext":base64.b64encode(plaintext).decode('utf-8')}
    else:
        return {"authentic": False, "plaintext":base64.b64encode(plaintext).decode('utf-8')}

def test():
    element = "ARIAAAAAAAAAAAAAAAAAgA=="
    elem_fe = FieldElementGCM(element)
    transformed_element = elem_fe.test(element)
    print(f"GCM Semantic Element: {transformed_element}")
